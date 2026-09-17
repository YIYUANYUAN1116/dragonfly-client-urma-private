//! Child ownership foundation with context-routed CQE retirement. Production
//! READ commands and Storage publication remain gated.
use super::{
    ffi::{
        read::{
            ImportedReadSegment, ReadBufferCreation, ReadDescriptor, ReadPost, ReadRequest,
            ReadToken, ReadWrHandle,
        },
        FfiError, JettyHandle, NativeRuntime, SegmentHandle, TargetHandle,
    },
    read_owner::{ReadOwnerId, ReapDecision, VerifiedRetirement},
};
use std::{
    collections::BTreeMap,
    mem::ManuallyDrop,
    sync::atomic::{AtomicU32, Ordering},
};

// Existing SEND/RECV WrToken values always carry operation 1 or 2 in bits
// 32..40. Reserve an invalid operation byte for READ so a stale or unknown
// READ CQE can never be decoded as an ordinary SEND/RECV completion.
const READ_CONTEXT_PREFIX: u64 = 0xffff_ff52_0000_0000;
const READ_CONTEXT_MASK: u64 = 0xffff_ffff_0000_0000;
static NEXT_READ_CONTEXT: AtomicU32 = AtomicU32::new(1);

pub(crate) fn is_read_context(context: u64) -> bool {
    context & READ_CONTEXT_MASK == READ_CONTEXT_PREFIX
}

/// A decoded completion whose provider retirement semantics have been validated.
/// Identity is checked again against the owning bundle before any WR is released.
pub(crate) struct ReadRetired {
    owner: ReadOwnerId,
    jetty: u32,
    context: u64,
    length: u32,
    success: bool,
}
impl ReadRetired {
    /// # Safety
    /// The native record must prove retirement of this READ WR (not a receive,
    /// unrelated opcode, malformed record, or ambiguous flush). Validate context
    /// flags and the provider's error/flush semantics before normalizing length.
    /// For failed WRs, length means the matched request length, not bytes written.
    pub(crate) unsafe fn new(
        owner: ReadOwnerId,
        jetty: u32,
        context: u64,
        length: u32,
        success: bool,
    ) -> Self {
        Self {
            owner,
            jetty,
            context,
            length,
            success,
        }
    }

    pub(crate) fn context(&self) -> u64 {
        self.context
    }
}

pub(crate) enum ChildPost<W> {
    Posted(W),
    Rejected(FfiError),
    Uncertain(W, FfiError),
}

pub(crate) enum ChildPostOutcome {
    Posted(u64),
    /// The provider may have accepted the WR. The context must be routed even
    /// though the operation is quarantined and no further READ may be posted.
    Uncertain {
        context: u64,
        error: FfiError,
    },
    Rejected(FfiError),
}

/// Implementations must retain destination/import/native dependencies until close.
/// Kept private to this transport module; no CPU buffer access is exposed.
pub(crate) trait ChildResources {
    type Wr;
    fn post(&mut self, request: &ReadRequest) -> Result<ChildPost<Self::Wr>, FfiError>;
    /// # Safety
    /// The WR has independently verified retirement, checked by ChildOwner.
    unsafe fn complete(&mut self, wr: Self::Wr);
    fn unimport(&mut self) -> Result<(), FfiError>;
    fn close_buffer(&mut self) -> Result<(), FfiError>;
}

pub(crate) struct NativeChild<K> {
    jetty: std::rc::Rc<std::cell::RefCell<JettyHandle>>,
    target: std::rc::Rc<TargetHandle>,
    local: SegmentHandle,
    remote: Option<ImportedReadSegment>,
    import_uncertain: bool,
    _keepalive: K,
}
impl<K> NativeChild<K> {
    /// # Safety
    /// Caller reserved actual allocation bytes before creating local/import, owns
    /// the exact Piece buffer exclusively, and validated descriptor identity and
    /// bounds. No CPU consumer or other DMA may access local while this owns it.
    /// Shared JFS/per-peer permits must cover every post until its completion.
    pub(crate) unsafe fn new(
        jetty: std::rc::Rc<std::cell::RefCell<JettyHandle>>,
        target: std::rc::Rc<TargetHandle>,
        local: SegmentHandle,
        remote: ImportedReadSegment,
        keepalive: K,
    ) -> Self {
        Self {
            jetty,
            target,
            local,
            remote: Some(remote),
            import_uncertain: false,
            _keepalive: keepalive,
        }
    }
}
impl<K> NativeChild<K> {
    /// # Safety
    /// Invoke only inside ReadOwners::create_child after reserving allocation_bytes.
    /// Descriptor authentication/generation, provider rollback semantics for import,
    /// exact Piece bounds and device capability gates remain caller requirements.
    pub(crate) unsafe fn create(
        runtime: &mut NativeRuntime,
        jetty: std::rc::Rc<std::cell::RefCell<JettyHandle>>,
        target: std::rc::Rc<TargetHandle>,
        spec: super::read_owners::ChildSpec,
        alignment: u64,
        descriptor: &ReadDescriptor,
        token: &ReadToken,
        max_read_size: u32,
        keepalive: K,
    ) -> super::read_owners::ChildCreation<Self> {
        use super::read_owners::ChildCreation;
        if spec.piece_length == 0
            || descriptor.length != spec.piece_length
            || spec.allocation_bytes < spec.piece_length
            || max_read_size == 0
        {
            return ChildCreation::Rejected(FfiError::Contract("invalid native Child bounds"));
        }
        let ids = match jetty.try_borrow() {
            Ok(jetty) => jetty.local_ids(),
            Err(_) => return ChildCreation::Rejected(FfiError::Contract("shared Jetty is busy")),
        };
        match ids {
            Ok((id, _)) if id == spec.jetty_id => {}
            Ok(_) => {
                return ChildCreation::Rejected(FfiError::Contract("Child Jetty identity mismatch"))
            }
            Err(error) => return ChildCreation::Rejected(error),
        }
        let (local, allocation_error) =
            match SegmentHandle::create_read_buffer(runtime, spec.allocation_bytes, alignment) {
                ReadBufferCreation::Ready(local) => (local, None),
                ReadBufferCreation::Uncertain { buffer, error } => (buffer, Some(error)),
                ReadBufferCreation::Rejected(FfiError::NullHandle) => {
                    // Broken shim contract: preserve guards and shared native
                    // owners along with the manager's ownerless reservation.
                    std::mem::forget((jetty, target, keepalive));
                    return ChildCreation::Lost(FfiError::NullHandle);
                }
                ReadBufferCreation::Rejected(error) => return ChildCreation::Rejected(error),
            };
        let mut owner = Self {
            jetty,
            target,
            local,
            remote: None,
            import_uncertain: false,
            _keepalive: keepalive,
        };
        if let Some(error) = allocation_error {
            return ChildCreation::Uncertain {
                resources: owner,
                error,
            };
        }
        match owner
            .target
            .import_read_segment(descriptor, token, max_read_size)
        {
            Ok(remote) => {
                owner.remote = Some(remote);
                ChildCreation::Ready(owner)
            }
            Err(error) => {
                // The import API returns no retained owner on failure; provider
                // rollback must be validated before enabling this factory.
                if error == FfiError::NullHandle {
                    owner.import_uncertain = true;
                    return ChildCreation::Uncertain {
                        resources: owner,
                        error,
                    };
                }
                match owner.local.close() {
                    Ok(()) => ChildCreation::Rejected(error),
                    Err(cleanup_error) => ChildCreation::Uncertain {
                        resources: owner,
                        error: cleanup_error,
                    },
                }
            }
        }
    }
}

impl<K> ChildResources for NativeChild<K> {
    type Wr = ReadWrHandle;
    fn post(&mut self, request: &ReadRequest) -> Result<ChildPost<Self::Wr>, FfiError> {
        // SAFETY: Exclusive ownership and admission are required by construction;
        // ChildOwner issues disjoint sequential ranges and retains every accepted WR.
        let Ok(mut jetty) = self.jetty.try_borrow_mut() else {
            return Ok(ChildPost::Rejected(FfiError::Contract(
                "shared Jetty is busy",
            )));
        };
        let Some(remote) = self.remote.as_ref() else {
            return Ok(ChildPost::Rejected(FfiError::Contract(
                "READ import missing",
            )));
        };
        unsafe { jetty.post_read(&self.target, &self.local, remote, request) }.map(
            |post| match post {
                ReadPost::Posted(wr) => ChildPost::Posted(wr),
                ReadPost::Rejected(error) => ChildPost::Rejected(error),
                ReadPost::Uncertain { wr, error } => ChildPost::Uncertain(wr, error),
            },
        )
    }
    unsafe fn complete(&mut self, wr: Self::Wr) {
        // SAFETY: Caller validates native retirement and exact identity.
        unsafe { wr.complete() };
    }
    fn unimport(&mut self) -> Result<(), FfiError> {
        if self.import_uncertain {
            return Err(FfiError::Contract("READ import ownership unknown"));
        }
        if let Some(remote) = self.remote.as_mut() {
            remote.close()?;
        }
        self.remote = None;
        Ok(())
    }
    fn close_buffer(&mut self) -> Result<(), FfiError> {
        self.local.close()
    }
}

struct Pending<W> {
    length: u32,
    wr: W,
}
pub(crate) struct ChildOwner<R: ChildResources> {
    id: ReadOwnerId,
    jetty: u32,
    piece_length: u64,
    posted_bytes: u64,
    max_outstanding: usize,
    stopped: bool,
    failed: bool,
    // A broken shim success-without-handle cannot be resolved by ordinary CQEs.
    lost_handle: bool,
    imported: bool,
    closed: bool,
    pending: BTreeMap<u64, Pending<R::Wr>>,
    resources: ManuallyDrop<R>,
}
impl<R: ChildResources> ChildOwner<R> {
    /// # Safety
    /// id must refer to the destination reservation charging these resources.
    /// piece_length must match both validated ranges; jetty is the actual native
    /// endpoint identity. R owns exclusive memory, and no Storage consumer exists.
    pub(crate) unsafe fn new(
        id: ReadOwnerId,
        jetty: u32,
        piece_length: u64,
        max_outstanding: usize,
        resources: R,
    ) -> Self {
        // Invalid configuration closes posting rather than dropping native owners.
        let invalid = piece_length == 0 || max_outstanding == 0;
        Self {
            id,
            jetty,
            piece_length,
            posted_bytes: 0,
            max_outstanding,
            stopped: invalid,
            failed: invalid,
            lost_handle: false,
            imported: true,
            closed: false,
            pending: BTreeMap::new(),
            resources: ManuallyDrop::new(resources),
        }
    }
    pub(crate) fn stop(&mut self) {
        self.stopped = true;
    }
    pub(crate) fn outstanding(&self) -> usize {
        self.pending.len()
    }
    pub(crate) fn jetty(&self) -> u32 {
        self.jetty
    }
    pub(crate) fn read_succeeded(&self) -> bool {
        !self.failed
            && !self.lost_handle
            && self.posted_bytes == self.piece_length
            && self.pending.is_empty()
    }
    pub(crate) fn post(&mut self, length: u32) -> Result<u64, FfiError> {
        match self.post_routed(length) {
            ChildPostOutcome::Posted(context) => Ok(context),
            ChildPostOutcome::Uncertain { error, .. } | ChildPostOutcome::Rejected(error) => {
                Err(error)
            }
        }
    }
    pub(crate) fn post_routed(&mut self, length: u32) -> ChildPostOutcome {
        if self.stopped
            || self.closed
            || !self.imported
            || length == 0
            || u64::from(length) > self.piece_length - self.posted_bytes
            || self.pending.len() >= self.max_outstanding
        {
            return ChildPostOutcome::Rejected(FfiError::Contract("READ post admission rejected"));
        }
        let sequence =
            match NEXT_READ_CONTEXT
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            {
                Ok(sequence) => sequence,
                Err(_) => {
                    return ChildPostOutcome::Rejected(FfiError::Contract("READ context exhausted"))
                }
            };
        let context = READ_CONTEXT_PREFIX | u64::from(sequence);
        let request = ReadRequest {
            local_offset: self.posted_bytes,
            remote_offset: self.posted_bytes,
            length,
            user_ctx: context,
        };
        let (wr, error) = match self.resources.post(&request) {
            Ok(ChildPost::Posted(wr)) => (wr, None),
            Ok(ChildPost::Uncertain(wr, error)) => (wr, Some(error)),
            Ok(ChildPost::Rejected(error)) => {
                self.failed = true;
                self.stop();
                return ChildPostOutcome::Rejected(error);
            }
            Err(error) => {
                self.failed = true;
                self.stop();
                // Includes malformed success without a handle. Conservatively
                // retain the entire bundle; no implicit reset on timeout.
                self.lost_handle = true;
                return ChildPostOutcome::Rejected(error);
            }
        };
        self.pending.insert(context, Pending { length, wr });
        self.posted_bytes += u64::from(length);
        if let Some(error) = error {
            self.failed = true;
            self.stop();
            return ChildPostOutcome::Uncertain { context, error };
        }
        ChildPostOutcome::Posted(context)
    }
    pub(crate) fn complete(&mut self, record: ReadRetired) -> Result<(), FfiError> {
        if record.owner != self.id
            || record.jetty != self.jetty
            || self
                .pending
                .get(&record.context)
                .is_none_or(|wr| wr.length != record.length)
        {
            self.failed = true;
            self.stop();
            return Err(FfiError::Contract("READ completion identity mismatch"));
        }
        let pending = self
            .pending
            .remove(&record.context)
            .expect("matched pending WR");
        // SAFETY: ReadRetired requires provider evidence; all identity fields match.
        unsafe { self.resources.complete(pending.wr) };
        if !record.success {
            self.failed = true;
            self.stop();
        }
        Ok(())
    }
    /// For registry.reap_with after retirement/quarantine. No successful Piece is
    /// published here: this is cleanup only, including cancellation and shutdown.
    pub(crate) fn reap(&mut self) -> Result<ReapDecision, FfiError> {
        self.stop();
        if self.lost_handle || !self.pending.is_empty() {
            return Ok(ReapDecision::Pending);
        }
        if self.imported {
            self.resources.unimport()?;
            self.imported = false;
        }
        if !self.closed {
            self.resources.close_buffer()?;
            // SAFETY: No WRs/consumers, import and destination closed successfully.
            unsafe { ManuallyDrop::drop(&mut self.resources) };
            self.closed = true;
        }
        // SAFETY: Entire Child bundle is closed. No remote source owned here.
        Ok(ReapDecision::Retired(unsafe {
            VerifiedRetirement::new(self.id)
        }))
    }
}
// ManuallyDrop retains resources on accidental Drop. Pending native WR handles
// also retain their shim dependencies; the registry must remain alive for retries.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::read_owner::{
        ReadBudget, ReadCapacity, ReadDirection, ReadOwnerRegistry, ReadPeer,
    };
    use std::{cell::RefCell, rc::Rc};
    #[derive(Default)]
    struct Trace {
        contexts: Vec<u64>,
        events: Vec<&'static str>,
        mode: u8,
        fail_close: bool,
        fail_import: bool,
    }
    struct Mock(Rc<RefCell<Trace>>);
    impl ChildResources for Mock {
        type Wr = u64;
        fn post(&mut self, r: &ReadRequest) -> Result<ChildPost<u64>, FfiError> {
            let mut t = self.0.borrow_mut();
            t.contexts.push(r.user_ctx);
            t.events.push("post");
            assert_eq!(r.local_offset, r.remote_offset);
            Ok(match t.mode {
                1 => ChildPost::Uncertain(r.user_ctx, FfiError::Status(-1)),
                2 => ChildPost::Rejected(FfiError::Status(-2)),
                3 => return Err(FfiError::NullHandle),
                _ => ChildPost::Posted(r.user_ctx),
            })
        }
        unsafe fn complete(&mut self, _: u64) {
            self.0.borrow_mut().events.push("complete");
        }
        fn unimport(&mut self) -> Result<(), FfiError> {
            let mut t = self.0.borrow_mut();
            t.events.push("unimport");
            if std::mem::take(&mut t.fail_import) {
                return Err(FfiError::Status(-3));
            }
            Ok(())
        }
        fn close_buffer(&mut self) -> Result<(), FfiError> {
            let mut t = self.0.borrow_mut();
            t.events.push("buffer-close");
            if std::mem::take(&mut t.fail_close) {
                return Err(FfiError::Status(-4));
            }
            Ok(())
        }
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.0.borrow_mut().events.push("drop");
        }
    }
    fn setup() -> (
        ReadOwnerRegistry<ChildOwner<Mock>>,
        ReadOwnerId,
        Rc<RefCell<Trace>>,
    ) {
        let cap = |bytes, entries| ReadCapacity { bytes, entries };
        let mut registry = ReadOwnerRegistry::new(ReadBudget {
            total: cap(128, 4),
            source: cap(64, 2),
            destination: cap(64, 2),
            per_peer_source: cap(64, 2),
            per_peer_destination: cap(64, 2),
            quarantine: cap(64, 2),
        })
        .unwrap();
        let peer = ReadPeer {
            id: 1,
            generation: 1,
        };
        registry.activate_peer(peer).unwrap();
        let id = registry
            .reserve(peer, ReadDirection::Destination, 8)
            .unwrap();
        let trace = Rc::new(RefCell::new(Trace::default()));
        // SAFETY: Mock owns no native memory; matching reservation exists.
        let owner = unsafe { ChildOwner::new(id, 42, 8, 2, Mock(trace.clone())) };
        assert!(registry.attach(id, owner).is_ok());
        (registry, id, trace)
    }
    fn completion(id: ReadOwnerId, context: u64, success: bool) -> ReadRetired {
        // SAFETY: Mock WRs have no DMA and are immediately retired.
        unsafe { ReadRetired::new(id, 42, context, 4, success) }
    }
    #[test]
    fn out_of_order_completions_hold_buffer_and_budget_until_cleanup() {
        let (mut registry, id, trace) = setup();
        let owner = registry.active_owner(id).unwrap();
        let first = owner.post(4).unwrap();
        let second = owner.post(4).unwrap();
        assert!(owner.post(1).is_err());
        owner.complete(completion(id, second, true)).unwrap();
        assert!(!owner.read_succeeded());
        registry.retire(id).unwrap();
        assert_eq!(registry.reap_with(id, |o| o.reap()), Ok(false));
        assert_eq!(registry.usage().bytes, 8);
        assert_eq!(
            registry.reap_with(id, |o| {
                o.complete(completion(id, first, true))?;
                assert!(o.read_succeeded());
                o.reap()
            }),
            Ok(true)
        );
        assert!(registry.drained());
        assert_eq!(
            trace.borrow().events,
            [
                "post",
                "post",
                "complete",
                "complete",
                "unimport",
                "buffer-close",
                "drop"
            ]
        );
    }
    #[test]
    fn uncertain_post_stops_new_work_but_retains_wr_until_matching_retirement() {
        let (mut registry, id, trace) = setup();
        trace.borrow_mut().mode = 1;
        let owner = registry.active_owner(id).unwrap();
        assert!(owner.post(4).is_err());
        assert_eq!(owner.outstanding(), 1);
        assert!(owner.post(4).is_err());
        let context = trace.borrow().contexts[0];
        registry.begin_shutdown();
        assert_eq!(registry.reap_with(id, |o| o.reap()), Ok(false));
        assert_eq!(
            registry.reap_with(id, |o| {
                o.complete(completion(id, context, false))?;
                assert!(!o.read_succeeded());
                o.reap()
            }),
            Ok(true)
        );
    }
    #[test]
    fn malformed_and_duplicate_completions_never_consume_another_wr() {
        let (mut registry, id, trace) = setup();
        let owner = registry.active_owner(id).unwrap();
        let a = owner.post(4).unwrap();
        let b = owner.post(4).unwrap();
        let (mut other_registry, other, _) = setup();
        other_registry.retire(other).unwrap();
        assert_eq!(other_registry.reap_with(other, |o| o.reap()), Ok(true));
        for (identity, jetty, context, length) in [
            (other, 42, a, 4),
            (id, 99, a, 4),
            (id, 42, a, 3),
            (id, 42, u64::MAX, 4),
        ] {
            let record = unsafe { ReadRetired::new(identity, jetty, context, length, true) };
            assert!(owner.complete(record).is_err());
            assert_eq!(owner.outstanding(), 2);
        }
        owner.complete(completion(id, a, true)).unwrap();
        assert!(owner.complete(completion(id, a, true)).is_err());
        assert_eq!(owner.outstanding(), 1);
        owner.complete(completion(id, b, true)).unwrap();
        assert!(!owner.read_succeeded());
        registry.retire(id).unwrap();
        assert_eq!(registry.reap_with(id, |o| o.reap()), Ok(true));
        assert_eq!(
            trace
                .borrow()
                .events
                .iter()
                .filter(|e| **e == "complete")
                .count(),
            2
        );
    }
    #[test]
    fn cleanup_retries_preserve_budget_and_do_not_repeat_successful_unimport() {
        let (mut registry, id, trace) = setup();
        trace.borrow_mut().fail_import = true;
        trace.borrow_mut().fail_close = true;
        registry.retire(id).unwrap();
        for _ in 0..2 {
            assert!(registry.reap_with(id, |o| o.reap()).is_err());
            assert_eq!(registry.usage().bytes, 8);
        }
        assert_eq!(registry.reap_with(id, |o| o.reap()), Ok(true));
        assert_eq!(
            trace.borrow().events,
            [
                "unimport",
                "unimport",
                "buffer-close",
                "buffer-close",
                "drop"
            ]
        );
    }
    #[test]
    fn known_rejection_cleans_up_but_missing_handle_stays_isolated() {
        let (mut registry, id, trace) = setup();
        trace.borrow_mut().mode = 2;
        assert!(registry.active_owner(id).unwrap().post(4).is_err());
        registry.retire(id).unwrap();
        assert_eq!(registry.reap_with(id, |o| o.reap()), Ok(true));
        let (mut registry, id, trace) = setup();
        trace.borrow_mut().mode = 3;
        assert!(registry.active_owner(id).unwrap().post(4).is_err());
        registry.retire(id).unwrap();
        assert_eq!(registry.reap_with(id, |o| o.reap()), Ok(false));
        assert_eq!(registry.usage().bytes, 8);
        assert_eq!(trace.borrow().events, ["post"]);
        // Reclaim only this test's known resource-free mock. Production has no
        // API to clear lost_handle or infer retirement from a timeout.
        assert_eq!(
            registry.reap_with(id, |o| {
                o.lost_handle = false;
                o.reap()
            }),
            Ok(true)
        );
    }
}
