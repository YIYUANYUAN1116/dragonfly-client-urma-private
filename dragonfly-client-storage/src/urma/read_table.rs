//! One budget, peer lifecycle, and CQE route table for both READ directions.
//! Shared by Fabric progress, source workers and Storage lease publication.
use super::{
    ffi::{
        read::{
            source::{ReadBacking, ReadSourceStages},
            ReadDescriptor, ReadToken,
        },
        FfiError, NativeRuntime,
    },
    read_child_owner::{
        is_read_context, ChildOwner, ChildPostOutcome, ChildProgress, ChildResources, LeaseSpan,
        ReadChildUpdate, ReadRetired,
    },
    read_registry::{
        OwnerError, QuarantineReason, ReadBudget, ReadDirection, ReadOwnerId, ReadOwnerRegistry,
        ReadPeer, ReadUsage, ReapDecision, ReapError,
    },
    read_source_owner::{
        SourceAdmission, SourceAdmissionError, SourceOwner, SourceRevoked, SourceSlot,
        UnregisterPermit,
    },
};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use tokio::sync::watch;

fn cache_owner_error(error: super::read_source_cache::CacheError) -> OwnerError {
    use super::read_source_cache::CacheError;
    match error {
        CacheError::Registry(error) => error,
        CacheError::Missing => OwnerError::UnknownOwner,
        CacheError::InvalidState => OwnerError::NotActive,
        CacheError::IdentityMismatch => OwnerError::WrongProof,
        CacheError::Shutdown => OwnerError::Shutdown,
        CacheError::Storage(_) => OwnerError::InvalidSize,
    }
}

#[derive(Clone, Copy)]
struct ReadRoute {
    owner: ReadOwnerId,
    jetty: u32,
    length: u32,
}

enum ReadBundle<K, R: ChildResources> {
    Source(SourceOwner<K>),
    WorkerSource(usize),
    Child(ChildOwner<R>),
}
impl<K, R: ChildResources> SourceSlot for ReadBundle<K, R> {
    type Keepalive = K;
    fn from_source(source: SourceOwner<K>) -> Self {
        Self::Source(source)
    }
    fn source_mut(&mut self) -> Result<&mut SourceOwner<K>, FfiError> {
        match self {
            Self::Source(source) => Ok(source),
            Self::Child(_) | Self::WorkerSource(_) => {
                Err(FfiError::Contract("expected source owner"))
            }
        }
    }
}
impl<K, R: ChildResources> ReadBundle<K, R> {
    fn child_mut(&mut self) -> Result<&mut ChildOwner<R>, FfiError> {
        match self {
            Self::Child(child) => Ok(child),
            Self::Source(_) | Self::WorkerSource(_) => {
                Err(FfiError::Contract("expected Child owner"))
            }
        }
    }
}

pub(crate) enum ChildCreation<R> {
    Ready(R),
    /// Every partially created resource was successfully closed; no DMA exists.
    Rejected(FfiError),
    /// R retains all partial resources and supports their cleanup.
    Uncertain {
        resources: R,
        error: FfiError,
    },
    /// Resource ownership cannot be reconstructed. Keep the reservation forever
    /// unless a future explicit provider recovery path proves it safe to release.
    Lost(FfiError),
}
#[derive(Clone, Copy)]
pub(crate) struct ChildSpec {
    pub(crate) allocation_bytes: u64,
    pub(crate) piece_length: u64,
    pub(crate) jetty_id: u32,
    pub(crate) max_outstanding: usize,
}
#[derive(Debug, PartialEq)]
pub(crate) enum ReadDispatchError {
    Registry(OwnerError),
    Native(FfiError),
}
impl From<OwnerError> for ReadDispatchError {
    fn from(e: OwnerError) -> Self {
        Self::Registry(e)
    }
}
impl From<FfiError> for ReadDispatchError {
    fn from(e: FfiError) -> Self {
        Self::Native(e)
    }
}

pub(crate) enum ChildAdmission {
    Ready(ReadOwnerId),
    Rejected(ReadDispatchError),
    Quarantined { id: ReadOwnerId, error: FfiError },
}

pub(crate) struct ReadOwners<K, R: ChildResources> {
    registry: ReadOwnerRegistry<ReadBundle<K, R>>,
    source_cache: super::read_source_cache::ReadSourceCache,
    routes: BTreeMap<u64, ReadRoute>,
    // Only IDs are queued; resources and WR permits stay with their owners.
    blocked_children: BTreeSet<ReadOwnerId>,
    // Channels own snapshots only, never native resources or budget. A dropped
    // receiver cannot cancel DMA or release an owner.
    progress_watchers: BTreeMap<ReadOwnerId, watch::Sender<ReadChildUpdate>>,
}
impl<K, R: ChildResources> ReadOwners<K, R> {
    pub(crate) fn new(budget: ReadBudget) -> Result<Self, OwnerError> {
        Ok(Self {
            registry: ReadOwnerRegistry::new(budget)?,
            source_cache: super::read_source_cache::ReadSourceCache::new(),
            routes: BTreeMap::new(),
            blocked_children: BTreeSet::new(),
            progress_watchers: BTreeMap::new(),
        })
    }
    pub(crate) fn activate_peer(&mut self, peer: ReadPeer) -> Result<(), OwnerError> {
        self.registry.activate_peer(peer)
    }
    pub(crate) fn contains(&self, id: ReadOwnerId) -> bool {
        self.registry.state(id).is_ok()
    }
    pub(crate) fn usage(&self) -> ReadUsage {
        self.registry.usage()
    }
    pub(crate) fn peer_drained(&self, peer: ReadPeer) -> bool {
        self.registry.peer_usage(peer).entries == 0
    }
    pub(crate) fn drained(&self) -> bool {
        self.routes.is_empty() && self.registry.drained()
    }
    pub(crate) fn begin_shutdown(&mut self) {
        if let Err(error) = self.source_cache.begin_shutdown(&mut self.registry) {
            tracing::error!(%error, "source cache shutdown incomplete; resources retained");
        }
        self.registry.begin_shutdown();
        self.interrupt_waiters();
    }
    pub(crate) fn drain_peer(&mut self, peer: ReadPeer) -> Result<(), OwnerError> {
        self.registry.drain_peer(peer)?;
        self.blocked_children.retain(|id| id.peer() != peer);
        for (id, tx) in &self.progress_watchers {
            if id.peer() == peer {
                tx.send_modify(|update| {
                    update.interrupted = true;
                    update.notified_at = std::time::Instant::now();
                });
            }
        }
        Ok(())
    }
    pub(crate) fn retire(&mut self, id: ReadOwnerId) -> Result<(), OwnerError> {
        if self.source_cache.contains(id) {
            return self
                .source_cache
                .retire(&mut self.registry, id)
                .map_err(cache_owner_error);
        }
        self.registry.retire(id)?;
        self.blocked_children.remove(&id);
        self.notify_child(id, true);
        Ok(())
    }

    pub(crate) fn interrupt_waiters(&mut self) {
        self.blocked_children.clear();
        for tx in self.progress_watchers.values() {
            tx.send_modify(|update| {
                update.interrupted = true;
                update.notified_at = std::time::Instant::now();
            });
        }
    }

    pub(crate) fn subscribe_child_progress(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<watch::Receiver<ReadChildUpdate>, ReadDispatchError> {
        // Validate identity even if a sender already exists.
        let child = self.registry.active_owner(id)?.child_mut()?;
        let update = ReadChildUpdate {
            progress: child.progress(),
            timing: child.timing(),
            notified_at: std::time::Instant::now(),
            interrupted: false,
        };
        Ok(self
            .progress_watchers
            .entry(id)
            .or_insert_with(|| watch::channel(update).0)
            .subscribe())
    }

    fn notify_child(&mut self, id: ReadOwnerId, interrupted: bool) {
        let Some(tx) = self.progress_watchers.get(&id) else {
            return;
        };
        let Ok(bundle) = self.registry.retained_owner(id) else {
            return;
        };
        let Ok(child) = bundle.child_mut() else {
            return;
        };
        let already_interrupted = tx.borrow().interrupted;
        tx.send_replace(ReadChildUpdate {
            progress: child.progress(),
            timing: child.timing(),
            notified_at: std::time::Instant::now(),
            interrupted: already_interrupted || interrupted,
        });
    }

    fn wake_credit_waiters(&mut self) {
        // Any retired WR can free the process-wide JFS capacity, including a WR
        // from another peer. Watch snapshots retain wakeups until async drivers
        // observe them; exhausted drivers register again without busy polling.
        for id in std::mem::take(&mut self.blocked_children) {
            self.notify_child(id, false);
        }
    }

    pub(crate) fn record_post_command_wait(
        &mut self,
        id: ReadOwnerId,
        admission_ns: u64,
        queue_ns: u64,
    ) -> Result<(), ReadDispatchError> {
        self.registry
            .retained_owner(id)?
            .child_mut()?
            .record_post_command_wait(admission_ns, queue_ns);
        Ok(())
    }

    // Worker sources keep native resources on their worker; the registry owns
    // identity, peer lifecycle and budget until an exact cleanup result arrives.
    pub(crate) fn reserve_worker_source(
        &mut self,
        peer: ReadPeer,
        bytes: u64,
    ) -> Result<ReadOwnerId, OwnerError> {
        self.registry.reserve(peer, ReadDirection::Source, bytes)
    }

    /// Owner-side entry for the upcoming cached registration command. It does
    /// not dispatch native work. Only register=true may dispatch; failures to
    /// dispatch must resolve through reject_worker_source, not drop the claim.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "cached Fabric command follows the Region Offer change"
        )
    )]
    pub(crate) fn claim_cached_worker_source(
        &mut self,
        request: super::read_source_cache::CacheRequest<'_>,
        now: std::time::Instant,
    ) -> Result<super::read_source_cache::CacheClaim, super::read_source_cache::CacheError> {
        let claim = self.source_cache.claim(&mut self.registry, request, now)?;
        if claim.register {
            self.source_cache.start_registration(claim.source)?;
        }
        Ok(claim)
    }

    pub(crate) fn reject_worker_source(&mut self, id: ReadOwnerId) -> Result<(), OwnerError> {
        if self.source_cache.contains(id) {
            // SAFETY: this existing entry is only used for a known native
            // rejection or a job that failed dispatch before native execution.
            return unsafe {
                self.source_cache
                    .registration_rejected(&mut self.registry, id)
            }
            .map_err(cache_owner_error);
        }
        self.registry.release_unused_reservation(id)
    }
    pub(crate) fn attach_worker_source(
        &mut self,
        id: ReadOwnerId,
        worker: usize,
        uncertain: bool,
    ) -> Result<bool, OwnerError> {
        if self.source_cache.contains(id) {
            self.source_cache
                .registered(
                    &mut self.registry,
                    id,
                    ReadBundle::WorkerSource(worker),
                    uncertain,
                )
                .map_err(|(error, _)| cache_owner_error(error))?;
            return Ok(self.registry.state(id)? == super::read_registry::OwnerState::Active);
        }
        self.registry
            .attach(id, ReadBundle::WorkerSource(worker))
            .map_err(|(error, _)| error)?;
        if uncertain {
            self.registry
                .quarantine(id, QuarantineReason::RegistrationUncertain)?;
        }
        Ok(self.registry.state(id)? == super::read_registry::OwnerState::Active)
    }
    pub(crate) fn worker_source(&mut self, id: ReadOwnerId) -> Result<usize, OwnerError> {
        if self.source_cache.contains(id) {
            self.source_cache
                .check_cleanup(&self.registry, id)
                .map_err(cache_owner_error)?;
        }
        // This runs before sending native cleanup to a worker. Checking only
        // when its completion arrives would allow unregister during another
        // peer's READ even though the registry later refused to release bytes.
        self.registry.check_source_cleanup(id)?;
        if !matches!(
            self.registry.state(id)?,
            super::read_registry::OwnerState::Retiring
                | super::read_registry::OwnerState::Quarantined(_)
        ) {
            return Err(OwnerError::NotRetiring);
        }
        match self.registry.retained_owner(id)? {
            ReadBundle::WorkerSource(worker) => Ok(*worker),
            _ => Err(OwnerError::OwnerMissing),
        }
    }
    pub(crate) fn complete_worker_cleanup(
        &mut self,
        id: ReadOwnerId,
        result: Result<ReapDecision, FfiError>,
    ) -> Result<bool, ReapError<FfiError>> {
        if self.source_cache.contains(id) {
            self.source_cache
                .check_cleanup(&self.registry, id)
                .map_err(|error| ReapError::Registry(cache_owner_error(error)))?;
        }
        let result = self.registry.reap_with(id, |bundle| match bundle {
            ReadBundle::WorkerSource(_) => result,
            _ => Err(FfiError::Contract(
                "worker cleanup source identity mismatch",
            )),
        });
        if self.source_cache.contains(id) {
            self.source_cache
                .observe_cleanup(&self.registry, id)
                .map_err(|error| ReapError::Registry(cache_owner_error(error)))?;
        }
        result
    }

    /// # Safety
    /// Same immutable backing and provider requirements as ReadSource::register.
    pub(crate) unsafe fn register_source(
        &mut self,
        peer: ReadPeer,
        runtime: &mut NativeRuntime,
        backing: ReadBacking<K>,
        token: &ReadToken,
    ) -> SourceAdmission<K> {
        // SAFETY: Caller provides native guarantees, shared registry admits bytes.
        unsafe { self.registry.register_source(peer, runtime, backing, token) }
    }
    pub(crate) fn source_descriptor(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<ReadDescriptor, SourceAdmissionError> {
        self.registry.source_descriptor(id)
    }
    /// Diagnostic-only register sub-phase timings for one admitted source.
    pub(crate) fn source_register_stages(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<ReadSourceStages, SourceAdmissionError> {
        self.registry.source_register_stages(id)
    }
    pub(crate) fn reap_source(
        &mut self,
        id: ReadOwnerId,
        permit: &UnregisterPermit,
        revoked: Option<&SourceRevoked>,
    ) -> Result<bool, ReapError<FfiError>> {
        if self.source_cache.contains(id) {
            self.source_cache
                .check_cleanup(&self.registry, id)
                .map_err(|error| ReapError::Registry(cache_owner_error(error)))?;
        }
        let result = self.registry.reap_source(id, permit, revoked);
        if self.source_cache.contains(id) {
            self.source_cache
                .observe_cleanup(&self.registry, id)
                .map_err(|error| ReapError::Registry(cache_owner_error(error)))?;
        }
        result
    }

    /// Reserve before invoking any allocation/import factory; execute synchronously
    /// on the owner thread. Returned failures retain partial resources and charges.
    /// # Safety
    /// Factory must charge actual allocation size, enforce exclusive Piece bounds,
    /// retain all partial native dependencies, and accurately classify rejection.
    /// Native READ/provider and per-WR JFS admission requirements still apply.
    pub(crate) unsafe fn create_child(
        &mut self,
        peer: ReadPeer,
        spec: ChildSpec,
        factory: impl FnOnce() -> ChildCreation<R>,
    ) -> ChildAdmission {
        if spec.piece_length == 0
            || spec.piece_length > spec.allocation_bytes
            || spec.max_outstanding == 0
            || spec.jetty_id == 0
        {
            return ChildAdmission::Rejected(ReadDispatchError::Native(FfiError::Contract(
                "invalid Child allocation specification",
            )));
        }
        let id =
            match self
                .registry
                .reserve(peer, ReadDirection::Destination, spec.allocation_bytes)
            {
                Ok(id) => id,
                Err(error) => return ChildAdmission::Rejected(error.into()),
            };
        let (resources, error) = match factory() {
            ChildCreation::Ready(resources) => (resources, None),
            ChildCreation::Uncertain { resources, error } => (resources, Some(error)),
            ChildCreation::Rejected(error) => {
                self.registry
                    .release_unused_reservation(id)
                    .expect("synchronous reservation");
                return ChildAdmission::Rejected(error.into());
            }
            ChildCreation::Lost(error) => {
                self.registry
                    .quarantine(id, QuarantineReason::RegistrationUncertain)
                    .expect("synchronous reservation");
                return ChildAdmission::Quarantined { id, error };
            }
        };
        // SAFETY: Factory guarantees exact owned ranges, reservation already held.
        let child = unsafe {
            ChildOwner::new(
                id,
                spec.jetty_id,
                spec.piece_length,
                spec.max_outstanding,
                resources,
            )
        };
        if let Err((_, bundle)) = self.registry.attach(id, ReadBundle::Child(child)) {
            std::mem::forget(bundle);
            panic!("Child reservation lost during synchronous creation");
        }
        if let Some(error) = error {
            self.registry
                .quarantine(id, QuarantineReason::RegistrationUncertain)
                .expect("attached Child");
            ChildAdmission::Quarantined { id, error }
        } else {
            ChildAdmission::Ready(id)
        }
    }
    #[cfg(test)]
    pub(crate) fn post(&mut self, id: ReadOwnerId, length: u32) -> Result<u64, ReadDispatchError> {
        self.try_post(id, length)?
            .ok_or_else(|| FfiError::Contract("READ post temporarily blocked").into())
    }

    fn try_post(&mut self, id: ReadOwnerId, length: u32) -> Result<Option<u64>, ReadDispatchError> {
        self.blocked_children.remove(&id);

        let outcome = self
            .registry
            .active_owner(id)?
            .child_mut()?
            .post_routed(length);
        let (context, error) = match outcome {
            ChildPostOutcome::Posted(context) => (Some(context), None),
            ChildPostOutcome::Blocked => {
                self.blocked_children.insert(id);
                return Ok(None);
            }
            ChildPostOutcome::Uncertain { context, error } => (Some(context), Some(error)),
            ChildPostOutcome::Rejected(error) => (None, Some(error)),
        };
        if let Some(context) = context {
            let jetty = self.registry.retained_owner(id)?.child_mut()?.jetty();
            match self.routes.entry(context) {
                Entry::Vacant(entry) => {
                    entry.insert(ReadRoute {
                        owner: id,
                        jetty,
                        length,
                    });
                }
                Entry::Occupied(_) => {
                    self.registry.quarantine(id, QuarantineReason::WrongProof)?;
                    return Err(FfiError::Contract("duplicate READ completion context").into());
                }
            }
        }
        if let Some(error) = error {
            // Conservative policy: even local admission rejection closes this
            // attempt. An uncertain accepted WR remains routed while quarantined.
            self.registry
                .quarantine(id, QuarantineReason::PostUncertain)?;
            self.notify_child(id, true);
            return Err(error.into());
        }
        Ok(Some(context.expect("successful READ post has a context")))
    }

    /// Posts one scheduling batch without returning to the async facade between
    /// WRs. Capacity exhaustion returns the posted prefix (possibly zero) and
    /// waits for another owner's CQE; it does not quarantine. Native failures
    /// still retain earlier contexts and use the existing cleanup path.
    pub(crate) fn post_batch(
        &mut self,
        id: ReadOwnerId,
        lengths: &[u32],
    ) -> Result<usize, ReadDispatchError> {
        if lengths.is_empty() {
            return Err(FfiError::Contract("empty READ post batch").into());
        }
        let mut posted = 0usize;
        for &length in lengths {
            if self.try_post(id, length)?.is_none() {
                break;
            }
            posted += 1;
        }
        // Do not notify on a zero post: the driver must sleep until capacity is
        // returned or its lifecycle is interrupted, rather than retrying itself.
        if posted != 0 {
            self.notify_child(id, false);
        }
        Ok(posted)
    }

    pub(crate) fn outstanding_completions(&self) -> usize {
        self.routes.len()
    }

    pub(crate) fn child_progress(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<ChildProgress, ReadDispatchError> {
        Ok(self.registry.retained_owner(id)?.child_mut()?.progress())
    }

    /// Decode a send-JFC CQE using the context route installed at post time.
    /// The real provider reports READ with opcode=0 and completion_len=0, so
    /// neither field participates in identity or length validation.
    pub(crate) fn route_completion(
        &mut self,
        record: super::ffi::CompletionRecord,
        recv_queue: bool,
    ) -> Option<Result<(), ReadDispatchError>> {
        if !record.user_ctx_valid || !is_read_context(record.user_ctx) {
            return None;
        }
        let Some(route) = self.routes.get(&record.user_ctx).copied() else {
            return Some(Err(
                FfiError::Contract("unknown or duplicate READ CQE").into()
            ));
        };
        if recv_queue
            || record.event_kind != super::ffi::CompletionEventKind::WorkRequest
            || record.is_recv
            || !record.is_jetty
            || record.local_id != route.jetty
        {
            let error = self
                .registry
                .quarantine(route.owner, QuarantineReason::WrongProof)
                .map_or_else(ReadDispatchError::Registry, |_| {
                    ReadDispatchError::Native(FfiError::Contract(
                        "READ CQE queue or native identity mismatch",
                    ))
                });
            self.notify_child(route.owner, true);
            return Some(Err(error));
        }
        // SAFETY: A route exists only after the matching native post retained
        // its WR. Provider probe established that a work-request event on the
        // send JFC with valid user_ctx retires that READ; status selects success.
        let retired = unsafe {
            ReadRetired::new(
                route.owner,
                route.jetty,
                record.user_ctx,
                route.length,
                record.status == 0,
            )
            .observed_at(record.observed_at)
        };
        Some(self.complete(route.owner, retired))
    }
    pub(crate) fn complete(
        &mut self,
        id: ReadOwnerId,
        completion: ReadRetired,
    ) -> Result<(), ReadDispatchError> {
        let context = completion.context();
        let result = self
            .registry
            .retained_owner(id)?
            .child_mut()?
            .complete(completion);
        if result.is_err() {
            self.registry.quarantine(id, QuarantineReason::WrongProof)?;
        } else {
            self.routes.remove(&context);
        }
        self.notify_child(id, result.is_err());
        if result.is_ok() {
            self.wake_credit_waiters();
        }
        result.map_err(Into::into)
    }
    pub(crate) fn reap_child(&mut self, id: ReadOwnerId) -> Result<bool, ReapError<FfiError>> {
        let result = self
            .registry
            .reap_with(id, |bundle| bundle.child_mut()?.reap());
        if matches!(result, Ok(true)) {
            self.blocked_children.remove(&id);
            self.progress_watchers.remove(&id);
        }
        result
    }

    /// First lease stage: stop posting and close the import while keeping the
    /// registered buffer and the full budget charge. The owner stays in the
    /// registry either way.
    pub(crate) fn drain_child_for_lease(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<(), ReadDispatchError> {
        let decision = self
            .registry
            .retained_owner(id)?
            .child_mut()?
            .drain_for_lease()?;
        match decision {
            ReapDecision::Pending => Ok(()),
            ReapDecision::Retired(_) => {
                Err(FfiError::Contract("lease drain must retain the Child owner").into())
            }
        }
    }

    /// Extracts the CPU span of the fully read registered destination buffer.
    /// The lease itself never leaves the owner thread; only the span crosses.
    pub(crate) fn publish_child_lease(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<LeaseSpan, ReadDispatchError> {
        self.registry
            .retained_owner(id)?
            .child_mut()?
            .publish_lease()
            .map_err(Into::into)
    }

    /// Final lease stage: close the published lease and complete the reap.
    /// Requires a retired (or quarantined) owner per registry rules.
    pub(crate) fn recycle_child_lease(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<bool, ReapError<FfiError>> {
        let result = self
            .registry
            .reap_with(id, |bundle| bundle.child_mut()?.recycle_lease());
        if matches!(result, Ok(true)) {
            self.blocked_children.remove(&id);
            self.progress_watchers.remove(&id);
        }
        result
    }
}

impl<K, R: ChildResources> super::completion::ReadCompletionSink for ReadOwners<K, R> {
    fn outstanding_read_completions(&self) -> usize {
        self.outstanding_completions()
    }

    fn try_route_read_completion(
        &mut self,
        record: super::ffi::CompletionRecord,
        recv_queue: bool,
    ) -> Option<super::Result<()>> {
        self.route_completion(record, recv_queue).map(|result| {
            result.map_err(|error| {
                super::Error::Protocol(format!("READ completion routing failed: {error:?}"))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ffi::read::ReadRequest, read_child_owner::ChildPost, read_registry::ReadCapacity,
    };
    use super::*;
    use std::{cell::Cell, rc::Rc};

    #[test]
    fn cached_worker_registration_shares_budget_and_blocks_native_cleanup_until_all_leases_end() {
        use super::super::{
            read_protocol::ReadTransferIdentity,
            read_registry::VerifiedRetirement,
            read_source_cache::{CacheRequest, CacheState},
        };
        use crate::{content::ReadSourceFile, rendezvous::PieceKind};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("task");
        std::fs::write(&path, vec![1; 64]).unwrap();
        let file = ReadSourceFile::open(&path).unwrap();
        let request = || CacheRequest {
            kind: PieceKind::Piece,
            task: "task",
            file: file.clone(),
            piece_length: 8,
            max_region_bytes: 64,
            piece_offset: 0,
            completed: &[0..64],
        };
        let (mut owners, _) = credited_setup(8, 4);
        let other = ReadPeer {
            id: 2,
            generation: 1,
        };
        owners.activate_peer(other).unwrap();
        let now = std::time::Instant::now();
        let first = owners.claim_cached_worker_source(request(), now).unwrap();
        let second = owners.claim_cached_worker_source(request(), now).unwrap();
        assert!(first.register);
        assert!(!second.register);
        assert_eq!(first.source, second.source);
        assert!(owners.attach_worker_source(first.source, 4, false).unwrap());
        assert_eq!(*second.updates.borrow(), CacheState::Ready);
        let transfer = ReadTransferIdentity {
            session_generation: 1,
            transfer_id: 1,
            metadata_generation: 1,
        };
        let a = owners
            .source_cache
            .acquire(
                &mut owners.registry,
                first.source,
                PEER,
                transfer,
                0..8,
                now,
            )
            .unwrap();
        let b = owners
            .source_cache
            .acquire(
                &mut owners.registry,
                first.source,
                other,
                transfer,
                8..16,
                now,
            )
            .unwrap();
        assert_eq!(owners.usage().source_bytes, 64);
        owners.retire(first.source).unwrap();
        assert_eq!(
            owners.worker_source(first.source),
            Err(OwnerError::SourceBusy)
        );
        owners
            .source_cache
            .abandon(&mut owners.registry, a, now)
            .unwrap();
        assert_eq!(
            owners.worker_source(first.source),
            Err(OwnerError::SourceBusy)
        );
        owners
            .source_cache
            .abandon(&mut owners.registry, b, now)
            .unwrap();
        assert_eq!(owners.worker_source(first.source), Ok(4));
        assert!(owners
            .complete_worker_cleanup(first.source, Err(FfiError::Status(-5)))
            .is_err());
        assert_eq!(*second.updates.borrow(), CacheState::Retained);
        assert_eq!(owners.usage().source_bytes, 64);
        assert_eq!(owners.worker_source(first.source), Ok(4));
        // SAFETY: only a worker index exists in this device-free test.
        let proof = unsafe { VerifiedRetirement::new(first.source) };
        assert_eq!(
            owners.complete_worker_cleanup(first.source, Ok(ReapDecision::Retired(proof))),
            Ok(true)
        );
        assert_eq!(*second.updates.borrow(), CacheState::Released);
        assert!(owners.drained());
    }

    #[test]
    fn cached_worker_dispatch_rejection_and_shutdown_late_result_update_waiters() {
        use super::super::{
            read_registry::VerifiedRetirement,
            read_source_cache::{CacheRequest, CacheState},
        };
        use crate::{content::ReadSourceFile, rendezvous::PieceKind};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("task");
        std::fs::write(&path, vec![1; 64]).unwrap();
        let file = ReadSourceFile::open(&path).unwrap();
        let request = || CacheRequest {
            kind: PieceKind::Piece,
            task: "task",
            file: file.clone(),
            piece_length: 8,
            max_region_bytes: 64,
            piece_offset: 0,
            completed: &[0..64],
        };
        let (mut owners, _) = credited_setup(8, 4);
        let now = std::time::Instant::now();
        let rejected = owners.claim_cached_worker_source(request(), now).unwrap();
        owners.reject_worker_source(rejected.source).unwrap();
        assert_eq!(*rejected.updates.borrow(), CacheState::Released);
        assert!(owners.drained());
        let late = owners.claim_cached_worker_source(request(), now).unwrap();
        owners.begin_shutdown();
        assert_eq!(*late.updates.borrow(), CacheState::Retiring);
        assert!(!owners.attach_worker_source(late.source, 3, false).unwrap());
        assert_eq!(*late.updates.borrow(), CacheState::Retiring);
        assert_eq!(owners.worker_source(late.source), Ok(3));
        // SAFETY: no native registration exists; model a verified worker reply.
        let proof = unsafe { VerifiedRetirement::new(late.source) };
        assert_eq!(
            owners.complete_worker_cleanup(late.source, Ok(ReapDecision::Retired(proof))),
            Ok(true)
        );
        assert_eq!(*late.updates.borrow(), CacheState::Released);
        assert!(owners.drained());
    }
    struct Mock {
        closes: Rc<Cell<usize>>,
    }
    impl ChildResources for Mock {
        type Wr = ();
        type Lease = ();
        fn post(&mut self, _: &ReadRequest) -> Result<ChildPost<()>, FfiError> {
            Ok(ChildPost::Posted(()))
        }
        unsafe fn complete(&mut self, _: ()) {}
        fn unimport(&mut self) -> Result<(), FfiError> {
            self.closes.set(self.closes.get() + 1);
            Ok(())
        }
        fn close_buffer(&mut self) -> Result<(), FfiError> {
            self.closes.set(self.closes.get() + 1);
            Ok(())
        }
        fn extract_lease(&mut self) -> Result<((), LeaseSpan), FfiError> {
            Ok((
                (),
                LeaseSpan {
                    // SAFETY: Mock never dereferences the span.
                    data: std::ptr::NonNull::dangling().as_ptr(),
                    length: 0,
                },
            ))
        }
        fn close_lease(&mut self, (): ()) -> Result<(), ((), FfiError)> {
            self.closes.set(self.closes.get() + 1);
            Ok(())
        }
    }
    const PEER: ReadPeer = ReadPeer {
        id: 1,
        generation: 1,
    };
    const SPEC: ChildSpec = ChildSpec {
        allocation_bytes: 8,
        piece_length: 4,
        jetty_id: 7,
        max_outstanding: 2,
    };
    type CreditedOwners = ReadOwners<(), super::super::wr_admission::CreditedChild<Mock>>;
    type SharedCredits = Rc<std::cell::RefCell<super::super::wr_admission::ReadWrCredits>>;

    fn credited_setup(capacity: usize, per_peer: usize) -> (CreditedOwners, SharedCredits) {
        let cap = |bytes, entries| ReadCapacity { bytes, entries };
        let mut owners = ReadOwners::new(ReadBudget {
            total: cap(512, 128),
            source: cap(256, 64),
            destination: cap(256, 64),
            per_peer_source: cap(256, 64),
            per_peer_destination: cap(256, 64),
            quarantine: cap(256, 64),
        })
        .unwrap();
        owners.activate_peer(PEER).unwrap();
        let credits = super::super::wr_admission::ReadWrCredits::new(capacity, per_peer).unwrap();
        (owners, credits)
    }

    fn credited_child(
        owners: &mut CreditedOwners,
        credits: &SharedCredits,
        peer: ReadPeer,
    ) -> ReadOwnerId {
        // SAFETY: Mock resources have no native backing, and create_child owns admission.
        match unsafe {
            owners.create_child(
                peer,
                ChildSpec {
                    allocation_bytes: 4,
                    ..SPEC
                },
                || {
                    ChildCreation::Ready(super::super::wr_admission::CreditedChild::new(
                        Mock {
                            closes: Rc::new(Cell::new(0)),
                        },
                        credits.clone(),
                        peer,
                    ))
                },
            )
        } {
            ChildAdmission::Ready(id) => id,
            _ => panic!("mock admission"),
        }
    }

    fn complete_credited(owners: &mut CreditedOwners, id: ReadOwnerId) {
        let context = *owners
            .routes
            .iter()
            .find(|(_, route)| route.owner == id)
            .unwrap()
            .0;
        // SAFETY: Test-owned mock WR has no DMA and exactly matches its route.
        owners
            .complete(id, unsafe {
                ReadRetired::new(id, SPEC.jetty_id, context, 4, true)
            })
            .unwrap();
    }

    #[test]
    fn sixteen_pieces_wait_on_eight_shared_credits_without_quarantine() {
        let (mut owners, credits) = credited_setup(8, 8);
        let ids = (0..16)
            .map(|_| credited_child(&mut owners, &credits, PEER))
            .collect::<Vec<_>>();
        let mut waiting = Vec::new();
        for (index, &id) in ids.iter().enumerate() {
            let mut rx = owners.subscribe_child_progress(id).unwrap();
            assert_eq!(owners.post_batch(id, &[4]).unwrap(), usize::from(index < 8));
            if index >= 8 {
                rx.borrow_and_update();
                assert_eq!(owners.post_batch(id, &[4]).unwrap(), 0);
                assert!(
                    !rx.has_changed().unwrap(),
                    "zero posts must not wake themselves"
                );
                assert!(!rx.borrow().progress.failed);
                assert!(!rx.borrow().interrupted);
                waiting.push(rx);
            }
        }
        assert_eq!(credits.borrow().used(), 8);
        assert_eq!(owners.usage().quarantined_entries, 0);
        for &id in &ids[..8] {
            complete_credited(&mut owners, id);
        }
        for (rx, &id) in waiting.iter_mut().zip(&ids[8..]) {
            assert!(
                rx.has_changed().unwrap(),
                "another Piece's CQE must wake a zero-WR waiter"
            );
            assert_eq!(owners.post_batch(id, &[4]).unwrap(), 1);
        }
        for &id in &ids[8..] {
            complete_credited(&mut owners, id);
        }
        assert_eq!(credits.borrow().used(), 0);
        for id in ids {
            assert!(owners.child_progress(id).unwrap().read_succeeded);
            owners.retire(id).unwrap();
            assert_eq!(owners.reap_child(id), Ok(true));
        }
        assert!(owners.drained());
    }

    #[test]
    fn global_credit_return_wakes_a_different_peer() {
        let (mut owners, credits) = credited_setup(1, 1);
        let other = ReadPeer {
            id: 2,
            generation: 1,
        };
        owners.activate_peer(other).unwrap();
        let first = credited_child(&mut owners, &credits, PEER);
        let second = credited_child(&mut owners, &credits, other);
        let mut rx = owners.subscribe_child_progress(second).unwrap();
        assert_eq!(owners.post_batch(first, &[4]).unwrap(), 1);
        assert_eq!(owners.post_batch(second, &[4]).unwrap(), 0);
        rx.borrow_and_update();
        complete_credited(&mut owners, first);
        assert!(rx.has_changed().unwrap());
        assert_eq!(owners.post_batch(second, &[4]).unwrap(), 1);
        complete_credited(&mut owners, second);
        for id in [first, second] {
            owners.retire(id).unwrap();
            assert_eq!(owners.reap_child(id), Ok(true));
        }
        assert!(owners.drained());
    }

    #[test]
    fn blocked_waiters_are_interrupted_and_removed_on_retire_drain_and_shutdown() {
        for mode in 0..3 {
            let (mut owners, credits) = credited_setup(1, 1);
            let active = credited_child(&mut owners, &credits, PEER);
            let waiting = credited_child(&mut owners, &credits, PEER);
            let mut rx = owners.subscribe_child_progress(waiting).unwrap();
            assert_eq!(owners.post_batch(active, &[4]).unwrap(), 1);
            assert_eq!(owners.post_batch(waiting, &[4]).unwrap(), 0);
            rx.borrow_and_update();
            match mode {
                0 => owners.retire(waiting).unwrap(),
                1 => owners.drain_peer(PEER).unwrap(),
                _ => owners.begin_shutdown(),
            }
            assert!(owners.blocked_children.is_empty());
            assert!(rx.has_changed().unwrap());
            assert!(rx.borrow().interrupted);
            assert_eq!(owners.reap_child(waiting), Ok(true));
            complete_credited(&mut owners, active);
            assert!(!owners.contains(waiting));
            owners.retire(active).unwrap();
            assert_eq!(owners.reap_child(active), Ok(true));
            assert_eq!(credits.borrow().used(), 0);
            assert!(owners.drained());
        }
    }

    #[test]
    fn partial_batch_keeps_prefix_routed_and_waits_for_capacity() {
        let (mut owners, credits) = credited_setup(1, 1);
        // SAFETY: Mock-only resource owner; no native DMA exists.
        let id = match unsafe {
            owners.create_child(
                PEER,
                ChildSpec {
                    allocation_bytes: 8,
                    piece_length: 8,
                    ..SPEC
                },
                || {
                    ChildCreation::Ready(super::super::wr_admission::CreditedChild::new(
                        Mock {
                            closes: Rc::new(Cell::new(0)),
                        },
                        credits.clone(),
                        PEER,
                    ))
                },
            )
        } {
            ChildAdmission::Ready(id) => id,
            _ => panic!("mock admission"),
        };
        assert_eq!(owners.post_batch(id, &[4, 4]).unwrap(), 1);
        assert_eq!(owners.outstanding_completions(), 1);
        assert_eq!(owners.usage().quarantined_entries, 0);
        complete_credited(&mut owners, id);
        assert_eq!(owners.post_batch(id, &[4]).unwrap(), 1);
        complete_credited(&mut owners, id);
        assert!(owners.child_progress(id).unwrap().read_succeeded);
        owners.retire(id).unwrap();
        assert_eq!(owners.reap_child(id), Ok(true));
    }

    #[test]
    fn successful_worker_result_after_shutdown_never_reopens_publication() {
        let mut owners = setup();
        let source = owners.reserve_worker_source(PEER, 8).unwrap();
        owners.begin_shutdown();
        assert!(!owners.attach_worker_source(source, 1, false).unwrap());
        assert_eq!(owners.usage().source_bytes, 8);
        assert_eq!(owners.worker_source(source).unwrap(), 1);
        assert!(owners.reserve_worker_source(PEER, 1).is_err());
        let proof = unsafe { super::super::read_registry::VerifiedRetirement::new(source) };
        assert_eq!(
            owners.complete_worker_cleanup(source, Ok(ReapDecision::Retired(proof))),
            Ok(true)
        );
        assert!(owners.drained());
    }

    #[test]
    fn another_peer_lease_blocks_worker_cleanup_before_native_dispatch() {
        let mut owners = setup();
        let other = ReadPeer {
            id: 2,
            generation: 1,
        };
        owners.activate_peer(other).unwrap();
        let source = owners.reserve_worker_source(PEER, 4).unwrap();
        assert!(owners.attach_worker_source(source, 1, false).unwrap());
        let lease = owners
            .registry
            .acquire_source_lease(source, other, 4)
            .unwrap();
        owners.retire(source).unwrap();
        // worker_source is the runtime's pre-dispatch gate, not just a check
        // performed after native unregister may already have run.
        assert_eq!(owners.worker_source(source), Err(OwnerError::SourceBusy));
        assert_eq!(
            owners.complete_worker_cleanup(source, Ok(ReapDecision::Pending)),
            Err(ReapError::Registry(OwnerError::SourceBusy))
        );
        assert!(!owners.peer_drained(PEER));
        assert!(!owners.peer_drained(other));
        assert_eq!(owners.usage().source_bytes, 4);
        // SAFETY: Test owners have no native resources or remote accesses.
        unsafe {
            owners.registry.release_source_lease(lease).unwrap();
        }
        assert!(owners.peer_drained(other));
        assert_eq!(owners.worker_source(source), Ok(1));
        // SAFETY: Resource-free mock worker completed all cleanup.
        let proof = unsafe { super::super::read_registry::VerifiedRetirement::new(source) };
        assert_eq!(
            owners.complete_worker_cleanup(source, Ok(ReapDecision::Retired(proof))),
            Ok(true)
        );
        assert!(owners.peer_drained(PEER));
        assert!(owners.drained());
    }

    #[test]
    fn worker_reservation_survives_peer_drain_and_releases_only_after_proven_cleanup() {
        let mut owners = setup();
        let source = owners.reserve_worker_source(PEER, 8).unwrap();
        assert_eq!(owners.usage().source_bytes, 8);
        assert!(owners.reserve_worker_source(PEER, 1).is_err());
        owners.drain_peer(PEER).unwrap();
        assert!(!owners.attach_worker_source(source, 0, false).unwrap());
        assert!(!owners.peer_drained(PEER));
        assert_eq!(owners.worker_source(source).unwrap(), 0);
        assert!(owners
            .complete_worker_cleanup(source, Err(FfiError::Status(-5)))
            .is_err());
        assert_eq!(owners.usage().source_bytes, 8);
        assert_eq!(
            owners.complete_worker_cleanup(source, Ok(ReapDecision::Pending)),
            Ok(false)
        );
        let other = owners.registry.reserve(PEER, ReadDirection::Source, 1);
        assert!(other.is_err());
        let proof = unsafe { super::super::read_registry::VerifiedRetirement::new(source) };
        assert_eq!(
            owners.complete_worker_cleanup(source, Ok(ReapDecision::Retired(proof))),
            Ok(true)
        );
        assert!(owners.peer_drained(PEER));
        assert_eq!(owners.usage().source_bytes, 0);
    }

    fn setup() -> ReadOwners<(), Mock> {
        let cap = |bytes, entries| ReadCapacity { bytes, entries };
        let mut owners = ReadOwners::new(ReadBudget {
            total: cap(16, 4),
            source: cap(8, 2),
            destination: cap(8, 2),
            per_peer_source: cap(8, 2),
            per_peer_destination: cap(8, 2),
            quarantine: cap(8, 2),
        })
        .unwrap();
        owners.activate_peer(PEER).unwrap();
        owners
    }
    fn create(owners: &mut ReadOwners<(), Mock>, closes: Rc<Cell<usize>>) -> ReadOwnerId {
        // SAFETY: Resource-free mock; factory size matches the admitted specification.
        match unsafe { owners.create_child(PEER, SPEC, || ChildCreation::Ready(Mock { closes })) } {
            ChildAdmission::Ready(id) => id,
            _ => panic!("expected admission"),
        }
    }
    fn read_cqe(context: u64, status: i32) -> super::super::ffi::CompletionRecord {
        super::super::ffi::CompletionRecord {
            observed_at: Some(std::time::Instant::now()),
            status,
            user_ctx: context,
            local_id: 7,
            is_jetty: true,
            user_ctx_valid: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn notifications_keep_early_and_out_of_order_completions_until_observed() {
        let mut owners = setup();
        let closes = Rc::new(Cell::new(0));
        let id = create(&mut owners, closes.clone());
        let mut updates = owners.subscribe_child_progress(id).unwrap();
        updates.borrow_and_update();
        owners.post_batch(id, &[2, 2]).unwrap();
        let contexts: Vec<_> = owners.routes.keys().copied().collect();
        owners
            .route_completion(read_cqe(contexts[1], 0), false)
            .unwrap()
            .unwrap();
        // Updates precede changed(). Coalescing must retain exact progress,
        // and one CQE must not permit publication of the whole Piece.
        updates.changed().await.unwrap();
        let partial = *updates.borrow_and_update();
        assert_eq!(partial.progress.retired_bytes, 2);
        assert_eq!(partial.progress.outstanding_wr_count, 1);
        assert!(!partial.progress.read_succeeded);
        assert!(owners.publish_child_lease(id).is_err());
        owners
            .route_completion(read_cqe(contexts[0], 0), false)
            .unwrap()
            .unwrap();
        updates.changed().await.unwrap();
        assert!(updates.borrow_and_update().progress.read_succeeded);
        assert_eq!(owners.usage().bytes, 8);
        assert_eq!(closes.get(), 0);
        // A late subscription observes already-completed state immediately.
        assert!(
            owners
                .subscribe_child_progress(id)
                .unwrap()
                .borrow()
                .progress
                .read_succeeded
        );
        owners.retire(id).unwrap();
        owners.reap_child(id).unwrap();
        assert!(updates.changed().await.is_ok()); // retirement notification
        updates.borrow_and_update();
        assert!(updates.changed().await.is_err()); // sender removed on reap
    }

    #[tokio::test]
    async fn failed_cqe_and_shutdown_wake_waiters_without_releasing_dma_resources() {
        let mut owners = setup();
        let closes = Rc::new(Cell::new(0));
        let id = create(&mut owners, closes.clone());
        let mut updates = owners.subscribe_child_progress(id).unwrap();
        owners.post_batch(id, &[2, 2]).unwrap();
        updates.borrow_and_update();
        let context = *owners.routes.keys().next().unwrap();
        owners
            .route_completion(read_cqe(context, -1), false)
            .unwrap()
            .unwrap();
        updates.changed().await.unwrap();
        assert!(updates.borrow_and_update().progress.failed);
        assert_eq!(owners.outstanding_completions(), 1);
        owners.begin_shutdown();
        updates.changed().await.unwrap();
        assert!(updates.borrow_and_update().interrupted);
        assert_eq!(owners.usage().bytes, 8);
        assert_eq!(owners.reap_child(id), Ok(false));
        assert_eq!(closes.get(), 0);
    }

    #[tokio::test]
    async fn peer_drain_and_retire_interrupt_only_the_matching_waiters() {
        let mut owners = setup();
        let other_peer = ReadPeer {
            id: 2,
            generation: 1,
        };
        owners.activate_peer(other_peer).unwrap();
        // Fit two distinct peers inside the shared eight-byte destination cap.
        let spec = ChildSpec {
            allocation_bytes: 4,
            ..SPEC
        };
        let id = match unsafe {
            owners.create_child(PEER, spec, || {
                ChildCreation::Ready(Mock {
                    closes: Rc::new(Cell::new(0)),
                })
            })
        } {
            ChildAdmission::Ready(id) => id,
            _ => panic!("expected admission"),
        };
        let other = match unsafe {
            owners.create_child(other_peer, spec, || {
                ChildCreation::Ready(Mock {
                    closes: Rc::new(Cell::new(0)),
                })
            })
        } {
            ChildAdmission::Ready(id) => id,
            _ => panic!("expected admission"),
        };
        let mut updates = owners.subscribe_child_progress(id).unwrap();
        let mut other_updates = owners.subscribe_child_progress(other).unwrap();
        owners.drain_peer(PEER).unwrap();
        updates.changed().await.unwrap();
        assert!(updates.borrow_and_update().interrupted);
        assert!(!other_updates.has_changed().unwrap());
        owners.retire(other).unwrap();
        other_updates.changed().await.unwrap();
        assert!(other_updates.borrow().interrupted);
    }

    #[test]
    fn dropping_progress_receiver_does_not_retire_owner_or_credits() {
        let mut owners = setup();
        let closes = Rc::new(Cell::new(0));
        let id = create(&mut owners, closes.clone());
        let updates = owners.subscribe_child_progress(id).unwrap();
        owners.post_batch(id, &[4]).unwrap();
        drop(updates);
        assert_eq!(owners.outstanding_completions(), 1);
        assert_eq!(owners.usage().bytes, 8);
        assert_eq!(closes.get(), 0);
    }

    #[test]
    fn shared_source_and_destination_reservations_charge_one_budget() {
        let mut owners = setup();
        let source = owners
            .registry
            .reserve(PEER, ReadDirection::Source, 8)
            .unwrap();
        let closes = Rc::new(Cell::new(0));
        let child = create(&mut owners, closes.clone());
        assert_eq!(owners.usage().bytes, 16);
        assert_eq!(owners.usage().source_bytes, 8);
        assert_eq!(owners.usage().destination_bytes, 8);
        let result = unsafe { owners.create_child(PEER, SPEC, || panic!("factory before budget")) };
        assert!(matches!(
            result,
            ChildAdmission::Rejected(ReadDispatchError::Registry(OwnerError::Capacity))
        ));
        // Source was a pending reservation only, no native command was started.
        owners.registry.release_unused_reservation(source).unwrap();
        owners.retire(child).unwrap();
        assert_eq!(owners.reap_child(child), Ok(true));
        assert_eq!(closes.get(), 2);
        assert!(owners.drained());
    }
    #[test]
    fn invalid_spec_and_shutdown_never_invoke_factory() {
        let mut owners = setup();
        for spec in [
            ChildSpec {
                allocation_bytes: 3,
                ..SPEC
            },
            ChildSpec {
                max_outstanding: 0,
                ..SPEC
            },
            ChildSpec {
                jetty_id: 0,
                ..SPEC
            },
        ] {
            assert!(matches!(
                unsafe { owners.create_child(PEER, spec, || panic!("invalid factory")) },
                ChildAdmission::Rejected(_)
            ));
        }
        assert!(owners.drained());
        owners.begin_shutdown();
        assert!(matches!(
            unsafe { owners.create_child(PEER, SPEC, || panic!("shutdown factory")) },
            ChildAdmission::Rejected(ReadDispatchError::Registry(OwnerError::Shutdown))
        ));
    }
    #[test]
    fn partial_creation_retains_charge_and_known_rejection_releases_it() {
        let mut owners = setup();
        assert!(matches!(
            unsafe {
                owners.create_child(PEER, SPEC, || ChildCreation::Rejected(FfiError::Status(-1)))
            },
            ChildAdmission::Rejected(_)
        ));
        assert!(owners.drained());
        let closes = Rc::new(Cell::new(0));
        let ChildAdmission::Quarantined { id, .. } = (unsafe {
            owners.create_child(PEER, SPEC, || ChildCreation::Uncertain {
                resources: Mock {
                    closes: closes.clone(),
                },
                error: FfiError::Status(-2),
            })
        }) else {
            panic!("expected quarantine")
        };
        assert_eq!(owners.usage().bytes, 8);
        assert_eq!(owners.usage().quarantined_bytes, 8);
        assert!(owners.post(id, 4).is_err());
        assert_eq!(closes.get(), 0);
        assert_eq!(owners.reap_child(id), Ok(true));
        assert!(owners.drained());
    }
    #[test]
    fn shutdown_and_dispatch_errors_still_allow_exact_completion() {
        let mut owners = setup();
        let closes = Rc::new(Cell::new(0));
        let id = create(&mut owners, closes.clone());
        let context = owners.post(id, 4).unwrap();
        assert!(owners.source_descriptor(id).is_err());
        // Bounds error automatically closes registry dispatch, preserving the WR.
        assert!(owners.post(id, 1).is_err());
        assert_eq!(owners.usage().quarantined_bytes, 8);
        owners.begin_shutdown();
        assert_eq!(owners.reap_child(id), Ok(false));
        assert_eq!(closes.get(), 0);
        let record = unsafe { ReadRetired::new(id, 7, context, 4, true) };
        owners.complete(id, record).unwrap();
        assert_eq!(owners.reap_child(id), Ok(true));
        assert!(owners.drained());
        assert_eq!(closes.get(), 2);
    }
    #[test]
    fn real_provider_read_cqe_routes_by_context_and_send_shape() {
        let mut owners = setup();
        let closes = Rc::new(Cell::new(0));
        let id = create(&mut owners, closes.clone());
        let context = owners.post(id, 4).unwrap();
        assert!(is_read_context(context));
        assert_eq!(owners.outstanding_completions(), 1);

        // Real udma reports READ opcode=0 and completion_len=0; neither field
        // is a READ identity source.
        let record = super::super::ffi::CompletionRecord {
            status: 0,
            opcode: 0,
            user_ctx: context,
            completion_len: 0,
            local_id: 7,
            is_recv: false,
            is_jetty: true,
            user_ctx_valid: true,
            event_kind: super::super::ffi::CompletionEventKind::WorkRequest,
            ..Default::default()
        };
        assert_eq!(owners.route_completion(record, false), Some(Ok(())));
        assert_eq!(owners.outstanding_completions(), 0);
        assert!(owners.route_completion(record, false).unwrap().is_err());
        owners.retire(id).unwrap();
        assert_eq!(owners.reap_child(id), Ok(true));
        assert_eq!(closes.get(), 2);
    }
    #[test]
    fn batch_post_routes_every_wr_without_intermediate_progress() {
        let mut owners = setup();
        let id = create(&mut owners, Rc::new(Cell::new(0)));

        let posted = owners.post_batch(id, &[2, 2]).unwrap();

        assert_eq!(posted, 2);
        let progress = owners.child_progress(id).unwrap();
        assert_eq!(progress.accepted_bytes, 4);
        assert_eq!(progress.accepted_wr_count, 2);
        assert_eq!(progress.outstanding_wr_count, 2);
        assert_eq!(owners.outstanding_completions(), 2);
    }

    #[test]
    fn empty_batch_post_is_rejected_without_changing_child() {
        let mut owners = setup();
        let id = create(&mut owners, Rc::new(Cell::new(0)));

        assert!(owners.post_batch(id, &[]).is_err());

        let progress = owners.child_progress(id).unwrap();
        assert_eq!(progress.accepted_bytes, 0);
        assert_eq!(progress.accepted_wr_count, 0);
        assert!(!progress.failed);
    }

    #[test]
    fn read_cqe_wrong_queue_or_jetty_keeps_wr_routed_and_quarantines_owner() {
        let mut owners = setup();
        let id = create(&mut owners, Rc::new(Cell::new(0)));
        let updates = owners.subscribe_child_progress(id).unwrap();
        let context = owners.post(id, 4).unwrap();
        let record = super::super::ffi::CompletionRecord {
            status: 0,
            user_ctx: context,
            local_id: 7,
            is_recv: true,
            is_jetty: true,
            user_ctx_valid: true,
            event_kind: super::super::ffi::CompletionEventKind::WorkRequest,
            ..Default::default()
        };
        assert!(owners.route_completion(record, true).unwrap().is_err());
        assert!(updates.borrow().interrupted);
        assert_eq!(owners.outstanding_completions(), 1);
        assert_eq!(owners.usage().quarantined_entries, 1);
        assert_eq!(owners.reap_child(id), Ok(false));
    }
    #[test]
    fn uncertain_post_is_routed_until_its_error_cqe_retires_the_wr() {
        struct UncertainMock {
            context: Rc<Cell<u64>>,
        }
        impl ChildResources for UncertainMock {
            type Wr = ();
            type Lease = ();
            fn post(&mut self, request: &ReadRequest) -> Result<ChildPost<()>, FfiError> {
                self.context.set(request.user_ctx);
                Ok(ChildPost::Uncertain((), FfiError::Status(-5)))
            }
            unsafe fn complete(&mut self, _: ()) {}
            fn unimport(&mut self) -> Result<(), FfiError> {
                Ok(())
            }
            fn close_buffer(&mut self) -> Result<(), FfiError> {
                Ok(())
            }
            fn extract_lease(&mut self) -> Result<((), LeaseSpan), FfiError> {
                Err(FfiError::Contract("mock has no lease"))
            }
            fn close_lease(&mut self, (): ()) -> Result<(), ((), FfiError)> {
                Ok(())
            }
        }
        let cap = |bytes, entries| ReadCapacity { bytes, entries };
        let mut owners: ReadOwners<(), UncertainMock> = ReadOwners::new(ReadBudget {
            total: cap(16, 4),
            source: cap(8, 2),
            destination: cap(8, 2),
            per_peer_source: cap(8, 2),
            per_peer_destination: cap(8, 2),
            quarantine: cap(8, 2),
        })
        .unwrap();
        owners.activate_peer(PEER).unwrap();
        let context = Rc::new(Cell::new(0));
        let id = match unsafe {
            owners.create_child(PEER, SPEC, || {
                ChildCreation::Ready(UncertainMock {
                    context: context.clone(),
                })
            })
        } {
            ChildAdmission::Ready(id) => id,
            _ => panic!("expected admission"),
        };
        let updates = owners.subscribe_child_progress(id).unwrap();
        assert!(owners.post(id, 4).is_err());
        assert!(updates.borrow().interrupted);
        let user_ctx = context.get();
        assert!(is_read_context(user_ctx));
        assert_eq!(owners.outstanding_completions(), 1);
        let record = super::super::ffi::CompletionRecord {
            status: -5,
            opcode: 0,
            user_ctx,
            completion_len: 0,
            local_id: 7,
            is_recv: false,
            is_jetty: true,
            user_ctx_valid: true,
            event_kind: super::super::ffi::CompletionEventKind::WorkRequest,
            ..Default::default()
        };
        assert_eq!(owners.route_completion(record, false), Some(Ok(())));
        assert_eq!(owners.outstanding_completions(), 0);
        assert_eq!(owners.reap_child(id), Ok(true));
    }
    #[test]
    fn lost_creation_keeps_reservation_and_blocks_further_admission() {
        let mut owners = setup();
        let ChildAdmission::Quarantined { id, .. } = (unsafe {
            owners.create_child(PEER, SPEC, || ChildCreation::Lost(FfiError::NullHandle))
        }) else {
            panic!("expected isolation")
        };
        assert_eq!(owners.usage().bytes, 8);
        assert!(!owners.drained());
        assert_eq!(
            owners.reap_child(id),
            Err(ReapError::Registry(OwnerError::OwnerMissing))
        );
        assert!(matches!(
            unsafe { owners.create_child(PEER, SPEC, || panic!("isolation factory")) },
            ChildAdmission::Rejected(ReadDispatchError::Registry(OwnerError::QuarantineLimit))
        ));
    }
}

impl<K, C>
    ReadOwners<K, super::wr_admission::CreditedChild<super::read_child_owner::NativeChild<C>>>
{
    /// # Safety
    /// NativeChild::create's descriptor/provider requirements apply. credits must
    /// represent this Jetty's available JFS depth shared by every READ owner.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn create_native_child(
        &mut self,
        peer: ReadPeer,
        spec: ChildSpec,
        runtime: &mut NativeRuntime,
        jetty: std::rc::Rc<std::cell::RefCell<super::ffi::JettyHandle>>,
        target: std::rc::Rc<super::ffi::TargetHandle>,
        alignment: u64,
        descriptor: &ReadDescriptor,
        token: &ReadToken,
        max_read_size: u32,
        keepalive: C,
        credits: std::rc::Rc<std::cell::RefCell<super::wr_admission::ReadWrCredits>>,
        pool: std::rc::Rc<std::cell::RefCell<super::destination_pool::ReadBufferPool>>,
    ) -> ChildAdmission {
        let active_destination_bytes = self.usage().destination_bytes;
        // SAFETY: create_child supplies byte admission before any native calls;
        // caller supplies provider/descriptor facts and shared credit identity.
        unsafe {
            self.create_child(peer, spec, || {
                let result = super::read_child_owner::NativeChild::create(
                    runtime,
                    jetty,
                    target,
                    spec,
                    alignment,
                    descriptor,
                    token,
                    max_read_size,
                    pool,
                    active_destination_bytes,
                    keepalive,
                );
                let wrap =
                    |resources| super::wr_admission::CreditedChild::new(resources, credits, peer);
                match result {
                    ChildCreation::Ready(resources) => ChildCreation::Ready(wrap(resources)),
                    ChildCreation::Uncertain { resources, error } => ChildCreation::Uncertain {
                        resources: wrap(resources),
                        error,
                    },
                    ChildCreation::Rejected(error) => ChildCreation::Rejected(error),
                    ChildCreation::Lost(error) => ChildCreation::Lost(error),
                }
            })
        }
    }
}
