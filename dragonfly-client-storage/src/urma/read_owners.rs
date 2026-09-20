//! One budget, peer lifecycle, and CQE route table for both READ directions.
//! Production command and Storage wiring remain gated.
use super::{
    ffi::{
        read::{source::ReadBacking, ReadDescriptor, ReadToken},
        FfiError, NativeRuntime,
    },
    read_child_owner::{
        is_read_context, ChildOwner, ChildPostOutcome, ChildProgress, ChildResources, LeaseSpan,
        ReadRetired,
    },
    read_owner::{
        OwnerError, QuarantineReason, ReadBudget, ReadDirection, ReadOwnerId, ReadOwnerRegistry,
        ReadPeer, ReadUsage, ReapDecision, ReapError,
    },
    read_source_owner::{
        SourceAdmission, SourceAdmissionError, SourceOwner, SourceRevoked, SourceSlot,
        UnregisterPermit,
    },
};
use std::collections::{btree_map::Entry, BTreeMap};

#[derive(Clone, Copy)]
struct ReadRoute {
    owner: ReadOwnerId,
    jetty: u32,
    length: u32,
}

enum ReadBundle<K, R: ChildResources> {
    Source(SourceOwner<K>),
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
            Self::Child(_) => Err(FfiError::Contract("expected source owner")),
        }
    }
}
impl<K, R: ChildResources> ReadBundle<K, R> {
    fn child_mut(&mut self) -> Result<&mut ChildOwner<R>, FfiError> {
        match self {
            Self::Child(child) => Ok(child),
            Self::Source(_) => Err(FfiError::Contract("expected Child owner")),
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
    routes: BTreeMap<u64, ReadRoute>,
}
impl<K, R: ChildResources> ReadOwners<K, R> {
    pub(crate) fn new(budget: ReadBudget) -> Result<Self, OwnerError> {
        Ok(Self {
            registry: ReadOwnerRegistry::new(budget)?,
            routes: BTreeMap::new(),
        })
    }
    pub(crate) fn activate_peer(&mut self, peer: ReadPeer) -> Result<(), OwnerError> {
        self.registry.activate_peer(peer)
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
        self.registry.begin_shutdown();
    }
    pub(crate) fn drain_peer(&mut self, peer: ReadPeer) -> Result<(), OwnerError> {
        self.registry.drain_peer(peer)
    }
    pub(crate) fn retire(&mut self, id: ReadOwnerId) -> Result<(), OwnerError> {
        self.registry.retire(id)
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
    pub(crate) fn reap_source(
        &mut self,
        id: ReadOwnerId,
        permit: &UnregisterPermit,
        revoked: Option<&SourceRevoked>,
    ) -> Result<bool, ReapError<FfiError>> {
        self.registry.reap_source(id, permit, revoked)
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
    pub(crate) fn post(&mut self, id: ReadOwnerId, length: u32) -> Result<u64, ReadDispatchError> {
        let outcome = self
            .registry
            .active_owner(id)?
            .child_mut()?
            .post_routed(length);
        let (context, error) = match outcome {
            ChildPostOutcome::Posted(context) => (Some(context), None),
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
            return Err(error.into());
        }
        Ok(context.expect("successful READ post has a context"))
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
        result.map_err(Into::into)
    }
    pub(crate) fn reap_child(&mut self, id: ReadOwnerId) -> Result<bool, ReapError<FfiError>> {
        self.registry
            .reap_with(id, |bundle| bundle.child_mut()?.reap())
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
            ReapDecision::Retired(_) => Err(FfiError::Contract(
                "lease drain must retain the Child owner",
            )
            .into()),
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
        self.registry
            .reap_with(id, |bundle| bundle.child_mut()?.recycle_lease())
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
        ffi::read::ReadRequest, read_child_owner::ChildPost, read_owner::ReadCapacity,
    };
    use super::*;
    use std::{cell::Cell, rc::Rc};
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
        fn close_lease(&mut self, (): ()) -> Result<(), FfiError> {
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
    fn read_cqe_wrong_queue_or_jetty_keeps_wr_routed_and_quarantines_owner() {
        let mut owners = setup();
        let id = create(&mut owners, Rc::new(Cell::new(0)));
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
            fn close_lease(&mut self, (): ()) -> Result<(), FfiError> {
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
        assert!(owners.post(id, 4).is_err());
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
    ReadOwners<K, super::read_wr_credit::CreditedChild<super::read_child_owner::NativeChild<C>>>
{
    /// # Safety
    /// NativeChild::create's descriptor/provider requirements apply. credits must
    /// represent this Jetty's available JFS depth shared by every READ owner.
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
        credits: std::rc::Rc<std::cell::RefCell<super::read_wr_credit::ReadWrCredits>>,
    ) -> ChildAdmission {
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
                    keepalive,
                );
                let wrap =
                    |resources| super::read_wr_credit::CreditedChild::new(resources, credits, peer);
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
