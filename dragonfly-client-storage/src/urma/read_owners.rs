//! One budget and peer lifecycle for both READ directions. Production wiring is
//! still gated: factories and completion decoding must supply native evidence.
use super::{
    ffi::{
        read::{source::ReadBacking, ReadDescriptor, ReadToken},
        FfiError, NativeRuntime,
    },
    read_child_owner::{ChildOwner, ChildResources, ReadRetired},
    read_owner::{
        OwnerError, QuarantineReason, ReadBudget, ReadDirection, ReadOwnerId, ReadOwnerRegistry,
        ReadPeer, ReadUsage, ReapError,
    },
    read_source_owner::{
        SourceAdmission, SourceAdmissionError, SourceOwner, SourceRevoked, SourceSlot,
        UnregisterPermit,
    },
};

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
}
impl<K, R: ChildResources> ReadOwners<K, R> {
    pub(crate) fn new(budget: ReadBudget) -> Result<Self, OwnerError> {
        Ok(Self {
            registry: ReadOwnerRegistry::new(budget)?,
        })
    }
    pub(crate) fn activate_peer(&mut self, peer: ReadPeer) -> Result<(), OwnerError> {
        self.registry.activate_peer(peer)
    }
    pub(crate) fn usage(&self) -> ReadUsage {
        self.registry.usage()
    }
    pub(crate) fn drained(&self) -> bool {
        self.registry.drained()
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
        let result = self.registry.active_owner(id)?.child_mut()?.post(length);
        // Conservative policy: even local admission rejection closes this attempt.
        // Native uncertain post must never remain dispatchable after an error.
        if result.is_err() {
            self.registry
                .quarantine(id, QuarantineReason::PostUncertain)?;
        }
        result.map_err(Into::into)
    }
    pub(crate) fn complete(
        &mut self,
        id: ReadOwnerId,
        completion: ReadRetired,
    ) -> Result<(), ReadDispatchError> {
        let result = self
            .registry
            .retained_owner(id)?
            .child_mut()?
            .complete(completion);
        if result.is_err() {
            self.registry.quarantine(id, QuarantineReason::WrongProof)?;
        }
        result.map_err(Into::into)
    }
    pub(crate) fn reap_child(&mut self, id: ReadOwnerId) -> Result<bool, ReapError<FfiError>> {
        self.registry
            .reap_with(id, |bundle| bundle.child_mut()?.reap())
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
