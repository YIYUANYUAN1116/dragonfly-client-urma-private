//! Parent native source adapter. Not connected to production dispatch.
//! Keep the shared source/destination registry alive through shutdown.

use super::{
    ffi::{
        read::{
            source::{ReadBacking, ReadSource, SourceRegistration},
            ReadDescriptor, ReadToken,
        },
        FfiError, NativeRuntime,
    },
    read_owner::{
        OwnerError, QuarantineReason, ReadDirection, ReadOwnerId, ReadOwnerRegistry, ReadPeer,
        ReapDecision, ReapError, VerifiedRetirement,
    },
};

/// Permission to invoke unregister under a provider-validated drain protocol.
/// This does not prove that revocation has completed.
pub(crate) struct UnregisterPermit(ReadOwnerId);
impl UnregisterPermit {
    /// # Safety
    /// The provider's unregister preconditions for this exact source, including
    /// outstanding remote access, must be satisfied. EOF/timeout is insufficient.
    pub(crate) unsafe fn new(id: ReadOwnerId) -> Self {
        Self(id)
    }
}

pub(crate) struct SourceRevoked(ReadOwnerId);
impl SourceRevoked {
    /// # Safety
    /// Independently prove access to this exact source has ceased and cannot
    /// resume (including stale tokens and failed-registration grant rollback).
    /// A peer message or successful unregister alone is not evidence.
    pub(crate) unsafe fn new(id: ReadOwnerId) -> Self {
        Self(id)
    }
}

// Private adapter: tests exercise the same staged cleanup with injected failures.
trait SourceResource {
    fn unregister(&mut self) -> Result<(), FfiError>;
    fn release(&mut self) -> Result<(), FfiError>;
}
impl<K> SourceResource for ReadSource<K> {
    fn unregister(&mut self) -> Result<(), FfiError> {
        // SAFETY: cleanup is accessible only with an identity-bound permit.
        unsafe { self.unregister() }
    }
    fn release(&mut self) -> Result<(), FfiError> {
        // SAFETY: cleanup requires an independent identity-bound revocation proof.
        let backing = unsafe { self.release_after_revoke()? };
        drop(backing);
        Ok(())
    }
}

pub(crate) struct SourceOwner<K> {
    cleanup: SourceCleanup<ReadSource<K>>,
}
struct SourceCleanup<S> {
    source: S,
    // Registration failure can leave grants without a native registration handle.
    // Such owners skip unregister, but still require rollback/revocation proof.
    unregistered: bool,
}
impl<S: SourceResource> SourceCleanup<S> {
    fn reap(
        &mut self,
        id: ReadOwnerId,
        permit: &UnregisterPermit,
        revoked: Option<&SourceRevoked>,
    ) -> Result<ReapDecision, FfiError> {
        if permit.0 != id || revoked.is_some_and(|proof| proof.0 != id) {
            return Err(FfiError::Contract("source cleanup proof identity mismatch"));
        }
        if !self.unregistered {
            self.source.unregister()?;
            self.unregistered = true;
        }
        if revoked.is_none() {
            return Ok(ReapDecision::Pending);
        }
        self.source.release()?;
        // SAFETY: Native registration/token and backing have been released under
        // the supplied proof. This bundle has no Child WRs or consumer workers.
        Ok(ReapDecision::Retired(unsafe {
            VerifiedRetirement::new(id)
        }))
    }
}

pub(crate) enum SourceAdmission<K> {
    Registered(ReadOwnerId),
    Rejected {
        error: SourceAdmissionError,
        backing: ReadBacking<K>,
    },
    Uncertain {
        id: ReadOwnerId,
        error: FfiError,
    },
}
#[derive(Debug)]
pub(crate) enum SourceAdmissionError {
    Budget(OwnerError),
    Native(FfiError),
}

pub(crate) trait SourceSlot {
    type Keepalive;
    fn from_source(source: SourceOwner<Self::Keepalive>) -> Self;
    fn source_mut(&mut self) -> Result<&mut SourceOwner<Self::Keepalive>, FfiError>;
}
impl<K> SourceSlot for SourceOwner<K> {
    type Keepalive = K;
    fn from_source(source: Self) -> Self {
        source
    }
    fn source_mut(&mut self) -> Result<&mut Self, FfiError> {
        Ok(self)
    }
}

impl<T: SourceSlot> ReadOwnerRegistry<T> {
    /// Admission and registration execute synchronously on the native owner thread.
    /// # Safety
    /// ReadSource::register's provider, exact-range and immutable Storage backing
    /// requirements still apply. This method supplies source byte/entry admission.
    pub(crate) unsafe fn register_source(
        &mut self,
        peer: ReadPeer,
        runtime: &mut NativeRuntime,
        backing: ReadBacking<T::Keepalive>,
        token: &ReadToken,
    ) -> SourceAdmission<T::Keepalive> {
        let id = match self.reserve(peer, ReadDirection::Source, backing.len()) {
            Ok(id) => id,
            Err(error) => {
                return SourceAdmission::Rejected {
                    error: SourceAdmissionError::Budget(error),
                    backing,
                }
            }
        };
        // SAFETY: Caller supplies provider/backing guarantees; reservation is held.
        let (source, error) = match unsafe { ReadSource::register(runtime, backing, token) } {
            SourceRegistration::Registered(source) => (source, None),
            SourceRegistration::Uncertain { error, source } => (source, Some(error)),
            SourceRegistration::Rejected { error, backing } => {
                self.release_unused_reservation(id)
                    .expect("synchronous untouched reservation");
                return SourceAdmission::Rejected {
                    error: SourceAdmissionError::Native(error),
                    backing,
                };
            }
        };
        let owner = SourceOwner {
            cleanup: SourceCleanup {
                source,
                unregistered: error.is_some(),
            },
        };
        if let Err((_, owner)) = self.attach(id, T::from_source(owner)) {
            // Impossible without registry corruption; retain native backing anyway.
            std::mem::forget(owner);
            panic!("source reservation lost during synchronous registration");
        }
        match error {
            None => SourceAdmission::Registered(id),
            Some(error) => {
                self.quarantine(id, QuarantineReason::RegistrationUncertain)
                    .expect("attached source");
                SourceAdmission::Uncertain { id, error }
            }
        }
    }

    pub(crate) fn source_descriptor(
        &mut self,
        id: ReadOwnerId,
    ) -> Result<ReadDescriptor, SourceAdmissionError> {
        self.active_owner(id)
            .map_err(SourceAdmissionError::Budget)?
            .source_mut()
            .map_err(SourceAdmissionError::Native)?
            .cleanup
            .source
            .descriptor()
            .map_err(SourceAdmissionError::Native)
    }

    /// Caller first retires/quarantines the entry, disabling descriptor dispatch.
    /// Unregister and release failures retain cleanup stage and the full charge.
    pub(crate) fn reap_source(
        &mut self,
        id: ReadOwnerId,
        permit: &UnregisterPermit,
        revoked: Option<&SourceRevoked>,
    ) -> Result<bool, ReapError<FfiError>> {
        self.reap_with(id, |owner| {
            owner.source_mut()?.cleanup.reap(id, permit, revoked)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::read_owner::{OwnerState, ReadBudget, ReadCapacity};
    use std::{cell::RefCell, rc::Rc};

    fn registry<T>() -> ReadOwnerRegistry<T> {
        let cap = |bytes, entries| ReadCapacity { bytes, entries };
        let mut registry = ReadOwnerRegistry::new(ReadBudget {
            total: cap(128, 4),
            destination: cap(64, 2),
            source: cap(64, 2),
            per_peer_destination: cap(64, 2),
            per_peer_source: cap(64, 2),
            quarantine: cap(64, 2),
        })
        .unwrap();
        registry
            .activate_peer(ReadPeer {
                id: 1,
                generation: 1,
            })
            .unwrap();
        registry
    }
    struct MockSource {
        calls: Rc<RefCell<Vec<&'static str>>>,
        unregister_failures: usize,
        release_failures: usize,
    }
    impl SourceResource for MockSource {
        fn unregister(&mut self) -> Result<(), FfiError> {
            self.calls.borrow_mut().push("unregister");
            if self.unregister_failures > 0 {
                self.unregister_failures -= 1;
                return Err(FfiError::Status(-1));
            }
            Ok(())
        }
        fn release(&mut self) -> Result<(), FfiError> {
            self.calls.borrow_mut().push("release");
            if self.release_failures > 0 {
                self.release_failures -= 1;
                return Err(FfiError::Status(-2));
            }
            Ok(())
        }
    }
    impl Drop for MockSource {
        fn drop(&mut self) {
            self.calls.borrow_mut().push("drop");
        }
    }
    fn attach(
        registry: &mut ReadOwnerRegistry<SourceCleanup<MockSource>>,
        unregistered: bool,
        failures: (usize, usize),
    ) -> (ReadOwnerId, Rc<RefCell<Vec<&'static str>>>) {
        let id = registry
            .reserve(
                ReadPeer {
                    id: 1,
                    generation: 1,
                },
                ReadDirection::Source,
                32,
            )
            .unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let owner = SourceCleanup {
            source: MockSource {
                calls: calls.clone(),
                unregister_failures: failures.0,
                release_failures: failures.1,
            },
            unregistered,
        };
        assert!(registry.attach(id, owner).is_ok());
        registry.retire(id).unwrap();
        (id, calls)
    }
    // Only mock resources exist below; these tokens assert no hardware evidence.
    fn proofs(id: ReadOwnerId) -> (UnregisterPermit, SourceRevoked) {
        unsafe { (UnregisterPermit::new(id), SourceRevoked::new(id)) }
    }

    #[test]
    fn unregister_success_waits_for_independent_revocation_and_keeps_budget() {
        let mut registry = registry();
        let (id, calls) = attach(&mut registry, false, (0, 0));
        let (permit, proof) = proofs(id);
        for _ in 0..2 {
            assert_eq!(
                registry.reap_with(id, |s| s.reap(id, &permit, None)),
                Ok(false)
            );
            assert_eq!(registry.usage().source_bytes, 32);
        }
        assert_eq!(&*calls.borrow(), &["unregister"]);
        assert_eq!(
            registry.reap_with(id, |s| s.reap(id, &permit, Some(&proof))),
            Ok(true)
        );
        assert_eq!(&*calls.borrow(), &["unregister", "release", "drop"]);
        assert!(registry.drained());
    }

    #[test]
    fn unregister_and_token_release_failures_preserve_stage_and_charge() {
        let mut registry = registry();
        let (id, calls) = attach(&mut registry, false, (1, 1));
        let (permit, proof) = proofs(id);
        for code in [-1, -2] {
            assert_eq!(
                registry.reap_with(id, |s| s.reap(id, &permit, Some(&proof))),
                Err(ReapError::Cleanup(FfiError::Status(code)))
            );
            assert_eq!(registry.usage().source_bytes, 32);
            assert_eq!(
                registry.state(id),
                Ok(OwnerState::Quarantined(QuarantineReason::CleanupFailed))
            );
        }
        assert_eq!(
            registry.reap_with(id, |s| s.reap(id, &permit, Some(&proof))),
            Ok(true)
        );
        assert_eq!(
            &*calls.borrow(),
            &["unregister", "unregister", "release", "release", "drop"]
        );
        assert!(registry.drained());
    }

    #[test]
    fn uncertain_registration_skips_missing_handle_but_requires_rollback_proof() {
        let mut registry = registry();
        let (id, calls) = attach(&mut registry, true, (0, 0));
        registry
            .quarantine(id, QuarantineReason::RegistrationUncertain)
            .unwrap();
        let (permit, proof) = proofs(id);
        assert_eq!(
            registry.reap_with(id, |s| s.reap(id, &permit, None)),
            Ok(false)
        );
        assert!(calls.borrow().is_empty());
        assert_eq!(
            registry.reap_with(id, |s| s.reap(id, &permit, Some(&proof))),
            Ok(true)
        );
        assert_eq!(&*calls.borrow(), &["release", "drop"]);
    }

    #[test]
    fn mismatched_permit_or_revocation_never_calls_native_cleanup() {
        let mut registry = registry();
        let (id, calls) = attach(&mut registry, false, (0, 0));
        let (other, other_calls) = attach(&mut registry, false, (0, 0));
        let (permit, proof) = proofs(id);
        let (other_permit, other_proof) = proofs(other);
        assert!(registry
            .reap_with(id, |s| s.reap(id, &other_permit, Some(&proof)))
            .is_err());
        assert!(registry
            .reap_with(id, |s| s.reap(id, &permit, Some(&other_proof)))
            .is_err());
        assert!(calls.borrow().is_empty());
        assert!(other_calls.borrow().is_empty());
        assert_eq!(registry.usage().source_bytes, 64);
        registry.begin_shutdown();
        assert_eq!(
            registry.reap_with(id, |s| s.reap(id, &permit, Some(&proof))),
            Ok(true)
        );
        assert_eq!(
            registry.reap_with(other, |s| s.reap(other, &other_permit, Some(&other_proof))),
            Ok(true)
        );
        assert!(registry.drained());
    }
}
