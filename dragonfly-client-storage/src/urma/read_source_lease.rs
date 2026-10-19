//! One Parent transfer's claim on a native source owned by the Fabric.
//!
//! The lease records exposure and cooperative Child drain. It never owns or
//! frees the Segment: cancellation retains it through the existing cleanup
//! guard, and release still requires the caller's provider revocation proof.

use super::{
    read_handoff::ResourceGuard, read_protocol::ReadTransferIdentity, runtime::ReadSourceId, Error,
    Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceLeaseState {
    RegistrationUncertain,
    Unpublished,
    Exposed(u64),
    ChildDrained(u64),
    Released,
}

pub(crate) struct SourceLease {
    source: ReadSourceId,
    transfer: ReadTransferIdentity,
    state: SourceLeaseState,
    guard: Option<ResourceGuard>,
}

impl SourceLease {
    pub(crate) fn new(
        source: ReadSourceId,
        transfer: ReadTransferIdentity,
        registered: bool,
        guard: ResourceGuard,
    ) -> Self {
        Self {
            source,
            transfer,
            state: if registered {
                SourceLeaseState::Unpublished
            } else {
                SourceLeaseState::RegistrationUncertain
            },
            guard: Some(guard),
        }
    }

    /// Arm failure retention before sending an Offer: a cancelled or failed
    /// send may already have disclosed the descriptor to the remote Child.
    /// An unpublished-only cleanup guard must no longer release this source.
    pub(crate) fn expose(
        &mut self,
        generation: u64,
        exposed_guard: Option<ResourceGuard>,
    ) -> Result<()> {
        if generation == 0 || self.state != SourceLeaseState::Unpublished {
            return Err(Error::Protocol("invalid source lease publication".into()));
        }
        self.state = SourceLeaseState::Exposed(generation);
        if let Some(guard) = exposed_guard {
            if let Some(unpublished) = self.guard.replace(guard) {
                unpublished.disarm();
            }
        }
        Ok(())
    }

    /// Called only after ParentReadState validates ReadDone/CancelDrained.
    /// This cooperative drain is not a provider revocation proof.
    pub(crate) fn child_drained(
        &mut self,
        transfer: ReadTransferIdentity,
        generation: u64,
    ) -> Result<()> {
        if transfer != self.transfer || self.state != SourceLeaseState::Exposed(generation) {
            return Err(Error::Protocol(
                "source lease drain identity mismatch".into(),
            ));
        }
        self.state = SourceLeaseState::ChildDrained(generation);
        Ok(())
    }

    pub(crate) fn check_revoke(
        &self,
        source: ReadSourceId,
        transfer: ReadTransferIdentity,
        generation: u64,
    ) -> Result<()> {
        if source != self.source
            || transfer != self.transfer
            || self.state != SourceLeaseState::ChildDrained(generation)
        {
            return Err(Error::Protocol(
                "source lease revoke identity mismatch".into(),
            ));
        }
        Ok(())
    }

    /// # Safety
    /// The native owner has finished unregister and backing release under an
    /// independently validated provider revocation contract for this source.
    /// A peer ACK, timeout, or successful unregister alone is insufficient.
    pub(crate) unsafe fn released_after_revoke(
        &mut self,
        source: ReadSourceId,
        transfer: ReadTransferIdentity,
        generation: u64,
    ) -> Result<()> {
        self.check_revoke(source, transfer, generation)?;
        self.state = SourceLeaseState::Released;
        if let Some(guard) = self.guard.take() {
            guard.disarm();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::read_registry::{
        ReadBudget, ReadCapacity, ReadDirection, ReadOwnerRegistry, ReadPeer,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const TRANSFER: ReadTransferIdentity = ReadTransferIdentity {
        session_generation: 1,
        transfer_id: 2,
        metadata_generation: 3,
    };

    fn source_id() -> ReadSourceId {
        // Registry identity is real, but no native resource is allocated.
        let pool = ReadCapacity {
            bytes: 64,
            entries: 4,
        };
        let mut registry = ReadOwnerRegistry::<()>::new(ReadBudget {
            total: ReadCapacity {
                bytes: 128,
                entries: 8,
            },
            source: pool,
            destination: pool,
            per_peer_source: pool,
            per_peer_destination: pool,
            quarantine: pool,
        })
        .unwrap();
        let peer = ReadPeer {
            id: 1,
            generation: 1,
        };
        registry.activate_peer(peer).unwrap();
        ReadSourceId(registry.reserve(peer, ReadDirection::Source, 32).unwrap())
    }

    fn guard(counter: &Arc<AtomicUsize>) -> ResourceGuard {
        let counter = counter.clone();
        ResourceGuard::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })
    }

    #[test]
    fn cancellation_at_each_stage_keeps_cleanup_armed() {
        for stage in 0..4 {
            let retained = Arc::new(AtomicUsize::new(0));
            let source = source_id();
            let mut lease = SourceLease::new(source, TRANSFER, stage != 0, guard(&retained));
            if stage >= 2 {
                lease.expose(7, None).unwrap();
            }
            if stage >= 3 {
                lease.child_drained(TRANSFER, 7).unwrap();
            }
            drop(lease);
            assert_eq!(retained.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn exposure_replaces_unpublished_cleanup_before_send() {
        let unpublished = Arc::new(AtomicUsize::new(0));
        let exposed = Arc::new(AtomicUsize::new(0));
        let mut lease = SourceLease::new(source_id(), TRANSFER, true, guard(&unpublished));
        lease.expose(7, Some(guard(&exposed))).unwrap();
        // Models cancellation while sending the descriptor, before an ACK.
        drop(lease);
        assert_eq!(unpublished.load(Ordering::SeqCst), 0);
        assert_eq!(exposed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn uncertain_or_repeated_publication_cannot_authorize_drain() {
        let retained = Arc::new(AtomicUsize::new(0));
        let mut lease = SourceLease::new(source_id(), TRANSFER, false, guard(&retained));
        assert!(lease.expose(7, None).is_err());
        assert!(lease.child_drained(TRANSFER, 7).is_err());
        drop(lease);
        let mut lease = SourceLease::new(source_id(), TRANSFER, true, guard(&retained));
        assert!(lease.expose(0, None).is_err());
        lease.expose(7, None).unwrap();
        assert!(lease.expose(8, None).is_err());
        assert!(lease.child_drained(TRANSFER, 8).is_err());
        lease.child_drained(TRANSFER, 7).unwrap();
        assert!(lease.child_drained(TRANSFER, 7).is_err());
        drop(lease);
        assert_eq!(retained.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn wrong_source_session_transfer_or_metadata_never_releases_lease() {
        let retained = Arc::new(AtomicUsize::new(0));
        let source = source_id();
        let mut lease = SourceLease::new(source, TRANSFER, true, guard(&retained));
        assert!(lease.check_revoke(source, TRANSFER, 7).is_err());
        lease.expose(7, None).unwrap();
        assert!(lease.check_revoke(source, TRANSFER, 7).is_err());
        for wrong in [
            ReadTransferIdentity {
                session_generation: 4,
                ..TRANSFER
            },
            ReadTransferIdentity {
                transfer_id: 4,
                ..TRANSFER
            },
            ReadTransferIdentity {
                metadata_generation: 4,
                ..TRANSFER
            },
        ] {
            assert!(lease.child_drained(wrong, 7).is_err());
        }
        lease.child_drained(TRANSFER, 7).unwrap();
        assert!(lease.check_revoke(source_id(), TRANSFER, 7).is_err());
        assert!(lease.check_revoke(source, TRANSFER, 8).is_err());
        assert!(lease
            .check_revoke(
                source,
                ReadTransferIdentity {
                    transfer_id: 4,
                    ..TRANSFER
                },
                7
            )
            .is_err());
        drop(lease);
        assert_eq!(retained.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn successful_release_disarms_cleanup_once() {
        let retained = Arc::new(AtomicUsize::new(0));
        let source = source_id();
        let mut lease = SourceLease::new(source, TRANSFER, true, guard(&retained));
        lease.expose(7, None).unwrap();
        lease.child_drained(TRANSFER, 7).unwrap();
        // SAFETY: This test has no native grants, backing or DMA.
        unsafe {
            lease.released_after_revoke(source, TRANSFER, 7).unwrap();
        }
        assert!(lease.check_revoke(source, TRANSFER, 7).is_err());
        drop(lease);
        assert_eq!(retained.load(Ordering::SeqCst), 0);
    }
}
