//! Single-owner READ resource admission and retirement, independent of a device.
//!
//! Reserve before native allocation/import; attach the resulting ownership bundle
//! even on uncertain registration. Retiring and quarantined resources remain fully
//! charged. The production Runtime must drive cleanup; no timeout implies DMA or
//! revocation completion, and dropping this registry never drops unreaped owners.

use std::{
    collections::BTreeMap,
    mem::ManuallyDrop,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_REGISTRY: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ReadPeer {
    pub(crate) id: u16,
    pub(crate) generation: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ReadOwnerId {
    registry: u64,
    sequence: u64,
    peer: ReadPeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadDirection {
    Destination,
    Source,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadCapacity {
    pub(crate) bytes: u64,
    pub(crate) entries: usize,
}

impl ReadCapacity {
    fn fits(self, limit: Self) -> bool {
        self.bytes > 0
            && self.entries > 0
            && self.bytes <= limit.bytes
            && self.entries <= limit.entries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadBudget {
    pub(crate) total: ReadCapacity,
    pub(crate) destination: ReadCapacity,
    pub(crate) source: ReadCapacity,
    pub(crate) per_peer_destination: ReadCapacity,
    pub(crate) per_peer_source: ReadCapacity,
    pub(crate) quarantine: ReadCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerError {
    InvalidBudget,
    InvalidPeer,
    StalePeer,
    PeerBusy,
    PeerDraining,
    Shutdown,
    QuarantineLimit,
    Capacity,
    InvalidSize,
    IdExhausted,
    UnknownOwner,
    AlreadyAttached,
    OwnerAttached,
    OwnerMissing,
    NotActive,
    NotRetiring,
    WrongProof,
}

impl std::fmt::Display for OwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "READ owner registry: {self:?}")
    }
}

impl std::error::Error for OwnerError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantineReason {
    RegistrationUncertain,
    PostUncertain,
    DrainTimeout,
    RevokeUncertain,
    CleanupFailed,
    WrongProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerState {
    Reserved,
    Active,
    Retiring,
    Quarantined(QuarantineReason),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReadUsage {
    pub(crate) bytes: u64,
    pub(crate) destination_bytes: u64,
    pub(crate) source_bytes: u64,
    pub(crate) destination_entries: usize,
    pub(crate) source_entries: usize,
    pub(crate) entries: usize,
    pub(crate) reserved_entries: usize,
    pub(crate) retiring_entries: usize,
    pub(crate) quarantined_bytes: u64,
    pub(crate) quarantined_entries: usize,
}

/// This cannot be constructed from a timeout, TCP message or local-only CQE.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedRetirement(ReadOwnerId);

impl VerifiedRetirement {
    /// # Safety
    /// All resources belonging to this exact owner must be safe to drop: native
    /// WRs retired, imports closed, consumer workers joined, and remote grants
    /// independently proven revoked with source unregister/token release complete.
    /// The proof covers the whole bundle, including uncertain native operations.
    pub(crate) unsafe fn new(id: ReadOwnerId) -> Self {
        Self(id)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReapDecision {
    Pending,
    Retired(VerifiedRetirement),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReapError<E> {
    Registry(OwnerError),
    Cleanup(E),
}

struct Entry<T> {
    direction: ReadDirection,
    bytes: u64,
    state: OwnerState,
    // Generic bundles may have destructors that release native backing/permits.
    // Only a checked retirement proof permits invoking these destructors.
    owner: Option<ManuallyDrop<T>>,
}

struct PeerState {
    generation: u8,
    active: bool,
}

pub(crate) struct ReadOwnerRegistry<T> {
    budget: ReadBudget,
    registry_id: u64,
    next_sequence: u64,
    accepting: bool,
    // Keep generation high-water marks after drain. The u16 ID namespace bounds
    // tombstone count; an old generation can never be reactivated after reap.
    peers: BTreeMap<u16, PeerState>,
    entries: BTreeMap<ReadOwnerId, Entry<T>>,
}

impl<T> ReadOwnerRegistry<T> {
    pub(crate) fn new(budget: ReadBudget) -> Result<Self, OwnerError> {
        let bytes = budget.destination.bytes.checked_add(budget.source.bytes);
        let entries = budget
            .destination
            .entries
            .checked_add(budget.source.entries);
        if !budget.destination.fits(budget.total)
            || !budget.source.fits(budget.total)
            || bytes.is_none_or(|bytes| bytes > budget.total.bytes)
            || entries.is_none_or(|entries| entries > budget.total.entries)
            || !budget.per_peer_destination.fits(budget.destination)
            || !budget.per_peer_source.fits(budget.source)
            || !budget.quarantine.fits(budget.total)
        {
            return Err(OwnerError::InvalidBudget);
        }
        let registry_id = NEXT_REGISTRY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| OwnerError::IdExhausted)?;
        Ok(Self {
            budget,
            registry_id,
            next_sequence: 1,
            accepting: true,
            peers: BTreeMap::new(),
            entries: BTreeMap::new(),
        })
    }

    pub(crate) fn activate_peer(&mut self, peer: ReadPeer) -> Result<(), OwnerError> {
        if !self.accepting {
            return Err(OwnerError::Shutdown);
        }
        if peer.id == 0 || peer.generation == 0 {
            return Err(OwnerError::InvalidPeer);
        }
        if let Some(previous) = self.peers.get(&peer.id) {
            if peer.generation <= previous.generation {
                return Err(OwnerError::StalePeer);
            }
            if previous.active || self.entries.keys().any(|id| id.peer.id == peer.id) {
                return Err(OwnerError::PeerBusy);
            }
        }
        self.peers.insert(
            peer.id,
            PeerState {
                generation: peer.generation,
                active: true,
            },
        );
        Ok(())
    }

    fn peer(&self, peer: ReadPeer) -> Result<&PeerState, OwnerError> {
        self.peers
            .get(&peer.id)
            .filter(|state| state.generation == peer.generation)
            .ok_or(OwnerError::StalePeer)
    }

    pub(crate) fn usage(&self) -> ReadUsage {
        self.usage_for(None)
    }

    pub(crate) fn peer_usage(&self, peer: ReadPeer) -> ReadUsage {
        self.usage_for(Some(peer))
    }

    fn usage_for(&self, peer: Option<ReadPeer>) -> ReadUsage {
        let mut usage = ReadUsage::default();
        for (id, entry) in &self.entries {
            if peer.is_some_and(|peer| peer != id.peer) {
                continue;
            }
            usage.bytes += entry.bytes;
            usage.entries += 1;
            match entry.direction {
                ReadDirection::Destination => {
                    usage.destination_bytes += entry.bytes;
                    usage.destination_entries += 1;
                }
                ReadDirection::Source => {
                    usage.source_bytes += entry.bytes;
                    usage.source_entries += 1;
                }
            }
            if entry.owner.is_none() {
                usage.reserved_entries += 1;
            }
            match entry.state {
                OwnerState::Retiring => usage.retiring_entries += 1,
                OwnerState::Quarantined(_) => {
                    usage.quarantined_entries += 1;
                    usage.quarantined_bytes += entry.bytes;
                }
                _ => {}
            }
        }
        usage
    }

    /// Non-blocking, atomic owner-thread admission. Charge actual allocation/
    /// registration bytes, including alignment and capacity padding. Source and
    /// destination cannot borrow each other's partition. Runtime supplies bounded
    /// waits/fair scheduling; no native resource may be created before this succeeds.
    pub(crate) fn reserve(
        &mut self,
        peer: ReadPeer,
        direction: ReadDirection,
        bytes: u64,
    ) -> Result<ReadOwnerId, OwnerError> {
        if !self.accepting {
            return Err(OwnerError::Shutdown);
        }
        if !self.peer(peer)?.active {
            return Err(OwnerError::PeerDraining);
        }
        if bytes == 0 {
            return Err(OwnerError::InvalidSize);
        }
        let usage = self.usage();
        if usage.quarantined_bytes >= self.budget.quarantine.bytes
            || usage.quarantined_entries >= self.budget.quarantine.entries
        {
            return Err(OwnerError::QuarantineLimit);
        }
        let peer_usage = self.peer_usage(peer);
        let (used, count, peer_used, peer_count, limit, peer_limit) = match direction {
            ReadDirection::Destination => (
                usage.destination_bytes,
                usage.destination_entries,
                peer_usage.destination_bytes,
                peer_usage.destination_entries,
                self.budget.destination,
                self.budget.per_peer_destination,
            ),
            ReadDirection::Source => (
                usage.source_bytes,
                usage.source_entries,
                peer_usage.source_bytes,
                peer_usage.source_entries,
                self.budget.source,
                self.budget.per_peer_source,
            ),
        };
        if bytes > limit.bytes - used
            || bytes > self.budget.total.bytes - usage.bytes
            || bytes > peer_limit.bytes - peer_used
            || usage.entries >= self.budget.total.entries
            || count >= limit.entries
            || peer_count >= peer_limit.entries
        {
            return Err(OwnerError::Capacity);
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(OwnerError::IdExhausted)?;
        let id = ReadOwnerId {
            registry: self.registry_id,
            sequence,
            peer,
        };
        self.entries.insert(
            id,
            Entry {
                direction,
                bytes,
                state: OwnerState::Reserved,
                owner: None,
            },
        );
        Ok(id)
    }

    /// Ownership is returned on rejection, never implicitly dropped. A reservation
    /// cancelled while native creation was in flight still accepts its result,
    /// retaining Retiring/Quarantined state instead of reopening admission.
    pub(crate) fn attach(&mut self, id: ReadOwnerId, owner: T) -> Result<(), (OwnerError, T)> {
        let Some(entry) = self.entries.get_mut(&id) else {
            return Err((OwnerError::UnknownOwner, owner));
        };
        if entry.owner.is_some() {
            return Err((OwnerError::AlreadyAttached, owner));
        }
        entry.owner = Some(ManuallyDrop::new(owner));
        if entry.state == OwnerState::Reserved {
            entry.state = OwnerState::Active;
        }
        Ok(())
    }

    /// Resolve only a native creation command that never started or returned a
    /// known rejection. An uncertain creation must attach/quarantine its owner.
    pub(crate) fn release_unused_reservation(&mut self, id: ReadOwnerId) -> Result<(), OwnerError> {
        let entry = self.entries.get(&id).ok_or(OwnerError::UnknownOwner)?;
        if entry.owner.is_some() {
            return Err(OwnerError::OwnerAttached);
        }
        if matches!(entry.state, OwnerState::Quarantined(_)) {
            return Err(OwnerError::NotRetiring);
        }
        self.entries.remove(&id);
        Ok(())
    }

    /// Resolve an isolated creation command whose eventual result proves that no
    /// native resource remains. Unlike an ordinary preflight rejection, a timeout
    /// or uncertain reservation requires the same identity-bound proof as an owner.
    pub(crate) fn release_verified_reservation(
        &mut self,
        id: ReadOwnerId,
        proof: VerifiedRetirement,
    ) -> Result<(), OwnerError> {
        let entry = self.entries.get(&id).ok_or(OwnerError::UnknownOwner)?;
        if entry.owner.is_some() {
            return Err(OwnerError::OwnerAttached);
        }
        if proof.0 != id {
            return Err(OwnerError::WrongProof);
        }
        self.entries.remove(&id);
        Ok(())
    }

    pub(crate) fn state(&self, id: ReadOwnerId) -> Result<OwnerState, OwnerError> {
        Ok(self.entries.get(&id).ok_or(OwnerError::UnknownOwner)?.state)
    }

    /// Access for active operations only. Cleanup of draining/quarantined resources
    /// goes through reap_with; normal dispatch cannot accidentally reuse them.
    pub(crate) fn active_owner(&mut self, id: ReadOwnerId) -> Result<&mut T, OwnerError> {
        let entry = self.entries.get_mut(&id).ok_or(OwnerError::UnknownOwner)?;
        if entry.state != OwnerState::Active {
            return Err(OwnerError::NotActive);
        }
        entry.owner.as_deref_mut().ok_or(OwnerError::OwnerMissing)
    }

    /// Completion delivery must remain possible after retire/quarantine. This
    /// does not authorize new work; dispatch must still use active_owner.
    pub(crate) fn retained_owner(&mut self, id: ReadOwnerId) -> Result<&mut T, OwnerError> {
        self.entries
            .get_mut(&id)
            .ok_or(OwnerError::UnknownOwner)?
            .owner
            .as_deref_mut()
            .ok_or(OwnerError::OwnerMissing)
    }

    pub(crate) fn retire(&mut self, id: ReadOwnerId) -> Result<(), OwnerError> {
        let entry = self.entries.get_mut(&id).ok_or(OwnerError::UnknownOwner)?;
        if !matches!(entry.state, OwnerState::Quarantined(_)) {
            entry.state = OwnerState::Retiring;
        }
        Ok(())
    }

    /// This trigger may be exceeded by already-admitted work becoming uncertain.
    /// Keep every owner charged; never evict a quarantine to enforce its threshold.
    pub(crate) fn quarantine(
        &mut self,
        id: ReadOwnerId,
        reason: QuarantineReason,
    ) -> Result<(), OwnerError> {
        let entry = self.entries.get_mut(&id).ok_or(OwnerError::UnknownOwner)?;
        entry.state = OwnerState::Quarantined(reason);
        Ok(())
    }

    pub(crate) fn drain_peer(&mut self, peer: ReadPeer) -> Result<(), OwnerError> {
        self.peer(peer)?;
        self.peers.get_mut(&peer.id).expect("validated peer").active = false;
        for (id, entry) in &mut self.entries {
            if id.peer == peer && !matches!(entry.state, OwnerState::Quarantined(_)) {
                entry.state = OwnerState::Retiring;
            }
        }
        Ok(())
    }

    pub(crate) fn begin_shutdown(&mut self) {
        self.accepting = false;
        for peer in self.peers.values_mut() {
            peer.active = false;
        }
        for entry in self.entries.values_mut() {
            if !matches!(entry.state, OwnerState::Quarantined(_)) {
                entry.state = OwnerState::Retiring;
            }
        }
    }

    pub(crate) fn drained(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bounded by entry admission. Includes unresolved reservations: the owner
    /// loop must resolve their pending creation result before attempting cleanup.
    pub(crate) fn retirement_candidates(&self) -> Vec<ReadOwnerId> {
        self.entries
            .iter()
            .filter_map(|(id, entry)| {
                matches!(
                    entry.state,
                    OwnerState::Retiring | OwnerState::Quarantined(_)
                )
                .then_some(*id)
            })
            .collect()
    }

    /// Retry cleanup without removing its owner. Only a proof for this registry,
    /// sequence and peer generation can release bytes/entries. Errors quarantine
    /// the bundle and preserve progress made by a partially successful cleanup.
    pub(crate) fn reap_with<E>(
        &mut self,
        id: ReadOwnerId,
        cleanup: impl FnOnce(&mut T) -> Result<ReapDecision, E>,
    ) -> Result<bool, ReapError<E>> {
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(ReapError::Registry(OwnerError::UnknownOwner))?;
        if !matches!(
            entry.state,
            OwnerState::Retiring | OwnerState::Quarantined(_)
        ) {
            return Err(ReapError::Registry(OwnerError::NotRetiring));
        }
        let owner = entry
            .owner
            .as_deref_mut()
            .ok_or(ReapError::Registry(OwnerError::OwnerMissing))?;
        match cleanup(owner) {
            Ok(ReapDecision::Pending) => Ok(false),
            Err(error) => {
                entry.state = OwnerState::Quarantined(QuarantineReason::CleanupFailed);
                Err(ReapError::Cleanup(error))
            }
            Ok(ReapDecision::Retired(proof)) if proof.0 != id => {
                entry.state = OwnerState::Quarantined(QuarantineReason::WrongProof);
                Err(ReapError::Registry(OwnerError::WrongProof))
            }
            Ok(ReapDecision::Retired(_)) => {
                let mut entry = self.entries.remove(&id).expect("entry validated");
                // SAFETY: The checked VerifiedRetirement authorizes dropping this
                // entire ownership bundle; it is removed and taken exactly once.
                unsafe { ManuallyDrop::drop(entry.owner.as_mut().expect("owner validated")) };
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    const A: ReadPeer = ReadPeer {
        id: 1,
        generation: 1,
    };
    const B: ReadPeer = ReadPeer {
        id: 2,
        generation: 1,
    };

    fn capacity(bytes: u64, entries: usize) -> ReadCapacity {
        ReadCapacity { bytes, entries }
    }

    fn budget() -> ReadBudget {
        ReadBudget {
            total: capacity(128, 8),
            destination: capacity(64, 4),
            source: capacity(64, 4),
            per_peer_destination: capacity(32, 2),
            per_peer_source: capacity(32, 2),
            quarantine: capacity(32, 2),
        }
    }

    fn registry<T>() -> ReadOwnerRegistry<T> {
        let mut registry = ReadOwnerRegistry::new(budget()).unwrap();
        registry.activate_peer(A).unwrap();
        registry.activate_peer(B).unwrap();
        registry
    }

    fn attach(registry: &mut ReadOwnerRegistry<u32>, peer: ReadPeer, bytes: u64) -> ReadOwnerId {
        let id = registry
            .reserve(peer, ReadDirection::Destination, bytes)
            .unwrap();
        registry.attach(id, 0).unwrap();
        id
    }

    fn proof(id: ReadOwnerId) -> ReapDecision {
        // SAFETY: Tests use ordinary counters, with no native grants/DMA/workers.
        ReapDecision::Retired(unsafe { VerifiedRetirement::new(id) })
    }

    fn reap(registry: &mut ReadOwnerRegistry<u32>, id: ReadOwnerId) {
        assert_eq!(registry.reap_with(id, |_| Ok::<_, ()>(proof(id))), Ok(true));
    }

    #[test]
    fn invalid_partition_overflow_and_zero_threshold_are_rejected() {
        let mut invalid = budget();
        invalid.source.bytes = u64::MAX;
        assert!(matches!(
            ReadOwnerRegistry::<()>::new(invalid),
            Err(OwnerError::InvalidBudget)
        ));
        invalid = budget();
        invalid.source.entries = usize::MAX;
        assert!(matches!(
            ReadOwnerRegistry::<()>::new(invalid),
            Err(OwnerError::InvalidBudget)
        ));
        invalid = budget();
        invalid.quarantine.bytes = 0;
        assert!(matches!(
            ReadOwnerRegistry::<()>::new(invalid),
            Err(OwnerError::InvalidBudget)
        ));
        invalid = budget();
        invalid.per_peer_destination.bytes = 65;
        assert!(matches!(
            ReadOwnerRegistry::<()>::new(invalid),
            Err(OwnerError::InvalidBudget)
        ));
    }

    #[test]
    fn source_has_byte_and_entry_headroom_when_same_peers_fill_destination() {
        let mut r = registry::<u32>();
        for peer in [A, B] {
            for _ in 0..2 {
                attach(&mut r, peer, 16);
            }
            assert_eq!(
                r.reserve(peer, ReadDirection::Destination, 1),
                Err(OwnerError::Capacity)
            );
        }
        assert_eq!(r.usage().destination_bytes, 64);
        for peer in [A, B] {
            for _ in 0..2 {
                let id = r.reserve(peer, ReadDirection::Source, 16).unwrap();
                r.attach(id, 0).unwrap();
            }
        }
        assert_eq!(r.usage().bytes, 128);
        assert_eq!(r.usage().entries, 8);
        assert_eq!(r.peer_usage(A).bytes, 64);
        r.begin_shutdown();
        for id in r.retirement_candidates() {
            reap(&mut r, id);
        }
        assert!(r.drained());
    }

    #[test]
    fn admission_failure_is_atomic_and_limits_are_not_borrowed() {
        let mut r = registry::<u32>();
        let id = attach(&mut r, A, 32);
        let before = r.usage();
        assert_eq!(
            r.reserve(A, ReadDirection::Destination, 1),
            Err(OwnerError::Capacity)
        );
        assert_eq!(
            r.reserve(B, ReadDirection::Source, u64::MAX),
            Err(OwnerError::Capacity)
        );
        assert_eq!(
            r.reserve(B, ReadDirection::Source, 0),
            Err(OwnerError::InvalidSize)
        );
        assert_eq!(r.usage(), before);
        r.retire(id).unwrap();
        assert_eq!(r.usage().bytes, 32);
        assert_eq!(
            r.reap_with(id, |_| Ok::<_, ()>(ReapDecision::Pending)),
            Ok(false)
        );
        assert_eq!(r.usage().bytes, 32);
        reap(&mut r, id);
    }

    #[test]
    fn failed_cleanup_is_retryable_without_losing_owner_or_charge() {
        let mut r = registry::<u32>();
        let id = attach(&mut r, A, 16);
        r.retire(id).unwrap();
        let result = r.reap_with(id, |owner| {
            *owner = 7;
            Err("unimport failed")
        });
        assert_eq!(result, Err(ReapError::Cleanup("unimport failed")));
        assert_eq!(r.usage().quarantined_bytes, 16);
        assert_eq!(r.active_owner(id), Err(OwnerError::NotActive));
        assert_eq!(
            r.reap_with(id, |owner| {
                assert_eq!(*owner, 7);
                Ok::<_, ()>(proof(id))
            }),
            Ok(true)
        );
        assert_eq!(r.usage(), ReadUsage::default());
        assert_eq!(
            r.reap_with(id, |_| Ok::<_, ()>(proof(id))),
            Err(ReapError::Registry(OwnerError::UnknownOwner))
        );
    }

    #[test]
    fn quarantine_is_a_stop_trigger_not_an_eviction_limit() {
        let mut r = registry::<u32>();
        let a = attach(&mut r, A, 32);
        let b = attach(&mut r, B, 32);
        r.quarantine(a, QuarantineReason::RevokeUncertain).unwrap();
        assert_eq!(
            r.reserve(A, ReadDirection::Source, 1),
            Err(OwnerError::QuarantineLimit)
        );
        r.quarantine(b, QuarantineReason::DrainTimeout).unwrap();
        assert_eq!(r.usage().quarantined_bytes, 64);
        assert_eq!(r.usage().entries, 2);
        r.retire(a).unwrap();
        assert!(matches!(r.state(a), Ok(OwnerState::Quarantined(_))));
        reap(&mut r, a);
        assert_eq!(
            r.reserve(A, ReadDirection::Source, 1),
            Err(OwnerError::QuarantineLimit)
        );
        reap(&mut r, b);
        let next = r.reserve(A, ReadDirection::Source, 1).unwrap();
        r.release_unused_reservation(next).unwrap();
    }

    #[test]
    fn quarantine_entry_threshold_also_stops_admission() {
        let mut r = registry::<u32>();
        let a = attach(&mut r, A, 1);
        let b = attach(&mut r, B, 1);
        r.quarantine(a, QuarantineReason::PostUncertain).unwrap();
        r.quarantine(b, QuarantineReason::RegistrationUncertain)
            .unwrap();
        assert_eq!(
            r.reserve(A, ReadDirection::Source, 1),
            Err(OwnerError::QuarantineLimit)
        );
        reap(&mut r, a);
        reap(&mut r, b);
    }

    #[test]
    fn shutdown_preserves_inflight_reservations_and_accepts_their_late_owners() {
        let mut r = registry::<u32>();
        let id = r.reserve(A, ReadDirection::Source, 32).unwrap();
        r.begin_shutdown();
        assert!(!r.drained());
        assert_eq!(r.usage().reserved_entries, 1);
        assert_eq!(
            r.reserve(B, ReadDirection::Source, 1),
            Err(OwnerError::Shutdown)
        );
        assert_eq!(
            r.reap_with(id, |_| Ok::<_, ()>(proof(id))),
            Err(ReapError::Registry(OwnerError::OwnerMissing))
        );
        r.attach(id, 9).unwrap();
        assert_eq!(r.state(id), Ok(OwnerState::Retiring));
        assert_eq!(
            r.release_unused_reservation(id),
            Err(OwnerError::OwnerAttached)
        );
        reap(&mut r, id);
        assert!(r.drained());
    }

    #[test]
    fn peer_drain_isolated_and_generation_cannot_reuse_old_owners() {
        let mut r = registry::<u32>();
        let a = attach(&mut r, A, 16);
        let b = attach(&mut r, B, 16);
        let next = ReadPeer { generation: 2, ..A };
        r.drain_peer(A).unwrap();
        assert_eq!(r.state(a), Ok(OwnerState::Retiring));
        assert_eq!(r.state(b), Ok(OwnerState::Active));
        assert_eq!(
            r.reserve(A, ReadDirection::Source, 1),
            Err(OwnerError::PeerDraining)
        );
        assert_eq!(r.activate_peer(next), Err(OwnerError::PeerBusy));
        reap(&mut r, a);
        assert_eq!(r.activate_peer(A), Err(OwnerError::StalePeer));
        r.activate_peer(next).unwrap();
        assert_eq!(r.drain_peer(A), Err(OwnerError::StalePeer));
        let c = attach(&mut r, next, 16);
        assert_ne!(c, a);
        r.begin_shutdown();
        for id in r.retirement_candidates() {
            reap(&mut r, id);
        }
    }

    #[test]
    fn cross_registry_id_and_wrong_retirement_proof_do_not_release() {
        let mut r = registry::<u32>();
        let mut other = registry::<u32>();
        let a = attach(&mut r, A, 16);
        let b = attach(&mut other, A, 16);
        assert_ne!(a, b);
        assert_eq!(r.retire(b), Err(OwnerError::UnknownOwner));
        r.retire(a).unwrap();
        assert_eq!(
            r.reap_with(a, |_| Ok::<_, ()>(proof(b))),
            Err(ReapError::Registry(OwnerError::WrongProof))
        );
        assert_eq!(r.usage().bytes, 16);
        reap(&mut r, a);
        other.retire(b).unwrap();
        reap(&mut other, b);
    }

    #[test]
    fn reservation_resolution_and_rejected_attach_return_ownership() {
        let mut r = registry::<u32>();
        let id = r.reserve(A, ReadDirection::Source, 16).unwrap();
        r.retire(id).unwrap();
        r.release_unused_reservation(id).unwrap();
        assert_eq!(r.attach(id, 42), Err((OwnerError::UnknownOwner, 42)));
        let id = attach(&mut r, A, 16);
        assert_eq!(r.attach(id, 43), Err((OwnerError::AlreadyAttached, 43)));
        assert_eq!(
            r.reap_with(id, |_| Ok::<_, ()>(proof(id))),
            Err(ReapError::Registry(OwnerError::NotRetiring))
        );
        r.retire(id).unwrap();
        reap(&mut r, id);
    }

    #[test]
    fn late_creation_resolves_quarantine_without_reopening_or_unaccounted_release() {
        let mut r = registry::<u32>();
        let id = r.reserve(A, ReadDirection::Source, 16).unwrap();
        r.quarantine(id, QuarantineReason::RegistrationUncertain)
            .unwrap();
        assert_eq!(
            r.release_unused_reservation(id),
            Err(OwnerError::NotRetiring)
        );
        r.attach(id, 3).unwrap();
        assert_eq!(
            r.state(id),
            Ok(OwnerState::Quarantined(
                QuarantineReason::RegistrationUncertain
            ))
        );
        assert_eq!(r.usage().quarantined_bytes, 16);
        reap(&mut r, id);

        let empty = r.reserve(A, ReadDirection::Source, 16).unwrap();
        r.quarantine(empty, QuarantineReason::DrainTimeout).unwrap();
        // SAFETY: Test commands never created native resources; the old identity
        // deliberately checks proof matching, not provider behavior.
        let old = unsafe { VerifiedRetirement::new(id) };
        assert_eq!(
            r.release_verified_reservation(empty, old),
            Err(OwnerError::WrongProof)
        );
        assert_eq!(r.usage().quarantined_bytes, 16);
        // SAFETY: The simulated late result confirms this exact creation never ran.
        let verified = unsafe { VerifiedRetirement::new(empty) };
        r.release_verified_reservation(empty, verified).unwrap();
        assert!(r.drained());
    }

    #[test]
    fn sequence_and_peer_generation_never_wrap() {
        let mut r = registry::<u32>();
        r.next_sequence = u64::MAX;
        assert_eq!(
            r.reserve(A, ReadDirection::Source, 1),
            Err(OwnerError::IdExhausted)
        );
        assert!(r.drained());
        let last = ReadPeer {
            id: 3,
            generation: u8::MAX,
        };
        r.activate_peer(last).unwrap();
        r.drain_peer(last).unwrap();
        assert_eq!(
            r.activate_peer(ReadPeer {
                generation: 1,
                ..last
            }),
            Err(OwnerError::StalePeer)
        );
    }

    #[test]
    fn dropping_registry_never_drops_unreaped_bundles() {
        struct Guard(Rc<Cell<usize>>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Rc::new(Cell::new(0));
        let owner = Rc::new(Guard(drops.clone()));
        let cleanup_pointer = Rc::as_ptr(&owner);
        let mut r = registry::<Rc<Guard>>();
        let id = r.reserve(A, ReadDirection::Source, 16).unwrap();
        assert!(r.attach(id, owner.clone()).is_ok());
        drop(r);
        assert_eq!(Rc::strong_count(&owner), 2);
        assert_eq!(drops.get(), 0);
        // SAFETY: This device-free test knows the forgotten registry held exactly
        // one Rc clone. Reclaim that clone; no native resources exist here.
        unsafe {
            drop(Rc::from_raw(cleanup_pointer));
        }
        drop(owner);
        assert_eq!(drops.get(), 1);
    }
}
