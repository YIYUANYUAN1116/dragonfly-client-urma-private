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

/// A peer's use of a source registration. The registration keeps its own ID
/// and physical charge even when the peer that first used it has departed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ReadSourceLeaseId {
    source: ReadOwnerId,
    sequence: u64,
}

struct SourceLeaseCharge {
    peer: ReadPeer,
    bytes: u64,
}

impl ReadOwnerId {
    /// Destination peer, or the internal id-zero scope for a physical source.
    /// Source peer usage/lifetime is tracked by leases, not this scope value.
    pub(crate) fn peer(self) -> ReadPeer {
        self.peer
    }
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
    UnknownLease,
    SourceBusy,
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
    #[cfg(test)]
    DrainTimeout,
    #[cfg(test)]
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
    /// independently proven revoked with source unregister and bundle release
    /// complete. A shared runtime token and pooled buffers may outlive this owner.
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
    source_leases: BTreeMap<ReadSourceLeaseId, SourceLeaseCharge>,
    next_source_lease: u64,
    // The existing per-Piece API owns this first lease. Additional leases must
    // be explicitly drained before it can invoke native cleanup. Cached sources
    // will release their leases separately and retain the physical registration.
    primary_source_lease: Option<ReadSourceLeaseId>,
}

impl<T> Entry<T> {
    fn charged_to(&self, id: ReadOwnerId, peer: ReadPeer) -> bool {
        match self.direction {
            ReadDirection::Destination => id.peer == peer,
            ReadDirection::Source => self.source_leases.values().any(|lease| lease.peer == peer),
        }
    }
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
    pub(crate) fn identity(&self) -> u64 {
        self.registry_id
    }

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
            if previous.active
                || self.entries.iter().any(|(id, entry)| {
                    entry.charged_to(
                        *id,
                        ReadPeer {
                            id: peer.id,
                            generation: previous.generation,
                        },
                    )
                })
            {
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
        // Source usage is logical lease bytes/entries. Global usage counts each
        // physical source once; summing peer usage need not equal global usage.
        self.usage_for(Some(peer))
    }

    fn usage_for(&self, peer: Option<ReadPeer>) -> ReadUsage {
        let mut usage = ReadUsage::default();
        for (id, entry) in &self.entries {
            let (bytes, count) = match (peer, entry.direction) {
                (None, _) => (entry.bytes, 1),
                (Some(peer), ReadDirection::Destination) if peer == id.peer => (entry.bytes, 1),
                (Some(peer), ReadDirection::Source) => entry
                    .source_leases
                    .values()
                    .filter(|lease| lease.peer == peer)
                    .fold((0, 0), |(bytes, count), lease| {
                        (bytes + lease.bytes, count + 1)
                    }),
                _ => (0, 0),
            };
            if count == 0 {
                continue;
            }
            usage.bytes += bytes;
            usage.entries += count;
            match entry.direction {
                ReadDirection::Destination => {
                    usage.destination_bytes += bytes;
                    usage.destination_entries += count;
                }
                ReadDirection::Source => {
                    usage.source_bytes += bytes;
                    usage.source_entries += count;
                }
            }
            if entry.owner.is_none() {
                usage.reserved_entries += count;
            }
            match entry.state {
                OwnerState::Retiring => usage.retiring_entries += count,
                OwnerState::Quarantined(_) => {
                    usage.quarantined_entries += count;
                    usage.quarantined_bytes += bytes;
                }
                _ => {}
            }
        }
        usage
    }

    /// Non-blocking admission for a dedicated Piece. Source bytes are charged
    /// once to the physical pool and independently to its initial peer lease.
    /// No native resource may be created before both reservations succeed.
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
        if direction == ReadDirection::Source {
            let id = self.reserve_source(bytes)?;
            match self.acquire_source_lease(id, peer, bytes) {
                Ok(lease) => {
                    self.entries
                        .get_mut(&id)
                        .expect("inserted source")
                        .primary_source_lease = Some(lease);
                    return Ok(id);
                }
                Err(error) => {
                    // Native registration has not started, so the physical
                    // reservation may be rolled back without a revocation proof.
                    self.entries.remove(&id);
                    return Err(error);
                }
            }
        }
        // Preserve quarantine as the process-wide stop reason even when this
        // peer's destination quota is also exhausted.
        let usage = self.usage();
        if usage.quarantined_bytes >= self.budget.quarantine.bytes
            || usage.quarantined_entries >= self.budget.quarantine.entries
        {
            return Err(OwnerError::QuarantineLimit);
        }
        let used = self.peer_usage(peer);
        let limit = self.budget.per_peer_destination;
        if bytes > limit.bytes.saturating_sub(used.destination_bytes)
            || used.destination_entries >= limit.entries
        {
            return Err(OwnerError::Capacity);
        }
        self.reserve_physical(peer, direction, bytes)
    }

    /// Source registrations belong to this registry, not the first Child.
    /// Peer id zero is internal and can never be activated as a network peer.
    pub(crate) fn reserve_source(&mut self, bytes: u64) -> Result<ReadOwnerId, OwnerError> {
        self.reserve_physical(
            ReadPeer {
                id: 0,
                generation: 1,
            },
            ReadDirection::Source,
            bytes,
        )
    }

    fn reserve_physical(
        &mut self,
        owner_peer: ReadPeer,
        direction: ReadDirection,
        bytes: u64,
    ) -> Result<ReadOwnerId, OwnerError> {
        if !self.accepting {
            return Err(OwnerError::Shutdown);
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
        let (used, count, limit) = match direction {
            ReadDirection::Destination => (
                usage.destination_bytes,
                usage.destination_entries,
                self.budget.destination,
            ),
            ReadDirection::Source => (usage.source_bytes, usage.source_entries, self.budget.source),
        };
        if bytes > limit.bytes.saturating_sub(used)
            || bytes > self.budget.total.bytes.saturating_sub(usage.bytes)
            || usage.entries >= self.budget.total.entries
            || count >= limit.entries
        {
            return Err(OwnerError::Capacity);
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(OwnerError::IdExhausted)?;
        let id = ReadOwnerId {
            registry: self.registry_id,
            sequence,
            peer: owner_peer,
        };
        self.entries.insert(
            id,
            Entry {
                direction,
                bytes,
                state: OwnerState::Reserved,
                owner: None,
                source_leases: BTreeMap::new(),
                next_source_lease: 1,
                primary_source_lease: None,
            },
        );
        Ok(id)
    }

    pub(crate) fn acquire_source_lease(
        &mut self,
        source: ReadOwnerId,
        peer: ReadPeer,
        bytes: u64,
    ) -> Result<ReadSourceLeaseId, OwnerError> {
        if !self.accepting {
            return Err(OwnerError::Shutdown);
        }
        if !self.peer(peer)?.active {
            return Err(OwnerError::PeerDraining);
        }
        let entry = self.entries.get(&source).ok_or(OwnerError::UnknownOwner)?;
        if entry.direction != ReadDirection::Source {
            return Err(OwnerError::NotActive);
        }
        // Only the initial lease may precede the native registration result.
        if entry.state != OwnerState::Active
            && !(entry.state == OwnerState::Reserved && entry.next_source_lease == 1)
        {
            return Err(OwnerError::NotActive);
        }
        if bytes == 0 || bytes > entry.bytes {
            return Err(OwnerError::InvalidSize);
        }
        let usage = self.usage();
        if usage.quarantined_bytes >= self.budget.quarantine.bytes
            || usage.quarantined_entries >= self.budget.quarantine.entries
        {
            return Err(OwnerError::QuarantineLimit);
        }
        let usage = self.peer_usage(peer);
        let limit = self.budget.per_peer_source;
        if bytes > limit.bytes.saturating_sub(usage.source_bytes)
            || usage.source_entries >= limit.entries
        {
            return Err(OwnerError::Capacity);
        }
        let entry = self.entries.get_mut(&source).expect("validated source");
        let sequence = entry.next_source_lease;
        entry.next_source_lease = sequence.checked_add(1).ok_or(OwnerError::IdExhausted)?;
        let lease = ReadSourceLeaseId { source, sequence };
        entry
            .source_leases
            .insert(lease, SourceLeaseCharge { peer, bytes });
        Ok(lease)
    }

    /// # Safety
    /// This exact lease has finished all remote accesses and cannot resume
    /// them. Timeout/EOF or dropping a future is insufficient. Releasing a lease
    /// never unregisters the source or releases its physical charge/backing.
    pub(crate) unsafe fn release_source_lease(
        &mut self,
        lease: ReadSourceLeaseId,
    ) -> Result<(), OwnerError> {
        let entry = self
            .entries
            .get_mut(&lease.source)
            .ok_or(OwnerError::UnknownOwner)?;
        entry
            .source_leases
            .remove(&lease)
            .ok_or(OwnerError::UnknownLease)?;
        if entry.primary_source_lease == Some(lease) {
            entry.primary_source_lease = None;
        }
        Ok(())
    }

    /// Existing dedicated-Piece cleanup may retire its primary lease together
    /// with the registration under the caller's revocation proof. Any additional
    /// lease blocks native cleanup, even after its peer has started draining.
    pub(crate) fn check_source_cleanup(&self, id: ReadOwnerId) -> Result<(), OwnerError> {
        let entry = self.entries.get(&id).ok_or(OwnerError::UnknownOwner)?;
        if entry.direction == ReadDirection::Source
            && entry
                .source_leases
                .keys()
                .any(|lease| Some(*lease) != entry.primary_source_lease)
        {
            return Err(OwnerError::SourceBusy);
        }
        Ok(())
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
    #[cfg(test)]
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
            // A shared registration has no dedicated primary lease. Its cache
            // controls retirement, even when its final peer starts draining;
            // outstanding peer lease charges still remain until explicit drain.
            let draining = entry.charged_to(*id, peer)
                && (entry.direction == ReadDirection::Destination
                    || (entry.primary_source_lease.is_some()
                        && !entry.source_leases.values().any(|lease| {
                            self.peers.get(&lease.peer.id).is_some_and(|state| {
                                state.generation == lease.peer.generation && state.active
                            })
                        })));
            if draining && !matches!(entry.state, OwnerState::Quarantined(_)) {
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
    #[cfg(test)]
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
        // Do not invoke a native unregister/release closure while another
        // transfer still owns a lease; checking only after cleanup is too late.
        self.check_source_cleanup(id).map_err(ReapError::Registry)?;
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
                if let Some(lease) = entry.primary_source_lease {
                    // SAFETY: The checked owner proof covers this registration
                    // and all accesses of its sole remaining dedicated lease.
                    unsafe { self.release_source_lease(lease) }.map_err(ReapError::Registry)?;
                }
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

    fn unlease(registry: &mut ReadOwnerRegistry<u32>, lease: ReadSourceLeaseId) {
        // SAFETY: All tests below use integer owners with no remote accesses.
        unsafe { registry.release_source_lease(lease).unwrap() };
    }

    #[test]
    fn shared_source_physical_charge_and_peer_lease_limits_are_independent() {
        let mut r = registry::<u32>();
        // The physical source may exceed a peer's Piece-lease budget.
        let source = r.reserve_source(64).unwrap();
        assert_eq!(
            source.peer(),
            ReadPeer {
                id: 0,
                generation: 1
            }
        );
        assert_eq!(r.activate_peer(source.peer()), Err(OwnerError::InvalidPeer));
        r.attach(source, 7).unwrap();
        let a1 = r.acquire_source_lease(source, A, 16).unwrap();
        let a2 = r.acquire_source_lease(source, A, 16).unwrap();
        let b = r.acquire_source_lease(source, B, 32).unwrap();
        assert_eq!(r.usage().source_bytes, 64);
        assert_eq!(r.usage().source_entries, 1);
        assert_eq!(r.peer_usage(A).source_bytes, 32);
        assert_eq!(r.peer_usage(A).source_entries, 2);
        assert_eq!(r.peer_usage(B).source_bytes, 32);
        let before = r.usage();
        assert_eq!(
            r.acquire_source_lease(source, A, 1),
            Err(OwnerError::Capacity)
        );
        assert_eq!(
            r.acquire_source_lease(source, B, 1),
            Err(OwnerError::Capacity)
        );
        assert_eq!(
            r.acquire_source_lease(source, B, 0),
            Err(OwnerError::InvalidSize)
        );
        assert_eq!(
            r.acquire_source_lease(source, B, 65),
            Err(OwnerError::InvalidSize)
        );
        assert_eq!(r.usage(), before);
        for lease in [a1, a2, b] {
            unlease(&mut r, lease);
        }
        assert_eq!(r.peer_usage(A), ReadUsage::default());
        assert_eq!(r.usage().source_bytes, 64);
        r.retire(source).unwrap();
        reap(&mut r, source);
        assert!(r.drained());
    }

    #[test]
    fn first_peer_drain_cannot_retire_another_peers_source_lease() {
        let mut r = registry::<u32>();
        let source = r.reserve_source(32).unwrap();
        r.attach(source, 1).unwrap();
        let a = r.acquire_source_lease(source, A, 16).unwrap();
        let b = r.acquire_source_lease(source, B, 16).unwrap();
        r.drain_peer(A).unwrap();
        assert_eq!(r.state(source), Ok(OwnerState::Active));
        assert_eq!(r.peer_usage(A).source_bytes, 16);
        assert_eq!(
            r.acquire_source_lease(source, A, 1),
            Err(OwnerError::PeerDraining)
        );
        let next = ReadPeer { generation: 2, ..A };
        assert_eq!(r.activate_peer(next), Err(OwnerError::PeerBusy));
        unlease(&mut r, a);
        r.activate_peer(next).unwrap();
        let newer = r.acquire_source_lease(source, next, 16).unwrap();
        assert_eq!(
            unsafe { r.release_source_lease(a) },
            Err(OwnerError::UnknownLease)
        );
        assert_eq!(r.peer_usage(next).source_bytes, 16);
        assert_eq!(
            r.acquire_source_lease(source, A, 1),
            Err(OwnerError::StalePeer)
        );
        r.retire(source).unwrap();
        assert_eq!(
            r.acquire_source_lease(source, B, 1),
            Err(OwnerError::NotActive)
        );
        assert_eq!(
            r.reap_with(source, |_| -> Result<_, ()> {
                panic!("must reject before native cleanup")
            }),
            Err(ReapError::Registry(OwnerError::SourceBusy))
        );
        unlease(&mut r, b);
        assert_eq!(r.check_source_cleanup(source), Err(OwnerError::SourceBusy));
        unlease(&mut r, newer);
        reap(&mut r, source);
    }

    #[test]
    fn extra_lease_blocks_cleanup_and_failed_cleanup_keeps_primary_charge() {
        let mut r = registry::<u32>();
        let source = r.reserve(A, ReadDirection::Source, 16).unwrap();
        r.attach(source, 1).unwrap();
        let b = r.acquire_source_lease(source, B, 16).unwrap();
        r.retire(source).unwrap();
        assert_eq!(
            r.reap_with(source, |_| -> Result<_, ()> {
                panic!("must reject before native unregister")
            }),
            Err(ReapError::Registry(OwnerError::SourceBusy))
        );
        unlease(&mut r, b);
        assert_eq!(
            r.reap_with(source, |_| Err("unregister failed")),
            Err(ReapError::Cleanup("unregister failed"))
        );
        assert_eq!(r.usage().quarantined_bytes, 16);
        assert_eq!(r.peer_usage(A).source_bytes, 16);
        assert_eq!(
            r.reap_with(source, |_| Ok::<_, ()>(ReapDecision::Pending)),
            Ok(false)
        );
        assert_eq!(r.peer_usage(A).source_bytes, 16);
        reap(&mut r, source);
        assert_eq!(r.peer_usage(A), ReadUsage::default());
    }

    #[test]
    fn lease_identity_cannot_alias_a_different_source_or_registry() {
        let mut r = registry::<u32>();
        let source = r.reserve_source(16).unwrap();
        r.attach(source, 1).unwrap();
        let old = r.acquire_source_lease(source, A, 8).unwrap();
        unlease(&mut r, old);
        let newer = r.acquire_source_lease(source, A, 8).unwrap();
        assert_ne!(old, newer);
        assert_eq!(
            unsafe { r.release_source_lease(old) },
            Err(OwnerError::UnknownLease)
        );
        let second = r.reserve_source(16).unwrap();
        r.attach(second, 2).unwrap();
        let other = r.acquire_source_lease(second, B, 8).unwrap();
        assert_eq!(old.sequence, other.sequence);
        assert_ne!(old, other);
        assert_eq!(
            unsafe { r.release_source_lease(old) },
            Err(OwnerError::UnknownLease)
        );
        assert_eq!(r.peer_usage(B).source_bytes, 8);
        let mut foreign = registry::<u32>();
        assert_eq!(
            unsafe { foreign.release_source_lease(newer) },
            Err(OwnerError::UnknownOwner)
        );
        assert_eq!(r.peer_usage(A).source_bytes, 8);
        unlease(&mut r, newer);
        unlease(&mut r, other);
        for id in [source, second] {
            r.retire(id).unwrap();
            reap(&mut r, id);
        }
    }

    #[test]
    fn peer_lease_rejection_rolls_back_physical_source_reservation() {
        let mut r = registry::<u32>();
        let source = r.reserve(A, ReadDirection::Source, 32).unwrap();
        r.attach(source, 1).unwrap();
        let before = r.usage();
        assert_eq!(
            r.reserve(A, ReadDirection::Source, 1),
            Err(OwnerError::Capacity)
        );
        assert_eq!(r.usage(), before);
        let rejected = r.reserve(B, ReadDirection::Source, 16).unwrap();
        assert_eq!(r.peer_usage(B).source_bytes, 16);
        r.release_unused_reservation(rejected).unwrap();
        assert_eq!(r.usage(), before);
        assert_eq!(r.peer_usage(B), ReadUsage::default());
        r.retire(source).unwrap();
        reap(&mut r, source);
    }

    #[test]
    fn idle_registration_survives_peer_drain_but_not_verified_shutdown() {
        let mut r = registry::<u32>();
        let source = r.reserve_source(16).unwrap();
        r.attach(source, 1).unwrap();
        let a = r.acquire_source_lease(source, A, 8).unwrap();
        unlease(&mut r, a);
        r.drain_peer(A).unwrap();
        assert_eq!(r.state(source), Ok(OwnerState::Active));
        assert_eq!(r.usage().source_bytes, 16);
        r.begin_shutdown();
        assert_eq!(
            r.acquire_source_lease(source, B, 8),
            Err(OwnerError::Shutdown)
        );
        assert_eq!(r.reserve_source(1), Err(OwnerError::Shutdown));
        assert_eq!(r.state(source), Ok(OwnerState::Retiring));
        reap(&mut r, source);
        assert!(r.drained());
    }

    #[test]
    fn source_lease_sequence_never_wraps_or_mutates_usage_on_exhaustion() {
        let mut r = registry::<u32>();
        let source = r.reserve_source(16).unwrap();
        r.attach(source, 1).unwrap();
        r.entries.get_mut(&source).unwrap().next_source_lease = u64::MAX;
        let before = r.usage();
        assert_eq!(
            r.acquire_source_lease(source, A, 8),
            Err(OwnerError::IdExhausted)
        );
        assert_eq!(r.peer_usage(A), ReadUsage::default());
        assert_eq!(r.usage(), before);
        r.retire(source).unwrap();
        reap(&mut r, source);
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
