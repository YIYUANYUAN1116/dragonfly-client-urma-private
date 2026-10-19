//! Single-owner registered-source cache metadata. Native resources and all
//! physical/peer admission remain in the process ReadOwnerRegistry.
//!
//! Selection and reservation are one owner operation. Native work happens only
//! after start_registration, outside this operation; its eventual result must
//! be returned even if every request/watcher has gone away.

use super::{
    read_protocol::ReadTransferIdentity,
    read_registry::{
        OwnerError, OwnerState, QuarantineReason, ReadOwnerId, ReadOwnerRegistry, ReadPeer,
        ReadSourceLeaseId,
    },
};
use crate::{
    content::{ReadFileIdentity, ReadRegionLayout, ReadRegionSelection, ReadSourceFile},
    rendezvous::PieceKind,
};
use std::{collections::BTreeMap, ops::Range, sync::Arc, time::Instant};
use tokio::sync::watch;

#[derive(Debug)]
pub(crate) enum CacheError {
    Registry(OwnerError),
    Storage(dragonfly_client_core::Error),
    Missing,
    InvalidState,
    IdentityMismatch,
    Shutdown,
}
impl From<OwnerError> for CacheError {
    fn from(error: OwnerError) -> Self {
        Self::Registry(error)
    }
}
impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(error) => write!(f, "source cache admission: {error}"),
            Self::Storage(error) => write!(f, "source cache backing: {error}"),
            Self::Missing => f.write_str("unknown source cache entry or lease"),
            Self::InvalidState => f.write_str("invalid source cache lifecycle transition"),
            Self::IdentityMismatch => f.write_str("source cache identity or geometry mismatch"),
            Self::Shutdown => f.write_str("source cache admission stopped"),
        }
    }
}
impl std::error::Error for CacheError {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct FileKey {
    kind: u8,
    task: String,
    file: ReadFileIdentity,
}

pub(crate) struct CacheRequest<'a> {
    pub(crate) kind: PieceKind,
    pub(crate) task: &'a str,
    pub(crate) file: Arc<ReadSourceFile>,
    pub(crate) piece_length: u64,
    pub(crate) max_region_bytes: u64,
    pub(crate) piece_offset: u64,
    /// Completed ranges belong to this file; an empty list permits lookup only.
    pub(crate) completed: &'a [Range<u64>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheState {
    Reserved,
    Registering,
    Ready,
    Retiring,
    Retained,
    Released,
}

/// A watch receiver is only a notification. Dropping it cannot cancel native
/// work, release budget, or retire an entry that other requests may need.
pub(crate) struct CacheClaim {
    pub(crate) source: ReadOwnerId,
    pub(crate) range: Range<u64>,
    pub(crate) file: Arc<ReadSourceFile>,
    /// Exactly the claim that created this entry gets registration authority.
    pub(crate) register: bool,
    pub(crate) updates: watch::Receiver<CacheState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheLease {
    source: ReadOwnerId,
    lease: ReadSourceLeaseId,
    peer: ReadPeer,
    transfer: ReadTransferIdentity,
}
impl CacheLease {
    pub(crate) fn peer(self) -> ReadPeer {
        self.peer
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseState {
    Unpublished,
    Exposed(u64),
    Retained(u64),
}

struct LeaseEntry {
    identity: CacheLease,
    state: LeaseState,
}

struct Region {
    key: FileKey,
    geometry: (u64, u64, u64),
    range: Range<u64>,
    file: Arc<ReadSourceFile>,
    state: CacheState,
    registration_pending: bool,
    /// Only a known successful registration may use automatic cleanup. A
    /// failed/lost registration needs separate grant rollback evidence.
    registration_succeeded: bool,
    changed: watch::Sender<CacheState>,
    leases: BTreeMap<ReadSourceLeaseId, LeaseEntry>,
    /// Updated when a lease is acquired/released, not when a waiter polls.
    last_used: Instant,
}
impl Region {
    fn transition(&mut self, state: CacheState) {
        self.state = state;
        self.changed.send_replace(state);
    }
}

pub(crate) struct ReadSourceCache {
    accepting: bool,
    registry: Option<u64>,
    /// Includes registering, retiring and uncertain ranges until their physical
    /// reservation is safely released. No second overlapping registration.
    files: BTreeMap<FileKey, BTreeMap<u64, ReadOwnerId>>,
    regions: BTreeMap<ReadOwnerId, Region>,
    transfers: BTreeMap<(ReadPeer, u64, u32, u64), CacheLease>,
}

impl ReadSourceCache {
    pub(crate) fn new() -> Self {
        Self {
            accepting: true,
            registry: None,
            files: BTreeMap::new(),
            regions: BTreeMap::new(),
            transfers: BTreeMap::new(),
        }
    }

    pub(crate) fn contains(&self, id: ReadOwnerId) -> bool {
        self.regions.contains_key(&id)
    }

    pub(crate) fn range(&self, id: ReadOwnerId) -> Result<Range<u64>, CacheError> {
        Ok(self
            .regions
            .get(&id)
            .ok_or(CacheError::Missing)?
            .range
            .clone())
    }

    /// No native call or await occurs between selecting a range, charging it,
    /// and inserting its claim. The caller serializes access on the owner.
    pub(crate) fn claim<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        request: CacheRequest<'_>,
        now: Instant,
    ) -> Result<CacheClaim, CacheError> {
        if !self.accepting {
            return Err(CacheError::Shutdown);
        }
        if self
            .registry
            .is_some_and(|bound| bound != registry.identity())
        {
            return Err(CacheError::IdentityMismatch);
        }
        if request.task.is_empty() {
            return Err(CacheError::IdentityMismatch);
        }
        // Identity and geometry were captured when Storage opened the file.
        // Keep filesystem calls out of the native owner operation.
        let length = request.file.opened_length();
        let layout = ReadRegionLayout::new(length, request.piece_length, request.max_region_bytes)
            .map_err(CacheError::Storage)?;
        let key = FileKey {
            kind: request.kind.into(),
            task: request.task.into(),
            file: request.file.identity(),
        };
        let geometry = (length, request.piece_length, request.max_region_bytes);
        if let Some(previous) = self
            .files
            .get(&key)
            .and_then(|ranges| ranges.values().next())
        {
            if self.regions[previous].geometry != geometry {
                return Err(CacheError::IdentityMismatch);
            }
        }
        let occupied: Vec<_> = self
            .files
            .get(&key)
            .into_iter()
            .flat_map(|ranges| ranges.values())
            .map(|id| self.regions[id].range.clone())
            .collect();
        // An empty completion list is lookup-only. Only an existing claim can
        // supply a Region; the caller must establish full-file completion
        // before sending a registration request on a miss.
        let selection = if request.completed.is_empty() {
            layout
                .window(request.piece_offset)
                .map_err(CacheError::Storage)?;
            let end =
                request.piece_offset + request.piece_length.min(length - request.piece_offset);
            ReadRegionSelection::Covered(
                occupied
                    .iter()
                    .find(|range| range.start <= request.piece_offset && range.end >= end)
                    .cloned()
                    .ok_or(CacheError::Missing)?,
            )
        } else {
            layout
                .select(request.piece_offset, request.completed, &occupied)
                .map_err(CacheError::Storage)?
        };
        match selection {
            ReadRegionSelection::Covered(range) => {
                let source = self.files[&key][&range.start];
                let region = &self.regions[&source];
                Ok(CacheClaim {
                    source,
                    range,
                    file: region.file.clone(),
                    register: false,
                    updates: region.changed.subscribe(),
                })
            }
            ReadRegionSelection::Register(range) => {
                // Existing physical admission is the sole budget authority.
                // No peer is charged until a ready transfer lease is acquired.
                let source = registry.reserve_source(range.end - range.start)?;
                self.registry = Some(registry.identity());
                let (changed, updates) = watch::channel(CacheState::Reserved);
                self.files
                    .entry(key.clone())
                    .or_default()
                    .insert(range.start, source);
                self.regions.insert(
                    source,
                    Region {
                        key,
                        geometry,
                        range: range.clone(),
                        file: request.file.clone(),
                        state: CacheState::Reserved,
                        registration_pending: false,
                        registration_succeeded: false,
                        changed,
                        leases: BTreeMap::new(),
                        last_used: now,
                    },
                );
                Ok(CacheClaim {
                    source,
                    range,
                    file: request.file,
                    register: true,
                    updates,
                })
            }
        }
    }

    /// Call before handing backing to a worker. A duplicate dispatcher cannot
    /// start registration twice, even when the first request has disappeared.
    pub(crate) fn start_registration(&mut self, id: ReadOwnerId) -> Result<(), CacheError> {
        let region = self.regions.get_mut(&id).ok_or(CacheError::Missing)?;
        if region.state != CacheState::Reserved {
            return Err(CacheError::InvalidState);
        }
        region.registration_pending = true;
        region.transition(CacheState::Registering);
        Ok(())
    }

    /// Attaches a known-ready native ownership bundle. Late success after
    /// retirement/shutdown is retained for cleanup and never becomes Ready.
    /// On rejection, ownership is returned to the caller for safe retention.
    pub(crate) fn registered<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        id: ReadOwnerId,
        owner: T,
        uncertain: bool,
    ) -> Result<(), (CacheError, T)> {
        if let Err(error) = self.check_registry(registry) {
            return Err((error, owner));
        }
        let Some(region) = self.regions.get_mut(&id) else {
            return Err((CacheError::Missing, owner));
        };
        if !region.registration_pending {
            return Err((CacheError::InvalidState, owner));
        }
        if let Err((error, owner)) = registry.attach(id, owner) {
            return Err((error.into(), owner));
        }
        region.registration_pending = false;
        region.registration_succeeded = !uncertain;
        if uncertain {
            // The reservation was validated by attach; the entry still exists.
            registry
                .quarantine(id, QuarantineReason::RegistrationUncertain)
                .expect("attached cache source");
            region.transition(CacheState::Retained);
        } else if matches!(registry.state(id), Ok(OwnerState::Quarantined(_))) {
            region.transition(CacheState::Retained);
        } else if region.state == CacheState::Registering
            && registry.state(id) == Ok(OwnerState::Active)
        {
            region.transition(CacheState::Ready);
        } else {
            region.transition(CacheState::Retiring);
        }
        Ok(())
    }

    /// Resolves a registration that definitely never ran or was rejected with
    /// all grants rolled back. An uncertain/lost result must remain retained.
    ///
    /// # Safety
    /// A started native operation must have returned a definitive rejection for
    /// this exact source, with no backing or remote permission left in use.
    pub(crate) unsafe fn registration_rejected<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        id: ReadOwnerId,
    ) -> Result<(), CacheError> {
        self.check_registry(registry)?;
        let region = self.regions.get(&id).ok_or(CacheError::Missing)?;
        if !region.registration_pending {
            return Err(CacheError::InvalidState);
        }
        registry.release_unused_reservation(id)?;
        self.remove(id);
        Ok(())
    }

    /// A lost worker/result is not a rejection. Keep the physical reservation,
    /// file and range occupied, awaiting recovery or an independent proof.
    pub(crate) fn registration_lost<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        id: ReadOwnerId,
    ) -> Result<(), CacheError> {
        self.check_registry(registry)?;
        let region = self.regions.get_mut(&id).ok_or(CacheError::Missing)?;
        if !region.registration_pending {
            return Err(CacheError::InvalidState);
        }
        registry.quarantine(id, QuarantineReason::RegistrationUncertain)?;
        region.transition(CacheState::Retained);
        Ok(())
    }

    pub(crate) fn acquire<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        id: ReadOwnerId,
        peer: ReadPeer,
        transfer: ReadTransferIdentity,
        piece: Range<u64>,
        now: Instant,
    ) -> Result<CacheLease, CacheError> {
        self.check_registry(registry)?;
        if !self.accepting {
            return Err(CacheError::Shutdown);
        }
        let region = self.regions.get_mut(&id).ok_or(CacheError::Missing)?;
        if region.state != CacheState::Ready {
            return Err(CacheError::InvalidState);
        }
        if piece.start >= piece.end
            || piece.start < region.range.start
            || piece.end > region.range.end
            || transfer.session_generation == 0
            || transfer.transfer_id == 0
            || transfer.metadata_generation == 0
            || self.transfers.contains_key(&transfer_key(peer, transfer))
        {
            return Err(CacheError::IdentityMismatch);
        }
        let lease = registry.acquire_source_lease(id, peer, piece.end - piece.start)?;
        let identity = CacheLease {
            source: id,
            lease,
            peer,
            transfer,
        };
        region.leases.insert(
            lease,
            LeaseEntry {
                identity,
                state: LeaseState::Unpublished,
            },
        );
        region.last_used = now;
        self.transfers
            .insert(transfer_key(peer, transfer), identity);
        Ok(identity)
    }

    /// Arm before a descriptor might reach the wire, never after send returns.
    pub(crate) fn expose(
        &mut self,
        lease: CacheLease,
        segment_generation: u64,
    ) -> Result<(), CacheError> {
        if !self.accepting {
            return Err(CacheError::Shutdown);
        }
        let entry = self.lease_mut(lease)?;
        if segment_generation == 0 || entry.state != LeaseState::Unpublished {
            return Err(CacheError::InvalidState);
        }
        entry.state = LeaseState::Exposed(segment_generation);
        Ok(())
    }

    /// Cancellation/reply loss before exposure releases only that peer lease.
    /// After exposure it retains the lease and blocks native retirement. The
    /// registration remains cache-owned, regardless of the acquiring request.
    pub(crate) fn abandon<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        lease: CacheLease,
        now: Instant,
    ) -> Result<(), CacheError> {
        self.check_registry(registry)?;
        let entry = self.lease_mut(lease)?;
        match entry.state {
            LeaseState::Unpublished => {
                // SAFETY: expose is the mandatory pre-publication transition;
                // this lease never disclosed a descriptor or posted remote work.
                unsafe { registry.release_source_lease(lease.lease)? };
                let region = self
                    .regions
                    .get_mut(&lease.source)
                    .expect("validated lease");
                region.leases.remove(&lease.lease);
                region.last_used = now;
                self.transfers
                    .remove(&transfer_key(lease.peer, lease.transfer));
            }
            LeaseState::Exposed(generation) | LeaseState::Retained(generation) => {
                entry.state = LeaseState::Retained(generation);
                registry.retire(lease.source)?;
                let region = self
                    .regions
                    .get_mut(&lease.source)
                    .expect("validated lease");
                if region.state != CacheState::Retained {
                    region.transition(CacheState::Retiring);
                }
            }
        }
        Ok(())
    }

    /// Releases only the supplied transfer's accounting, never the Segment.
    ///
    /// # Safety
    /// The exact transfer's READ operations have drained and cannot resume.
    /// The caller must validate the full protocol identity and provider/peer
    /// contract; timeout/EOF alone is insufficient. The cached capability may
    /// remain valid for other authorized transfers until physical revocation.
    pub(crate) unsafe fn release_drained<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        lease: CacheLease,
        transfer: ReadTransferIdentity,
        segment_generation: u64,
        now: Instant,
    ) -> Result<(), CacheError> {
        self.check_registry(registry)?;
        if transfer != lease.transfer {
            return Err(CacheError::IdentityMismatch);
        }
        let entry = self.lease_mut(lease)?;
        if !matches!(entry.state, LeaseState::Exposed(g) | LeaseState::Retained(g) if g == segment_generation)
        {
            return Err(CacheError::IdentityMismatch);
        }
        // SAFETY: supplied for this exact lease by the caller, not inferred from
        // a watch notification or software reference count.
        unsafe { registry.release_source_lease(lease.lease)? };
        let region = self
            .regions
            .get_mut(&lease.source)
            .expect("validated lease");
        region.leases.remove(&lease.lease);
        region.last_used = now;
        self.transfers
            .remove(&transfer_key(lease.peer, lease.transfer));
        Ok(())
    }

    /// Retiring stays indexed even with no active lease, until verified native
    /// cleanup. A never-dispatched reservation can be removed immediately.
    pub(crate) fn retire<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
        id: ReadOwnerId,
    ) -> Result<(), CacheError> {
        self.check_registry(registry)?;
        let region = self.regions.get_mut(&id).ok_or(CacheError::Missing)?;
        if region.state == CacheState::Reserved {
            registry.release_unused_reservation(id)?;
            self.remove(id);
        } else {
            registry.retire(id)?;
            if region.state != CacheState::Retained {
                region.transition(CacheState::Retiring);
            }
        }
        Ok(())
    }

    /// Called before dispatching native cleanup, including worker cleanup.
    pub(crate) fn check_cleanup<T>(
        &self,
        registry: &ReadOwnerRegistry<T>,
        id: ReadOwnerId,
    ) -> Result<(), CacheError> {
        self.check_registry(registry)?;
        let region = self.regions.get(&id).ok_or(CacheError::Missing)?;
        if region.registration_pending
            || !matches!(region.state, CacheState::Retiring | CacheState::Retained)
        {
            return Err(CacheError::InvalidState);
        }
        registry.check_source_cleanup(id)?;
        Ok(())
    }

    /// The native registry is the release authority. An error/Pending result
    /// keeps the range, FD and watch state; successful removal wakes all waiters.
    pub(crate) fn observe_cleanup<T>(
        &mut self,
        registry: &ReadOwnerRegistry<T>,
        id: ReadOwnerId,
    ) -> Result<bool, CacheError> {
        self.check_registry(registry)?;
        let region = self.regions.get_mut(&id).ok_or(CacheError::Missing)?;
        if region.registration_pending
            || !matches!(region.state, CacheState::Retiring | CacheState::Retained)
        {
            return Err(CacheError::InvalidState);
        }
        match registry.state(id) {
            Err(OwnerError::UnknownOwner) if region.leases.is_empty() => {
                self.remove(id);
                Ok(true)
            }
            Ok(OwnerState::Quarantined(_)) => {
                region.transition(CacheState::Retained);
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Selects idle eviction candidates without assuming a timeout proves DMA
    /// completion. Native cleanup and budget return are separate operations.
    pub(crate) fn idle_candidates(&self, before: Instant) -> Vec<ReadOwnerId> {
        let mut idle: Vec<_> = self
            .regions
            .iter()
            .filter(|(_, region)| {
                region.state == CacheState::Ready
                    && region.leases.is_empty()
                    && region.last_used <= before
            })
            .map(|(id, region)| (region.last_used, *id))
            .collect();
        idle.sort_unstable();
        idle.into_iter().map(|(_, id)| id).collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Software drain is a precondition, not revocation proof. Runtime must
    /// additionally enforce the deployment's provider revocation contract.
    pub(crate) fn cleanup_candidates<T>(
        &self,
        registry: &ReadOwnerRegistry<T>,
    ) -> Vec<ReadOwnerId> {
        self.regions
            .iter()
            .filter(|(id, region)| {
                region.registration_succeeded
                    && region.leases.is_empty()
                    && self.check_cleanup(registry, **id).is_ok()
            })
            .map(|(&id, _)| id)
            .collect()
    }

    pub(crate) fn begin_shutdown<T>(
        &mut self,
        registry: &mut ReadOwnerRegistry<T>,
    ) -> Result<(), CacheError> {
        if self.registry.is_some() {
            self.check_registry(registry)?;
        }
        self.accepting = false;
        for id in self.regions.keys().copied().collect::<Vec<_>>() {
            self.retire(registry, id)?;
        }
        Ok(())
    }

    fn check_registry<T>(&self, registry: &ReadOwnerRegistry<T>) -> Result<(), CacheError> {
        if self.registry != Some(registry.identity()) {
            return Err(CacheError::IdentityMismatch);
        }
        Ok(())
    }

    fn lease_mut(&mut self, lease: CacheLease) -> Result<&mut LeaseEntry, CacheError> {
        let region = self
            .regions
            .get_mut(&lease.source)
            .ok_or(CacheError::Missing)?;
        let entry = region
            .leases
            .get_mut(&lease.lease)
            .ok_or(CacheError::Missing)?;
        if entry.identity != lease {
            return Err(CacheError::IdentityMismatch);
        }
        Ok(entry)
    }

    fn remove(&mut self, id: ReadOwnerId) {
        let mut region = self.regions.remove(&id).expect("validated cache source");
        assert!(region.leases.is_empty(), "cache release with live leases");
        region.transition(CacheState::Released);
        let ranges = self.files.get_mut(&region.key).expect("cache file index");
        assert_eq!(ranges.remove(&region.range.start), Some(id));
        if ranges.is_empty() {
            self.files.remove(&region.key);
        }
    }
}

fn transfer_key(peer: ReadPeer, identity: ReadTransferIdentity) -> (ReadPeer, u64, u32, u64) {
    (
        peer,
        identity.session_generation,
        identity.transfer_id,
        identity.metadata_generation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::read_registry::{
        ReadBudget, ReadCapacity, ReapDecision, ReapError, VerifiedRetirement,
    };
    use std::{fs, time::Duration};
    use tempfile::{tempdir, TempDir};

    const A: ReadPeer = ReadPeer {
        id: 1,
        generation: 1,
    };
    const B: ReadPeer = ReadPeer {
        id: 2,
        generation: 1,
    };

    fn transfer(id: u32) -> ReadTransferIdentity {
        ReadTransferIdentity {
            session_generation: 7,
            transfer_id: id,
            metadata_generation: 9,
        }
    }

    fn registry() -> ReadOwnerRegistry<u32> {
        let capacity = |bytes, entries| ReadCapacity { bytes, entries };
        let mut registry = ReadOwnerRegistry::new(ReadBudget {
            total: capacity(256, 16),
            source: capacity(128, 8),
            destination: capacity(128, 8),
            per_peer_source: capacity(32, 4),
            per_peer_destination: capacity(32, 4),
            quarantine: capacity(64, 8),
        })
        .unwrap();
        registry.activate_peer(A).unwrap();
        registry.activate_peer(B).unwrap();
        registry
    }

    struct Fixture {
        dir: TempDir,
        file: Arc<ReadSourceFile>,
        cache: ReadSourceCache,
        registry: ReadOwnerRegistry<u32>,
        now: Instant,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempdir().unwrap();
            let path = dir.path().join("task");
            fs::write(&path, vec![1; 64]).unwrap();
            Self {
                file: ReadSourceFile::open(&path).unwrap(),
                dir,
                cache: ReadSourceCache::new(),
                registry: registry(),
                now: Instant::now(),
            }
        }
        fn claim(&mut self, offset: u64, completed: &[Range<u64>]) -> CacheClaim {
            self.cache
                .claim(
                    &mut self.registry,
                    CacheRequest {
                        kind: PieceKind::Piece,
                        task: "task",
                        file: self.file.clone(),
                        piece_length: 8,
                        max_region_bytes: 64,
                        piece_offset: offset,
                        completed,
                    },
                    self.now,
                )
                .unwrap()
        }
        fn ready(&mut self, id: ReadOwnerId) {
            self.cache.start_registration(id).unwrap();
            self.cache
                .registered(&mut self.registry, id, 7, false)
                .unwrap();
        }
        fn lease(
            &mut self,
            id: ReadOwnerId,
            peer: ReadPeer,
            tid: u32,
            piece: Range<u64>,
        ) -> CacheLease {
            self.cache
                .acquire(&mut self.registry, id, peer, transfer(tid), piece, self.now)
                .unwrap()
        }
        fn drain(&mut self, lease: CacheLease, generation: u64) {
            // SAFETY: integer test owners have no native grant, work or remote reader.
            unsafe {
                self.cache.release_drained(
                    &mut self.registry,
                    lease,
                    lease.transfer,
                    generation,
                    self.now,
                )
            }
            .unwrap();
        }
        fn clean(&mut self, id: ReadOwnerId) {
            self.cache.check_cleanup(&self.registry, id).unwrap();
            assert_eq!(
                self.registry.reap_with(id, |_| Ok::<_, ()>(proof(id))),
                Ok(true)
            );
            assert!(self.cache.observe_cleanup(&self.registry, id).unwrap());
        }
    }
    fn proof(id: ReadOwnerId) -> ReapDecision {
        // SAFETY: test owners are integers; no native resource or access exists.
        ReapDecision::Retired(unsafe { VerifiedRetirement::new(id) })
    }

    #[test]
    fn concurrent_miss_has_one_registration_authority_and_retained_notification() {
        let mut f = Fixture::new();
        let first = f.claim(0, &[0..40]);
        assert!(first.register);
        assert_eq!(first.range, 0..40);
        f.cache.start_registration(first.source).unwrap();
        assert!(matches!(
            f.cache.start_registration(first.source),
            Err(CacheError::InvalidState)
        ));
        let second = f.claim(16, &[0..40]);
        assert!(!second.register);
        assert_eq!(second.source, first.source);
        assert_eq!(*second.updates.borrow(), CacheState::Registering);
        assert_eq!(f.registry.usage().source_bytes, 40);
        assert_eq!(f.registry.peer_usage(A).source_bytes, 0);
        // Every original caller may disappear. The owner still owns the claim.
        let id = first.source;
        drop(first);
        drop(second);
        f.cache.registered(&mut f.registry, id, 7, false).unwrap();
        let late = f.claim(8, &[0..48]);
        assert_eq!(*late.updates.borrow(), CacheState::Ready);
        let suffix = f.claim(40, &[0..48]);
        assert!(suffix.register);
        assert_eq!(suffix.range, 40..48);
        assert_eq!(f.registry.usage().source_bytes, 48);
        assert_eq!(f.registry.usage().source_entries, 2);
        assert_eq!(late.file.identity(), f.file.identity());
    }

    #[test]
    fn shared_leases_charge_peers_and_last_peer_drain_does_not_own_the_cache() {
        let mut f = Fixture::new();
        let id = f.claim(0, &[0..64]).source;
        f.ready(id);
        let a = f.lease(id, A, 1, 0..8);
        let b = f.lease(id, B, 2, 8..16);
        f.cache.expose(a, 11).unwrap();
        f.cache.expose(b, 12).unwrap();
        assert_eq!(f.registry.usage().source_bytes, 64);
        assert_eq!(f.registry.peer_usage(A).source_bytes, 8);
        assert_eq!(f.registry.peer_usage(B).source_bytes, 8);
        f.registry.drain_peer(A).unwrap();
        f.registry.drain_peer(B).unwrap();
        assert_eq!(f.registry.state(id), Ok(OwnerState::Active));
        f.drain(a, 11);
        f.drain(b, 12);
        assert_eq!(f.registry.usage().source_bytes, 64);
        f.registry
            .activate_peer(ReadPeer { generation: 2, ..A })
            .unwrap();
        let next = f.lease(id, ReadPeer { generation: 2, ..A }, 1, 16..24);
        f.cache.abandon(&mut f.registry, next, f.now).unwrap();
        f.cache.retire(&mut f.registry, id).unwrap();
        f.clean(id);
        assert!(f.registry.drained());
    }

    #[test]
    fn unpublished_reply_loss_only_releases_its_lease_exposed_loss_blocks_cleanup() {
        let mut f = Fixture::new();
        let id = f.claim(0, &[0..64]).source;
        f.ready(id);
        let unpublished = f.lease(id, A, 1, 0..8);
        let live = f.lease(id, B, 2, 8..16);
        f.cache.expose(live, 22).unwrap();
        f.cache
            .abandon(&mut f.registry, unpublished, f.now)
            .unwrap();
        assert_eq!(f.registry.peer_usage(A).source_bytes, 0);
        assert_eq!(f.cache.regions[&id].state, CacheState::Ready);
        let lost = f.lease(id, A, 3, 16..24);
        f.cache.expose(lost, 23).unwrap();
        f.cache.abandon(&mut f.registry, lost, f.now).unwrap();
        assert_eq!(f.cache.regions[&id].state, CacheState::Retiring);
        assert!(matches!(
            f.cache.check_cleanup(&f.registry, id),
            Err(CacheError::Registry(OwnerError::SourceBusy))
        ));
        assert!(matches!(
            f.cache
                .acquire(&mut f.registry, id, B, transfer(4), 0..8, f.now),
            Err(CacheError::InvalidState)
        ));
        f.drain(live, 22);
        assert_eq!(f.registry.peer_usage(B).source_bytes, 0);
        assert_eq!(f.registry.peer_usage(A).source_bytes, 8);
        assert!(f.cache.check_cleanup(&f.registry, id).is_err());
        f.drain(lost, 23);
        f.clean(id);
    }

    #[test]
    fn full_transfer_generation_and_duplicate_identity_are_checked() {
        let mut f = Fixture::new();
        let first = f.claim(0, &[0..32]).source;
        let second = f.claim(32, &[32..64]).source;
        f.ready(first);
        f.ready(second);
        let lease = f.lease(first, A, 1, 0..8);
        assert!(matches!(
            f.cache
                .acquire(&mut f.registry, second, A, transfer(1), 32..40, f.now),
            Err(CacheError::IdentityMismatch)
        ));
        f.cache.expose(lease, 12).unwrap();
        assert!(f.cache.expose(lease, 12).is_err());
        for identity in [
            ReadTransferIdentity {
                session_generation: 8,
                ..transfer(1)
            },
            transfer(2),
            ReadTransferIdentity {
                metadata_generation: 10,
                ..transfer(1)
            },
        ] {
            // SAFETY: no native access; exercise identity rejection before release.
            assert!(matches!(
                unsafe {
                    f.cache
                        .release_drained(&mut f.registry, lease, identity, 12, f.now)
                },
                Err(CacheError::IdentityMismatch)
            ));
        }
        // SAFETY: no native access; wrong generation must not release accounting.
        assert!(unsafe {
            f.cache
                .release_drained(&mut f.registry, lease, transfer(1), 13, f.now)
        }
        .is_err());
        assert_eq!(f.registry.peer_usage(A).source_bytes, 8);
        f.drain(lease, 12);
        // SAFETY: repeated release cannot affect a subsequent transfer.
        assert!(unsafe {
            f.cache
                .release_drained(&mut f.registry, lease, transfer(1), 12, f.now)
        }
        .is_err());
        let later = f.lease(second, A, 2, 32..40);
        f.cache.abandon(&mut f.registry, later, f.now).unwrap();
    }

    #[test]
    fn retiring_registration_accepts_late_result_without_reopening_the_range() {
        let mut f = Fixture::new();
        let old = f.claim(0, &[0..64]);
        f.cache.start_registration(old.source).unwrap();
        f.cache.retire(&mut f.registry, old.source).unwrap();
        assert!(f.cache.check_cleanup(&f.registry, old.source).is_err());
        let waiter = f.claim(0, &[0..64]);
        assert!(!waiter.register);
        assert_eq!(waiter.source, old.source);
        f.cache
            .registered(&mut f.registry, old.source, 7, false)
            .unwrap();
        assert_eq!(*waiter.updates.borrow(), CacheState::Retiring);
        f.clean(old.source);
        assert_eq!(*old.updates.borrow(), CacheState::Released);
        let next = f.claim(0, &[0..64]);
        assert!(next.register);
        assert_ne!(old.source, next.source);
    }

    #[test]
    fn never_dispatched_and_known_rejected_registrations_release_once() {
        let mut f = Fixture::new();
        let first = f.claim(0, &[0..64]);
        f.cache.retire(&mut f.registry, first.source).unwrap();
        assert_eq!(*first.updates.borrow(), CacheState::Released);
        assert!(f.registry.drained());
        assert!(f.cache.start_registration(first.source).is_err());
        let next = f.claim(0, &[0..64]);
        f.cache.start_registration(next.source).unwrap();
        // SAFETY: fake native operation created no grant or resource.
        unsafe { f.cache.registration_rejected(&mut f.registry, next.source) }.unwrap();
        assert_eq!(*next.updates.borrow(), CacheState::Released);
        assert!(f.registry.drained());
        assert!(f.cache.files.is_empty());
    }

    #[test]
    fn lost_worker_keeps_range_and_budget_until_late_owner_and_verified_cleanup() {
        let mut f = Fixture::new();
        let id = f.claim(0, &[0..64]).source;
        f.cache.start_registration(id).unwrap();
        f.cache.registration_lost(&mut f.registry, id).unwrap();
        assert_eq!(f.registry.usage().quarantined_bytes, 64);
        assert_eq!(f.cache.regions[&id].state, CacheState::Retained);
        assert!(f.cache.check_cleanup(&f.registry, id).is_err());
        let claim = f.claim(0, &[0..64]);
        assert!(!claim.register);
        // SAFETY: no grants exist in this fake setup, but a quarantined result
        // must still reject this shortcut and require explicit verified reap.
        assert!(unsafe { f.cache.registration_rejected(&mut f.registry, id) }.is_err());
        f.cache.registered(&mut f.registry, id, 7, false).unwrap();
        assert_eq!(*claim.updates.borrow(), CacheState::Retained);
        f.clean(id);
    }

    #[test]
    fn cleanup_failure_pending_and_wrong_proof_keep_cache_occupancy() {
        let mut f = Fixture::new();
        let id = f.claim(0, &[0..64]).source;
        f.cache.start_registration(id).unwrap();
        f.cache.registered(&mut f.registry, id, 7, true).unwrap();
        f.cache.check_cleanup(&f.registry, id).unwrap();
        assert_eq!(
            f.registry.reap_with(id, |_| Err("native error")),
            Err(ReapError::Cleanup("native error"))
        );
        assert!(!f.cache.observe_cleanup(&f.registry, id).unwrap());
        assert_eq!(f.registry.usage().source_bytes, 64);
        assert_eq!(
            f.registry
                .reap_with(id, |_| Ok::<_, ()>(ReapDecision::Pending)),
            Ok(false)
        );
        assert!(!f.cache.observe_cleanup(&f.registry, id).unwrap());
        assert_eq!(f.claim(0, &[0..64]).source, id);
        let mut other = registry();
        let wrong = other.reserve_source(8).unwrap();
        assert_eq!(
            f.registry.reap_with(id, |_| Ok::<_, ()>(proof(wrong))),
            Err(ReapError::Registry(OwnerError::WrongProof))
        );
        assert!(!f.cache.observe_cleanup(&f.registry, id).unwrap());
        f.clean(id);
        other.release_unused_reservation(wrong).unwrap();
    }

    #[test]
    fn lookup_only_miss_never_registers_and_hit_reuses_completed_file_claim() {
        let mut f = Fixture::new();
        assert!(matches!(
            f.cache.claim(
                &mut f.registry,
                CacheRequest {
                    kind: PieceKind::Piece,
                    task: "task",
                    file: f.file.clone(),
                    piece_length: 8,
                    max_region_bytes: 32,
                    piece_offset: 8,
                    completed: &[],
                },
                f.now
            ),
            Err(CacheError::Missing)
        ));
        assert_eq!(f.registry.usage().source_entries, 0);
        let register = f
            .cache
            .claim(
                &mut f.registry,
                CacheRequest {
                    kind: PieceKind::Piece,
                    task: "task",
                    file: f.file.clone(),
                    piece_length: 8,
                    max_region_bytes: 32,
                    piece_offset: 8,
                    completed: &[0..64],
                },
                f.now,
            )
            .unwrap();
        assert!(register.register);
        assert_eq!(register.range, 0..32);
        let hit = f
            .cache
            .claim(
                &mut f.registry,
                CacheRequest {
                    kind: PieceKind::Piece,
                    task: "task",
                    file: f.file.clone(),
                    piece_length: 8,
                    max_region_bytes: 32,
                    piece_offset: 24,
                    completed: &[],
                },
                f.now,
            )
            .unwrap();
        assert!(!hit.register);
        assert_eq!(hit.source, register.source);
        assert_eq!(hit.range, 0..32);
        assert!(matches!(
            f.cache.claim(
                &mut f.registry,
                CacheRequest {
                    kind: PieceKind::Piece,
                    task: "task",
                    file: f.file.clone(),
                    piece_length: 8,
                    max_region_bytes: 32,
                    piece_offset: 32,
                    completed: &[],
                },
                f.now
            ),
            Err(CacheError::Missing)
        ));
        assert_eq!(f.registry.usage().source_entries, 1);
    }

    #[test]
    fn wrong_registry_geometry_and_incomplete_hit_do_not_mutate_cache() {
        let mut f = Fixture::new();
        let id = f.claim(0, &[0..64]).source;
        let other = registry();
        assert!(matches!(
            f.cache.observe_cleanup(&other, id),
            Err(CacheError::IdentityMismatch)
        ));
        for (piece_length, max_region_bytes, completed) in [
            (16, 64, vec![0..64]),
            (8, 32, vec![0..64]),
            (8, 64, vec![0..4]),
        ] {
            assert!(f
                .cache
                .claim(
                    &mut f.registry,
                    CacheRequest {
                        kind: PieceKind::Piece,
                        task: "task",
                        file: f.file.clone(),
                        piece_length,
                        max_region_bytes,
                        piece_offset: 0,
                        completed: &completed
                    },
                    f.now
                )
                .is_err());
        }
        assert_eq!(f.registry.usage().source_entries, 1);
        assert_eq!(f.cache.regions.len(), 1);
    }

    #[test]
    fn kind_and_recreated_file_are_distinct_and_failed_admission_leaves_no_claim() {
        let mut f = Fixture::new();
        let old = f.claim(0, &[0..64]).source;
        let persistent = f
            .cache
            .claim(
                &mut f.registry,
                CacheRequest {
                    kind: PieceKind::PersistentPiece,
                    task: "task",
                    file: f.file.clone(),
                    piece_length: 8,
                    max_region_bytes: 64,
                    piece_offset: 0,
                    completed: &[0..64],
                },
                f.now,
            )
            .unwrap();
        assert_ne!(old, persistent.source);
        assert_eq!(f.registry.usage().source_bytes, 128);
        let path = f.dir.path().join("task");
        fs::remove_file(&path).unwrap();
        fs::write(&path, vec![2; 64]).unwrap();
        let replacement = ReadSourceFile::open(&path).unwrap();
        assert_ne!(f.file.identity(), replacement.identity());
        let result = f.cache.claim(
            &mut f.registry,
            CacheRequest {
                kind: PieceKind::Piece,
                task: "task",
                file: replacement.clone(),
                piece_length: 8,
                max_region_bytes: 64,
                piece_offset: 0,
                completed: &[0..64],
            },
            f.now,
        );
        assert!(matches!(
            result,
            Err(CacheError::Registry(OwnerError::Capacity))
        ));
        assert_eq!(f.cache.regions.len(), 2);
        f.cache.retire(&mut f.registry, persistent.source).unwrap();
        let new = f
            .cache
            .claim(
                &mut f.registry,
                CacheRequest {
                    kind: PieceKind::Piece,
                    task: "task",
                    file: replacement,
                    piece_length: 8,
                    max_region_bytes: 64,
                    piece_offset: 0,
                    completed: &[0..64],
                },
                f.now,
            )
            .unwrap();
        assert_ne!(old, new.source);
        assert!(new.register);
        assert!(f.cache.regions[&old].file.is_unlinked().unwrap());
    }

    #[test]
    fn idle_candidates_are_ordered_and_exclude_live_leases() {
        let mut f = Fixture::new();
        let first = f.claim(0, &[0..32]).source;
        let second = f.claim(32, &[32..64]).source;
        f.ready(first);
        f.ready(second);
        f.now += Duration::from_secs(1);
        let lease = f.lease(first, A, 1, 0..8);
        assert_eq!(f.cache.idle_candidates(f.now), vec![second]);
        f.now += Duration::from_secs(1);
        f.cache.abandon(&mut f.registry, lease, f.now).unwrap();
        assert_eq!(f.cache.idle_candidates(f.now), vec![second, first]);
    }

    #[test]
    fn shutdown_drops_only_undispatched_reservations_and_drains_late_results() {
        let mut f = Fixture::new();
        let reserved = f.claim(0, &[0..8]);
        let registering = f.claim(8, &[8..16]);
        let ready = f.claim(16, &[16..24]);
        f.cache.start_registration(registering.source).unwrap();
        f.ready(ready.source);
        let lease = f.lease(ready.source, A, 1, 16..24);
        f.cache.expose(lease, 44).unwrap();
        f.cache.begin_shutdown(&mut f.registry).unwrap();
        f.registry.begin_shutdown();
        assert_eq!(*reserved.updates.borrow(), CacheState::Released);
        assert_eq!(*registering.updates.borrow(), CacheState::Retiring);
        assert_eq!(*ready.updates.borrow(), CacheState::Retiring);
        assert_eq!(f.registry.usage().source_bytes, 16);
        assert!(matches!(
            f.cache
                .acquire(&mut f.registry, ready.source, B, transfer(2), 16..24, f.now),
            Err(CacheError::Shutdown)
        ));
        f.cache
            .registered(&mut f.registry, registering.source, 7, false)
            .unwrap();
        assert_eq!(*registering.updates.borrow(), CacheState::Retiring);
        f.drain(lease, 44);
        f.clean(ready.source);
        f.clean(registering.source);
        assert!(f.registry.drained());
        assert!(f.cache.regions.is_empty());
        assert!(f.cache.transfers.is_empty());
    }

    #[test]
    fn automatic_cleanup_requires_known_registration_and_every_lease_drained() {
        let mut f = Fixture::new();
        let ready = f.claim(0, &[0..16]).source;
        let uncertain = f.claim(16, &[16..32]).source;
        let lost = f.claim(32, &[32..48]).source;
        f.ready(ready);
        f.cache.start_registration(uncertain).unwrap();
        f.cache
            .registered(&mut f.registry, uncertain, 7, true)
            .unwrap();
        f.cache.start_registration(lost).unwrap();
        f.cache.registration_lost(&mut f.registry, lost).unwrap();
        let a = f.lease(ready, A, 1, 0..8);
        let b = f.lease(ready, B, 2, 8..16);
        f.cache.expose(a, 10).unwrap();
        f.cache.expose(b, 20).unwrap();
        f.cache.retire(&mut f.registry, ready).unwrap();
        assert!(f.cache.cleanup_candidates(&f.registry).is_empty());
        f.drain(a, 10);
        assert!(f.cache.cleanup_candidates(&f.registry).is_empty());
        f.cache.abandon(&mut f.registry, b, f.now).unwrap();
        assert!(f.cache.cleanup_candidates(&f.registry).is_empty());
        f.drain(b, 20);
        assert_eq!(f.cache.cleanup_candidates(&f.registry), vec![ready]);
        assert_eq!(f.registry.usage().source_bytes, 48);
        assert!(f
            .registry
            .reap_with(ready, |_| Err::<ReapDecision, _>(()))
            .is_err());
        f.cache.observe_cleanup(&f.registry, ready).unwrap();
        // A cleanup failure may be retried; registration uncertainty cannot.
        assert_eq!(f.cache.cleanup_candidates(&f.registry), vec![ready]);
        f.clean(ready);
        assert_eq!(f.registry.usage().source_bytes, 32);
    }
}
