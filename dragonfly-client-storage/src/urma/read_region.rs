//! Parent registration cache. Native resources remain owned by ReadOwners;
//! this table owns only descriptors and identity-bound transfer leases.
use super::{
    ffi::read::{source::ReadBacking, ReadDescriptor, ReadToken},
    read_owner::{ReadCapacity, ReadPeer},
    read_protocol::ReadTransferIdentity,
    runtime::{ReadSourceId, ReadSourceOffer},
    Error, Result,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct RegionKey {
    pub(crate) kind: u8,
    pub(crate) task_id: String,
    // Taken from the same open file used for mmap. A retained mapping keeps the
    // old inode alive; replacing a task path cannot reuse its cached descriptor.
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) file_length: u64,
    pub(crate) offset: u64,
    pub(crate) length: u64,
}
impl RegionKey {
    fn same_backing(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.task_id == other.task_id
            && self.device == other.device
            && self.inode == other.inode
            && self.file_length == other.file_length
    }
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.task_id == other.task_id
            && self.device == other.device
            && self.inode == other.inode
            && self.offset < other.offset.saturating_add(other.length)
            && other.offset < self.offset.saturating_add(self.length)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RegionSession {
    pub(crate) peer: ReadPeer,
    pub(crate) generation: u64,
}

pub(crate) struct RegionRequest {
    pub(crate) session: RegionSession,
    pub(crate) identity: ReadTransferIdentity,
    pub(crate) key: RegionKey,
    pub(crate) remote_offset: u64,
    pub(crate) piece_length: u64,
    pub(crate) max_regions: usize,
    pub(crate) backing: Option<ReadBacking<()>>,
    pub(crate) token: Option<ReadToken>,
}

#[derive(Clone)]
pub(crate) struct RegionOffer {
    pub(crate) source_id: ReadSourceId,
    pub(crate) peer: ReadPeer,
    pub(crate) identity: ReadTransferIdentity,
    pub(crate) segment_generation: u64,
    pub(crate) descriptor: ReadDescriptor,
    pub(crate) token: ReadToken,
    pub(crate) remote_offset: u64,
    pub(crate) piece_length: u64,
    pub(crate) cache_hit: bool,
    pub(crate) cached_bytes: u64,
    pub(crate) cached_regions: usize,
    pub(crate) active_leases: usize,
    pub(crate) register_stages: super::ffi::read::source::ReadSourceStages,
}

pub(crate) struct RegionEntry {
    pub(crate) source: ReadSourceOffer,
    pub(crate) generation: u64,
    pub(crate) accepting: bool,
    pub(crate) last_used: u64,
}
struct RegionLease {
    key: RegionKey,
    peer: ReadPeer,
    bytes: u64,
}
#[derive(Default)]
pub(crate) struct RegionCache {
    pub(crate) entries: BTreeMap<RegionKey, RegionEntry>,
    leases: BTreeMap<(ReadPeer, ReadTransferIdentity), RegionLease>,
    clock: u64,
    pub(crate) uncertain_sources: Vec<(RegionKey, ReadSourceId)>,
}
impl RegionCache {
    pub(crate) fn peer_usage(&self, peer: ReadPeer) -> (u64, usize) {
        self.leases
            .values()
            .filter(|lease| lease.peer == peer)
            .fold((0u64, 0usize), |(used, count), lease| {
                (used.saturating_add(lease.bytes), count + 1)
            })
    }

    pub(crate) fn check_lease(
        &self,
        identity: ReadTransferIdentity,
        peer: ReadPeer,
        bytes: u64,
        limit: ReadCapacity,
    ) -> Result<()> {
        identity.validate()?;
        if self.leases.contains_key(&(peer, identity)) || bytes == 0 {
            return Err(Error::Protocol("duplicate or empty Region lease".into()));
        }
        let (used, count) = self
            .leases
            .values()
            .filter(|lease| lease.peer == peer)
            .fold((0u64, 0usize), |(used, count), lease| {
                (used.saturating_add(lease.bytes), count + 1)
            });
        if bytes > limit.bytes.saturating_sub(used) || count >= limit.entries {
            return Err(Error::Protocol(
                "Region per-peer lease capacity exhausted".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn idle(&self, key: &RegionKey) -> bool {
        !self.leases.values().any(|lease| &lease.key == key)
    }
    pub(crate) fn containing(
        &self,
        candidate: &RegionKey,
        offset: u64,
        bytes: u64,
    ) -> Option<RegionKey> {
        let start = candidate.offset.checked_add(offset)?;
        let end = start.checked_add(bytes)?;
        self.entries
            .iter()
            .find(|(key, entry)| {
                entry.accepting
                    && key.same_backing(candidate)
                    && key.offset <= start
                    && key
                        .offset
                        .checked_add(key.length)
                        .is_some_and(|limit| end <= limit)
            })
            .map(|(key, _)| key.clone())
    }

    pub(crate) fn begin_eviction(&mut self, key: &RegionKey) -> Result<ReadSourceId> {
        if !self.idle(key) {
            return Err(Error::Protocol("Region has active leases".into()));
        }
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| Error::Protocol("Region missing".into()))?;
        entry.accepting = false;
        Ok(entry.source.id)
    }
    pub(crate) fn finish_eviction(
        &mut self,
        key: &RegionKey,
        source_id: ReadSourceId,
    ) -> Result<()> {
        let entry = self
            .entries
            .get(key)
            .ok_or_else(|| Error::Protocol("Region missing".into()))?;
        if entry.accepting || entry.source.id != source_id || !self.idle(key) {
            return Err(Error::Protocol(
                "Region eviction identity or state mismatch".into(),
            ));
        }
        self.entries.remove(key);
        Ok(())
    }

    pub(crate) fn idle_lru(&self) -> Option<RegionKey> {
        self.entries
            .iter()
            .filter(|(key, _)| self.idle(key))
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
    }
    pub(crate) fn acquire(
        &mut self,
        key: &RegionKey,
        identity: ReadTransferIdentity,
        peer: ReadPeer,
        offset: u64,
        bytes: u64,
        hit: bool,
    ) -> Result<RegionOffer> {
        if self.leases.contains_key(&(peer, identity)) {
            return Err(Error::Protocol("duplicate Region transfer identity".into()));
        }
        let cached_bytes = self.entries.keys().map(|key| key.length).sum();
        let cached_regions = self.entries.len();
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| Error::Protocol("Region missing".into()))?;
        if !entry.accepting
            || bytes == 0
            || offset.checked_add(bytes).is_none_or(|end| end > key.length)
        {
            return Err(Error::Protocol(
                "Region retired or Piece range invalid".into(),
            ));
        }
        self.clock = self.clock.saturating_add(1);
        entry.last_used = self.clock;
        let offer = RegionOffer {
            source_id: entry.source.id,
            peer,
            identity,
            segment_generation: entry.generation,
            descriptor: entry.source.descriptor.clone(),
            token: entry.source.token.clone(),
            remote_offset: offset,
            piece_length: bytes,
            cache_hit: hit,
            cached_bytes,
            cached_regions,
            active_leases: self.leases.len() + 1,
            register_stages: if hit {
                super::ffi::read::source::ReadSourceStages::default()
            } else {
                entry.source.register_stages
            },
        };
        self.leases.insert(
            (peer, identity),
            RegionLease {
                key: key.clone(),
                peer,
                bytes,
            },
        );
        Ok(offer)
    }
    // Idempotent completion. A stale generation/owner cannot release a newer lease.
    pub(crate) fn release(&mut self, offer: &RegionOffer) -> Result<()> {
        let Some(lease) = self.leases.get(&(offer.peer, offer.identity)) else {
            return Ok(());
        };
        let entry = self
            .entries
            .get(&lease.key)
            .ok_or_else(|| Error::Protocol("Region lease lost its owner".into()))?;
        if entry.source.id != offer.source_id || entry.generation != offer.segment_generation {
            return Err(Error::Protocol("Region release generation mismatch".into()));
        }
        self.leases.remove(&(offer.peer, offer.identity));
        Ok(())
    }
    // Called only after this lane's remote target is closed under the provider gate.
    // Session generation avoids affecting a new lane that reuses a numeric peer ID.
    pub(crate) fn release_session(&mut self, session: RegionSession) {
        self.leases.retain(|(peer, identity), _| {
            *peer != session.peer || identity.session_generation != session.generation
        });
    }
    pub(crate) fn has_leases(&self) -> bool {
        !self.leases.is_empty()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RegionPiece {
    pub(crate) number: u32,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) ready: bool,
}

/// Complete adjacent Pieces only. A tail Region may have fewer Pieces; an
/// unfinished or missing neighbour immediately selects the requested Piece.
pub(crate) fn select_region(
    requested: RegionPiece,
    file_length: u64,
    pieces: &[RegionPiece],
) -> Result<(u64, u64)> {
    let single = (requested.offset, requested.length);
    let Some(first) = pieces.first() else {
        return Ok(single);
    };
    let mut end = first.offset;
    let mut found = false;
    let mut previous = None;
    for piece in pieces {
        if !piece.ready
            || piece.length == 0
            || piece.offset != end
            || previous.is_some_and(|number: u32| number.checked_add(1) != Some(piece.number))
        {
            return Ok(single);
        }
        end = match piece.offset.checked_add(piece.length) {
            Some(end) if end <= file_length => end,
            _ => return Ok(single),
        };
        if piece.number == requested.number {
            if piece.offset != requested.offset || piece.length != requested.length {
                return Err(Error::Protocol(
                    "requested Piece changed during Region selection".into(),
                ));
            }
            found = true;
        }
        previous = Some(piece.number);
        if end == file_length {
            break;
        }
    }
    if !found {
        return Ok(single);
    }
    Ok((first.offset, end - first.offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::{
        ffi::read::source::ReadSourceStages,
        read_owner::{ReadBudget, ReadOwnerRegistry},
    };

    const A: ReadPeer = ReadPeer {
        id: 1,
        generation: 1,
    };
    const B: ReadPeer = ReadPeer {
        id: 2,
        generation: 1,
    };
    fn id(session: u64, transfer: u32) -> ReadTransferIdentity {
        ReadTransferIdentity {
            session_generation: session,
            transfer_id: transfer,
            metadata_generation: 1,
        }
    }
    fn key(offset: u64, length: u64) -> RegionKey {
        RegionKey {
            kind: 0,
            task_id: "model".into(),
            device: 1,
            inode: 2,
            file_length: 128,
            offset,
            length,
        }
    }
    fn source() -> ReadSourceOffer {
        let cap = ReadCapacity {
            bytes: 128,
            entries: 8,
        };
        let peer = ReadCapacity {
            bytes: 64,
            entries: 4,
        };
        let mut registry = ReadOwnerRegistry::<()>::new(ReadBudget {
            total: ReadCapacity {
                bytes: 256,
                entries: 16,
            },
            source: cap,
            destination: cap,
            per_peer_source: peer,
            per_peer_destination: peer,
            quarantine: peer,
        })
        .unwrap();
        let owner = registry.reserve_shared_source(64).unwrap();
        // Only a mock identity is needed here: no native allocation/Segment.
        registry.release_unused_reservation(owner).unwrap();
        ReadSourceOffer {
            id: ReadSourceId::mock(owner),
            descriptor: ReadDescriptor {
                version: 1,
                eid: [1; 16],
                uasid: 1,
                va: 4096,
                length: 64,
                token_id: 1,
                access: 2,
                token_policy: 0,
            },
            token: ReadToken::new(42),
            register_stages: ReadSourceStages::default(),
        }
    }
    fn cache() -> RegionCache {
        let mut cache = RegionCache::default();
        cache.entries.insert(
            key(0, 64),
            RegionEntry {
                source: source(),
                generation: 11,
                accepting: true,
                last_used: 0,
            },
        );
        cache
    }
    fn piece(number: u32) -> RegionPiece {
        RegionPiece {
            number,
            offset: u64::from(number) * 32,
            length: 32,
            ready: true,
        }
    }
    #[test]
    fn eviction_waits_for_all_readers_and_failed_cleanup_keeps_entry_blocked() {
        let mut cache = cache();
        let a = cache
            .acquire(&key(0, 64), id(1, 1), A, 0, 32, false)
            .unwrap();
        let b = cache
            .acquire(&key(0, 64), id(1, 1), B, 32, 32, true)
            .unwrap();
        assert!(cache.begin_eviction(&key(0, 64)).is_err());
        cache.release(&a).unwrap();
        assert!(cache.begin_eviction(&key(0, 64)).is_err());
        cache.release(&b).unwrap();
        let owner = cache.begin_eviction(&key(0, 64)).unwrap();
        // A failed native unregister/revoke never calls finish_eviction.
        assert_eq!(cache.entries.len(), 1);
        assert!(cache
            .acquire(&key(0, 64), id(3, 1), A, 0, 32, true)
            .is_err());
        assert!(cache.finish_eviction(&key(0, 64), source().id).is_err());
        assert_eq!(cache.begin_eviction(&key(0, 64)).unwrap(), owner);
        cache.finish_eviction(&key(0, 64), owner).unwrap();
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn an_existing_registration_can_serve_a_piece_without_upgrading_its_region() {
        let mut cache = cache();
        let a = cache
            .acquire(&key(0, 64), id(1, 1), A, 0, 32, false)
            .unwrap();
        assert_eq!(cache.containing(&key(0, 128), 32, 32), Some(key(0, 64)));
        assert_eq!(cache.containing(&key(0, 128), 64, 32), None);
        cache.release(&a).unwrap();
        let mut replaced = key(0, 128);
        replaced.inode += 1;
        assert_eq!(cache.containing(&replaced, 32, 32), None);
    }

    #[test]
    fn two_children_share_region_and_retire_independently() {
        let mut cache = cache();
        let a = cache
            .acquire(&key(0, 64), id(1, 1), A, 0, 32, false)
            .unwrap();
        let b = cache
            .acquire(&key(0, 64), id(1, 1), B, 32, 32, true)
            .unwrap();
        assert_eq!(a.source_id, b.source_id);
        assert_eq!(a.segment_generation, b.segment_generation);
        assert_eq!(b.remote_offset, 32);
        assert!(!cache.idle(&key(0, 64)));
        cache.release(&a).unwrap();
        cache.release(&a).unwrap(); // duplicate terminal is harmless
        assert!(!cache.idle(&key(0, 64)));
        cache.release(&b).unwrap();
        assert_eq!(cache.entries.len(), 1); // register survives Piece completion
        assert_eq!(cache.idle_lru(), Some(key(0, 64)));
        let next = cache
            .acquire(&key(0, 64), id(3, 1), A, 0, 32, true)
            .unwrap();
        assert_eq!(next.source_id, a.source_id);
    }
    #[test]
    fn failed_child_cleanup_does_not_release_another_child_with_equal_wire_identity() {
        let mut cache = cache();
        let identity = id(1, 1); // two processes both start counters at one
        cache
            .acquire(&key(0, 64), identity, A, 0, 32, false)
            .unwrap();
        let b = cache
            .acquire(&key(0, 64), identity, B, 32, 32, true)
            .unwrap();
        cache.release_session(RegionSession {
            peer: A,
            generation: 1,
        });
        assert_eq!(cache.peer_usage(A), (0, 0));
        assert_eq!(cache.peer_usage(B), (32, 1));
        assert!(cache.begin_eviction(&key(0, 64)).is_err());
        cache.release(&b).unwrap();
        assert!(cache.begin_eviction(&key(0, 64)).is_ok());
    }

    #[test]
    fn dropped_reply_keeps_lease_and_session_cleanup_is_scoped() {
        let mut cache = cache();
        drop(
            cache
                .acquire(&key(0, 64), id(1, 1), A, 0, 32, false)
                .unwrap(),
        );
        let new_lane = cache
            .acquire(
                &key(0, 64),
                id(1, 1),
                ReadPeer { generation: 2, ..A },
                32,
                32,
                true,
            )
            .unwrap();
        cache.release_session(RegionSession {
            peer: A,
            generation: 1,
        });
        assert!(!cache.idle(&key(0, 64)));
        cache.release_session(RegionSession {
            peer: A,
            generation: 1,
        }); // cannot affect a reused numeric peer ID
        cache.release(&new_lane).unwrap();
        assert!(!cache.has_leases());
    }
    #[test]
    fn stale_release_and_duplicate_identity_cannot_release_an_active_reader() {
        let mut cache = cache();
        let offer = cache
            .acquire(&key(0, 64), id(1, 1), A, 0, 32, false)
            .unwrap();
        assert!(cache
            .acquire(&key(0, 64), id(1, 1), A, 32, 32, true)
            .is_err());
        let mut stale = offer.clone();
        stale.segment_generation += 1;
        assert!(cache.release(&stale).is_err());
        stale = offer.clone();
        stale.source_id = source().id;
        assert!(cache.release(&stale).is_err());
        assert!(!cache.idle(&key(0, 64)));
        cache.release(&offer).unwrap();
    }
    #[test]
    fn busy_regions_are_not_lru_victims_and_retired_regions_refuse_new_leases() {
        let mut cache = cache();
        let busy = cache
            .acquire(&key(0, 64), id(1, 1), A, 0, 32, false)
            .unwrap();
        cache.entries.insert(
            key(64, 64),
            RegionEntry {
                source: source(),
                generation: 12,
                accepting: true,
                last_used: 3,
            },
        );
        assert_eq!(cache.idle_lru(), Some(key(64, 64)));
        cache.entries.get_mut(&key(0, 64)).unwrap().accepting = false;
        assert!(cache
            .acquire(&key(0, 64), id(1, 1), A, 32, 32, true)
            .is_err());
        cache.release(&busy).unwrap(); // blocked owner still accepts cleanup
        assert_eq!(cache.entries.len(), 2); // failed native revoke must retain metadata
    }
    #[test]
    fn lease_capacity_and_bounds_are_independent_of_region_size() {
        let mut cache = cache();
        let limit = ReadCapacity {
            bytes: 32,
            entries: 1,
        };
        cache.check_lease(id(1, 1), A, 32, limit).unwrap();
        cache
            .acquire(&key(0, 64), id(1, 1), A, 32, 32, false)
            .unwrap();
        assert!(cache.check_lease(id(1, 2), A, 1, limit).is_err());
        cache.check_lease(id(2, 1), B, 32, limit).unwrap();
        for (offset, bytes) in [(63, 2), (u64::MAX, 1), (0, 0)] {
            assert!(cache
                .acquire(&key(0, 64), id(2, 1), B, offset, bytes, true)
                .is_err());
        }
        assert_eq!(cache.peer_usage(B), (0, 0));
    }
    #[test]
    fn overlap_checks_distinguish_tasks_backings_and_adjacent_ranges() {
        let a = key(0, 32);
        assert!(!a.overlaps(&key(32, 32)));
        assert!(a.overlaps(&key(0, 64)));
        let mut replacement = key(0, 64);
        replacement.inode += 1;
        assert!(!a.overlaps(&replacement));
        replacement = key(0, 64);
        replacement.task_id = "another-task".into();
        assert!(!a.overlaps(&replacement));
    }
    #[test]
    fn selection_handles_complete_group_unfinished_neighbour_tail_and_gaps() {
        let pieces = [piece(0), piece(1), piece(2), piece(3)];
        assert_eq!(select_region(piece(2), 128, &pieces).unwrap(), (0, 128));
        let mut unfinished = pieces;
        unfinished[3].ready = false;
        assert_eq!(select_region(piece(2), 128, &unfinished).unwrap(), (64, 32));
        let mut gap = pieces;
        gap[1].offset += 1;
        assert_eq!(select_region(piece(2), 128, &gap).unwrap(), (64, 32));
        let tail = [
            piece(2),
            RegionPiece {
                length: 7,
                ..piece(3)
            },
        ];
        assert_eq!(select_region(tail[1], 103, &tail).unwrap(), (64, 39));
        let changed = RegionPiece {
            length: 1,
            ..piece(2)
        };
        assert!(select_region(changed, 128, &pieces).is_err());
    }
}
