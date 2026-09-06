use super::{target::PeerTargetId, Error, Result};
use std::collections::HashMap;

/// Logical receive-credit state for one RM PeerTarget. This is deliberately
/// independent of native WR ownership: shared-JFR RQEs remain anonymous.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PeerCredit {
    pub(crate) guaranteed_limit: usize,
    pub(crate) guaranteed: usize,
    pub(crate) borrowed: usize,
    pub(crate) outstanding: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PeerCreditGrant {
    peer_id: PeerTargetId,
    guaranteed: usize,
    borrowed: usize,
}

impl PeerCreditGrant {
    pub(crate) fn peer_id(&self) -> PeerTargetId {
        self.peer_id
    }

    pub(crate) fn guaranteed(&self) -> usize {
        self.guaranteed
    }

    pub(crate) fn borrowed(&self) -> usize {
        self.borrowed
    }

    pub(crate) fn count(&self) -> usize {
        self.guaranteed + self.borrowed
    }
}

/// Process-wide RM credit planner. Physical capacity is supplied by the
/// shared semaphore; this ledger decides which part of that capacity a Peer
/// may consume without stealing another Peer's unused guarantee.
pub(crate) struct PeerCreditRegistry {
    capacity: usize,
    guaranteed_total: usize,
    outstanding: usize,
    peers: HashMap<PeerTargetId, PeerCredit>,
}

impl PeerCreditRegistry {
    pub(crate) fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(Error::InvalidConfiguration(
                "RM PeerCredit capacity must be non-zero".into(),
            ));
        }
        Ok(Self {
            capacity,
            guaranteed_total: 0,
            outstanding: 0,
            peers: HashMap::new(),
        })
    }

    pub(crate) fn register_peer(
        &mut self,
        peer_id: PeerTargetId,
        guaranteed_limit: usize,
    ) -> Result<()> {
        if peer_id == 0 {
            return Err(Error::InvalidConfiguration(
                "RM PeerCredit requires a non-zero PeerTarget id".into(),
            ));
        }
        if self.peers.contains_key(&peer_id) {
            return Err(Error::Protocol(format!(
                "PeerTarget {peer_id} already has an RM credit account"
            )));
        }
        let guaranteed_total = self
            .guaranteed_total
            .checked_add(guaranteed_limit)
            .ok_or_else(|| Error::InvalidConfiguration("RM guarantee total overflow".into()))?;
        if guaranteed_total > self.capacity {
            return Err(Error::InvalidConfiguration(format!(
                "RM PeerTarget guarantee exceeds shared capacity: existing={} requested={} capacity={}",
                self.guaranteed_total, guaranteed_limit, self.capacity
            )));
        }
        // Existing borrowed credits may already occupy nominally unreserved
        // capacity. Do not create a new guarantee that cannot be honored until
        // those credits happen to drain.
        let reserved_unused = self.unused_guarantees();
        let available_for_guarantee = self
            .capacity
            .saturating_sub(self.outstanding)
            .saturating_sub(reserved_unused);
        if guaranteed_limit > available_for_guarantee {
            return Err(Error::BufferUnavailable {
                kind: "shared RM guarantee",
                requested: guaranteed_limit,
                available: available_for_guarantee,
            });
        }
        self.guaranteed_total = guaranteed_total;
        self.peers.insert(
            peer_id,
            PeerCredit {
                guaranteed_limit,
                ..PeerCredit::default()
            },
        );
        debug_assert!(self.invariant_holds());
        Ok(())
    }

    pub(crate) fn unregister_peer(&mut self, peer_id: PeerTargetId) -> Result<()> {
        let account = self
            .peers
            .get(&peer_id)
            .copied()
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {peer_id}")))?;
        if account.outstanding != 0 {
            return Err(Error::Protocol(format!(
                "cannot remove PeerTarget {peer_id} with {} outstanding RM credits",
                account.outstanding
            )));
        }
        self.peers.remove(&peer_id);
        self.guaranteed_total -= account.guaranteed_limit;
        debug_assert!(self.invariant_holds());
        Ok(())
    }

    pub(crate) fn try_grant(
        &mut self,
        peer_id: PeerTargetId,
        count: usize,
    ) -> Result<PeerCreditGrant> {
        if count == 0 {
            return Err(Error::InvalidConfiguration(
                "RM credit grant must be non-zero".into(),
            ));
        }
        let account = self
            .peers
            .get(&peer_id)
            .copied()
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {peer_id}")))?;
        let available = self.capacity.saturating_sub(self.outstanding);
        if count > available {
            return Err(Error::BufferUnavailable {
                kind: "shared RM credit",
                requested: count,
                available,
            });
        }

        let guaranteed = count.min(account.guaranteed_limit.saturating_sub(account.guaranteed));
        let borrowed = count - guaranteed;
        let unused_other_guarantees = self
            .peers
            .iter()
            .filter(|(id, _)| **id != peer_id)
            .map(|(_, peer)| peer.guaranteed_limit.saturating_sub(peer.guaranteed))
            .sum::<usize>();
        let borrowable = available.saturating_sub(unused_other_guarantees);
        if borrowed > borrowable {
            return Err(Error::BufferUnavailable {
                kind: "shared RM surplus",
                requested: borrowed,
                available: borrowable,
            });
        }

        let account = self
            .peers
            .get_mut(&peer_id)
            .expect("PeerTarget account checked above");
        account.guaranteed += guaranteed;
        account.borrowed += borrowed;
        account.outstanding += count;
        self.outstanding += count;
        debug_assert!(self.invariant_holds());
        Ok(PeerCreditGrant {
            peer_id,
            guaranteed,
            borrowed,
        })
    }

    pub(crate) fn release(&mut self, grant: PeerCreditGrant) -> Result<()> {
        let account = self
            .peers
            .get_mut(&grant.peer_id)
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {}", grant.peer_id)))?;
        if grant.guaranteed > account.guaranteed
            || grant.borrowed > account.borrowed
            || grant.count() > account.outstanding
            || grant.count() > self.outstanding
        {
            return Err(Error::Protocol(
                "RM PeerCredit release exceeds outstanding grant".into(),
            ));
        }
        account.guaranteed -= grant.guaranteed;
        account.borrowed -= grant.borrowed;
        account.outstanding -= grant.count();
        self.outstanding -= grant.count();
        debug_assert!(self.invariant_holds());
        Ok(())
    }

    pub(crate) fn peer(&self, peer_id: PeerTargetId) -> Option<PeerCredit> {
        self.peers.get(&peer_id).copied()
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding
    }

    fn unused_guarantees(&self) -> usize {
        self.peers
            .values()
            .map(|peer| peer.guaranteed_limit - peer.guaranteed)
            .sum()
    }

    fn invariant_holds(&self) -> bool {
        let accounted_outstanding = self
            .peers
            .values()
            .map(|peer| peer.outstanding)
            .sum::<usize>();
        let account_classes_match = self
            .peers
            .values()
            .all(|peer| peer.guaranteed + peer.borrowed == peer.outstanding);
        account_classes_match
            && accounted_outstanding == self.outstanding
            && self.guaranteed_total
                == self
                    .peers
                    .values()
                    .map(|peer| peer.guaranteed_limit)
                    .sum::<usize>()
            && self.outstanding + self.unused_guarantees() <= self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_guarantees_are_protected_while_surplus_is_borrowable() {
        let mut credits = PeerCreditRegistry::new(12).unwrap();
        credits.register_peer(1, 3).unwrap();
        credits.register_peer(2, 3).unwrap();

        let first = credits.try_grant(1, 8).unwrap();
        assert_eq!(first.guaranteed(), 3);
        assert_eq!(first.borrowed(), 5);
        assert_eq!(first.peer_id(), 1);
        assert_eq!(credits.peer(1).unwrap().outstanding, 8);

        // Peer 1 cannot consume Peer 2's untouched guarantee.
        assert!(matches!(
            credits.try_grant(1, 2),
            Err(Error::BufferUnavailable {
                kind: "shared RM surplus",
                ..
            })
        ));
        let second = credits.try_grant(2, 3).unwrap();
        assert_eq!(second.guaranteed(), 3);
        assert_eq!(second.borrowed(), 0);
        assert_eq!(credits.outstanding(), 11);

        credits.release(first).unwrap();
        credits.release(second).unwrap();
        assert_eq!(credits.outstanding(), 0);
        credits.unregister_peer(1).unwrap();
        credits.unregister_peer(2).unwrap();
    }

    #[test]
    fn guarantee_registration_and_retirement_are_bounded() {
        assert!(PeerCreditRegistry::new(0).is_err());
        let mut credits = PeerCreditRegistry::new(4).unwrap();
        credits.register_peer(1, 2).unwrap();
        assert!(credits.register_peer(2, 3).is_err());
        credits.register_peer(2, 2).unwrap();
        // Zero is a valid account for a Peer that may only borrow surplus;
        // this assertion checks duplicate registration, not the zero limit.
        assert!(credits.register_peer(2, 0).is_err());

        let grant = credits.try_grant(1, 1).unwrap();
        assert!(credits.unregister_peer(1).is_err());
        credits.release(grant).unwrap();
        credits.unregister_peer(1).unwrap();
    }

    #[test]
    fn registration_cannot_overcommit_capacity_already_borrowed() {
        let mut credits = PeerCreditRegistry::new(12).unwrap();
        credits.register_peer(1, 3).unwrap();
        let grant = credits.try_grant(1, 10).unwrap();

        assert!(matches!(
            credits.register_peer(2, 3),
            Err(Error::BufferUnavailable {
                kind: "shared RM guarantee",
                requested: 3,
                available: 2,
            })
        ));
        credits.register_peer(2, 2).unwrap();

        credits.release(grant).unwrap();
        credits.unregister_peer(1).unwrap();
        credits.unregister_peer(2).unwrap();
    }

    #[test]
    fn zero_guarantee_peer_can_only_borrow_unreserved_surplus() {
        let mut credits = PeerCreditRegistry::new(4).unwrap();
        credits.register_peer(1, 3).unwrap();
        credits.register_peer(2, 0).unwrap();

        let borrowed = credits.try_grant(2, 1).unwrap();
        assert_eq!(borrowed.guaranteed(), 0);
        assert_eq!(borrowed.borrowed(), 1);
        assert!(credits.try_grant(2, 1).is_err());

        credits.release(borrowed).unwrap();
    }
}
