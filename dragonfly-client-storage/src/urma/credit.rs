use super::{target::PeerTargetId, Error, Result};
use dragonfly_client_metric::{
    collect_urma_rx_peer_credit_event_metrics, collect_urma_rx_peer_credit_metrics,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};

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

    #[cfg(test)]
    pub(crate) fn guaranteed(&self) -> usize {
        self.guaranteed
    }

    #[cfg(test)]
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

struct PeerCreditAdmissionState {
    credits: PeerCreditRegistry,
    retiring: HashSet<PeerTargetId>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PeerCreditSnapshot {
    active_peers: usize,
    retiring_peers: usize,
    guaranteed_limit: usize,
    guaranteed: usize,
    borrowed: usize,
    outstanding: usize,
}

struct PeerCreditAdmissionInner {
    permits: Arc<Semaphore>,
    state: Mutex<PeerCreditAdmissionState>,
    required_queue: AsyncMutex<()>,
    changed: Notify,
}

/// Process-wide RX admission shared by every RM PeerTarget. The semaphore
/// owns physical depth while `PeerCreditRegistry` protects unused per-peer
/// guarantees from surplus borrowers.
#[derive(Clone)]
pub(crate) struct PeerCreditAdmission {
    inner: Arc<PeerCreditAdmissionInner>,
}

/// One admitted RX window. Dropping it atomically returns both its physical
/// shared-JFR permits and logical guaranteed/borrowed grant.
pub(crate) struct PeerCreditPermit {
    inner: Arc<PeerCreditAdmissionInner>,
    grant: Option<PeerCreditGrant>,
    permit: Option<OwnedSemaphorePermit>,
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
        // `available` still contains the caller's unused guarantee. The
        // guaranteed portion above consumes it, while only capacity beyond
        // every currently-unused guarantee is borrowable surplus.
        let borrowable = available.saturating_sub(self.unused_guarantees());
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

    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding
    }

    fn snapshot(&self, retiring_peers: usize) -> PeerCreditSnapshot {
        PeerCreditSnapshot {
            active_peers: self.peers.len().saturating_sub(retiring_peers),
            retiring_peers,
            guaranteed_limit: self.peers.values().map(|peer| peer.guaranteed_limit).sum(),
            guaranteed: self.peers.values().map(|peer| peer.guaranteed).sum(),
            borrowed: self.peers.values().map(|peer| peer.borrowed).sum(),
            outstanding: self.outstanding,
        }
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

impl PeerCreditAdmission {
    pub(crate) fn new(capacity: u32) -> Result<Self> {
        let capacity = usize::try_from(capacity).map_err(|_| {
            Error::InvalidConfiguration("shared RM credit depth does not fit usize".into())
        })?;
        let admission = Self {
            inner: Arc::new(PeerCreditAdmissionInner {
                permits: Arc::new(Semaphore::new(capacity)),
                state: Mutex::new(PeerCreditAdmissionState {
                    credits: PeerCreditRegistry::new(capacity)?,
                    retiring: HashSet::new(),
                }),
                required_queue: AsyncMutex::new(()),
                changed: Notify::new(),
            }),
        };
        publish_credit_snapshot(PeerCreditSnapshot::default());
        Ok(admission)
    }

    pub(crate) fn register_peer(&self, peer_id: PeerTargetId, guaranteed_limit: u32) -> Result<()> {
        let guaranteed_limit = usize::try_from(guaranteed_limit).map_err(|_| {
            Error::InvalidConfiguration("RM PeerTarget guarantee does not fit usize".into())
        })?;
        let (result, snapshot) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let result = state.credits.register_peer(peer_id, guaranteed_limit);
            let snapshot = state.credits.snapshot(state.retiring.len());
            (result, snapshot)
        };
        let event = match &result {
            Ok(()) => "registered",
            Err(Error::BufferUnavailable { .. }) => "register_rejected_capacity",
            Err(Error::Protocol(_)) => "register_rejected_duplicate",
            Err(Error::InvalidConfiguration(detail))
                if detail.contains("exceeds shared capacity") =>
            {
                "register_rejected_capacity"
            }
            Err(_) => "register_rejected_configuration",
        };
        publish_credit_snapshot(snapshot);
        collect_urma_rx_peer_credit_event_metrics(event);
        result
    }

    /// Stops new grants immediately. Account removal is deferred until every
    /// lease-held permit for the Peer has been dropped.
    pub(crate) fn retire_peer(&self, peer_id: PeerTargetId) -> Result<()> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let account = state
            .credits
            .peer(peer_id)
            .ok_or_else(|| Error::Protocol(format!("unknown PeerTarget {peer_id}")))?;
        let newly_retiring = if account.outstanding == 0 {
            state.credits.unregister_peer(peer_id)?;
            false
        } else {
            state.retiring.insert(peer_id)
        };
        let snapshot = state.credits.snapshot(state.retiring.len());
        drop(state);
        publish_credit_snapshot(snapshot);
        if account.outstanding == 0 || newly_retiring {
            collect_urma_rx_peer_credit_event_metrics("retiring");
        }
        if account.outstanding == 0 {
            collect_urma_rx_peer_credit_event_metrics("unregistered");
        }
        self.inner.changed.notify_waiters();
        Ok(())
    }

    pub(crate) async fn acquire(
        &self,
        peer_id: PeerTargetId,
        count: u32,
    ) -> Result<PeerCreditPermit> {
        loop {
            // Subscribe before checking state so a concurrent release cannot
            // be lost between a failed grant and the await.
            let changed = self.inner.changed.notified();
            // Serialize each reservation attempt, but never hold the FIFO gate
            // while waiting for another Peer's protected guarantee. Otherwise
            // an oversized head request can prevent that Peer from consuming
            // its own guarantee, leaving an entirely idle pool deadlocked.
            let reserved = {
                let _queue = self.inner.required_queue.lock().await;
                self.reserve(peer_id, count)
            };
            match reserved {
                Ok(mut credit) => {
                    let permit = self
                        .inner
                        .permits
                        .clone()
                        .acquire_many_owned(count)
                        .await
                        .map_err(|_| Error::Shutdown {
                            failures: vec!["shared RM RX admission is closed".into()],
                        })?;
                    credit.permit = Some(permit);
                    return Ok(credit);
                }
                Err(Error::BufferUnavailable { .. }) => changed.await,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn try_acquire(
        &self,
        peer_id: PeerTargetId,
        count: u32,
    ) -> Result<PeerCreditPermit> {
        let mut credit = self.reserve(peer_id, count)?;
        let available = self.inner.permits.available_permits();
        let permit = self
            .inner
            .permits
            .clone()
            .try_acquire_many_owned(count)
            .map_err(|_| Error::BufferUnavailable {
                kind: "shared RM physical RX",
                requested: count as usize,
                available,
            })?;
        credit.permit = Some(permit);
        Ok(credit)
    }

    pub(crate) fn available_permits(&self) -> usize {
        self.inner.permits.available_permits()
    }

    fn reserve(&self, peer_id: PeerTargetId, count: u32) -> Result<PeerCreditPermit> {
        let count = usize::try_from(count).map_err(|_| {
            Error::InvalidConfiguration("RM credit request does not fit usize".into())
        })?;
        let (grant, snapshot) = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.retiring.contains(&peer_id) {
                return Err(Error::Protocol(format!(
                    "PeerTarget {peer_id} is retiring and rejects RX credit"
                )));
            }
            let grant = state.credits.try_grant(peer_id, count)?;
            let snapshot = state.credits.snapshot(state.retiring.len());
            (grant, snapshot)
        };
        publish_credit_snapshot(snapshot);
        collect_urma_rx_peer_credit_event_metrics("granted");
        Ok(PeerCreditPermit {
            inner: Arc::clone(&self.inner),
            grant: Some(grant),
            permit: None,
        })
    }
}

impl PeerCreditPermit {
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.grant
            .as_ref()
            .map(PeerCreditGrant::count)
            .unwrap_or_default()
    }
}

impl Drop for PeerCreditPermit {
    fn drop(&mut self) {
        // Return physical capacity before waking logical waiters. A borrower
        // racing in this small interval still sees its grant reserved and
        // waits for the notification below.
        drop(self.permit.take());
        let Some(grant) = self.grant.take() else {
            return;
        };
        let peer_id = grant.peer_id();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let release = state.credits.release(grant);
        debug_assert!(release.is_ok(), "PeerCreditPermit release must balance");
        let released = release.is_ok();
        let mut unregistered = false;
        if released
            && state.retiring.contains(&peer_id)
            && state
                .credits
                .peer(peer_id)
                .is_some_and(|account| account.outstanding == 0)
        {
            let unregister = state.credits.unregister_peer(peer_id);
            debug_assert!(unregister.is_ok(), "retired PeerCredit must unregister");
            if unregister.is_ok() {
                state.retiring.remove(&peer_id);
                unregistered = true;
            }
        }
        let snapshot = state.credits.snapshot(state.retiring.len());
        drop(state);
        publish_credit_snapshot(snapshot);
        if released {
            collect_urma_rx_peer_credit_event_metrics("released");
        }
        if unregistered {
            collect_urma_rx_peer_credit_event_metrics("unregistered");
        }
        self.inner.changed.notify_waiters();
    }
}

fn publish_credit_snapshot(snapshot: PeerCreditSnapshot) {
    collect_urma_rx_peer_credit_metrics(
        snapshot.active_peers,
        snapshot.retiring_peers,
        snapshot.guaranteed_limit,
        snapshot.guaranteed,
        snapshot.borrowed,
        snapshot.outstanding,
    );
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
        assert_eq!(
            credits.snapshot(0),
            PeerCreditSnapshot {
                active_peers: 2,
                retiring_peers: 0,
                guaranteed_limit: 6,
                guaranteed: 6,
                borrowed: 5,
                outstanding: 11,
            }
        );

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

    #[test]
    fn admission_preserves_guarantees_while_lending_real_surplus() {
        let admission = PeerCreditAdmission::new(6).unwrap();
        admission.register_peer(1, 2).unwrap();
        admission.register_peer(2, 2).unwrap();

        let peer_1 = admission.try_acquire(1, 4).unwrap();
        assert_eq!(peer_1.count(), 4);
        let peer_2 = admission.try_acquire(2, 2).unwrap();
        assert_eq!(peer_2.count(), 2);
        assert_eq!(admission.available_permits(), 0);
        assert!(admission.try_acquire(1, 1).is_err());

        drop(peer_1);
        drop(peer_2);
        assert_eq!(admission.available_permits(), 6);
    }

    #[tokio::test]
    async fn required_admission_wakes_after_lease_held_credit_returns() {
        let admission = PeerCreditAdmission::new(1).unwrap();
        admission.register_peer(1, 0).unwrap();
        admission.register_peer(2, 0).unwrap();
        let peer_1 = admission.acquire(1, 1).await.unwrap();

        let waiter = tokio::spawn({
            let admission = admission.clone();
            async move { admission.acquire(2, 1).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(peer_1);

        let peer_2 = waiter.await.unwrap().unwrap();
        assert_eq!(peer_2.count(), 1);
    }

    #[tokio::test]
    async fn oversized_head_waiter_does_not_block_another_peers_guarantee() {
        let admission = PeerCreditAdmission::new(8).unwrap();
        admission.register_peer(1, 4).unwrap();
        admission.register_peer(2, 4).unwrap();

        let blocked = {
            let admission = admission.clone();
            tokio::spawn(async move { admission.acquire(1, 8).await })
        };
        tokio::task::yield_now().await;

        let peer_two = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            admission.acquire(2, 4),
        )
        .await
        .expect("Peer 2 must pass the blocked oversized head waiter")
        .unwrap();
        assert_eq!(peer_two.count(), 4);
        drop(peer_two);
        blocked.abort();
    }

    #[tokio::test]
    async fn hot_borrower_preserves_sibling_guarantees_during_concurrent_churn() {
        let admission = PeerCreditAdmission::new(32).unwrap();
        for peer_id in 1..=4 {
            admission.register_peer(peer_id, 4).unwrap();
        }

        // Peer 1 consumes its guarantee plus every byte of real surplus. The
        // remaining capacity is exactly the three sibling guarantees.
        let hot = admission.try_acquire(1, 20).unwrap();
        assert!(admission.try_acquire(1, 1).is_err());

        let mut waiters = Vec::new();
        for peer_id in 2..=4 {
            let admission = admission.clone();
            waiters.push(tokio::spawn(
                async move { admission.acquire(peer_id, 4).await },
            ));
        }
        let peer_2 = waiters.remove(0).await.unwrap().unwrap();
        let peer_3 = waiters.remove(0).await.unwrap().unwrap();
        let peer_4 = waiters.remove(0).await.unwrap().unwrap();
        assert_eq!(admission.available_permits(), 0);

        // Retirement remains deferred until Peer 2's lease-held credit is
        // released, after which the same logical id can represent a new peer
        // generation without colliding with the old account.
        admission.retire_peer(2).unwrap();
        drop(peer_2);
        admission.register_peer(2, 4).unwrap();

        drop(peer_3);
        drop(peer_4);
        drop(hot);
        assert_eq!(admission.available_permits(), 32);
        let peer_2 = admission.try_acquire(2, 4).unwrap();
        assert_eq!(peer_2.count(), 4);
    }

    #[tokio::test]
    async fn cancelled_required_acquire_returns_reserved_logical_credit() {
        let admission = PeerCreditAdmission::new(1).unwrap();
        admission.register_peer(1, 0).unwrap();

        // Hold only the physical permit to force `acquire` into the narrow
        // state where its logical grant exists but semaphore acquisition is
        // pending. Cancelling the future must drop that grant.
        let physical = admission
            .inner
            .permits
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let admission = admission.clone();
            async move { admission.acquire(1, 1).await }
        });
        tokio::task::yield_now().await;
        waiter.abort();
        match waiter.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("aborted RM admission unexpectedly completed"),
        }

        drop(physical);
        assert!(admission.try_acquire(1, 1).is_ok());
    }

    #[test]
    fn retiring_account_rejects_new_grants_and_unregisters_after_drop() {
        let admission = PeerCreditAdmission::new(2).unwrap();
        admission.register_peer(7, 1).unwrap();
        let permit = admission.try_acquire(7, 1).unwrap();

        admission.retire_peer(7).unwrap();
        assert!(admission.try_acquire(7, 1).is_err());
        {
            let state = admission.inner.state.lock().unwrap();
            assert_eq!(
                state.credits.snapshot(state.retiring.len()),
                PeerCreditSnapshot {
                    active_peers: 0,
                    retiring_peers: 1,
                    guaranteed_limit: 1,
                    guaranteed: 1,
                    borrowed: 0,
                    outstanding: 1,
                }
            );
        }
        drop(permit);

        // Deferred retirement removed the old account, so the same logical
        // id can be registered again by a future generation.
        {
            let state = admission.inner.state.lock().unwrap();
            assert_eq!(
                state.credits.snapshot(state.retiring.len()),
                PeerCreditSnapshot::default()
            );
        }
        admission.register_peer(7, 1).unwrap();
    }
}
