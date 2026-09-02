use super::{
    buffer::{RegisteredRxWindowLease, TxWindowLease, UrmaBufferPool},
    ffi,
    lane::{OperationType, WrToken},
    native_error, Error, Result,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::oneshot;

const MAX_POLL_BATCH: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompletionStats {
    pub(crate) send_post: u64,
    pub(crate) recv_post: u64,
    pub(crate) send_cqe: u64,
    pub(crate) recv_cqe: u64,
    pub(crate) cqe_error: u64,
    pub(crate) poll_calls: u64,
    pub(crate) empty_polls: u64,
    pub(crate) max_outstanding: u64,
}

pub(crate) struct RegisteredRxCompletion {
    pub(crate) lane_id: u16,
    /// Sequence assigned when this receive WR was posted. SEND/RECV matching
    /// on the provider is not FIFO, so this is only a local bookkeeping hint;
    /// `imm_data` is the authoritative logical transfer/chunk identity.
    pub(crate) posted_sequence: Option<u64>,
    pub(crate) imm_data: u64,
    pub(crate) slot: crate::urma::buffer::SlotId,
    pub(crate) lease: RegisteredRxWindowLease,
}

pub(crate) type RegisteredRxCompletionTx = oneshot::Sender<Result<RegisteredRxCompletion>>;

pub(crate) struct RegisteredTxCompletion {
    pub(crate) lane_id: u16,
    pub(crate) sequences: Vec<u64>,
    pub(crate) lease: TxWindowLease,
}

pub(crate) type RegisteredTxCompletionTx = oneshot::Sender<Result<RegisteredTxCompletion>>;

struct RegisteredTxWindowInner {
    pending: usize,
    posting_finished: bool,
    first_error: Option<Error>,
    lane_id: u16,
    sequences: Vec<u64>,
    lease: Option<TxWindowLease>,
    completion: Option<RegisteredTxCompletionTx>,
}

#[derive(Clone)]
pub(crate) struct RegisteredTxWindowState(Arc<Mutex<RegisteredTxWindowInner>>);

impl RegisteredTxWindowState {
    pub(crate) fn new(
        lane_id: u16,
        sequences: Vec<u64>,
        lease: TxWindowLease,
        completion: RegisteredTxCompletionTx,
    ) -> Self {
        Self(Arc::new(Mutex::new(RegisteredTxWindowInner {
            pending: 0,
            posting_finished: false,
            first_error: None,
            lane_id,
            sequences,
            lease: Some(lease),
            completion: Some(completion),
        })))
    }

    fn posted(&self) {
        self.0.lock().unwrap().pending += 1;
    }

    pub(crate) fn finish_posting(&self, error: Option<Error>) {
        let mut inner = self.0.lock().unwrap();
        inner.posting_finished = true;
        if inner.first_error.is_none() {
            inner.first_error = error;
        }
        Self::resolve(&mut inner);
    }

    fn completed(&self, result: &Result<RoutedCompletion>) {
        let mut inner = self.0.lock().unwrap();
        debug_assert_ne!(inner.pending, 0);
        inner.pending -= 1;
        if inner.first_error.is_none() {
            if let Err(error) = result {
                inner.first_error = Some(error.clone());
            }
        }
        Self::resolve(&mut inner);
    }

    fn fail(&self, error: Error) {
        let mut inner = self.0.lock().unwrap();
        if inner.first_error.is_none() {
            inner.first_error = Some(error.clone());
        }
        if let Some(completion) = inner.completion.take() {
            let _ = completion.send(Err(error));
        }
    }

    fn resolve(inner: &mut RegisteredTxWindowInner) {
        if !inner.posting_finished || inner.pending != 0 {
            return;
        }
        let Some(completion) = inner.completion.take() else {
            return;
        };
        if let Some(error) = inner.first_error.take() {
            // Dropping only after every posted CQE has restored its slot to
            // LeasedTx makes the lease's owner-thread recycle notification safe.
            inner.lease.take();
            let _ = completion.send(Err(error));
        } else {
            let lease = inner.lease.take().expect("registered TX lease is owned");
            let _ = completion.send(Ok(RegisteredTxCompletion {
                lane_id: inner.lane_id,
                sequences: std::mem::take(&mut inner.sequences),
                lease,
            }));
        }
    }
}

enum CompletionTarget {
    RegisteredRx(RegisteredRxCompletionTx),
    RegisteredTx(RegisteredTxWindowState),
}

enum RoutedCompletion {
    RegisteredRx(RegisteredRxCompletion),
    RegisteredTx,
}

fn validate_recv_immediate(record: ffi::CompletionRecord) -> Result<u64> {
    if record.opcode != ffi::CR_OPCODE_SEND_WITH_IMM || !record.imm_data_valid {
        return Err(Error::Protocol(format!(
            "URMA receive CQE lacks SEND_WITH_IMM identity: opcode={} imm_data_valid={}",
            record.opcode, record.imm_data_valid
        )));
    }
    Ok(record.imm_data)
}

impl CompletionTarget {
    fn send(self, result: Result<RoutedCompletion>) {
        match (self, result) {
            (Self::RegisteredRx(completion), Ok(RoutedCompletion::RegisteredRx(value))) => {
                let _ = completion.send(Ok(value));
            }
            (Self::RegisteredTx(completion), result) => completion.completed(&result),
            (Self::RegisteredRx(completion), Err(error)) => {
                let _ = completion.send(Err(error));
            }
            (Self::RegisteredRx(completion), Ok(RoutedCompletion::RegisteredTx)) => {
                let _ = completion.send(Err(Error::Protocol(
                    "registered TX completion routed to RX receiver".into(),
                )));
            }
        }
    }

    fn fail(self, error: Error) {
        match self {
            Self::RegisteredRx(completion) => {
                let _ = completion.send(Err(error));
            }
            Self::RegisteredTx(completion) => completion.fail(error),
        }
    }
}

struct OutstandingWr {
    user_ctx: u64,
    handle: ffi::WrHandle,
    sequence: Option<u64>,
    completion: Option<CompletionTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaneRetirement {
    jetty_id: u32,
    jfr_id: u32,
    waiting_for_flush: bool,
    flush_done: bool,
}

/// The single completion consumer for the process-shared JFCs. A JFC must not
/// be polled independently by individual lanes because any poll may return a
/// completion belonging to any Jetty attached to that JFC.
pub(crate) struct CompletionRouter {
    batch: usize,
    outstanding: Vec<Option<OutstandingWr>>,
    outstanding_total: usize,
    outstanding_send: usize,
    outstanding_recv: usize,
    outstanding_by_lane: HashMap<u16, usize>,
    retirement_by_lane: HashMap<u16, LaneRetirement>,
    lane_by_jetty_id: HashMap<u32, u16>,
    stats: CompletionStats,
}

impl CompletionRouter {
    pub(crate) fn new(batch: usize) -> Result<Self> {
        if batch == 0 || batch > MAX_POLL_BATCH {
            return Err(Error::InvalidConfiguration(format!(
                "completion poll batch must be in 1..={MAX_POLL_BATCH}"
            )));
        }
        Ok(Self {
            batch,
            outstanding: Vec::new(),
            outstanding_total: 0,
            outstanding_send: 0,
            outstanding_recv: 0,
            outstanding_by_lane: HashMap::new(),
            retirement_by_lane: HashMap::new(),
            lane_by_jetty_id: HashMap::new(),
            stats: CompletionStats::default(),
        })
    }

    pub(crate) fn register_lane(&mut self, lane_id: u16, jetty_id: u32, jfr_id: u32) -> Result<()> {
        if self.retirement_by_lane.contains_key(&lane_id) {
            return Err(Error::Protocol(format!(
                "duplicate completion lifecycle registration for lane {lane_id}"
            )));
        }
        if let Some(existing) = self.lane_by_jetty_id.insert(jetty_id, lane_id) {
            self.lane_by_jetty_id.insert(jetty_id, existing);
            return Err(Error::Protocol(format!(
                "native Jetty id {jetty_id} is already owned by lane {existing}"
            )));
        }
        self.retirement_by_lane.insert(
            lane_id,
            LaneRetirement {
                jetty_id,
                jfr_id,
                waiting_for_flush: false,
                flush_done: false,
            },
        );
        Ok(())
    }

    pub(crate) fn begin_lane_retirement(&mut self, lane_id: u16) -> Result<()> {
        let retirement = self.retirement_by_lane.get_mut(&lane_id).ok_or_else(|| {
            Error::Protocol(format!(
                "lane {lane_id} has no completion lifecycle registration"
            ))
        })?;
        retirement.waiting_for_flush = true;
        tracing::debug!(
            lane_id,
            native_jetty_id = retirement.jetty_id,
            native_jfr_id = retirement.jfr_id,
            "waiting for URMA lane flush completion"
        );
        Ok(())
    }

    pub(crate) fn lane_flush_done(&self, lane_id: u16) -> bool {
        self.retirement_by_lane
            .get(&lane_id)
            .is_some_and(|retirement| retirement.flush_done)
    }

    pub(crate) fn unregister_lane(&mut self, lane_id: u16) -> Result<()> {
        let retirement = self.retirement_by_lane.remove(&lane_id).ok_or_else(|| {
            Error::Protocol(format!(
                "lane {lane_id} has no completion lifecycle registration"
            ))
        })?;
        self.lane_by_jetty_id.remove(&retirement.jetty_id);
        Ok(())
    }

    fn has_pending_flush(&self) -> bool {
        self.retirement_by_lane
            .values()
            .any(|retirement| retirement.waiting_for_flush && !retirement.flush_done)
    }

    pub(crate) fn track_registered_rx(
        &mut self,
        user_ctx: u64,
        handle: ffi::WrHandle,
        sequence: Option<u64>,
        completion: RegisteredRxCompletionTx,
    ) -> Result<()> {
        let token = WrToken::decode(user_ctx)?;
        if token.operation != OperationType::Recv {
            return Err(Error::Protocol(
                "registered RX completion requires a RECV WR".into(),
            ));
        }
        let slot = token.slot.index();
        if self.outstanding.len() <= slot {
            self.outstanding.resize_with(slot + 1, || None);
        }
        if self.outstanding[slot].is_some() {
            return Err(Error::Protocol("duplicate outstanding slot".into()));
        }
        self.outstanding[slot] = Some(OutstandingWr {
            user_ctx,
            handle,
            sequence,
            completion: Some(CompletionTarget::RegisteredRx(completion)),
        });
        self.outstanding_total += 1;
        self.outstanding_recv += 1;
        *self.outstanding_by_lane.entry(token.lane_id).or_default() += 1;
        self.stats.recv_post += 1;
        self.stats.max_outstanding = self
            .stats
            .max_outstanding
            .max(self.outstanding_total as u64);
        Ok(())
    }

    pub(crate) fn track_registered_tx(
        &mut self,
        user_ctx: u64,
        handle: ffi::WrHandle,
        sequence: u64,
        completion: RegisteredTxWindowState,
    ) -> Result<()> {
        let token = WrToken::decode(user_ctx)?;
        if token.operation != OperationType::Send {
            return Err(Error::Protocol(
                "registered TX completion requires a SEND WR".into(),
            ));
        }
        let slot = token.slot.index();
        if self.outstanding.len() <= slot {
            self.outstanding.resize_with(slot + 1, || None);
        }
        if self.outstanding[slot].is_some() {
            return Err(Error::Protocol("duplicate outstanding slot".into()));
        }
        completion.posted();
        self.outstanding[slot] = Some(OutstandingWr {
            user_ctx,
            handle,
            sequence: Some(sequence),
            completion: Some(CompletionTarget::RegisteredTx(completion)),
        });
        self.outstanding_total += 1;
        self.outstanding_send += 1;
        *self.outstanding_by_lane.entry(token.lane_id).or_default() += 1;
        self.stats.send_post += 1;
        self.stats.max_outstanding = self
            .stats
            .max_outstanding
            .max(self.outstanding_total as u64);
        Ok(())
    }

    pub(crate) fn poll_once(
        &mut self,
        send_jfc: &ffi::JfcHandle,
        recv_jfc: &ffi::JfcHandle,
        pool: &mut UrmaBufferPool,
    ) -> Result<usize> {
        self.stats.poll_calls += 1;
        let mut completed = 0;
        let mut first_error = None;
        if self.outstanding_send != 0 || self.has_pending_flush() {
            match self.poll_jfc(send_jfc, false, pool) {
                Ok(count) => completed += count,
                Err(error) => first_error = Some(error),
            }
        }
        if self.outstanding_recv != 0 {
            match self.poll_jfc(recv_jfc, true, pool) {
                Ok(count) => completed += count,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if completed == 0 {
            self.stats.empty_polls += 1;
            std::hint::spin_loop();
        }
        Ok(completed)
    }

    fn poll_jfc(
        &mut self,
        jfc: &ffi::JfcHandle,
        recv_queue: bool,
        pool: &mut UrmaBufferPool,
    ) -> Result<usize> {
        let mut records = [ffi::CompletionRecord::default(); MAX_POLL_BATCH];
        let count = jfc
            .poll_into(&mut records[..self.batch])
            .map_err(|error| native_error("poll_jfc", error))?;
        drain_batch(records.into_iter().take(count), |record| {
            self.route(record, recv_queue, pool)
        })
    }

    fn route(
        &mut self,
        record: ffi::CompletionRecord,
        recv_queue: bool,
        pool: &mut UrmaBufferPool,
    ) -> Result<()> {
        match record.event_kind {
            ffi::CompletionEventKind::FlushErrorDone => {
                return self.route_flush_done(record, recv_queue);
            }
            ffi::CompletionEventKind::SuspendDone => {
                self.stats.cqe_error += 1;
                return Err(Error::Protocol(format!(
                    "unexpected WR_SUSPEND_DONE lifecycle CQE on native object {}",
                    record.local_id
                )));
            }
            ffi::CompletionEventKind::Unknown(kind) => {
                self.stats.cqe_error += 1;
                return Err(Error::Protocol(format!(
                    "unknown URMA completion event kind {kind}"
                )));
            }
            ffi::CompletionEventKind::WorkRequest => {}
        }
        if !record.user_ctx_valid {
            self.stats.cqe_error += 1;
            return Err(Error::Completion {
                status: record.status,
                opcode: record.opcode,
                user_ctx: 0,
                sequence: None,
                post_call: None,
            });
        }
        let token = WrToken::decode(record.user_ctx)?;
        // Cross-validate the hardware-written native Jetty identity against
        // the software-written user_ctx lane before touching any WR
        // ownership. UMDK stamps local_id = jetty->jetty_id.id with
        // is_jetty=1 on both SEND and RECV CQEs of a shared-JFR Jetty
        // (udma_u_parse_cqe_for_jfc resolves source identity through the
        // Jetty table; udma_u_delete_jetty cleans the send and receive JFCs
        // by Jetty id, and udma_u_clean_jfc matches local_id against it), so
        // local_id must always map back to the token's lane. A mismatch
        // means corrupt routing identity: fail closed without retiring the
        // WR through the untrusted user_ctx; the poll error fails the fabric
        // owner via fail_pending and poison.
        if self.lane_by_jetty_id.get(&record.local_id) != Some(&token.lane_id) {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(format!(
                "CQE native Jetty {} does not belong to lane {}",
                record.local_id, token.lane_id
            )));
        }
        let retiring = self
            .retirement_by_lane
            .get(&token.lane_id)
            .is_some_and(|retirement| retirement.waiting_for_flush);
        let mut outstanding = self.take_outstanding(record.user_ctx)?;
        outstanding.handle.complete();
        let expected_recv = token.operation == OperationType::Recv;
        let registered_tx = matches!(
            outstanding.completion,
            Some(CompletionTarget::RegisteredTx(_))
        );
        let result =
            if expected_recv != recv_queue || record.is_recv != recv_queue || !record.is_jetty {
                self.stats.cqe_error += 1;
                self.decrement_operation(token.operation);
                (if registered_tx {
                    pool.complete_tx_lease_send(token.slot)
                } else {
                    pool.complete_error(token.slot, token.operation)
                        .and_then(|()| pool.release(token.slot))
                })
                .and(Err(Error::Protocol(
                    "CQE queue/operation flags disagree".into(),
                )))
            } else if record.status != 0 {
                self.stats.cqe_error += 1;
                self.decrement_operation(token.operation);
                (if registered_tx {
                    pool.complete_tx_lease_send(token.slot)
                } else {
                    pool.complete_error(token.slot, token.operation)
                        .and_then(|()| pool.release(token.slot))
                })
                .and(Err(Error::Completion {
                    status: record.status,
                    opcode: record.opcode,
                    user_ctx: record.user_ctx,
                    sequence: outstanding.sequence,
                    post_call: None,
                }))
            } else {
                (|| match token.operation {
                    OperationType::Send => {
                        self.outstanding_send -= 1;
                        self.stats.send_cqe += 1;
                        if matches!(
                            outstanding.completion,
                            Some(CompletionTarget::RegisteredTx(_))
                        ) {
                            pool.complete_tx_lease_send(token.slot)?;
                            Ok(RoutedCompletion::RegisteredTx)
                        } else {
                            pool.complete_error(token.slot, token.operation)?;
                            pool.release(token.slot)?;
                            Err(Error::Protocol(
                                "SEND CQE has no registered TX owner".into(),
                            ))
                        }
                    }
                    OperationType::Recv => {
                        self.outstanding_recv -= 1;
                        self.stats.recv_cqe += 1;
                        let imm_data = match validate_recv_immediate(record) {
                            Ok(imm_data) => imm_data,
                            Err(error) => {
                                self.stats.cqe_error += 1;
                                pool.complete_error(token.slot, token.operation)?;
                                pool.release(token.slot)?;
                                return Err(error);
                            }
                        };
                        if matches!(
                            outstanding.completion,
                            Some(CompletionTarget::RegisteredRx(_))
                        ) {
                            if let Err(error) =
                                pool.complete_recv_leased(token.slot, record.completion_len)
                            {
                                pool.complete_error(token.slot, token.operation)?;
                                pool.release(token.slot)?;
                                return Err(error);
                            }
                            let lease = match pool
                                .lease_completed_rx_window(&[(token.slot, record.completion_len)])
                            {
                                Ok(lease) => lease,
                                Err(error) => {
                                    pool.release(token.slot)?;
                                    return Err(error);
                                }
                            };
                            tracing::debug!(
                                lane_id = token.lane_id,
                                rx_slot = token.slot.index(),
                                posted_sequence = outstanding.sequence,
                                received_imm_data = imm_data,
                                "received URMA SEND_IMM completion for semantic routing"
                            );
                            Ok(RoutedCompletion::RegisteredRx(RegisteredRxCompletion {
                                lane_id: token.lane_id,
                                posted_sequence: outstanding.sequence,
                                imm_data,
                                slot: token.slot,
                                lease,
                            }))
                        } else {
                            pool.complete_error(token.slot, token.operation)?;
                            pool.release(token.slot)?;
                            Err(Error::Protocol(
                                "owned RX completion path is disabled".into(),
                            ))
                        }
                    }
                })()
            };

        let owner_error = result.as_ref().err().cloned();
        if let Some(completion) = outstanding.completion.take() {
            completion.send(result);
        }
        match owner_error {
            Some(Error::Completion { .. }) if retiring => Ok(()),
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn route_flush_done(&mut self, record: ffi::CompletionRecord, recv_queue: bool) -> Result<()> {
        if recv_queue {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(
                "WR_FLUSH_ERR_DONE arrived on the receive JFC".into(),
            ));
        }
        let lane_id = self
            .lane_by_jetty_id
            .get(&record.local_id)
            .copied()
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "WR_FLUSH_ERR_DONE references unknown native Jetty {}",
                    record.local_id
                ))
            })?;
        let retirement = self
            .retirement_by_lane
            .get_mut(&lane_id)
            .expect("native Jetty map and lane retirement map agree");
        if !retirement.waiting_for_flush {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(format!(
                "lane {lane_id} received WR_FLUSH_ERR_DONE before retirement"
            )));
        }
        retirement.flush_done = true;
        tracing::debug!(
            lane_id,
            native_jetty_id = record.local_id,
            "received URMA lane flush completion"
        );
        Ok(())
    }

    fn take_outstanding(&mut self, user_ctx: u64) -> Result<OutstandingWr> {
        let token = WrToken::decode(user_ctx)?;
        let entry = self
            .outstanding
            .get_mut(token.slot.index())
            .ok_or_else(|| Error::Protocol("CQE slot is outside outstanding table".into()))?;
        if !entry
            .as_ref()
            .is_some_and(|outstanding| outstanding.user_ctx == user_ctx)
        {
            return Err(Error::Protocol("CQE has no outstanding WR".into()));
        }
        self.outstanding_total -= 1;
        let lane_count = self
            .outstanding_by_lane
            .get_mut(&token.lane_id)
            .ok_or_else(|| Error::Protocol("CQE lane has no outstanding WR".into()))?;
        *lane_count -= 1;
        if *lane_count == 0 {
            self.outstanding_by_lane.remove(&token.lane_id);
        }
        Ok(entry.take().expect("entry checked above"))
    }

    fn decrement_operation(&mut self, operation: OperationType) {
        match operation {
            OperationType::Send => self.outstanding_send -= 1,
            OperationType::Recv => self.outstanding_recv -= 1,
        }
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding_total
    }

    pub(crate) fn outstanding_for_lane(&self, lane_id: u16) -> usize {
        self.outstanding_by_lane
            .get(&lane_id)
            .copied()
            .unwrap_or_default()
    }

    /// Wakes every logical waiter after a fatal progress failure without
    /// releasing native WR or buffer ownership. Later CQEs still retire those
    /// resources through the normal route path.
    pub(crate) fn fail_pending(&mut self, error: &Error) {
        for outstanding in self.outstanding.iter_mut().flatten() {
            if let Some(completion) = outstanding.completion.take() {
                completion.fail(error.clone());
            }
        }
    }

    pub(crate) fn stats(&self) -> CompletionStats {
        self.stats
    }
}

/// A provider poll consumes the complete batch. Route every record even when
/// one record fails, otherwise later WR ownership and buffer slots are lost.
fn drain_batch<T, E>(
    records: impl IntoIterator<Item = T>,
    mut route: impl FnMut(T) -> std::result::Result<(), E>,
) -> std::result::Result<usize, E> {
    let mut routed = 0;
    let mut first_error = None;
    for record in records {
        match route(record) {
            Ok(()) => routed += 1,
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    first_error.map_or(Ok(routed), Err)
}

pub(crate) fn deadline_after(timeout: std::time::Duration) -> Instant {
    Instant::now() + timeout
}

pub(crate) fn deadline_expired(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::buffer::{
        LeaseBook, LeaseKind, LeaseRecycleNotifier, SlotId, SlotKind, SlotState, UrmaBufferPool,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn deadline_helper_expires() {
        assert!(deadline_expired(Instant::now()));
    }

    #[test]
    fn completion_router_rejects_invalid_batch() {
        assert!(CompletionRouter::new(0).is_err());
        assert!(CompletionRouter::new(MAX_POLL_BATCH + 1).is_err());
    }

    #[test]
    fn batch_drain_routes_records_after_an_error() {
        let mut visited = Vec::new();
        let result = drain_batch(0..4, |record| {
            visited.push(record);
            if record == 1 {
                Err("first failure")
            } else if record == 2 {
                Err("later failure")
            } else {
                Ok(())
            }
        });

        assert_eq!(visited, vec![0, 1, 2, 3]);
        assert_eq!(result, Err("first failure"));
    }

    #[test]
    fn registered_completion_preserves_lease_ownership_across_oneshot() {
        let mut leases = LeaseBook::new();
        let recycle = leases
            .issue(LeaseKind::Rx, vec![SlotId::new(2, 5).unwrap()])
            .unwrap();
        let returned = Arc::new(Mutex::new(None));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| *returned.lock().unwrap() = Some(recycle))
        };
        let lease =
            RegisteredRxWindowLease::from_test_parts(vec![vec![7, 8, 9]], recycle, notifier);
        let (tx, rx) = oneshot::channel();
        CompletionTarget::RegisteredRx(tx).send(Ok(RoutedCompletion::RegisteredRx(
            RegisteredRxCompletion {
                lane_id: 4,
                posted_sequence: Some(12),
                imm_data: 12,
                slot: SlotId::new(2, 5).unwrap(),
                lease,
            },
        )));

        let completion = rx.blocking_recv().unwrap().unwrap();
        assert_eq!(completion.lane_id, 4);
        assert_eq!(completion.posted_sequence, Some(12));
        assert_eq!(completion.imm_data, 12);
        assert_eq!(completion.slot, SlotId::new(2, 5).unwrap());
        assert_eq!(completion.lease.parts().next().unwrap(), &[7, 8, 9]);
        drop(completion);
        assert_eq!(*returned.lock().unwrap(), Some(recycle));
    }

    #[test]
    fn registered_tx_window_returns_lease_only_after_every_cqe() {
        let slots = vec![SlotId::new(0, 1).unwrap(), SlotId::new(1, 1).unwrap()];
        let mut leases = LeaseBook::new();
        let recycle = leases.issue(LeaseKind::Tx, slots).unwrap();
        let returned = Arc::new(Mutex::new(None));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| *returned.lock().unwrap() = Some(recycle))
        };
        let lease = TxWindowLease::from_test_parts(vec![4, 1], recycle, notifier);
        let (tx, mut rx) = oneshot::channel();
        let state = RegisteredTxWindowState::new(7, vec![10, 11], lease, tx);
        state.posted();
        state.posted();
        state.finish_posting(None);

        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(*returned.lock().unwrap(), None);

        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        let completion = rx.blocking_recv().unwrap().unwrap();
        assert_eq!(completion.lane_id, 7);
        assert_eq!(completion.sequences, vec![10, 11]);
        assert_eq!(completion.lease.len(), 5);
        drop(completion);
        assert_eq!(*returned.lock().unwrap(), Some(recycle));
    }

    #[test]
    fn partial_post_failure_waits_only_for_the_submitted_prefix() {
        let slots = vec![
            SlotId::new(0, 1).unwrap(),
            SlotId::new(1, 1).unwrap(),
            SlotId::new(2, 1).unwrap(),
        ];
        let mut leases = LeaseBook::new();
        let recycle = leases.issue(LeaseKind::Tx, slots).unwrap();
        let returned = Arc::new(Mutex::new(None));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| *returned.lock().unwrap() = Some(recycle))
        };
        let lease = TxWindowLease::from_test_parts(vec![4, 4, 4], recycle, notifier);
        let (tx, mut rx) = oneshot::channel();
        let state = RegisteredTxWindowState::new(3, vec![20, 21, 22], lease, tx);

        // The provider accepted only the first two WRs. The unposted suffix
        // owns no CQE and must not extend the lease's completion gate.
        state.posted();
        state.posted();
        state.finish_posting(Some(Error::Protocol("partial post".into())));
        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        assert!(matches!(
            rx.blocking_recv().unwrap(),
            Err(Error::Protocol(_))
        ));
        assert_eq!(*returned.lock().unwrap(), Some(recycle));
    }

    #[test]
    fn flush_done_is_routed_by_native_jetty_id_and_gates_retirement() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_lane(7, 101, 202).unwrap();
        router.begin_lane_retirement(7).unwrap();
        assert!(router.has_pending_flush());
        assert!(!router.lane_flush_done(7));

        router
            .route_flush_done(
                ffi::CompletionRecord {
                    status: 13,
                    local_id: 101,
                    event_kind: ffi::CompletionEventKind::FlushErrorDone,
                    ..Default::default()
                },
                false,
            )
            .unwrap();

        assert!(router.lane_flush_done(7));
        assert!(!router.has_pending_flush());
        router.unregister_lane(7).unwrap();
    }

    #[test]
    fn flush_done_rejects_receive_jfc_and_unknown_native_id() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_lane(8, 303, 404).unwrap();
        router.begin_lane_retirement(8).unwrap();
        let record = ffi::CompletionRecord {
            status: 13,
            local_id: 303,
            event_kind: ffi::CompletionEventKind::FlushErrorDone,
            ..Default::default()
        };
        assert!(router.route_flush_done(record, true).is_err());
        assert!(router
            .route_flush_done(
                ffi::CompletionRecord {
                    local_id: 999,
                    ..record
                },
                false,
            )
            .is_err());
    }

    #[test]
    fn send_cqe_fails_closed_on_cross_lane_native_jetty() {
        // UMDK stamps local_id = jetty->jetty_id.id with is_jetty=1 on both
        // SEND and RECV CQEs of a shared-JFR Jetty, so a CQE whose native
        // Jetty (102) belongs to lane 2 while its user_ctx encodes lane 1
        // carries corrupt routing identity. The router must fail closed
        // without consuming the WR ownership referenced by the untrusted
        // user_ctx; the poll error then fails the fabric owner.
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_lane(1, 101, 201).unwrap();
        router.register_lane(2, 102, 202).unwrap();

        let send_ctx = WrToken {
            lane_id: 1,
            generation: 1,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        router
            .track_registered_tx(
                send_ctx,
                ffi::WrHandle::without_native(),
                7,
                RegisteredTxWindowState::new(
                    1,
                    vec![7],
                    TxWindowLease::from_test_lengths(vec![8]),
                    oneshot::channel().0,
                ),
            )
            .unwrap();

        // The pool is never consulted: the CQE is rejected before ownership
        // is touched.
        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Tx, SlotState::SendPosted)]);

        let error = router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: send_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 102,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .expect_err("cross-lane native Jetty identity must fail closed");
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        assert_eq!(router.outstanding(), 1);
        assert_eq!(router.outstanding_for_lane(1), 1);
    }

    #[test]
    fn recv_cqe_fails_closed_on_cross_lane_native_jetty() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_lane(1, 101, 201).unwrap();
        router.register_lane(2, 102, 202).unwrap();

        let recv_ctx = WrToken {
            lane_id: 1,
            generation: 1,
            operation: OperationType::Recv,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        router
            .track_registered_rx(
                recv_ctx,
                ffi::WrHandle::without_native(),
                None,
                oneshot::channel().0,
            )
            .unwrap();

        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Rx, SlotState::PostedRecv)]);

        let error = router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: recv_ctx,
                    user_ctx_valid: true,
                    is_recv: true,
                    is_jetty: true,
                    local_id: 102,
                    ..Default::default()
                },
                true,
                &mut pool,
            )
            .expect_err("cross-lane native Jetty identity must fail closed");
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        assert_eq!(router.outstanding(), 1);
        assert_eq!(router.outstanding_for_lane(1), 1);
    }

    #[test]
    fn send_cqe_routes_when_native_jetty_matches_token_lane() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_lane(1, 101, 201).unwrap();
        router.register_lane(2, 102, 202).unwrap();

        let send_ctx = WrToken {
            lane_id: 1,
            generation: 1,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        router
            .track_registered_tx(
                send_ctx,
                ffi::WrHandle::without_native(),
                7,
                RegisteredTxWindowState::new(
                    1,
                    vec![7],
                    TxWindowLease::from_test_lengths(vec![8]),
                    oneshot::channel().0,
                ),
            )
            .unwrap();

        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Tx, SlotState::SendPosted)]);

        router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: send_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .expect("matching native Jetty identity must route");
        assert_eq!(router.outstanding(), 0);
    }

    #[test]
    fn send_imm_receive_identity_preserves_full_64_bits() {
        let identity = 0xfedc_ba98_7654_3210;
        let record = ffi::CompletionRecord {
            opcode: ffi::CR_OPCODE_SEND_WITH_IMM,
            imm_data: identity,
            imm_data_valid: true,
            ..Default::default()
        };
        assert_eq!(validate_recv_immediate(record), Ok(identity));
    }

    #[test]
    fn ordinary_send_or_invalid_immediate_flag_is_rejected() {
        let ordinary_send = ffi::CompletionRecord {
            // shim.c statically verifies UMDK's ordinary SEND CQE opcode is 0.
            opcode: 0,
            imm_data: 7,
            imm_data_valid: false,
            ..Default::default()
        };
        assert!(validate_recv_immediate(ordinary_send).is_err());

        let invalid_flag = ffi::CompletionRecord {
            opcode: ffi::CR_OPCODE_SEND_WITH_IMM,
            imm_data: 7,
            imm_data_valid: false,
            ..Default::default()
        };
        assert!(validate_recv_immediate(invalid_flag).is_err());
    }
}
