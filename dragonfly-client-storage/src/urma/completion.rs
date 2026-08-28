use super::{
    buffer::{ReceivedChunk, UrmaBufferPool},
    ffi,
    lane::{OperationType, WrToken},
    native_error, Error, Result,
};
use std::{collections::HashMap, time::Instant};
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

/// A completion already routed to its owning lane. No native handle leaves the
/// fabric thread.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LaneCompletion {
    Sent {
        lane_id: u16,
        sequence: Option<u64>,
    },
    Received {
        lane_id: u16,
        sequence: Option<u64>,
        chunk: ReceivedChunk,
    },
}

pub(crate) type OperationCompletionTx = oneshot::Sender<Result<LaneCompletion>>;

struct OutstandingWr {
    user_ctx: u64,
    handle: ffi::WrHandle,
    sequence: Option<u64>,
    completion: Option<OperationCompletionTx>,
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
            stats: CompletionStats::default(),
        })
    }

    pub(crate) fn track(
        &mut self,
        user_ctx: u64,
        handle: ffi::WrHandle,
        sequence: Option<u64>,
        completion: OperationCompletionTx,
    ) -> Result<()> {
        let token = WrToken::decode(user_ctx)?;
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
            completion: Some(completion),
        });
        self.outstanding_total += 1;
        *self.outstanding_by_lane.entry(token.lane_id).or_default() += 1;
        match token.operation {
            OperationType::Send => {
                self.outstanding_send += 1;
                self.stats.send_post += 1;
            }
            OperationType::Recv => {
                self.outstanding_recv += 1;
                self.stats.recv_post += 1;
            }
        }
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
        if self.outstanding_send != 0 {
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
        let mut outstanding = self.take_outstanding(record.user_ctx)?;
        outstanding.handle.complete();
        let expected_recv = token.operation == OperationType::Recv;
        let result =
            if expected_recv != recv_queue || record.is_recv != recv_queue || !record.is_jetty {
                self.stats.cqe_error += 1;
                self.decrement_operation(token.operation);
                pool.complete_error(token.slot, token.operation)
                    .and_then(|()| pool.release(token.slot))
                    .and(Err(Error::Protocol(
                        "CQE queue/operation flags disagree".into(),
                    )))
            } else if record.status != 0 {
                self.stats.cqe_error += 1;
                self.decrement_operation(token.operation);
                pool.complete_error(token.slot, token.operation)
                    .and_then(|()| pool.release(token.slot))
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
                        pool.complete_send(token.slot)?;
                        pool.release(token.slot)?;
                        Ok(LaneCompletion::Sent {
                            lane_id: token.lane_id,
                            sequence: outstanding.sequence,
                        })
                    }
                    OperationType::Recv => {
                        self.outstanding_recv -= 1;
                        self.stats.recv_cqe += 1;
                        if record.opcode != 0 {
                            self.stats.cqe_error += 1;
                            pool.complete_error(token.slot, token.operation)?;
                            pool.release(token.slot)?;
                            return Err(Error::Protocol(format!(
                                "unexpected receive CQE opcode {}",
                                record.opcode
                            )));
                        }
                        let chunk = pool.complete_recv(token.slot, record.completion_len)?;
                        pool.release(token.slot)?;
                        Ok(LaneCompletion::Received {
                            lane_id: token.lane_id,
                            sequence: outstanding.sequence,
                            chunk,
                        })
                    }
                })()
            };

        let owner_error = result.as_ref().err().cloned();
        if let Some(completion) = outstanding.completion.take() {
            let _ = completion.send(result);
        }
        owner_error.map_or(Ok(()), Err)
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
                let _ = completion.send(Err(error.clone()));
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
}
