use super::{ffi, native_error, Error, Result};
use std::time::Instant;
/// Owner-loop hook for READ CQEs sharing the send JFC. Implementations route
/// by a separately reserved user_ctx namespace and retain native WR ownership.
pub(crate) trait ReadCompletionSink {
    fn outstanding_read_completions(&self) -> usize;
    fn try_route_read_completion(
        &mut self,
        record: ffi::CompletionRecord,
        recv_queue: bool,
    ) -> Option<Result<()>>;
}
const MAX_POLL_BATCH: usize = 16;
#[derive(Default)]
struct CompletionStats {
    poll_calls: u64,
    empty_polls: u64,
    cqe_error: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointLifecycle {
    jetty_id: u32,
    waiting_for_flush: bool,
    flush_done: bool,
}
/// The sole consumer of READ CQEs and endpoint flush notifications.
pub(crate) struct CompletionRouter {
    batch: usize,
    endpoint: Option<EndpointLifecycle>,
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
            endpoint: None,
            stats: CompletionStats::default(),
        })
    }
    pub(crate) fn endpoint_ready_to_close(&self) -> bool {
        self.endpoint
            .as_ref()
            .is_none_or(|endpoint| !endpoint.waiting_for_flush || endpoint.flush_done)
    }
    pub(crate) fn outstanding_with_read<R: ReadCompletionSink>(&self, read: &R) -> usize {
        read.outstanding_read_completions()
    }

    pub(crate) fn register_endpoint(&mut self, jetty_id: u32) -> Result<()> {
        if self.endpoint.is_some() {
            return Err(Error::Protocol(
                "the shared RM endpoint is already registered".into(),
            ));
        }
        self.endpoint = Some(EndpointLifecycle {
            jetty_id,
            waiting_for_flush: false,
            flush_done: false,
        });
        Ok(())
    }
    /// Fatal escalation for the whole shared endpoint (shutdown timeout or
    /// process teardown): forces every stranded WR to complete with an error.
    pub(crate) fn begin_endpoint_flush(&mut self) -> bool {
        match self.endpoint.as_mut() {
            Some(endpoint) if !endpoint.waiting_for_flush => {
                endpoint.waiting_for_flush = true;
                true
            }
            _ => false,
        }
    }

    fn has_pending_flush(&self) -> bool {
        self.endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.waiting_for_flush && !endpoint.flush_done)
    }
    /// READ-only progress path. No registered SEND/RECV buffer pool exists in
    /// this mode, so every ordinary WR CQE must be consumed by the READ sink.
    pub(crate) fn poll_read_only<R: ReadCompletionSink>(
        &mut self,
        send_jfc: &ffi::JfcHandle,
        read: &mut R,
    ) -> Result<usize> {
        self.stats.poll_calls += 1;
        let completed = if read.outstanding_read_completions() != 0 || self.has_pending_flush() {
            let mut records = [ffi::CompletionRecord::default(); MAX_POLL_BATCH];
            let count = send_jfc
                .poll_into(&mut records[..self.batch])
                .map_err(|error| native_error("poll_read_jfc", error))?;
            drain_batch(records.into_iter().take(count), |record| {
                if let Some(result) = read.try_route_read_completion(record, false) {
                    return result;
                }
                match record.event_kind {
                    ffi::CompletionEventKind::FlushErrorDone => {
                        self.route_flush_done(record, false)
                    }
                    ffi::CompletionEventKind::SuspendDone => Err(Error::Protocol(format!(
                        "unexpected WR_SUSPEND_DONE lifecycle CQE on native object {}",
                        record.local_id
                    ))),
                    ffi::CompletionEventKind::Unknown(kind) => Err(Error::Protocol(format!(
                        "unknown URMA completion event kind {kind}"
                    ))),
                    ffi::CompletionEventKind::WorkRequest => Err(Error::Protocol(format!(
                        "non-READ work-request CQE in READ-only mode: user_ctx={}",
                        record.user_ctx
                    ))),
                }
            })?
        } else {
            0
        };
        if completed == 0 {
            self.stats.empty_polls += 1;
            std::hint::spin_loop();
        }
        Ok(completed)
    }

    fn route_flush_done(&mut self, record: ffi::CompletionRecord, recv_queue: bool) -> Result<()> {
        if recv_queue {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(
                "WR_FLUSH_ERR_DONE arrived on the receive JFC".into(),
            ));
        }
        let endpoint = self.endpoint.as_mut().ok_or_else(|| {
            Error::Protocol("WR_FLUSH_ERR_DONE arrived without a shared RM endpoint".into())
        })?;
        if endpoint.jetty_id != record.local_id {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(format!(
                "WR_FLUSH_ERR_DONE references unknown native Jetty {}",
                record.local_id
            )));
        }
        if !endpoint.waiting_for_flush {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(
                "shared RM endpoint received WR_FLUSH_ERR_DONE before retirement".into(),
            ));
        }
        endpoint.flush_done = true;
        tracing::debug!(
            native_jetty_id = record.local_id,
            "received URMA shared endpoint flush completion"
        );
        Ok(())
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
    #[test]
    fn flush_done_requires_endpoint_retirement_and_known_jetty() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(303).unwrap();
        let record = ffi::CompletionRecord {
            status: 13,
            local_id: 303,
            event_kind: ffi::CompletionEventKind::FlushErrorDone,
            ..Default::default()
        };
        // Without an armed endpoint flush, the lifecycle CQE must be rejected.
        assert!(router.route_flush_done(record, false).is_err());
        router.begin_endpoint_flush();
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
        assert!(!router.endpoint_ready_to_close());
        assert!(router.has_pending_flush());
        router.route_flush_done(record, false).unwrap();
        assert!(!router.has_pending_flush());
        assert!(router.endpoint_ready_to_close());
        assert!(!router.begin_endpoint_flush());
    }
}
