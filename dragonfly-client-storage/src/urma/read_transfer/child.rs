//! Child-side RM READ transfer of one Piece.
//!
//! Drains READ work and the remote import before publishing the destination
//! lease. Storage consumption and recycle remain separate lifecycle stages;
//! failure and cancellation retain owners whenever cleanup cannot prove release.

use super::protocol;
use crate::urma::{
    fabric::UrmaFabricHandle,
    ffi::read::{ReadDescriptor, ReadToken},
    read_child_owner::{ReadChildUpdate, ReadCompletionTiming},
    read_control::ReadTransferControl,
    read_handoff::ResourceGuard,
    read_protocol::{
        ChildAction, ChildReadState, ReadFrame, ReadPieceLocator, ReadSegmentOffer,
        ReadTransferIdentity,
    },
    runtime::{
        ReadChildAdmission, ReadChildId, ReadChildProgress, ReadChildRequest, ReadLeaseSpan,
    },
    Error, Result,
};
use tokio::time::{timeout_at, Duration, Instant};
use tracing::debug;

async fn until<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    timeout_at(deadline, future)
        .await
        .map_err(|_| protocol("Child READ transfer deadline expired"))?
}

fn native_descriptor(offer: &ReadSegmentOffer) -> (ReadDescriptor, ReadToken) {
    (
        ReadDescriptor {
            version: offer.descriptor_version,
            eid: offer.eid,
            uasid: offer.uasid,
            va: offer.va,
            length: offer.length,
            token_id: offer.token_id,
            access: offer.access,
            token_policy: offer.token_policy,
        },
        ReadToken::new(offer.token),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadTransportResult {
    pub(crate) completed_bytes: u64,
    pub(crate) read_wr_count: u64,
    pub(crate) read_post_batch_count: u64,
    pub(crate) progress_query_count: u64,
    pub(crate) progress_query_ns: u64,
    pub(crate) post_command_ns: u64,
    pub(crate) poll_sleep_ns: u64,
    pub(crate) progress_subscribe_ns: u64,
    pub(crate) progress_notification_count: u64,
    pub(crate) progress_wait_ns: u64,
    pub(crate) completion_notification_delay_ns: u64,
    pub(crate) cqe_to_observed_ns: u64,
    pub(crate) native: ReadCompletionTiming,
}

/// A published destination lease awaiting Storage consumption. The CPU span is
/// final READ content; the caller must consume it and then recycle the lease
/// through [`UrmaFabricHandle::recycle_published_child_lease`] to close the
/// buffer and release the transfer budget.
pub(crate) struct PublishedChildLease {
    pub(crate) child_id: ReadChildId,
    pub(crate) span: ReadLeaseSpan,
    pub(crate) guard: ResourceGuard,
}

/// Success outcome of the Child transport adapter including the published
/// destination lease. `piece_offset` echoes the Parent's Piece metadata so
/// the caller can commit the download position without a metadata frame, and
/// `digest` carries the Parent's Piece digest for the local integrity check.
pub(crate) struct ChildTransportSuccess {
    pub(crate) completed_bytes: u64,
    pub(crate) read_wr_count: u64,
    pub(crate) read_post_batch_count: u64,
    pub(crate) piece_offset: u64,
    pub(crate) digest: String,
    pub(crate) lease: PublishedChildLease,
    pub(crate) timing: ChildTransportTiming,
}

/// Child-side successful-path timing. These stages are observational and do
/// not participate in protocol or owner-lifetime decisions.
///
/// native_read_envelope_ns (logged from native.envelope_ns()) brackets the
/// first native shim post call and the JFC poll returning the last matched CQE.
/// It includes native setup, DMA/network work, owner scheduling and polling;
/// it is not wire time. native_post_to_cqe_sum_ns sums per-WR intervals, which
/// may overlap. cqe_to_observed_ns covers the last poll return through routing,
/// notification and the async driver's observation of success.
///
/// post_admission_wait_ns covers acquiring a Fabric command slot;
/// post_queue_wait_ns covers enqueue to owner dispatch. post_command_ns also
/// includes execution and async reply scheduling, so these fields overlap.
/// progress_wait_ns measures awaiting changes (including DMA time), not CPU
/// overhead. Legacy progress_query_* and poll_sleep_ns remain zero on this
/// path; progress_subscribe_ns measures its one initial subscription command.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChildTransportTiming {
    pub(crate) buffer_ready_send_ns: u64,
    pub(crate) segment_offer_wait_ns: u64,
    pub(crate) destination_admission_ns: u64,
    pub(crate) read_completion_ns: u64,
    pub(crate) progress_query_count: u64,
    pub(crate) progress_query_ns: u64,
    pub(crate) post_command_ns: u64,
    pub(crate) poll_sleep_ns: u64,
    pub(crate) progress_subscribe_ns: u64,
    pub(crate) progress_notification_count: u64,
    pub(crate) progress_wait_ns: u64,
    pub(crate) completion_notification_delay_ns: u64,
    pub(crate) cqe_to_observed_ns: u64,
    pub(crate) native: ReadCompletionTiming,
    pub(crate) lease_publish_ns: u64,
    pub(crate) read_done_send_ns: u64,
    pub(crate) done_wait_ns: u64,
    pub(crate) done_round_trip_ns: u64,
}

/// Failure outcome of the Child transport adapter. `retained_child` is set
/// only when the native Child owner could not be proven fully drained and
/// closed: the caller must keep this id for a later cleanup owner pass and
/// must not treat the transfer budget as released.
pub(crate) struct ChildTransportFailure {
    pub(crate) error: Error,
    pub(crate) retained_child: Option<RetainedChildOwner>,
}

/// Identifies which cleanup operation can safely retry a retained Child. A
/// published lease must be recycled; the generic cleanup path intentionally
/// refuses to close it because a Storage consumer may still hold its span.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RetainedChildOwner {
    Cleanup(ReadChildId),
    PublishedLease(ReadChildId),
}

impl RetainedChildOwner {
    pub(crate) fn id(self) -> ReadChildId {
        match self {
            Self::Cleanup(id) | Self::PublishedLease(id) => id,
        }
    }
}

/// Best-effort extraction of a matched drain declaration from the last
/// observed Child progress. Counts are only usable when the accepted and
/// retired WR counts are already equal; otherwise no CancelDrained may be
/// sent.
fn drainable_wr_counts(progress: Option<ReadChildProgress>) -> Option<(u64, u64)> {
    progress
        .filter(|progress| progress.accepted_wr_count == progress.retired_wr_count)
        .map(|progress| (progress.accepted_wr_count, progress.retired_wr_count))
}

pub(crate) struct ChildTransfer {
    fabric: UrmaFabricHandle,
    lane_id: u16,
    control: ReadTransferControl,
    state: ChildReadState,
    identity: ReadTransferIdentity,
    request: ReadPieceLocator,
    piece_length: u64,
    allocation_bytes: u64,
    max_outstanding: usize,
    completion_timeout: Duration,
    deadline: Instant,
    child_guard: Option<ResourceGuard>,
}

impl ChildTransfer {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        fabric: UrmaFabricHandle,
        lane_id: u16,
        control: ReadTransferControl,
        identity: ReadTransferIdentity,
        request: ReadPieceLocator,
        piece_length: u64,
        allocation_bytes: u64,
        max_read_size: u32,
        max_outstanding: usize,
        completion_timeout: Duration,
    ) -> Result<Self> {
        if control.identity() != identity
            || allocation_bytes < piece_length
            || max_outstanding == 0
            || completion_timeout.is_zero()
        {
            return Err(protocol("invalid Child READ session configuration"));
        }
        request.validate()?;
        Ok(Self {
            fabric,
            lane_id,
            control,
            state: ChildReadState::new(identity, piece_length, max_read_size)?,
            identity,
            request,
            piece_length,
            allocation_bytes,
            max_outstanding,
            completion_timeout,
            deadline: Instant::now() + completion_timeout,
            child_guard: None,
        })
    }

    pub(crate) fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = deadline;
        self
    }

    /// Runs one Piece through READ and terminal control, then publishes the
    /// destination lease. No implicit native release happens here: the caller
    /// owns the lease handoff and must recycle it after Storage consumption.
    ///
    /// On failure the adapter runs the cooperative cancel exchange and a
    /// cleanup-only retirement. `ChildTransportFailure::retained_child` is set
    /// only when that retirement could not prove a full drain/close; the id
    /// then stays valid for a later cleanup owner pass. A lease published
    /// before a late failure keeps its owner retained as well: the buffer
    /// content is already final, so the caller may still consume and recycle
    /// it through the retained id. Dropping the future without running this
    /// path keeps the native owner retained in the registry (fail closed) but
    /// skips the wire cancel exchange.
    ///
    /// # Safety
    /// The caller must bind this lane/identity to an authenticated handshake and
    /// guarantee exclusive ownership of the destination Piece allocation.
    pub(crate) async unsafe fn run_transport_only(
        mut self,
    ) -> std::result::Result<ChildTransportSuccess, ChildTransportFailure> {
        // SAFETY: The method contract supplies authenticated identity and
        // exclusive destination ownership.
        match self.run_inner().await {
            Ok((result, segment_generation, piece_offset, digest, lease, timing)) => {
                self.control
                    .finish(Some(segment_generation))
                    .map_err(|error| ChildTransportFailure {
                        error,
                        retained_child: Some(RetainedChildOwner::PublishedLease(lease.child_id)),
                    })?;
                Ok(ChildTransportSuccess {
                    completed_bytes: result.completed_bytes,
                    read_wr_count: result.read_wr_count,
                    read_post_batch_count: result.read_post_batch_count,
                    piece_offset,
                    digest,
                    lease,
                    timing,
                })
            }
            Err((error, child_id)) => Err(self.cancel_after_failure(child_id, error).await),
        }
    }

    /// Normal path. Errors carry the still-existing native Child id so the
    /// cancel/cleanup path can address it; `None` means no owner exists or it
    /// was already fully closed. Success additionally returns the terminal
    /// segment generation, the Parent's Piece offset, and the published
    /// destination lease so the owning call can finish the control route and
    /// hand the lease to Storage.
    async fn run_inner(
        &mut self,
    ) -> std::result::Result<
        (
            ReadTransportResult,
            u64,
            u64,
            String,
            PublishedChildLease,
            ChildTransportTiming,
        ),
        (Error, Option<RetainedChildOwner>),
    > {
        let mut timing = ChildTransportTiming::default();
        let stage_start = Instant::now();
        until(
            self.deadline,
            self.control.send(ReadFrame::BufferReady {
                identity: self.identity,
                accepted_length: self.piece_length,
                request: self.request.clone(),
            }),
        )
        .await
        .map_err(|error| (error, None))?;
        timing.buffer_ready_send_ns = stage_start.elapsed().as_nanos() as u64;
        let stage_start = Instant::now();
        let frame = until(self.deadline, self.control.receive())
            .await
            .map_err(|error| (error, None))?;
        timing.segment_offer_wait_ns = stage_start.elapsed().as_nanos() as u64;
        if self.state.on_frame(&frame).map_err(|error| (error, None))? != ChildAction::StartRead {
            return Err((
                protocol("Child did not receive a usable SegmentOffer"),
                None,
            ));
        }
        let ReadFrame::SegmentOffer { offer, .. } = frame else {
            return Err((protocol("Child expected SegmentOffer"), None));
        };
        let max_read_size = offer.effective_max_read_size;
        let piece_offset = offer.piece_offset;
        let digest = offer.digest.clone();
        let (descriptor, token) = native_descriptor(&offer);
        // SAFETY: The method contract supplies authenticated identity and
        // exclusive destination ownership; the state machine validated Offer.
        let stage_start = Instant::now();
        let admission = until(self.deadline, unsafe {
            self.fabric.create_read_child(ReadChildRequest {
                peer_id: self.lane_id,
                allocation_bytes: self.allocation_bytes,
                piece_length: self.piece_length,
                max_outstanding: self.max_outstanding,
                descriptor,
                token,
            })
        })
        .await;
        timing.destination_admission_ns = stage_start.elapsed().as_nanos() as u64;
        let child_id = match admission {
            Ok(ReadChildAdmission::Ready(id)) => id,
            Ok(ReadChildAdmission::Quarantined { id, error }) => {
                self.child_guard = Some(self.fabric.child_guard(id));
                return Err((error, Some(RetainedChildOwner::Cleanup(id))));
            }
            Err(error) => return Err((error, None)),
        };
        self.child_guard = Some(self.fabric.child_guard(child_id));
        let stage_start = Instant::now();
        let result = match self.drive_reads(child_id, max_read_size).await {
            Ok(result) => result,
            Err(error) => return Err((error, Some(RetainedChildOwner::Cleanup(child_id)))),
        };
        timing.read_completion_ns = stage_start.elapsed().as_nanos() as u64;
        timing.progress_query_count = result.progress_query_count;
        timing.progress_query_ns = result.progress_query_ns;
        timing.post_command_ns = result.post_command_ns;
        timing.poll_sleep_ns = result.poll_sleep_ns;
        timing.progress_subscribe_ns = result.progress_subscribe_ns;
        timing.progress_notification_count = result.progress_notification_count;
        timing.progress_wait_ns = result.progress_wait_ns;
        timing.completion_notification_delay_ns = result.completion_notification_delay_ns;
        timing.cqe_to_observed_ns = result.cqe_to_observed_ns;
        timing.native = result.native;
        debug!(
            task_id = %self.request.task_id,
            piece_number = self.request.piece_number,
            transfer_id = self.identity.transfer_id,
            completed_bytes = result.completed_bytes,
            read_wr_count = result.read_wr_count,
            read_post_batch_count = result.read_post_batch_count,
            read_completion_ns = timing.read_completion_ns,
            progress_query_count = timing.progress_query_count,
            progress_query_ns = timing.progress_query_ns,
            post_command_ns = timing.post_command_ns,
            poll_sleep_ns = timing.poll_sleep_ns,
            progress_subscribe_ns = timing.progress_subscribe_ns,
            progress_notification_count = timing.progress_notification_count,
            progress_wait_ns = timing.progress_wait_ns,
            completion_notification_delay_ns = timing.completion_notification_delay_ns,
            cqe_to_observed_ns = timing.cqe_to_observed_ns,
            native_timed_wr_count = timing.native.native_timed_wr_count,
            native_post_call_ns = timing.native.native_post_call_ns,
            native_post_to_cqe_sum_ns = timing.native.native_post_to_cqe_sum_ns,
            native_post_to_cqe_max_ns = timing.native.native_post_to_cqe_max_ns,
            native_read_envelope_ns = timing.native.envelope_ns(),
            post_admission_wait_ns = timing.native.post_admission_wait_ns,
            post_queue_wait_ns = timing.native.post_queue_wait_ns,
            "urma READ child completed data transfer"
        );
        // Lease flow stage 1: stop posting and close the import while keeping
        // the registered destination buffer and the full budget charge.
        let stage_start = Instant::now();
        if let Err(error) = until(
            self.deadline,
            self.fabric.drain_read_child_for_lease(child_id),
        )
        .await
        {
            return Err((error, Some(RetainedChildOwner::Cleanup(child_id))));
        }
        // Stage 2: extract the CPU span of the final READ content. The lease
        // itself stays on the native owner thread until the caller recycles.
        let span = match until(
            self.deadline,
            self.fabric.publish_read_child_lease(child_id),
        )
        .await
        {
            Ok(span) => span,
            Err(error) => return Err((error, Some(RetainedChildOwner::Cleanup(child_id)))),
        };
        timing.lease_publish_ns = stage_start.elapsed().as_nanos() as u64;
        // From here the destination lease is published; later failures keep
        // the owner retained (the content is final) and only abandon the
        // control exchange.
        let action = match self
            .state
            .read_finished(result.completed_bytes, result.read_wr_count)
        {
            Ok(ChildAction::SendReadDone { segment_generation }) => segment_generation,
            Ok(_) | Err(_) => {
                return Err((
                    protocol("Child READ completion produced an invalid action"),
                    Some(RetainedChildOwner::PublishedLease(child_id)),
                ))
            }
        };
        let stage_start = Instant::now();
        if let Err(error) = until(
            self.deadline,
            self.control.send(ReadFrame::ReadDone {
                identity: self.identity,
                segment_generation: action,
                completed_length: result.completed_bytes,
                read_wr_count: result.read_wr_count,
            }),
        )
        .await
        {
            return Err((error, Some(RetainedChildOwner::PublishedLease(child_id))));
        }
        timing.read_done_send_ns = stage_start.elapsed().as_nanos() as u64;
        let done_wait_start = Instant::now();
        let terminal = match until(self.deadline, self.control.receive()).await {
            Ok(terminal) => terminal,
            Err(error) => return Err((error, Some(RetainedChildOwner::PublishedLease(child_id)))),
        };
        timing.done_wait_ns = done_wait_start.elapsed().as_nanos() as u64;
        if self
            .state
            .on_frame(&terminal)
            .map_err(|error| (error, Some(RetainedChildOwner::PublishedLease(child_id))))?
            != ChildAction::Complete
        {
            return Err((
                protocol("Child expected Done after ReadDone"),
                Some(RetainedChildOwner::PublishedLease(child_id)),
            ));
        }
        timing.done_round_trip_ns = stage_start.elapsed().as_nanos() as u64;
        Ok((
            result,
            action,
            piece_offset,
            digest,
            PublishedChildLease {
                child_id,
                span,
                guard: self.child_guard.take().expect("published child guard"),
            },
            timing,
        ))
    }

    /// Cancel/cleanup path for a failed transport attempt. The wire exchange
    /// is best-effort: the native cleanup decision never depends on it. The
    /// owner is retained only when `retire_read_child_for_cleanup` could not
    /// prove a full drain and close.
    async fn cancel_after_failure(
        mut self,
        child: Option<RetainedChildOwner>,
        error: Error,
    ) -> ChildTransportFailure {
        let cleanup_deadline = Instant::now() + self.completion_timeout.min(Duration::from_secs(1));
        let Some(child) = child else {
            return ChildTransportFailure {
                error,
                retained_child: None,
            };
        };
        if let RetainedChildOwner::PublishedLease(child_id) = child {
            let retained_child = match until(
                cleanup_deadline,
                self.fabric.recycle_published_child_lease(child_id),
            )
            .await
            {
                Ok(true) => None,
                Ok(false) | Err(_) => Some(child),
            };
            return ChildTransportFailure {
                error,
                retained_child,
            };
        }
        let child_id = child.id();
        // The state machine is in Reading(generation) whenever a native Child
        // exists. A failed transition skips only the wire exchange, never the
        // local cleanup below.
        let generation = match self.state.cancel() {
            Ok(ChildAction::SendCancel {
                segment_generation: Some(generation),
            }) => Some(generation),
            _ => None,
        };
        if let Some(generation) = generation {
            let _ = until(
                cleanup_deadline,
                self.control.send(ReadFrame::Cancel {
                    identity: self.identity,
                    segment_generation: Some(generation),
                    reason: "child READ transport failure".into(),
                }),
            )
            .await;
        }
        let counts = match until(cleanup_deadline, self.fabric.read_child_progress(child_id)).await
        {
            Ok(progress) => drainable_wr_counts(Some(progress)),
            Err(_) => None,
        };
        let drained = until(
            cleanup_deadline,
            self.fabric.retire_read_child_for_cleanup(child_id),
        )
        .await;
        let drained = match drained {
            Ok(true) => true,
            Ok(false) | Err(_) => false,
        };
        if !drained {
            return ChildTransportFailure {
                error,
                retained_child: Some(RetainedChildOwner::Cleanup(child_id)),
            };
        }
        if let (Some(published_generation), Some((accepted, retired))) = (generation, counts) {
            if let Ok(ChildAction::SendCancelDrained {
                segment_generation: Some(wire_generation),
            }) = self.state.import_drained(accepted, retired)
            {
                if wire_generation == published_generation
                    && until(
                        cleanup_deadline,
                        self.control.send(ReadFrame::CancelDrained {
                            identity: self.identity,
                            segment_generation: Some(wire_generation),
                            accepted_wr_count: accepted,
                            retired_wr_count: retired,
                        }),
                    )
                    .await
                    .is_ok()
                {
                    let cancelled = until(cleanup_deadline, self.control.receive()).await;
                    if let Ok(frame) = cancelled {
                        if matches!(self.state.on_frame(&frame), Ok(ChildAction::Cancelled)) {
                            let _ = self.control.finish(Some(wire_generation));
                        }
                    }
                }
            }
        }
        // The native owner is proven closed, but the wire terminal may have
        // been abandoned. Dropping the control tombstones the lane and the
        // Parent keeps its export until its own fail-closed cleanup.
        ChildTransportFailure {
            error,
            retained_child: None,
        }
    }

    async fn drive_reads(
        &self,
        child_id: ReadChildId,
        max_read_size: u32,
    ) -> Result<ReadTransportResult> {
        let deadline = self.deadline;
        let subscribe_start = Instant::now();
        let progress = timeout_at(
            deadline,
            self.fabric.subscribe_read_child_progress(child_id),
        )
        .await
        .map_err(|_| protocol("Child READ completion deadline expired"))??;
        let subscribe_ns = subscribe_start.elapsed().as_nanos() as u64;
        drive_read_notifications(
            progress,
            self.piece_length,
            self.max_outstanding,
            max_read_size,
            deadline,
            subscribe_ns,
            |lengths| self.fabric.post_read_child_batch(child_id, lengths),
        )
        .await
    }
}

/// Progress snapshots remain in the watch channel even when a post/CQE happens
/// before the waiter runs. Notification Drop only cancels interest, never DMA.
async fn drive_read_notifications<F, Fut>(
    mut updates: tokio::sync::watch::Receiver<ReadChildUpdate>,
    piece_length: u64,
    max_outstanding: usize,
    max_read_size: u32,
    deadline: Instant,
    progress_subscribe_ns: u64,
    mut post: F,
) -> Result<ReadTransportResult>
where
    F: FnMut(Vec<u32>) -> Fut,
    Fut: std::future::Future<Output = Result<usize>>,
{
    let mut read_post_batch_count = 0u64;
    let mut post_command_ns = 0u64;
    let mut progress_notification_count = 0u64;
    let mut progress_wait_ns = 0u64;
    loop {
        if Instant::now() >= deadline {
            return Err(protocol("Child READ completion deadline expired"));
        }
        let update = *updates.borrow_and_update();
        let observed_at = std::time::Instant::now();
        let progress = update.progress;
        validate_progress(progress, piece_length)?;
        if update.interrupted || progress.failed {
            return Err(protocol("native Child READ failed or interrupted"));
        }
        if progress.read_succeeded {
            return Ok(ReadTransportResult {
                completed_bytes: progress.retired_bytes,
                read_wr_count: progress.retired_wr_count,
                read_post_batch_count,
                // Kept for existing log consumers; there are no polling queries
                // or deliberate sleeps on the event-driven path.
                progress_query_count: 0,
                progress_query_ns: 0,
                post_command_ns,
                poll_sleep_ns: 0,
                progress_subscribe_ns,
                progress_notification_count,
                progress_wait_ns,
                completion_notification_delay_ns: observed_at
                    .saturating_duration_since(update.notified_at)
                    .as_nanos() as u64,
                cqe_to_observed_ns: update.timing.last_cqe_at.map_or(0, |at| {
                    observed_at.saturating_duration_since(at).as_nanos() as u64
                }),
                native: update.timing,
            });
        }
        if progress.posting_stopped {
            return Err(protocol("Child READ posting stopped before success"));
        }
        let available = max_outstanding.saturating_sub(progress.outstanding_wr_count);
        let mut remaining = piece_length - progress.accepted_bytes;
        let remaining_wr_count = remaining.div_ceil(u64::from(max_read_size));
        let mut lengths = Vec::with_capacity(
            available.min(usize::try_from(remaining_wr_count).unwrap_or(usize::MAX)),
        );
        for _ in 0..available {
            if remaining == 0 {
                break;
            }
            let length = remaining.min(u64::from(max_read_size)) as u32;
            lengths.push(length);
            remaining -= u64::from(length);
        }
        if !lengths.is_empty() {
            let batch_length = lengths.len();
            let post_start = Instant::now();
            let posted = timeout_at(deadline, post(lengths))
                .await
                .map_err(|_| protocol("Child READ completion deadline expired"))??;
            post_command_ns =
                post_command_ns.saturating_add(post_start.elapsed().as_nanos() as u64);
            if posted > batch_length {
                return Err(protocol("inconsistent READ post batch result"));
            }
            // A shared peer/JFS credit limit may admit only a prefix or none.
            // Retry from accepted_bytes after the owner's next notification.
            if posted != 0 {
                read_post_batch_count += 1;
            }
        }
        // The owner publishes accepted progress before replying to post. changed()
        // sees that update even if it was sent before this await, then later sees
        // CQE progress. Zero posts wait for capacity notifications, including
        // CQEs of other owners sharing credits. No polling query is sent.
        let wait_start = Instant::now();
        timeout_at(deadline, updates.changed())
            .await
            .map_err(|_| protocol("Child READ completion deadline expired"))?
            .map_err(|_| protocol("Child READ progress notification closed"))?;
        progress_wait_ns = progress_wait_ns.saturating_add(wait_start.elapsed().as_nanos() as u64);
        progress_notification_count += 1;
    }
}

fn validate_progress(progress: ReadChildProgress, piece_length: u64) -> Result<()> {
    if progress.piece_length != piece_length
        || progress.accepted_bytes > piece_length
        || progress.retired_bytes > progress.accepted_bytes
        || progress.retired_wr_count > progress.accepted_wr_count
        || progress.outstanding_wr_count
            != usize::try_from(progress.accepted_wr_count - progress.retired_wr_count)
                .unwrap_or(usize::MAX)
    {
        return Err(protocol("inconsistent Child READ progress"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_progress(accepted: u64, retired: u64) -> ReadChildUpdate {
        ReadChildUpdate {
            progress: ReadChildProgress {
                piece_length: 8,
                accepted_bytes: accepted,
                retired_bytes: retired,
                accepted_wr_count: accepted / 4,
                retired_wr_count: retired / 4,
                outstanding_wr_count: ((accepted - retired) / 4) as usize,
                posting_stopped: false,
                failed: false,
                read_succeeded: retired == 8,
            },
            timing: ReadCompletionTiming::default(),
            notified_at: std::time::Instant::now(),
            interrupted: false,
        }
    }

    #[tokio::test]
    async fn driver_uses_whole_pieces_or_splits_at_negotiated_provider_and_software_limits() {
        use crate::urma::read_protocol::{ReadCapability, READ_DESCRIPTOR_VERSION};

        let mib = 1024 * 1024u32;
        let automatic = dragonfly_client_config::dfdaemon::UrmaReadServer::default()
            .max_read_size
            .as_u64() as u32;
        // Piece MiB, Child provider MiB, Parent provider MiB, software cap, WR MiB.
        for (piece_mib, child_max, parent_max, software, expected) in [
            (16, 64, 64, automatic, vec![16]),
            (32, 64, 64, automatic, vec![32]),
            (64, 64, 64, automatic, vec![64]),
            (128, 64, 64, automatic, vec![64, 64]),
            (64, 64, 32, automatic, vec![32, 32]),
            (64, 16, 64, automatic, vec![16, 16, 16, 16]),
            (17, 64, 8, automatic, vec![8, 8, 1]),
            (32, 64, 64, 8 * mib, vec![8, 8, 8, 8]),
            (16, 64, 64, mib, vec![1; 16]),
        ] {
            let capability = |provider_mib| {
                ReadCapability {
                    max_read_size: software,
                    max_jfs_sge: 1,
                    descriptor_version: READ_DESCRIPTOR_VERSION,
                }
                .with_provider_limit(provider_mib * mib)
            };
            let max_read_size = capability(child_max)
                .effective_max_read_size(&capability(parent_max))
                .unwrap();
            let piece_length = u64::from(piece_mib * mib);
            let update = |bytes, count| ReadChildUpdate {
                progress: ReadChildProgress {
                    piece_length,
                    accepted_bytes: bytes,
                    retired_bytes: bytes,
                    accepted_wr_count: count,
                    retired_wr_count: count,
                    outstanding_wr_count: 0,
                    posting_stopped: false,
                    failed: false,
                    read_succeeded: bytes == piece_length,
                },
                timing: ReadCompletionTiming::default(),
                notified_at: std::time::Instant::now(),
                interrupted: false,
            };
            let (tx, rx) = tokio::sync::watch::channel(update(0, 0));
            let mut posted = Vec::new();
            let mut bytes = 0;
            let result = drive_read_notifications(
                rx,
                piece_length,
                8,
                max_read_size,
                Instant::now() + Duration::from_secs(1),
                0,
                |lengths| {
                    for &length in &lengths {
                        assert!(length > 0 && length <= max_read_size);
                        bytes += u64::from(length);
                    }
                    let count = lengths.len();
                    posted.extend(lengths);
                    tx.send_replace(update(bytes, posted.len() as u64));
                    std::future::ready(Ok(count))
                },
            )
            .await
            .unwrap();
            assert_eq!(
                posted,
                expected.into_iter().map(|n| n * mib).collect::<Vec<_>>()
            );
            assert_eq!(result.completed_bytes, piece_length);
            assert_eq!(result.read_wr_count, posted.len() as u64);
        }
    }

    #[tokio::test]
    async fn notification_driver_retries_zero_and_partial_posts_from_accepted_progress() {
        let (tx, rx) = tokio::sync::watch::channel(update_progress(0, 0));
        let mut calls = 0;
        let mut accepted = 0;
        let result = drive_read_notifications(
            rx,
            8,
            2,
            4,
            Instant::now() + Duration::from_secs(1),
            0,
            |lengths| {
                calls += 1;
                if calls == 1 {
                    assert_eq!(lengths, vec![4, 4]);
                    // Another owner's CQE frees capacity before this submit
                    // reply is observed; this Piece still has zero accepted WRs.
                    tx.send_replace(update_progress(0, 0));
                    return std::future::ready(Ok(0));
                }
                // Admit only a prefix, even though the first retry offers two WRs.
                assert_eq!(lengths[0], 4);
                accepted += 4;
                tx.send_replace(update_progress(accepted, accepted));
                std::future::ready(Ok(1))
            },
        )
        .await
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(result.completed_bytes, 8);
        assert_eq!(result.read_wr_count, 2);
        assert_eq!(result.read_post_batch_count, 2);
    }

    #[tokio::test]
    async fn zero_post_sleeps_without_notifications_and_remains_deadline_bounded() {
        let (_tx, rx) = tokio::sync::watch::channel(update_progress(0, 0));
        let mut calls = 0;
        let result = drive_read_notifications(
            rx,
            8,
            2,
            4,
            Instant::now() + Duration::from_millis(50),
            0,
            |_| {
                calls += 1;
                std::future::ready(Ok(0))
            },
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("deadline expired"));
        assert_eq!(
            calls, 1,
            "exhausted credits must not cause a submit spin loop"
        );
    }

    #[tokio::test]
    async fn notification_driver_refills_window_when_completion_precedes_await() {
        let (tx, rx) = tokio::sync::watch::channel(update_progress(0, 0));
        let mut accepted = 0;
        let mut batches = 0;
        let result = drive_read_notifications(
            rx,
            8,
            1,
            4,
            Instant::now() + Duration::from_secs(1),
            0,
            |lengths| {
                // Simulates a full post + CQE before the submit future returns.
                // With outstanding=1, the second WR must wait for retirement.
                assert_eq!(lengths, vec![4]);
                accepted += 4;
                batches += 1;
                tx.send_replace(update_progress(accepted, accepted));
                std::future::ready(Ok(1))
            },
        )
        .await
        .unwrap();
        assert_eq!(batches, 2);
        assert_eq!(result.completed_bytes, 8);
        assert_eq!(result.read_wr_count, 2);
        assert_eq!(result.read_post_batch_count, 2);
        assert_eq!(result.progress_notification_count, 2);
        assert_eq!(result.progress_query_count, 0);
        assert_eq!(result.poll_sleep_ns, 0);
    }

    #[tokio::test]
    async fn notification_driver_sees_completion_before_subscription_without_posting() {
        let (_, rx) = tokio::sync::watch::channel(update_progress(8, 8));
        let result = drive_read_notifications(
            rx,
            8,
            1,
            4,
            Instant::now() + Duration::from_secs(1),
            0,
            |_| std::future::ready(Err(protocol("must not post completed Piece"))),
        )
        .await
        .unwrap();
        assert_eq!(result.completed_bytes, 8);
        assert_eq!(result.read_post_batch_count, 0);
    }

    #[tokio::test]
    async fn notification_driver_fails_on_closed_channel_and_deadline() {
        let (tx, rx) = tokio::sync::watch::channel(update_progress(4, 0));
        drop(tx);
        let closed = drive_read_notifications(
            rx,
            8,
            1,
            4,
            Instant::now() + Duration::from_secs(1),
            0,
            |_| std::future::ready(Err(protocol("must not post full window"))),
        )
        .await;
        assert!(closed
            .unwrap_err()
            .to_string()
            .contains("notification closed"));
        let (_tx, rx) = tokio::sync::watch::channel(update_progress(4, 0));
        let expired = drive_read_notifications(
            rx,
            8,
            1,
            4,
            Instant::now() + Duration::from_millis(5),
            0,
            |_| std::future::ready(Err(protocol("must not post full window"))),
        )
        .await;
        assert!(expired
            .unwrap_err()
            .to_string()
            .contains("deadline expired"));
    }

    #[tokio::test]
    async fn notification_driver_deadline_also_bounds_a_stalled_post_command() {
        let (_tx, rx) = tokio::sync::watch::channel(update_progress(0, 0));
        let result = drive_read_notifications(
            rx,
            8,
            1,
            4,
            Instant::now() + Duration::from_millis(5),
            0,
            |_| std::future::pending::<Result<usize>>(),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("deadline expired"));
    }

    #[tokio::test]
    async fn interrupted_notification_cannot_publish_success() {
        let mut update = update_progress(8, 8);
        update.interrupted = true;
        let (_, rx) = tokio::sync::watch::channel(update);
        let result = drive_read_notifications(
            rx,
            8,
            1,
            4,
            Instant::now() + Duration::from_secs(1),
            0,
            |_| std::future::ready(Err(protocol("must not post interrupted Piece"))),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("interrupted"));
    }

    fn wr_progress(accepted: u64, retired: u64) -> ReadChildProgress {
        ReadChildProgress {
            piece_length: 8192,
            accepted_bytes: 8192,
            retired_bytes: 8192,
            accepted_wr_count: accepted,
            retired_wr_count: retired,
            outstanding_wr_count: usize::try_from(accepted - retired).unwrap_or(usize::MAX),
            posting_stopped: false,
            failed: false,
            read_succeeded: false,
        }
    }

    #[test]
    fn drainable_counts_require_matched_wr_retirement() {
        assert_eq!(drainable_wr_counts(None), None);
        assert_eq!(drainable_wr_counts(Some(wr_progress(4, 2))), None);
        assert_eq!(drainable_wr_counts(Some(wr_progress(4, 4))), Some((4, 4)));
        assert_eq!(drainable_wr_counts(Some(wr_progress(0, 0))), Some((0, 0)));
    }

    #[test]
    fn progress_validation_requires_exact_monotonic_accounting() {
        let valid = ReadChildProgress {
            piece_length: 8192,
            accepted_bytes: 8192,
            retired_bytes: 4096,
            accepted_wr_count: 2,
            retired_wr_count: 1,
            outstanding_wr_count: 1,
            posting_stopped: false,
            failed: false,
            read_succeeded: false,
        };
        validate_progress(valid, 8192).unwrap();
        assert!(validate_progress(
            ReadChildProgress {
                outstanding_wr_count: 0,
                ..valid
            },
            8192
        )
        .is_err());
        assert!(validate_progress(
            ReadChildProgress {
                retired_bytes: 8193,
                ..valid
            },
            8192
        )
        .is_err());
    }

    #[tokio::test]
    async fn offer_and_done_waits_expire_without_losing_the_cancel_route() {
        use crate::urma::read_control::ReadLaneControl;
        let (child_stream, parent_stream) = tokio::io::duplex(4096);
        let child = ReadLaneControl::spawn(child_stream, 41, 2, 4).unwrap();
        let parent = ReadLaneControl::spawn(parent_stream, 41, 2, 4).unwrap();
        for transfer_id in [1, 2] {
            let identity = ReadTransferIdentity {
                session_generation: 41,
                transfer_id,
                metadata_generation: 100 + u64::from(transfer_id),
            };
            let mut child_control = child.register(identity).unwrap();
            let parent_control = parent.register(identity).unwrap();
            let error = until(
                Instant::now() + Duration::from_millis(10),
                child_control.receive(),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("deadline expired"));
            // Timeout cancels only the wait. The owner can still run the
            // cancellation exchange rather than losing its transfer route.
            let frame = ReadFrame::Cancelled {
                identity,
                segment_generation: None,
            };
            parent_control.send(frame.clone()).await.unwrap();
            assert_eq!(
                until(
                    Instant::now() + Duration::from_secs(1),
                    child_control.receive()
                )
                .await
                .unwrap(),
                frame
            );
        }
    }
    #[tokio::test]
    async fn stalled_handshake_expires_while_tcp_control_remains_open() {
        let (mut child, _parent) = tokio::io::duplex(4096);
        let result = until(
            Instant::now() + Duration::from_millis(10),
            crate::urma::read_control::read_handshake(&mut child),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("deadline expired"));
    }
}
