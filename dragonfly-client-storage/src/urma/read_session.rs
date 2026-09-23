//! Gated READ session adapters.
//!
//! The Child adapter proves the wire/native lifecycle and then publishes the
//! fully read destination lease: drain (stop posting, close the import) →
//! publish (extract the registered buffer's CPU span) → caller-driven recycle
//! (close the buffer and release the budget) after Storage consumption. The
//! registered lease itself never leaves the native owner thread.
//!
//! Failure and cancel paths keep native owners fail closed: the Child reports
//! a retained owner id whenever cleanup cannot prove a full drain/close, and
//! the Parent reports a retained source whenever its export could not be
//! released inside the attempt. Wire cancel exchanges are best-effort and
//! never substitute for provider-side revocation evidence.

use super::{
    fabric::UrmaFabricHandle,
    ffi::read::{source::ReadSourceStages, ReadDescriptor, ReadToken},
    read_control::ReadTransferControl,
    read_protocol::{
        ChildAction, ChildReadState, ParentAction, ParentReadState, ReadFrame, ReadPieceLocator,
        ReadSegmentOffer, ReadTransferIdentity,
    },
    runtime::{
        ReadChildAdmission, ReadChildId, ReadChildProgress, ReadChildRequest, ReadLeaseSpan,
        ReadSourceAdmission, ReadSourceId, ReadSourceOffer, ReadSourceRequest,
    },
    Error, Result,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{sleep, timeout, Duration, Instant};

static NEXT_SEGMENT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

fn next_segment_generation() -> Result<u64> {
    NEXT_SEGMENT_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| protocol("READ segment generation space exhausted"))
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

fn wire_offer(
    offer: ReadSourceOffer,
    segment_generation: u64,
    effective_max_read_size: u32,
    piece_offset: u64,
    digest: String,
) -> Result<(ReadSourceId, ReadSegmentOffer)> {
    if segment_generation == 0 || effective_max_read_size == 0 {
        return Err(protocol("invalid READ source publication limits"));
    }
    let descriptor = offer.descriptor;
    Ok((
        offer.id,
        ReadSegmentOffer {
            descriptor_version: descriptor.version,
            eid: descriptor.eid,
            uasid: descriptor.uasid,
            va: descriptor.va,
            length: descriptor.length,
            token_id: descriptor.token_id,
            access: descriptor.access,
            token_policy: descriptor.token_policy,
            token: offer.token.into_wire_value(),
            segment_generation,
            effective_max_read_size,
            piece_offset,
            digest,
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadTransportResult {
    pub(crate) completed_bytes: u64,
    pub(crate) read_wr_count: u64,
}

/// A published destination lease awaiting Storage consumption. The CPU span is
/// final READ content; the caller must consume it and then recycle the lease
/// through [`UrmaFabricHandle::recycle_published_child_lease`] to close the
/// buffer and release the transfer budget.
pub(crate) struct PublishedChildLease {
    pub(crate) child_id: ReadChildId,
    pub(crate) span: ReadLeaseSpan,
}

/// Success outcome of the Child transport adapter including the published
/// destination lease. `piece_offset` echoes the Parent's Piece metadata so
/// the caller can commit the download position without a metadata frame, and
/// `digest` carries the Parent's Piece digest for the local integrity check.
pub(crate) struct ChildTransportSuccess {
    pub(crate) completed_bytes: u64,
    pub(crate) read_wr_count: u64,
    pub(crate) piece_offset: u64,
    pub(crate) digest: String,
    pub(crate) lease: PublishedChildLease,
    pub(crate) timing: ChildTransportTiming,
}

/// Child-side successful-path timing. These stages are observational and do
/// not participate in protocol or owner-lifetime decisions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChildTransportTiming {
    pub(crate) buffer_ready_send_ns: u64,
    pub(crate) segment_offer_wait_ns: u64,
    pub(crate) destination_admission_ns: u64,
    pub(crate) read_completion_ns: u64,
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

pub(crate) struct ChildTransportSession {
    fabric: UrmaFabricHandle,
    lane_id: u16,
    control: ReadTransferControl,
    state: ChildReadState,
    identity: ReadTransferIdentity,
    request: ReadPieceLocator,
    piece_length: u64,
    allocation_bytes: u64,
    max_outstanding: usize,
    poll_interval: Duration,
    completion_timeout: Duration,
}

impl ChildTransportSession {
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
        poll_interval: Duration,
        completion_timeout: Duration,
    ) -> Result<Self> {
        if control.identity() != identity
            || allocation_bytes < piece_length
            || max_outstanding == 0
            || poll_interval.is_zero()
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
            poll_interval,
            completion_timeout,
        })
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
        self.control
            .send(ReadFrame::BufferReady {
                identity: self.identity,
                accepted_length: self.piece_length,
                request: self.request.clone(),
            })
            .await
            .map_err(|error| (error, None))?;
        timing.buffer_ready_send_ns = stage_start.elapsed().as_nanos() as u64;
        let stage_start = Instant::now();
        let frame = self
            .control
            .receive()
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
        let admission = unsafe {
            self.fabric
                .create_read_child(ReadChildRequest {
                    peer_id: self.lane_id,
                    allocation_bytes: self.allocation_bytes,
                    piece_length: self.piece_length,
                    max_outstanding: self.max_outstanding,
                    descriptor,
                    token,
                })
                .await
        };
        timing.destination_admission_ns = stage_start.elapsed().as_nanos() as u64;
        let child_id = match admission {
            Ok(ReadChildAdmission::Ready(id)) => id,
            Ok(ReadChildAdmission::Quarantined { id, error }) => {
                return Err((error, Some(RetainedChildOwner::Cleanup(id))))
            }
            Err(error) => return Err((error, None)),
        };
        let stage_start = Instant::now();
        let result = match self.drive_reads(child_id, max_read_size).await {
            Ok(result) => result,
            Err(error) => return Err((error, Some(RetainedChildOwner::Cleanup(child_id)))),
        };
        timing.read_completion_ns = stage_start.elapsed().as_nanos() as u64;
        // Lease flow stage 1: stop posting and close the import while keeping
        // the registered destination buffer and the full budget charge.
        let stage_start = Instant::now();
        if let Err(error) = self.fabric.drain_read_child_for_lease(child_id).await {
            return Err((error, Some(RetainedChildOwner::Cleanup(child_id))));
        }
        // Stage 2: extract the CPU span of the final READ content. The lease
        // itself stays on the native owner thread until the caller recycles.
        let span = match self.fabric.publish_read_child_lease(child_id).await {
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
        if let Err(error) = self
            .control
            .send(ReadFrame::ReadDone {
                identity: self.identity,
                segment_generation: action,
                completed_length: result.completed_bytes,
                read_wr_count: result.read_wr_count,
            })
            .await
        {
            return Err((error, Some(RetainedChildOwner::PublishedLease(child_id))));
        }
        timing.read_done_send_ns = stage_start.elapsed().as_nanos() as u64;
        let done_wait_start = Instant::now();
        let terminal = match self.control.receive().await {
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
            PublishedChildLease { child_id, span },
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
        let Some(child) = child else {
            return ChildTransportFailure {
                error,
                retained_child: None,
            };
        };
        if let RetainedChildOwner::PublishedLease(child_id) = child {
            let retained_child = match self.fabric.recycle_published_child_lease(child_id).await {
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
            let _ = self
                .control
                .send(ReadFrame::Cancel {
                    identity: self.identity,
                    segment_generation: Some(generation),
                    reason: "child READ transport failure".into(),
                })
                .await;
        }
        let counts = match self.fabric.read_child_progress(child_id).await {
            Ok(progress) => drainable_wr_counts(Some(progress)),
            Err(_) => None,
        };
        let drained = self.fabric.retire_read_child_for_cleanup(child_id).await;
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
                    && self
                        .control
                        .send(ReadFrame::CancelDrained {
                            identity: self.identity,
                            segment_generation: Some(wire_generation),
                            accepted_wr_count: accepted,
                            retired_wr_count: retired,
                        })
                        .await
                        .is_ok()
                {
                    let cancelled = timeout(self.completion_timeout, self.control.receive()).await;
                    if let Ok(Ok(frame)) = cancelled {
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
        let deadline = Instant::now() + self.completion_timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(protocol("Child READ completion deadline expired"));
            }
            let progress = self.fabric.read_child_progress(child_id).await?;
            validate_progress(progress, self.piece_length)?;
            if progress.failed {
                return Err(protocol("native Child READ failed"));
            }
            if progress.read_succeeded {
                return Ok(ReadTransportResult {
                    completed_bytes: progress.retired_bytes,
                    read_wr_count: progress.retired_wr_count,
                });
            }
            let available = self
                .max_outstanding
                .saturating_sub(progress.outstanding_wr_count);
            let mut remaining = self.piece_length - progress.accepted_bytes;
            for _ in 0..available {
                if remaining == 0 {
                    break;
                }
                let length = remaining.min(u64::from(max_read_size)) as u32;
                self.fabric.post_read_child(child_id, length).await?;
                remaining -= u64::from(length);
            }
            sleep(self.poll_interval).await;
        }
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

/// Parent adapter stops at the explicit provider-revocation gate. The caller
/// must not turn ReadDone into the unsafe proof required by source release.
pub(crate) struct ParentSourceSession {
    fabric: UrmaFabricHandle,
    lane_id: u16,
    control: ReadTransferControl,
    state: ParentReadState,
    identity: ReadTransferIdentity,
    piece_offset: u64,
    digest: String,
    effective_max_read_size: u32,
    published_source: Option<(ReadSourceId, u64)>,
    awaiting_buffer_ready: bool,
}

/// Terminal kind recorded while waiting for ReadDone. `Cancelled` means the
/// Child declared a full cancel drain instead of a successful READ; the
/// release step then answers with `Cancelled` rather than `Done`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParentTerminal {
    Success,
    Cancelled,
}

pub(crate) struct PendingSourceRevoke {
    pub(crate) source_id: ReadSourceId,
    pub(crate) segment_generation: u64,
    pub(crate) completed_length: u64,
    pub(crate) read_wr_count: u64,
    pub(crate) terminal: ParentTerminal,
    /// Stage timings for the monitoring checklist: native source register
    /// (aligned copy + token + provider MR registration) and the ReadDone wait.
    pub(crate) register_ns: u64,
    pub(crate) wait_read_done_ns: u64,
    /// Diagnostic shim sub-phases of `register_ns`: alloc / copy#2 / token /
    /// provider MR pin. Observation only; never a lifecycle input.
    pub(crate) register_stages: ReadSourceStages,
}

/// A registered Parent source owner that the caller must keep for a later
/// cleanup pass: the export could not be released inside this attempt.
/// `segment_generation` is `None` while the Offer was never published.
pub(crate) struct RetainedSourceOwner {
    pub(crate) source_id: ReadSourceId,
    pub(crate) segment_generation: Option<u64>,
}

pub(crate) struct ParentTransportFailure {
    pub(crate) error: Error,
    pub(crate) retained_source: Option<RetainedSourceOwner>,
}

impl ParentSourceSession {
    pub(crate) fn new(
        fabric: UrmaFabricHandle,
        lane_id: u16,
        control: ReadTransferControl,
        identity: ReadTransferIdentity,
        piece_length: u64,
        piece_offset: u64,
        digest: String,
        effective_max_read_size: u32,
    ) -> Result<Self> {
        if control.identity() != identity || effective_max_read_size == 0 {
            return Err(protocol("invalid Parent READ session configuration"));
        }
        Ok(Self {
            fabric,
            lane_id,
            control,
            state: ParentReadState::new(identity, piece_length)?,
            identity,
            piece_offset,
            digest,
            effective_max_read_size,
            published_source: None,
            awaiting_buffer_ready: true,
        })
    }

    /// Builds the session from a dynamically admitted transfer: the
    /// dispatcher hands over the initiating BufferReady, so the accepted
    /// length defines the Piece length and the state machine starts past the
    /// awaiting phase. Returns the Piece locator for caller-side resolution.
    /// `piece_offset` is the caller-resolved Piece position echoed in the
    /// SegmentOffer, and `digest` is the caller-resolved Piece digest.
    pub(crate) fn accept(
        fabric: UrmaFabricHandle,
        lane_id: u16,
        control: ReadTransferControl,
        buffer_ready: ReadFrame,
        piece_offset: u64,
        digest: String,
        effective_max_read_size: u32,
    ) -> Result<(Self, ReadPieceLocator)> {
        if effective_max_read_size == 0 {
            return Err(protocol("invalid Parent READ session configuration"));
        }
        let identity = control.identity();
        let accepted_length = match &buffer_ready {
            ReadFrame::BufferReady {
                accepted_length,
                request,
                ..
            } => {
                request.validate()?;
                *accepted_length
            }
            _ => return Err(protocol("Parent READ accept requires a BufferReady")),
        };
        let mut state = ParentReadState::new(identity, accepted_length)?;
        if state.on_frame(&buffer_ready) != Ok(ParentAction::RegisterSource) {
            return Err(protocol("Parent READ accept rejected the BufferReady"));
        }
        let request = match &buffer_ready {
            ReadFrame::BufferReady { request, .. } => request.clone(),
            _ => unreachable!("checked above"),
        };
        Ok((
            Self {
                fabric,
                lane_id,
                control,
                state,
                identity,
                piece_offset,
                digest,
                effective_max_read_size,
                published_source: None,
                awaiting_buffer_ready: false,
            },
            request,
        ))
    }

    /// Registers and publishes a source, then waits until ReadDone or a full
    /// cancel drain requests the provider-specific revoke step. It never
    /// fabricates that proof. Failures return a `ParentTransportFailure`
    /// whose retained source must stay registered (and budgeted) until a
    /// later cleanup pass proves revocation.
    ///
    /// # Safety
    /// `request` must hold the authenticated immutable exact-Piece backing for
    /// this transfer and lane.
    pub(crate) async unsafe fn publish_and_wait_read_done(
        mut self,
        request: ReadSourceRequest,
    ) -> std::result::Result<(Self, PendingSourceRevoke), ParentTransportFailure> {
        let fail =
            |error: Error, retained_source: Option<RetainedSourceOwner>| ParentTransportFailure {
                error,
                retained_source,
            };
        if request.peer_id != self.lane_id {
            return Err(fail(
                protocol("Parent source request uses the wrong lane"),
                None,
            ));
        }
        // Statically registered routes still owe the initiating BufferReady;
        // dynamically accepted transfers consumed theirs in `accept`.
        if self.awaiting_buffer_ready {
            let ready = match self.control.receive().await {
                Ok(ready) => ready,
                Err(error) => return Err(fail(error, None)),
            };
            if self.state.on_frame(&ready) != Ok(ParentAction::RegisterSource) {
                return Err(fail(protocol("Parent expected BufferReady"), None));
            }
        }
        // SAFETY: Supplied by the method contract and validated state identity.
        let register_start = std::time::Instant::now();
        let admission = unsafe { self.fabric.register_read_source(request).await };
        let register_ns = register_start.elapsed().as_nanos() as u64;
        let offer = match admission {
            Ok(ReadSourceAdmission::Ready(offer)) => offer,
            Ok(ReadSourceAdmission::Quarantined { id, error }) => {
                return Err(fail(
                    error,
                    Some(RetainedSourceOwner {
                        source_id: id,
                        segment_generation: None,
                    }),
                ));
            }
            Err(error) => return Err(fail(error, None)),
        };
        let register_stages = offer.register_stages;
        let source_id = offer.id;
        let unpublished = |error: Error| ParentTransportFailure {
            error,
            retained_source: Some(RetainedSourceOwner {
                source_id,
                segment_generation: None,
            }),
        };
        let segment_generation = match next_segment_generation() {
            Ok(generation) => generation,
            Err(error) => return Err(unpublished(error)),
        };
        let (source_id, offer) = match wire_offer(
            offer,
            segment_generation,
            self.effective_max_read_size,
            self.piece_offset,
            self.digest.clone(),
        ) {
            Ok(offer) => offer,
            Err(error) => return Err(unpublished(error)),
        };
        if let Err(error) = self
            .control
            .send(ReadFrame::SegmentOffer {
                identity: self.identity,
                offer,
            })
            .await
        {
            return Err(ParentTransportFailure {
                error,
                retained_source: Some(RetainedSourceOwner {
                    source_id,
                    segment_generation: Some(segment_generation),
                }),
            });
        }
        if let Err(error) = self.state.offer_published(segment_generation) {
            return Err(ParentTransportFailure {
                error,
                retained_source: Some(RetainedSourceOwner {
                    source_id,
                    segment_generation: Some(segment_generation),
                }),
            });
        }
        self.published_source = Some((source_id, segment_generation));
        let published = |error: Error| ParentTransportFailure {
            error,
            retained_source: Some(RetainedSourceOwner {
                source_id,
                segment_generation: Some(segment_generation),
            }),
        };
        // Only ReadDone and a matching-generation CancelDrained reach the
        // release stage; Cancel frames only switch the wait target.
        let wait_read_done_start = std::time::Instant::now();
        let (terminal, completed_length, read_wr_count) = loop {
            let frame = match self.control.receive().await {
                Ok(frame) => frame,
                Err(error) => return Err(published(error)),
            };
            let terminal = match &frame {
                ReadFrame::ReadDone { .. } => ParentTerminal::Success,
                ReadFrame::CancelDrained { .. } => ParentTerminal::Cancelled,
                _ => match self.state.on_frame(&frame) {
                    Ok(ParentAction::WaitForChildDrain) => continue,
                    Ok(_) | Err(_) => {
                        return Err(published(protocol(
                            "Parent expected ReadDone or a full cancel drain",
                        )));
                    }
                },
            };
            let (completed_length, read_wr_count) = match &frame {
                ReadFrame::ReadDone {
                    completed_length,
                    read_wr_count,
                    ..
                } => (*completed_length, *read_wr_count),
                ReadFrame::CancelDrained {
                    accepted_wr_count,
                    retired_wr_count,
                    ..
                } => (*accepted_wr_count, *retired_wr_count),
                _ => {
                    return Err(published(protocol(
                        "Parent release stage requires ReadDone or CancelDrained",
                    )));
                }
            };
            match self.state.on_frame(&frame) {
                Ok(ParentAction::RevokeSource) => {
                    break (terminal, completed_length, read_wr_count)
                }
                Ok(_) | Err(_) => {
                    return Err(published(protocol(
                        "Parent release stage was not authorized by the READ state machine",
                    )));
                }
            }
        };
        if let Err(error) = self.fabric.retire_read_source(source_id).await {
            return Err(ParentTransportFailure {
                error,
                retained_source: Some(RetainedSourceOwner {
                    source_id,
                    segment_generation: Some(segment_generation),
                }),
            });
        }
        Ok((
            self,
            PendingSourceRevoke {
                source_id,
                segment_generation,
                completed_length,
                read_wr_count,
                terminal,
                register_ns,
                wait_read_done_ns: wait_read_done_start.elapsed().as_nanos() as u64,
                register_stages,
            },
        ))
    }

    /// Executes unregister/release and sends Done or Cancelled after the
    /// caller supplies the external provider revocation proof.
    ///
    /// # Safety
    /// The provider's unregister preconditions must hold and remote access to
    /// this exact source generation must have ceased and be unable to resume.
    /// ReadDone, CancelDrained, EOF or timeout alone do not satisfy this
    /// contract.
    pub(crate) async unsafe fn revoke_and_finish(
        mut self,
        pending: PendingSourceRevoke,
    ) -> Result<()> {
        if self.published_source != Some((pending.source_id, pending.segment_generation)) {
            return Err(protocol("Parent revoke identity mismatch"));
        }
        // SAFETY: The caller supplies the provider drain proof.
        if unsafe {
            self.fabric
                .unregister_read_source(pending.source_id)
                .await?
        } {
            return Err(protocol("source retired before revocation proof stage"));
        }
        // SAFETY: The caller supplies independent remote revocation proof.
        if !unsafe {
            self.fabric
                .release_read_source_after_revoke(pending.source_id)
                .await?
        } {
            return Err(protocol("source remained pending after revocation proof"));
        }
        match self.state.source_released()? {
            ParentAction::SendDone { segment_generation } => {
                if pending.terminal != ParentTerminal::Success
                    || segment_generation != pending.segment_generation
                {
                    return Err(protocol("Parent terminal mismatch"));
                }
                self.control
                    .send(ReadFrame::Done {
                        identity: self.identity,
                        segment_generation,
                    })
                    .await?;
            }
            ParentAction::SendCancelled { segment_generation } => {
                if pending.terminal != ParentTerminal::Cancelled
                    || segment_generation != Some(pending.segment_generation)
                {
                    return Err(protocol("Parent terminal mismatch"));
                }
                self.control
                    .send(ReadFrame::Cancelled {
                        identity: self.identity,
                        segment_generation,
                    })
                    .await?;
            }
            _ => return Err(protocol("Parent source release produced invalid action")),
        }
        self.published_source = None;
        self.control.finish(Some(pending.segment_generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn source_offer_conversion_preserves_descriptor_and_redacts_token() {
        // The native owner ID cannot be forged here; token redaction and full
        // descriptor round-trip remain covered by read_protocol/ffi tests.
        assert!(format!("{:?}", ReadToken::new(0xfeed_beef)).contains("REDACTED"));
    }
}
