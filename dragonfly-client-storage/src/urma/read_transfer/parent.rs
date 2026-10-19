//! Parent-side RM READ transfer of one Piece.
//!
//! Registers and publishes an immutable source, waits for Child drain, then
//! releases it only with caller-supplied provider revocation evidence. Wire
//! cancellation, EOF and timeout never substitute for that evidence.

use super::protocol;
use crate::urma::{
    fabric::UrmaFabricHandle,
    ffi::read::source::ReadSourceStages,
    read_control::ReadTransferControl,
    read_handoff::ResourceGuard,
    read_protocol::{
        ParentAction, ParentReadState, ReadFrame, ReadPieceLocator, ReadSegmentOffer,
        ReadTransferIdentity,
    },
    read_source_lease::SourceLease,
    runtime::{ReadSourceAdmission, ReadSourceId, ReadSourceOffer, ReadSourceRequest},
    Error, Result,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, Instant};

static NEXT_SEGMENT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_segment_generation() -> Result<u64> {
    NEXT_SEGMENT_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| protocol("READ segment generation space exhausted"))
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

/// Parent adapter stops at the explicit provider-revocation gate. The caller
/// must not turn ReadDone into the unsafe proof required by source release.
#[derive(Clone, Copy)]
pub(crate) enum SourceState {
    Registered,
    Retained,
    Released,
}

pub(crate) struct ParentTransfer {
    fabric: UrmaFabricHandle,
    lane_id: u16,
    control: ReadTransferControl,
    state: ParentReadState,
    identity: ReadTransferIdentity,
    piece_offset: u64,
    digest: String,
    effective_max_read_size: u32,
    awaiting_buffer_ready: bool,
    source_lease: Option<SourceLease>,
    on_source_state: Option<std::sync::Arc<dyn Fn(ReadSourceId, SourceState) + Send + Sync>>,
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
    identity: ReadTransferIdentity,
    pub(crate) source_id: ReadSourceId,
    pub(crate) segment_generation: u64,
    pub(crate) completed_length: u64,
    pub(crate) read_wr_count: u64,
    pub(crate) terminal: ParentTerminal,
    /// Source admission (including owner/worker queueing) and ReadDone wait.
    /// The native register sub-phases are recorded separately below.
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

impl ParentTransfer {
    /// Builds the Parent transfer from a dynamically admitted transfer: the
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
                awaiting_buffer_ready: false,
                source_lease: None,
                on_source_state: None,
            },
            request,
        ))
    }

    pub(crate) fn on_source_state(
        mut self,
        callback: impl Fn(ReadSourceId, SourceState) + Send + Sync + 'static,
    ) -> Self {
        self.on_source_state = Some(std::sync::Arc::new(callback));
        self
    }
    fn guard_source(&mut self, id: ReadSourceId, ready: bool) {
        let guard = if let Some(callback) = self.on_source_state.clone() {
            callback(id, SourceState::Registered);
            ResourceGuard::new(move || callback(id, SourceState::Retained))
        } else if ready {
            self.fabric.source_guard(id)
        } else {
            self.fabric.retained_source_guard(id)
        };
        self.source_lease = Some(SourceLease::new(id, self.identity, ready, guard));
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
        completion_timeout: Duration,
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
        if completion_timeout.is_zero() {
            return Err(fail(
                protocol("invalid Parent READ completion timeout"),
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
                self.guard_source(id, false);
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
        self.guard_source(source_id, true);
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
        let exposed_guard = self
            .on_source_state
            .is_none()
            .then(|| self.fabric.retained_source_guard(source_id));
        self.source_lease
            .as_mut()
            .ok_or_else(|| unpublished(protocol("Parent source lease missing")))?
            .expose(segment_generation, exposed_guard)
            .map_err(unpublished)?;
        let deadline = Instant::now() + completion_timeout;
        let send_result = tokio::time::timeout_at(
            deadline,
            self.control.send(ReadFrame::SegmentOffer {
                identity: self.identity,
                offer,
            }),
        )
        .await;
        let send_error = match send_result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some(protocol("Parent READ SegmentOffer deadline expired")),
        };
        if let Some(error) = send_error {
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
            // Timeout only stops this control wait. The exported source remains
            // owned and charged until lane closure plus provider revocation
            // proof; the caller receives its id in the failure below.
            let frame = match tokio::time::timeout_at(deadline, self.control.receive()).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(error)) => return Err(published(error)),
                Err(_) => {
                    return Err(published(protocol(
                        "Parent READ completion deadline expired",
                    )))
                }
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
        self.source_lease
            .as_mut()
            .ok_or_else(|| published(protocol("Parent source lease missing")))?
            .child_drained(self.identity, segment_generation)
            .map_err(published)?;
        if let Err(error) = self.fabric.retire_read_source(source_id).await {
            return Err(ParentTransportFailure {
                error,
                retained_source: Some(RetainedSourceOwner {
                    source_id,
                    segment_generation: Some(segment_generation),
                }),
            });
        }
        let identity = self.identity;
        Ok((
            self,
            PendingSourceRevoke {
                identity,
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
        let lease = self
            .source_lease
            .as_mut()
            .ok_or_else(|| protocol("Parent source lease missing"))?;
        lease.check_revoke(
            pending.source_id,
            pending.identity,
            pending.segment_generation,
        )?;
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
        // SAFETY: Both owner cleanup stages above completed under the caller's
        // provider revocation contract for the identity checked by the lease.
        unsafe {
            lease.released_after_revoke(
                pending.source_id,
                pending.identity,
                pending.segment_generation,
            )?;
        }
        if let Some(callback) = &self.on_source_state {
            callback(pending.source_id, SourceState::Released);
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
        self.control.finish(Some(pending.segment_generation))
    }
}

#[cfg(test)]
mod tests {
    use crate::urma::ffi::read::ReadToken;

    #[test]
    fn source_offer_conversion_preserves_descriptor_and_redacts_token() {
        // The native owner ID cannot be forged here; token redaction and full
        // descriptor round-trip remain covered by read_protocol/ffi tests.
        assert!(format!("{:?}", ReadToken::new(0xfeed_beef)).contains("REDACTED"));
    }
}
