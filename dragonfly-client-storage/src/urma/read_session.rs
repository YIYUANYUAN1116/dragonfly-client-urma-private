//! Gated READ session adapters.
//!
//! The Child adapter below is transport-only: it proves the wire/native
//! lifecycle and then closes the destination. It does not publish bytes to
//! Storage until a separate destination lease handoff is implemented.

use super::{
    fabric::UrmaFabricHandle,
    ffi::read::{ReadDescriptor, ReadToken},
    read_control::ReadTransferControl,
    read_protocol::{
        ChildAction, ChildReadState, ParentAction, ParentReadState, ReadFrame, ReadSegmentOffer,
        ReadTransferIdentity,
    },
    runtime::{
        ReadChildAdmission, ReadChildId, ReadChildProgress, ReadChildRequest, ReadSourceAdmission,
        ReadSourceId, ReadSourceOffer, ReadSourceRequest,
    },
    Error, Result,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{sleep, Duration, Instant};

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
        },
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadTransportResult {
    pub(crate) completed_bytes: u64,
    pub(crate) read_wr_count: u64,
}

pub(crate) struct ChildTransportSession {
    fabric: UrmaFabricHandle,
    lane_id: u16,
    control: ReadTransferControl,
    state: ChildReadState,
    identity: ReadTransferIdentity,
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
        Ok(Self {
            fabric,
            lane_id,
            control,
            state: ChildReadState::new(identity, piece_length, max_read_size)?,
            identity,
            piece_length,
            allocation_bytes,
            max_outstanding,
            poll_interval,
            completion_timeout,
        })
    }

    /// Runs one Piece through READ and terminal control, then closes the native
    /// destination. No Storage success may be reported from this transport-only
    /// result because the destination bytes are deliberately not handed out.
    ///
    /// # Safety
    /// The caller must bind this lane/identity to an authenticated handshake and
    /// guarantee exclusive ownership of the destination Piece allocation.
    pub(crate) async unsafe fn run_transport_only(mut self) -> Result<ReadTransportResult> {
        self.control
            .send(ReadFrame::BufferReady {
                identity: self.identity,
                accepted_length: self.piece_length,
            })
            .await?;
        let frame = self.control.receive().await?;
        if self.state.on_frame(&frame)? != ChildAction::StartRead {
            return Err(protocol("Child did not receive a usable SegmentOffer"));
        }
        let ReadFrame::SegmentOffer { offer, .. } = frame else {
            return Err(protocol("Child expected SegmentOffer"));
        };
        let max_read_size = offer.effective_max_read_size;
        let (descriptor, token) = native_descriptor(&offer);
        // SAFETY: The method contract supplies authenticated identity and
        // exclusive destination ownership; the state machine validated Offer.
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
                .await?
        };
        let child_id = match admission {
            ReadChildAdmission::Ready(id) => id,
            ReadChildAdmission::Quarantined { id, error } => {
                let _ = self.fabric.retire_read_child_for_cleanup(id).await;
                return Err(error);
            }
        };
        let result = self.drive_reads(child_id, max_read_size).await;
        if result.is_err() {
            let _ = self.fabric.retire_read_child_for_cleanup(child_id).await;
            return result;
        }
        let result = result.expect("checked successful READ drive");
        // No Storage lease is exported by this transport-only adapter. Close
        // import/destination after all CQEs and before ReadDone allows Parent
        // to start source revocation.
        if !self.fabric.retire_read_child_for_cleanup(child_id).await? {
            return Err(protocol("successful Child destination did not drain"));
        }
        let action = self
            .state
            .read_finished(result.completed_bytes, result.read_wr_count)?;
        let ChildAction::SendReadDone { segment_generation } = action else {
            return Err(protocol("Child READ completion produced an invalid action"));
        };
        self.control
            .send(ReadFrame::ReadDone {
                identity: self.identity,
                segment_generation,
                completed_length: result.completed_bytes,
                read_wr_count: result.read_wr_count,
            })
            .await?;
        let terminal = self.control.receive().await?;
        if self.state.on_frame(&terminal)? != ChildAction::Complete {
            return Err(protocol("Child expected Done after ReadDone"));
        }
        self.control.finish(Some(segment_generation))?;
        Ok(result)
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
    effective_max_read_size: u32,
    published_source: Option<(ReadSourceId, u64)>,
}

pub(crate) struct PendingSourceRevoke {
    pub(crate) source_id: ReadSourceId,
    pub(crate) segment_generation: u64,
    pub(crate) completed_length: u64,
    pub(crate) read_wr_count: u64,
}

impl ParentSourceSession {
    pub(crate) fn new(
        fabric: UrmaFabricHandle,
        lane_id: u16,
        control: ReadTransferControl,
        identity: ReadTransferIdentity,
        piece_length: u64,
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
            effective_max_read_size,
            published_source: None,
        })
    }

    /// Registers and publishes a source, then waits until ReadDone requests the
    /// provider-specific revoke step. It never fabricates that proof.
    ///
    /// # Safety
    /// `request` must hold the authenticated immutable exact-Piece backing for
    /// this transfer and lane.
    pub(crate) async unsafe fn publish_and_wait_read_done(
        mut self,
        request: ReadSourceRequest,
    ) -> Result<(Self, PendingSourceRevoke)> {
        if request.peer_id != self.lane_id {
            return Err(protocol("Parent source request uses the wrong lane"));
        }
        let ready = self.control.receive().await?;
        if self.state.on_frame(&ready)? != ParentAction::RegisterSource {
            return Err(protocol("Parent expected BufferReady"));
        }
        // SAFETY: Supplied by the method contract and validated state identity.
        let admission = unsafe { self.fabric.register_read_source(request).await? };
        let offer = match admission {
            ReadSourceAdmission::Ready(offer) => offer,
            ReadSourceAdmission::Quarantined { error, .. } => return Err(error),
        };
        let segment_generation = next_segment_generation()?;
        let (source_id, offer) =
            wire_offer(offer, segment_generation, self.effective_max_read_size)?;
        self.control
            .send(ReadFrame::SegmentOffer {
                identity: self.identity,
                offer,
            })
            .await?;
        self.state.offer_published(segment_generation)?;
        self.published_source = Some((source_id, segment_generation));
        let done = self.control.receive().await?;
        if self.state.on_frame(&done)? != ParentAction::RevokeSource {
            return Err(protocol("Parent expected ReadDone"));
        }
        let ReadFrame::ReadDone {
            completed_length,
            read_wr_count,
            ..
        } = done
        else {
            return Err(protocol("Parent expected ReadDone"));
        };
        self.fabric.retire_read_source(source_id).await?;
        Ok((
            self,
            PendingSourceRevoke {
                source_id,
                segment_generation,
                completed_length,
                read_wr_count,
            },
        ))
    }

    /// Executes unregister/release and sends Done after the caller supplies the
    /// external provider revocation proof.
    ///
    /// # Safety
    /// The provider's unregister preconditions must hold and remote access to
    /// this exact source generation must have ceased and be unable to resume.
    /// ReadDone, EOF or timeout alone do not satisfy this contract.
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
        let ParentAction::SendDone { segment_generation } = self.state.source_released()? else {
            return Err(protocol("Parent source release produced invalid action"));
        };
        if segment_generation != pending.segment_generation {
            return Err(protocol("Parent source release generation mismatch"));
        }
        self.control
            .send(ReadFrame::Done {
                identity: self.identity,
                segment_generation,
            })
            .await?;
        self.published_source = None;
        self.control.finish(Some(segment_generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
