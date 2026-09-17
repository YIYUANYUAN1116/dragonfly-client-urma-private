//! READ-only DFUR wire DTOs and transfer state machines.
//!
//! This module is intentionally independent of sockets and native handles. The
//! session adapter will translate actions into owner-loop commands only after
//! every identity and state transition has been validated here.

use crate::{
    rendezvous::{
        put_bytes, read_envelope, write_envelope, PayloadReader, MAX_PAYLOAD_LENGTH,
        MAX_STRING_LENGTH,
    },
    urma::{Error, Result},
};
use std::collections::{HashSet, VecDeque};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) const READ_DFUR_VERSION: u8 = 5;
pub(crate) const READ_DESCRIPTOR_VERSION: u32 = 1;
const EID_LENGTH: usize = 16;

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

struct WireReader<'a>(PayloadReader<'a>);

impl<'a> WireReader<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self(PayloadReader::new(payload))
    }

    fn map<T>(result: dragonfly_client_core::Result<T>) -> Result<T> {
        result.map_err(|error| protocol(format!("invalid READ wire payload: {error}")))
    }

    fn finish(self) -> Result<()> {
        Self::map(self.0.finish())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        Self::map(self.0.take(length))
    }

    fn u8(&mut self) -> Result<u8> {
        Self::map(self.0.u8())
    }

    fn u32(&mut self) -> Result<u32> {
        Self::map(self.0.u32())
    }

    fn u64(&mut self) -> Result<u64> {
        Self::map(self.0.u64())
    }

    fn string(&mut self, max: usize) -> Result<String> {
        Self::map(self.0.string(max))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReadTransferIdentity {
    pub(crate) peer_generation: u8,
    pub(crate) transfer_id: u32,
    pub(crate) metadata_generation: u64,
}

impl ReadTransferIdentity {
    pub(crate) fn validate(self) -> Result<()> {
        if self.peer_generation == 0 || self.transfer_id == 0 || self.metadata_generation == 0 {
            return Err(protocol(
                "READ transfer identity contains a zero generation/id",
            ));
        }
        Ok(())
    }

    fn encode(self, payload: &mut Vec<u8>) {
        payload.push(self.peer_generation);
        payload.extend_from_slice(&self.transfer_id.to_be_bytes());
        payload.extend_from_slice(&self.metadata_generation.to_be_bytes());
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self> {
        let identity = Self {
            peer_generation: reader.u8()?,
            transfer_id: reader.u32()?,
            metadata_generation: reader.u64()?,
        };
        identity.validate()?;
        Ok(identity)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadCapability {
    pub(crate) max_read_size: u32,
    pub(crate) max_jfs_sge: u32,
    pub(crate) descriptor_version: u32,
}

impl ReadCapability {
    pub(crate) fn compatible(&self, remote: &Self) -> Result<()> {
        if self.max_read_size == 0 || remote.max_read_size == 0 {
            return Err(protocol("READ capability has zero max_read_size"));
        }
        if self.max_jfs_sge == 0 || remote.max_jfs_sge == 0 {
            return Err(protocol("READ capability has zero max_jfs_sge"));
        }
        if self.descriptor_version != READ_DESCRIPTOR_VERSION
            || remote.descriptor_version != READ_DESCRIPTOR_VERSION
        {
            return Err(protocol("READ descriptor version is incompatible"));
        }
        Ok(())
    }

    pub(crate) fn effective_max_read_size(&self, remote: &Self) -> Result<u32> {
        self.compatible(remote)?;
        Ok(self.max_read_size.min(remote.max_read_size))
    }

    pub(crate) fn encode(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.max_read_size.to_be_bytes());
        payload.extend_from_slice(&self.max_jfs_sge.to_be_bytes());
        payload.extend_from_slice(&self.descriptor_version.to_be_bytes());
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self> {
        let capability = Self {
            max_read_size: reader.u32()?,
            max_jfs_sge: reader.u32()?,
            descriptor_version: reader.u32()?,
        };
        capability.compatible(&capability)?;
        Ok(capability)
    }
}

/// Pointer-free DTO copied from the native descriptor. `token` is deliberately
/// absent from Debug output and must never enter logs or metrics.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ReadSegmentOffer {
    pub(crate) descriptor_version: u32,
    pub(crate) eid: [u8; EID_LENGTH],
    pub(crate) uasid: u32,
    pub(crate) va: u64,
    pub(crate) length: u64,
    pub(crate) token_id: u32,
    pub(crate) access: u32,
    pub(crate) token_policy: u32,
    pub(crate) token: u32,
    pub(crate) segment_generation: u64,
    pub(crate) effective_max_read_size: u32,
}

impl std::fmt::Debug for ReadSegmentOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadSegmentOffer")
            .field("descriptor_version", &self.descriptor_version)
            .field("length", &self.length)
            .field("segment_generation", &self.segment_generation)
            .field("effective_max_read_size", &self.effective_max_read_size)
            .finish_non_exhaustive()
    }
}

impl ReadSegmentOffer {
    fn validate(&self) -> Result<()> {
        if self.descriptor_version != READ_DESCRIPTOR_VERSION
            || self.length == 0
            || self.segment_generation == 0
            || self.effective_max_read_size == 0
        {
            return Err(protocol("invalid READ SegmentOffer"));
        }
        Ok(())
    }

    fn encode(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.descriptor_version.to_be_bytes());
        payload.extend_from_slice(&self.eid);
        payload.extend_from_slice(&self.uasid.to_be_bytes());
        payload.extend_from_slice(&self.va.to_be_bytes());
        payload.extend_from_slice(&self.length.to_be_bytes());
        payload.extend_from_slice(&self.token_id.to_be_bytes());
        payload.extend_from_slice(&self.access.to_be_bytes());
        payload.extend_from_slice(&self.token_policy.to_be_bytes());
        payload.extend_from_slice(&self.token.to_be_bytes());
        payload.extend_from_slice(&self.segment_generation.to_be_bytes());
        payload.extend_from_slice(&self.effective_max_read_size.to_be_bytes());
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self> {
        let offer = Self {
            descriptor_version: reader.u32()?,
            eid: reader
                .take(EID_LENGTH)?
                .try_into()
                .expect("fixed EID length"),
            uasid: reader.u32()?,
            va: reader.u64()?,
            length: reader.u64()?,
            token_id: reader.u32()?,
            access: reader.u32()?,
            token_policy: reader.u32()?,
            token: reader.u32()?,
            segment_generation: reader.u64()?,
            effective_max_read_size: reader.u32()?,
        };
        offer.validate()?;
        Ok(offer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReadFrame {
    BufferReady {
        identity: ReadTransferIdentity,
        accepted_length: u64,
    },
    SegmentOffer {
        identity: ReadTransferIdentity,
        offer: ReadSegmentOffer,
    },
    ReadDone {
        identity: ReadTransferIdentity,
        segment_generation: u64,
        completed_length: u64,
        read_wr_count: u64,
    },
    Done {
        identity: ReadTransferIdentity,
        segment_generation: u64,
    },
    Cancel {
        identity: ReadTransferIdentity,
        segment_generation: Option<u64>,
        reason: String,
    },
    CancelDrained {
        identity: ReadTransferIdentity,
        segment_generation: Option<u64>,
        accepted_wr_count: u64,
        retired_wr_count: u64,
    },
    Cancelled {
        identity: ReadTransferIdentity,
        segment_generation: Option<u64>,
    },
}

impl ReadFrame {
    pub(crate) fn identity(&self) -> ReadTransferIdentity {
        match self {
            Self::BufferReady { identity, .. }
            | Self::SegmentOffer { identity, .. }
            | Self::ReadDone { identity, .. }
            | Self::Done { identity, .. }
            | Self::Cancel { identity, .. }
            | Self::CancelDrained { identity, .. }
            | Self::Cancelled { identity, .. } => *identity,
        }
    }

    pub(crate) fn encode(&self) -> Result<(u8, Vec<u8>)> {
        self.identity().validate()?;
        let mut payload = Vec::new();
        self.identity().encode(&mut payload);
        let frame_type = match self {
            Self::BufferReady {
                accepted_length, ..
            } => {
                if *accepted_length == 0 {
                    return Err(protocol("BufferReady has zero accepted_length"));
                }
                payload.extend_from_slice(&accepted_length.to_be_bytes());
                10
            }
            Self::SegmentOffer { offer, .. } => {
                offer.validate()?;
                offer.encode(&mut payload);
                11
            }
            Self::ReadDone {
                segment_generation,
                completed_length,
                read_wr_count,
                ..
            } => {
                require_generation(*segment_generation)?;
                if *completed_length == 0 || *read_wr_count == 0 {
                    return Err(protocol("ReadDone has zero completion accounting"));
                }
                payload.extend_from_slice(&segment_generation.to_be_bytes());
                payload.extend_from_slice(&completed_length.to_be_bytes());
                payload.extend_from_slice(&read_wr_count.to_be_bytes());
                12
            }
            Self::Done {
                segment_generation, ..
            } => {
                require_generation(*segment_generation)?;
                payload.extend_from_slice(&segment_generation.to_be_bytes());
                13
            }
            Self::Cancel {
                segment_generation,
                reason,
                ..
            } => {
                encode_generation(*segment_generation, &mut payload)?;
                if reason.is_empty() {
                    return Err(protocol("Cancel reason is empty"));
                }
                put_bytes(&mut payload, reason.as_bytes());
                14
            }
            Self::CancelDrained {
                segment_generation,
                accepted_wr_count,
                retired_wr_count,
                ..
            } => {
                encode_generation(*segment_generation, &mut payload)?;
                if retired_wr_count > accepted_wr_count {
                    return Err(protocol(
                        "CancelDrained retired count exceeds accepted count",
                    ));
                }
                payload.extend_from_slice(&accepted_wr_count.to_be_bytes());
                payload.extend_from_slice(&retired_wr_count.to_be_bytes());
                15
            }
            Self::Cancelled {
                segment_generation, ..
            } => {
                encode_generation(*segment_generation, &mut payload)?;
                16
            }
        };
        Ok((frame_type, payload))
    }

    pub(crate) fn decode(frame_type: u8, payload: &[u8]) -> Result<Self> {
        let mut reader = WireReader::new(payload);
        let identity = ReadTransferIdentity::decode(&mut reader)?;
        let frame = match frame_type {
            10 => Self::BufferReady {
                identity,
                accepted_length: reader.u64()?,
            },
            11 => Self::SegmentOffer {
                identity,
                offer: ReadSegmentOffer::decode(&mut reader)?,
            },
            12 => Self::ReadDone {
                identity,
                segment_generation: reader.u64()?,
                completed_length: reader.u64()?,
                read_wr_count: reader.u64()?,
            },
            13 => Self::Done {
                identity,
                segment_generation: reader.u64()?,
            },
            14 => Self::Cancel {
                identity,
                segment_generation: decode_generation(&mut reader)?,
                reason: reader.string(MAX_STRING_LENGTH)?,
            },
            15 => Self::CancelDrained {
                identity,
                segment_generation: decode_generation(&mut reader)?,
                accepted_wr_count: reader.u64()?,
                retired_wr_count: reader.u64()?,
            },
            16 => Self::Cancelled {
                identity,
                segment_generation: decode_generation(&mut reader)?,
            },
            _ => return Err(protocol(format!("unknown READ frame type {frame_type}"))),
        };
        reader.finish()?;
        // Reuse all encode-time semantic validation after structural decode.
        frame.encode()?;
        Ok(frame)
    }
}

pub(crate) async fn write_read_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &ReadFrame,
) -> Result<()> {
    let (frame_type, payload) = frame.encode()?;
    write_envelope(
        writer,
        super::rendezvous::MAGIC,
        READ_DFUR_VERSION,
        frame_type,
        &payload,
        MAX_PAYLOAD_LENGTH,
    )
    .await
    .map_err(|error| protocol(format!("write READ control frame failed: {error}")))
}

pub(crate) async fn read_read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ReadFrame> {
    let (frame_type, payload) = read_envelope(
        reader,
        super::rendezvous::MAGIC,
        READ_DFUR_VERSION,
        MAX_PAYLOAD_LENGTH,
    )
    .await
    .map_err(|error| protocol(format!("read READ control frame failed: {error}")))?;
    ReadFrame::decode(frame_type, &payload)
}

fn require_generation(generation: u64) -> Result<()> {
    if generation == 0 {
        Err(protocol("zero READ segment generation"))
    } else {
        Ok(())
    }
}

fn encode_generation(generation: Option<u64>, payload: &mut Vec<u8>) -> Result<()> {
    match generation {
        None => payload.push(0),
        Some(generation) => {
            require_generation(generation)?;
            payload.push(1);
            payload.extend_from_slice(&generation.to_be_bytes());
        }
    }
    Ok(())
}

fn decode_generation(reader: &mut WireReader<'_>) -> Result<Option<u64>> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let generation = reader.u64()?;
            require_generation(generation)?;
            Ok(Some(generation))
        }
        _ => Err(protocol("invalid optional segment generation tag")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParentAction {
    RegisterSource,
    WaitForChildDrain,
    RevokeSource,
    SendDone { segment_generation: u64 },
    SendCancelled { segment_generation: Option<u64> },
    DuplicateTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParentPhase {
    AwaitingBufferReady,
    RegisteringSource,
    Offered(u64),
    WaitingCancelDrain(u64),
    RevokingSuccess(u64),
    RevokingCancel(Option<u64>),
    TerminalSuccess(u64),
    TerminalCancel(Option<u64>),
}

pub(crate) struct ParentReadState {
    identity: ReadTransferIdentity,
    length: u64,
    phase: ParentPhase,
}

impl ParentReadState {
    pub(crate) fn new(identity: ReadTransferIdentity, length: u64) -> Result<Self> {
        identity.validate()?;
        if length == 0 {
            return Err(protocol("zero READ Piece length"));
        }
        Ok(Self {
            identity,
            length,
            phase: ParentPhase::AwaitingBufferReady,
        })
    }

    pub(crate) fn on_frame(&mut self, frame: &ReadFrame) -> Result<ParentAction> {
        self.match_identity(frame.identity())?;
        match (&self.phase, frame) {
            (
                ParentPhase::AwaitingBufferReady,
                ReadFrame::BufferReady {
                    accepted_length, ..
                },
            ) if *accepted_length == self.length => {
                self.phase = ParentPhase::RegisteringSource;
                Ok(ParentAction::RegisterSource)
            }
            (
                ParentPhase::Offered(expected),
                ReadFrame::ReadDone {
                    segment_generation,
                    completed_length,
                    read_wr_count,
                    ..
                },
            ) if segment_generation == expected
                && *completed_length == self.length
                && *read_wr_count != 0 =>
            {
                self.phase = ParentPhase::RevokingSuccess(*expected);
                Ok(ParentAction::RevokeSource)
            }
            (
                ParentPhase::AwaitingBufferReady | ParentPhase::RegisteringSource,
                ReadFrame::Cancel {
                    segment_generation: None,
                    ..
                },
            ) => {
                self.phase = ParentPhase::RevokingCancel(None);
                Ok(ParentAction::RevokeSource)
            }
            (
                ParentPhase::Offered(expected),
                ReadFrame::Cancel {
                    segment_generation: Some(received),
                    ..
                },
            ) if expected == received => {
                self.phase = ParentPhase::WaitingCancelDrain(*expected);
                Ok(ParentAction::WaitForChildDrain)
            }
            (
                ParentPhase::WaitingCancelDrain(expected),
                ReadFrame::CancelDrained {
                    segment_generation: Some(received),
                    accepted_wr_count,
                    retired_wr_count,
                    ..
                },
            ) if expected == received && accepted_wr_count == retired_wr_count => {
                self.phase = ParentPhase::RevokingCancel(Some(*expected));
                Ok(ParentAction::RevokeSource)
            }
            (
                ParentPhase::TerminalSuccess(expected),
                ReadFrame::ReadDone {
                    segment_generation, ..
                },
            ) if expected == segment_generation => Ok(ParentAction::DuplicateTerminal),
            (
                ParentPhase::TerminalCancel(expected),
                ReadFrame::CancelDrained {
                    segment_generation, ..
                },
            ) if expected == segment_generation => Ok(ParentAction::DuplicateTerminal),
            _ => Err(protocol(format!(
                "invalid Parent READ transition from {:?} with {:?}",
                self.phase, frame
            ))),
        }
    }

    /// Commits the writer ordering point: after this returns, Cancel without a
    /// segment generation is invalid even if the peer has not read the Offer yet.
    pub(crate) fn offer_published(&mut self, segment_generation: u64) -> Result<()> {
        require_generation(segment_generation)?;
        if self.phase != ParentPhase::RegisteringSource {
            return Err(protocol("SegmentOffer published in the wrong Parent state"));
        }
        self.phase = ParentPhase::Offered(segment_generation);
        Ok(())
    }

    pub(crate) fn source_released(&mut self) -> Result<ParentAction> {
        match self.phase {
            ParentPhase::RevokingSuccess(generation) => {
                self.phase = ParentPhase::TerminalSuccess(generation);
                Ok(ParentAction::SendDone {
                    segment_generation: generation,
                })
            }
            ParentPhase::RevokingCancel(generation) => {
                self.phase = ParentPhase::TerminalCancel(generation);
                Ok(ParentAction::SendCancelled {
                    segment_generation: generation,
                })
            }
            _ => Err(protocol(
                "source release completed in the wrong Parent state",
            )),
        }
    }

    fn match_identity(&self, received: ReadTransferIdentity) -> Result<()> {
        if received != self.identity {
            return Err(protocol("READ transfer identity/generation mismatch"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildAction {
    StartRead,
    SendCancel { segment_generation: Option<u64> },
    DrainLateOffer { segment_generation: u64 },
    SendReadDone { segment_generation: u64 },
    SendCancelDrained { segment_generation: Option<u64> },
    Complete,
    Cancelled,
    DuplicateTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildPhase {
    WaitingOffer,
    Reading(u64),
    WaitingDone(u64),
    CancellingWithoutOffer,
    CancellingWithOffer(u64),
    WaitingCancelled(Option<u64>),
    TerminalSuccess(u64),
    TerminalCancel(Option<u64>),
}

pub(crate) struct ChildReadState {
    identity: ReadTransferIdentity,
    length: u64,
    max_read_size: u32,
    phase: ChildPhase,
}

impl ChildReadState {
    pub(crate) fn new(
        identity: ReadTransferIdentity,
        length: u64,
        max_read_size: u32,
    ) -> Result<Self> {
        identity.validate()?;
        if length == 0 || max_read_size == 0 {
            return Err(protocol("invalid Child READ limits"));
        }
        Ok(Self {
            identity,
            length,
            max_read_size,
            phase: ChildPhase::WaitingOffer,
        })
    }

    pub(crate) fn on_frame(&mut self, frame: &ReadFrame) -> Result<ChildAction> {
        self.match_identity(frame.identity())?;
        match (&self.phase, frame) {
            (ChildPhase::WaitingOffer, ReadFrame::SegmentOffer { offer, .. }) => {
                self.validate_offer(offer)?;
                self.phase = ChildPhase::Reading(offer.segment_generation);
                Ok(ChildAction::StartRead)
            }
            (ChildPhase::CancellingWithoutOffer, ReadFrame::SegmentOffer { offer, .. }) => {
                self.validate_offer(offer)?;
                self.phase = ChildPhase::CancellingWithOffer(offer.segment_generation);
                Ok(ChildAction::DrainLateOffer {
                    segment_generation: offer.segment_generation,
                })
            }
            (ChildPhase::WaitingCancelled(None), ReadFrame::SegmentOffer { offer, .. }) => {
                self.validate_offer(offer)?;
                self.phase = ChildPhase::CancellingWithOffer(offer.segment_generation);
                Ok(ChildAction::DrainLateOffer {
                    segment_generation: offer.segment_generation,
                })
            }
            (
                ChildPhase::WaitingDone(expected),
                ReadFrame::Done {
                    segment_generation, ..
                },
            ) if expected == segment_generation => {
                self.phase = ChildPhase::TerminalSuccess(*expected);
                Ok(ChildAction::Complete)
            }
            (
                ChildPhase::WaitingCancelled(expected),
                ReadFrame::Cancelled {
                    segment_generation, ..
                },
            ) if expected == segment_generation => {
                self.phase = ChildPhase::TerminalCancel(*expected);
                Ok(ChildAction::Cancelled)
            }
            (
                ChildPhase::TerminalSuccess(expected),
                ReadFrame::Done {
                    segment_generation, ..
                },
            ) if expected == segment_generation => Ok(ChildAction::DuplicateTerminal),
            (
                ChildPhase::TerminalCancel(expected),
                ReadFrame::Cancelled {
                    segment_generation, ..
                },
            ) if expected == segment_generation => Ok(ChildAction::DuplicateTerminal),
            _ => Err(protocol(format!(
                "invalid Child READ transition from {:?} with {:?}",
                self.phase, frame
            ))),
        }
    }

    pub(crate) fn cancel(&mut self) -> Result<ChildAction> {
        match self.phase {
            ChildPhase::WaitingOffer => {
                self.phase = ChildPhase::CancellingWithoutOffer;
                Ok(ChildAction::SendCancel {
                    segment_generation: None,
                })
            }
            ChildPhase::Reading(generation) => {
                self.phase = ChildPhase::CancellingWithOffer(generation);
                Ok(ChildAction::SendCancel {
                    segment_generation: Some(generation),
                })
            }
            _ => Err(protocol("Child cancellation requested in the wrong state")),
        }
    }

    pub(crate) fn read_finished(
        &mut self,
        completed_length: u64,
        read_wr_count: u64,
    ) -> Result<ChildAction> {
        let ChildPhase::Reading(generation) = self.phase else {
            return Err(protocol("READ completed in the wrong Child state"));
        };
        if completed_length != self.length || read_wr_count == 0 {
            return Err(protocol("READ completion accounting mismatch"));
        }
        self.phase = ChildPhase::WaitingDone(generation);
        Ok(ChildAction::SendReadDone {
            segment_generation: generation,
        })
    }

    pub(crate) fn import_drained(
        &mut self,
        accepted_wr_count: u64,
        retired_wr_count: u64,
    ) -> Result<ChildAction> {
        if accepted_wr_count != retired_wr_count {
            return Err(protocol("Child import is not fully drained"));
        }
        let generation = match self.phase {
            ChildPhase::CancellingWithoutOffer => None,
            ChildPhase::CancellingWithOffer(generation) => Some(generation),
            _ => return Err(protocol("import drained in the wrong Child state")),
        };
        self.phase = ChildPhase::WaitingCancelled(generation);
        Ok(ChildAction::SendCancelDrained {
            segment_generation: generation,
        })
    }

    fn validate_offer(&self, offer: &ReadSegmentOffer) -> Result<()> {
        offer.validate()?;
        if offer.length != self.length || offer.effective_max_read_size > self.max_read_size {
            return Err(protocol("SegmentOffer length or READ limit mismatch"));
        }
        Ok(())
    }

    fn match_identity(&self, received: ReadTransferIdentity) -> Result<()> {
        if received != self.identity {
            return Err(protocol("READ transfer identity/generation mismatch"));
        }
        Ok(())
    }
}

/// Bounded duplicate-terminal filter. Capacity is fixed by session admission;
/// eviction permits only ancient duplicates to fail closed as unknown.
pub(crate) struct ReadTombstones {
    capacity: usize,
    order: VecDeque<(ReadTransferIdentity, Option<u64>)>,
    entries: HashSet<(ReadTransferIdentity, Option<u64>)>,
}

impl ReadTombstones {
    pub(crate) fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(protocol("READ tombstone capacity is zero"));
        }
        Ok(Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            entries: HashSet::with_capacity(capacity),
        })
    }

    pub(crate) fn insert(
        &mut self,
        identity: ReadTransferIdentity,
        generation: Option<u64>,
    ) -> Result<()> {
        identity.validate()?;
        if generation == Some(0) {
            return Err(protocol("zero tombstone generation"));
        }
        let key = (identity, generation);
        if self.entries.insert(key) {
            self.order.push_back(key);
            if self.order.len() > self.capacity {
                let evicted = self.order.pop_front().expect("over-capacity tombstone");
                self.entries.remove(&evicted);
            }
        }
        Ok(())
    }

    pub(crate) fn contains(&self, identity: ReadTransferIdentity, generation: Option<u64>) -> bool {
        self.entries.contains(&(identity, generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: ReadTransferIdentity = ReadTransferIdentity {
        peer_generation: 3,
        transfer_id: 17,
        metadata_generation: 9,
    };

    fn offer(generation: u64) -> ReadSegmentOffer {
        ReadSegmentOffer {
            descriptor_version: READ_DESCRIPTOR_VERSION,
            eid: [7; EID_LENGTH],
            uasid: 4,
            va: 0x1000,
            length: 64 * 1024,
            token_id: 5,
            access: 1,
            token_policy: 0,
            token: 0xfeed_beef,
            segment_generation: generation,
            effective_max_read_size: 4096,
        }
    }

    fn segment_offer(generation: u64) -> ReadFrame {
        ReadFrame::SegmentOffer {
            identity: ID,
            offer: offer(generation),
        }
    }

    #[test]
    fn read_frames_round_trip_without_exposing_token_in_debug() {
        let frames = [
            ReadFrame::BufferReady {
                identity: ID,
                accepted_length: 64 * 1024,
            },
            segment_offer(11),
            ReadFrame::ReadDone {
                identity: ID,
                segment_generation: 11,
                completed_length: 64 * 1024,
                read_wr_count: 16,
            },
            ReadFrame::Done {
                identity: ID,
                segment_generation: 11,
            },
            ReadFrame::Cancel {
                identity: ID,
                segment_generation: None,
                reason: "caller cancelled".into(),
            },
            ReadFrame::CancelDrained {
                identity: ID,
                segment_generation: Some(11),
                accepted_wr_count: 8,
                retired_wr_count: 8,
            },
            ReadFrame::Cancelled {
                identity: ID,
                segment_generation: Some(11),
            },
        ];
        for frame in frames {
            let (kind, payload) = frame.encode().unwrap();
            assert_eq!(ReadFrame::decode(kind, &payload).unwrap(), frame);
        }
        assert!(!format!("{:?}", offer(11)).contains("feedbeef"));
    }

    #[test]
    fn normal_parent_and_child_lifecycle_requires_revoke_before_done() {
        let mut parent = ParentReadState::new(ID, 64 * 1024).unwrap();
        let mut child = ChildReadState::new(ID, 64 * 1024, 4096).unwrap();
        assert_eq!(
            parent
                .on_frame(&ReadFrame::BufferReady {
                    identity: ID,
                    accepted_length: 64 * 1024,
                })
                .unwrap(),
            ParentAction::RegisterSource
        );
        parent.offer_published(11).unwrap();
        assert_eq!(
            child.on_frame(&segment_offer(11)).unwrap(),
            ChildAction::StartRead
        );
        assert_eq!(
            child.read_finished(64 * 1024, 16).unwrap(),
            ChildAction::SendReadDone {
                segment_generation: 11
            }
        );
        assert_eq!(
            parent
                .on_frame(&ReadFrame::ReadDone {
                    identity: ID,
                    segment_generation: 11,
                    completed_length: 64 * 1024,
                    read_wr_count: 16,
                })
                .unwrap(),
            ParentAction::RevokeSource
        );
        assert_eq!(
            parent.source_released().unwrap(),
            ParentAction::SendDone {
                segment_generation: 11
            }
        );
        let done = ReadFrame::Done {
            identity: ID,
            segment_generation: 11,
        };
        assert_eq!(child.on_frame(&done).unwrap(), ChildAction::Complete);
        assert_eq!(
            child.on_frame(&done).unwrap(),
            ChildAction::DuplicateTerminal
        );
    }

    #[test]
    fn cancel_before_offer_consumes_late_offer_without_starting_read() {
        let mut child = ChildReadState::new(ID, 64 * 1024, 4096).unwrap();
        assert_eq!(
            child.cancel().unwrap(),
            ChildAction::SendCancel {
                segment_generation: None
            }
        );
        assert_eq!(
            child.import_drained(0, 0).unwrap(),
            ChildAction::SendCancelDrained {
                segment_generation: None
            }
        );
        assert_eq!(
            child.on_frame(&segment_offer(12)).unwrap(),
            ChildAction::DrainLateOffer {
                segment_generation: 12
            }
        );
        assert_eq!(
            child.import_drained(0, 0).unwrap(),
            ChildAction::SendCancelDrained {
                segment_generation: Some(12)
            }
        );
    }

    #[test]
    fn generations_counts_and_lengths_fail_closed() {
        let mut parent = ParentReadState::new(ID, 64 * 1024).unwrap();
        assert!(parent
            .on_frame(&ReadFrame::BufferReady {
                identity: ReadTransferIdentity {
                    peer_generation: 4,
                    ..ID
                },
                accepted_length: 64 * 1024,
            })
            .is_err());
        parent
            .on_frame(&ReadFrame::BufferReady {
                identity: ID,
                accepted_length: 64 * 1024,
            })
            .unwrap();
        parent.offer_published(11).unwrap();
        assert!(parent
            .on_frame(&ReadFrame::ReadDone {
                identity: ID,
                segment_generation: 12,
                completed_length: 64 * 1024,
                read_wr_count: 1,
            })
            .is_err());

        let invalid = ReadFrame::CancelDrained {
            identity: ID,
            segment_generation: Some(11),
            accepted_wr_count: 2,
            retired_wr_count: 3,
        };
        assert!(invalid.encode().is_err());
        assert!(ReadFrame::Done {
            identity: ID,
            segment_generation: 0,
        }
        .encode()
        .is_err());
    }

    #[test]
    fn offered_cancel_waits_for_matching_full_drain() {
        let mut parent = ParentReadState::new(ID, 64 * 1024).unwrap();
        parent
            .on_frame(&ReadFrame::BufferReady {
                identity: ID,
                accepted_length: 64 * 1024,
            })
            .unwrap();
        parent.offer_published(21).unwrap();
        assert_eq!(
            parent
                .on_frame(&ReadFrame::Cancel {
                    identity: ID,
                    segment_generation: Some(21),
                    reason: "deadline".into(),
                })
                .unwrap(),
            ParentAction::WaitForChildDrain
        );
        assert!(parent
            .on_frame(&ReadFrame::CancelDrained {
                identity: ID,
                segment_generation: Some(21),
                accepted_wr_count: 4,
                retired_wr_count: 3,
            })
            .is_err());
        assert_eq!(
            parent
                .on_frame(&ReadFrame::CancelDrained {
                    identity: ID,
                    segment_generation: Some(21),
                    accepted_wr_count: 4,
                    retired_wr_count: 4,
                })
                .unwrap(),
            ParentAction::RevokeSource
        );
        assert_eq!(
            parent.source_released().unwrap(),
            ParentAction::SendCancelled {
                segment_generation: Some(21)
            }
        );
    }

    #[test]
    fn tombstones_are_bounded_and_match_the_full_identity() {
        let mut tombstones = ReadTombstones::new(2).unwrap();
        tombstones.insert(ID, Some(1)).unwrap();
        tombstones.insert(ID, Some(2)).unwrap();
        tombstones.insert(ID, Some(3)).unwrap();
        assert!(!tombstones.contains(ID, Some(1)));
        assert!(tombstones.contains(ID, Some(2)));
        assert!(tombstones.contains(ID, Some(3)));
        assert!(!tombstones.contains(
            ReadTransferIdentity {
                metadata_generation: 10,
                ..ID
            },
            Some(3)
        ));
    }

    #[test]
    fn capability_codec_negotiates_the_smaller_read_limit() {
        let local = ReadCapability {
            max_read_size: 256 * 1024 * 1024,
            max_jfs_sge: 13,
            descriptor_version: READ_DESCRIPTOR_VERSION,
        };
        let remote = ReadCapability {
            max_read_size: 64 * 1024 * 1024,
            max_jfs_sge: 1,
            descriptor_version: READ_DESCRIPTOR_VERSION,
        };
        assert_eq!(
            local.effective_max_read_size(&remote).unwrap(),
            64 * 1024 * 1024
        );
        let mut payload = Vec::new();
        local.encode(&mut payload);
        let mut reader = WireReader::new(&payload);
        assert_eq!(ReadCapability::decode(&mut reader).unwrap(), local);
        reader.finish().unwrap();
    }

    #[tokio::test]
    async fn read_envelope_rejects_the_legacy_wire_version() {
        let frame = segment_offer(11);
        let (mut writer, mut reader) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        write_read_frame(&mut writer, &frame).await.unwrap();
        assert_eq!(read_read_frame(&mut reader).await.unwrap(), frame);

        let (kind, payload) = frame.encode().unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        write_envelope(
            &mut writer,
            super::super::rendezvous::MAGIC,
            READ_DFUR_VERSION - 1,
            kind,
            &payload,
            MAX_PAYLOAD_LENGTH,
        )
        .await
        .unwrap();
        assert!(read_read_frame(&mut reader).await.is_err());
    }

    #[test]
    fn child_cancel_after_offer_requires_matching_cancelled_generation() {
        let mut child = ChildReadState::new(ID, 64 * 1024, 4096).unwrap();
        child.on_frame(&segment_offer(31)).unwrap();
        assert_eq!(
            child.cancel().unwrap(),
            ChildAction::SendCancel {
                segment_generation: Some(31)
            }
        );
        assert!(child.import_drained(4, 3).is_err());
        assert_eq!(
            child.import_drained(4, 4).unwrap(),
            ChildAction::SendCancelDrained {
                segment_generation: Some(31)
            }
        );
        assert!(child
            .on_frame(&ReadFrame::Cancelled {
                identity: ID,
                segment_generation: Some(32),
            })
            .is_err());
        assert_eq!(
            child
                .on_frame(&ReadFrame::Cancelled {
                    identity: ID,
                    segment_generation: Some(31),
                })
                .unwrap(),
            ChildAction::Cancelled
        );
    }
}
