//! URMA control-plane wire contract built on the shared Piece rendezvous schema.
//!
//! TCP carries reliable control frames; only chunk bytes use the negotiated
//! RM Jetty. The sender may not post a SEND until a validated
//! `RecvPosted` window has granted matching remote receive credits.

use super::lane::{TpType, TransportMode};
use crate::rendezvous::{
    put_bytes, read_envelope, write_envelope, PayloadReader, MAX_PAYLOAD_LENGTH, MAX_STRING_LENGTH,
};
pub(crate) use crate::rendezvous::{
    PieceMetadata, PieceRequest as CommonPieceRequest, ReceiveWindow, RendezvousError,
};
use dragonfly_client_core::{Error, Result};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncWrite};

/// "DFUR" distinguishes URMA control traffic from the existing RDMA wire.
pub(crate) const MAGIC: u32 = 0x4446_5552;
// Version 2 scopes every Piece control frame to a logical transfer. This is
// the wire prerequisite for multiplexing several Pieces over one peer lane;
// version 1 implicitly allowed only one active Piece per lane.
// Version 3 explicitly identifies RM and rejects RC peers on this branch.
// Version 4 negotiates RTP versus CTP before provider import.
pub(crate) const VERSION: u8 = 4;
const MAX_DESCRIPTOR_LENGTH: usize = 64 * 1024;

pub(crate) type TransferId = u32;
pub(crate) const SESSION_TRANSFER_ID: TransferId = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrmaCapability {
    pub transport_type: u32,
    pub transport_mode: TransportMode,
    pub tp_type: TpType,
    pub fabric_tag: String,
    pub max_message_size: u64,
}

impl UrmaCapability {
    pub fn compatible(&self, remote: &Self) -> std::result::Result<(), String> {
        if self.transport_type != remote.transport_type {
            return Err(format!(
                "URMA transport mismatch: local {}, remote {}",
                self.transport_type, remote.transport_type
            ));
        }
        if self.transport_mode != remote.transport_mode {
            return Err(format!(
                "URMA mode mismatch: local {:?}, remote {:?}",
                self.transport_mode, remote.transport_mode
            ));
        }
        if self.tp_type != remote.tp_type {
            return Err(format!(
                "URMA TP type mismatch: local {:?}, remote {:?}",
                self.tp_type, remote.tp_type
            ));
        }
        if self.fabric_tag.is_empty() || remote.fabric_tag.is_empty() {
            return Err("missing URMA fabric tag".to_string());
        }
        if self.fabric_tag != remote.fabric_tag {
            return Err(format!(
                "URMA fabric tag mismatch: local {}, remote {}",
                self.fabric_tag, remote.fabric_tag
            ));
        }
        if self.max_message_size == 0 || remote.max_message_size == 0 {
            return Err("invalid URMA max message size".to_string());
        }
        Ok(())
    }

    fn encode(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.transport_type.to_be_bytes());
        payload.push(self.transport_mode.wire_value());
        payload.push(self.tp_type.wire_value());
        put_bytes(payload, self.fabric_tag.as_bytes());
        payload.extend_from_slice(&self.max_message_size.to_be_bytes());
    }

    fn decode(reader: &mut PayloadReader<'_>) -> Result<Self> {
        Ok(Self {
            transport_type: reader.u32()?,
            transport_mode: TransportMode::from_wire(reader.u8()?).map_err(Error::Unknown)?,
            tp_type: TpType::from_wire(reader.u8()?).map_err(Error::Unknown)?,
            fabric_tag: reader.string(MAX_STRING_LENGTH)?,
            max_message_size: reader.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrmaAdvertisement {
    pub capability: UrmaCapability,
    pub port: u16,
    /// Rendezvous port serving the RM-READ data plane (DFUR version 5). Zero
    /// means the parent has no READ capability; READ and legacy lanes share
    /// the same listener when both are served, so this usually equals `port`.
    pub read_port: u16,
}

/// Publishes URMA readiness to the already-advertised TCP Piece endpoint. The registry contains
/// an advertisement only after both the process Fabric and rendezvous listener are ready.
#[derive(Clone, Default)]
pub struct CapabilityRegistry {
    inner: Arc<RwLock<Option<UrmaAdvertisement>>>,
}

impl CapabilityRegistry {
    pub(crate) fn publish(&self, advertisement: UrmaAdvertisement) {
        *self.inner.write().unwrap() = Some(advertisement);
    }

    pub(crate) fn clear(&self) {
        *self.inner.write().unwrap() = None;
    }

    pub(crate) fn get(&self) -> Option<UrmaAdvertisement> {
        self.inner.read().unwrap().clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaneConnect {
    pub(crate) capability: UrmaCapability,
    pub(crate) client_descriptor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaneConnected {
    pub(crate) server_descriptor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    Connect(LaneConnect),
    Connected(LaneConnected),
    Request {
        transfer_id: TransferId,
        request: CommonPieceRequest,
    },
    Ready {
        transfer_id: TransferId,
        metadata: PieceMetadata,
    },
    RecvPosted {
        transfer_id: TransferId,
        window: ReceiveWindow,
    },
    Done {
        transfer_id: TransferId,
    },
    Error {
        transfer_id: TransferId,
        error: RendezvousError,
    },
    Discover,
    Capability(UrmaAdvertisement),
}

impl Frame {
    pub(crate) fn transfer_id(&self) -> Option<TransferId> {
        match self {
            Self::Request { transfer_id, .. }
            | Self::Ready { transfer_id, .. }
            | Self::RecvPosted { transfer_id, .. }
            | Self::Done { transfer_id }
            | Self::Error { transfer_id, .. } => Some(*transfer_id),
            Self::Connect(_) | Self::Connected(_) | Self::Discover | Self::Capability(_) => None,
        }
    }

    fn frame_type(&self) -> u8 {
        match self {
            Self::Connect(_) => 1,
            Self::Connected(_) => 2,
            Self::Request { .. } => 3,
            Self::Ready { .. } => 4,
            Self::RecvPosted { .. } => 5,
            Self::Done { .. } => 6,
            Self::Error { .. } => 7,
            Self::Discover => 8,
            Self::Capability(_) => 9,
        }
    }
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<()> {
    let mut payload = Vec::new();
    match frame {
        Frame::Discover => {}
        Frame::Capability(advertisement) => {
            advertisement.capability.encode(&mut payload);
            payload.extend_from_slice(&advertisement.port.to_be_bytes());
            payload.extend_from_slice(&advertisement.read_port.to_be_bytes());
        }
        Frame::Connect(connect) => {
            connect.capability.encode(&mut payload);
            put_bytes(&mut payload, &connect.client_descriptor);
        }
        Frame::Connected(connected) => {
            put_bytes(&mut payload, &connected.server_descriptor);
        }
        Frame::Request {
            transfer_id,
            request,
        } => {
            payload.extend_from_slice(&transfer_id.to_be_bytes());
            request.encode(&mut payload);
        }
        Frame::Ready {
            transfer_id,
            metadata,
        } => {
            payload.extend_from_slice(&transfer_id.to_be_bytes());
            metadata.encode(&mut payload);
        }
        Frame::RecvPosted {
            transfer_id,
            window,
        } => {
            payload.extend_from_slice(&transfer_id.to_be_bytes());
            window.encode(&mut payload);
        }
        Frame::Done { transfer_id } => payload.extend_from_slice(&transfer_id.to_be_bytes()),
        Frame::Error { transfer_id, error } => {
            payload.extend_from_slice(&transfer_id.to_be_bytes());
            error.encode(&mut payload);
        }
    }
    write_envelope(
        writer,
        MAGIC,
        VERSION,
        frame.frame_type(),
        &payload,
        MAX_PAYLOAD_LENGTH,
    )
    .await
}

pub(crate) async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let (frame_type, payload) = read_envelope(reader, MAGIC, VERSION, MAX_PAYLOAD_LENGTH).await?;
    let mut reader = PayloadReader::new(&payload);
    let frame = match frame_type {
        1 => Frame::Connect(LaneConnect {
            capability: UrmaCapability::decode(&mut reader)?,
            client_descriptor: reader.bytes(MAX_DESCRIPTOR_LENGTH)?,
        }),
        2 => Frame::Connected(LaneConnected {
            server_descriptor: reader.bytes(MAX_DESCRIPTOR_LENGTH)?,
        }),
        3 => Frame::Request {
            transfer_id: reader.u32()?,
            request: CommonPieceRequest::decode(&mut reader)?,
        },
        4 => Frame::Ready {
            transfer_id: reader.u32()?,
            metadata: PieceMetadata::decode(&mut reader)?,
        },
        5 => {
            let transfer_id = reader.u32()?;
            let window = ReceiveWindow::decode(&mut reader)?;
            window.validate(window.start_chunk, u64::MAX)?;
            Frame::RecvPosted {
                transfer_id,
                window,
            }
        }
        6 => Frame::Done {
            transfer_id: reader.u32()?,
        },
        7 => Frame::Error {
            transfer_id: reader.u32()?,
            error: RendezvousError::decode(&mut reader)?,
        },
        8 => Frame::Discover,
        9 => Frame::Capability(UrmaAdvertisement {
            capability: UrmaCapability::decode(&mut reader)?,
            port: reader.u16()?,
            // Older parents end their payload after the legacy port; a short
            // payload decodes as "no READ plane".
            read_port: reader.u16().unwrap_or(0),
        }),
        _ => {
            return Err(Error::Unknown(format!(
                "unknown URMA rendezvous frame type: {frame_type}"
            )));
        }
    };
    reader.finish()?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::PieceKind;

    async fn round_trip(frame: Frame) -> Frame {
        let (mut writer, mut reader) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        write_frame(&mut writer, &frame).await.unwrap();
        read_frame(&mut reader).await.unwrap()
    }

    fn capability() -> UrmaCapability {
        UrmaCapability {
            transport_type: 3,
            transport_mode: TransportMode::Rm,
            tp_type: TpType::Rtp,
            fabric_tag: "rack-a".into(),
            max_message_size: 64 * 1024,
        }
    }

    #[test]
    fn capability_registry_tracks_listener_lifetime() {
        let registry = CapabilityRegistry::default();
        assert!(registry.get().is_none());
        let advertisement = UrmaAdvertisement {
            capability: capability(),
            port: 4008,
            read_port: 0,
        };
        registry.publish(advertisement.clone());
        assert_eq!(registry.get(), Some(advertisement));
        registry.clear();
        assert!(registry.get().is_none());
    }

    #[tokio::test]
    async fn round_trips_urma_frames() {
        let connect = Frame::Connect(LaneConnect {
            capability: capability(),
            client_descriptor: vec![1, 2, 3],
        });
        assert_eq!(round_trip(connect.clone()).await, connect);

        let connected = Frame::Connected(LaneConnected {
            server_descriptor: vec![4, 5, 6],
        });
        assert_eq!(round_trip(connected.clone()).await, connected);

        let request = Frame::Request {
            transfer_id: 17,
            request: CommonPieceRequest {
                kind: PieceKind::PersistentPiece,
                task_id: "task-a".into(),
                piece_number: 7,
                chunk_size: 64 * 1024,
                max_inflight_chunks: 8,
            },
        };
        assert_eq!(round_trip(request.clone()).await, request);

        let ready = Frame::Ready {
            transfer_id: 17,
            metadata: PieceMetadata {
                offset: 11,
                length: 1024,
                digest: "crc32:42".into(),
                chunk_size: 512,
                max_inflight_chunks: 2,
            },
        };
        assert_eq!(round_trip(ready.clone()).await, ready);

        let posted = Frame::RecvPosted {
            transfer_id: 17,
            window: ReceiveWindow {
                start_chunk: 0,
                chunk_count: 2,
            },
        };
        assert_eq!(round_trip(posted.clone()).await, posted);
    }

    #[tokio::test]
    async fn one_lane_can_carry_multiple_piece_requests() {
        let (mut client, mut server) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        let first = Frame::Request {
            transfer_id: 1,
            request: CommonPieceRequest {
                kind: PieceKind::Piece,
                task_id: "task-a".into(),
                piece_number: 1,
                chunk_size: 4096,
                max_inflight_chunks: 2,
            },
        };
        let second = Frame::Request {
            transfer_id: 2,
            request: CommonPieceRequest {
                kind: PieceKind::Piece,
                task_id: "task-a".into(),
                piece_number: 2,
                chunk_size: 4096,
                max_inflight_chunks: 2,
            },
        };

        write_frame(&mut client, &first).await.unwrap();
        write_frame(&mut client, &Frame::Done { transfer_id: 1 })
            .await
            .unwrap();
        write_frame(&mut client, &second).await.unwrap();

        assert_eq!(read_frame(&mut server).await.unwrap(), first);
        assert_eq!(
            read_frame(&mut server).await.unwrap(),
            Frame::Done { transfer_id: 1 }
        );
        assert_eq!(read_frame(&mut server).await.unwrap(), second);
    }

    #[tokio::test]
    async fn transfer_ids_preserve_interleaved_piece_identity() {
        let (mut client, mut server) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        let frames = [
            Frame::Done { transfer_id: 2 },
            Frame::RecvPosted {
                transfer_id: 1,
                window: ReceiveWindow {
                    start_chunk: 4,
                    chunk_count: 2,
                },
            },
            Frame::Error {
                transfer_id: 2,
                error: RendezvousError {
                    code: 9,
                    message: "piece-local failure".into(),
                },
            },
        ];

        for frame in &frames {
            write_frame(&mut client, frame).await.unwrap();
        }
        for expected in frames {
            assert_eq!(read_frame(&mut server).await.unwrap(), expected);
        }
    }

    #[test]
    fn capability_is_fail_closed() {
        let local = capability();
        assert!(local.compatible(&local).is_ok());
        let mut remote = local.clone();
        remote.fabric_tag = "rack-b".into();
        assert!(local.compatible(&remote).is_err());
        let mut remote = local.clone();
        remote.tp_type = TpType::Ctp;
        assert!(local.compatible(&remote).is_err());
    }

    #[test]
    fn transport_mode_wire_values_match_umdks_public_api() {
        assert_eq!(TransportMode::from_wire(1).unwrap(), TransportMode::Rm);
        assert!(TransportMode::from_wire(2).is_err());
        assert!(TransportMode::from_wire(0).is_err());
        assert_eq!(TpType::from_wire(0).unwrap(), TpType::Rtp);
        assert_eq!(TpType::from_wire(1).unwrap(), TpType::Ctp);
        assert!(TpType::from_wire(2).is_err());
    }
}
