//! URMA control-plane wire contract built on the shared Piece rendezvous schema.
//!
//! TCP carries reliable control frames; only chunk bytes use the bound RC
//! Jetty. The sender may not post a SEND until a validated `RecvPosted` window
//! has granted matching remote receive credits.

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
pub(crate) const VERSION: u8 = 1;
const MAX_DESCRIPTOR_LENGTH: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrmaCapability {
    pub transport_type: u32,
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
        put_bytes(payload, self.fabric_tag.as_bytes());
        payload.extend_from_slice(&self.max_message_size.to_be_bytes());
    }

    fn decode(reader: &mut PayloadReader<'_>) -> Result<Self> {
        Ok(Self {
            transport_type: reader.u32()?,
            fabric_tag: reader.string(MAX_STRING_LENGTH)?,
            max_message_size: reader.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrmaAdvertisement {
    pub capability: UrmaCapability,
    pub port: u16,
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
    Request(CommonPieceRequest),
    Ready(PieceMetadata),
    RecvPosted(ReceiveWindow),
    Done,
    Error(RendezvousError),
    Discover,
    Capability(UrmaAdvertisement),
}

impl Frame {
    fn frame_type(&self) -> u8 {
        match self {
            Self::Connect(_) => 1,
            Self::Connected(_) => 2,
            Self::Request(_) => 3,
            Self::Ready(_) => 4,
            Self::RecvPosted(_) => 5,
            Self::Done => 6,
            Self::Error(_) => 7,
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
        Frame::Discover | Frame::Done => {}
        Frame::Capability(advertisement) => {
            advertisement.capability.encode(&mut payload);
            payload.extend_from_slice(&advertisement.port.to_be_bytes());
        }
        Frame::Connect(connect) => {
            connect.capability.encode(&mut payload);
            put_bytes(&mut payload, &connect.client_descriptor);
        }
        Frame::Connected(connected) => {
            put_bytes(&mut payload, &connected.server_descriptor);
        }
        Frame::Request(request) => request.encode(&mut payload),
        Frame::Ready(metadata) => metadata.encode(&mut payload),
        Frame::RecvPosted(window) => window.encode(&mut payload),
        Frame::Error(error) => error.encode(&mut payload),
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
        3 => Frame::Request(CommonPieceRequest::decode(&mut reader)?),
        4 => Frame::Ready(PieceMetadata::decode(&mut reader)?),
        5 => {
            let window = ReceiveWindow::decode(&mut reader)?;
            window.validate(window.start_chunk, u64::MAX)?;
            Frame::RecvPosted(window)
        }
        6 => Frame::Done,
        7 => Frame::Error(RendezvousError::decode(&mut reader)?),
        8 => Frame::Discover,
        9 => Frame::Capability(UrmaAdvertisement {
            capability: UrmaCapability::decode(&mut reader)?,
            port: reader.u16()?,
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

        let request = Frame::Request(CommonPieceRequest {
            kind: PieceKind::PersistentPiece,
            task_id: "task-a".into(),
            piece_number: 7,
            chunk_size: 64 * 1024,
            max_inflight_chunks: 8,
        });
        assert_eq!(round_trip(request.clone()).await, request);

        let ready = Frame::Ready(PieceMetadata {
            offset: 11,
            length: 1024,
            digest: "crc32:42".into(),
            chunk_size: 512,
            max_inflight_chunks: 2,
        });
        assert_eq!(round_trip(ready.clone()).await, ready);

        let posted = Frame::RecvPosted(ReceiveWindow {
            start_chunk: 0,
            chunk_count: 2,
        });
        assert_eq!(round_trip(posted.clone()).await, posted);
    }

    #[tokio::test]
    async fn one_lane_can_carry_multiple_piece_requests() {
        let (mut client, mut server) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        let first = Frame::Request(CommonPieceRequest {
            kind: PieceKind::Piece,
            task_id: "task-a".into(),
            piece_number: 1,
            chunk_size: 4096,
            max_inflight_chunks: 2,
        });
        let second = Frame::Request(CommonPieceRequest {
            kind: PieceKind::Piece,
            task_id: "task-a".into(),
            piece_number: 2,
            chunk_size: 4096,
            max_inflight_chunks: 2,
        });

        write_frame(&mut client, &first).await.unwrap();
        write_frame(&mut client, &Frame::Done).await.unwrap();
        write_frame(&mut client, &second).await.unwrap();

        assert_eq!(read_frame(&mut server).await.unwrap(), first);
        assert_eq!(read_frame(&mut server).await.unwrap(), Frame::Done);
        assert_eq!(read_frame(&mut server).await.unwrap(), second);
    }

    #[test]
    fn capability_is_fail_closed() {
        let local = capability();
        assert!(local.compatible(&local).is_ok());
        let mut remote = local.clone();
        remote.fabric_tag = "rack-b".into();
        assert!(local.compatible(&remote).is_err());
    }
}
