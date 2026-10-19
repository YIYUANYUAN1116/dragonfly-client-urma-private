//! DFUR v4 discovery over TCP. Bulk transfer uses the separate v6 READ lane.

use super::lane::{TpType, TransportMode};
pub use crate::rendezvous::PieceKind;
pub(crate) use crate::rendezvous::RendezvousError;
use crate::rendezvous::{
    put_bytes, read_envelope, write_envelope, PayloadReader, MAX_PAYLOAD_LENGTH, MAX_STRING_LENGTH,
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
    /// Rendezvous port serving the RM-READ data plane (DFUR version 6). Zero
    /// means the parent has no READ capability. A READ-only parent sets
    /// this to its READ listener port.
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
pub(crate) enum Frame {
    Error {
        transfer_id: TransferId,
        error: RendezvousError,
    },
    Discover,
    Capability(UrmaAdvertisement),
}

impl Frame {
    fn frame_type(&self) -> u8 {
        match self {
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
    async fn discovery_wire_keeps_v4_types_and_ports() {
        assert_eq!(VERSION, 4);
        assert_eq!(Frame::Discover.frame_type(), 8);
        let advertisement = Frame::Capability(UrmaAdvertisement {
            capability: capability(),
            port: 4008,
            read_port: 4008,
        });
        assert_eq!(advertisement.frame_type(), 9);
        assert_eq!(round_trip(advertisement.clone()).await, advertisement);
        assert_eq!(round_trip(Frame::Discover).await, Frame::Discover);
    }

    #[tokio::test]
    async fn older_v4_advertisement_has_no_read_plane() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let mut payload = Vec::new();
        capability().encode(&mut payload);
        payload.extend_from_slice(&4008u16.to_be_bytes());
        write_envelope(&mut writer, MAGIC, VERSION, 9, &payload, MAX_PAYLOAD_LENGTH)
            .await
            .unwrap();
        let Frame::Capability(advertisement) = read_frame(&mut reader).await.unwrap() else {
            panic!("expected capability");
        };
        assert_eq!(advertisement.port, 4008);
        assert_eq!(advertisement.read_port, 0);
    }

    #[tokio::test]
    async fn v4_send_recv_connect_is_rejected() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        write_envelope(&mut writer, MAGIC, VERSION, 1, &[], MAX_PAYLOAD_LENGTH)
            .await
            .unwrap();
        assert!(read_frame(&mut reader).await.is_err());
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
