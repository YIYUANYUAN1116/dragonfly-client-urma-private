/*
 *     Copyright 2026 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Wire protocol for the RDMA rendezvous channel.
//!
//! Control messages (piece request, capability exchange, metadata, readiness, errors) ride
//! a plain TCP connection to the parent's RDMA rendezvous port; only bulk piece bytes move
//! over libfabric. Keeping control on TCP gives reliable framing for messages that must not
//! be lost, sidesteps EFA's limited unexpected-message buffering, and makes falling back to
//! the TCP piece transport trivial.
//!
//! Framing: magic (u32) | version (u8) | frame type (u8) | payload length (u32) | payload.
//! All integers are big-endian. Payload fields are fixed-width integers and
//! length-prefixed byte strings with hard caps, so a malicious peer cannot force large
//! allocations.

use crate::rendezvous::{
    put_bytes, read_envelope, write_envelope, PayloadReader, MAX_STRING_LENGTH,
};
pub use crate::rendezvous::{
    PieceKind, PieceMetadata as CommonPieceMetadata, PieceRequest as CommonPieceRequest,
    ReceiveWindow, RendezvousError, ERROR_CODE_BUSY, ERROR_CODE_INCOMPATIBLE, ERROR_CODE_INTERNAL,
    ERROR_CODE_NOT_FOUND, ERROR_CODE_TOO_LARGE,
};
use dragonfly_client_core::{Error, Result};
use std::{
    ops::Deref,
    sync::{Arc, RwLock},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// MAGIC identifies a Dragonfly RDMA rendezvous frame ("DFRD").
pub const MAGIC: u32 = 0x4446_5244;

/// VERSION is the rendezvous wire-contract version. Peers with different versions must
/// fall back to TCP.
pub const VERSION: u8 = 2;

/// MAX_ENDPOINT_LENGTH caps provider-opaque endpoint addresses.
const MAX_ENDPOINT_LENGTH: usize = 512;

/// MAX_PAYLOAD_LENGTH caps a whole frame payload.
const MAX_PAYLOAD_LENGTH: usize = 64 * 1024;

/// WireCapability describes one side of a prospective fabric pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireCapability {
    /// provider is the concrete libfabric provider name (e.g. "efa", "verbs;ofi_rxm").
    pub provider: String,

    /// fabric_tag is the operator-supplied reachability-domain label.
    pub fabric_tag: String,
}

/// RdmaAdvertisement is returned on the already-advertised TCP piece port so downloaders learn
/// the actual RDMA rendezvous port and only attempt compatible, initialized parents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaAdvertisement {
    /// capability is the concrete provider and reachability domain currently serving requests.
    pub capability: WireCapability,

    /// port is the parent's RDMA rendezvous listener port.
    pub port: u16,
}

/// CapabilityRegistry publishes RDMA readiness to the TCP piece server. A value is present only
/// after the RDMA fabric and rendezvous listener have both initialized successfully.
#[derive(Clone, Default)]
pub struct CapabilityRegistry {
    inner: Arc<RwLock<Option<RdmaAdvertisement>>>,
}

impl CapabilityRegistry {
    /// publish replaces the current ready advertisement.
    pub fn publish(&self, advertisement: RdmaAdvertisement) {
        *self.inner.write().unwrap() = Some(advertisement);
    }

    /// clear removes the advertisement when the listener exits.
    pub fn clear(&self) {
        *self.inner.write().unwrap() = None;
    }

    /// get returns the current ready advertisement.
    pub fn get(&self) -> Option<RdmaAdvertisement> {
        self.inner.read().unwrap().clone()
    }
}

impl WireCapability {
    /// compatible fails closed: peers form a fabric pair only with identical providers and
    /// identical, non-empty fabric tags. An EFA endpoint is never compatible with a verbs
    /// endpoint even though both speak libfabric.
    pub fn compatible(&self, remote: &WireCapability) -> std::result::Result<(), String> {
        if self.provider.is_empty() || remote.provider.is_empty() {
            return Err("missing provider".to_string());
        }
        if self.provider != remote.provider {
            return Err(format!(
                "provider mismatch: local {}, remote {}",
                self.provider, remote.provider
            ));
        }
        if self.fabric_tag.is_empty() || remote.fabric_tag.is_empty() {
            return Err("missing fabric tag".to_string());
        }
        if self.fabric_tag != remote.fabric_tag {
            return Err(format!(
                "fabric tag mismatch: local {}, remote {}",
                self.fabric_tag, remote.fabric_tag
            ));
        }
        Ok(())
    }
}

/// PieceRequest asks a parent for one piece over the fabric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceRequest {
    /// Transport-neutral Piece identity and requested transfer window.
    pub common: CommonPieceRequest,

    /// capability describes the downloader's fabric endpoint.
    pub capability: WireCapability,

    /// client_endpoint is the downloader's provider-opaque endpoint address.
    pub client_endpoint: Vec<u8>,

    /// tag is the base tag for the transfer; chunk i uses tag + i.
    pub tag: u64,
}

impl Deref for PieceRequest {
    type Target = CommonPieceRequest;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

/// PieceReady tells the downloader the parent is ready to send the piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceReady {
    /// Transport-neutral Piece metadata and negotiated transfer window.
    pub common: CommonPieceMetadata,

    /// server_endpoint is the parent's provider-opaque endpoint address.
    pub server_endpoint: Vec<u8>,
}

impl Deref for PieceReady {
    type Target = CommonPieceMetadata;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

/// Frame is one rendezvous message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Discover asks the normal TCP piece server for its current RDMA advertisement.
    Discover,

    /// Capability returns the concrete provider and rendezvous port of a ready RDMA server.
    Capability(RdmaAdvertisement),

    /// Request initiates a piece transfer (client to parent).
    Request(PieceRequest),

    /// Ready reports piece metadata and the parent endpoint (parent to client).
    Ready(PieceReady),

    /// RecvPosted grants permission to send one contiguous chunk window. The parent must not
    /// send the window before this arrives (EFA has limited unexpected-message buffering).
    RecvPosted(ReceiveWindow),

    /// Done signals all fabric sends completed (parent to client).
    Done,

    /// Error aborts the transfer.
    Error(RendezvousError),
}

impl Frame {
    /// frame_type returns the wire discriminant.
    fn frame_type(&self) -> u8 {
        match self {
            Frame::Discover => 6,
            Frame::Capability(_) => 7,
            Frame::Request(_) => 1,
            Frame::Ready(_) => 2,
            Frame::RecvPosted(_) => 3,
            Frame::Done => 4,
            Frame::Error(_) => 5,
        }
    }
}

/// write_frame encodes and sends one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    let mut payload = Vec::new();
    match frame {
        Frame::Discover => {}
        Frame::Capability(advertisement) => {
            put_bytes(&mut payload, advertisement.capability.provider.as_bytes());
            put_bytes(&mut payload, advertisement.capability.fabric_tag.as_bytes());
            payload.extend_from_slice(&advertisement.port.to_be_bytes());
        }
        Frame::Request(request) => {
            payload.push(request.common.kind.into());
            put_bytes(&mut payload, request.task_id.as_bytes());
            payload.extend_from_slice(&request.piece_number.to_be_bytes());
            put_bytes(&mut payload, request.capability.provider.as_bytes());
            put_bytes(&mut payload, request.capability.fabric_tag.as_bytes());
            put_bytes(&mut payload, &request.client_endpoint);
            payload.extend_from_slice(&request.tag.to_be_bytes());
            payload.extend_from_slice(&request.chunk_size.to_be_bytes());
            payload.extend_from_slice(&request.max_inflight_chunks.to_be_bytes());
        }
        Frame::Ready(ready) => {
            payload.extend_from_slice(&ready.offset.to_be_bytes());
            payload.extend_from_slice(&ready.length.to_be_bytes());
            put_bytes(&mut payload, ready.digest.as_bytes());
            put_bytes(&mut payload, &ready.server_endpoint);
            payload.extend_from_slice(&ready.chunk_size.to_be_bytes());
            payload.extend_from_slice(&ready.max_inflight_chunks.to_be_bytes());
        }
        Frame::RecvPosted(window) => window.encode(&mut payload),
        Frame::Done => {}
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

/// read_frame reads and decodes one frame. A version mismatch is reported as an
/// incompatibility so callers fall back to TCP.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let (frame_type, payload) = read_envelope(reader, MAGIC, VERSION, MAX_PAYLOAD_LENGTH).await?;
    let mut reader = PayloadReader::new(&payload);

    let frame = match frame_type {
        1 => {
            let kind = reader.u8()?.try_into()?;
            let task_id = reader.string(crate::rendezvous::MAX_TASK_ID_LENGTH)?;
            let piece_number = reader.u32()?;
            let capability = WireCapability {
                provider: reader.string(MAX_STRING_LENGTH)?,
                fabric_tag: reader.string(MAX_STRING_LENGTH)?,
            };
            let client_endpoint = reader.bytes(MAX_ENDPOINT_LENGTH)?;
            let tag = reader.u64()?;
            let chunk_size = reader.u64()?;
            let max_inflight_chunks = reader.u32()?;
            Frame::Request(PieceRequest {
                common: CommonPieceRequest {
                    kind,
                    task_id,
                    piece_number,
                    chunk_size,
                    max_inflight_chunks,
                },
                capability,
                client_endpoint,
                tag,
            })
        }
        2 => {
            let offset = reader.u64()?;
            let length = reader.u64()?;
            let digest = reader.string(MAX_STRING_LENGTH)?;
            let server_endpoint = reader.bytes(MAX_ENDPOINT_LENGTH)?;
            let chunk_size = reader.u64()?;
            let max_inflight_chunks = reader.u32()?;
            Frame::Ready(PieceReady {
                common: CommonPieceMetadata {
                    offset,
                    length,
                    digest,
                    chunk_size,
                    max_inflight_chunks,
                },
                server_endpoint,
            })
        }
        3 => {
            let window = ReceiveWindow::decode(&mut reader)?;
            window.validate(window.start_chunk, u64::MAX)?;
            Frame::RecvPosted(window)
        }
        4 => Frame::Done,
        5 => Frame::Error(RendezvousError::decode(&mut reader)?),
        6 => Frame::Discover,
        7 => Frame::Capability(RdmaAdvertisement {
            capability: WireCapability {
                provider: reader.string(MAX_STRING_LENGTH)?,
                fabric_tag: reader.string(MAX_STRING_LENGTH)?,
            },
            port: reader.u16()?,
        }),
        _ => {
            return Err(Error::Unknown(format!(
                "unknown rendezvous frame type: {frame_type}"
            )));
        }
    };
    reader.finish()?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// roundtrip encodes and decodes a frame through an in-memory duplex pipe.
    async fn roundtrip(frame: Frame) -> Frame {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024 + 1024);
        write_frame(&mut client, &frame).await.unwrap();
        read_frame(&mut server).await.unwrap()
    }

    #[tokio::test]
    async fn roundtrips_all_frames() {
        assert_eq!(roundtrip(Frame::Discover).await, Frame::Discover);

        let advertisement = Frame::Capability(RdmaAdvertisement {
            capability: WireCapability {
                provider: "efa".to_string(),
                fabric_tag: "vpc-1/use1-az1".to_string(),
            },
            port: 4007,
        });
        assert_eq!(roundtrip(advertisement.clone()).await, advertisement);

        let request = Frame::Request(PieceRequest {
            common: CommonPieceRequest {
                kind: PieceKind::PersistentCachePiece,
                task_id: "task-123".to_string(),
                piece_number: 42,
                chunk_size: 4 * 1024 * 1024,
                max_inflight_chunks: 16,
            },
            capability: WireCapability {
                provider: "efa".to_string(),
                fabric_tag: "vpc-1/use1-az1".to_string(),
            },
            client_endpoint: vec![1, 2, 3, 4],
            tag: 0xdead_beef_dead_beef,
        });
        assert_eq!(roundtrip(request.clone()).await, request);

        let ready = Frame::Ready(PieceReady {
            common: CommonPieceMetadata {
                offset: 128,
                length: 4096,
                digest: "crc32:12345678".to_string(),
                chunk_size: 1024 * 1024,
                max_inflight_chunks: 8,
            },
            server_endpoint: vec![9, 8, 7],
        });
        assert_eq!(roundtrip(ready.clone()).await, ready);

        let recv_posted = Frame::RecvPosted(ReceiveWindow {
            start_chunk: 32,
            chunk_count: 8,
        });
        assert_eq!(roundtrip(recv_posted.clone()).await, recv_posted);
        assert_eq!(roundtrip(Frame::Done).await, Frame::Done);

        let error = Frame::Error(RendezvousError {
            code: ERROR_CODE_INCOMPATIBLE,
            message: "provider mismatch".to_string(),
        });
        assert_eq!(roundtrip(error.clone()).await, error);
    }

    #[tokio::test]
    async fn request_keeps_the_v2_wire_field_order() {
        let frame = Frame::Request(PieceRequest {
            common: CommonPieceRequest {
                kind: PieceKind::Piece,
                task_id: "t".into(),
                piece_number: 2,
                chunk_size: 3,
                max_inflight_chunks: 4,
            },
            capability: WireCapability {
                provider: "p".into(),
                fabric_tag: "f".into(),
            },
            client_endpoint: vec![5],
            tag: 6,
        });
        let mut payload = Vec::new();
        payload.push(0);
        put_bytes(&mut payload, b"t");
        payload.extend_from_slice(&2u32.to_be_bytes());
        put_bytes(&mut payload, b"p");
        put_bytes(&mut payload, b"f");
        put_bytes(&mut payload, &[5]);
        payload.extend_from_slice(&6u64.to_be_bytes());
        payload.extend_from_slice(&3u64.to_be_bytes());
        payload.extend_from_slice(&4u32.to_be_bytes());

        let mut expected = Vec::new();
        expected.extend_from_slice(&MAGIC.to_be_bytes());
        expected.push(VERSION);
        expected.push(1);
        expected.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        expected.extend_from_slice(&payload);

        let (mut writer, mut reader) = tokio::io::duplex(128);
        write_frame(&mut writer, &frame).await.unwrap();
        let mut actual = vec![0; expected.len()];
        reader.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn rejects_bad_magic_and_version() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&[0xff; 10]).await.unwrap();
        assert!(read_frame(&mut server).await.is_err());

        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut header = Vec::new();
        header.extend_from_slice(&MAGIC.to_be_bytes());
        header.push(VERSION + 1);
        header.push(3);
        header.extend_from_slice(&0u32.to_be_bytes());
        client.write_all(&header).await.unwrap();
        let err = read_frame(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("version mismatch"));
    }

    #[tokio::test]
    async fn rejects_oversized_fields() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut header = Vec::new();
        header.extend_from_slice(&MAGIC.to_be_bytes());
        header.push(VERSION);
        header.push(1);
        header.extend_from_slice(&(MAX_PAYLOAD_LENGTH as u32 + 1).to_be_bytes());
        client.write_all(&header).await.unwrap();
        assert!(read_frame(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn rejects_trailing_payload_bytes() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MAGIC.to_be_bytes());
        frame.push(VERSION);
        frame.push(Frame::Done.frame_type());
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.push(0xff);
        client.write_all(&frame).await.unwrap();

        let err = read_frame(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("trailing payload"));
    }

    #[test]
    fn capability_compatibility_fails_closed() {
        let efa = WireCapability {
            provider: "efa".to_string(),
            fabric_tag: "vpc-1/use1-az1".to_string(),
        };
        assert!(efa.compatible(&efa.clone()).is_ok());

        let verbs = WireCapability {
            provider: "verbs;ofi_rxm".to_string(),
            ..efa.clone()
        };
        assert!(efa.compatible(&verbs).is_err());

        let other_az = WireCapability {
            fabric_tag: "vpc-1/use1-az2".to_string(),
            ..efa.clone()
        };
        assert!(efa.compatible(&other_az).is_err());

        let untagged = WireCapability {
            fabric_tag: String::new(),
            ..efa.clone()
        };
        assert!(efa.compatible(&untagged).is_err());
        assert!(untagged.compatible(&untagged.clone()).is_err());
    }
}
