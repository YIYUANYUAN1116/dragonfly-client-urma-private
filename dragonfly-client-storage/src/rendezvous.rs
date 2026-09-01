//! Transport-neutral control-plane primitives shared by native piece transports.
//!
//! This module owns only reliable framing and Dragonfly Piece/window semantics.
//! Provider compatibility, endpoint descriptors and data-plane operation ids
//! remain in the transport-specific URMA rendezvous module.

use dragonfly_client_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const HEADER_LENGTH: usize = 10;
pub(crate) const MAX_TASK_ID_LENGTH: usize = 4096;
pub(crate) const MAX_STRING_LENGTH: usize = 4096;
pub(crate) const MAX_PAYLOAD_LENGTH: usize = 128 * 1024;

pub const ERROR_CODE_INCOMPATIBLE: u32 = 1;
pub const ERROR_CODE_NOT_FOUND: u32 = 2;
pub const ERROR_CODE_INTERNAL: u32 = 3;
pub const ERROR_CODE_TOO_LARGE: u32 = 4;
pub const ERROR_CODE_BUSY: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceKind {
    Piece,
    PersistentPiece,
    PersistentCachePiece,
}

impl TryFrom<u8> for PieceKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Piece),
            1 => Ok(Self::PersistentPiece),
            2 => Ok(Self::PersistentCachePiece),
            _ => Err(Error::Unknown(format!("invalid piece kind: {value}"))),
        }
    }
}

impl From<PieceKind> for u8 {
    fn from(value: PieceKind) -> Self {
        match value {
            PieceKind::Piece => 0,
            PieceKind::PersistentPiece => 1,
            PieceKind::PersistentCachePiece => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceRequest {
    pub kind: PieceKind,
    pub task_id: String,
    pub piece_number: u32,
    pub chunk_size: u64,
    pub max_inflight_chunks: u32,
}

impl PieceRequest {
    #[cfg(feature = "urma")]
    pub(crate) fn encode(&self, payload: &mut Vec<u8>) {
        payload.push(self.kind.into());
        put_bytes(payload, self.task_id.as_bytes());
        payload.extend_from_slice(&self.piece_number.to_be_bytes());
        payload.extend_from_slice(&self.chunk_size.to_be_bytes());
        payload.extend_from_slice(&self.max_inflight_chunks.to_be_bytes());
    }

    #[cfg(feature = "urma")]
    pub(crate) fn decode(reader: &mut PayloadReader<'_>) -> Result<Self> {
        Ok(Self {
            kind: reader.u8()?.try_into()?,
            task_id: reader.string(MAX_TASK_ID_LENGTH)?,
            piece_number: reader.u32()?,
            chunk_size: reader.u64()?,
            max_inflight_chunks: reader.u32()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceMetadata {
    pub offset: u64,
    pub length: u64,
    pub digest: String,
    pub chunk_size: u64,
    pub max_inflight_chunks: u32,
}

impl PieceMetadata {
    #[cfg(feature = "urma")]
    pub(crate) fn encode(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.offset.to_be_bytes());
        payload.extend_from_slice(&self.length.to_be_bytes());
        put_bytes(payload, self.digest.as_bytes());
        payload.extend_from_slice(&self.chunk_size.to_be_bytes());
        payload.extend_from_slice(&self.max_inflight_chunks.to_be_bytes());
    }

    #[cfg(feature = "urma")]
    pub(crate) fn decode(reader: &mut PayloadReader<'_>) -> Result<Self> {
        Ok(Self {
            offset: reader.u64()?,
            length: reader.u64()?,
            digest: reader.string(MAX_STRING_LENGTH)?,
            chunk_size: reader.u64()?,
            max_inflight_chunks: reader.u32()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveWindow {
    pub start_chunk: u64,
    pub chunk_count: u32,
}

impl ReceiveWindow {
    pub(crate) fn encode(self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.start_chunk.to_be_bytes());
        payload.extend_from_slice(&self.chunk_count.to_be_bytes());
    }

    pub(crate) fn decode(reader: &mut PayloadReader<'_>) -> Result<Self> {
        Ok(Self {
            start_chunk: reader.u64()?,
            chunk_count: reader.u32()?,
        })
    }

    pub(crate) fn validate(self, expected_start: u64, remaining_chunks: u64) -> Result<()> {
        if self.start_chunk != expected_start || self.chunk_count == 0 {
            return Err(Error::Unknown(format!(
                "invalid receive window: expected start {expected_start}, got start {} count {}",
                self.start_chunk, self.chunk_count
            )));
        }
        if u64::from(self.chunk_count) > remaining_chunks {
            return Err(Error::Unknown(format!(
                "receive window count {} exceeds {remaining_chunks} remaining chunks",
                self.chunk_count
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousError {
    pub code: u32,
    pub message: String,
}

impl RendezvousError {
    pub(crate) fn encode(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.code.to_be_bytes());
        put_bytes(payload, self.message.as_bytes());
    }

    pub(crate) fn decode(reader: &mut PayloadReader<'_>) -> Result<Self> {
        Ok(Self {
            code: reader.u32()?,
            message: reader.string(MAX_STRING_LENGTH)?,
        })
    }
}

pub(crate) fn put_bytes(payload: &mut Vec<u8>, bytes: &[u8]) {
    payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(bytes);
}

pub(crate) struct PayloadReader<'a> {
    buf: &'a [u8],
}

impl<'a> PayloadReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Unknown(format!(
                "rendezvous frame has {} trailing payload bytes",
                self.buf.len()
            )))
        }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Unknown("rendezvous payload truncated".to_string()));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn bytes(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(Error::Unknown(format!(
                "rendezvous field of {len} bytes exceeds the {max} byte cap"
            )));
        }
        Ok(self.take(len)?.to_vec())
    }

    pub(crate) fn string(&mut self, max: usize) -> Result<String> {
        String::from_utf8(self.bytes(max)?)
            .map_err(|_| Error::Unknown("rendezvous string is not utf-8".to_string()))
    }
}

pub(crate) async fn write_envelope<W: AsyncWrite + Unpin>(
    writer: &mut W,
    magic: u32,
    version: u8,
    frame_type: u8,
    payload: &[u8],
    max_payload_length: usize,
) -> Result<()> {
    if payload.len() > max_payload_length || max_payload_length > MAX_PAYLOAD_LENGTH {
        return Err(Error::Unknown(format!(
            "rendezvous payload of {} bytes exceeds the cap",
            payload.len()
        )));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| Error::Unknown("rendezvous payload length exceeds u32".to_string()))?;
    let mut header = [0u8; HEADER_LENGTH];
    header[0..4].copy_from_slice(&magic.to_be_bytes());
    header[4] = version;
    header[5] = frame_type;
    header[6..10].copy_from_slice(&payload_len.to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_envelope<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_magic: u32,
    expected_version: u8,
    max_payload_length: usize,
) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; HEADER_LENGTH];
    reader.read_exact(&mut header).await?;
    let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
    if magic != expected_magic {
        return Err(Error::Unknown("invalid rendezvous magic".to_string()));
    }
    let version = header[4];
    if version != expected_version {
        return Err(Error::Unknown(format!(
            "rendezvous version mismatch: local {expected_version}, remote {version}"
        )));
    }
    let payload_length = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;
    if payload_length > max_payload_length || max_payload_length > MAX_PAYLOAD_LENGTH {
        return Err(Error::Unknown(format!(
            "rendezvous payload of {payload_length} bytes exceeds the cap"
        )));
    }
    let mut payload = vec![0u8; payload_length];
    reader.read_exact(&mut payload).await?;
    Ok((header[5], payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_window_is_contiguous_and_bounded() {
        assert!(ReceiveWindow {
            start_chunk: 4,
            chunk_count: 3
        }
        .validate(4, 3)
        .is_ok());
        assert!(ReceiveWindow {
            start_chunk: 5,
            chunk_count: 1
        }
        .validate(4, 3)
        .is_err());
        assert!(ReceiveWindow {
            start_chunk: 4,
            chunk_count: 4
        }
        .validate(4, 3)
        .is_err());
    }

    #[tokio::test]
    async fn envelope_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        write_envelope(&mut writer, 7, 2, 9, b"payload", MAX_PAYLOAD_LENGTH)
            .await
            .unwrap();
        assert_eq!(
            read_envelope(&mut reader, 7, 2, MAX_PAYLOAD_LENGTH)
                .await
                .unwrap(),
            (9, b"payload".to_vec())
        );
    }
}
