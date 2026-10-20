//! Bounded byte-stream adapter for the existing READ frame codec/dispatcher.
//! TCP bootstraps descriptors and remains an EOF watchdog; transfer bytes use
//! only SEND/RECV. Sessions never fall back to TCP after the handshake.
use super::{
    fabric::UrmaFabricHandle,
    native_control::{ControlSetup, PACKET_BYTES},
    Error, Result,
};
use std::{collections::BTreeMap, io};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
const HEADER: usize = 16;
const REORDER_LIMIT: u64 = 32;

pub(crate) fn pack_descriptors(data: Vec<u8>, control: Option<&ControlSetup>) -> Result<Vec<u8>> {
    let Some(control) = control else {
        return Ok(data);
    };
    if data.is_empty()
        || control.descriptor.is_empty()
        || data.len() + control.descriptor.len() + 4 > 64 * 1024
    {
        return Err(Error::Protocol("invalid control descriptor bundle".into()));
    }
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&data);
    out.extend_from_slice(&control.descriptor);
    Ok(out)
}
pub(crate) fn unpack_descriptors(bytes: &[u8], native: bool) -> Result<(Vec<u8>, Vec<u8>)> {
    if !native {
        return Ok((bytes.to_vec(), Vec::new()));
    }
    let prefix: [u8; 4] = bytes
        .get(..4)
        .ok_or_else(|| Error::Protocol("truncated control descriptors".into()))?
        .try_into()
        .unwrap();
    let end = 4usize
        .checked_add(u32::from_be_bytes(prefix) as usize)
        .filter(|end| *end > 4 && *end < bytes.len())
        .ok_or_else(|| Error::Protocol("invalid control descriptors".into()))?;
    Ok((bytes[4..end].to_vec(), bytes[end..].to_vec()))
}

struct PacketOrder {
    session: u64,
    next: u64,
    pending: BTreeMap<u64, Vec<u8>>,
}
impl PacketOrder {
    fn new(session: u64) -> Self {
        Self {
            session,
            next: 1,
            pending: BTreeMap::new(),
        }
    }
    fn insert(&mut self, packet: Vec<u8>) -> io::Result<()> {
        if packet.len() <= HEADER || packet.len() > PACKET_BYTES {
            return Err(io::Error::other("control packet size"));
        }
        let session = u64::from_be_bytes(packet[..8].try_into().unwrap());
        let sequence = u64::from_be_bytes(packet[8..16].try_into().unwrap());
        if session != self.session
            || sequence < self.next
            || sequence - self.next >= REORDER_LIMIT
            || self.pending.contains_key(&sequence)
        {
            return Err(io::Error::other("control packet session/sequence"));
        }
        self.pending.insert(sequence, packet[HEADER..].to_vec());
        Ok(())
    }
    fn pop(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some(packet) = self.pending.remove(&self.next) else {
            return Ok(None);
        };
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("control sequence exhausted"))?;
        Ok(Some(packet))
    }
}

pub(crate) fn spawn<S: tokio::io::AsyncRead + Unpin + Send + 'static>(
    fabric: UrmaFabricHandle,
    lane_id: u16,
    session: u64,
    mut setup: ControlSetup,
    mut watchdog: S,
) -> DuplexStream {
    let (application, bridge) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        // Covers bridge cancellation as well as EOF and native failures. The
        // Runtime owns posted WRs and retains buffers until CQE/flush proof.
        let _guard = fabric.control_guard(lane_id, setup.id);
        let (mut outgoing, mut incoming) = tokio::io::split(bridge);
        let send = async {
            let mut sequence = 1u64;
            let mut packet = vec![0; PACKET_BYTES];
            loop {
                let count = outgoing.read(&mut packet[HEADER..]).await?;
                if count == 0 {
                    return Ok::<_, io::Error>(());
                }
                packet[..8].copy_from_slice(&session.to_be_bytes());
                packet[8..HEADER].copy_from_slice(&sequence.to_be_bytes());
                fabric
                    .send_control(lane_id, setup.id, packet[..HEADER + count].to_vec())
                    .await
                    .map_err(io::Error::other)?;
                sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("control sequence exhausted"))?;
            }
        };
        let receive = async {
            let mut order = PacketOrder::new(session);
            while let Some(packet) = setup.incoming.recv().await {
                order.insert(packet.map_err(io::Error::other)?)?;
                while let Some(bytes) = order.pop()? {
                    incoming.write_all(&bytes).await?;
                }
            }
            Ok::<_, io::Error>(())
        };
        let closed = async {
            let mut byte = [0; 1];
            match watchdog.read(&mut byte).await? {
                0 => Ok(()),
                _ => Err(io::Error::other(
                    "unexpected TCP data after SEND/RECV handshake",
                )),
            }
        };
        let result = tokio::select! { result = send => result, result = receive => result, result = closed => result };
        if let Err(error) = result {
            tracing::debug!(lane_id, %error, "SEND/RECV control bridge closed");
        }
    });
    application
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(session: u64, seq: u64, body: &[u8]) -> Vec<u8> {
        [
            session.to_be_bytes().as_slice(),
            seq.to_be_bytes().as_slice(),
            body,
        ]
        .concat()
    }
    #[test]
    fn reordered_packets_preserve_stream_and_reject_stale_duplicate_and_unbounded_input() {
        let mut order = PacketOrder::new(17);
        order.insert(packet(17, 2, b"second")).unwrap();
        assert!(order.pop().unwrap().is_none());
        order.insert(packet(17, 1, b"first")).unwrap();
        assert_eq!(order.pop().unwrap().unwrap(), b"first");
        assert_eq!(order.pop().unwrap().unwrap(), b"second");
        assert!(order.insert(packet(17, 1, b"old")).is_err());
        assert!(order.insert(packet(18, 3, b"wrong session")).is_err());
        assert!(order.insert(packet(17, 35, b"unbounded")).is_err());
        order.insert(packet(17, 4, b"future")).unwrap();
        assert!(order.insert(packet(17, 4, b"duplicate")).is_err());
        assert!(order.insert(vec![0; HEADER]).is_err());
        assert!(order.insert(packet(17, 3, &vec![0; PACKET_BYTES])).is_err());
    }
    #[test]
    fn descriptor_bundle_rejects_truncation_and_empty_descriptors() {
        for bytes in [vec![], vec![0; 4], vec![0, 0, 0, 8, 1], vec![0, 0, 0, 1, 1]] {
            assert!(unpack_descriptors(&bytes, true).is_err());
        }
        assert_eq!(
            unpack_descriptors(&[0, 0, 0, 1, 7, 8], true).unwrap(),
            (vec![7], vec![8])
        );
        assert_eq!(unpack_descriptors(&[7], false).unwrap(), (vec![7], vec![]));
    }
}
