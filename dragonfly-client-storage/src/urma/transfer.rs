use super::{rendezvous::TransferId, Error, Result};
use std::collections::HashMap;

/// Application routing identity carried by SEND_IMM.
///
/// The upper 32 bits identify one process-wide Piece transfer and the lower
/// 32 bits identify a chunk inside that transfer. The full transfer id is an
/// opaque, non-reused lifetime identity; it is not a lane-local sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RoutingToken {
    transfer_id: TransferId,
    chunk: u32,
}

impl RoutingToken {
    pub(crate) fn decode(value: u64) -> Result<Self> {
        let transfer_id = (value >> 32) as TransferId;
        if transfer_id == 0 {
            return Err(Error::Protocol(format!(
                "invalid URMA routing token: value={value} transfer_id=0"
            )));
        }
        Ok(Self {
            transfer_id,
            chunk: value as u32,
        })
    }

    pub(crate) fn encode(transfer_id: TransferId, chunk: u64) -> Result<u64> {
        if transfer_id == 0 || chunk > u64::from(u32::MAX) {
            return Err(Error::Protocol(format!(
                "invalid URMA routing token: transfer_id={transfer_id} chunk={chunk}"
            )));
        }
        Ok((u64::from(transfer_id) << 32) | chunk)
    }

    pub(crate) fn transfer_id(self) -> TransferId {
        self.transfer_id
    }

    pub(crate) fn chunk(self) -> u32 {
        self.chunk
    }
}

/// Logical receive waiters for one PeerTarget, grouped by Piece transfer.
/// Physical receive WRs remain anonymous and are deliberately not stored
/// here; only a validated `(remote_id, routing_token)` may select a waiter.
pub(crate) struct TransferRegistry<T> {
    by_transfer: HashMap<TransferId, HashMap<u32, T>>,
    len: usize,
}

impl<T> Default for TransferRegistry<T> {
    fn default() -> Self {
        Self {
            by_transfer: HashMap::new(),
            len: 0,
        }
    }
}

impl<T> TransferRegistry<T> {
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn contains(&self, token: RoutingToken) -> bool {
        self.by_transfer
            .get(&token.transfer_id())
            .is_some_and(|chunks| chunks.contains_key(&token.chunk()))
    }

    pub(crate) fn contains_transfer(&self, token: RoutingToken) -> bool {
        self.by_transfer.contains_key(&token.transfer_id())
    }

    pub(crate) fn insert(&mut self, token: RoutingToken, value: T) -> Result<()> {
        let chunks = self.by_transfer.entry(token.transfer_id()).or_default();
        if chunks.contains_key(&token.chunk()) {
            return Err(Error::Protocol(format!(
                "duplicate registered RX routing token: transfer_id={} chunk={}",
                token.transfer_id(),
                token.chunk()
            )));
        }
        chunks.insert(token.chunk(), value);
        self.len += 1;
        Ok(())
    }

    pub(crate) fn remove(&mut self, token: RoutingToken) -> Option<T> {
        let chunks = self.by_transfer.get_mut(&token.transfer_id())?;
        let value = chunks.remove(&token.chunk())?;
        self.len -= 1;
        if chunks.is_empty() {
            self.by_transfer.remove(&token.transfer_id());
        }
        Some(value)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn drain(&mut self) -> Vec<T> {
        self.len = 0;
        self.by_transfer
            .drain()
            .flat_map(|(_, chunks)| chunks.into_values())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_token_round_trip_preserves_transfer_and_chunk() {
        let encoded = RoutingToken::encode(0xfedc_ba98, 0x7654_3210).unwrap();
        let token = RoutingToken::decode(encoded).unwrap();
        assert_eq!(token.transfer_id(), 0xfedc_ba98);
        assert_eq!(token.chunk(), 0x7654_3210);
        assert!(RoutingToken::encode(0, 1).is_err());
        assert!(RoutingToken::encode(1, u64::from(u32::MAX) + 1).is_err());
        assert!(RoutingToken::decode(7).is_err());
    }

    #[test]
    fn registry_groups_chunks_by_transfer_and_removes_empty_transfer() {
        let mut registry = TransferRegistry::default();
        let a0 = RoutingToken::decode(RoutingToken::encode(7, 0).unwrap()).unwrap();
        let a1 = RoutingToken::decode(RoutingToken::encode(7, 1).unwrap()).unwrap();
        let b0 = RoutingToken::decode(RoutingToken::encode(8, 0).unwrap()).unwrap();
        registry.insert(a0, "a0").unwrap();
        registry.insert(a1, "a1").unwrap();
        registry.insert(b0, "b0").unwrap();
        assert_eq!(registry.len(), 3);
        assert!(registry.contains_transfer(a0));
        assert!(registry.insert(a0, "duplicate").is_err());
        assert_eq!(registry.remove(a0), Some("a0"));
        assert!(registry.contains_transfer(a1));
        assert_eq!(registry.remove(a1), Some("a1"));
        assert!(!registry.contains_transfer(a1));
        assert_eq!(registry.remove(b0), Some("b0"));
        assert!(registry.is_empty());
    }
}
