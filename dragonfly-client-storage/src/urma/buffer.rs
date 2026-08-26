use super::{native_error, Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BufferPoolConfig {
    pub(crate) slot_size: usize,
    pub(crate) tx_slot_count: usize,
    pub(crate) rx_slot_count: usize,
    pub(crate) alignment: usize,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            slot_size: 64 * 1024,
            tx_slot_count: 128,
            rx_slot_count: 512,
            alignment: 4096,
        }
    }
}

impl BufferPoolConfig {
    pub(crate) fn total_len(&self) -> Result<usize> {
        if self.slot_size == 0 {
            return Err(Error::InvalidConfiguration(
                "slot_size must be non-zero".into(),
            ));
        }
        if self.tx_slot_count == 0 || self.rx_slot_count == 0 {
            return Err(Error::InvalidConfiguration(
                "tx_slot_count and rx_slot_count must be non-zero".into(),
            ));
        }
        if self.alignment < std::mem::size_of::<usize>() || !self.alignment.is_power_of_two() {
            return Err(Error::InvalidConfiguration(
                "alignment must be a power of two and at least pointer-sized".into(),
            ));
        }
        let slots = self
            .tx_slot_count
            .checked_add(self.rx_slot_count)
            .ok_or_else(|| Error::InvalidConfiguration("slot count overflow".into()))?;
        self.slot_size
            .checked_mul(slots)
            .ok_or_else(|| Error::InvalidConfiguration("buffer pool size overflow".into()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotKind {
    Tx,
    Rx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotState {
    Free,
    Allocated,
    PostedRecv,
    RecvCompleted,
    SendPosted,
    SendCompleted,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SlotId(usize);

impl SlotId {
    pub(crate) fn index(self) -> usize {
        self.0
    }

    pub(crate) fn from_index(index: usize) -> Self {
        Self(index)
    }
}

/// One receive completion in a transport-neutral ownership wrapper. Phase A
/// currently copies from the C-owned registered region; callers depend only on
/// this wrapper so the backing can later become a borrowed registered window
/// without changing the client/storage contract.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReceivedChunk {
    bytes: Vec<u8>,
}

impl ReceivedChunk {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Debug)]
struct BufferSlot {
    kind: SlotKind,
    offset: usize,
    len: usize,
    state: SlotState,
}

mod native {
    use super::*;
    use crate::urma::ffi;
    use std::collections::VecDeque;

    /// RAII owner of one local-only registered Segment and its backing memory.
    pub(crate) struct UrmaRegisteredSegment {
        handle: ffi::SegmentHandle,
    }

    impl UrmaRegisteredSegment {
        fn create(runtime: &mut ffi::NativeRuntime, len: usize, alignment: usize) -> Result<Self> {
            let length = u64::try_from(len).map_err(|_| {
                Error::InvalidConfiguration("registered length does not fit u64".into())
            })?;
            let alignment = u64::try_from(alignment)
                .map_err(|_| Error::InvalidConfiguration("alignment does not fit u64".into()))?;
            let handle = ffi::SegmentHandle::create(runtime, length, alignment)
                .map_err(|error| native_error("register_segment", error))?;
            Ok(Self { handle })
        }

        fn close(&mut self) -> Result<()> {
            self.handle
                .close()
                .map_err(|error| native_error("unregister_segment", error))
        }
    }

    /// Fixed-size slot metadata over one local registered Segment.
    pub(crate) struct UrmaBufferPool {
        segment: Option<UrmaRegisteredSegment>,
        slots: Vec<BufferSlot>,
        free_tx: Vec<usize>,
        free_rx: VecDeque<usize>,
        accepting: bool,
    }

    impl UrmaBufferPool {
        pub(crate) fn create(
            runtime: &mut ffi::NativeRuntime,
            config: BufferPoolConfig,
        ) -> Result<Self> {
            let total_len = config.total_len()?;
            let segment = UrmaRegisteredSegment::create(runtime, total_len, config.alignment)?;
            let slot_count = config
                .tx_slot_count
                .checked_add(config.rx_slot_count)
                .ok_or_else(|| Error::InvalidConfiguration("slot count overflow".into()))?;
            let mut slots = Vec::with_capacity(slot_count);
            for index in 0..config.tx_slot_count {
                slots.push(BufferSlot {
                    kind: SlotKind::Tx,
                    offset: slot_offset(&config, index)?,
                    len: config.slot_size,
                    state: SlotState::Free,
                });
            }
            for index in 0..config.rx_slot_count {
                slots.push(BufferSlot {
                    kind: SlotKind::Rx,
                    offset: slot_offset(
                        &config,
                        config.tx_slot_count.checked_add(index).ok_or_else(|| {
                            Error::InvalidConfiguration("slot index overflow".into())
                        })?,
                    )?,
                    len: config.slot_size,
                    state: SlotState::Free,
                });
            }
            let free_tx = (0..config.tx_slot_count).rev().collect();
            let free_rx = (config.tx_slot_count..slot_count).collect();
            Ok(Self {
                segment: Some(segment),
                slots,
                free_tx,
                free_rx,
                accepting: true,
            })
        }

        pub(crate) fn allocate(&mut self, kind: SlotKind) -> Option<SlotId> {
            if !self.accepting {
                return None;
            }
            let index = match kind {
                SlotKind::Tx => self.free_tx.pop()?,
                SlotKind::Rx => self.free_rx.pop_front()?,
            };
            let slot = self.slots.get_mut(index)?;
            debug_assert_eq!(slot.kind, kind);
            debug_assert_eq!(slot.state, SlotState::Free);
            slot.state = SlotState::Allocated;
            Some(SlotId(index))
        }

        pub(crate) fn release(&mut self, id: SlotId) -> Result<()> {
            let slot = self.slots.get_mut(id.0).ok_or_else(|| {
                Error::InvalidConfiguration("slot id is outside this buffer pool".into())
            })?;
            if !matches!(
                slot.state,
                SlotState::Allocated | SlotState::RecvCompleted | SlotState::SendCompleted
            ) {
                return Err(Error::InvalidConfiguration(
                    "slot cannot be released while a WR may still reference it".into(),
                ));
            }
            slot.state = SlotState::Free;
            match slot.kind {
                SlotKind::Tx => self.free_tx.push(id.0),
                SlotKind::Rx => self.free_rx.push_back(id.0),
            }
            Ok(())
        }

        pub(crate) fn segment_handle(&self) -> Result<&ffi::SegmentHandle> {
            self.segment
                .as_ref()
                .map(|segment| &segment.handle)
                .ok_or_else(|| Error::InvalidConfiguration("registered Segment is closed".into()))
        }

        pub(crate) fn write_tx(&mut self, id: SlotId, data: &[u8]) -> Result<(u64, u32)> {
            let (offset, capacity, kind, state) = self.slot_fields(id)?;
            if kind != SlotKind::Tx || state != SlotState::Allocated {
                return Err(Error::InvalidConfiguration(
                    "TX write requires an allocated TX slot".into(),
                ));
            }
            if data.is_empty() || data.len() > capacity {
                return Err(Error::InvalidConfiguration(format!(
                    "TX message length {} is outside 1..={capacity}",
                    data.len()
                )));
            }
            let offset = u64::try_from(offset)
                .map_err(|_| Error::InvalidConfiguration("slot offset exceeds u64".into()))?;
            self.segment_handle()?
                .write(offset, data)
                .map_err(|error| native_error("write_tx_slot", error))?;
            let length = u32::try_from(data.len())
                .map_err(|_| Error::InvalidConfiguration("TX length exceeds u32".into()))?;
            Ok((offset, length))
        }

        pub(crate) fn recv_post_layout(&self, id: SlotId) -> Result<(u64, u32)> {
            let (offset, capacity, kind, state) = self.slot_fields(id)?;
            if kind != SlotKind::Rx || state != SlotState::Allocated {
                return Err(Error::InvalidConfiguration(
                    "RECV post requires an allocated RX slot".into(),
                ));
            }
            Ok((
                u64::try_from(offset)
                    .map_err(|_| Error::InvalidConfiguration("slot offset exceeds u64".into()))?,
                u32::try_from(capacity)
                    .map_err(|_| Error::InvalidConfiguration("slot size exceeds u32".into()))?,
            ))
        }

        pub(crate) fn mark_posted(&mut self, id: SlotId, kind: SlotKind) -> Result<()> {
            let expected_kind = self
                .slots
                .get(id.0)
                .ok_or_else(|| Error::Protocol("completion slot is outside buffer pool".into()))?
                .kind;
            if expected_kind != kind {
                return Err(Error::Protocol(
                    "WR operation does not match slot kind".into(),
                ));
            }
            self.transition(
                id,
                SlotState::Allocated,
                match kind {
                    SlotKind::Tx => SlotState::SendPosted,
                    SlotKind::Rx => SlotState::PostedRecv,
                },
            )
        }

        pub(crate) fn rollback_post(&mut self, id: SlotId, kind: SlotKind) -> Result<()> {
            self.transition(
                id,
                match kind {
                    SlotKind::Tx => SlotState::SendPosted,
                    SlotKind::Rx => SlotState::PostedRecv,
                },
                SlotState::Allocated,
            )
        }

        pub(crate) fn complete_send(&mut self, id: SlotId) -> Result<()> {
            self.transition(id, SlotState::SendPosted, SlotState::SendCompleted)
        }

        pub(crate) fn complete_error(
            &mut self,
            id: SlotId,
            operation: crate::urma::lane::OperationType,
        ) -> Result<()> {
            let (from, to) = match operation {
                crate::urma::lane::OperationType::Send => {
                    (SlotState::SendPosted, SlotState::SendCompleted)
                }
                crate::urma::lane::OperationType::Recv => {
                    (SlotState::PostedRecv, SlotState::RecvCompleted)
                }
            };
            self.transition(id, from, to)
        }

        pub(crate) fn complete_recv(&mut self, id: SlotId, length: u32) -> Result<ReceivedChunk> {
            let (offset, capacity, kind, state) = self.slot_fields(id)?;
            if kind != SlotKind::Rx || state != SlotState::PostedRecv {
                return Err(Error::Protocol(
                    "RECV CQE does not match a posted RX slot".into(),
                ));
            }
            let length = usize::try_from(length)
                .map_err(|_| Error::Protocol("completion length exceeds usize".into()))?;
            if length == 0 || length > capacity {
                return Err(Error::Protocol(format!(
                    "RECV completion length {length} is outside 1..={capacity}"
                )));
            }
            let bytes = self
                .segment_handle()?
                .read(offset as u64, length as u32)
                .map_err(|error| native_error("read_rx_slot", error))?;
            self.transition(id, SlotState::PostedRecv, SlotState::RecvCompleted)?;
            Ok(ReceivedChunk { bytes })
        }

        fn slot_fields(&self, id: SlotId) -> Result<(usize, usize, SlotKind, SlotState)> {
            self.slots
                .get(id.0)
                .map(|slot| (slot.offset, slot.len, slot.kind, slot.state))
                .ok_or_else(|| Error::InvalidConfiguration("slot id is outside buffer pool".into()))
        }

        fn transition(&mut self, id: SlotId, from: SlotState, to: SlotState) -> Result<()> {
            let slot = self
                .slots
                .get_mut(id.0)
                .ok_or_else(|| Error::Protocol("completion slot is outside buffer pool".into()))?;
            if slot.state != from {
                return Err(Error::Protocol(format!(
                    "slot {} state {:?}, expected {:?}",
                    id.0, slot.state, from
                )));
            }
            slot.state = to;
            Ok(())
        }

        pub(crate) fn stop(&mut self) {
            self.accepting = false;
        }

        pub(crate) fn close(&mut self) -> Result<()> {
            self.stop();
            let Some(mut segment) = self.segment.take() else {
                return Ok(());
            };
            segment.close()
        }
    }

    fn slot_offset(config: &BufferPoolConfig, index: usize) -> Result<usize> {
        config
            .slot_size
            .checked_mul(index)
            .ok_or_else(|| Error::InvalidConfiguration("slot offset overflow".into()))
    }
}

pub(crate) use native::UrmaBufferPool;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_fixed_slot_layout_without_urma() {
        let config = BufferPoolConfig {
            slot_size: 1024,
            tx_slot_count: 2,
            rx_slot_count: 3,
            alignment: 4096,
        };
        assert_eq!(config.total_len(), Ok(5 * 1024));
    }

    #[test]
    fn rejects_invalid_layout_without_touching_urma() {
        let config = BufferPoolConfig {
            slot_size: 0,
            ..BufferPoolConfig::default()
        };
        assert!(matches!(
            config.total_len(),
            Err(Error::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn rejects_registered_pool_size_overflow() {
        let config = BufferPoolConfig {
            slot_size: usize::MAX,
            tx_slot_count: 1,
            rx_slot_count: 1,
            alignment: 4096,
        };
        assert!(matches!(
            config.total_len(),
            Err(Error::InvalidConfiguration(_))
        ));
    }
}
