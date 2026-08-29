use super::{native_error, Error, Result};
use std::{
    collections::HashMap,
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::OwnedSemaphorePermit;

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
        if slots > usize::from(u16::MAX) + 1 {
            return Err(Error::InvalidConfiguration(
                "buffer pool cannot exceed 65536 slots".into(),
            ));
        }
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
    LeasedRx,
    LeasedTx,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SlotId {
    index: u16,
    generation: u16,
}

impl SlotId {
    pub(crate) fn index(self) -> usize {
        usize::from(self.index)
    }

    pub(crate) fn generation(self) -> u16 {
        self.generation
    }

    pub(crate) fn encode(self) -> u32 {
        (u32::from(self.generation) << 16) | u32::from(self.index)
    }

    pub(crate) fn decode(encoded: u32) -> Result<Self> {
        let generation = (encoded >> 16) as u16;
        if generation == 0 {
            return Err(Error::Protocol(
                "slot identity has a zero generation".into(),
            ));
        }
        Ok(Self {
            index: encoded as u16,
            generation,
        })
    }

    pub(crate) fn new(index: usize, generation: u16) -> Result<Self> {
        if generation == 0 {
            return Err(Error::InvalidConfiguration(
                "slot generation must be non-zero".into(),
            ));
        }
        Ok(Self {
            index: u16::try_from(index)
                .map_err(|_| Error::InvalidConfiguration("slot index exceeds 16 bits".into()))?,
            generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseKind {
    Rx,
    Tx,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct LeaseRecycle {
    pool_id: u64,
    lease_id: u64,
}

pub(crate) type LeaseRecycleNotifier = Arc<dyn Fn(LeaseRecycle) + Send + Sync>;

#[derive(Debug)]
struct LeaseRecord {
    kind: LeaseKind,
    slots: Vec<SlotId>,
}

#[derive(Debug)]
pub(crate) struct LeaseBook {
    pool_id: u64,
    next_lease_id: u64,
    active: HashMap<u64, LeaseRecord>,
}

impl LeaseBook {
    pub(crate) fn new() -> Self {
        static NEXT_POOL_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            pool_id: NEXT_POOL_ID.fetch_add(1, Ordering::Relaxed),
            next_lease_id: 1,
            active: HashMap::new(),
        }
    }

    pub(crate) fn issue(&mut self, kind: LeaseKind, slots: Vec<SlotId>) -> Result<LeaseRecycle> {
        if slots.is_empty() {
            return Err(Error::InvalidConfiguration(
                "registered lease requires at least one slot".into(),
            ));
        }
        let lease_id = self.next_lease_id;
        self.next_lease_id = self
            .next_lease_id
            .checked_add(1)
            .filter(|id| *id != 0)
            .ok_or_else(|| Error::InvalidConfiguration("lease id space exhausted".into()))?;
        self.active.insert(lease_id, LeaseRecord { kind, slots });
        Ok(LeaseRecycle {
            pool_id: self.pool_id,
            lease_id,
        })
    }

    fn record(&self, recycle: LeaseRecycle) -> Result<&LeaseRecord> {
        if recycle.pool_id != self.pool_id {
            return Err(Error::Protocol(
                "registered lease belongs to another pool".into(),
            ));
        }
        self.active
            .get(&recycle.lease_id)
            .ok_or_else(|| Error::Protocol("registered lease was already recycled".into()))
    }

    fn finish(&mut self, recycle: LeaseRecycle) -> Result<LeaseRecord> {
        self.record(recycle)?;
        Ok(self
            .active
            .remove(&recycle.lease_id)
            .expect("lease presence checked above"))
    }

    fn active(&self) -> usize {
        self.active.len()
    }

    fn ensure_empty(&self) -> Result<()> {
        if self.active.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidConfiguration(format!(
                "cannot close registered Segment with {} active leases",
                self.active.len()
            )))
        }
    }
}

struct LeaseCore {
    recycle: Option<LeaseRecycle>,
    notifier: LeaseRecycleNotifier,
}

impl LeaseCore {
    fn recycle(&self) -> Result<LeaseRecycle> {
        self.recycle
            .as_ref()
            .copied()
            .ok_or_else(|| Error::Protocol("registered lease was already consumed".into()))
    }

    fn disarm(&mut self) {
        self.recycle = None;
    }
}

impl Drop for LeaseCore {
    fn drop(&mut self) {
        if let Some(recycle) = self.recycle.take() {
            (self.notifier)(recycle);
        }
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // B1 foundation; read by the B2 direct-RX consumer.
struct RegisteredSpan {
    data: NonNull<u8>,
    length: usize,
}

/// Immutable ownership of a completed registered RX window. The native
/// handles remain on the owner thread; this value only exposes validated CPU
/// spans after all corresponding receive CQEs completed.
#[allow(dead_code)] // B1 foundation; published by B2.
pub(crate) struct RegisteredRxWindowLease {
    spans: Vec<RegisteredSpan>,
    length: usize,
    cores: Vec<LeaseCore>,
    pipeline_permit: Option<OwnedSemaphorePermit>,
    #[cfg(test)]
    _test_backing: Vec<Box<[u8]>>,
}

// SAFETY: the pool changes every covered slot to LeasedRx before construction.
// No receive can be reposted until the owner consumes the recycle token, and
// the only exposed access is shared and immutable.
unsafe impl Send for RegisteredRxWindowLease {}
// SAFETY: concurrent readers cannot mutate the leased registered spans.
unsafe impl Sync for RegisteredRxWindowLease {}

#[allow(dead_code)] // B1 foundation; published by B2.
impl RegisteredRxWindowLease {
    pub(crate) fn parts(&self) -> impl Iterator<Item = &[u8]> {
        self.spans.iter().map(|span| {
            // SAFETY: construction bounds-checks every span against the live
            // Segment and pool close refuses while this lease is active.
            unsafe { std::slice::from_raw_parts(span.data.as_ptr(), span.length) }
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.length
    }

    pub(crate) fn merge(windows: Vec<Self>) -> Result<Self> {
        if windows.is_empty() {
            return Err(Error::InvalidConfiguration(
                "RX window merge requires at least one lease".into(),
            ));
        }
        let mut spans = Vec::new();
        let mut cores = Vec::new();
        let mut length = 0usize;
        #[cfg(test)]
        let mut test_backing = Vec::new();
        for mut window in windows {
            if window.pipeline_permit.is_some() {
                return Err(Error::Protocol(
                    "chunk lease unexpectedly owns a pipeline permit".into(),
                ));
            }
            length = length
                .checked_add(window.length)
                .ok_or_else(|| Error::Protocol("RX window merge length overflow".into()))?;
            spans.append(&mut window.spans);
            cores.append(&mut window.cores);
            #[cfg(test)]
            test_backing.append(&mut window._test_backing);
        }
        Ok(Self {
            spans,
            length,
            cores,
            pipeline_permit: None,
            #[cfg(test)]
            _test_backing: test_backing,
        })
    }

    pub(crate) fn with_pipeline_permit(mut self, permit: OwnedSemaphorePermit) -> Self {
        self.pipeline_permit = Some(permit);
        self
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        parts: Vec<Vec<u8>>,
        recycle: LeaseRecycle,
        notifier: LeaseRecycleNotifier,
    ) -> Self {
        let backing = parts
            .into_iter()
            .map(Vec::into_boxed_slice)
            .collect::<Vec<_>>();
        let spans = backing
            .iter()
            .map(|part| RegisteredSpan {
                data: NonNull::new(part.as_ptr().cast_mut()).expect("test part is non-empty"),
                length: part.len(),
            })
            .collect::<Vec<_>>();
        Self {
            length: backing.iter().map(|part| part.len()).sum(),
            spans,
            cores: vec![LeaseCore {
                recycle: Some(recycle),
                notifier,
            }],
            pipeline_permit: None,
            _test_backing: backing,
        }
    }

    /// Builds an ownerless completed lease for higher-level consumer tests.
    /// Production leases always carry recycle cores issued by LeaseBook.
    #[cfg(test)]
    pub(crate) fn from_test_untracked_parts(parts: Vec<Vec<u8>>) -> Self {
        let backing = parts
            .into_iter()
            .map(Vec::into_boxed_slice)
            .collect::<Vec<_>>();
        let spans = backing
            .iter()
            .map(|part| RegisteredSpan {
                data: NonNull::new(part.as_ptr().cast_mut()).expect("test part is non-empty"),
                length: part.len(),
            })
            .collect::<Vec<_>>();
        Self {
            length: backing.iter().map(|part| part.len()).sum(),
            spans,
            cores: Vec::new(),
            pipeline_permit: None,
            _test_backing: backing,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_lengths(lengths: Vec<usize>) -> Self {
        let slots = (0..lengths.len())
            .map(|index| SlotId::new(index, 1).unwrap())
            .collect();
        let mut leases = LeaseBook::new();
        let recycle = leases.issue(LeaseKind::Tx, slots).unwrap();
        Self::from_test_parts(lengths, recycle, Arc::new(|_| {}))
    }
}

/// Exclusive ownership of registered TX backing before any SEND is posted.
/// B4 will consume this lease into operation ownership; until then callers may
/// fill the logical window directly without an intermediate Vec.
#[allow(dead_code)] // B1 foundation; filled and posted by B4.
pub(crate) struct TxWindowLease {
    spans: Vec<RegisteredSpan>,
    layouts: Vec<TxLeaseLayout>,
    length: usize,
    core: LeaseCore,
    #[cfg(test)]
    _test_backing: Box<[u8]>,
}

// SAFETY: TxWindowLease is exclusive, is not Sync, and its slots cannot be
// posted or allocated again until the owner consumes its recycle token.
unsafe impl Send for TxWindowLease {}

#[allow(dead_code)] // B1 foundation; filled and posted by B4.
impl TxWindowLease {
    pub(crate) fn part_count(&self) -> usize {
        self.spans.len()
    }

    pub(crate) fn part_mut(&mut self, index: usize) -> Result<&mut [u8]> {
        let span = self
            .spans
            .get_mut(index)
            .ok_or_else(|| Error::Protocol("TX lease part index is out of range".into()))?;
        // SAFETY: the indexed span belongs to this exclusive lease and the
        // mutable lease borrow prevents another part borrow at the same time.
        Ok(unsafe { std::slice::from_raw_parts_mut(span.data.as_ptr(), span.length) })
    }

    #[cfg(test)]
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        assert_eq!(self.spans.len(), 1);
        // SAFETY: the single-span test helper has exclusive lease ownership.
        unsafe { std::slice::from_raw_parts_mut(self.spans[0].data.as_ptr(), self.spans[0].length) }
    }

    pub(crate) fn len(&self) -> usize {
        self.length
    }

    pub(crate) fn chunk_count(&self) -> usize {
        self.layouts.len()
    }

    /// Narrows a reusable full-size window for a final short window. B4 never
    /// grows a lease or changes its slot identities off the owner thread.
    pub(crate) fn reshape(&mut self, chunk_lengths: &[usize]) -> Result<()> {
        if chunk_lengths.is_empty() || chunk_lengths.len() > self.layouts.len() {
            return Err(Error::InvalidConfiguration(
                "TX lease reshape exceeds its slot count".into(),
            ));
        }
        let mut total = 0usize;
        for (index, length) in chunk_lengths.iter().copied().enumerate() {
            if length == 0 || length > self.spans[index].length {
                return Err(Error::InvalidConfiguration(
                    "TX lease reshape exceeds its original span".into(),
                ));
            }
            self.spans[index].length = length;
            self.layouts[index].length = u32::try_from(length)
                .map_err(|_| Error::InvalidConfiguration("TX chunk exceeds u32".into()))?;
            total = total
                .checked_add(length)
                .ok_or_else(|| Error::InvalidConfiguration("TX window length overflow".into()))?;
        }
        self.spans.truncate(chunk_lengths.len());
        self.layouts.truncate(chunk_lengths.len());
        self.length = total;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        lengths: Vec<usize>,
        recycle: LeaseRecycle,
        notifier: LeaseRecycleNotifier,
    ) -> Self {
        let total = lengths.iter().sum();
        let mut backing = vec![0u8; total].into_boxed_slice();
        let base = backing.as_mut_ptr();
        let mut offset = 0usize;
        let mut spans = Vec::with_capacity(lengths.len());
        let mut layouts = Vec::with_capacity(lengths.len());
        for (index, length) in lengths.into_iter().enumerate() {
            // SAFETY: offsets are accumulated from the exact backing length.
            let data = unsafe { NonNull::new_unchecked(base.add(offset)) };
            spans.push(RegisteredSpan { data, length });
            layouts.push(TxLeaseLayout {
                slot: SlotId::new(index, 1).unwrap(),
                offset: offset as u64,
                length: length as u32,
            });
            offset += length;
        }
        Self {
            spans,
            layouts,
            length: total,
            core: LeaseCore {
                recycle: Some(recycle),
                notifier,
            },
            _test_backing: backing,
        }
    }
}

#[derive(Clone, Copy)]
struct TxLeaseLayout {
    slot: SlotId,
    offset: u64,
    length: u32,
}

#[derive(Clone, Debug)]
struct BufferSlot {
    kind: SlotKind,
    offset: usize,
    len: usize,
    state: SlotState,
    generation: u16,
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
        leases: LeaseBook,
        recycle_notifier: LeaseRecycleNotifier,
        accepting: bool,
    }

    impl UrmaBufferPool {
        pub(crate) fn create(
            runtime: &mut ffi::NativeRuntime,
            config: BufferPoolConfig,
            recycle_notifier: LeaseRecycleNotifier,
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
                    generation: 0,
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
                    generation: 0,
                });
            }
            let free_tx = (0..config.tx_slot_count).rev().collect();
            let free_rx = (config.tx_slot_count..slot_count).collect();
            Ok(Self {
                segment: Some(segment),
                slots,
                free_tx,
                free_rx,
                leases: LeaseBook::new(),
                recycle_notifier,
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
            slot.generation = slot.generation.wrapping_add(1);
            if slot.generation == 0 {
                slot.generation = 1;
            }
            slot.state = SlotState::Allocated;
            SlotId::new(index, slot.generation).ok()
        }

        pub(crate) fn allocate_rx_window(&mut self, count: usize) -> Result<Vec<SlotId>> {
            if count == 0 {
                return Err(Error::InvalidConfiguration(
                    "RX window slot count must be non-zero".into(),
                ));
            }
            if !self.accepting || self.free_rx.len() < count {
                return Err(Error::BufferUnavailable {
                    kind: "RX",
                    requested: count,
                    available: if self.accepting {
                        self.free_rx.len()
                    } else {
                        0
                    },
                });
            }
            let mut slots = Vec::with_capacity(count);
            for _ in 0..count {
                slots.push(
                    self.allocate(SlotKind::Rx)
                        .expect("free RX count checked before allocation"),
                );
            }
            Ok(slots)
        }

        pub(crate) fn release_unposted_rx_window(&mut self, slots: Vec<SlotId>) -> Result<()> {
            for slot in slots {
                self.release(slot)?;
            }
            Ok(())
        }

        pub(crate) fn release(&mut self, id: SlotId) -> Result<()> {
            let index = id.index();
            let slot = self.slots.get_mut(index).ok_or_else(|| {
                Error::InvalidConfiguration("slot id is outside this buffer pool".into())
            })?;
            if slot.generation != id.generation() {
                return Err(Error::Protocol("stale slot generation".into()));
            }
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
                SlotKind::Tx => self.free_tx.push(index),
                SlotKind::Rx => self.free_rx.push_back(index),
            }
            Ok(())
        }

        pub(crate) fn segment_handle(&self) -> Result<&ffi::SegmentHandle> {
            self.segment
                .as_ref()
                .map(|segment| &segment.handle)
                .ok_or_else(|| Error::InvalidConfiguration("registered Segment is closed".into()))
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
            let (_, _, expected_kind, _) = self.slot_fields(id)?;
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

        pub(crate) fn tx_lease_layouts(
            &self,
            lease: &TxWindowLease,
        ) -> Result<Vec<(SlotId, u64, u32)>> {
            if lease.layouts.is_empty() {
                return Err(Error::Protocol("TX lease has no layouts".into()));
            }
            for layout in &lease.layouts {
                let (_, _, kind, state) = self.slot_fields(layout.slot)?;
                if kind != SlotKind::Tx || state != SlotState::LeasedTx {
                    return Err(Error::Protocol(
                        "TX lease layout does not reference a leased TX slot".into(),
                    ));
                }
            }
            Ok(lease
                .layouts
                .iter()
                .map(|layout| (layout.slot, layout.offset, layout.length))
                .collect())
        }

        pub(crate) fn mark_tx_lease_posted(&mut self, id: SlotId) -> Result<()> {
            self.transition(id, SlotState::LeasedTx, SlotState::SendPosted)
        }

        pub(crate) fn rollback_tx_lease_post(&mut self, id: SlotId) -> Result<()> {
            self.transition(id, SlotState::SendPosted, SlotState::LeasedTx)
        }

        pub(crate) fn complete_tx_lease_send(&mut self, id: SlotId) -> Result<()> {
            self.transition(id, SlotState::SendPosted, SlotState::LeasedTx)
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

        /// Marks one RX CQE complete without copying its registered bytes.
        /// B2 will group these completions into a published window lease.
        #[allow(dead_code)] // Selected by the B2 completion route.
        pub(crate) fn complete_recv_leased(&mut self, id: SlotId, length: u32) -> Result<()> {
            let (_, capacity, kind, state) = self.slot_fields(id)?;
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
            self.transition(id, SlotState::PostedRecv, SlotState::RecvCompleted)
        }

        #[allow(dead_code)] // Selected by the B2 completion route.
        pub(crate) fn lease_completed_rx_window(
            &mut self,
            completions: &[(SlotId, u32)],
        ) -> Result<RegisteredRxWindowLease> {
            if completions.is_empty() {
                return Err(Error::InvalidConfiguration(
                    "RX window lease requires at least one completion".into(),
                ));
            }
            let (base, registered_len) = self
                .segment_handle()?
                .data()
                .map_err(|error| native_error("borrow_rx_window", error))?;
            let mut spans: Vec<RegisteredSpan> = Vec::with_capacity(completions.len());
            let mut slots = Vec::with_capacity(completions.len());
            let mut total = 0usize;
            let mut previous_end = None;
            for (position, &(slot, length)) in completions.iter().enumerate() {
                let (offset, capacity, kind, state) = self.slot_fields(slot)?;
                let length = usize::try_from(length)
                    .map_err(|_| Error::Protocol("completion length exceeds usize".into()))?;
                if kind != SlotKind::Rx || state != SlotState::RecvCompleted {
                    return Err(Error::Protocol(
                        "RX lease requires completed receive slots".into(),
                    ));
                }
                if length == 0 || length > capacity {
                    return Err(Error::Protocol("invalid RX lease chunk length".into()));
                }
                if position + 1 != completions.len() && length != capacity {
                    return Err(Error::Protocol(
                        "only the final RX lease chunk may be short".into(),
                    ));
                }
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| Error::Protocol("RX lease offset overflow".into()))?;
                if end > registered_len {
                    return Err(Error::Protocol(
                        "RX lease span exceeds registered Segment".into(),
                    ));
                }
                // SAFETY: offset..end was checked against the live Segment.
                let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(offset)) };
                if previous_end == Some(offset) {
                    let previous = spans.last_mut().expect("previous span exists");
                    previous.length = previous
                        .length
                        .checked_add(length)
                        .ok_or_else(|| Error::Protocol("RX lease length overflow".into()))?;
                } else {
                    spans.push(RegisteredSpan { data, length });
                }
                previous_end = Some(end);
                total = total
                    .checked_add(length)
                    .ok_or_else(|| Error::Protocol("RX lease length overflow".into()))?;
                slots.push(slot);
            }
            for &slot in &slots {
                self.transition(slot, SlotState::RecvCompleted, SlotState::LeasedRx)?;
            }
            let recycle = match self.leases.issue(LeaseKind::Rx, slots.clone()) {
                Ok(recycle) => recycle,
                Err(error) => {
                    for slot in slots {
                        self.transition(slot, SlotState::LeasedRx, SlotState::RecvCompleted)?;
                    }
                    return Err(error);
                }
            };
            Ok(RegisteredRxWindowLease {
                spans,
                length: total,
                cores: vec![LeaseCore {
                    recycle: Some(recycle),
                    notifier: self.recycle_notifier.clone(),
                }],
                pipeline_permit: None,
                #[cfg(test)]
                _test_backing: Vec::new(),
            })
        }

        pub(crate) fn acquire_tx_window(&mut self, length: usize) -> Result<TxWindowLease> {
            self.acquire_tx_window_chunks(&[length])
        }

        /// Leases one TX slot per message. Payload spans are logically packed
        /// even when a negotiated chunk is smaller than the fixed slot size;
        /// provider offsets still point at distinct slots so all SENDs may be
        /// outstanding concurrently.
        pub(crate) fn acquire_tx_window_chunks(
            &mut self,
            chunk_lengths: &[usize],
        ) -> Result<TxWindowLease> {
            if chunk_lengths.is_empty() || chunk_lengths.contains(&0) {
                return Err(Error::InvalidConfiguration(
                    "TX window lease requires non-empty chunks".into(),
                ));
            }
            let slot_capacity = self
                .slots
                .iter()
                .find(|slot| slot.kind == SlotKind::Tx)
                .map(|slot| slot.len)
                .ok_or_else(|| Error::InvalidConfiguration("TX pool is empty".into()))?;
            if let Some(length) = chunk_lengths.iter().find(|length| **length > slot_capacity) {
                return Err(Error::InvalidConfiguration(format!(
                    "TX chunk length {length} exceeds slot capacity {slot_capacity}"
                )));
            }
            let encoded_lengths = chunk_lengths
                .iter()
                .map(|length| {
                    u32::try_from(*length).map_err(|_| {
                        Error::InvalidConfiguration("TX chunk length exceeds u32".into())
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let slot_count = chunk_lengths.len();
            let length = chunk_lengths.iter().try_fold(0usize, |total, length| {
                total
                    .checked_add(*length)
                    .ok_or_else(|| Error::InvalidConfiguration("TX window length overflow".into()))
            })?;
            let available = self
                .slots
                .iter()
                .take_while(|slot| slot.kind == SlotKind::Tx)
                .filter(|slot| slot.state == SlotState::Free)
                .count();
            let start = self
                .slots
                .iter()
                .take_while(|slot| slot.kind == SlotKind::Tx)
                .map(|slot| slot.state)
                .collect::<Vec<_>>()
                .windows(slot_count)
                .position(|states| states.iter().all(|state| *state == SlotState::Free))
                .ok_or(Error::BufferUnavailable {
                    kind: "TX",
                    requested: slot_count,
                    available,
                })?;
            let (base, registered_len) = self
                .segment_handle()?
                .data()
                .map_err(|error| native_error("borrow_tx_window", error))?;
            let mut slots = Vec::with_capacity(slot_count);
            let mut spans = Vec::with_capacity(slot_count);
            let mut layouts = Vec::with_capacity(slot_count);
            for index in start..start + slot_count {
                self.free_tx.retain(|free| *free != index);
                let slot = self
                    .slots
                    .get_mut(index)
                    .expect("TX window was bounded by slots");
                slot.generation = slot.generation.wrapping_add(1);
                if slot.generation == 0 {
                    slot.generation = 1;
                }
                slot.state = SlotState::LeasedTx;
                let id = SlotId::new(index, slot.generation)?;
                let chunk_length = chunk_lengths[slots.len()];
                let end = slot.offset.checked_add(chunk_length).ok_or_else(|| {
                    Error::InvalidConfiguration("TX window offset overflow".into())
                })?;
                if end > registered_len {
                    return Err(Error::InvalidConfiguration(
                        "TX window exceeds registered Segment".into(),
                    ));
                }
                // SAFETY: this slot span was bounds checked against the live Segment.
                let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(slot.offset)) };
                spans.push(RegisteredSpan {
                    data,
                    length: chunk_length,
                });
                layouts.push(TxLeaseLayout {
                    slot: id,
                    offset: u64::try_from(slot.offset).map_err(|_| {
                        Error::InvalidConfiguration("TX slot offset exceeds u64".into())
                    })?,
                    length: encoded_lengths[slots.len()],
                });
                slots.push(id);
            }
            let recycle = match self.leases.issue(LeaseKind::Tx, slots.clone()) {
                Ok(recycle) => recycle,
                Err(error) => {
                    for slot in slots {
                        self.transition(slot, SlotState::LeasedTx, SlotState::Allocated)?;
                        self.release(slot)?;
                    }
                    return Err(error);
                }
            };
            Ok(TxWindowLease {
                spans,
                layouts,
                length,
                core: LeaseCore {
                    recycle: Some(recycle),
                    notifier: self.recycle_notifier.clone(),
                },
                #[cfg(test)]
                _test_backing: Vec::new().into_boxed_slice(),
            })
        }

        pub(crate) fn recycle_rx_lease(
            &mut self,
            mut lease: RegisteredRxWindowLease,
        ) -> Result<usize> {
            let mut count = 0usize;
            for core in &mut lease.cores {
                let recycle = core.recycle()?;
                count = count
                    .checked_add(self.recycle(recycle, LeaseKind::Rx)?)
                    .ok_or_else(|| Error::Protocol("RX recycle count overflow".into()))?;
                core.disarm();
            }
            Ok(count)
        }

        pub(crate) fn recycle_tx_lease(&mut self, mut lease: TxWindowLease) -> Result<usize> {
            let recycle = lease.core.recycle()?;
            let count = self.recycle(recycle, LeaseKind::Tx)?;
            lease.core.disarm();
            Ok(count)
        }

        pub(crate) fn recycle_dropped_lease(&mut self, recycle: LeaseRecycle) -> Result<usize> {
            let kind = self.leases.record(recycle)?.kind;
            self.recycle(recycle, kind)
        }

        fn recycle(&mut self, recycle: LeaseRecycle, expected: LeaseKind) -> Result<usize> {
            let record = self.leases.record(recycle)?;
            if record.kind != expected {
                return Err(Error::Protocol("registered lease kind mismatch".into()));
            }
            for &slot in &record.slots {
                let (_, _, kind, state) = self.slot_fields(slot)?;
                let valid = matches!(
                    (expected, kind, state),
                    (LeaseKind::Rx, SlotKind::Rx, SlotState::LeasedRx)
                        | (LeaseKind::Tx, SlotKind::Tx, SlotState::LeasedTx)
                );
                if !valid {
                    return Err(Error::Protocol(
                        "registered lease slot state mismatch".into(),
                    ));
                }
            }
            let record = self.leases.finish(recycle)?;
            let count = record.slots.len();
            for slot in record.slots {
                let completed = match expected {
                    LeaseKind::Rx => SlotState::RecvCompleted,
                    LeaseKind::Tx => SlotState::Allocated,
                };
                let leased = match expected {
                    LeaseKind::Rx => SlotState::LeasedRx,
                    LeaseKind::Tx => SlotState::LeasedTx,
                };
                self.transition(slot, leased, completed)?;
                self.release(slot)?;
            }
            Ok(count)
        }

        fn slot_fields(&self, id: SlotId) -> Result<(usize, usize, SlotKind, SlotState)> {
            let slot = self.slots.get(id.index()).ok_or_else(|| {
                Error::InvalidConfiguration("slot id is outside buffer pool".into())
            })?;
            if slot.generation != id.generation() {
                return Err(Error::Protocol("stale slot generation".into()));
            }
            Ok((slot.offset, slot.len, slot.kind, slot.state))
        }

        fn transition(&mut self, id: SlotId, from: SlotState, to: SlotState) -> Result<()> {
            let slot = self
                .slots
                .get_mut(id.index())
                .ok_or_else(|| Error::Protocol("completion slot is outside buffer pool".into()))?;
            if slot.generation != id.generation() {
                return Err(Error::Protocol("stale slot generation".into()));
            }
            if slot.state != from {
                return Err(Error::Protocol(format!(
                    "slot {} state {:?}, expected {:?}",
                    id.index(),
                    slot.state,
                    from
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
            self.leases.ensure_empty()?;
            let Some(segment) = self.segment.as_mut() else {
                return Ok(());
            };
            segment.close()?;
            self.segment = None;
            Ok(())
        }
    }

    impl Drop for UrmaBufferPool {
        fn drop(&mut self) {
            if self.leases.active() != 0 {
                // Active leases may still be read or filled on another thread.
                // Isolate the native Segment instead of letting field Drop
                // unregister and free backing that those leases reference.
                if let Some(segment) = self.segment.take() {
                    std::mem::forget(segment);
                }
            }
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
    use std::sync::{mpsc, Mutex};

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

    #[test]
    fn slot_identity_round_trip_includes_generation() {
        let first = SlotId::new(1234, 7).unwrap();
        let reused = SlotId::new(1234, 8).unwrap();
        assert_eq!(SlotId::decode(first.encode()), Ok(first));
        assert_ne!(first.encode(), reused.encode());
        assert!(SlotId::decode(1234).is_err());
    }

    #[test]
    fn lease_book_rejects_wrong_pool_and_double_recycle() {
        let slot = SlotId::new(4, 2).unwrap();
        let mut first = LeaseBook::new();
        let second = LeaseBook::new();
        let recycle = first.issue(LeaseKind::Rx, vec![slot]).unwrap();

        assert!(second.record(recycle).is_err());
        assert_eq!(first.active(), 1);
        let record = first.finish(recycle).unwrap();
        assert_eq!(record.kind, LeaseKind::Rx);
        assert_eq!(record.slots, vec![slot]);
        assert!(first.finish(recycle).is_err());
    }

    #[test]
    fn active_lease_blocks_registered_pool_close_gate() {
        let mut leases = LeaseBook::new();
        let recycle = leases
            .issue(LeaseKind::Tx, vec![SlotId::new(1, 1).unwrap()])
            .unwrap();
        assert!(leases.ensure_empty().is_err());
        leases.finish(recycle).unwrap();
        assert!(leases.ensure_empty().is_ok());
    }

    #[test]
    fn dropped_rx_lease_notifies_owner_and_keeps_tail_parts_borrowed() {
        let mut leases = LeaseBook::new();
        let slots = vec![SlotId::new(3, 1).unwrap(), SlotId::new(4, 1).unwrap()];
        let recycle = leases.issue(LeaseKind::Rx, slots).unwrap();
        let (tx, rx) = mpsc::channel();
        let notifier: LeaseRecycleNotifier = Arc::new(move |recycle| {
            tx.send(recycle).unwrap();
        });
        let lease = RegisteredRxWindowLease::from_test_parts(
            vec![vec![1, 2, 3, 4], vec![5, 6]],
            recycle,
            notifier,
        );

        assert_eq!(lease.len(), 6);
        assert_eq!(
            lease.parts().collect::<Vec<_>>(),
            vec![&[1, 2, 3, 4][..], &[5, 6][..]]
        );
        drop(lease);

        let returned = rx.recv().unwrap();
        assert_eq!(returned, recycle);
        // Drop only notifies. The owner remains authoritative for recycling
        // and therefore for the close gate.
        assert_eq!(leases.active(), 1);
        leases.finish(returned).unwrap();
        assert!(leases.ensure_empty().is_ok());
    }

    #[test]
    fn merged_rx_window_preserves_parts_recycles_every_slot_and_holds_pipeline_credit() {
        let mut leases = LeaseBook::new();
        let first = leases
            .issue(LeaseKind::Rx, vec![SlotId::new(8, 1).unwrap()])
            .unwrap();
        let second = leases
            .issue(LeaseKind::Rx, vec![SlotId::new(9, 1).unwrap()])
            .unwrap();
        let returned = Arc::new(Mutex::new(Vec::new()));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| returned.lock().unwrap().push(recycle))
        };
        let first_window = RegisteredRxWindowLease::from_test_parts(
            vec![vec![1, 2, 3, 4]],
            first,
            notifier.clone(),
        );
        let tail_window =
            RegisteredRxWindowLease::from_test_parts(vec![vec![5, 6]], second, notifier);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = permits.clone().try_acquire_owned().unwrap();
        let window = RegisteredRxWindowLease::merge(vec![first_window, tail_window])
            .unwrap()
            .with_pipeline_permit(permit);

        assert_eq!(window.len(), 6);
        assert_eq!(
            window.parts().collect::<Vec<_>>(),
            vec![&[1, 2, 3, 4][..], &[5, 6][..]]
        );
        assert!(permits.clone().try_acquire_owned().is_err());
        drop(window);
        assert!(permits.try_acquire_owned().is_ok());
        let mut actual = returned.lock().unwrap().clone();
        actual.sort_by_key(|recycle| recycle.lease_id);
        assert_eq!(actual, vec![first, second]);
    }

    #[test]
    fn tx_lease_exposes_exclusive_direct_fill() {
        let mut leases = LeaseBook::new();
        let recycle = leases
            .issue(LeaseKind::Tx, vec![SlotId::new(0, 1).unwrap()])
            .unwrap();
        let returned = Arc::new(Mutex::new(None));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| *returned.lock().unwrap() = Some(recycle))
        };
        let mut backing = vec![0u8; 7].into_boxed_slice();
        let data = NonNull::new(backing.as_mut_ptr()).unwrap();
        let mut lease = TxWindowLease {
            spans: vec![RegisteredSpan {
                data,
                length: backing.len(),
            }],
            layouts: vec![TxLeaseLayout {
                slot: SlotId::new(0, 1).unwrap(),
                offset: 0,
                length: backing.len() as u32,
            }],
            length: backing.len(),
            core: LeaseCore {
                recycle: Some(recycle),
                notifier,
            },
            _test_backing: backing,
        };
        lease.bytes_mut().copy_from_slice(b"direct!");
        assert_eq!(lease.len(), 7);
        assert_eq!(&*lease._test_backing, b"direct!");
        drop(lease);
        assert_eq!(*returned.lock().unwrap(), Some(recycle));
    }

    #[test]
    fn tx_lease_reshape_preserves_distinct_chunk_spans_and_trims_tail() {
        let slots = (0..3)
            .map(|index| SlotId::new(index, 1).unwrap())
            .collect::<Vec<_>>();
        let mut leases = LeaseBook::new();
        let recycle = leases.issue(LeaseKind::Tx, slots.clone()).unwrap();
        let notifier: LeaseRecycleNotifier = Arc::new(|_| {});
        let mut backing = vec![0u8; 12].into_boxed_slice();
        let base = backing.as_mut_ptr();
        let mut lease = TxWindowLease {
            spans: (0..3)
                .map(|index| RegisteredSpan {
                    // SAFETY: every four-byte span is within `backing`.
                    data: unsafe { NonNull::new_unchecked(base.add(index * 4)) },
                    length: 4,
                })
                .collect(),
            layouts: slots
                .into_iter()
                .enumerate()
                .map(|(index, slot)| TxLeaseLayout {
                    slot,
                    offset: (index * 4) as u64,
                    length: 4,
                })
                .collect(),
            length: 12,
            core: LeaseCore {
                recycle: Some(recycle),
                notifier,
            },
            _test_backing: backing,
        };

        lease.reshape(&[4, 1]).unwrap();
        assert_eq!(lease.len(), 5);
        assert_eq!(lease.chunk_count(), 2);
        lease.part_mut(0).unwrap().copy_from_slice(b"full");
        lease.part_mut(1).unwrap().copy_from_slice(b"!");
        assert_eq!(&lease._test_backing[..5], b"full!");
        assert!(lease.reshape(&[4, 2, 4]).is_err());
    }

    #[test]
    fn lease_thread_traits_match_access_modes() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RegisteredRxWindowLease>();
        assert_send::<TxWindowLease>();
    }
}
