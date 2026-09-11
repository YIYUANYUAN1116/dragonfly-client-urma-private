//! Device-independent READ planning and accepted-WR accounting.
//!
//! No native operations or wire capability are enabled by this module. The future
//! owner must retain buffer, imported Segment and PeerTarget owners independently
//! of this bookkeeping. Local drain is not remote revocation or permission to
//! publish data to Storage: unimport and the terminal control gate still follow.

use std::collections::BTreeSet;
use std::num::NonZeroU32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadError {
    UnsupportedLimit,
    InvalidRange,
    SliceOutOfRange,
    InvalidAdmission,
    PostingClosed,
    PostInProgress,
    NoPostInProgress,
    InvalidAcceptedPrefix,
    UnknownCompletion,
    InvalidCompletionLength,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "READ contract violation: {self:?}")
    }
}

impl std::error::Error for ReadError {}

/// A byte limit, never inferred from SEND max_msg_size or a fixed 256M value.
/// The caller must separately validate RM/profile support and one local/remote SGE.
pub(crate) fn negotiate_read_size(
    device_max: u32,
    peer_max: u32,
    configured_max: u32,
) -> Result<NonZeroU32, ReadError> {
    NonZeroU32::new(device_max.min(peer_max).min(configured_max)).ok_or(ReadError::UnsupportedLimit)
}

/// Bounds of a local allocation or an imported remote Segment, in bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadRegion {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) piece_offset: u64,
}

impl ReadRegion {
    fn piece_base(self, piece_length: u64) -> Result<u64, ReadError> {
        self.base
            .checked_add(self.length)
            .ok_or(ReadError::InvalidRange)?;
        let end = self
            .piece_offset
            .checked_add(piece_length)
            .ok_or(ReadError::InvalidRange)?;
        if end > self.length {
            return Err(ReadError::InvalidRange);
        }
        self.base
            .checked_add(self.piece_offset)
            .ok_or(ReadError::InvalidRange)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadSlice {
    pub(crate) index: u64,
    pub(crate) offset: u64,
    pub(crate) local_address: u64,
    pub(crate) remote_address: u64,
    pub(crate) length: u32,
}

/// Constant-space plan, including when a small limit produces many slices.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadPlan {
    piece_length: u64,
    max_read_size: NonZeroU32,
    local_base: u64,
    remote_base: u64,
}

impl ReadPlan {
    pub(crate) fn new(
        piece_length: u64,
        max_read_size: NonZeroU32,
        local: ReadRegion,
        remote: ReadRegion,
    ) -> Result<Self, ReadError> {
        // Rust slices/allocations cannot exceed isize::MAX. Byte-budget admission
        // is a separate requirement; successful planning does not allocate memory.
        if piece_length == 0 || piece_length > isize::MAX as u64 {
            return Err(ReadError::InvalidRange);
        }
        let local_base = local.piece_base(piece_length)?;
        let remote_base = remote.piece_base(piece_length)?;
        let local_end = local_base + piece_length;
        if usize::try_from(local_end).is_err() {
            return Err(ReadError::InvalidRange);
        }
        Ok(Self {
            piece_length,
            max_read_size,
            local_base,
            remote_base,
        })
    }

    pub(crate) fn slice_count(self) -> u64 {
        self.piece_length
            .div_ceil(u64::from(self.max_read_size.get()))
    }

    pub(crate) fn slice(self, index: u64) -> Result<ReadSlice, ReadError> {
        if index >= self.slice_count() {
            return Err(ReadError::SliceOutOfRange);
        }
        // Valid index and the checked region bounds make all additions bounded.
        let offset = index * u64::from(self.max_read_size.get());
        Ok(ReadSlice {
            index,
            offset,
            local_address: self.local_base + offset,
            remote_address: self.remote_base + offset,
            length: (self.piece_length - offset).min(u64::from(self.max_read_size.get())) as u32,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadPostBatch {
    pub(crate) start: u64,
    pub(crate) count: u32,
}

/// Per-transfer bookkeeping after the outer registry has validated peer/transfer/
/// Segment generations and CQE identity. Pending storage is bounded by admission,
/// not total slice count. One owner serializes post results and CQE processing.
#[derive(Debug)]
pub(crate) struct ReadProgress {
    plan: ReadPlan,
    max_outstanding: NonZeroU32,
    accepted: u64,
    pending_post: Option<ReadPostBatch>,
    pending: BTreeSet<u64>,
    successful_bytes: u64,
    stopped: bool,
    failed: bool,
    uncertain: bool,
}

impl ReadProgress {
    pub(crate) fn new(plan: ReadPlan, max_outstanding: NonZeroU32) -> Self {
        Self {
            plan,
            max_outstanding,
            accepted: 0,
            pending_post: None,
            pending: BTreeSet::new(),
            successful_bytes: 0,
            stopped: false,
            failed: false,
            uncertain: false,
        }
    }

    /// Reserves a batch before native post. The caller also needs shared JFS and
    /// peer permits and must cap the list to the native shim's post-list limit.
    pub(crate) fn begin_post(&mut self, count: u32) -> Result<ReadPostBatch, ReadError> {
        if self.stopped || self.accepted == self.plan.slice_count() {
            return Err(ReadError::PostingClosed);
        }
        if self.pending_post.is_some() {
            return Err(ReadError::PostInProgress);
        }
        let available = u64::from(self.max_outstanding.get()) - self.pending.len() as u64;
        if count == 0
            || u64::from(count) > available
            || u64::from(count) > self.plan.slice_count() - self.accepted
        {
            return Err(ReadError::InvalidAdmission);
        }
        let batch = ReadPostBatch {
            start: self.accepted,
            count,
        };
        self.pending_post = Some(batch);
        Ok(batch)
    }

    /// Commit only the provider-accepted prefix. Cancellation does not erase a
    /// reserved batch: post may already have reached hardware. An error with zero
    /// accepted WRs is legal; a partial success without an error is not.
    pub(crate) fn finish_post(
        &mut self,
        accepted: u32,
        post_failed: bool,
    ) -> Result<(), ReadError> {
        let Some(batch) = self.pending_post else {
            self.mark_uncertain();
            return Err(ReadError::NoPostInProgress);
        };
        if accepted > batch.count || (!post_failed && accepted != batch.count) {
            self.mark_uncertain();
            return Err(ReadError::InvalidAcceptedPrefix);
        }
        self.pending_post = None;
        self.pending
            .extend(batch.start..batch.start + u64::from(accepted));
        self.accepted += u64::from(accepted);
        if post_failed {
            self.stopped = true;
            self.failed = true;
        }
        Ok(())
    }

    /// A failed CQE retires its known WR but cannot prove successful byte coverage.
    /// `successful_length` is None for failed/flush-error CQEs. The future shim
    /// must first establish the provider's READ completion_len contract.
    pub(crate) fn complete(
        &mut self,
        index: u64,
        successful_length: Option<u32>,
    ) -> Result<(), ReadError> {
        if !self.pending.contains(&index) {
            self.mark_uncertain();
            return Err(ReadError::UnknownCompletion);
        }
        let slice = self.plan.slice(index)?;
        if successful_length.is_some_and(|length| length != slice.length) {
            self.mark_uncertain();
            return Err(ReadError::InvalidCompletionLength);
        }
        self.pending.remove(&index);
        if successful_length.is_some() {
            self.successful_bytes += u64::from(slice.length);
        } else {
            self.failed = true;
            self.stopped = true;
        }
        Ok(())
    }

    pub(crate) fn cancel(&mut self) {
        self.stopped = true;
    }

    fn mark_uncertain(&mut self) {
        self.stopped = true;
        self.failed = true;
        self.uncertain = true;
    }

    /// True only when no further native post can occur and all accepted WRs are
    /// retired. This is NOT a remote Segment revocation or Storage publication gate.
    pub(crate) fn locally_drained(&self) -> bool {
        !self.uncertain
            && self.pending_post.is_none()
            && self.pending.is_empty()
            && (self.stopped || self.accepted == self.plan.slice_count())
    }

    pub(crate) fn read_succeeded(&self) -> bool {
        self.locally_drained()
            && !self.stopped
            && !self.failed
            && self.successful_bytes == self.plan.piece_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(length: u64) -> ReadRegion {
        ReadRegion {
            base: 4096,
            length,
            piece_offset: 0,
        }
    }

    fn plan(length: u64, limit: u32) -> ReadPlan {
        ReadPlan::new(
            length,
            NonZeroU32::new(limit).unwrap(),
            region(length),
            region(length),
        )
        .unwrap()
    }

    fn progress() -> ReadProgress {
        ReadProgress::new(plan(10, 4), NonZeroU32::new(2).unwrap())
    }

    #[test]
    fn limits_are_minimum_bytes_and_zero_disables_read() {
        for (a, b, c) in [(8, 16, 32), (16, 8, 32), (16, 32, 8)] {
            assert_eq!(negotiate_read_size(a, b, c).unwrap().get(), 8);
        }
        for (a, b, c) in [(0, 16, 32), (16, 0, 32), (16, 32, 0)] {
            assert_eq!(
                negotiate_read_size(a, b, c),
                Err(ReadError::UnsupportedLimit)
            );
        }
    }

    #[test]
    fn slices_cover_boundary_and_tail_without_overlap() {
        for limit in [1, 4096, 8192, 65536] {
            for length in [1, 8191, 8192, 8193, 65536, 65537] {
                let plan = plan(length, limit);
                let mut offset = 0;
                for index in 0..plan.slice_count() {
                    let slice = plan.slice(index).unwrap();
                    assert_eq!(slice.offset, offset);
                    assert_eq!(slice.local_address, 4096 + offset);
                    assert_eq!(slice.remote_address, 4096 + offset);
                    assert!(slice.length > 0 && slice.length <= limit);
                    offset += u64::from(slice.length);
                }
                assert_eq!(offset, length);
                assert_eq!(
                    plan.slice(plan.slice_count()),
                    Err(ReadError::SliceOutOfRange)
                );
            }
        }
    }

    #[test]
    fn large_plan_is_lazy_and_sge_lengths_fit_u32() {
        let length = u64::from(u32::MAX) + 17;
        if length <= isize::MAX as u64 {
            let wide_plan = plan(length, u32::MAX);
            assert_eq!(wide_plan.slice_count(), 2);
            assert_eq!(wide_plan.slice(0).unwrap().length, u32::MAX);
            assert_eq!(wide_plan.slice(1).unwrap().length, 17);
            let tiny_limit = plan(length, 1);
            assert_eq!(tiny_limit.slice_count(), length);
            assert_eq!(tiny_limit.slice(length - 1).unwrap().length, 1);
        }
    }

    #[test]
    fn range_checks_both_regions_and_address_overflow() {
        let limit = NonZeroU32::new(8).unwrap();
        let good = region(32);
        for bad in [
            ReadRegion { length: 7, ..good },
            ReadRegion {
                piece_offset: 25,
                ..good
            },
            ReadRegion {
                piece_offset: u64::MAX,
                ..good
            },
            ReadRegion {
                base: u64::MAX - 3,
                ..good
            },
        ] {
            assert_eq!(
                ReadPlan::new(8, limit, bad, good).unwrap_err(),
                ReadError::InvalidRange
            );
            assert_eq!(
                ReadPlan::new(8, limit, good, bad).unwrap_err(),
                ReadError::InvalidRange
            );
        }
        assert!(ReadPlan::new(0, limit, good, good).is_err());
        assert!(ReadPlan::new(isize::MAX as u64 + 1, limit, good, good).is_err());
        let plan = ReadPlan::new(
            8,
            limit,
            ReadRegion {
                piece_offset: 3,
                ..good
            },
            ReadRegion {
                base: 8192,
                piece_offset: 5,
                ..good
            },
        )
        .unwrap();
        assert_eq!(plan.slice(0).unwrap().local_address, 4099);
        assert_eq!(plan.slice(0).unwrap().remote_address, 8197);
    }

    #[test]
    fn out_of_order_cqes_and_sliding_admission_complete_exact_coverage() {
        let mut p = progress();
        assert!(!p.locally_drained());
        assert_eq!(p.begin_post(3), Err(ReadError::InvalidAdmission));
        p.begin_post(2).unwrap();
        assert_eq!(p.begin_post(1), Err(ReadError::PostInProgress));
        p.finish_post(2, false).unwrap();
        assert_eq!(p.begin_post(1), Err(ReadError::InvalidAdmission));
        p.complete(1, Some(4)).unwrap();
        assert_eq!(p.begin_post(1).unwrap().start, 2);
        p.finish_post(1, false).unwrap();
        p.complete(2, Some(2)).unwrap();
        assert!(!p.read_succeeded());
        p.complete(0, Some(4)).unwrap();
        assert!(p.read_succeeded());
        assert!(p.locally_drained());
        assert_eq!(p.begin_post(1), Err(ReadError::PostingClosed));
    }

    #[test]
    fn partial_post_waits_only_for_accepted_prefix() {
        let mut p = progress();
        p.begin_post(2).unwrap();
        p.finish_post(1, true).unwrap();
        assert!(!p.locally_drained());
        assert_eq!(p.begin_post(1), Err(ReadError::PostingClosed));
        p.complete(0, Some(4)).unwrap();
        assert!(p.locally_drained());
        assert!(!p.read_succeeded());
    }

    #[test]
    fn cancel_during_post_retains_unresolved_and_accepted_work() {
        let mut p = progress();
        p.begin_post(2).unwrap();
        p.cancel();
        assert!(!p.locally_drained());
        p.finish_post(2, false).unwrap();
        p.complete(1, None).unwrap();
        assert!(!p.locally_drained());
        p.complete(0, Some(4)).unwrap();
        assert!(p.locally_drained());
        assert!(!p.read_succeeded());
    }

    #[test]
    fn zero_prefix_failure_and_cancel_before_post_need_no_cqe() {
        let mut p = progress();
        p.begin_post(2).unwrap();
        p.finish_post(0, true).unwrap();
        assert!(p.locally_drained());
        assert!(!p.read_succeeded());
        let mut p = progress();
        p.cancel();
        assert!(p.locally_drained());
        assert!(!p.read_succeeded());
    }

    #[test]
    fn error_cqe_stops_posting_but_other_wr_still_requires_drain() {
        let mut p = progress();
        p.begin_post(2).unwrap();
        p.finish_post(2, false).unwrap();
        p.complete(0, None).unwrap();
        assert!(!p.locally_drained());
        assert_eq!(p.begin_post(1), Err(ReadError::PostingClosed));
        p.complete(1, Some(4)).unwrap();
        assert!(p.locally_drained());
        assert!(!p.read_succeeded());
    }

    #[test]
    fn inconsistent_post_result_never_proves_drain() {
        for (accepted, failed) in [(3, true), (1, false)] {
            let mut p = progress();
            p.begin_post(2).unwrap();
            assert_eq!(
                p.finish_post(accepted, failed),
                Err(ReadError::InvalidAcceptedPrefix)
            );
            p.cancel();
            assert!(!p.locally_drained());
            assert!(!p.read_succeeded());
        }
        let mut p = progress();
        assert_eq!(p.finish_post(1, false), Err(ReadError::NoPostInProgress));
        p.cancel();
        assert!(!p.locally_drained());
    }

    #[test]
    fn every_failed_prefix_and_completion_order_preserves_drain_gate() {
        for accepted in 0..=3 {
            for reverse in [false, true] {
                let mut p = ReadProgress::new(plan(10, 4), NonZeroU32::new(3).unwrap());
                p.begin_post(3).unwrap();
                p.finish_post(accepted, true).unwrap();
                for step in 0..accepted {
                    assert!(!p.locally_drained());
                    let index = if reverse { accepted - 1 - step } else { step };
                    let length = p.plan.slice(u64::from(index)).unwrap().length;
                    p.complete(u64::from(index), Some(length)).unwrap();
                }
                assert!(p.locally_drained());
                // Even a provider error accepting the entire list fails the attempt.
                assert!(!p.read_succeeded());
            }
        }
    }

    #[test]
    fn unknown_duplicate_and_wrong_length_fail_closed() {
        for (index, length, expected) in [
            (2, 2, ReadError::UnknownCompletion),
            (0, 3, ReadError::InvalidCompletionLength),
        ] {
            let mut p = progress();
            p.begin_post(2).unwrap();
            p.finish_post(2, false).unwrap();
            assert_eq!(p.complete(index, Some(length)), Err(expected));
            assert!(!p.locally_drained());
        }
        let mut p = progress();
        p.begin_post(2).unwrap();
        p.finish_post(2, false).unwrap();
        p.complete(0, Some(4)).unwrap();
        assert_eq!(p.complete(0, Some(4)), Err(ReadError::UnknownCompletion));
        p.complete(1, Some(4)).unwrap();
        assert!(!p.locally_drained());
    }
}
