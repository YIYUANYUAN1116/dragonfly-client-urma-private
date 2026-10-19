//! Piece-aligned registration range selection for one content instance.
//!
//! File allocation is not completion evidence. Only completed ranges may be
//! selected. All claimed ranges (including registration in progress and native
//! retirement) must be supplied by the cache owner under its reservation lock.
//! Selection alone neither reserves bytes nor grants a source lease.

use dragonfly_client_core::{Error, Result};
use std::ops::Range;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadRegionSelection {
    /// An existing claim covers the Piece. The cache must resolve its state:
    /// wait for registration, acquire a ready lease, or wait for retirement.
    Covered(Range<u64>),
    /// Reserve this entire range before releasing the cache lock or registering.
    Register(Range<u64>),
}

/// Fixed windows for one Task's Piece geometry. Window size rounds the byte
/// cap down to whole Pieces; the final window ends at the content length.
pub struct ReadRegionLayout {
    file_length: u64,
    piece_length: u64,
    window_length: u64,
}

impl ReadRegionLayout {
    pub fn new(file_length: u64, piece_length: u64, max_region_bytes: u64) -> Result<Self> {
        if file_length == 0 || piece_length == 0 || max_region_bytes == 0 {
            return Err(Error::InvalidParameter);
        }
        let window_length = if file_length <= max_region_bytes {
            file_length
        } else {
            (max_region_bytes / piece_length) * piece_length
        };
        if window_length == 0 {
            return Err(Error::Unsupported(
                "READ Piece exceeds the registration region limit".into(),
            ));
        }
        Ok(Self {
            file_length,
            piece_length,
            window_length,
        })
    }

    /// Selects for the whole Piece beginning at `piece_offset`. Inputs belong
    /// to this exact opened file instance, not another incarnation of a Task.
    /// Completed ranges may overlap; claimed ranges must be disjoint.
    pub fn select(
        &self,
        piece_offset: u64,
        completed: &[Range<u64>],
        claimed: &[Range<u64>],
    ) -> Result<ReadRegionSelection> {
        if piece_offset >= self.file_length || piece_offset % self.piece_length != 0 {
            return Err(Error::InvalidParameter);
        }
        let piece_end = piece_offset + self.piece_length.min(self.file_length - piece_offset);
        let mut completed = self.checked_ranges(completed)?;
        let claimed = self.checked_ranges(claimed)?;
        if claimed.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(Error::InvalidParameter);
        }

        // Completion may arrive as individual Pieces or merged intervals.
        // Merge adjacency as well as overlap, without bridging unfinished gaps.
        let mut merged: Vec<Range<u64>> = Vec::new();
        for range in completed.drain(..) {
            if let Some(last) = merged.last_mut() {
                if range.start <= last.end {
                    last.end = last.end.max(range.end);
                    continue;
                }
            }
            merged.push(range);
        }
        let completed = merged
            .into_iter()
            .find(|range| range.start <= piece_offset && range.end >= piece_end)
            .ok_or_else(|| Error::Unsupported("READ Piece is not completely available".into()))?;

        let window_start = piece_offset / self.window_length * self.window_length;
        let window_end = window_start + self.window_length.min(self.file_length - window_start);
        let mut selected = completed.start.max(window_start)..completed.end.min(window_end);
        for range in claimed {
            if range.start <= piece_offset && range.end >= piece_end {
                return Ok(ReadRegionSelection::Covered(range));
            }
            if range.end <= piece_offset {
                selected.start = selected.start.max(range.end);
            } else if range.start >= piece_end {
                selected.end = selected.end.min(range.start);
            } else {
                // Never split a single Piece across two source descriptors.
                return Err(Error::Unsupported(
                    "READ Piece partially overlaps an existing registration".into(),
                ));
            }
        }
        if selected.start > piece_offset || selected.end < piece_end {
            return Err(Error::InvalidParameter);
        }
        Ok(ReadRegionSelection::Register(selected))
    }

    fn checked_ranges(&self, ranges: &[Range<u64>]) -> Result<Vec<Range<u64>>> {
        if ranges.iter().any(|range| {
            range.start >= range.end
                || range.end > self.file_length
                || range.start % self.piece_length != 0
                || (range.end != self.file_length && range.end % self.piece_length != 0)
        }) {
            return Err(Error::InvalidParameter);
        }
        let mut ranges = ranges.to_vec();
        ranges.sort_unstable_by_key(|range| (range.start, range.end));
        Ok(ranges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growing_completion_registers_only_the_unclaimed_suffix() {
        let layout = ReadRegionLayout::new(80, 10, 80).unwrap();
        assert_eq!(
            layout.select(0, &[0..50], &[]).unwrap(),
            ReadRegionSelection::Register(0..50)
        );
        // The first claim may still be registering. It already excludes a
        // second registration of 0..60 when the sixth Piece finishes.
        assert_eq!(
            layout.select(50, &[0..60], &[0..50]).unwrap(),
            ReadRegionSelection::Register(50..60)
        );
        assert_eq!(
            layout.select(20, &[0..60], &[0..50, 50..60]).unwrap(),
            ReadRegionSelection::Covered(0..50)
        );
        assert_eq!(
            layout.select(60, &[0..80], &[0..50, 50..60]).unwrap(),
            ReadRegionSelection::Register(60..80)
        );
    }

    #[test]
    fn windows_round_down_to_pieces_and_include_a_short_final_piece() {
        let layout = ReadRegionLayout::new(95, 10, 35).unwrap();
        for (offset, expected) in [(20, 0..30), (30, 30..60), (90, 90..95)] {
            assert_eq!(
                layout.select(offset, &[0..95], &[]).unwrap(),
                ReadRegionSelection::Register(expected)
            );
        }
        let small = ReadRegionLayout::new(25, 10, 35).unwrap();
        assert_eq!(
            small.select(20, &[0..25], &[]).unwrap(),
            ReadRegionSelection::Register(0..25)
        );
    }

    #[test]
    fn unfinished_gaps_and_existing_claims_bound_new_registration() {
        let layout = ReadRegionLayout::new(100, 10, 100).unwrap();
        assert_eq!(
            layout.select(30, &[20..40, 0..10, 40..60], &[]).unwrap(),
            ReadRegionSelection::Register(20..60)
        );
        assert_eq!(
            layout.select(50, &[0..100], &[70..90, 0..30]).unwrap(),
            ReadRegionSelection::Register(30..70)
        );
        // A complete file length cannot substitute for Piece completion.
        assert!(layout.select(10, &[0..10, 20..100], &[]).is_err());
        assert!(layout.select(0, &[], &[0..100]).is_err());
    }

    #[test]
    fn invalid_geometry_claims_and_ranges_are_rejected() {
        assert!(ReadRegionLayout::new(100, 10, 9).is_err());
        for geometry in [(0, 10, 10), (100, 0, 10), (100, 10, 0)] {
            assert!(ReadRegionLayout::new(geometry.0, geometry.1, geometry.2).is_err());
        }
        let layout = ReadRegionLayout::new(100, 10, 30).unwrap();
        for ranges in [vec![0..0], vec![0..101], vec![1..10], vec![0..11]] {
            assert!(layout.select(0, &ranges, &[]).is_err());
        }
        assert!(layout.select(1, &[0..100], &[]).is_err());
        assert!(layout.select(100, &[0..100], &[]).is_err());
        assert!(layout.select(0, &[0..100], &[0..20, 10..30]).is_err());

        let huge = ReadRegionLayout::new(u64::MAX, 10, u64::MAX).unwrap();
        assert_eq!(
            huge.select(u64::MAX - 5, &[0..u64::MAX], &[]).unwrap(),
            ReadRegionSelection::Register(0..u64::MAX)
        );
    }
}
