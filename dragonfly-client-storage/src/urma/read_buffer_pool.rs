//! Owner-thread pooling of registered READ destination buffers.
//!
//! Every Piece used to allocate and register a fresh pinned destination buffer
//! and unregister it after the lease recycle, paying the full provider MR
//! round trip per Piece. The pool retains closed registered buffers keyed by
//! their allocation length so the next Piece of the same length reuses the
//! registration instead of recreating it.
//!
//! Pooled bytes are outside the peer owner registry, but remain charged to the
//! process destination budget. A miss evicts idle registrations until active
//! and retained bytes leave room for the new registration.

use super::ffi::{read::ReadBufferCreation, NativeRuntime, SegmentHandle};
use std::collections::BTreeMap;
use tracing::debug;

pub(crate) struct ReadBufferPool {
    max_retained_bytes: u64,
    retained_bytes: u64,
    classes: BTreeMap<u64, Vec<SegmentHandle>>,
}

impl ReadBufferPool {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            max_retained_bytes,
            retained_bytes: 0,
            classes: BTreeMap::new(),
        }
    }

    /// Borrows a registered destination buffer of exactly `length` bytes,
    /// reusing a pooled one when available and creating through the provider
    /// otherwise. `active_bytes` excludes the requested buffer and includes all
    /// other active destination owners. `alignment` only participates in fresh
    /// creation because all pooled buffers use the runtime-wide alignment.
    pub(crate) fn take(
        &mut self,
        runtime: &mut NativeRuntime,
        length: u64,
        alignment: u64,
        active_bytes: u64,
    ) -> ReadBufferCreation {
        let (hit, remove_class) = match self.classes.get_mut(&length) {
            Some(class) => (class.pop(), class.is_empty()),
            None => (None, false),
        };
        if remove_class {
            self.classes.remove(&length);
        }
        if let Some(buffer) = hit {
            let Some(retained_bytes) = self.retained_bytes.checked_sub(length) else {
                self.classes.entry(length).or_default().push(buffer);
                return ReadBufferCreation::Rejected(super::ffi::FfiError::Contract(
                    "READ pool retained bytes underflow on hit",
                ));
            };
            self.retained_bytes = retained_bytes;
            debug!(
                length,
                retained_bytes = self.retained_bytes,
                "urma READ pool hit"
            );
            return ReadBufferCreation::Ready(buffer);
        }
        let Some(retained_limit) = self
            .max_retained_bytes
            .checked_sub(active_bytes)
            .and_then(|available| available.checked_sub(length))
        else {
            return ReadBufferCreation::Rejected(super::ffi::FfiError::Contract(
                "READ destination budget exhausted before pool miss",
            ));
        };
        if let Err(error) = self.shrink_to(retained_limit) {
            return ReadBufferCreation::Rejected(error);
        }
        debug!(
            length,
            retained_bytes = self.retained_bytes,
            "urma READ pool miss; registering destination"
        );
        SegmentHandle::create_read_buffer(runtime, length, alignment)
    }

    /// Closes idle registrations until `retained_bytes <= limit`. A provider
    /// failure keeps the still-live handle in the pool and aborts the new
    /// allocation, preserving both ownership and budget accounting.
    fn shrink_to(&mut self, limit: u64) -> Result<(), super::ffi::FfiError> {
        while self.retained_bytes > limit {
            let Some((&length, _)) = self.classes.last_key_value() else {
                return Err(super::ffi::FfiError::Contract(
                    "READ pool retained-byte accounting diverged",
                ));
            };
            let (mut buffer, remove_class) = {
                let class = self.classes.get_mut(&length).expect("class exists");
                let buffer = class.pop().expect("pool classes are never empty");
                (buffer, class.is_empty())
            };
            if remove_class {
                self.classes.remove(&length);
            }
            if let Err(error) = buffer.close() {
                self.classes.entry(length).or_default().push(buffer);
                return Err(error);
            }
            self.retained_bytes =
                self.retained_bytes
                    .checked_sub(length)
                    .ok_or(super::ffi::FfiError::Contract(
                        "READ pool retained bytes underflow",
                    ))?;
            debug!(
                length,
                retained_bytes = self.retained_bytes,
                "urma READ pool evicted"
            );
        }
        Ok(())
    }

    /// Returns a registered buffer to the pool when the retention budget
    /// allows; `Err(buffer)` gives it back so the caller can close it.
    pub(crate) fn put(&mut self, buffer: SegmentHandle, length: u64) -> Result<(), SegmentHandle> {
        let Some(retained_bytes) = self.retained_after(length) else {
            return Err(buffer);
        };
        self.retained_bytes = retained_bytes;
        self.classes.entry(length).or_default().push(buffer);
        debug!(
            length,
            retained_bytes = self.retained_bytes,
            "urma READ pool returned"
        );
        Ok(())
    }

    fn should_retain(&self, length: u64) -> bool {
        self.retained_after(length).is_some()
    }

    fn retained_after(&self, length: u64) -> Option<u64> {
        self.retained_bytes
            .checked_add(length)
            .filter(|retained| *retained <= self.max_retained_bytes)
    }

    pub(crate) fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Closes every retained buffer. Handles whose provider close fails remain
    /// owned by the pool so shutdown cannot lose a live registered Segment.
    pub(crate) fn close_all(&mut self) -> Vec<super::ffi::FfiError> {
        let mut failures = Vec::new();
        let classes = std::mem::take(&mut self.classes);
        self.retained_bytes = 0;
        for (length, buffers) in classes {
            for mut buffer in buffers {
                if let Err(error) = buffer.close() {
                    self.retained_bytes = self.retained_bytes.saturating_add(length);
                    self.classes.entry(length).or_default().push(buffer);
                    failures.push(error);
                }
            }
        }
        failures
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_respects_capacity_and_frees_on_reuse() {
        let mut pool = ReadBufferPool::new(16);
        assert!(pool.should_retain(16));
        assert!(!pool.should_retain(17));
        // One 16-byte buffer fits; nothing else is retained until it is reused.
        assert!(pool.should_retain(16));
        pool.retained_bytes = 16;
        assert!(!pool.should_retain(16));
        pool.retained_bytes = 0;
        // Reuse releases the retained charge before the next admission check.
        assert!(pool.should_retain(16));
        assert_eq!(pool.retained_bytes(), 0);
    }

    #[test]
    fn empty_pool_take_delegates_to_provider() {
        // With no pooled buffer the pool cannot answer without a native
        // runtime; take must fall through to create_read_buffer, which rejects
        // a closed runtime instead of panicking.
        let mut pool = ReadBufferPool::new(64);
        let creation = pool.take(
            &mut super::super::ffi::NativeRuntime::without_native(),
            16,
            4096,
            0,
        );
        assert!(matches!(creation, ReadBufferCreation::Rejected(_)));
        assert_eq!(pool.retained_bytes(), 0);
    }

    #[test]
    fn miss_evicts_idle_registrations_before_fresh_allocation() {
        let mut pool = ReadBufferPool::new(16);
        pool.classes
            .entry(8)
            .or_default()
            .push(SegmentHandle::without_native());
        pool.classes
            .entry(8)
            .or_default()
            .push(SegmentHandle::without_native());
        pool.retained_bytes = 16;

        // A 16-byte miss has no budget alongside the old 8-byte class. The
        // closed runtime rejects fresh creation after both idle handles have
        // been evicted, proving the pool cannot retain them and over-allocate.
        let creation = pool.take(
            &mut super::super::ffi::NativeRuntime::without_native(),
            16,
            4096,
            0,
        );
        assert!(matches!(creation, ReadBufferCreation::Rejected(_)));
        assert_eq!(pool.retained_bytes(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn exact_hit_transfers_retained_charge_to_active_owner() {
        let mut pool = ReadBufferPool::new(16);
        pool.classes
            .entry(16)
            .or_default()
            .push(SegmentHandle::without_native());
        pool.retained_bytes = 16;

        let creation = pool.take(
            &mut super::super::ffi::NativeRuntime::without_native(),
            16,
            4096,
            0,
        );
        assert!(matches!(creation, ReadBufferCreation::Ready(_)));
        assert_eq!(pool.retained_bytes(), 0);
        assert!(pool.is_empty());
    }
}
