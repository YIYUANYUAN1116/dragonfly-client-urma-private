//! Owner-thread pooling of registered READ destination buffers.
//!
//! Every Piece used to allocate and register a fresh pinned destination buffer
//! and unregister it after the lease recycle, paying the full provider MR
//! round trip per Piece. The pool retains closed registered buffers keyed by
//! their allocation length so the next Piece of the same length reuses the
//! registration instead of recreating it.
//!
//! Retention is capped at the destination budget: pooled bytes are no longer
//! charged to the owner registry, so worst-case pinned memory equals the
//! in-flight destination charge plus the retained pool.

use super::ffi::{read::ReadBufferCreation, NativeRuntime, SegmentHandle};
use std::collections::BTreeMap;

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
    /// otherwise. `alignment` only participates in fresh creation because all
    /// pooled buffers were created with the same runtime-wide alignment.
    pub(crate) fn take(
        &mut self,
        runtime: &mut NativeRuntime,
        length: u64,
        alignment: u64,
    ) -> ReadBufferCreation {
        if let Some(buffer) = self.classes.get_mut(&length).and_then(|class| class.pop()) {
            self.retained_bytes = self.retained_bytes.saturating_sub(length);
            return ReadBufferCreation::Ready(buffer);
        }
        SegmentHandle::create_read_buffer(runtime, length, alignment)
    }

    /// Returns a registered buffer to the pool when the retention budget
    /// allows; `Err(buffer)` gives it back so the caller can close it.
    pub(crate) fn put(&mut self, buffer: SegmentHandle, length: u64) -> Result<(), SegmentHandle> {
        if !self.should_retain(length) {
            return Err(buffer);
        }
        self.retained_bytes += length;
        self.classes.entry(length).or_default().push(buffer);
        Ok(())
    }

    fn should_retain(&self, length: u64) -> bool {
        self.retained_bytes.saturating_add(length) <= self.max_retained_bytes
    }

    pub(crate) fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Explicitly surrenders every retained buffer for closing. Shutdown calls
    /// this before the native runtime closes; relying on struct drop order
    /// would segment-delete against an already-closed runtime.
    pub(crate) fn drain(&mut self) -> std::collections::btree_map::IntoIter<u64, Vec<SegmentHandle>> {
        self.retained_bytes = 0;
        std::mem::take(&mut self.classes).into_iter()
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
        let creation = pool.take(&mut super::super::ffi::NativeRuntime::without_native(), 16, 4096);
        assert!(matches!(creation, ReadBufferCreation::Rejected(_)));
        assert_eq!(pool.retained_bytes(), 0);
    }
}
