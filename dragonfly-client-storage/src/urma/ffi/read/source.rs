//! Parent-side source registration with explicit backing retention.
//! Native unregister, remote revocation proof and backing release are separate.

use super::{sys, FfiError, ReadDescriptor, ReadToken};
use crate::urma::ffi::{status_result, NativeRuntime};
use std::{marker::PhantomData, ptr::NonNull, rc::Rc};

pub(crate) enum ReadSourceMemory {
    Bytes(Box<[u8]>),
    Mapped(memmap2::Mmap),
}

impl ReadSourceMemory {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Mapped(mapped) => mapped,
        }
    }
}

/// Owns a stable, immutable VA plus the future Storage lease/byte permits. Moving
/// this value does not move the allocation. Registered sources never expose it.
pub(crate) struct ReadBacking<K> {
    memory: ReadSourceMemory,
    keepalive: K,
}

impl<K> ReadBacking<K> {
    pub(crate) fn new(memory: ReadSourceMemory, keepalive: K) -> Self {
        Self { memory, keepalive }
    }

    /// Only available before registration or after verified release.
    pub(crate) fn into_parts(self) -> (ReadSourceMemory, K) {
        (self.memory, self.keepalive)
    }
}

/// Rejected means no registration call occurred and backing may be released.
/// Uncertain owns the backing and token even though registration returned NULL.
pub(crate) enum SourceRegistration<K> {
    Registered(ReadSource<K>),
    Rejected {
        error: FfiError,
        backing: ReadBacking<K>,
    },
    Uncertain {
        error: FfiError,
        source: ReadSource<K>,
    },
}

pub(crate) struct ReadSource<K> {
    raw: Option<NonNull<sys::dfurma_read_source_t>>,
    backing: Option<ReadBacking<K>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<K> ReadSource<K> {
    /// # Safety
    /// The caller must enforce source byte/Segment admission and immutable Storage
    /// lifetime (including no truncate/overwrite of mmap backing). The provider's
    /// registration/rollback contract must have passed the deployment gate. Memory
    /// with insufficient alignment must not be silently registered with wider bounds.
    pub(crate) unsafe fn register(
        runtime: &mut NativeRuntime,
        backing: ReadBacking<K>,
        token: &ReadToken,
    ) -> SourceRegistration<K> {
        let Some(runtime) = runtime.raw else {
            return SourceRegistration::Rejected {
                error: FfiError::Contract("runtime is closed"),
                backing,
            };
        };
        let bytes = backing.memory.bytes();
        let mut raw = std::ptr::null_mut();
        // SAFETY: The caller provides immutability/admission. Memory is owned and
        // stable; the shim validates length and does not free external memory.
        let status = unsafe {
            sys::dfurma_read_source_register(
                runtime.as_ptr(),
                bytes.as_ptr(),
                bytes.len() as u64,
                token.0,
                &mut raw,
            )
        };
        let Some(raw) = NonNull::new(raw) else {
            if status == 0 {
                // Broken shim contract: we cannot prove backing was not granted.
                // Retain it even without a usable native cleanup handle.
                return SourceRegistration::Uncertain {
                    error: FfiError::NullHandle,
                    source: Self {
                        raw: None,
                        backing: Some(backing),
                        _not_send_sync: PhantomData,
                    },
                };
            }
            return SourceRegistration::Rejected {
                error: FfiError::Status(status),
                backing,
            };
        };
        let source = Self {
            raw: Some(raw),
            backing: Some(backing),
            _not_send_sync: PhantomData,
        };
        if status == 0 {
            SourceRegistration::Registered(source)
        } else {
            SourceRegistration::Uncertain {
                error: FfiError::Status(status),
                source,
            }
        }
    }

    /// Reads provider context through the C shim. Unsupported attributes or opaque
    /// extensions are rejected rather than discarded during DTO conversion.
    pub(crate) fn descriptor(&self) -> Result<ReadDescriptor, FfiError> {
        let raw = self
            .raw
            .ok_or(FfiError::Contract("READ source is closed"))?;
        let mut descriptor = std::mem::MaybeUninit::<sys::dfurma_read_descriptor_t>::uninit();
        // SAFETY: Source owns its backing; successful export initializes this DTO.
        status_result(unsafe {
            sys::dfurma_read_source_descriptor(raw.as_ptr(), descriptor.as_mut_ptr())
        })?;
        // SAFETY: A successful shim call initialized every field.
        let descriptor = unsafe { descriptor.assume_init() };
        Ok(ReadDescriptor {
            version: descriptor.version,
            eid: descriptor.eid,
            uasid: descriptor.uasid,
            va: descriptor.va,
            length: descriptor.length,
            token_id: descriptor.token_id,
            access: descriptor.access,
            token_policy: descriptor.token_policy,
        })
    }

    /// Stops new descriptor export even on failure. Backing/token/runtime
    /// references remain held on both success and failure.
    ///
    /// # Safety
    /// The caller must follow a verified provider protocol for outstanding remote
    /// access during unregister. TCP EOF/timeout alone is not that protocol.
    pub(crate) unsafe fn unregister(&mut self) -> Result<(), FfiError> {
        let raw = self
            .raw
            .ok_or(FfiError::Contract("READ source is closed"))?;
        // SAFETY: Unique live wrapper; no backing is freed. Provider preconditions
        // are the caller's responsibility; the shim retains the wrapper on success.
        status_result(unsafe { sys::dfurma_read_source_unregister(raw.as_ptr()) })
    }

    /// # Safety
    /// Independently prove that all remote access has ceased and cannot resume,
    /// including stale-token access. Native unregister success is insufficient.
    /// For failed registration, verify any provider grant/pin rollback as well.
    /// Success returns the memory and Storage/budget guards; dropping them is then safe.
    pub(crate) unsafe fn release_after_revoke(&mut self) -> Result<ReadBacking<K>, FfiError> {
        let raw = self
            .raw
            .ok_or(FfiError::Contract("READ source is closed"))?;
        // SAFETY: Caller supplies revocation proof; C refuses live registrations
        // and retains the wrapper/token on token-release failure.
        status_result(unsafe { sys::dfurma_read_source_release_after_revoke(raw.as_ptr()) })?;
        self.raw = None;
        Ok(self.backing.take().expect("live READ source owns backing"))
    }
}

impl<K> Drop for ReadSource<K> {
    fn drop(&mut self) {
        // Drop cannot establish remote revocation. Retain memory AND Storage/budget
        // guards, even after successful native unregister. Runtime integration must
        // keep this owner in an explicit quarantine/reap registry instead of dropping.
        if let Some(backing) = self.backing.take() {
            std::mem::forget(backing);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Guard(Rc<Cell<usize>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn source_drop_retains_memory_and_keepalive_without_native_cleanup() {
        let drops = Rc::new(Cell::new(0));
        let mut memory = vec![1u8, 2, 3].into_boxed_slice();
        let memory_pointer = memory.as_mut() as *mut [u8];
        let mut guard = Box::new(Guard(drops.clone()));
        let guard_pointer = guard.as_mut() as *mut Guard;
        let source = ReadSource {
            // No native resource exists in this test; Drop must not call FFI.
            raw: Some(NonNull::dangling()),
            backing: Some(ReadBacking::new(ReadSourceMemory::Bytes(memory), guard)),
            _not_send_sync: PhantomData,
        };
        drop(source);
        assert_eq!(drops.get(), 0);
        // SAFETY: These exact Box allocations were deliberately retained by Drop.
        // No native DMA exists in this test; reclaim them to avoid test-only leaks.
        unsafe {
            assert_eq!(&*memory_pointer, &[1, 2, 3]);
            drop(Box::from_raw(memory_pointer));
            drop(Box::from_raw(guard_pointer));
        }
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn closed_runtime_rejects_registration_and_returns_backing() {
        let drops = Rc::new(Cell::new(0));
        let mut runtime = NativeRuntime {
            raw: None,
            _not_send_sync: PhantomData,
        };
        let backing = ReadBacking::new(
            ReadSourceMemory::Bytes(vec![7].into_boxed_slice()),
            Guard(drops.clone()),
        );
        // SAFETY: No native runtime exists; this verifies the preflight-only rejection.
        let result = unsafe { ReadSource::register(&mut runtime, backing, &ReadToken::new(1)) };
        let SourceRegistration::Rejected { backing, .. } = result else {
            panic!("expected rejection");
        };
        assert_eq!(drops.get(), 0);
        let (memory, guard) = backing.into_parts();
        assert_eq!(memory.bytes(), &[7]);
        drop(guard);
        assert_eq!(drops.get(), 1);
    }
}
