//! Native READ handles. Raw UMDK objects stay inside the shim.
//! This is not a wire protocol and does not grant permission to enable READ.

use super::{sys, FfiError, JettyHandle, SegmentHandle, TargetHandle, WrHandle, EID_SIZE};
use std::{fmt, marker::PhantomData, ptr::NonNull, rc::Rc};

pub(crate) mod source;

/// Version 1 represents only pinned, non-cacheable, read-only/plain-token source
/// Segments with no provider extension. An eventual exporter must reject any
/// context it cannot represent exactly, rather than silently dropping attributes.
pub(crate) struct ReadDescriptor {
    pub(crate) version: u32,
    pub(crate) eid: [u8; EID_SIZE],
    pub(crate) uasid: u32,
    pub(crate) va: u64,
    pub(crate) length: u64,
    pub(crate) token_id: u32,
    pub(crate) access: u32,
    pub(crate) token_policy: u32,
}

impl fmt::Debug for ReadDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadDescriptor")
            .field("version", &self.version)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

/// Never include the access token in tracing, errors or a derived Debug dump.
pub(crate) struct ReadToken(u32);

impl ReadToken {
    pub(crate) fn new(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Debug for ReadToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadToken([REDACTED])")
    }
}

pub(crate) struct ImportedReadSegment {
    raw: Option<NonNull<sys::dfurma_read_segment_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl TargetHandle {
    /// Import only after the session has authenticated the source and validated
    /// transfer/Segment generation and exact Piece bounds. The shim additionally
    /// binds the Segment EID/UASID and lifetime to this native PeerTarget.
    pub(crate) fn import_read_segment(
        &self,
        descriptor: &ReadDescriptor,
        token: &ReadToken,
        max_read_size: u32,
    ) -> Result<ImportedReadSegment, FfiError> {
        let target = self.raw.ok_or(FfiError::Contract("target is closed"))?;
        let descriptor = sys::dfurma_read_descriptor_t {
            version: descriptor.version,
            eid: descriptor.eid,
            uasid: descriptor.uasid,
            va: descriptor.va,
            length: descriptor.length,
            token_id: descriptor.token_id,
            access: descriptor.access,
            token_policy: descriptor.token_policy,
        };
        let mut raw = std::ptr::null_mut();
        // SAFETY: Target is live; descriptor is an explicit pointer-free DTO.
        // The shim checks bounds, access, peer identity and device limits, and
        // records a dependency preventing target/runtime deletion until unimport.
        let status = unsafe {
            sys::dfurma_read_segment_import(
                target.as_ptr(),
                &descriptor,
                token.0,
                max_read_size,
                &mut raw,
            )
        };
        super::status_result(status)?;
        Ok(ImportedReadSegment {
            raw: Some(NonNull::new(raw).ok_or(FfiError::NullHandle)?),
            _not_send_sync: PhantomData,
        })
    }
}

impl ImportedReadSegment {
    /// No cancellation or revocation semantics: the shim refuses unimport while
    /// READ owners are outstanding. Failure retains the native handle for retry.
    pub(crate) fn close(&mut self) -> Result<(), FfiError> {
        let Some(raw) = self.raw else {
            return Ok(());
        };
        // SAFETY: Unique shim wrapper; only consumed on success. Outstanding WRs
        // protect it even if the Rust owner is dropped before CQE processing.
        let status = unsafe { sys::dfurma_read_segment_unimport(raw.as_ptr()) };
        super::status_result(status)?;
        self.raw = None;
        Ok(())
    }
}

impl Drop for ImportedReadSegment {
    fn drop(&mut self) {
        // As with existing FFI owners, a failed close deliberately retains native
        // dependencies. Runtime-level quarantine/reap is still required at integration.
        let _ = self.close();
    }
}

pub(crate) enum ReadBufferCreation {
    Ready(SegmentHandle),
    Rejected(FfiError),
    Uncertain {
        buffer: SegmentHandle,
        error: FfiError,
    },
}
impl SegmentHandle {
    /// READ-only allocation entry: failed registration retains the native wrapper
    /// and backing. Such a wrapper cannot be reclaimed by ordinary close.
    pub(crate) fn create_read_buffer(
        runtime: &mut super::NativeRuntime,
        length: u64,
        alignment: u64,
    ) -> ReadBufferCreation {
        let Some(runtime) = runtime.raw else {
            return ReadBufferCreation::Rejected(FfiError::Contract("runtime is closed"));
        };
        let mut raw = std::ptr::null_mut();
        // SAFETY: Runtime is live; shim validates size/alignment and owns memory.
        let status = unsafe {
            sys::dfurma_read_buffer_create(runtime.as_ptr(), length, alignment, &mut raw)
        };
        match NonNull::new(raw) {
            Some(raw) => {
                let buffer = SegmentHandle {
                    raw: Some(raw),
                    _not_send_sync: PhantomData,
                };
                if status == 0 {
                    ReadBufferCreation::Ready(buffer)
                } else {
                    ReadBufferCreation::Uncertain {
                        buffer,
                        error: FfiError::Status(status),
                    }
                }
            }
            None => ReadBufferCreation::Rejected(if status == 0 {
                FfiError::NullHandle
            } else {
                FfiError::Status(status)
            }),
        }
    }
}

pub(crate) struct ReadRequest {
    /// Offsets from the local registered allocation and remote Segment bases,
    /// respectively (not necessarily offsets from the Piece start).
    pub(crate) local_offset: u64,
    pub(crate) remote_offset: u64,
    pub(crate) length: u32,
    pub(crate) user_ctx: u64,
}

/// Distinguishes a known unposted request from an ambiguous provider error.
pub(crate) enum ReadPost {
    Posted(ReadWrHandle),
    Rejected(FfiError),
    Uncertain { wr: ReadWrHandle, error: FfiError },
}

pub(crate) struct ReadWrHandle(WrHandle);

impl ReadWrHandle {
    /// # Safety
    /// The caller must have validated the unique matching CQE or a provider-proven
    /// retirement covering this WR. Timeout, unimport and terminal TCP messages do
    /// not supply this proof. Removing ownership before DMA stops is unsound.
    pub(crate) unsafe fn complete(self) {
        self.0.complete();
    }
}

impl JettyHandle {
    /// Posts one signaled READ with one remote source and one local destination SGE.
    ///
    /// # Safety
    /// The caller must exclusively reserve the destination range against CPU access
    /// and other DMA until retirement, enforce byte/JFS/peer admission, and route
    /// user_ctx through the generation-checked operation registry. Provider RM READ
    /// and CQE semantics must have passed the deployment's capability gates.
    pub(crate) unsafe fn post_read(
        &mut self,
        target: &TargetHandle,
        local: &SegmentHandle,
        remote: &ImportedReadSegment,
        request: &ReadRequest,
    ) -> Result<ReadPost, FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        let target = target.raw.ok_or(FfiError::Contract("target is closed"))?;
        let local = local.raw.ok_or(FfiError::Contract("Segment is closed"))?;
        let remote = remote
            .raw
            .ok_or(FfiError::Contract("READ Segment is closed"))?;
        let mut raw = std::ptr::null_mut();
        // SAFETY: Owners are live; the shim verifies runtime/target ownership and
        // both ranges. The caller supplies destination exclusivity until retirement.
        let status = unsafe {
            sys::dfurma_post_read(
                jetty.as_ptr(),
                target.as_ptr(),
                local.as_ptr(),
                remote.as_ptr(),
                request.local_offset,
                request.remote_offset,
                request.length,
                request.user_ctx,
                &mut raw,
            )
        };
        match (status, NonNull::new(raw)) {
            (0, Some(raw)) => Ok(ReadPost::Posted(ReadWrHandle(WrHandle {
                raw: Some(raw),
                _not_send_sync: PhantomData,
            }))),
            (0, None) => Err(FfiError::NullHandle),
            (status, None) => Ok(ReadPost::Rejected(FfiError::Status(status))),
            (status, Some(raw)) => Ok(ReadPost::Uncertain {
                wr: ReadWrHandle(WrHandle {
                    raw: Some(raw),
                    _not_send_sync: PhantomData,
                }),
                error: FfiError::Status(status),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_and_token_debug_do_not_disclose_credentials() {
        let descriptor = ReadDescriptor {
            version: 1,
            eid: [42; EID_SIZE],
            uasid: 3,
            va: 0xdeadbeef,
            length: 4096,
            token_id: 987654321,
            access: 2,
            token_policy: 1,
        };
        assert_eq!(
            format!("{descriptor:?}"),
            "ReadDescriptor { version: 1, length: 4096, .. }"
        );
        assert_eq!(
            format!("{:?}", ReadToken::new(123456789)),
            "ReadToken([REDACTED])"
        );
    }

    #[test]
    fn closed_import_close_is_idempotent_without_native_call() {
        let mut imported = ImportedReadSegment {
            raw: None,
            _not_send_sync: PhantomData,
        };
        assert_eq!(imported.close(), Ok(()));
        assert_eq!(imported.close(), Ok(()));
    }
}
