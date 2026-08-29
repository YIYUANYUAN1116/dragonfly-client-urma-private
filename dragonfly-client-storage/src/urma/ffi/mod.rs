//! Module-private native boundary. Raw generated types must not escape this module.

use std::{
    ffi::{c_int, CStr},
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
};

mod sys {
    #![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
    #![allow(clippy::all)]

    include!(concat!(env!("OUT_DIR"), "/urma_bindings.rs"));
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceCapability {
    pub transport_type: i32,
    pub max_jfc: u32,
    pub max_jfs: u32,
    pub max_jfr: u32,
    pub max_jetty: u32,
    pub max_jfc_depth: u32,
    pub max_jfs_depth: u32,
    pub max_jfr_depth: u32,
    pub max_jfs_sge: u32,
    pub max_jfs_rsge: u32,
    pub max_jfr_sge: u32,
    pub max_msg_size: u64,
}

pub(crate) struct JettyConfig {
    pub send_depth: u32,
    pub recv_depth: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub token: u32,
}

pub(crate) struct JettyDescriptorData {
    pub transport_type: u32,
    pub eid_index: u32,
    pub jetty_id: u32,
    pub opaque_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompletionRecord {
    pub status: i32,
    pub opcode: u32,
    pub user_ctx: u64,
    pub completion_len: u32,
    pub is_recv: bool,
    pub is_jetty: bool,
    pub user_ctx_valid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FfiError {
    Contract(&'static str),
    NullHandle,
    Status(c_int),
}

/// Unique Rust owner of the opaque C shim runtime.
///
/// All raw pointers and unsafe calls terminate in this type. The `Rc` marker
/// prevents the handle from crossing threads during Phase 0.
pub(crate) struct NativeRuntime {
    raw: Option<NonNull<sys::dfurma_runtime_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl NativeRuntime {
    pub(crate) fn open(device_name: &CStr, eid_index: u32) -> Result<Self, FfiError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: `device_name` is NUL terminated and valid for the call; `raw`
        // is writable and the returned pointer is checked before ownership.
        let status = unsafe { sys::dfurma_runtime_open(device_name.as_ptr(), eid_index, &mut raw) };
        if status != 0 {
            return Err(FfiError::Status(status));
        }
        let raw = NonNull::new(raw).ok_or(FfiError::NullHandle)?;
        Ok(Self {
            raw: Some(raw),
            _not_send_sync: PhantomData,
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), FfiError> {
        let Some(raw) = self.raw else {
            return Ok(());
        };
        // SAFETY: `raw` is the unique live allocation returned by the shim.
        // The shim consumes it only on success, so a failed close remains
        // retryable and the pointer must stay owned by this handle.
        let status = unsafe { sys::dfurma_runtime_close(raw.as_ptr()) };
        if status == 0 {
            self.raw = None;
            Ok(())
        } else {
            Err(FfiError::Status(status))
        }
    }

    pub(crate) fn query_device(&self) -> Result<DeviceCapability, FfiError> {
        let raw_runtime = self.raw.ok_or(FfiError::Contract("runtime is closed"))?;
        let mut raw = std::mem::MaybeUninit::<sys::dfurma_device_capability_t>::uninit();
        // SAFETY: Both pointers are valid for the duration of the call and the
        // shim initializes the complete pointer-free DTO on success.
        let status =
            unsafe { sys::dfurma_runtime_query_device(raw_runtime.as_ptr(), raw.as_mut_ptr()) };
        if status != 0 {
            return Err(FfiError::Status(status));
        }
        // SAFETY: A zero shim status guarantees full DTO initialization.
        let raw = unsafe { raw.assume_init() };
        Ok(DeviceCapability {
            transport_type: raw.transport_type,
            max_jfc: raw.max_jfc,
            max_jfs: raw.max_jfs,
            max_jfr: raw.max_jfr,
            max_jetty: raw.max_jetty,
            max_jfc_depth: raw.max_jfc_depth,
            max_jfs_depth: raw.max_jfs_depth,
            max_jfr_depth: raw.max_jfr_depth,
            max_jfs_sge: raw.max_jfs_sge,
            max_jfs_rsge: raw.max_jfs_rsge,
            max_jfr_sge: raw.max_jfr_sge,
            max_msg_size: raw.max_msg_size,
        })
    }
}

impl Drop for NativeRuntime {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(crate) struct JfcHandle {
    raw: Option<NonNull<sys::dfurma_jfc_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl JfcHandle {
    pub(crate) fn create(runtime: &mut NativeRuntime, depth: u32) -> Result<Self, FfiError> {
        let raw_runtime = runtime.raw.ok_or(FfiError::Contract("runtime is closed"))?;
        let mut raw = std::ptr::null_mut();
        // SAFETY: The runtime pointer is live and `raw` is a valid out pointer.
        let status = unsafe { sys::dfurma_jfc_create(raw_runtime.as_ptr(), depth, &mut raw) };
        if status != 0 {
            return Err(FfiError::Status(status));
        }
        let raw = NonNull::new(raw).ok_or(FfiError::NullHandle)?;
        Ok(Self {
            raw: Some(raw),
            _not_send_sync: PhantomData,
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), FfiError> {
        let Some(raw) = self.raw else {
            return Ok(());
        };
        // SAFETY: This is the unique live shim JFC wrapper.
        let status = unsafe { sys::dfurma_jfc_delete(raw.as_ptr()) };
        if status == 0 {
            self.raw = None;
            Ok(())
        } else {
            Err(FfiError::Status(status))
        }
    }

    pub(crate) fn poll_into(&self, out: &mut [CompletionRecord]) -> Result<usize, FfiError> {
        if out.is_empty() || out.len() > 16 {
            return Err(FfiError::Contract("poll capacity must be in 1..=16"));
        }
        let raw = self.raw.ok_or(FfiError::Contract("JFC is closed"))?;
        let mut records: [std::mem::MaybeUninit<sys::dfurma_completion_t>; 16] =
            std::array::from_fn(|_| std::mem::MaybeUninit::uninit());
        // SAFETY: `records` has `out.len()` writable entries and the live JFC is
        // only polled synchronously on its owner thread.
        let count = unsafe {
            sys::dfurma_jfc_poll(raw.as_ptr(), out.len() as u32, records.as_mut_ptr().cast())
        };
        if count < 0 {
            return Err(FfiError::Status(count));
        }
        let count = usize::try_from(count)
            .map_err(|_| FfiError::Contract("poll count does not fit usize"))?;
        if count > out.len() {
            return Err(FfiError::Contract("provider returned too many completions"));
        }
        for (destination, record) in out.iter_mut().zip(records.into_iter()).take(count) {
            // SAFETY: the shim initializes exactly the first `count` entries.
            let record = unsafe { record.assume_init() };
            *destination = CompletionRecord {
                status: record.status,
                opcode: record.opcode,
                user_ctx: record.user_ctx,
                completion_len: record.completion_len,
                is_recv: record.is_recv != 0,
                is_jetty: record.is_jetty != 0,
                user_ctx_valid: record.user_ctx_valid != 0,
            };
        }
        Ok(count)
    }
}

impl Drop for JfcHandle {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(crate) struct SegmentHandle {
    raw: Option<NonNull<sys::dfurma_segment_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl SegmentHandle {
    pub(crate) fn create(
        runtime: &mut NativeRuntime,
        length: u64,
        alignment: u64,
    ) -> Result<Self, FfiError> {
        let raw_runtime = runtime.raw.ok_or(FfiError::Contract("runtime is closed"))?;
        let mut raw = std::ptr::null_mut();
        // SAFETY: The runtime pointer is live and `raw` is a valid out pointer.
        let status = unsafe {
            sys::dfurma_segment_create(raw_runtime.as_ptr(), length, alignment, &mut raw)
        };
        if status != 0 {
            return Err(FfiError::Status(status));
        }
        let raw = NonNull::new(raw).ok_or(FfiError::NullHandle)?;
        Ok(Self {
            raw: Some(raw),
            _not_send_sync: PhantomData,
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), FfiError> {
        let Some(raw) = self.raw else {
            return Ok(());
        };
        // SAFETY: This is the unique live shim Segment wrapper.
        let status = unsafe { sys::dfurma_segment_delete(raw.as_ptr()) };
        if status == 0 {
            self.raw = None;
            Ok(())
        } else {
            Err(FfiError::Status(status))
        }
    }

    pub(crate) fn write(&self, offset: u64, data: &[u8]) -> Result<(), FfiError> {
        let raw = self.raw.ok_or(FfiError::Contract("Segment is closed"))?;
        let length = u32::try_from(data.len())
            .map_err(|_| FfiError::Contract("write length exceeds u32"))?;
        if length == 0 {
            return Err(FfiError::Contract("zero-length Segment write"));
        }
        // SAFETY: data remains valid for the synchronous copy into the Segment.
        status_result(unsafe {
            sys::dfurma_segment_write(raw.as_ptr(), offset, data.as_ptr(), length)
        })
    }

    pub(crate) fn read(&self, offset: u64, length: u32) -> Result<Vec<u8>, FfiError> {
        let raw = self.raw.ok_or(FfiError::Contract("Segment is closed"))?;
        if length == 0 {
            return Err(FfiError::Contract("zero-length Segment read"));
        }
        let mut out = vec![0u8; length as usize];
        // SAFETY: out has exactly `length` writable bytes.
        status_result(unsafe {
            sys::dfurma_segment_read(raw.as_ptr(), offset, out.as_mut_ptr(), length)
        })?;
        Ok(out)
    }

    /// Returns the ordinary CPU-visible allocation registered by the shim.
    /// The pointer remains valid until this Segment is successfully closed.
    pub(crate) fn data(&self) -> Result<(NonNull<u8>, usize), FfiError> {
        let raw = self.raw.ok_or(FfiError::Contract("Segment is closed"))?;
        let mut data = std::ptr::null_mut();
        let mut length = 0u64;
        // SAFETY: `raw` is live and both outputs are valid writable pointers.
        status_result(unsafe { sys::dfurma_segment_data(raw.as_ptr(), &mut data, &mut length) })?;
        let data = NonNull::new(data).ok_or(FfiError::NullHandle)?;
        let length = usize::try_from(length)
            .map_err(|_| FfiError::Contract("Segment length exceeds usize"))?;
        Ok((data, length))
    }
}

impl Drop for SegmentHandle {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(crate) struct JettyHandle {
    raw: Option<NonNull<sys::dfurma_jetty_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl JettyHandle {
    pub(crate) fn create(
        runtime: &mut NativeRuntime,
        send_jfc: &JfcHandle,
        recv_jfc: &JfcHandle,
        config: &JettyConfig,
    ) -> Result<Self, FfiError> {
        let runtime = runtime.raw.ok_or(FfiError::Contract("runtime is closed"))?;
        let send_jfc = send_jfc
            .raw
            .ok_or(FfiError::Contract("send JFC is closed"))?;
        let recv_jfc = recv_jfc
            .raw
            .ok_or(FfiError::Contract("recv JFC is closed"))?;
        let raw_config = sys::dfurma_jetty_config_t {
            send_depth: config.send_depth,
            recv_depth: config.recv_depth,
            max_send_sge: config.max_send_sge,
            max_recv_sge: config.max_recv_sge,
            token: config.token,
        };
        let mut raw = std::ptr::null_mut();
        // SAFETY: All three owners are live and `raw` is a valid out pointer.
        let status = unsafe {
            sys::dfurma_jetty_create(
                runtime.as_ptr(),
                send_jfc.as_ptr(),
                recv_jfc.as_ptr(),
                &raw_config,
                &mut raw,
            )
        };
        if status != 0 {
            return Err(FfiError::Status(status));
        }
        let raw = NonNull::new(raw).ok_or(FfiError::NullHandle)?;
        Ok(Self {
            raw: Some(raw),
            _not_send_sync: PhantomData,
        })
    }

    pub(crate) fn export_descriptor(&self) -> Result<JettyDescriptorData, FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        let mut meta = std::mem::MaybeUninit::<sys::dfurma_jetty_descriptor_meta_t>::uninit();
        let mut opaque_data = std::ptr::null_mut();
        // SAFETY: Jetty is live and both output pointers are writable.
        let status = unsafe {
            sys::dfurma_jetty_export_descriptor(jetty.as_ptr(), meta.as_mut_ptr(), &mut opaque_data)
        };
        if status != 0 {
            return Err(FfiError::Status(status));
        }
        let opaque_data = NonNull::new(opaque_data).ok_or(FfiError::NullHandle)?;
        // SAFETY: A zero status initializes the integer-only metadata DTO.
        let meta = unsafe { meta.assume_init() };
        let result = copy_descriptor(meta, opaque_data);
        // SAFETY: opaque_data is the unique provider allocation returned above.
        unsafe { sys::dfurma_descriptor_free(opaque_data.as_ptr()) };
        result
    }

    pub(crate) fn import(
        &mut self,
        descriptor: &JettyDescriptorData,
        token: u32,
    ) -> Result<(), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        let opaque_len = u32::try_from(descriptor.opaque_data.len())
            .map_err(|_| FfiError::Contract("descriptor length exceeds u32"))?;
        let meta = sys::dfurma_jetty_descriptor_meta_t {
            transport_type: descriptor.transport_type,
            eid_index: descriptor.eid_index,
            jetty_id: descriptor.jetty_id,
            opaque_len,
        };
        // SAFETY: Descriptor bytes are validated by the safe wire layer and
        // remain live for the synchronous shim import call.
        let status = unsafe {
            sys::dfurma_jetty_import(
                jetty.as_ptr(),
                &meta,
                descriptor.opaque_data.as_ptr(),
                opaque_len,
                token,
            )
        };
        status_result(status)
    }

    pub(crate) fn bind(&mut self) -> Result<(), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        // SAFETY: Jetty and its imported target are owned by this handle.
        status_result(unsafe { sys::dfurma_jetty_bind(jetty.as_ptr()) })
    }

    pub(crate) fn unbind(&mut self) -> Result<(), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        // SAFETY: Jetty is uniquely owned by this handle.
        status_result(unsafe { sys::dfurma_jetty_unbind(jetty.as_ptr()) })
    }

    pub(crate) fn unimport(&mut self) -> Result<(), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        // SAFETY: The imported target, if any, is uniquely owned by the shim.
        status_result(unsafe { sys::dfurma_jetty_unimport(jetty.as_ptr()) })
    }

    pub(crate) fn mark_error(&mut self) -> Result<(), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        // SAFETY: Jetty is uniquely owned by this handle.
        status_result(unsafe { sys::dfurma_jetty_mark_error(jetty.as_ptr()) })
    }

    pub(crate) fn post_send(
        &mut self,
        segment: &SegmentHandle,
        offset: u64,
        length: u32,
        user_ctx: u64,
    ) -> Result<WrHandle, FfiError> {
        self.post(segment, offset, length, user_ctx, true)
    }

    pub(crate) fn post_recv(
        &mut self,
        segment: &SegmentHandle,
        offset: u64,
        length: u32,
        user_ctx: u64,
    ) -> Result<WrHandle, FfiError> {
        self.post(segment, offset, length, user_ctx, false)
    }

    fn post(
        &mut self,
        segment: &SegmentHandle,
        offset: u64,
        length: u32,
        user_ctx: u64,
        send: bool,
    ) -> Result<WrHandle, FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        let segment = segment.raw.ok_or(FfiError::Contract("Segment is closed"))?;
        let mut raw = std::ptr::null_mut();
        // SAFETY: Jetty and Segment are live, range validation is repeated by
        // the shim, and raw is a valid out pointer.
        let status = unsafe {
            if send {
                sys::dfurma_post_send(
                    jetty.as_ptr(),
                    segment.as_ptr(),
                    offset,
                    length,
                    user_ctx,
                    &mut raw,
                )
            } else {
                sys::dfurma_post_recv(
                    jetty.as_ptr(),
                    segment.as_ptr(),
                    offset,
                    length,
                    user_ctx,
                    &mut raw,
                )
            }
        };
        if status != 0 {
            return Err(FfiError::Status(status));
        }
        Ok(WrHandle {
            raw: Some(NonNull::new(raw).ok_or(FfiError::NullHandle)?),
            _not_send_sync: PhantomData,
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), FfiError> {
        let Some(jetty) = self.raw else {
            return Ok(());
        };
        // SAFETY: This consumes the unique local Jetty wrapper.
        let result = status_result(unsafe { sys::dfurma_jetty_delete(jetty.as_ptr()) });
        if result.is_ok() {
            self.raw = None;
        }
        result
    }
}

/// Owns C WR/SGE metadata until the matching CQE is consumed.
pub(crate) struct WrHandle {
    raw: Option<NonNull<sys::dfurma_wr_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl WrHandle {
    pub(crate) fn complete(mut self) {
        if let Some(raw) = self.raw.take() {
            // SAFETY: Completion routing guarantees one call for the unique WR.
            unsafe { sys::dfurma_wr_complete(raw.as_ptr()) };
        }
    }
}

impl Drop for WrHandle {
    fn drop(&mut self) {
        // A posted WR cannot be freed safely without its CQE. Deliberately leak
        // it; shim outstanding counters prevent teardown of dependent objects.
    }
}

impl Drop for JettyHandle {
    fn drop(&mut self) {
        let _ = self.unbind();
        let _ = self.unimport();
        let _ = self.close();
    }
}

fn copy_descriptor(
    meta: sys::dfurma_jetty_descriptor_meta_t,
    opaque_data: NonNull<u8>,
) -> Result<JettyDescriptorData, FfiError> {
    let length = usize::try_from(meta.opaque_len)
        .map_err(|_| FfiError::Contract("descriptor length does not fit usize"))?;
    const MAX_NATIVE_DESCRIPTOR_LEN: usize = 64 * 1024;
    if length == 0 || length > MAX_NATIVE_DESCRIPTOR_LEN {
        return Err(FfiError::Contract(
            "native descriptor length is zero or exceeds the descriptor limit",
        ));
    }
    // SAFETY: The shim guarantees that opaque_data references meta.opaque_len
    // bytes until descriptor_free is called by the caller.
    let opaque_data = unsafe { std::slice::from_raw_parts(opaque_data.as_ptr(), length) }.to_vec();
    Ok(JettyDescriptorData {
        transport_type: meta.transport_type,
        eid_index: meta.eid_index,
        jetty_id: meta.jetty_id,
        opaque_data,
    })
}

fn status_result(status: c_int) -> Result<(), FfiError> {
    if status == 0 {
        Ok(())
    } else {
        Err(FfiError::Status(status))
    }
}
