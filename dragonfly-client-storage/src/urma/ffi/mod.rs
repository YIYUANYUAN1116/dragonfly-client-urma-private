//! Module-private native boundary. Raw generated types must not escape this module.

use std::{
    ffi::{c_int, CStr},
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
};

// Native READ ownership and posting primitives.

pub(crate) mod read;

mod sys {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    #![allow(clippy::all)]

    include!(concat!(env!("OUT_DIR"), "/urma_bindings.rs"));
}

pub(crate) const CONTROL_RECV_OPCODE: u32 = sys::DFURMA_CONTROL_RECV_OPCODE;

pub(crate) const EID_SIZE: usize = sys::DFURMA_EID_SIZE as usize;
pub(crate) const TP_RTP: u32 = sys::DFURMA_TP_RTP;
pub(crate) const TP_CTP: u32 = sys::DFURMA_TP_CTP;
pub(crate) const IMPORT_STAGE_GET_TP: u32 = sys::DFURMA_IMPORT_STAGE_GET_TP;
pub(crate) const IMPORT_STAGE_IMPORT_EX: u32 = sys::DFURMA_IMPORT_STAGE_IMPORT_EX;
pub(crate) const IMPORT_STAGE_IMPORT: u32 = sys::DFURMA_IMPORT_STAGE_IMPORT;
pub(crate) const IMPORT_STAGE_CTP_AUTO_IMPORT: u32 = sys::DFURMA_IMPORT_STAGE_CTP_AUTO_IMPORT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceCapability {
    pub transport_type: i32,
    pub transport_modes: u32,
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
    pub max_read_size: u32,
    pub max_write_size: u32,
}

pub(crate) struct JettyConfig {
    pub send_depth: u32,
    pub recv_depth: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub token: u32,
    pub tp_type: u32,
}

pub(crate) struct JettyDescriptorData {
    pub transport_type: u32,
    pub tp_type: u32,
    pub eid_index: u32,
    pub jetty_id: u32,
    pub opaque_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompletionRecord {
    /// Host observation time immediately after the native JFC poll returns.
    /// This is not a hardware completion timestamp.
    pub observed_at: Option<std::time::Instant>,
    pub status: i32,
    pub opcode: u32,
    pub user_ctx: u64,
    pub completion_len: u32,
    pub local_id: u32,
    pub is_recv: bool,
    pub is_jetty: bool,
    pub user_ctx_valid: bool,
    pub event_kind: CompletionEventKind,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum CompletionEventKind {
    #[default]
    WorkRequest,
    SuspendDone,
    FlushErrorDone,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FfiError {
    Contract(&'static str),
    NullHandle,
    Status(c_int),
    Import(ImportFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImportFailure {
    pub(crate) stage: u32,
    pub(crate) native_status: i32,
    pub(crate) system_errno: i32,
    pub(crate) tp_count: u32,
    pub(crate) tp_handle: u64,
    pub(crate) tx_psn: u32,
    pub(crate) local_eid: [u8; EID_SIZE],
    pub(crate) peer_eid: [u8; EID_SIZE],
}

/// Unique Rust owner of the opaque C shim runtime.
///
/// All raw pointers and unsafe calls terminate in this type. The `Rc` marker
/// keeps endpoint handles on their owner thread.
pub(crate) struct NativeRuntime {
    raw: Option<NonNull<sys::dfurma_runtime_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl NativeRuntime {
    /// Test-only closed handle for ownership/lifecycle tests without a provider.
    #[cfg(test)]
    pub(crate) fn without_native() -> Self {
        Self {
            raw: None,
            _not_send_sync: PhantomData,
        }
    }

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

    pub(crate) fn is_closed(&self) -> bool {
        self.raw.is_none()
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
            transport_modes: raw.transport_modes,
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
            max_read_size: raw.max_read_size,
            max_write_size: raw.max_write_size,
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
        let observed_at = std::time::Instant::now();
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
                observed_at: Some(observed_at),
                status: record.status,
                opcode: record.opcode,
                user_ctx: record.user_ctx,
                completion_len: record.completion_len,
                local_id: record.local_id,
                is_recv: record.is_recv != 0,
                is_jetty: record.is_jetty != 0,
                user_ctx_valid: record.user_ctx_valid != 0,
                event_kind: match record.event_kind {
                    0 => CompletionEventKind::WorkRequest,
                    1 => CompletionEventKind::SuspendDone,
                    2 => CompletionEventKind::FlushErrorDone,
                    other => CompletionEventKind::Unknown(other),
                },
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
    #[cfg(test)]
    pub(crate) fn without_native() -> Self {
        Self {
            raw: None,
            _not_send_sync: PhantomData,
        }
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
    /// Test-only closed handle for ownership/lifecycle tests without a provider.
    #[cfg(test)]
    pub(crate) fn without_native() -> Self {
        Self {
            raw: None,
            _not_send_sync: PhantomData,
        }
    }

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
            tp_type: config.tp_type,
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

    pub(crate) fn import_target(
        &mut self,
        descriptor: &JettyDescriptorData,
        token: u32,
    ) -> Result<TargetHandle, FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        let opaque_len = u32::try_from(descriptor.opaque_data.len())
            .map_err(|_| FfiError::Contract("descriptor length exceeds u32"))?;
        let meta = sys::dfurma_jetty_descriptor_meta_t {
            transport_type: descriptor.transport_type,
            tp_type: descriptor.tp_type,
            eid_index: descriptor.eid_index,
            jetty_id: descriptor.jetty_id,
            opaque_len,
        };
        // SAFETY: Descriptor bytes are validated by the safe wire layer and
        // remain live for the synchronous shim import call.
        let mut raw_target = std::ptr::null_mut();
        let mut diagnostics = std::mem::MaybeUninit::<sys::dfurma_import_diagnostics_t>::zeroed();
        let status = unsafe {
            sys::dfurma_jetty_import(
                jetty.as_ptr(),
                &meta,
                descriptor.opaque_data.as_ptr(),
                opaque_len,
                token,
                &mut raw_target,
                diagnostics.as_mut_ptr(),
            )
        };
        if status != 0 {
            // SAFETY: The shim requires a diagnostics pointer and initializes
            // the complete pointer-free DTO before any provider operation.
            let diagnostics = unsafe { diagnostics.assume_init() };
            if diagnostics.stage == sys::DFURMA_IMPORT_STAGE_NONE {
                return Err(FfiError::Status(status));
            }
            return Err(FfiError::Import(ImportFailure {
                stage: diagnostics.stage,
                native_status: diagnostics.native_status,
                system_errno: diagnostics.system_errno,
                tp_count: diagnostics.tp_count,
                tp_handle: diagnostics.tp_handle,
                tx_psn: diagnostics.tx_psn,
                local_eid: diagnostics.local_eid,
                peer_eid: diagnostics.peer_eid,
            }));
        }
        Ok(TargetHandle {
            raw: Some(NonNull::new(raw_target).ok_or(FfiError::NullHandle)?),
            _not_send_sync: PhantomData,
        })
    }

    pub(crate) fn mark_error(&mut self) -> Result<(), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        // SAFETY: Jetty is uniquely owned by this handle.
        status_result(unsafe { sys::dfurma_jetty_mark_error(jetty.as_ptr()) })
    }

    pub(crate) fn local_ids(&self) -> Result<(u32, u32), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        let mut jetty_id = 0;
        let mut jfr_id = 0;
        // SAFETY: Jetty is live and both integer outputs are writable.
        status_result(unsafe {
            sys::dfurma_jetty_local_ids(jetty.as_ptr(), &mut jetty_id, &mut jfr_id)
        })?;
        Ok((jetty_id, jfr_id))
    }

    /// After success all native receive access is stopped. WR metadata must
    /// remain owned until the caller releases it, before closing this wrapper.
    pub(crate) fn destroy_control_recv_endpoint(&mut self) -> Result<(), FfiError> {
        let jetty = self.raw.ok_or(FfiError::Contract("Jetty is closed"))?;
        // SAFETY: unique owner; shim enforces ERROR, no targets, RECV-only WRs.
        status_result(unsafe { sys::dfurma_control_destroy_recv_endpoint(jetty.as_ptr()) })
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

/// Owns C WR/SGE metadata until CQE/flush retirement or successful destruction
/// of a stopped, dedicated control receive endpoint proves no further DMA.
pub(crate) struct WrHandle {
    raw: Option<NonNull<sys::dfurma_wr_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl WrHandle {
    pub(crate) fn complete(mut self) {
        if let Some(raw) = self.raw.take() {
            // SAFETY: Caller holds CQE/flush or control-endpoint destruction
            // proof and consumes the unique WR exactly once.
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
        let _ = self.close();
    }
}

pub(crate) struct TargetHandle {
    raw: Option<NonNull<sys::dfurma_target_t>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl TargetHandle {
    /// Test-only closed handle for ownership/lifecycle tests without a provider.
    #[cfg(test)]
    pub(crate) fn without_native() -> Self {
        Self {
            raw: None,
            _not_send_sync: PhantomData,
        }
    }

    pub(crate) fn close(&mut self) -> Result<(), FfiError> {
        let Some(target) = self.raw else {
            return Ok(());
        };
        // SAFETY: this consumes the unique imported target wrapper.
        let result = status_result(unsafe { sys::dfurma_target_unimport(target.as_ptr()) });
        if result.is_ok() {
            self.raw = None;
        }
        result
    }
}

impl Drop for TargetHandle {
    fn drop(&mut self) {
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
        tp_type: meta.tp_type,
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

/// Post control work on an independently owned endpoint. A returned WR on an
/// error remains owned by the caller; cancellation cannot release its buffer.
pub(crate) fn post_control(
    jetty: &JettyHandle,
    target: Option<&TargetHandle>,
    segment: &SegmentHandle,
    offset: u64,
    length: u32,
    context: u64,
) -> (Result<(), FfiError>, Option<WrHandle>) {
    let Some(jetty) = jetty.raw else {
        return (Err(FfiError::NullHandle), None);
    };
    let Some(segment) = segment.raw else {
        return (Err(FfiError::NullHandle), None);
    };
    let mut out = std::ptr::null_mut();
    // SAFETY: all handles stay on the Fabric owner; the caller owns this
    // non-overlapping slot until the returned WR retires.
    let status = unsafe {
        if let Some(target) = target {
            let Some(target) = target.raw else {
                return (Err(FfiError::NullHandle), None);
            };
            sys::dfurma_post_control_send(
                jetty.as_ptr(),
                target.as_ptr(),
                segment.as_ptr(),
                offset,
                length,
                context,
                &mut out,
            )
        } else {
            sys::dfurma_post_control_recv(
                jetty.as_ptr(),
                segment.as_ptr(),
                offset,
                length,
                context,
                &mut out,
            )
        }
    };
    let wr = NonNull::new(out).map(|raw| WrHandle {
        raw: Some(raw),
        _not_send_sync: PhantomData,
    });
    (
        if status == 0 {
            Ok(())
        } else {
            Err(FfiError::Status(status))
        },
        wr,
    )
}
