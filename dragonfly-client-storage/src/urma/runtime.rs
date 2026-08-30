use super::{
    buffer::{
        BufferPoolConfig, LeaseRecycle, LeaseRecycleNotifier, RegisteredRxWindowLease,
        TxWindowLease,
    },
    Error, Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeConfig {
    pub(crate) device_name: String,
    pub(crate) eid_index: u32,
    pub(crate) send_jfc_depth: u32,
    pub(crate) recv_jfc_depth: u32,
    pub(crate) buffer_pool: BufferPoolConfig,
}

impl RuntimeConfig {
    pub(crate) fn new(device_name: impl Into<String>, eid_index: u32) -> Self {
        Self {
            device_name: device_name.into(),
            eid_index,
            send_jfc_depth: 4096,
            recv_jfc_depth: 4096,
            buffer_pool: BufferPoolConfig::default(),
        }
    }
}

fn effective_max_message_size(device_max: u64, slot_size: usize) -> Result<u64> {
    let slot_size = u64::try_from(slot_size)
        .map_err(|_| Error::InvalidConfiguration("slot_size does not fit u64".into()))?;
    Ok(device_max.min(slot_size))
}

/// Rust-owned capability subset copied from `urma_device_attr_t`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UrmaDeviceCapability {
    pub(crate) transport_type: i32,
    pub(crate) max_jfc: u32,
    pub(crate) max_jfs: u32,
    pub(crate) max_jfr: u32,
    pub(crate) max_jetty: u32,
    pub(crate) max_jfc_depth: u32,
    pub(crate) max_jfs_depth: u32,
    pub(crate) max_jfr_depth: u32,
    pub(crate) max_jfs_sge: u32,
    pub(crate) max_jfs_rsge: u32,
    pub(crate) max_jfr_sge: u32,
    pub(crate) max_msg_size: u64,
}

mod native {
    use super::*;
    use crate::urma::{
        buffer::UrmaBufferPool,
        completion::{
            deadline_after, deadline_expired, CompletionRouter, RegisteredRxCompletionTx,
            RegisteredTxCompletionTx,
        },
        ffi::{self, NativeRuntime},
        lane::{JettyConfig, JettyDescriptor, UrmaJetty, UrmaLane},
        native_error,
    };
    use std::{
        collections::HashMap,
        ffi::CString,
        marker::PhantomData,
        rc::Rc,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum JfcKind {
        Send,
        Receive,
    }

    /// Safe owner of one native JFC. It remains part of the process-level
    /// Runtime resource tree and is never owned by a lane.
    struct UrmaJfc {
        kind: JfcKind,
        handle: ffi::JfcHandle,
    }

    impl UrmaJfc {
        fn create(runtime: &mut ffi::NativeRuntime, kind: JfcKind, depth: u32) -> Result<Self> {
            let operation = match kind {
                JfcKind::Send => "create_send_jfc",
                JfcKind::Receive => "create_recv_jfc",
            };
            let handle = ffi::JfcHandle::create(runtime, depth)
                .map_err(|error| native_error(operation, error))?;
            Ok(Self { kind, handle })
        }

        fn kind(&self) -> JfcKind {
            self.kind
        }

        fn handle(&self) -> &ffi::JfcHandle {
            &self.handle
        }

        fn close(&mut self) -> Result<()> {
            let operation = match self.kind {
                JfcKind::Send => "delete_send_jfc",
                JfcKind::Receive => "delete_recv_jfc",
            };
            self.handle
                .close()
                .map_err(|error| native_error(operation, error))
        }
    }

    static ACTIVE: AtomicBool = AtomicBool::new(false);

    /// Process-level owner of the complete native resource tree.
    pub(crate) struct UrmaRuntime {
        capability: UrmaDeviceCapability,
        max_payload_size: u64,
        max_post_list_size: u32,
        buffer_pool: Option<UrmaBufferPool>,
        recv_jfc: Option<UrmaJfc>,
        send_jfc: Option<UrmaJfc>,
        native: Option<ffi::NativeRuntime>,
        accepting: bool,
        poisoned: bool,
        next_lane_id: u16,
        lanes: HashMap<u16, UrmaLane>,
        completions: CompletionRouter,
        _not_send_sync: PhantomData<Rc<()>>,
    }

    impl UrmaRuntime {
        pub(crate) fn start(
            config: RuntimeConfig,
            recycle_notifier: LeaseRecycleNotifier,
        ) -> Result<Self> {
            if ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(Error::AlreadyInitialized);
            }

            match Self::start_inner(config, recycle_notifier) {
                Ok(runtime) => Ok(runtime),
                Err(error) => {
                    if !matches!(&error, Error::StartupRollback { .. }) {
                        ACTIVE.store(false, Ordering::Release);
                    }
                    Err(error)
                }
            }
        }

        fn start_inner(
            config: RuntimeConfig,
            recycle_notifier: LeaseRecycleNotifier,
        ) -> Result<Self> {
            let device = CString::new(config.device_name.as_str()).map_err(|_| {
                Error::InvalidConfiguration("device name contains an interior NUL byte".into())
            })?;
            let mut native: NativeRuntime = ffi::NativeRuntime::open(&device, config.eid_index)
                .map_err(|error| native_error("runtime_open", error))?;

            let capability = match native.query_device() {
                Ok(capability) => from_ffi_capability(capability),
                Err(error) => {
                    let primary = native_error("query_device", error);
                    return Err(rollback_startup(primary, None, None, None, Some(native)));
                }
            };
            if let Err(primary) = validate_config(&config, &capability) {
                return Err(rollback_startup(primary, None, None, None, Some(native)));
            }
            let max_payload_size =
                effective_max_message_size(capability.max_msg_size, config.buffer_pool.slot_size)?;
            let max_post_list_size = config
                .send_jfc_depth
                .min(config.recv_jfc_depth)
                .min(u32::try_from(config.buffer_pool.tx_slot_count).unwrap_or(u32::MAX))
                .min(u32::try_from(config.buffer_pool.rx_slot_count).unwrap_or(u32::MAX));

            let send_jfc = match UrmaJfc::create(&mut native, JfcKind::Send, config.send_jfc_depth)
            {
                Ok(jfc) => jfc,
                Err(primary) => {
                    return Err(rollback_startup(primary, None, None, None, Some(native)));
                }
            };
            let recv_jfc =
                match UrmaJfc::create(&mut native, JfcKind::Receive, config.recv_jfc_depth) {
                    Ok(jfc) => jfc,
                    Err(primary) => {
                        return Err(rollback_startup(
                            primary,
                            None,
                            None,
                            Some(send_jfc),
                            Some(native),
                        ));
                    }
                };
            let buffer_pool = match UrmaBufferPool::create(
                &mut native,
                config.buffer_pool.clone(),
                recycle_notifier,
            ) {
                Ok(pool) => pool,
                Err(primary) => {
                    return Err(rollback_startup(
                        primary,
                        None,
                        Some(recv_jfc),
                        Some(send_jfc),
                        Some(native),
                    ));
                }
            };

            debug_assert_eq!(send_jfc.kind(), JfcKind::Send);
            debug_assert_eq!(recv_jfc.kind(), JfcKind::Receive);
            Ok(Self {
                capability,
                max_payload_size,
                max_post_list_size,
                buffer_pool: Some(buffer_pool),
                recv_jfc: Some(recv_jfc),
                send_jfc: Some(send_jfc),
                native: Some(native),
                accepting: true,
                poisoned: false,
                next_lane_id: 1,
                lanes: HashMap::new(),
                completions: CompletionRouter::new(16)?,
                _not_send_sync: PhantomData,
            })
        }

        pub(crate) fn create_lane(
            &mut self,
            config: JettyConfig,
        ) -> Result<(u16, JettyDescriptor)> {
            if !self.accepting {
                return Err(Error::InvalidConfiguration(
                    "runtime is no longer accepting operations".into(),
                ));
            }
            validate_jetty_config(&config, &self.capability)?;
            let capability = self.capability.clone();
            let lane_id = self.next_lane_id;
            self.next_lane_id = self
                .next_lane_id
                .checked_add(1)
                .filter(|id| *id != 0)
                .ok_or_else(|| Error::InvalidConfiguration("lane id space exhausted".into()))?;
            let native = self
                .native
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("runtime is closed".into()))?;
            let send_jfc = self
                .send_jfc
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("send JFC is closed".into()))?;
            let recv_jfc = self
                .recv_jfc
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("receive JFC is closed".into()))?;
            let jetty = UrmaJetty::create(native, send_jfc.handle(), recv_jfc.handle(), &config)?;
            let effective_post_list_size = config
                .post_list_size
                .min(config.send_depth)
                .min(config.recv_depth)
                .min(self.max_post_list_size);
            let mut lane = UrmaLane::new(lane_id, 1, capability, jetty, effective_post_list_size)?;
            let descriptor = lane.export_descriptor()?;
            self.lanes.insert(lane_id, lane);
            Ok((lane_id, descriptor))
        }

        pub(crate) fn bind_lane(
            &mut self,
            lane_id: u16,
            descriptor: &JettyDescriptor,
        ) -> Result<()> {
            let lane = self.lane_mut(lane_id)?;
            lane.import_and_bind(descriptor)?;
            lane.mark_ready()
        }

        pub(crate) fn post_receive_window_registered(
            &mut self,
            lane_id: u16,
            sequences: Vec<u64>,
            completion_txs: Vec<RegisteredRxCompletionTx>,
        ) -> Result<()> {
            let (lanes, pool, completions) = (
                &mut self.lanes,
                self.buffer_pool
                    .as_mut()
                    .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?,
                &mut self.completions,
            );
            lanes
                .get_mut(&lane_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA lane {lane_id}")))?
                .post_receive_window_registered(pool, completions, sequences, completion_txs)
        }

        pub(crate) fn grant_send_credit(&mut self, lane_id: u16, count: u32) -> Result<()> {
            self.lane_mut(lane_id)?.grant_send_credit(count)
        }

        pub(crate) fn send_registered_window(
            &mut self,
            lane_id: u16,
            lease: TxWindowLease,
            sequences: Vec<u64>,
            completion: RegisteredTxCompletionTx,
        ) -> Result<()> {
            let (lanes, pool, completions) = (
                &mut self.lanes,
                self.buffer_pool
                    .as_mut()
                    .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?,
                &mut self.completions,
            );
            lanes
                .get_mut(&lane_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA lane {lane_id}")))?
                .send_registered_window(pool, completions, lease, sequences, completion)
        }

        pub(crate) fn poll_once(&mut self) -> Result<usize> {
            let send_jfc = self
                .send_jfc
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("send JFC is closed".into()))?;
            let recv_jfc = self
                .recv_jfc
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("receive JFC is closed".into()))?;
            let pool = self
                .buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?;
            let progress = self
                .completions
                .poll_once(send_jfc.handle(), recv_jfc.handle(), pool);
            if let Err(error) = &progress {
                self.completions.fail_pending(error);
            }
            let reap = self.reap_drained_lanes();
            match (progress, reap) {
                (Err(error), _) | (Ok(_), Err(error)) => Err(error),
                (Ok(count), Ok(())) => Ok(count),
            }
        }

        pub(crate) fn outstanding(&self) -> usize {
            self.completions.outstanding()
        }

        pub(crate) fn recycle_dropped_lease(&mut self, recycle: LeaseRecycle) -> Result<usize> {
            self.buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .recycle_dropped_lease(recycle)
        }

        pub(crate) fn acquire_tx_window(&mut self, length: usize) -> Result<TxWindowLease> {
            self.buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .acquire_tx_window(length)
        }

        pub(crate) fn acquire_tx_window_chunks(
            &mut self,
            chunk_lengths: &[usize],
        ) -> Result<TxWindowLease> {
            self.buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .acquire_tx_window_chunks(chunk_lengths)
        }

        pub(crate) fn recycle_tx_window(&mut self, lease: TxWindowLease) -> Result<usize> {
            self.buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .recycle_tx_lease(lease)
        }

        pub(crate) fn recycle_rx_window(
            &mut self,
            lease: RegisteredRxWindowLease,
        ) -> Result<usize> {
            self.buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .recycle_rx_lease(lease)
        }

        pub(crate) fn transport_type(&self) -> u32 {
            u32::try_from(self.capability.transport_type).unwrap_or(0)
        }

        pub(crate) fn max_message_size(&self) -> u64 {
            self.max_payload_size
        }

        pub(crate) fn close_lane(&mut self, lane_id: u16) -> Result<()> {
            let outstanding = self.completions.outstanding_for_lane(lane_id);
            let lane = self.lane_mut(lane_id)?;
            lane.close(outstanding)?;
            self.lanes.remove(&lane_id);
            Ok(())
        }

        pub(crate) fn abort_lane(&mut self, lane_id: u16) -> Result<()> {
            self.lane_mut(lane_id)?.begin_draining()?;
            if self.completions.outstanding_for_lane(lane_id) == 0 {
                self.close_lane(lane_id)?;
            }
            Ok(())
        }

        fn reap_drained_lanes(&mut self) -> Result<()> {
            let drained = self
                .lanes
                .iter()
                .filter_map(|(&lane_id, lane)| {
                    (lane.is_draining() && self.completions.outstanding_for_lane(lane_id) == 0)
                        .then_some(lane_id)
                })
                .collect::<Vec<_>>();
            for lane_id in drained {
                self.close_lane(lane_id)?;
            }
            Ok(())
        }

        fn lane_mut(&mut self, lane_id: u16) -> Result<&mut UrmaLane> {
            self.lanes
                .get_mut(&lane_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA lane {lane_id}")))
        }

        pub(crate) fn shutdown(mut self) -> Result<()> {
            self.shutdown_inner()
        }

        fn shutdown_inner(&mut self) -> Result<()> {
            if self.poisoned {
                return Err(Error::Shutdown {
                    failures: vec!["a previous shutdown attempt left native state uncertain".into()],
                });
            }
            self.accepting = false;
            let mut failures = Vec::new();

            for lane in self.lanes.values_mut() {
                if self.completions.outstanding_for_lane(lane.id()) != 0 {
                    if let Err(error) = lane.begin_draining() {
                        failures.push(error.to_string());
                    }
                }
            }
            let drain_deadline = deadline_after(Duration::from_secs(1));
            while self.completions.outstanding() != 0 && !deadline_expired(drain_deadline) {
                if let Err(error) = self.poll_once() {
                    if !matches!(error, Error::Completion { .. }) {
                        failures.push(error.to_string());
                    }
                }
            }
            if self.completions.outstanding() != 0 {
                failures.push(format!(
                    "timed out draining {} outstanding URMA WRs",
                    self.completions.outstanding()
                ));
            }

            for lane in self.lanes.values_mut() {
                let outstanding = self.completions.outstanding_for_lane(lane.id());
                if let Err(error) = lane.close(outstanding) {
                    failures.push(error.to_string());
                }
            }
            self.lanes.clear();

            if let Some(mut pool) = self.buffer_pool.take() {
                pool.stop();
                if let Err(error) = pool.close() {
                    failures.push(error.to_string());
                }
            }
            if let Some(mut recv_jfc) = self.recv_jfc.take() {
                if let Err(error) = recv_jfc.close() {
                    failures.push(error.to_string());
                }
            }
            if let Some(mut send_jfc) = self.send_jfc.take() {
                if let Err(error) = send_jfc.close() {
                    failures.push(error.to_string());
                }
            }
            if let Some(mut native) = self.native.take() {
                if let Err(error) = native.close() {
                    failures.push(native_error("runtime_close", error).to_string());
                }
            }

            if failures.is_empty() {
                ACTIVE.store(false, Ordering::Release);
                Ok(())
            } else {
                // Native state is uncertain; keep the process guard active.
                self.poisoned = true;
                Err(Error::Shutdown { failures })
            }
        }
    }

    impl Drop for UrmaRuntime {
        fn drop(&mut self) {
            if !self.poisoned {
                let _ = self.shutdown_inner();
            }
        }
    }

    fn validate_config(config: &RuntimeConfig, capability: &UrmaDeviceCapability) -> Result<()> {
        config.buffer_pool.total_len()?;
        if capability.max_jfc < 2 {
            return Err(Error::InvalidConfiguration(
                "device reports fewer than two available JFC resources".into(),
            ));
        }
        for (name, depth) in [
            ("send_jfc_depth", config.send_jfc_depth),
            ("recv_jfc_depth", config.recv_jfc_depth),
        ] {
            if depth == 0 || depth > capability.max_jfc_depth {
                return Err(Error::InvalidConfiguration(format!(
                    "{name}={depth} is outside 1..={}",
                    capability.max_jfc_depth
                )));
            }
        }
        let slot_size = u64::try_from(config.buffer_pool.slot_size)
            .map_err(|_| Error::InvalidConfiguration("slot_size does not fit u64".into()))?;
        if slot_size > capability.max_msg_size {
            return Err(Error::InvalidConfiguration(format!(
                "slot_size={slot_size} exceeds max_msg_size={}",
                capability.max_msg_size
            )));
        }
        Ok(())
    }

    fn validate_jetty_config(
        config: &JettyConfig,
        capability: &UrmaDeviceCapability,
    ) -> Result<()> {
        if capability.max_jetty == 0 || capability.max_jfs == 0 || capability.max_jfr == 0 {
            return Err(Error::InvalidConfiguration(
                "device does not advertise the resources required by a duplex Jetty".into(),
            ));
        }
        for (name, value, maximum) in [
            ("send_depth", config.send_depth, capability.max_jfs_depth),
            ("recv_depth", config.recv_depth, capability.max_jfr_depth),
            ("max_send_sge", config.max_send_sge, capability.max_jfs_sge),
            ("max_recv_sge", config.max_recv_sge, capability.max_jfr_sge),
        ] {
            if value == 0 || value > maximum {
                return Err(Error::InvalidConfiguration(format!(
                    "Jetty {name}={value} is outside 1..={maximum}"
                )));
            }
        }
        if capability.max_jfs_rsge == 0 {
            return Err(Error::InvalidConfiguration(
                "device does not advertise an RC remote-SGE capability".into(),
            ));
        }
        if config.post_list_size == 0 || config.post_list_size > ffi::MAX_POST_LIST {
            return Err(Error::InvalidConfiguration(format!(
                "Jetty post_list_size={} is outside 1..={}",
                config.post_list_size,
                ffi::MAX_POST_LIST
            )));
        }
        Ok(())
    }

    fn rollback_startup(
        primary: Error,
        mut buffer_pool: Option<UrmaBufferPool>,
        mut recv_jfc: Option<UrmaJfc>,
        mut send_jfc: Option<UrmaJfc>,
        mut native: Option<ffi::NativeRuntime>,
    ) -> Error {
        let mut cleanup_failures = Vec::new();
        if let Some(pool) = buffer_pool.as_mut() {
            if let Err(error) = pool.close() {
                cleanup_failures.push(error.to_string());
            }
        }
        if let Some(jfc) = recv_jfc.as_mut() {
            if let Err(error) = jfc.close() {
                cleanup_failures.push(error.to_string());
            }
        }
        if let Some(jfc) = send_jfc.as_mut() {
            if let Err(error) = jfc.close() {
                cleanup_failures.push(error.to_string());
            }
        }
        if let Some(runtime) = native.as_mut() {
            if let Err(error) = runtime.close() {
                cleanup_failures.push(native_error("runtime_close", error).to_string());
            }
        }
        if cleanup_failures.is_empty() {
            primary
        } else {
            Error::StartupRollback {
                primary: Box::new(primary),
                cleanup_failures,
            }
        }
    }

    fn from_ffi_capability(raw: ffi::DeviceCapability) -> UrmaDeviceCapability {
        UrmaDeviceCapability {
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
        }
    }
}

pub(crate) use native::UrmaRuntime;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_keeps_device_selection_and_m1_defaults() {
        let config = RuntimeConfig::new("urma0", 2);
        assert_eq!(config.device_name, "urma0");
        assert_eq!(config.eid_index, 2);
        assert_eq!(config.send_jfc_depth, 4096);
        assert_eq!(config.recv_jfc_depth, 4096);
        assert_eq!(config.buffer_pool, BufferPoolConfig::default());
    }

    #[test]
    fn advertised_message_size_is_capped_by_registered_slot() {
        assert_eq!(
            effective_max_message_size(4 * 1024 * 1024, 64 * 1024).unwrap(),
            64 * 1024
        );
    }
}
