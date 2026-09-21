use super::{
    buffer::{
        BufferPoolConfig, LeaseRecycle, LeaseRecycleNotifier, RegisteredRxWindowLease,
        RxBufferStateCounts, TxWindowLease,
    },
    ffi::read::{source::ReadBacking, ReadDescriptor, ReadToken},
    read_owner::{ReadBudget, ReadOwnerId},
    Error, Result,
};
use dragonfly_client_metric::collect_urma_rx_state_metrics;

pub(crate) struct ReadChildRequest {
    pub(crate) peer_id: u16,
    pub(crate) allocation_bytes: u64,
    pub(crate) piece_length: u64,
    pub(crate) max_outstanding: usize,
    pub(crate) descriptor: ReadDescriptor,
    pub(crate) token: ReadToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadChildId(ReadOwnerId);

#[derive(Debug)]
#[allow(dead_code)] // Consumed by the gated READ session state machine.
pub(crate) enum ReadChildAdmission {
    Ready(ReadChildId),
    Quarantined { id: ReadChildId, error: Error },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadChildProgress {
    pub(crate) piece_length: u64,
    pub(crate) accepted_bytes: u64,
    pub(crate) retired_bytes: u64,
    pub(crate) accepted_wr_count: u64,
    pub(crate) retired_wr_count: u64,
    pub(crate) outstanding_wr_count: usize,
    pub(crate) posting_stopped: bool,
    pub(crate) failed: bool,
    pub(crate) read_succeeded: bool,
}

/// CPU-visible span of a published READ destination lease. The registered
/// buffer itself stays owned by the Child owner on the fabric owner thread;
/// only the pointer identity crosses to Storage. Content is final because
/// every READ WR retired before publication, so CPU reads cannot race DMA.
/// The pointer stays valid until recycle_read_child_lease succeeds.
#[derive(Clone, Copy)]
#[allow(dead_code)] // Consumed by the gated READ session state machine.
pub(crate) struct ReadLeaseSpan {
    pub(crate) data: *mut u8,
    pub(crate) length: usize,
}
// SAFETY: The span carries no ownership; the backing registered buffer remains
// on the fabric owner thread until recycle. The pointer is dereferenced only by
// the Storage consumer between publish and a successful recycle.
unsafe impl Send for ReadLeaseSpan {}

pub(crate) struct ReadSourceRequest {
    pub(crate) peer_id: u16,
    pub(crate) backing: ReadBacking<()>,
    pub(crate) token: ReadToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadSourceId(ReadOwnerId);

#[derive(Debug)]
#[allow(dead_code)] // Consumed by the gated READ session state machine.
pub(crate) struct ReadSourceOffer {
    pub(crate) id: ReadSourceId,
    pub(crate) descriptor: ReadDescriptor,
    pub(crate) token: ReadToken,
}

#[derive(Debug)]
#[allow(dead_code)] // Consumed by the gated READ session state machine.
pub(crate) enum ReadSourceAdmission {
    Ready(ReadSourceOffer),
    Quarantined { id: ReadSourceId, error: Error },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadRuntimeConfig {
    pub(crate) budget: ReadBudget,
    pub(crate) max_outstanding_per_peer: usize,
    pub(crate) buffer_alignment: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeConfig {
    pub(crate) device_name: String,
    pub(crate) eid_index: u32,
    pub(crate) send_jfc_depth: u32,
    pub(crate) recv_jfc_depth: u32,
    pub(crate) buffer_pool: BufferPoolConfig,
    pub(crate) tp_type: crate::urma::TpType,
    pub(crate) read: Option<ReadRuntimeConfig>,
}

impl RuntimeConfig {
    pub(crate) fn new(device_name: impl Into<String>, eid_index: u32) -> Self {
        Self {
            device_name: device_name.into(),
            eid_index,
            send_jfc_depth: 4096,
            recv_jfc_depth: 4096,
            buffer_pool: BufferPoolConfig::default(),
            tp_type: crate::urma::TpType::default(),
            read: None,
        }
    }

    pub(crate) fn with_registered_budget(
        mut self,
        max_registered_bytes: u64,
        tx_registered_bytes: u64,
    ) -> Result<Self> {
        let slot_size = u64::try_from(self.buffer_pool.slot_size)
            .map_err(|_| Error::InvalidConfiguration("URMA slot size exceeds u64".into()))?;
        let total_slots = usize::try_from(max_registered_bytes / slot_size).map_err(|_| {
            Error::InvalidConfiguration("URMA registered budget is too large".into())
        })?;
        let tx_slots = usize::try_from(tx_registered_bytes / slot_size)
            .map_err(|_| Error::InvalidConfiguration("URMA TX budget is too large".into()))?;
        if total_slots < 2 || tx_slots == 0 || tx_slots >= total_slots {
            return Err(Error::InvalidConfiguration(
                "URMA registered budget must reserve at least one slot for TX and RX".into(),
            ));
        }
        self.buffer_pool.tx_slot_count = tx_slots;
        self.buffer_pool.rx_slot_count = total_slots - tx_slots;
        // Re-run the slot identity and multiplication bounds before native
        // startup so an oversized budget cannot reach registration.
        self.buffer_pool.total_len()?;
        Ok(self)
    }

    pub(crate) fn with_tp_type(mut self, tp_type: crate::urma::TpType) -> Self {
        self.tp_type = tp_type;
        self
    }

    /// Enables the READ-only data plane. Once enabled, the full effective JFS
    /// depth is reserved for READ and legacy SEND/RECV posts are rejected.
    pub(crate) fn with_read_only(mut self, read: ReadRuntimeConfig) -> Self {
        self.read = Some(read);
        self
    }
}

fn effective_max_message_size(device_max: u64, slot_size: usize) -> Result<u64> {
    let slot_size = u64::try_from(slot_size)
        .map_err(|_| Error::InvalidConfiguration("slot_size does not fit u64".into()))?;
    Ok(device_max.min(slot_size))
}

fn shared_endpoint_config(
    runtime: &RuntimeConfig,
    capability: &UrmaDeviceCapability,
) -> crate::urma::lane::JettyConfig {
    let send_depth = runtime.send_jfc_depth.min(capability.max_jfs_depth);
    let send_depth = if runtime.read.is_some() {
        send_depth
    } else {
        send_depth.min(u32::try_from(runtime.buffer_pool.tx_slot_count).unwrap_or(u32::MAX))
    };
    let recv_depth = runtime.recv_jfc_depth.min(capability.max_jfr_depth);
    let recv_depth = if runtime.read.is_some() {
        recv_depth
    } else {
        recv_depth.min(u32::try_from(runtime.buffer_pool.rx_slot_count).unwrap_or(u32::MAX))
    };
    crate::urma::lane::JettyConfig {
        send_depth,
        recv_depth,
        max_send_sge: 1,
        max_recv_sge: 1,
        token: 0,
        tp_type: runtime.tp_type,
    }
}

/// Rust-owned capability subset copied from `urma_device_attr_t`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UrmaDeviceCapability {
    pub(crate) transport_type: i32,
    pub(crate) transport_modes: u32,
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
    pub(crate) max_read_size: u32,
    pub(crate) max_write_size: u32,
}

mod native {
    use super::*;
    use crate::urma::{
        buffer::UrmaBufferPool,
        completion::{
            deadline_after, deadline_expired, CompletionRouter, ReadCompletionSink,
            RegisteredRxCompletionTx, RegisteredTxCompletionTx,
        },
        ffi::{self, NativeRuntime},
        lane::{JettyConfig, JettyDescriptor, PeerTarget, TransportMode, UrmaJetty},
        native_error,
        read_child_owner::NativeChild,
        read_owner::ReadPeer,
        read_owners::ReadOwners,
        read_owners::{ChildAdmission, ChildSpec, ReadDispatchError},
        read_source_owner::{
            SourceAdmission, SourceAdmissionError, SourceRevoked, UnregisterPermit,
        },
        read_wr_credit::{CreditedChild, ReadWrCredits},
    };
    use std::{
        collections::HashMap,
        ffi::CString,
        marker::PhantomData,
        rc::Rc,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::Duration,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum JfcKind {
        Send,
        Receive,
    }

    /// Safe owner of one native JFC. It remains part of the process-level
    /// Runtime resource tree and is never owned by a PeerTarget.
    struct UrmaJfc {
        kind: JfcKind,
        handle: ffi::JfcHandle,
    }

    pub(super) struct PeerIdAllocator {
        next_fresh: u32,
        free: Vec<u16>,
        generations: HashMap<u16, u8>,
    }

    impl PeerIdAllocator {
        pub(super) fn new() -> Self {
            Self {
                next_fresh: 1,
                free: Vec::new(),
                generations: HashMap::new(),
            }
        }

        pub(super) fn allocate(&mut self) -> Result<(u16, u8)> {
            let id = match self.free.pop() {
                Some(id) => id,
                None if self.next_fresh <= u32::from(u16::MAX) => {
                    let id = self.next_fresh as u16;
                    self.next_fresh += 1;
                    id
                }
                None => {
                    return Err(Error::InvalidConfiguration(
                        "PeerTarget id space exhausted".into(),
                    ));
                }
            };
            let generation = self.generations.entry(id).or_insert(0);
            *generation = generation.wrapping_add(1);
            if *generation == 0 {
                *generation = 1;
            }
            Ok((id, *generation))
        }

        pub(super) fn release(&mut self, id: u16) {
            debug_assert_ne!(id, 0);
            debug_assert!(!self.free.contains(&id), "PeerTarget id released twice");
            self.free.push(id);
        }
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

    /// The one process-shared RM data-plane endpoint (Jetty + JFR pair).
    /// Created lazily before the first peer connects and reused by every
    /// later PeerTarget: all peers import into this Jetty and share the same
    /// local descriptor, so native Jetty/JFR resources stay O(1) per process.
    struct SharedRmEndpoint {
        jetty: UrmaJetty,
        descriptor: JettyDescriptor,
    }

    type RuntimeReadOwners = ReadOwners<(), CreditedChild<NativeChild<()>>>;

    /// The concrete READ owner container lives on the single fabric owner
    /// thread. RuntimeConfig selects Disabled or the READ-only Active state at
    /// startup; it never switches modes while native objects are live.
    enum RuntimeReadState {
        Disabled,
        Active {
            owners: RuntimeReadOwners,
            credits: Rc<std::cell::RefCell<ReadWrCredits>>,
            max_outstanding_per_peer: usize,
            buffer_alignment: u64,
        },
    }

    impl RuntimeReadState {
        fn activate_peer(&mut self, peer: ReadPeer) -> Result<()> {
            match self {
                Self::Disabled => Ok(()),
                Self::Active { owners, .. } => owners.activate_peer(peer).map_err(read_owner_error),
            }
        }

        fn drain_peer(&mut self, peer: ReadPeer) -> Result<()> {
            match self {
                Self::Disabled => Ok(()),
                Self::Active { owners, .. } => owners.drain_peer(peer).map_err(read_owner_error),
            }
        }

        fn peer_drained(&self, peer: ReadPeer) -> bool {
            match self {
                Self::Disabled => true,
                Self::Active { owners, .. } => owners.peer_drained(peer),
            }
        }

        fn begin_shutdown(&mut self) {
            if let Self::Active { owners, .. } = self {
                owners.begin_shutdown();
            }
        }

        fn drained(&self) -> bool {
            match self {
                Self::Disabled => true,
                Self::Active { owners, .. } => owners.drained(),
            }
        }

        fn is_active(&self) -> bool {
            matches!(self, Self::Active { .. })
        }
    }

    impl ReadCompletionSink for RuntimeReadState {
        fn outstanding_read_completions(&self) -> usize {
            match self {
                Self::Disabled => 0,
                Self::Active { owners, .. } => owners.outstanding_read_completions(),
            }
        }

        fn try_route_read_completion(
            &mut self,
            record: ffi::CompletionRecord,
            recv_queue: bool,
        ) -> Option<Result<()>> {
            match self {
                Self::Disabled => None,
                Self::Active { owners, .. } => owners.try_route_read_completion(record, recv_queue),
            }
        }
    }

    fn read_owner_error(error: super::super::read_owner::OwnerError) -> Error {
        Error::Protocol(error.to_string())
    }

    fn read_dispatch_error(error: ReadDispatchError) -> Error {
        match error {
            ReadDispatchError::Registry(error) => read_owner_error(error),
            ReadDispatchError::Native(error) => native_error("read_owner", error),
        }
    }

    fn read_source_error(operation: &'static str, error: SourceAdmissionError) -> Error {
        match error {
            SourceAdmissionError::Budget(error) => read_owner_error(error),
            SourceAdmissionError::Native(error) => native_error(operation, error),
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SharedRxStateSnapshot {
        physical: RxBufferStateCounts,
        posted_wrs: usize,
        logical_credits: usize,
    }

    impl SharedRxStateSnapshot {
        fn validate(self) -> Result<()> {
            if self.physical.accounted() != self.physical.total {
                return Err(Error::Protocol(format!(
                    "shared RX slot conservation failed: accounted={} total={}",
                    self.physical.accounted(),
                    self.physical.total
                )));
            }
            if self.physical.posted != self.posted_wrs {
                return Err(Error::Protocol(format!(
                    "shared RX WR conservation failed: physical_posted={} tracked_posted={}",
                    self.physical.posted, self.posted_wrs
                )));
            }
            if self.logical_credits > self.posted_wrs {
                return Err(Error::Protocol(format!(
                    "shared RX logical credit exceeds posted WRs: logical={} posted={}",
                    self.logical_credits, self.posted_wrs
                )));
            }
            Ok(())
        }
    }

    impl SharedRmEndpoint {
        fn create(
            native: &mut ffi::NativeRuntime,
            send_jfc: &ffi::JfcHandle,
            recv_jfc: &ffi::JfcHandle,
            config: &JettyConfig,
        ) -> Result<Self> {
            let mut jetty = UrmaJetty::create(native, send_jfc, recv_jfc, config)?;
            let descriptor = match jetty.export_descriptor() {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    // Roll the freshly created Jetty back so the process-wide
                    // endpoint state stays all-or-nothing.
                    let _ = jetty.close();
                    return Err(error);
                }
            };
            Ok(Self { jetty, descriptor })
        }
    }

    /// Safe owner of the complete native resource tree.
    pub(crate) struct UrmaRuntime {
        capability: UrmaDeviceCapability,
        max_payload_size: u64,
        max_post_list_size: u32,
        endpoint_config: JettyConfig,
        buffer_pool: Option<UrmaBufferPool>,
        recv_jfc: Option<UrmaJfc>,
        send_jfc: Option<UrmaJfc>,
        native: Option<ffi::NativeRuntime>,
        endpoint: Option<SharedRmEndpoint>,
        accepting: bool,
        poisoned: bool,
        peer_ids: PeerIdAllocator,
        peers: HashMap<u16, PeerTarget>,
        completions: CompletionRouter,
        read: RuntimeReadState,
        _not_send_sync: PhantomData<Rc<()>>,
    }

    impl UrmaRuntime {
        fn reject_legacy_data_plane_when_read_only(&self) -> Result<()> {
            if self.read.is_active() {
                return Err(Error::Protocol(
                    "legacy URMA SEND/RECV data plane is disabled in READ-only mode".into(),
                ));
            }
            Ok(())
        }

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
            let max_post_list_size = if config.read.is_some() {
                config.send_jfc_depth.min(config.recv_jfc_depth)
            } else {
                config
                    .send_jfc_depth
                    .min(config.recv_jfc_depth)
                    .min(u32::try_from(config.buffer_pool.tx_slot_count).unwrap_or(u32::MAX))
                    .min(u32::try_from(config.buffer_pool.rx_slot_count).unwrap_or(u32::MAX))
            };
            let endpoint_config = shared_endpoint_config(&config, &capability);
            validate_jetty_config(&endpoint_config, &capability)?;

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
            let buffer_pool = if config.read.is_some() {
                None
            } else {
                match UrmaBufferPool::create(
                    &mut native,
                    config.buffer_pool.clone(),
                    recycle_notifier,
                ) {
                    Ok(pool) => Some(pool),
                    Err(primary) => {
                        return Err(rollback_startup(
                            primary,
                            None,
                            Some(recv_jfc),
                            Some(send_jfc),
                            Some(native),
                        ));
                    }
                }
            };

            debug_assert_eq!(send_jfc.kind(), JfcKind::Send);
            debug_assert_eq!(recv_jfc.kind(), JfcKind::Receive);
            let read = match config.read {
                Some(read) => {
                    let credits = match ReadWrCredits::new(
                        endpoint_config.send_depth as usize,
                        read.max_outstanding_per_peer,
                    ) {
                        Ok(credits) => credits,
                        Err(error) => {
                            return Err(rollback_startup(
                                native_error("create_read_wr_credits", error),
                                buffer_pool,
                                Some(recv_jfc),
                                Some(send_jfc),
                                Some(native),
                            ))
                        }
                    };
                    let owners = match ReadOwners::new(read.budget) {
                        Ok(owners) => owners,
                        Err(error) => {
                            return Err(rollback_startup(
                                read_owner_error(error),
                                buffer_pool,
                                Some(recv_jfc),
                                Some(send_jfc),
                                Some(native),
                            ))
                        }
                    };
                    RuntimeReadState::Active {
                        owners,
                        credits,
                        max_outstanding_per_peer: read.max_outstanding_per_peer,
                        buffer_alignment: read.buffer_alignment,
                    }
                }
                None => RuntimeReadState::Disabled,
            };
            Ok(Self {
                capability,
                max_payload_size,
                max_post_list_size,
                endpoint_config,
                buffer_pool,
                recv_jfc: Some(recv_jfc),
                send_jfc: Some(send_jfc),
                native: Some(native),
                endpoint: None,
                accepting: true,
                poisoned: false,
                peer_ids: PeerIdAllocator::new(),
                peers: HashMap::new(),
                completions: CompletionRouter::new(16)?,
                read,
                _not_send_sync: PhantomData,
            })
        }

        pub(crate) fn create_peer_target(
            &mut self,
            post_list_size: u32,
        ) -> Result<(u16, JettyDescriptor)> {
            if !self.accepting {
                return Err(Error::InvalidConfiguration(
                    "runtime is no longer accepting operations".into(),
                ));
            }
            if post_list_size == 0 || post_list_size > ffi::MAX_POST_LIST {
                return Err(Error::InvalidConfiguration(format!(
                    "post_list_size={post_list_size} is outside 1..={}",
                    ffi::MAX_POST_LIST
                )));
            }
            if self.endpoint.is_none() {
                // First peer: create the one process-shared RM endpoint.
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
                let endpoint = SharedRmEndpoint::create(
                    native,
                    send_jfc.handle(),
                    recv_jfc.handle(),
                    &self.endpoint_config,
                )?;
                let (jetty_id, jfr_id) = endpoint.jetty.local_ids();
                self.completions.register_endpoint(jetty_id, jfr_id)?;
                self.endpoint = Some(endpoint);
            }
            let capability = self.capability.clone();
            let (peer_id, generation) = self.peer_ids.allocate()?;
            let endpoint = self
                .endpoint
                .as_ref()
                .expect("shared endpoint exists after create_peer_target");
            let peer = match PeerTarget::new(
                peer_id,
                generation,
                capability,
                post_list_size
                    .min(self.endpoint_config.send_depth)
                    .min(self.endpoint_config.recv_depth)
                    .min(self.max_post_list_size),
            ) {
                Ok(peer) => peer,
                Err(error) => {
                    self.peer_ids.release(peer_id);
                    return Err(error);
                }
            };
            let read_peer = ReadPeer {
                id: peer_id,
                generation,
            };
            if let Err(error) = self.read.activate_peer(read_peer) {
                self.peer_ids.release(peer_id);
                return Err(error);
            }
            self.peers.insert(peer_id, peer);
            Ok((peer_id, endpoint.descriptor.clone()))
        }

        pub(crate) fn connect_peer_target(
            &mut self,
            peer_id: u16,
            descriptor: &JettyDescriptor,
        ) -> Result<()> {
            // Split borrows: the endpoint Jetty and PeerTarget map are distinct
            // fields of Runtime.
            let Self {
                endpoint, peers, ..
            } = self;
            let endpoint = endpoint
                .as_mut()
                .ok_or_else(|| Error::Protocol("shared RM endpoint is not created".into()))?;
            let peer = peers
                .get_mut(&peer_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA PeerTarget {peer_id}")))?;
            peer.import_remote(&mut endpoint.jetty, descriptor)?;
            let (generation, remote_id) = (peer.generation(), peer.remote_id()?);
            self.completions
                .authorize_remote(peer_id, generation, remote_id)
        }

        /// # Safety
        /// The caller must have authenticated descriptor/token ownership and
        /// generation, validated exact Piece bounds, and reserved the business
        /// transfer identity. This owner-thread call supplies native/byte/JFS
        /// ownership but cannot establish those wire-level facts itself.
        pub(crate) unsafe fn create_read_child(
            &mut self,
            request: ReadChildRequest,
        ) -> Result<ReadChildAdmission> {
            if request.max_outstanding == 0 || request.piece_length == 0 {
                return Err(Error::InvalidConfiguration(
                    "invalid READ Child request".into(),
                ));
            }
            let peer = self.peers.get(&request.peer_id).ok_or_else(|| {
                Error::Protocol(format!("unknown URMA PeerTarget {}", request.peer_id))
            })?;
            let read_peer = ReadPeer {
                id: request.peer_id,
                generation: peer.generation(),
            };
            let target = peer.read_target()?;
            let endpoint = self
                .endpoint
                .as_ref()
                .ok_or_else(|| Error::Protocol("shared RM endpoint is not created".into()))?;
            let (jetty_id, _) = endpoint.jetty.local_ids();
            let jetty = endpoint.jetty.read_handle();
            let native = self
                .native
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("runtime is closed".into()))?;
            let (owners, credits, configured_max, alignment) = match &mut self.read {
                RuntimeReadState::Disabled => {
                    return Err(Error::InvalidConfiguration(
                        "READ-only runtime is not enabled".into(),
                    ))
                }
                RuntimeReadState::Active {
                    owners,
                    credits,
                    max_outstanding_per_peer,
                    buffer_alignment,
                } => (
                    owners,
                    credits.clone(),
                    *max_outstanding_per_peer,
                    *buffer_alignment,
                ),
            };
            if request.max_outstanding > configured_max {
                return Err(Error::InvalidConfiguration(format!(
                    "READ Child max_outstanding={} exceeds per-peer limit {configured_max}",
                    request.max_outstanding
                )));
            }
            let spec = ChildSpec {
                allocation_bytes: request.allocation_bytes,
                piece_length: request.piece_length,
                jetty_id,
                max_outstanding: request.max_outstanding,
            };
            // SAFETY: The caller provides authenticated descriptor/generation
            // and exact Piece ownership; runtime supplies the retained handles,
            // byte registry and READ-only JFS credits.
            match unsafe {
                owners.create_native_child(
                    read_peer,
                    spec,
                    native,
                    jetty,
                    target,
                    alignment,
                    &request.descriptor,
                    &request.token,
                    self.capability.max_read_size,
                    (),
                    credits,
                )
            } {
                ChildAdmission::Ready(id) => Ok(ReadChildAdmission::Ready(ReadChildId(id))),
                ChildAdmission::Rejected(error) => Err(read_dispatch_error(error)),
                ChildAdmission::Quarantined { id, error } => Ok(ReadChildAdmission::Quarantined {
                    id: ReadChildId(id),
                    error: native_error("create_read_child", error),
                }),
            }
        }

        pub(crate) fn post_read_child(&mut self, id: ReadChildId, length: u32) -> Result<u64> {
            match &mut self.read {
                RuntimeReadState::Disabled => Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                )),
                RuntimeReadState::Active { owners, .. } => {
                    owners.post(id.0, length).map_err(read_dispatch_error)
                }
            }
        }

        pub(crate) fn read_child_progress(&mut self, id: ReadChildId) -> Result<ReadChildProgress> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            let progress = owners.child_progress(id.0).map_err(read_dispatch_error)?;
            Ok(ReadChildProgress {
                piece_length: progress.piece_length,
                accepted_bytes: progress.accepted_bytes,
                retired_bytes: progress.retired_bytes,
                accepted_wr_count: progress.accepted_wr_count,
                retired_wr_count: progress.retired_wr_count,
                outstanding_wr_count: progress.outstanding_wr_count,
                posting_stopped: progress.posting_stopped,
                failed: progress.failed,
                read_succeeded: progress.read_succeeded,
            })
        }

        /// First lease stage: stop posting and close the native import while
        /// keeping the registered destination buffer and the full budget charge.
        pub(crate) fn drain_read_child_for_lease(&mut self, id: ReadChildId) -> Result<()> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            owners
                .drain_child_for_lease(id.0)
                .map_err(read_dispatch_error)
        }

        /// Extracts the CPU span of the fully read registered destination buffer
        /// for Storage. The lease itself stays on the owner thread until recycle;
        /// the budget stays charged until the reap completes.
        pub(crate) fn publish_read_child_lease(
            &mut self,
            id: ReadChildId,
        ) -> Result<ReadLeaseSpan> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            let span = owners
                .publish_child_lease(id.0)
                .map_err(read_dispatch_error)?;
            Ok(ReadLeaseSpan {
                data: span.data,
                length: span.length,
            })
        }

        /// Final lease stage: close the published lease and finish the reap,
        /// releasing the budget. Requires a retired (or quarantined) Child and
        /// joined Storage consumer workers.
        pub(crate) fn recycle_read_child_lease(&mut self, id: ReadChildId) -> Result<bool> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            owners
                .recycle_child_lease(id.0)
                .map_err(|error| match error {
                    super::super::read_owner::ReapError::Registry(error) => read_owner_error(error),
                    super::super::read_owner::ReapError::Cleanup(error) => {
                        native_error("recycle_read_child_lease", error)
                    }
                })
        }

        /// Registers one immutable Parent Piece and exports the descriptor on the
        /// native owner thread. The token is returned only with a usable offer.
        ///
        /// # Safety
        /// The caller must hold an immutable, exact-range Storage backing lease,
        /// enforce source admission, and bind this request to the authenticated
        /// peer/transfer generation. The backing must satisfy provider alignment.
        pub(crate) unsafe fn register_read_source(
            &mut self,
            request: ReadSourceRequest,
        ) -> Result<ReadSourceAdmission> {
            let peer = self.peers.get(&request.peer_id).ok_or_else(|| {
                Error::Protocol(format!("unknown URMA PeerTarget {}", request.peer_id))
            })?;
            let read_peer = ReadPeer {
                id: request.peer_id,
                generation: peer.generation(),
            };
            let native = self
                .native
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("runtime is closed".into()))?;
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            let ReadSourceRequest { backing, token, .. } = request;
            // SAFETY: The caller supplies immutable exact-range backing and
            // authenticated generation; the owner registry supplies admission.
            match unsafe { owners.register_source(read_peer, native, backing, &token) } {
                SourceAdmission::Registered(id) => match owners.source_descriptor(id) {
                    Ok(descriptor) => Ok(ReadSourceAdmission::Ready(ReadSourceOffer {
                        id: ReadSourceId(id),
                        descriptor,
                        token,
                    })),
                    Err(error) => {
                        // No descriptor is returned. Retain the source and charge
                        // until the normal unregister/revocation path reaps it.
                        owners.retire(id).map_err(read_owner_error)?;
                        Ok(ReadSourceAdmission::Quarantined {
                            id: ReadSourceId(id),
                            error: read_source_error("read_source_descriptor", error),
                        })
                    }
                },
                SourceAdmission::Rejected { error, backing } => {
                    // Rejected proves registration never began, so this backing is
                    // safe to release on the owner thread.
                    drop(backing);
                    Err(read_source_error("register_read_source", error))
                }
                SourceAdmission::Uncertain { id, error } => Ok(ReadSourceAdmission::Quarantined {
                    id: ReadSourceId(id),
                    error: native_error("register_read_source", error),
                }),
            }
        }

        /// Stops descriptor dispatch. This is only the local first step of
        /// revocation and does not release native state, backing, or budget.
        pub(crate) fn retire_read_source(&mut self, id: ReadSourceId) -> Result<()> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            owners.retire(id.0).map_err(read_owner_error)
        }

        /// Runs native unregister while retaining backing and budget.
        ///
        /// # Safety
        /// The caller must prove the provider's unregister preconditions for this
        /// exact source. ReadDone, EOF, and timeout alone are insufficient.
        pub(crate) unsafe fn unregister_read_source(&mut self, id: ReadSourceId) -> Result<bool> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            // SAFETY: The caller supplied the provider-specific drain proof.
            let permit = unsafe { UnregisterPermit::new(id.0) };
            owners
                .reap_source(id.0, &permit, None)
                .map_err(|error| match error {
                    super::super::read_owner::ReapError::Registry(error) => read_owner_error(error),
                    super::super::read_owner::ReapError::Cleanup(error) => {
                        native_error("unregister_read_source", error)
                    }
                })
        }

        /// Releases the source only after independent remote revocation proof.
        /// This retries unregister first if a previous attempt was uncertain.
        ///
        /// # Safety
        /// The caller must prove both unregister preconditions and that access to
        /// this exact generation has ceased and cannot resume, including stale
        /// tokens and failed-registration rollback.
        pub(crate) unsafe fn release_read_source_after_revoke(
            &mut self,
            id: ReadSourceId,
        ) -> Result<bool> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            // SAFETY: Both identity-bound proofs are supplied by the caller.
            let permit = unsafe { UnregisterPermit::new(id.0) };
            // SAFETY: See method contract.
            let revoked = unsafe { SourceRevoked::new(id.0) };
            owners
                .reap_source(id.0, &permit, Some(&revoked))
                .map_err(|error| match error {
                    super::super::read_owner::ReapError::Registry(error) => read_owner_error(error),
                    super::super::read_owner::ReapError::Cleanup(error) => {
                        native_error("release_read_source_after_revoke", error)
                    }
                })
        }

        /// Cleanup-only retirement. A later Storage handoff must extract an
        /// independently owned destination lease before invoking this path.
        pub(crate) fn retire_read_child_for_cleanup(&mut self, id: ReadChildId) -> Result<bool> {
            let RuntimeReadState::Active { owners, .. } = &mut self.read else {
                return Err(Error::InvalidConfiguration(
                    "READ-only runtime is not enabled".into(),
                ));
            };
            owners.retire(id.0).map_err(read_owner_error)?;
            owners.reap_child(id.0).map_err(|error| match error {
                super::super::read_owner::ReapError::Registry(error) => read_owner_error(error),
                super::super::read_owner::ReapError::Cleanup(error) => {
                    native_error("reap_read_child", error)
                }
            })
        }

        pub(crate) fn post_receive_window_registered(
            &mut self,
            peer_id: u16,
            sequences: Vec<u64>,
            completion_txs: Vec<RegisteredRxCompletionTx>,
        ) -> Result<()> {
            self.reject_legacy_data_plane_when_read_only()?;
            let pool = self
                .buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?;
            let completions = &mut self.completions;
            let endpoint = self
                .endpoint
                .as_mut()
                .ok_or_else(|| Error::Protocol("shared RM endpoint is not created".into()))?;
            self.peers
                .get_mut(&peer_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA PeerTarget {peer_id}")))?
                .post_receive_window_registered(
                    &mut endpoint.jetty,
                    self.endpoint_config.recv_depth as usize,
                    pool,
                    completions,
                    sequences,
                    completion_txs,
                )?;
            self.verify_shared_rx_state()
        }

        pub(crate) fn grant_send_credit(&mut self, peer_id: u16, count: u32) -> Result<()> {
            self.reject_legacy_data_plane_when_read_only()?;
            self.peer_mut(peer_id)?.grant_send_credit(count)
        }

        pub(crate) fn send_registered_window(
            &mut self,
            peer_id: u16,
            lease: TxWindowLease,
            sequences: Vec<u64>,
            completion: RegisteredTxCompletionTx,
        ) -> Result<()> {
            self.reject_legacy_data_plane_when_read_only()?;
            let pool = self
                .buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?;
            let completions = &mut self.completions;
            let endpoint = self
                .endpoint
                .as_mut()
                .ok_or_else(|| Error::Protocol("shared RM endpoint is not created".into()))?;
            self.peers
                .get_mut(&peer_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA PeerTarget {peer_id}")))?
                .send_registered_window(
                    &mut endpoint.jetty,
                    pool,
                    completions,
                    lease,
                    sequences,
                    completion,
                )
        }

        pub(crate) fn poll_once(&mut self) -> Result<usize> {
            let send_jfc = self
                .send_jfc
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("send JFC is closed".into()))?;
            let progress =
                if self.read.is_active() {
                    self.completions
                        .poll_read_only(send_jfc.handle(), &mut self.read)
                } else {
                    let recv_jfc = self.recv_jfc.as_ref().ok_or_else(|| {
                        Error::InvalidConfiguration("receive JFC is closed".into())
                    })?;
                    let pool = self.buffer_pool.as_mut().ok_or_else(|| {
                        Error::InvalidConfiguration("buffer pool is closed".into())
                    })?;
                    self.completions.poll_once_with_read(
                        send_jfc.handle(),
                        recv_jfc.handle(),
                        pool,
                        &mut self.read,
                    )
                };
            if let Err(error) = &progress {
                self.completions.fail_pending(error);
            }
            let failed_peers = self.completions.take_failed_peers();
            for peer_id in failed_peers {
                if self.peers.contains_key(&peer_id) {
                    self.abort_peer_target(peer_id)?;
                }
            }
            let reap = self.reap_drained_peers();
            let count = match (progress, reap) {
                (Err(error), _) | (Ok(_), Err(error)) => Err(error),
                (Ok(count), Ok(())) => Ok(count),
            }?;
            if !self.read.is_active() {
                self.verify_shared_rx_state()?;
            }
            Ok(count)
        }

        pub(crate) fn outstanding(&self) -> usize {
            self.completions.outstanding_with_read(&self.read)
        }

        pub(crate) fn recycle_dropped_lease(&mut self, recycle: LeaseRecycle) -> Result<usize> {
            let count = self
                .buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .recycle_dropped_lease(recycle)?;
            self.verify_shared_rx_state()?;
            Ok(count)
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
            let count = self
                .buffer_pool
                .as_mut()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .recycle_rx_lease(lease)?;
            self.verify_shared_rx_state()?;
            Ok(count)
        }

        fn shared_rx_state(&self) -> Result<SharedRxStateSnapshot> {
            let physical = self
                .buffer_pool
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("buffer pool is closed".into()))?
                .rx_state_counts();
            Ok(SharedRxStateSnapshot {
                physical,
                posted_wrs: self.completions.outstanding_recv(),
                logical_credits: self.completions.logical_rx_credits(),
            })
        }

        fn verify_shared_rx_state(&self) -> Result<()> {
            let snapshot = self.shared_rx_state()?;
            snapshot.validate()?;
            collect_urma_rx_state_metrics(
                snapshot.physical.free,
                snapshot.physical.allocated,
                snapshot.physical.posted,
                snapshot.physical.ready,
                snapshot.physical.leased,
                snapshot.logical_credits,
            );
            Ok(())
        }

        pub(crate) fn transport_type(&self) -> u32 {
            u32::try_from(self.capability.transport_type).unwrap_or(0)
        }

        pub(crate) fn transport_modes(&self) -> u32 {
            self.capability.transport_modes
        }

        pub(crate) fn max_message_size(&self) -> u64 {
            self.max_payload_size
        }

        pub(crate) fn max_jfr_depth(&self) -> u32 {
            self.capability.max_jfr_depth
        }

        pub(crate) fn max_jfs_depth(&self) -> u32 {
            self.capability.max_jfs_depth
        }

        pub(crate) fn close_peer_target(&mut self, peer_id: u16) -> Result<()> {
            // Close is asynchronous at the provider boundary. The PeerTarget stays
            // owned by Runtime until `reap_drained_peers` observes both gates.
            self.abort_peer_target(peer_id)
        }

        pub(crate) fn abort_peer_target(&mut self, peer_id: u16) -> Result<()> {
            let generation = self
                .peers
                .get(&peer_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA PeerTarget {peer_id}")))?
                .generation();
            self.read.drain_peer(ReadPeer {
                id: peer_id,
                generation,
            })?;
            self.completions.begin_peer_retirement(peer_id)?;
            self.peer_mut(peer_id)?.begin_draining()?;
            self.reap_drained_peers()
        }

        fn reap_drained_peers(&mut self) -> Result<()> {
            // Per-peer retirement needs no endpoint flush: the shared Jetty
            // keeps serving other peers, and a PeerTarget is reaped once its
            // own outstanding SEND WRs have completed. Shared-JFR receive WRs
            // are anonymous endpoint resources and never hold a PeerTarget
            // open.
            let drained = self
                .peers
                .iter()
                .filter_map(|(&peer_id, peer)| {
                    (peer.is_draining()
                        && peer.is_retirement_armed()
                        && self.read.peer_drained(ReadPeer {
                            id: peer_id,
                            generation: peer.generation(),
                        })
                        && self.completions.outstanding_for_peer(peer_id) == 0)
                        .then_some(peer_id)
                })
                .collect::<Vec<_>>();
            for peer_id in drained {
                let outstanding = self.completions.outstanding_for_peer(peer_id);
                self.peer_mut(peer_id)?.close(outstanding)?;
                self.completions.unregister_peer(peer_id)?;
                self.peers.remove(&peer_id);
                self.peer_ids.release(peer_id);
            }
            Ok(())
        }

        fn peer_mut(&mut self, peer_id: u16) -> Result<&mut PeerTarget> {
            self.peers
                .get_mut(&peer_id)
                .ok_or_else(|| Error::Protocol(format!("unknown URMA PeerTarget {peer_id}")))
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
            self.read.begin_shutdown();
            let mut failures = Vec::new();

            let peer_ids = self.peers.keys().copied().collect::<Vec<_>>();
            for peer_id in peer_ids {
                if let Err(error) = self.abort_peer_target(peer_id) {
                    failures.push(error.to_string());
                }
            }
            let drain_deadline = deadline_after(Duration::from_secs(1));
            while !self.peers.is_empty() && !deadline_expired(drain_deadline) {
                if let Err(error) = self.poll_once() {
                    if !matches!(error, Error::Completion { .. }) {
                        push_unique_failure(&mut failures, error.to_string());
                    }
                }
                thread::sleep(Duration::from_micros(100));
            }
            if !self.peers.is_empty() || self.outstanding() != 0 || !self.read.drained() {
                // Fatal escalation: the process is going away, so force every
                // stranded WR on the shared endpoint to complete with an
                // error (Jetty mark_error + WR_FLUSH_ERR_DONE) and keep
                // polling until the flush CQE confirms completion.
                if self.completions.begin_endpoint_flush() {
                    if let Some(endpoint) = self.endpoint.as_mut() {
                        if let Err(error) = endpoint.jetty.mark_error() {
                            failures.push(error.to_string());
                        }
                    }
                }
                let flush_deadline = deadline_after(Duration::from_secs(5));
                while (!self.peers.is_empty()
                    || !self.completions.endpoint_ready_to_close()
                    || !self.read.drained())
                    && !deadline_expired(flush_deadline)
                {
                    if let Err(error) = self.poll_once() {
                        if !matches!(error, Error::Completion { .. }) {
                            push_unique_failure(&mut failures, error.to_string());
                        }
                    }
                    thread::sleep(Duration::from_micros(100));
                }
                if !self.peers.is_empty()
                    || !self.completions.endpoint_ready_to_close()
                    || !self.read.drained()
                {
                    failures.push(format!(
                        "timed out retiring {} URMA PeerTargets with {} endpoint WRs and read_drained={} even after endpoint flush",
                        self.peers.len(),
                        self.outstanding(),
                        self.read.drained(),
                    ));
                }
            }

            if self.peers.is_empty()
                && self.completions.endpoint_ready_to_close()
                && self.read.drained()
            {
                if let Some(mut endpoint) = self.endpoint.take() {
                    if let Err(error) = endpoint.jetty.close() {
                        failures.push(error.to_string());
                    }
                }
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
        if let Some(read) = &config.read {
            if capability.max_read_size == 0 {
                return Err(Error::InvalidConfiguration(
                    "device does not advertise URMA READ capability".into(),
                ));
            }
            if read.max_outstanding_per_peer == 0
                || read.max_outstanding_per_peer
                    > config.send_jfc_depth.min(capability.max_jfs_depth) as usize
            {
                return Err(Error::InvalidConfiguration(
                    "READ per-peer outstanding limit exceeds effective JFS depth".into(),
                ));
            }
            if read.buffer_alignment < 4096 || !read.buffer_alignment.is_power_of_two() {
                return Err(Error::InvalidConfiguration(
                    "READ buffer alignment must be a power of two and at least 4096".into(),
                ));
            }
        }
        Ok(())
    }

    fn push_unique_failure(failures: &mut Vec<String>, failure: String) {
        if !failures.contains(&failure) {
            failures.push(failure);
        }
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
        if capability.transport_modes & TransportMode::Rm as u32 == 0 {
            return Err(Error::InvalidConfiguration(
                "device does not advertise URMA RM transport mode".into(),
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
                "device does not advertise a remote-SGE capability".into(),
            ));
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
        }
    }
}

pub(crate) use native::UrmaRuntime;

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_for_depths(send: u32, recv: u32) -> UrmaDeviceCapability {
        UrmaDeviceCapability {
            transport_type: 0,
            transport_modes: crate::urma::TransportMode::Rm as u32,
            max_jfc: 2,
            max_jfs: 1,
            max_jfr: 1,
            max_jetty: 1,
            max_jfc_depth: send.max(recv),
            max_jfs_depth: send,
            max_jfr_depth: recv,
            max_jfs_sge: 1,
            max_jfs_rsge: 1,
            max_jfr_sge: 1,
            max_msg_size: u64::MAX,
            max_read_size: 0,
            max_write_size: 0,
        }
    }

    #[test]
    fn runtime_config_keeps_device_selection_and_m1_defaults() {
        let config = RuntimeConfig::new("urma0", 2);
        assert_eq!(config.device_name, "urma0");
        assert_eq!(config.eid_index, 2);
        assert_eq!(config.send_jfc_depth, 4096);
        assert_eq!(config.recv_jfc_depth, 4096);
        assert_eq!(config.tp_type, crate::urma::TpType::Rtp);
        assert_eq!(config.buffer_pool, BufferPoolConfig::default());
        assert_eq!(config.buffer_pool.total_len().unwrap(), 40 * 1024 * 1024);
    }

    #[test]
    fn registered_budget_preserves_tx_and_rx_guarantees() {
        let config = RuntimeConfig::new("urma0", 0)
            .with_registered_budget(20 * 1024 * 1024, 4 * 1024 * 1024)
            .unwrap();
        assert_eq!(config.buffer_pool.tx_slot_count, 64);
        assert_eq!(config.buffer_pool.rx_slot_count, 256);
        assert_eq!(config.buffer_pool.total_len().unwrap(), 20 * 1024 * 1024);
    }

    #[test]
    fn registered_budget_requires_both_direction_reserves() {
        assert!(RuntimeConfig::new("urma0", 0)
            .with_registered_budget(64 * 1024, 64 * 1024)
            .is_err());
        assert!(RuntimeConfig::new("urma0", 0)
            .with_registered_budget(128 * 1024, 0)
            .is_err());
    }

    #[test]
    fn advertised_message_size_is_capped_by_registered_slot() {
        assert_eq!(
            effective_max_message_size(4 * 1024 * 1024, 64 * 1024).unwrap(),
            64 * 1024
        );
    }

    #[test]
    fn shared_endpoint_depth_is_process_owned_not_peer_configured() {
        let mut runtime = RuntimeConfig::new("urma0", 0);
        runtime.send_jfc_depth = 96;
        runtime.recv_jfc_depth = 384;
        runtime.buffer_pool.tx_slot_count = 64;
        runtime.buffer_pool.rx_slot_count = 256;

        let endpoint = shared_endpoint_config(&runtime, &capability_for_depths(80, 300));
        assert_eq!(endpoint.send_depth, 64);
        assert_eq!(endpoint.recv_depth, 256);
        assert_eq!(endpoint.max_send_sge, 1);
        assert_eq!(endpoint.max_recv_sge, 1);
        assert_eq!(endpoint.tp_type, crate::urma::TpType::Rtp);
    }

    #[test]
    fn shared_endpoint_uses_selected_ctp_type() {
        let runtime = RuntimeConfig::new("urma0", 0).with_tp_type(crate::urma::TpType::Ctp);
        let endpoint = shared_endpoint_config(&runtime, &capability_for_depths(8, 8));
        assert_eq!(endpoint.tp_type, crate::urma::TpType::Ctp);
    }

    #[test]
    fn read_only_mode_reserves_full_jfs_depth_and_changes_shared_identity() {
        use crate::urma::read_owner::{ReadBudget, ReadCapacity};
        let cap = |bytes, entries| ReadCapacity { bytes, entries };
        let read = ReadRuntimeConfig {
            budget: ReadBudget {
                total: cap(64 * 1024 * 1024, 8),
                source: cap(32 * 1024 * 1024, 4),
                destination: cap(32 * 1024 * 1024, 4),
                per_peer_source: cap(16 * 1024 * 1024, 2),
                per_peer_destination: cap(16 * 1024 * 1024, 2),
                quarantine: cap(16 * 1024 * 1024, 2),
            },
            max_outstanding_per_peer: 8,
            buffer_alignment: 4096,
        };
        let mut legacy = RuntimeConfig::new("urma0", 0);
        legacy.send_jfc_depth = 96;
        legacy.buffer_pool.tx_slot_count = 4;
        let read_only = legacy.clone().with_read_only(read);
        let capability = capability_for_depths(80, 8);
        assert_eq!(shared_endpoint_config(&legacy, &capability).send_depth, 4);
        assert_eq!(
            shared_endpoint_config(&read_only, &capability).send_depth,
            80
        );
        assert_ne!(legacy, read_only);
    }

    #[test]
    fn peer_ids_reuse_only_after_release_and_advance_generation() {
        let mut ids = native::PeerIdAllocator::new();
        let first = ids.allocate().unwrap();
        let second = ids.allocate().unwrap();
        assert_eq!(first, (1, 1));
        assert_eq!(second, (2, 1));

        ids.release(first.0);
        assert_eq!(ids.allocate().unwrap(), (1, 2));
        assert_eq!(ids.allocate().unwrap(), (3, 1));
    }

    #[test]
    fn peer_id_allocator_includes_u16_max_before_exhaustion() {
        let mut ids = native::PeerIdAllocator::new();
        let mut last = (0, 0);
        for _ in 0..u32::from(u16::MAX) {
            last = ids.allocate().unwrap();
        }
        assert_eq!(last, (u16::MAX, 1));
        assert!(ids.allocate().is_err());
    }
}
