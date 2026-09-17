use super::{
    buffer::{SlotId, SlotKind, TxWindowLease, UrmaBufferPool},
    completion::{
        CompletionRouter, RegisteredRxCompletionTx, RegisteredTxCompletionTx,
        RegisteredTxWindowState,
    },
    ffi, native_error,
    runtime::UrmaDeviceCapability,
    Error, Result,
};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u32)]
pub enum TransportMode {
    #[default]
    Rm = 1,
}

impl TransportMode {
    pub(crate) fn wire_value(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_wire(value: u8) -> std::result::Result<Self, String> {
        match value {
            1 => Ok(Self::Rm),
            _ => Err(format!("invalid URMA transport mode {value}")),
        }
    }
}

/// Provider transport-path type used by an RM Jetty.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u32)]
pub enum TpType {
    #[default]
    Rtp = 0,
    Ctp = 1,
}

impl TpType {
    pub(crate) fn wire_value(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_wire(value: u8) -> std::result::Result<Self, String> {
        match value {
            0 => Ok(Self::Rtp),
            1 => Ok(Self::Ctp),
            _ => Err(format!("invalid URMA TP type {value}")),
        }
    }

    fn ffi_value(self) -> u32 {
        match self {
            Self::Rtp => ffi::TP_RTP,
            Self::Ctp => ffi::TP_CTP,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum OperationType {
    Send = 1,
    Recv = 2,
}

impl TryFrom<u8> for OperationType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Send),
            2 => Ok(Self::Recv),
            _ => Err(Error::Protocol(format!(
                "invalid WR operation type {value}"
            ))),
        }
    }
}

/// Pointer-free user_ctx encoding:
/// `[owner:16][generation:8][operation:8][slot-generation:16|slot-index:16]`.
/// SEND uses its PeerTarget id as owner; shared-JFR RECV uses owner zero and
/// learns the logical PeerTarget from completion remote_id + routing token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WrToken {
    pub(crate) peer_id: u16,
    pub(crate) generation: u8,
    pub(crate) operation: OperationType,
    pub(crate) slot: SlotId,
}

impl WrToken {
    pub(crate) fn anonymous_recv(slot: SlotId) -> Self {
        Self {
            peer_id: 0,
            generation: 1,
            operation: OperationType::Recv,
            slot,
        }
    }

    pub(crate) fn encode(self) -> Result<u64> {
        if self.generation == 0 || (self.peer_id == 0 && self.operation != OperationType::Recv) {
            return Err(Error::InvalidConfiguration("WR identity is invalid".into()));
        }
        Ok((u64::from(self.peer_id) << 48)
            | (u64::from(self.generation) << 40)
            | (u64::from(self.operation as u8) << 32)
            | u64::from(self.slot.encode()))
    }

    pub(crate) fn decode(value: u64) -> Result<Self> {
        let peer_id = (value >> 48) as u16;
        let generation = ((value >> 40) & 0xff) as u8;
        let operation = OperationType::try_from(((value >> 32) & 0xff) as u8)?;
        if generation == 0 || (peer_id == 0 && operation != OperationType::Recv) {
            return Err(Error::Protocol("CQE user_ctx has a zero identity".into()));
        }
        Ok(Self {
            peer_id,
            generation,
            operation,
            slot: SlotId::decode((value & 0xffff_ffff) as u32)?,
        })
    }
}

#[derive(Default)]
struct PeerSendCredits {
    remote_receives_available: usize,
}

impl PeerSendCredits {
    fn grant_remote_receives(&mut self, count: u32) -> Result<()> {
        if count == 0 {
            return Err(Error::Protocol(
                "remote receive credit grant must be non-zero".into(),
            ));
        }
        let count = usize::try_from(count)
            .map_err(|_| Error::Protocol("remote receive credit does not fit usize".into()))?;
        self.remote_receives_available = self
            .remote_receives_available
            .checked_add(count)
            .ok_or_else(|| Error::Protocol("remote receive credit overflow".into()))?;
        Ok(())
    }

    fn require_remote_receives(&self, count: usize) -> Result<()> {
        if self.remote_receives_available < count {
            return Err(Error::Protocol(format!(
                "SEND window requires {count} receive credits, only {} available",
                self.remote_receives_available
            )));
        }
        Ok(())
    }

    fn consume_remote_receives(&mut self, count: usize) {
        debug_assert!(self.remote_receives_available >= count);
        self.remote_receives_available -= count;
    }

    fn clear(&mut self) {
        self.remote_receives_available = 0;
    }
}

const JETTY_DESCRIPTOR_VERSION: u16 = 2;
const MAX_JETTY_DESCRIPTOR_LEN: usize = 64 * 1024;

/// Stable wire DTO around provider-owned remote-Jetty bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JettyDescriptor {
    pub(crate) version: u16,
    pub(crate) transport_type: u32,
    pub(crate) tp_type: TpType,
    pub(crate) eid_index: u32,
    pub(crate) jetty_id: u32,
    pub(crate) opaque_len: u32,
    pub(crate) opaque_data: Vec<u8>,
}

impl JettyDescriptor {
    const FIXED_LEN: usize = 2 + 4 + 1 + 4 + 4 + 4;

    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != JETTY_DESCRIPTOR_VERSION {
            return Err(Error::Protocol(format!(
                "unsupported Jetty descriptor version {}",
                self.version
            )));
        }
        let declared = usize::try_from(self.opaque_len)
            .map_err(|_| Error::Protocol("descriptor length does not fit usize".into()))?;
        if declared == 0 || declared != self.opaque_data.len() {
            return Err(Error::Protocol(
                "descriptor opaque_len does not match opaque_data".into(),
            ));
        }
        if declared > MAX_JETTY_DESCRIPTOR_LEN {
            return Err(Error::Protocol(format!(
                "descriptor length {declared} exceeds {MAX_JETTY_DESCRIPTOR_LEN}"
            )));
        }
        Ok(())
    }

    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(Self::FIXED_LEN + self.opaque_data.len());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.transport_type.to_be_bytes());
        out.push(self.tp_type.wire_value());
        out.extend_from_slice(&self.eid_index.to_be_bytes());
        out.extend_from_slice(&self.jetty_id.to_be_bytes());
        out.extend_from_slice(&self.opaque_len.to_be_bytes());
        out.extend_from_slice(&self.opaque_data);
        Ok(out)
    }

    pub(crate) fn deserialize(input: &[u8]) -> Result<Self> {
        if input.len() < Self::FIXED_LEN {
            return Err(Error::Protocol("truncated Jetty descriptor".into()));
        }
        let descriptor = Self {
            version: u16::from_be_bytes([input[0], input[1]]),
            transport_type: u32::from_be_bytes(input[2..6].try_into().expect("fixed slice")),
            tp_type: TpType::from_wire(input[6]).map_err(Error::Protocol)?,
            eid_index: u32::from_be_bytes(input[7..11].try_into().expect("fixed slice")),
            jetty_id: u32::from_be_bytes(input[11..15].try_into().expect("fixed slice")),
            opaque_len: u32::from_be_bytes(input[15..19].try_into().expect("fixed slice")),
            opaque_data: input[Self::FIXED_LEN..].to_vec(),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn from_ffi(raw: ffi::JettyDescriptorData) -> Result<Self> {
        let opaque_len = u32::try_from(raw.opaque_data.len())
            .map_err(|_| Error::Protocol("native descriptor exceeds u32".into()))?;
        let descriptor = Self {
            version: JETTY_DESCRIPTOR_VERSION,
            transport_type: raw.transport_type,
            tp_type: TpType::from_wire(
                u8::try_from(raw.tp_type)
                    .map_err(|_| Error::Protocol("native TP type exceeds u8".into()))?,
            )
            .map_err(Error::Protocol)?,
            eid_index: raw.eid_index,
            jetty_id: raw.jetty_id,
            opaque_len,
            opaque_data: raw.opaque_data,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn to_ffi(&self) -> Result<ffi::JettyDescriptorData> {
        self.validate()?;
        Ok(ffi::JettyDescriptorData {
            transport_type: self.transport_type,
            tp_type: self.tp_type.ffi_value(),
            eid_index: self.eid_index,
            jetty_id: self.jetty_id,
            opaque_data: self.opaque_data.clone(),
        })
    }
}

/// Native sizing and import token for the one process-shared RM endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JettyConfig {
    pub(crate) send_depth: u32,
    pub(crate) recv_depth: u32,
    pub(crate) max_send_sge: u32,
    pub(crate) max_recv_sge: u32,
    pub(crate) token: u32,
    pub(crate) tp_type: TpType,
}

impl Default for JettyConfig {
    fn default() -> Self {
        Self {
            send_depth: 128,
            recv_depth: 512,
            max_send_sge: 1,
            max_recv_sge: 1,
            token: 0,
            tp_type: TpType::default(),
        }
    }
}

/// Safe owner of the process-shared RM Jetty. The Jetty itself owns no
/// remote targets: every peer imports its own `TargetHandle` into this Jetty,
/// and SEND posts must name that target explicitly. This is the single
/// native data-plane endpoint shared by every PeerTarget.
pub(crate) struct UrmaJetty {
    handle: Rc<RefCell<ffi::JettyHandle>>,
    local_jetty_id: u32,
    local_jfr_id: u32,
    token: u32,
    tp_type: TpType,
}

impl UrmaJetty {
    pub(crate) fn create(
        runtime: &mut ffi::NativeRuntime,
        send_jfc: &ffi::JfcHandle,
        recv_jfc: &ffi::JfcHandle,
        config: &JettyConfig,
    ) -> Result<Self> {
        let ffi_config = ffi::JettyConfig {
            send_depth: config.send_depth,
            recv_depth: config.recv_depth,
            max_send_sge: config.max_send_sge,
            max_recv_sge: config.max_recv_sge,
            token: config.token,
            tp_type: config.tp_type.ffi_value(),
        };
        let handle = ffi::JettyHandle::create(runtime, send_jfc, recv_jfc, &ffi_config)
            .map_err(|error| native_error("create_jetty", error))?;
        let (local_jetty_id, local_jfr_id) = handle
            .local_ids()
            .map_err(|error| native_error("query_jetty_local_ids", error))?;
        Ok(Self {
            handle: Rc::new(RefCell::new(handle)),
            local_jetty_id,
            local_jfr_id,
            token: config.token,
            tp_type: config.tp_type,
        })
    }

    pub(crate) fn export_descriptor(&self) -> Result<JettyDescriptor> {
        let handle = self
            .handle
            .try_borrow()
            .map_err(|_| Error::Protocol("shared RM Jetty is busy".into()))?;
        let raw = handle
            .export_descriptor()
            .map_err(|error| native_error("get_rjetty", error))?;
        JettyDescriptor::from_ffi(raw)
    }

    /// Imports one remote Jetty identity as an independent target owned by
    /// the caller (one `TargetHandle` per PeerTarget).
    pub(crate) fn import_target(
        &mut self,
        descriptor: &JettyDescriptor,
    ) -> Result<Rc<ffi::TargetHandle>> {
        if descriptor.tp_type != self.tp_type {
            return Err(Error::Protocol(format!(
                "remote Jetty TP type {:?} does not match local {:?}",
                descriptor.tp_type, self.tp_type
            )));
        }
        self.handle
            .try_borrow_mut()
            .map_err(|_| Error::Protocol("shared RM Jetty is busy".into()))?
            .import_target(&descriptor.to_ffi()?, self.token)
            .map_err(|error| {
                Error::Protocol(format!(
                    "import_jetty failed: tp_type={:?} transport_type={} local_jetty_id={} local_jfr_id={} remote_eid_index={} remote_jetty_id={} native={}",
                    self.tp_type,
                    descriptor.transport_type,
                    self.local_jetty_id,
                    self.local_jfr_id,
                    descriptor.eid_index,
                    descriptor.jetty_id,
                    native_error("import_jetty", error)
                ))
            })
            .map(Rc::new)
    }

    pub(crate) fn mark_error(&mut self) -> Result<()> {
        self.handle
            .try_borrow_mut()
            .map_err(|_| Error::Protocol("shared RM Jetty is busy".into()))?
            .mark_error()
            .map_err(|error| native_error("modify_jetty_error", error))
    }

    pub(crate) fn local_ids(&self) -> (u32, u32) {
        (self.local_jetty_id, self.local_jfr_id)
    }

    /// Shared native identity retained by READ owners. Runtime shutdown must
    /// drain every clone before closing the JFCs and native context.
    #[allow(dead_code)] // Used by the gated production READ command factory.
    pub(crate) fn read_handle(&self) -> Rc<RefCell<ffi::JettyHandle>> {
        self.handle.clone()
    }

    pub(crate) fn post_send_imm(
        &mut self,
        target: &ffi::TargetHandle,
        segment: &ffi::SegmentHandle,
        offset: u64,
        length: u32,
        user_ctx: u64,
        imm_data: u64,
    ) -> Result<ffi::WrHandle> {
        self.handle
            .try_borrow_mut()
            .map_err(|_| Error::Protocol("shared RM Jetty is busy".into()))?
            .post_send_imm(target, segment, offset, length, user_ctx, imm_data)
            .map_err(|error| native_error("post_jetty_send_imm_wr", error))
    }

    fn post_recv(
        &mut self,
        segment: &ffi::SegmentHandle,
        offset: u64,
        length: u32,
        user_ctx: u64,
    ) -> Result<ffi::WrHandle> {
        self.handle
            .try_borrow_mut()
            .map_err(|_| Error::Protocol("shared RM Jetty is busy".into()))?
            .post_recv(segment, offset, length, user_ctx)
            .map_err(|error| native_error("post_jetty_recv_wr", error))
    }

    pub(crate) fn post_send_batch(
        &mut self,
        target: &ffi::TargetHandle,
        segment: &ffi::SegmentHandle,
        entries: &[ffi::PostEntry],
    ) -> Result<ffi::PostBatch> {
        if let [entry] = entries {
            let imm_data = entry.imm_data.ok_or_else(|| {
                Error::InvalidConfiguration("registered TX entry lacks SEND_IMM identity".into())
            })?;
            return Ok(ffi::PostBatch {
                handles: vec![self.post_send_imm(
                    target,
                    segment,
                    entry.offset,
                    entry.length,
                    entry.user_ctx,
                    imm_data,
                )?],
                error: None,
            });
        }
        self.handle
            .try_borrow_mut()
            .map_err(|_| Error::Protocol("shared RM Jetty is busy".into()))?
            .post_send_imm_list(target, segment, entries)
            .map_err(|error| native_error("post_jetty_send_imm_wr_list", error))
    }

    fn post_recv_batch(
        &mut self,
        segment: &ffi::SegmentHandle,
        entries: &[ffi::PostEntry],
    ) -> Result<ffi::PostBatch> {
        if let [entry] = entries {
            return Ok(ffi::PostBatch {
                handles: vec![self.post_recv(
                    segment,
                    entry.offset,
                    entry.length,
                    entry.user_ctx,
                )?],
                error: None,
            });
        }
        self.handle
            .try_borrow_mut()
            .map_err(|_| Error::Protocol("shared RM Jetty is busy".into()))?
            .post_recv_list(segment, entries)
            .map_err(|error| native_error("post_jetty_recv_wr_list", error))
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if Rc::strong_count(&self.handle) != 1 {
            failures.push("shared RM Jetty is still retained by READ owners".into());
        } else {
            match self.handle.try_borrow_mut() {
                Ok(mut handle) => {
                    if let Err(error) = handle.close() {
                        failures.push(native_error("delete_jetty", error).to_string());
                    }
                }
                Err(_) => failures.push("shared RM Jetty is busy during close".into()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::Shutdown { failures })
        }
    }
}

impl Drop for UrmaJetty {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Lifecycle of one PeerTarget on the shared RM endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerTargetLifecycle {
    Created,
    Ready,
    Draining,
    Failed,
    Closed,
}

/// An owned PeerTarget. The native Jetty/JFR live in the Runtime's shared
/// endpoint and are borrowed only for individual posts; a PeerTarget owns
/// only its imported target identity, logical credits, and lifecycle state.
pub(crate) struct PeerTarget {
    id: u16,
    generation: u8,
    state: PeerTargetLifecycle,
    capability: UrmaDeviceCapability,
    target: Option<Rc<ffi::TargetHandle>>,
    credits: PeerSendCredits,
    post_list_size: usize,
    retirement_armed: bool,
}

impl PeerTarget {
    pub(crate) fn new(
        id: u16,
        generation: u8,
        capability: UrmaDeviceCapability,
        post_list_size: u32,
    ) -> Result<Self> {
        if id == 0 || generation == 0 {
            return Err(Error::InvalidConfiguration(
                "PeerTarget id and generation must be non-zero".into(),
            ));
        }
        Ok(Self {
            id,
            generation,
            state: PeerTargetLifecycle::Created,
            capability,
            target: None,
            credits: PeerSendCredits::default(),
            post_list_size: post_list_size as usize,
            retirement_armed: false,
        })
    }

    pub(crate) fn generation(&self) -> u8 {
        self.generation
    }

    /// Imports the remote Jetty descriptor as this PeerTarget's own target on
    /// the shared endpoint and moves the PeerTarget to Ready.
    pub(crate) fn import_remote(
        &mut self,
        jetty: &mut UrmaJetty,
        descriptor: &JettyDescriptor,
    ) -> Result<()> {
        if self.state != PeerTargetLifecycle::Created {
            return Err(self.state_error("import descriptor"));
        }
        let local_transport = u32::try_from(self.capability.transport_type)
            .map_err(|_| Error::Protocol("local transport type is negative".into()))?;
        if descriptor.transport_type != local_transport {
            return Err(Error::Protocol(format!(
                "remote transport type {} does not match local {}",
                descriptor.transport_type, local_transport
            )));
        }
        self.target = Some(jetty.import_target(descriptor)?);
        self.state = PeerTargetLifecycle::Ready;
        Ok(())
    }

    pub(crate) fn remote_id(&self) -> Result<ffi::RemoteJettyId> {
        self.target
            .as_ref()
            .ok_or_else(|| Error::Protocol("RM target is not imported".into()))?
            .remote_id()
            .map_err(|error| native_error("query_remote_jetty_id", error))
    }

    /// Retains the imported target while a READ import/WR can still refer to
    /// it. Peer retirement refuses to unimport until every clone is gone.
    #[allow(dead_code)] // Used by the gated production READ command factory.
    pub(crate) fn read_target(&self) -> Result<Rc<ffi::TargetHandle>> {
        self.require(PeerTargetLifecycle::Ready)?;
        self.target
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::Protocol("RM target is not imported".into()))
    }

    pub(crate) fn grant_send_credit(&mut self, count: u32) -> Result<()> {
        self.require(PeerTargetLifecycle::Ready)?;
        self.credits.grant_remote_receives(count)
    }

    pub(crate) fn post_receive_window_registered(
        &mut self,
        jetty: &mut UrmaJetty,
        shared_recv_depth: usize,
        pool: &mut UrmaBufferPool,
        completions: &mut CompletionRouter,
        sequences: Vec<u64>,
        completion_txs: Vec<RegisteredRxCompletionTx>,
    ) -> Result<()> {
        self.require(PeerTargetLifecycle::Ready)?;
        if sequences.is_empty() || sequences.len() != completion_txs.len() {
            return Err(Error::InvalidConfiguration(
                "registered RX window requires matching non-empty sequences and completions".into(),
            ));
        }
        // Reject duplicate logical ownership before any native WR is posted.
        // The owner thread cannot poll while this command is running, so the
        // preflight remains valid until the complete window is registered.
        completions.validate_registered_rx_identities(self.id, &sequences)?;
        // Peer retirement can leave endpoint-owned anonymous RQEs without
        // logical waiters. Reuse those first; only the deficit consumes new
        // JFR depth and registered RX slots.
        let reusable = completions.unassigned_recv_capacity()?.min(sequences.len());
        let post_count = sequences.len() - reusable;
        completions.ensure_recv_capacity(post_count, shared_recv_depth)?;
        let slots = if post_count == 0 {
            Vec::new()
        } else {
            pool.allocate_rx_window(post_count)?
        };
        let mut pending: Vec<_> = slots
            .into_iter()
            .zip(sequences.iter().copied().skip(reusable))
            .collect();
        while !pending.is_empty() {
            let batch_len = self.post_list_size.min(pending.len());
            let batch: Vec<_> = pending.drain(..batch_len).collect();
            let mut entries = Vec::with_capacity(batch_len);
            let prepare = (|| {
                for (slot, _) in &batch {
                    let (offset, length) = pool.recv_post_layout(*slot)?;
                    // Shared-JFR receive slots have no PeerTarget owner until
                    // the CQE supplies remote_id plus the routing token.
                    let user_ctx = WrToken::anonymous_recv(*slot).encode()?;
                    pool.mark_posted(*slot, SlotKind::Rx)?;
                    entries.push(ffi::PostEntry {
                        offset,
                        length,
                        user_ctx,
                        imm_data: None,
                    });
                }
                Ok(())
            })();
            if let Err(error) = prepare {
                for (slot, _) in batch.iter().take(entries.len()) {
                    pool.rollback_post(*slot, SlotKind::Rx)?;
                }
                pool.release_unposted_rx_window(
                    batch
                        .into_iter()
                        .map(|(slot, _)| slot)
                        .chain(pending.into_iter().map(|(slot, _)| slot))
                        .collect(),
                )?;
                return Err(error);
            }
            for (index, entry) in entries.iter().enumerate() {
                if let Err(error) =
                    completions.reserve_anonymous_rx(entry.user_ctx, Some(batch[index].1))
                {
                    for reserved_entry in entries.iter().take(index) {
                        completions.cancel_reservation(reserved_entry.user_ctx)?;
                    }
                    for (slot, _) in &batch {
                        pool.rollback_post(*slot, SlotKind::Rx)?;
                    }
                    pool.release_unposted_rx_window(
                        batch
                            .into_iter()
                            .map(|(slot, _)| slot)
                            .chain(pending.into_iter().map(|(slot, _)| slot))
                            .collect(),
                    )?;
                    return Err(error);
                }
            }
            let posted = match jetty.post_recv_batch(pool.segment_handle()?, &entries) {
                Ok(posted) => posted,
                Err(error) => {
                    for entry in &entries {
                        completions.cancel_reservation(entry.user_ctx)?;
                    }
                    for (slot, _) in &batch {
                        pool.rollback_post(*slot, SlotKind::Rx)?;
                    }
                    pool.release_unposted_rx_window(
                        batch
                            .into_iter()
                            .map(|(slot, _)| slot)
                            .chain(pending.into_iter().map(|(slot, _)| slot))
                            .collect(),
                    )?;
                    return Err(error);
                }
            };
            let posted_len = posted.handles.len();
            let mut handles = posted.handles.into_iter();
            let first_error = posted
                .error
                .map(|error| native_error("post_jetty_recv_wr_list", error));
            for (index, (slot, _sequence)) in batch.into_iter().enumerate() {
                if index < posted_len {
                    let wr = handles.next().expect("posted prefix handle count matches");
                    completions.commit_posted(entries[index].user_ctx, wr);
                } else {
                    completions.cancel_reservation(entries[index].user_ctx)?;
                    pool.rollback_post(slot, SlotKind::Rx)?;
                    pool.release(slot)?;
                }
            }
            if let Some(error) = first_error {
                pool.release_unposted_rx_window(
                    pending.into_iter().map(|(slot, _)| slot).collect(),
                )?;
                return Err(error);
            }
        }
        completions.register_rx_window(self.id, sequences, completion_txs)
    }

    pub(crate) fn send_registered_window(
        &mut self,
        jetty: &mut UrmaJetty,
        pool: &mut UrmaBufferPool,
        completions: &mut CompletionRouter,
        lease: TxWindowLease,
        sequences: Vec<u64>,
        completion: RegisteredTxCompletionTx,
    ) -> Result<()> {
        self.require(PeerTargetLifecycle::Ready)?;
        if sequences.len() != lease.chunk_count() || sequences.is_empty() {
            return Err(Error::InvalidConfiguration(
                "registered TX window requires one sequence per chunk".into(),
            ));
        }
        // Validate the logical PeerTarget immediately before touching native
        // TX ownership. This rejects both retirement races and stale target
        // generations on the shared RM endpoint.
        completions.validate_send_owner(self.id, self.generation)?;
        self.credits.require_remote_receives(sequences.len())?;
        let layouts = pool.tx_lease_layouts(&lease)?;
        let state = RegisteredTxWindowState::new(self.id, sequences.clone(), lease, completion);

        let mut pending: Vec<_> = layouts.into_iter().zip(sequences).collect();
        while !pending.is_empty() {
            let batch_len = self.post_list_size.min(pending.len());
            let batch: Vec<_> = pending.drain(..batch_len).collect();
            let mut entries = Vec::with_capacity(batch_len);
            let prepare: Result<()> = (|| {
                for ((slot, offset, length), sequence) in &batch {
                    let user_ctx = self.token(OperationType::Send, *slot).encode()?;
                    pool.mark_tx_lease_posted(*slot)?;
                    entries.push(ffi::PostEntry {
                        offset: *offset,
                        length: *length,
                        user_ctx,
                        imm_data: Some(*sequence),
                    });
                }
                Ok(())
            })();
            if let Err(error) = prepare {
                for ((slot, _, _), _) in batch.iter().take(entries.len()) {
                    pool.rollback_tx_lease_post(*slot)?;
                }
                state.finish_posting(Some(error.clone()));
                return Err(error);
            }
            for (index, entry) in entries.iter().enumerate() {
                if let Err(error) =
                    completions.reserve_registered_tx(entry.user_ctx, batch[index].1, state.clone())
                {
                    for reserved_entry in entries.iter().take(index) {
                        completions.cancel_reservation(reserved_entry.user_ctx)?;
                    }
                    for ((slot, _, _), _) in &batch {
                        pool.rollback_tx_lease_post(*slot)?;
                    }
                    state.finish_posting(Some(error.clone()));
                    return Err(error);
                }
            }
            let posted = match jetty.post_send_batch(
                self.target
                    .as_ref()
                    .ok_or_else(|| Error::Protocol("RM target is not imported".into()))?,
                pool.segment_handle()?,
                &entries,
            ) {
                Ok(posted) => posted,
                Err(error) => {
                    for entry in &entries {
                        completions.cancel_reservation(entry.user_ctx)?;
                    }
                    for ((slot, _, _), _) in &batch {
                        pool.rollback_tx_lease_post(*slot)?;
                    }
                    state.finish_posting(Some(error.clone()));
                    return Err(error);
                }
            };
            let posted_len = posted.handles.len();
            self.credits.consume_remote_receives(posted_len);
            let mut handles = posted.handles.into_iter();
            let first_error = posted
                .error
                .map(|error| native_error("post_jetty_send_wr_list", error));
            for (index, ((slot, _, _), _sequence)) in batch.into_iter().enumerate() {
                if index < posted_len {
                    let wr = handles.next().expect("posted prefix handle count matches");
                    completions.commit_posted(entries[index].user_ctx, wr);
                } else {
                    completions.cancel_reservation(entries[index].user_ctx)?;
                    pool.rollback_tx_lease_post(slot)?;
                }
            }
            if let Some(error) = first_error {
                state.finish_posting(Some(error.clone()));
                return Err(error);
            }
        }
        state.finish_posting(None);
        Ok(())
    }

    pub(crate) fn begin_draining(&mut self) -> Result<()> {
        if self.state == PeerTargetLifecycle::Closed {
            return Ok(());
        }
        // The shared endpoint must stay healthy for the other PeerTargets, so
        // a single peer's retirement cannot call Jetty mark_error. Draining
        // only converges once this target's outstanding WRs complete on their
        // own; a peer that strands WRs requires the endpoint-level flush
        // escalation in Runtime shutdown (per-target flush is pending RM0).
        self.credits.clear();
        self.state = PeerTargetLifecycle::Draining;
        self.retirement_armed = true;
        Ok(())
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.state == PeerTargetLifecycle::Draining
    }

    pub(crate) fn is_retirement_armed(&self) -> bool {
        self.retirement_armed
    }

    pub(crate) fn close(&mut self, outstanding: usize) -> Result<()> {
        if self.state == PeerTargetLifecycle::Closed {
            return Ok(());
        }
        if outstanding != 0 {
            return Err(Error::Protocol(format!(
                "cannot close PeerTarget {} with {outstanding} outstanding WRs",
                self.id
            )));
        }
        let result = match self.target.as_mut() {
            Some(target) => match Rc::get_mut(target) {
                None => Err(Error::Protocol(format!(
                    "cannot close PeerTarget {} while READ owners retain it",
                    self.id
                ))),
                Some(target) => match target.close() {
                    Ok(()) => {
                        self.target = None;
                        Ok(())
                    }
                    Err(error) => Err(native_error("unimport_jetty", error)),
                },
            },
            None => Ok(()),
        };
        match result {
            Ok(()) => {
                self.credits.clear();
                self.state = PeerTargetLifecycle::Closed;
                Ok(())
            }
            Err(error) => {
                self.state = PeerTargetLifecycle::Failed;
                Err(error)
            }
        }
    }

    fn token(&self, operation: OperationType, slot: SlotId) -> WrToken {
        WrToken {
            peer_id: self.id,
            generation: self.generation,
            operation,
            slot,
        }
    }

    fn require(&self, expected: PeerTargetLifecycle) -> Result<()> {
        if self.state == expected {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "PeerTarget {} is {:?}, expected {:?}",
                self.id, self.state, expected
            )))
        }
    }

    fn state_error(&self, operation: &str) -> Error {
        Error::Protocol(format!(
            "cannot {operation} while PeerTarget {} is {:?}",
            self.id, self.state
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> UrmaDeviceCapability {
        UrmaDeviceCapability {
            transport_type: 0,
            transport_modes: TransportMode::Rm as u32,
            max_jfc: 2,
            max_jfs: 1,
            max_jfr: 1,
            max_jetty: 1,
            max_jfc_depth: 8,
            max_jfs_depth: 8,
            max_jfr_depth: 8,
            max_jfs_sge: 1,
            max_jfs_rsge: 1,
            max_jfr_sge: 1,
            max_msg_size: 64 * 1024,
            max_read_size: 0,
            max_write_size: 0,
        }
    }

    fn descriptor() -> JettyDescriptor {
        JettyDescriptor {
            version: JETTY_DESCRIPTOR_VERSION,
            transport_type: 0,
            tp_type: TpType::Rtp,
            eid_index: 3,
            jetty_id: 42,
            opaque_len: 4,
            opaque_data: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn descriptor_round_trip() {
        let descriptor = descriptor();
        let bytes = descriptor.serialize().unwrap();
        assert_eq!(JettyDescriptor::deserialize(&bytes), Ok(descriptor));
    }

    #[test]
    fn descriptor_rejects_invalid_version() {
        let mut descriptor = descriptor();
        descriptor.version += 1;
        assert!(descriptor.serialize().is_err());
    }

    #[test]
    fn descriptor_round_trips_ctp_and_rejects_unknown_tp_type() {
        let mut descriptor = descriptor();
        descriptor.tp_type = TpType::Ctp;
        let bytes = descriptor.serialize().unwrap();
        assert_eq!(JettyDescriptor::deserialize(&bytes), Ok(descriptor));

        let mut unknown = bytes;
        unknown[6] = 2;
        assert!(JettyDescriptor::deserialize(&unknown).is_err());
    }

    #[test]
    fn user_context_round_trip_is_pointer_free() {
        let token = WrToken {
            peer_id: 9,
            generation: 2,
            operation: OperationType::Recv,
            slot: SlotId::new(1234, 7).unwrap(),
        };
        assert_eq!(WrToken::decode(token.encode().unwrap()), Ok(token));
    }

    #[test]
    fn send_requires_remote_recv_posted_credit() {
        let mut credits = PeerSendCredits::default();
        assert!(credits.require_remote_receives(1).is_err());
        assert!(credits.grant_remote_receives(0).is_err());

        credits.grant_remote_receives(1).unwrap();
        assert!(credits.require_remote_receives(1).is_ok());
        credits.consume_remote_receives(1);
        assert!(credits.require_remote_receives(1).is_err());
    }

    #[test]
    fn partial_post_consumes_only_the_submitted_credit_prefix() {
        let mut credits = PeerSendCredits::default();
        credits.grant_remote_receives(5).unwrap();
        credits.consume_remote_receives(3);
        assert!(credits.require_remote_receives(2).is_ok());
        assert!(credits.require_remote_receives(3).is_err());
    }

    #[test]
    fn draining_peer_rejects_new_credit_and_requires_send_drain_before_close() {
        let mut peer = PeerTarget::new(7, 2, capability(), 1).unwrap();
        // Native import is independently covered at the FFI boundary. Set the
        // pure lifecycle state directly so this test needs no provider.
        peer.state = PeerTargetLifecycle::Ready;
        peer.grant_send_credit(2).unwrap();

        peer.begin_draining().unwrap();
        assert_eq!(peer.state, PeerTargetLifecycle::Draining);
        assert!(peer.grant_send_credit(1).is_err());
        assert!(peer.credits.require_remote_receives(1).is_err());
        assert!(peer.close(1).is_err());
        assert_eq!(peer.state, PeerTargetLifecycle::Draining);

        peer.close(0).unwrap();
        assert_eq!(peer.state, PeerTargetLifecycle::Closed);
        assert!(peer.grant_send_credit(1).is_err());
    }

    #[test]
    fn read_owners_hold_jetty_and_target_close_gates() {
        let handle = Rc::new(RefCell::new(ffi::JettyHandle::without_native()));
        let mut jetty = UrmaJetty {
            handle: handle.clone(),
            local_jetty_id: 7,
            local_jfr_id: 8,
            token: 0,
            tp_type: TpType::Rtp,
        };
        drop(handle);
        let read_jetty = jetty.read_handle();
        assert!(jetty.close().is_err());
        drop(read_jetty);
        jetty.close().unwrap();

        let mut peer = PeerTarget::new(7, 2, capability(), 1).unwrap();
        peer.target = Some(Rc::new(ffi::TargetHandle::without_native()));
        peer.state = PeerTargetLifecycle::Ready;
        let read_target = peer.read_target().unwrap();
        peer.begin_draining().unwrap();
        assert!(peer.close(0).is_err());
        assert_eq!(peer.state, PeerTargetLifecycle::Failed);
        drop(read_target);
        peer.close(0).unwrap();
        assert_eq!(peer.state, PeerTargetLifecycle::Closed);
    }
}
