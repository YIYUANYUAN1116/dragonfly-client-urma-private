use super::{
    buffer::{SlotId, SlotKind, UrmaBufferPool},
    completion::{CompletionRouter, OperationCompletionTx},
    ffi, native_error,
    runtime::UrmaDeviceCapability,
    Error, Result,
};

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
/// `[lane:16][generation:8][operation:8][slot-generation:16|slot-index:16]`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WrToken {
    pub(crate) lane_id: u16,
    pub(crate) generation: u8,
    pub(crate) operation: OperationType,
    pub(crate) slot: SlotId,
}

impl WrToken {
    pub(crate) fn encode(self) -> Result<u64> {
        if self.lane_id == 0 || self.generation == 0 {
            return Err(Error::InvalidConfiguration(
                "lane id and generation must be non-zero".into(),
            ));
        }
        Ok((u64::from(self.lane_id) << 48)
            | (u64::from(self.generation) << 40)
            | (u64::from(self.operation as u8) << 32)
            | u64::from(self.slot.encode()))
    }

    pub(crate) fn decode(value: u64) -> Result<Self> {
        let lane_id = (value >> 48) as u16;
        let generation = ((value >> 40) & 0xff) as u8;
        let operation = OperationType::try_from(((value >> 32) & 0xff) as u8)?;
        if lane_id == 0 || generation == 0 {
            return Err(Error::Protocol("CQE user_ctx has a zero identity".into()));
        }
        Ok(Self {
            lane_id,
            generation,
            operation,
            slot: SlotId::decode((value & 0xffff_ffff) as u32)?,
        })
    }
}

#[derive(Default)]
struct LaneCredits {
    remote_receives_available: usize,
}

impl LaneCredits {
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

    fn require_remote_receive(&self) -> Result<()> {
        if self.remote_receives_available == 0 {
            return Err(Error::Protocol(
                "SEND is forbidden until the peer grants RecvPosted credit".into(),
            ));
        }
        Ok(())
    }

    fn consume_remote_receive(&mut self) {
        debug_assert_ne!(self.remote_receives_available, 0);
        self.remote_receives_available -= 1;
    }
}

const JETTY_DESCRIPTOR_VERSION: u16 = 1;
const MAX_JETTY_DESCRIPTOR_LEN: usize = 64 * 1024;

/// Stable wire DTO around provider-owned remote-Jetty bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JettyDescriptor {
    pub(crate) version: u16,
    pub(crate) transport_type: u32,
    pub(crate) eid_index: u32,
    pub(crate) jetty_id: u32,
    pub(crate) opaque_len: u32,
    pub(crate) opaque_data: Vec<u8>,
}

impl JettyDescriptor {
    const FIXED_LEN: usize = 2 + 4 + 4 + 4 + 4;

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
            eid_index: u32::from_be_bytes(input[6..10].try_into().expect("fixed slice")),
            jetty_id: u32::from_be_bytes(input[10..14].try_into().expect("fixed slice")),
            opaque_len: u32::from_be_bytes(input[14..18].try_into().expect("fixed slice")),
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
            eid_index: self.eid_index,
            jetty_id: self.jetty_id,
            opaque_data: self.opaque_data.clone(),
        })
    }
}

/// RC Jetty sizing and import token used when a lane is created.
pub(crate) struct JettyConfig {
    pub(crate) send_depth: u32,
    pub(crate) recv_depth: u32,
    pub(crate) max_send_sge: u32,
    pub(crate) max_recv_sge: u32,
    pub(crate) token: u32,
}

impl Default for JettyConfig {
    fn default() -> Self {
        Self {
            send_depth: 128,
            recv_depth: 512,
            max_send_sge: 1,
            max_recv_sge: 1,
            token: 0,
        }
    }
}

/// Safe owner of a local Jetty and an optional imported/bound remote Jetty.
pub(crate) struct UrmaJetty {
    handle: ffi::JettyHandle,
    token: u32,
    imported: bool,
    bound: bool,
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
        };
        let handle = ffi::JettyHandle::create(runtime, send_jfc, recv_jfc, &ffi_config)
            .map_err(|error| native_error("create_jetty", error))?;
        Ok(Self {
            handle,
            token: config.token,
            imported: false,
            bound: false,
        })
    }

    fn export_descriptor(&self) -> Result<JettyDescriptor> {
        let raw = self
            .handle
            .export_descriptor()
            .map_err(|error| native_error("get_rjetty", error))?;
        JettyDescriptor::from_ffi(raw)
    }

    fn import(&mut self, descriptor: &JettyDescriptor) -> Result<()> {
        if self.imported {
            return Err(Error::Protocol("a remote Jetty is already imported".into()));
        }
        self.handle
            .import(&descriptor.to_ffi()?, self.token)
            .map_err(|error| native_error("import_jetty", error))?;
        self.imported = true;
        Ok(())
    }

    fn bind(&mut self) -> Result<()> {
        if !self.imported {
            return Err(Error::Protocol("bind requires an imported Jetty".into()));
        }
        self.handle
            .bind()
            .map_err(|error| native_error("bind_jetty", error))?;
        self.bound = true;
        Ok(())
    }

    fn mark_error(&mut self) -> Result<()> {
        self.handle
            .mark_error()
            .map_err(|error| native_error("modify_jetty_error", error))
    }

    fn post_send(
        &mut self,
        segment: &ffi::SegmentHandle,
        offset: u64,
        length: u32,
        user_ctx: u64,
    ) -> Result<ffi::WrHandle> {
        self.handle
            .post_send(segment, offset, length, user_ctx)
            .map_err(|error| native_error("post_jetty_send_wr", error))
    }

    fn post_recv(
        &mut self,
        segment: &ffi::SegmentHandle,
        offset: u64,
        length: u32,
        user_ctx: u64,
    ) -> Result<ffi::WrHandle> {
        self.handle
            .post_recv(segment, offset, length, user_ctx)
            .map_err(|error| native_error("post_jetty_recv_wr", error))
    }

    fn close(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if self.bound {
            match self.handle.unbind() {
                Ok(()) => self.bound = false,
                Err(error) => failures.push(native_error("unbind_jetty", error).to_string()),
            }
        }
        if self.imported && !self.bound {
            match self.handle.unimport() {
                Ok(()) => self.imported = false,
                Err(error) => failures.push(native_error("unimport_jetty", error).to_string()),
            }
        }
        if !self.bound && !self.imported {
            if let Err(error) = self.handle.close() {
                failures.push(native_error("delete_jetty", error).to_string());
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

/// Lifecycle of one peer-facing RC Jetty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaneState {
    JettyCreated,
    DescriptorExchanged,
    Bound,
    Ready,
    Draining,
    Failed,
    Closed,
}

/// An owned peer lane. Process-wide resources such as JFCs and registered
/// memory remain in the fabric owner and are borrowed only for individual
/// posts. This makes lanes storable beside those resources without a
/// self-referential Runtime/Lane graph.
pub(crate) struct UrmaLane {
    id: u16,
    generation: u8,
    state: LaneState,
    capability: UrmaDeviceCapability,
    jetty: UrmaJetty,
    credits: LaneCredits,
}

impl UrmaLane {
    pub(crate) fn new(
        id: u16,
        generation: u8,
        capability: UrmaDeviceCapability,
        jetty: UrmaJetty,
    ) -> Result<Self> {
        if id == 0 || generation == 0 {
            return Err(Error::InvalidConfiguration(
                "lane id and generation must be non-zero".into(),
            ));
        }
        Ok(Self {
            id,
            generation,
            state: LaneState::JettyCreated,
            capability,
            jetty,
            credits: LaneCredits::default(),
        })
    }

    pub(crate) fn id(&self) -> u16 {
        self.id
    }

    pub(crate) fn export_descriptor(&mut self) -> Result<JettyDescriptor> {
        if !matches!(
            self.state,
            LaneState::JettyCreated | LaneState::DescriptorExchanged
        ) {
            return Err(self.state_error("export descriptor"));
        }
        let descriptor = self.jetty.export_descriptor()?;
        self.state = LaneState::DescriptorExchanged;
        Ok(descriptor)
    }

    pub(crate) fn import_and_bind(&mut self, descriptor: &JettyDescriptor) -> Result<()> {
        if !matches!(
            self.state,
            LaneState::JettyCreated | LaneState::DescriptorExchanged
        ) {
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
        self.state = LaneState::DescriptorExchanged;
        self.jetty.import(descriptor)?;
        self.jetty.bind()?;
        self.state = LaneState::Bound;
        Ok(())
    }

    pub(crate) fn mark_ready(&mut self) -> Result<()> {
        self.require(LaneState::Bound)?;
        self.state = LaneState::Ready;
        Ok(())
    }

    pub(crate) fn grant_send_credit(&mut self, count: u32) -> Result<()> {
        self.require(LaneState::Ready)?;
        self.credits.grant_remote_receives(count)
    }

    pub(crate) fn post_receive(
        &mut self,
        pool: &mut UrmaBufferPool,
        completions: &mut CompletionRouter,
        sequence: Option<u64>,
        completion: OperationCompletionTx,
    ) -> Result<()> {
        if !matches!(self.state, LaneState::Bound | LaneState::Ready) {
            return Err(self.state_error("post receive"));
        }
        let slot = pool
            .allocate(SlotKind::Rx)
            .ok_or_else(|| Error::InvalidConfiguration("no free RX slot".into()))?;
        let (offset, length) = pool.recv_post_layout(slot)?;
        let user_ctx = self.token(OperationType::Recv, slot).encode()?;
        pool.mark_posted(slot, SlotKind::Rx)?;
        let wr = match self
            .jetty
            .post_recv(pool.segment_handle()?, offset, length, user_ctx)
        {
            Ok(wr) => wr,
            Err(error) => {
                pool.rollback_post(slot, SlotKind::Rx)?;
                pool.release(slot)?;
                return Err(error);
            }
        };
        completions.track(user_ctx, wr, sequence, completion)
    }

    pub(crate) fn send(
        &mut self,
        pool: &mut UrmaBufferPool,
        completions: &mut CompletionRouter,
        bytes: &[u8],
        sequence: Option<u64>,
        completion: OperationCompletionTx,
    ) -> Result<()> {
        self.require(LaneState::Ready)?;
        self.credits.require_remote_receive()?;
        let slot = pool
            .allocate(SlotKind::Tx)
            .ok_or_else(|| Error::InvalidConfiguration("no free TX slot".into()))?;
        let (offset, length) = match pool.write_tx(slot, bytes) {
            Ok(layout) => layout,
            Err(error) => {
                pool.release(slot)?;
                return Err(error);
            }
        };
        let user_ctx = match self.token(OperationType::Send, slot).encode() {
            Ok(user_ctx) => user_ctx,
            Err(error) => {
                pool.release(slot)?;
                return Err(error);
            }
        };
        pool.mark_posted(slot, SlotKind::Tx)?;
        let wr = match self
            .jetty
            .post_send(pool.segment_handle()?, offset, length, user_ctx)
        {
            Ok(wr) => wr,
            Err(error) => {
                pool.rollback_post(slot, SlotKind::Tx)?;
                pool.release(slot)?;
                return Err(error);
            }
        };
        self.credits.consume_remote_receive();
        completions.track(user_ctx, wr, sequence, completion)
    }

    pub(crate) fn begin_draining(&mut self) -> Result<()> {
        if matches!(self.state, LaneState::Draining | LaneState::Closed) {
            return Ok(());
        }
        self.state = LaneState::Draining;
        self.jetty.mark_error()
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.state == LaneState::Draining
    }

    pub(crate) fn close(&mut self, outstanding: usize) -> Result<()> {
        if self.state == LaneState::Closed {
            return Ok(());
        }
        if outstanding != 0 {
            return Err(Error::Protocol(format!(
                "cannot close lane {} with {outstanding} outstanding WRs",
                self.id
            )));
        }
        match self.jetty.close() {
            Ok(()) => {
                self.state = LaneState::Closed;
                Ok(())
            }
            Err(error) => {
                self.state = LaneState::Failed;
                Err(error)
            }
        }
    }

    fn token(&self, operation: OperationType, slot: SlotId) -> WrToken {
        WrToken {
            lane_id: self.id,
            generation: self.generation,
            operation,
            slot,
        }
    }

    fn require(&self, expected: LaneState) -> Result<()> {
        if self.state == expected {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "lane {} is {:?}, expected {:?}",
                self.id, self.state, expected
            )))
        }
    }

    fn state_error(&self, operation: &str) -> Error {
        Error::Protocol(format!(
            "cannot {operation} while lane {} is {:?}",
            self.id, self.state
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> JettyDescriptor {
        JettyDescriptor {
            version: JETTY_DESCRIPTOR_VERSION,
            transport_type: 0,
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
    fn user_context_round_trip_is_pointer_free() {
        let token = WrToken {
            lane_id: 9,
            generation: 2,
            operation: OperationType::Recv,
            slot: SlotId::new(1234, 7).unwrap(),
        };
        assert_eq!(WrToken::decode(token.encode().unwrap()), Ok(token));
    }

    #[test]
    fn send_requires_remote_recv_posted_credit() {
        let mut credits = LaneCredits::default();
        assert!(credits.require_remote_receive().is_err());
        assert!(credits.grant_remote_receives(0).is_err());

        credits.grant_remote_receives(1).unwrap();
        assert!(credits.require_remote_receive().is_ok());
        credits.consume_remote_receive();
        assert!(credits.require_remote_receive().is_err());
    }
}
