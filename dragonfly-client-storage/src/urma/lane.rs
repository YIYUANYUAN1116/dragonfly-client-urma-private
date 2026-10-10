use super::{ffi, native_error, runtime::UrmaDeviceCapability, Error, Result};
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
/// and READ posts name that target explicitly. This is the single
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
    pub(crate) fn read_handle(&self) -> Rc<RefCell<ffi::JettyHandle>> {
        self.handle.clone()
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
/// only its imported target identity and lifecycle state.
pub(crate) struct PeerTarget {
    id: u16,
    generation: u8,
    state: PeerTargetLifecycle,
    capability: UrmaDeviceCapability,
    target: Option<Rc<ffi::TargetHandle>>,
    retirement_armed: bool,
}

impl PeerTarget {
    pub(crate) fn new(id: u16, generation: u8, capability: UrmaDeviceCapability) -> Result<Self> {
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

    /// Retains the imported target while a READ import/WR can still refer to
    /// it. Peer retirement refuses to unimport until every clone is gone.
    pub(crate) fn read_target(&self) -> Result<Rc<ffi::TargetHandle>> {
        self.require(PeerTargetLifecycle::Ready)?;
        self.target
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::Protocol("RM target is not imported".into()))
    }

    pub(crate) fn begin_draining(&mut self) -> Result<()> {
        if self.state == PeerTargetLifecycle::Closed {
            return Ok(());
        }
        // The shared endpoint must stay healthy for the other PeerTargets, so
        // a single peer's retirement cannot call Jetty mark_error. Draining
        // only converges once this target's outstanding WRs complete on their
        // own; a peer that strands WRs requires the endpoint-level flush
        // escalation in Runtime shutdown.
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

    pub(crate) fn close(&mut self) -> Result<()> {
        if self.state == PeerTargetLifecycle::Closed {
            return Ok(());
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
                self.state = PeerTargetLifecycle::Closed;
                Ok(())
            }
            Err(error) => {
                self.state = PeerTargetLifecycle::Failed;
                Err(error)
            }
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

        let mut peer = PeerTarget::new(7, 2, capability()).unwrap();
        peer.target = Some(Rc::new(ffi::TargetHandle::without_native()));
        peer.state = PeerTargetLifecycle::Ready;
        let read_target = peer.read_target().unwrap();
        peer.begin_draining().unwrap();
        assert!(peer.close().is_err());
        assert_eq!(peer.state, PeerTargetLifecycle::Failed);
        drop(read_target);
        peer.close().unwrap();
        assert_eq!(peer.state, PeerTargetLifecycle::Closed);
    }
}
