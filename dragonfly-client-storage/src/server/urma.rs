/*
 *     Copyright 2026 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::content::MappedPiece;
use crate::read_storage_source::ReadStorageSource;
use crate::rendezvous::PieceKind;
use crate::urma::fabric::{FabricReadiness, UrmaFabric, UrmaFabricHandle};
use crate::urma::ffi::read::source::{ReadBacking, ReadSourceMemory};
use crate::urma::ffi::read::ReadToken;
use crate::urma::read_control::{
    read_handshake, write_handshake, AcceptedReadTransfer, ReadHandshake, ReadLaneCapability,
    ReadLaneControl,
};
use crate::urma::read_handoff::ResourceGuard;
use crate::urma::read_protocol::{ReadCapability, READ_DESCRIPTOR_VERSION};
use crate::urma::read_transfer::parent::{ParentTransfer, SourceState};
use crate::urma::rendezvous::{CapabilityRegistry, UrmaAdvertisement, UrmaCapability};
use crate::urma::runtime::{
    ReadCachedSource, ReadCachedSourceRequest, ReadSourceId, ReadSourceRequest,
};
use crate::urma::server_session_idle_timeout;

use crate::urma::Error as UrmaError;

use crate::urma::{TpType, TransportMode};
use crate::Storage;
use dragonfly_client_config::dfdaemon::{
    Config, UrmaReadServer, UrmaRegistration, UrmaRegistrationMode,
};
use dragonfly_client_core::{Error as ClientError, Result as ClientResult};
use dragonfly_client_metric::{
    collect_upload_piece_finished_metrics, collect_upload_piece_traffic_metrics,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{debug, error, info, warn};

use dragonfly_client_util::shutdown;

type SourceLedger = Arc<std::sync::Mutex<HashMap<u16, Vec<ReadSourceId>>>>;

fn record_source_state(ledger: &SourceLedger, lane_id: u16, id: ReadSourceId, state: SourceState) {
    let mut sources = ledger.lock().unwrap();
    match state {
        SourceState::Registered => {
            let entries = sources.entry(lane_id).or_default();
            if !entries.contains(&id) {
                entries.push(id);
            }
        }
        SourceState::Released => {
            if let Some(entries) = sources.get_mut(&lane_id) {
                entries.retain(|entry| *entry != id);
            }
        }
        // The identity stays in the ledger or its cleanup batch. A late
        // cancellation must not recreate an identity already fully released.
        SourceState::Retained => {}
    }
}

fn source_cleanup_guard(
    ledger: SourceLedger,
    remaining: Arc<std::sync::Mutex<Vec<ReadSourceId>>>,
    lane_id: u16,
) -> ResourceGuard {
    ResourceGuard::new(move || {
        let pending = remaining.lock().unwrap();
        let mut ledger = ledger.lock().unwrap();
        let entries = ledger.entry(lane_id).or_default();
        for id in pending.iter() {
            if !entries.contains(id) {
                entries.push(*id);
            }
        }
    })
}

fn client_error(error: UrmaError) -> ClientError {
    ClientError::Unknown(error.to_string())
}

enum PieceSource {
    Mapped(MappedPiece),
    Reader(Box<dyn AsyncRead + Send + Unpin>),
}

/// Optional dfdaemon URMA rendezvous server. Native setup or listener failure disables only this
/// fast path; the normal TCP Piece server remains the discovery endpoint and fallback transport.
pub struct UrmaServer {
    config: Arc<Config>,
    addr: SocketAddr,
    storage: Arc<Storage>,
    shutdown: shutdown::Shutdown,
    _shutdown_complete: mpsc::UnboundedSender<()>,
    capability_registry: Option<CapabilityRegistry>,
}

struct PublishedCapability(CapabilityRegistry);

impl Drop for PublishedCapability {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl UrmaServer {
    pub fn new(
        config: Arc<Config>,
        addr: SocketAddr,
        storage: Arc<Storage>,
        shutdown: shutdown::Shutdown,
        shutdown_complete_tx: mpsc::UnboundedSender<()>,
    ) -> Self {
        Self {
            config,
            addr,
            storage,
            shutdown,
            _shutdown_complete: shutdown_complete_tx,
            capability_registry: None,
        }
    }

    /// Publishes discovery only after native startup and listener bind both succeed.
    pub fn with_capability_registry(mut self, registry: CapabilityRegistry) -> Self {
        self.capability_registry = Some(registry);
        self
    }

    pub async fn run(&mut self) -> ClientResult<()> {
        let urma_config = &self.config.storage.server.urma;
        if urma_config.deprecated.configured() {
            warn!("URMA SEND/RECV settings are deprecated and ignored; use storage.server.urma.read budgets and limits");
        }

        let Some(device) = urma_config
            .device
            .as_deref()
            .filter(|device| !device.is_empty())
        else {
            return Err(ClientError::Unsupported(
                "storage.server.urma.device is required".to_string(),
            ));
        };
        let Some(fabric_tag) = urma_config
            .fabric_tag
            .as_deref()
            .filter(|tag| !tag.is_empty())
        else {
            return Err(ClientError::Unsupported(
                "storage.server.urma.fabricTag is required".to_string(),
            ));
        };

        let read_config = urma_config
            .read
            .as_ref()
            .ok_or_else(|| ClientError::Unsupported("URMA READ is not configured".into()))?;
        if !read_config.provider_revocation_validated {
            return Err(ClientError::Unsupported(
                "URMA READ publication requires providerRevocationValidated".into(),
            ));
        }
        let tp_type = match urma_config.tp_type {
            dragonfly_client_config::dfdaemon::UrmaTpType::Rtp => TpType::Rtp,
            dragonfly_client_config::dfdaemon::UrmaTpType::Ctp => TpType::Ctp,
        };
        let device = device.to_string();
        let eid_index = urma_config.eid_index;
        let read_runtime = read_config.clone();
        let fabric = tokio::task::spawn_blocking(move || {
            UrmaFabric::get_or_start_with_read_config(device, eid_index, tp_type, &read_runtime)
        })
        .await
        .map_err(|error| {
            ClientError::Unknown(format!("URMA Fabric startup worker failed: {error}"))
        })?
        .map_err(client_error)?;
        let transport_mode = TransportMode::Rm;
        if !fabric.supports_rm() {
            return Err(ClientError::Unsupported(format!(
                "URMA device does not advertise {transport_mode:?} mode"
            )));
        }
        let capability = UrmaCapability {
            transport_type: fabric.transport_type(),
            transport_mode,
            tp_type: fabric.tp_type(),
            fabric_tag: fabric_tag.to_string(),
            max_message_size: fabric.max_message_size(),
        };
        info!(
            total_budget_bytes = read_config.total_bytes.as_u64(),
            source_budget_bytes = read_config.source_bytes.as_u64(),
            destination_budget_bytes = read_config.destination_bytes.as_u64(),
            "urma READ registration budgets configured"
        );
        let read_parent = read_parent_config(read_config, &fabric, fabric_tag);
        let handler = Arc::new(UrmaServerHandler::new(
            self.storage.clone(),
            fabric.clone(),
            urma_config.transfer_timeout,
            urma_config.transfer_timeout,
            urma_config.mmap_content,
            urma_config.max_concurrent_transfers as usize,
            read_parent,
        ));
        let admission = Arc::new(Semaphore::new(
            urma_config.max_concurrent_transfers as usize,
        ));

        let socket = Socket::new(
            Domain::for_address(self.addr),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_tcp_nodelay(true)?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_interval(super::DEFAULT_KEEPALIVE_INTERVAL)
                .with_time(super::DEFAULT_KEEPALIVE_TIME)
                .with_retries(super::DEFAULT_KEEPALIVE_RETRIES),
        )?;
        socket.bind(&self.addr.into())?;
        socket.listen(1024)?;
        let listener = TcpListener::from_std(socket.into()).inspect_err(|error| {
            error!("failed to bind urma rendezvous server: {error}");
        })?;
        info!(
            address = %self.addr,
            transport_type = capability.transport_type,
            "storage urma server ready"
        );
        let published = self.capability_registry.as_ref().map(|registry| {
            registry.publish(UrmaAdvertisement {
                capability,
                port: self.addr.port(),
                read_port: self.addr.port(),
            });
            PublishedCapability(registry.clone())
        });

        let mut readiness = fabric.subscribe_readiness();
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, remote_address) = accepted?;
                    let Ok(permit) = admission.clone().try_acquire_owned() else {
                        debug!(%remote_address, "urma connection admission full");
                        drop(stream);
                        continue;
                    };
                    let handler = handler.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handler.handle_read_lane(stream, remote_address.to_string()).await {
                            debug!(%remote_address, %error, "urma peer connection retired");
                        }
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = completed {
                        warn!(%error, "urma connection task failed");
                    }
                }
                changed = readiness.changed() => {
                    if changed.is_err() {
                        return Err(ClientError::Unknown(
                            "urma Fabric readiness channel closed".to_string(),
                        ));
                    }
                    match readiness.borrow().clone() {
                        FabricReadiness::Ready | FabricReadiness::Starting => {}
                        FabricReadiness::Failed(error) => {
                            return Err(ClientError::Unknown(format!(
                                "urma Fabric failed: {error}"
                            )));
                        }
                        FabricReadiness::Stopped => {
                            return Err(ClientError::Unknown(
                                "urma Fabric stopped while listener was active".to_string(),
                            ));
                        }
                    }
                }
                _ = self.shutdown.recv() => {
                    info!("urma server shutting down");
                    break;
                }
            }
        }

        // Stop discovery and close the listening socket before draining accepted lanes. A peer
        // must never discover a capability whose accept loop has already stopped.
        drop(published);
        drop(listener);
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        // Source identities are recorded as soon as registration is claimed,
        // so cancelled transfer futures cannot hide them from shutdown.
        let source_lanes: Vec<_> = handler
            .retained_read_sources
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect();
        for lane_id in source_lanes {
            let _ = fabric.close_lane(lane_id).await;
            if let Err(error) = handler.cleanup_retained_read_sources(lane_id).await {
                warn!(lane_id, %error, "READ shutdown source cleanup incomplete");
            }
        }
        fabric.shutdown().await.map_err(client_error)
    }
}

/// Storage-facing handler for one persistent URMA peer connection. Listener,
/// readiness publication and connection admission remain dfdaemon wiring
/// responsibilities; this type owns only the Piece upload contract.
struct UrmaServerHandler {
    storage: Arc<Storage>,
    fabric: UrmaFabricHandle,
    control_timeout: Duration,
    session_idle_timeout: Duration,
    transfer_timeout: Duration,
    mmap_content: bool,
    max_concurrent_transfers: usize,
    /// READ publication parameters with the validated provider gate.
    read: ReadParentConfig,
    retained_read_sources: SourceLedger,
}

/// Parent-side READ lane parameters derived from the process configuration.
#[derive(Clone)]
struct ReadParentConfig {
    capability: ReadLaneCapability,
    _revocation_gate: ProviderRevocationValidated,
    registration: UrmaRegistration,
}

/// Startup evidence that the deployment provider passed the external source
/// revocation gate. It cannot be constructed from ReadDone/CancelDrained.
#[derive(Clone)]
struct ProviderRevocationValidated;

/// Bearer token space for READ source publications.
///
/// Tokens must be process-unique so a stale offer can never arm a new export, and
/// they must not be derivable from tokens a reader has already been served: the
/// token is the whole credential, so a sequential counter lets a peer that holds
/// one Piece's descriptor guess the token of whichever Piece reuses that address.
/// That extrapolation was measured on hardware: guessing "current + 1" served the
/// bytes of a grant the reader was never authorized for.
///
/// A keyed permutation of the 32-bit token space provides both properties without
/// any bookkeeping. Feistel rounds are a bijection for every key, so distinct
/// indices can never collide and uniqueness costs no memory. Independent HMAC-SHA256
/// round keys come directly from the OS CSPRNG; token confidentiality is still
/// bounded by the provider's 32-bit field and must be paired with admission limits.
struct ReadTokenSpace {
    index: AtomicU32,
    round_keys: [[u8; 32]; READ_TOKEN_ROUNDS],
}

const READ_TOKEN_ROUNDS: usize = 4;
type ReadTokenMac = Hmac<Sha256>;

static READ_TOKEN_SPACE: OnceLock<Result<ReadTokenSpace, getrandom::Error>> = OnceLock::new();

fn next_read_token() -> ClientResult<u32> {
    let space = READ_TOKEN_SPACE
        .get_or_init(ReadTokenSpace::new)
        .as_ref()
        .map_err(|error| {
            ClientError::Unknown(format!(
                "failed to initialize URMA READ token space: {error}"
            ))
        })?;
    allocate_read_token(space)
}

impl ReadTokenSpace {
    fn new() -> Result<Self, getrandom::Error> {
        let mut round_keys = [[0u8; 32]; READ_TOKEN_ROUNDS];
        for key in &mut round_keys {
            getrandom::fill(key)?;
        }
        Ok(Self {
            index: AtomicU32::new(0),
            round_keys,
        })
    }

    #[cfg(test)]
    fn with_test_keys(round_keys: [[u8; 32]; READ_TOKEN_ROUNDS]) -> Self {
        Self {
            index: AtomicU32::new(0),
            round_keys,
        }
    }

    fn permute(&self, index: u32) -> u32 {
        let mut left = (index >> 16) as u16;
        let mut right = index as u16;
        for round in 0..READ_TOKEN_ROUNDS {
            let next_left = right;
            let next_right = left ^ self.round(round, right);
            left = next_left;
            right = next_right;
        }
        (u32::from(left) << 16) | u32::from(right)
    }

    fn round(&self, round: usize, half: u16) -> u16 {
        let mut mac = ReadTokenMac::new_from_slice(&self.round_keys[round])
            .expect("HMAC accepts every 32-byte key");
        mac.update(&half.to_be_bytes());
        let output = mac.finalize().into_bytes();
        u16::from_be_bytes([output[0], output[1]])
    }
}

fn allocate_read_token(space: &ReadTokenSpace) -> ClientResult<u32> {
    loop {
        let index = space
            .index
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ClientError::Unknown("urma READ token space exhausted".to_string()))?;

        // Preserve the transport's historical reservation of bearer value zero.
        // URMA_TOKEN_NONE is a separate policy field; zero is not a provider bypass.
        // Exactly one index maps to zero, so skipping it costs one draw.
        let token = space.permute(index);
        if token != 0 {
            return Ok(token);
        }
    }
}

/// Builds the READ lane capability advertised during the version-7 handshake.
fn read_parent_config(
    read: &UrmaReadServer,
    fabric: &UrmaFabricHandle,
    fabric_tag: &str,
) -> ReadParentConfig {
    ReadParentConfig {
        capability: ReadLaneCapability {
            control_transport: read.control_transport,
            transport_type: fabric.transport_type(),
            tp_type: fabric.tp_type(),
            fabric_tag: fabric_tag.to_string(),
            read: ReadCapability {
                max_read_size: read.max_read_size.as_u64() as u32,
                max_jfs_sge: read.max_jfs_sge,
                descriptor_version: READ_DESCRIPTOR_VERSION,
            }
            .with_provider_limit(fabric.max_read_size()),
        },
        _revocation_gate: ProviderRevocationValidated,
        registration: read.registration.clone(),
    }
}

impl UrmaServerHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        storage: Arc<Storage>,
        fabric: UrmaFabricHandle,
        control_timeout: Duration,
        transfer_timeout: Duration,
        mmap_content: bool,
        max_concurrent_transfers: usize,
        read: ReadParentConfig,
    ) -> Self {
        Self {
            storage,
            fabric,
            control_timeout,
            session_idle_timeout: server_session_idle_timeout(control_timeout),
            transfer_timeout,
            mmap_content,
            max_concurrent_transfers,
            read,
            retained_read_sources: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    fn piece_metadata(
        &self,
        kind: PieceKind,
        piece_id: &str,
    ) -> ClientResult<Option<crate::metadata::Piece>> {
        match kind {
            PieceKind::Piece => self.storage.get_piece(piece_id),
            PieceKind::PersistentPiece => self.storage.get_persistent_piece(piece_id),
            PieceKind::PersistentCachePiece => self.storage.get_persistent_cache_piece(piece_id),
        }
    }

    /// Only ordinary, on-disk completed files enter the cache. A lookup miss
    /// performs the full-file check; hits reuse its prior completion evidence.
    async fn prepare_cached_source(
        &self,
        lane_id: u16,
        kind: PieceKind,
        task_id: &str,
        piece_id: &str,
    ) -> ClientResult<Option<(ReadStorageSource, ReadCachedSource, u64)>> {
        if kind != PieceKind::Piece
            || !self.mmap_content
            || self.read.registration.mode != UrmaRegistrationMode::Cached
        {
            return Ok(None);
        }
        let Some(storage) = self.storage.read_cache_source(task_id, piece_id).await? else {
            return Ok(None);
        };
        let max_region_bytes = self.read.registration.max_region_bytes.as_u64();
        if storage.piece_length > max_region_bytes
            && storage.file.opened_length() > max_region_bytes
        {
            return Ok(None);
        }
        let request = |completed| -> ClientResult<_> {
            Ok(ReadCachedSourceRequest {
                peer_id: lane_id,
                kind,
                task: task_id.to_owned(),
                file: storage.file.clone(),
                piece_length: storage.piece_length,
                max_region_bytes,
                piece_offset: storage.piece.offset,
                completed,
                token: ReadToken::new(next_read_token()?),
            })
        };
        let started = Instant::now();
        // SAFETY: lookup-only cannot create a Source. Current Piece availability
        // was established above; file identity separates unlink/recreation.
        let source = match unsafe {
            self.fabric
                .register_cached_source(request(Vec::new())?, self.transfer_timeout)
                .await
        } {
            Ok(source) => source,
            Err(UrmaError::SourceCacheMiss) => {
                if !self
                    .storage
                    .file_is_complete_for_cache(task_id, &storage)
                    .await?
                {
                    return Ok(None);
                }
                // SAFETY: canonical completed disk Pieces cover this whole file;
                // reuse Dragonfly's existing completed-content immutability contract.
                unsafe {
                    self.fabric
                        .register_cached_source(
                            request(vec![0..storage.file.opened_length()])?,
                            self.transfer_timeout,
                        )
                        .await
                }
                .map_err(client_error)?
            }
            Err(error) => return Err(client_error(error)),
        };
        Ok(Some((storage, source, started.elapsed().as_nanos() as u64)))
    }

    async fn open_piece_source(
        &self,
        kind: PieceKind,
        task_id: &str,
        piece_id: &str,
    ) -> ClientResult<PieceSource> {
        if self.mmap_content {
            match self.storage.map_upload_piece(piece_id, task_id, kind).await {
                Ok(mapped) => {
                    debug!(piece_id, "URMA upload using mmap content");
                    return Ok(PieceSource::Mapped(mapped));
                }
                Err(error) => {
                    warn!(piece_id, %error, "URMA mmap unavailable; falling back to reader");
                }
            }
        }
        let reader = match kind {
            PieceKind::Piece => self
                .storage
                .upload_piece(piece_id, task_id, None)
                .await
                .map(|(_, reader)| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
            PieceKind::PersistentPiece => self
                .storage
                .upload_persistent_piece(piece_id, task_id, None)
                .await
                .map(|(_, reader)| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
            PieceKind::PersistentCachePiece => self
                .storage
                .upload_persistent_cache_piece(piece_id, task_id, None)
                .await
                .map(|(_, reader)| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
        }?;
        Ok(PieceSource::Reader(reader))
    }

    /// Serves one RM-READ lane: version-7 handshake, Child-side Jetty import, and
    /// Child-initiated transfer admission. TCP bootstraps descriptors, then
    /// control frames use the negotiated transport; Piece bytes use READ.
    async fn handle_read_lane(
        self: Arc<Self>,
        mut stream: TcpStream,
        remote_address: String,
    ) -> ClientResult<()> {
        let read = self.read.clone();
        let connect = match time::timeout(self.control_timeout, read_handshake(&mut stream)).await {
            Ok(Ok(connect)) => connect,
            Ok(Err(error)) => return Err(client_error(error)),
            Err(_) => {
                return Err(ClientError::Unknown(
                    "urma READ lane handshake timeout".to_string(),
                ));
            }
        };
        let (session_generation, effective_max_read_size, remote_descriptor) = connect
            .validate_connect(&read.capability)
            .map_err(client_error)?;

        // READ has a fixed one-sided direction. The Child imports this local
        // endpoint and posts READs; the Parent only registers source memory,
        // so importing the Child data Jetty would create an unused reverse
        // READ target. SEND/RECV uses a separate bidirectional control endpoint.
        let (lane_id, parent_descriptor) = self.fabric.create_lane().await.map_err(client_error)?;
        let guard = self.fabric.lane_guard(lane_id);
        let native_control = read.capability.control_transport
            == dragonfly_client_config::dfdaemon::UrmaControlTransport::Sendrecv;
        let (_, remote_control) =
            crate::urma::sendrecv_control::unpack_descriptors(remote_descriptor, native_control)
                .map_err(client_error)?;
        let setup = if native_control {
            let setup = self
                .fabric
                .create_control(lane_id)
                .await
                .map_err(client_error)?;
            self.fabric
                .connect_control(lane_id, setup.id, remote_control)
                .await
                .map_err(client_error)?;
            Some(setup)
        } else {
            None
        };
        let parent_descriptor =
            crate::urma::sendrecv_control::pack_descriptors(parent_descriptor, setup.as_ref())
                .map_err(client_error)?;

        if let Err(error) = write_handshake(
            &mut stream,
            &ReadHandshake::Connected {
                capability: read.capability.clone(),
                session_generation,
                descriptor: parent_descriptor,
            },
        )
        .await
        {
            return Err(client_error(error));
        }
        info!(
            %remote_address,
            lane_id,
            session_generation,
            max_read_size = effective_max_read_size,
            control_transport = ?read.capability.control_transport,
            "urma READ lane established"
        );

        let lane = if let Some(setup) = setup {
            let native = crate::urma::sendrecv_control::spawn(
                self.fabric.clone(),
                lane_id,
                session_generation,
                setup,
                stream,
            );
            ReadLaneControl::spawn(
                native,
                session_generation,
                self.max_concurrent_transfers,
                self.max_concurrent_transfers.saturating_mul(2).max(16),
            )
        } else {
            ReadLaneControl::spawn(
                stream,
                session_generation,
                self.max_concurrent_transfers,
                self.max_concurrent_transfers.saturating_mul(2).max(16),
            )
        }
        .map(Arc::new)
        .map_err(client_error)?;
        guard.disarm();
        let mut transfers = JoinSet::new();
        loop {
            let Some(accepted) = lane.accept_transfer(self.session_idle_timeout).await else {
                while transfers.join_next().await.is_some() {}
                debug!(lane_id, "urma READ lane closed or idle");
                break;
            };
            let handler = self.clone();
            let transfer_lane = lane.clone();
            transfers.spawn(async move {
                let result = time::timeout(
                    handler.transfer_timeout,
                    handler.clone().serve_read_transfer(
                        lane_id,
                        effective_max_read_size,
                        accepted,
                        transfer_lane.clone(),
                    ),
                )
                .await;
                if !matches!(&result, Ok(Ok(()))) {
                    transfer_lane.abort("READ Parent transfer failed or timed out");
                    debug!(?result, "urma READ transfer failed; retiring lane");
                }
            });
            while let Some(completed) = transfers.try_join_next() {
                match completed {
                    Ok(()) => {}
                    Err(error) => warn!(%error, "urma READ transfer task failed"),
                }
            }
        }
        drop(lane);
        self.fabric
            .close_lane(lane_id)
            .await
            .map_err(client_error)?;
        self.cleanup_retained_read_sources(lane_id).await
    }

    /// Publishes one Piece as a registered READ source and waits at the
    /// provider-revocation gate. Page-aligned Storage mappings are registered
    /// directly and retained through revocation; reader bytes use an aligned
    /// shim-owned copy.
    async fn serve_read_transfer(
        self: Arc<Self>,
        lane_id: u16,
        effective_max_read_size: u32,
        accepted: AcceptedReadTransfer,
        lane: Arc<ReadLaneControl>,
    ) -> ClientResult<()> {
        let accepted_length = match &accepted.buffer_ready {
            crate::urma::read_protocol::ReadFrame::BufferReady {
                accepted_length, ..
            } => *accepted_length,
            _ => {
                return Err(ClientError::Unknown(
                    "dispatcher admitted a non-BufferReady READ transfer".to_string(),
                ))
            }
        };
        let locator = match &accepted.buffer_ready {
            crate::urma::read_protocol::ReadFrame::BufferReady { request, .. } => request.clone(),
            _ => {
                return Err(ClientError::Unknown(
                    "dispatcher admitted a non-BufferReady READ transfer".to_string(),
                ))
            }
        };
        let piece_id = self
            .storage
            .piece_id(&locator.task_id, locator.piece_number);
        if accepted.identity != accepted.buffer_ready.identity() {
            return Err(ClientError::Unknown(
                "READ admission identity mismatch".into(),
            ));
        }
        let source_e2e_start = Instant::now();
        info!(
            task_id = %locator.task_id,
            piece_id,
            lane_id,
            "start READ upload piece content"
        );
        let cached = self
            .prepare_cached_source(lane_id, locator.kind, &locator.task_id, &piece_id)
            .await?;
        let piece = match &cached {
            Some((storage, _, _)) => Some(storage.piece.clone()),
            None => self.piece_metadata(locator.kind, &piece_id)?,
        };
        let Some(piece) = piece else {
            return Err(ClientError::Unknown(format!(
                "READ piece {piece_id} is not available"
            )));
        };
        if piece.length != accepted_length {
            return Err(ClientError::Unknown(format!(
                "READ piece {piece_id} length {} diverges from accepted length {accepted_length}",
                piece.length
            )));
        }
        let (transfer, locator) = ParentTransfer::accept(
            self.fabric.clone(),
            lane_id,
            accepted.control,
            accepted.buffer_ready,
            piece.offset,
            piece.digest.clone(),
            effective_max_read_size,
        )
        .map_err(client_error)?;
        let retained_handler = self.clone();
        let retained_lane = lane.clone();
        let transfer = transfer.on_source_state(move |id, state| {
            record_source_state(&retained_handler.retained_read_sources, lane_id, id, state);
            if matches!(state, SourceState::Retained) {
                retained_lane.abort("READ source retained after failure or cancellation");
            }
        });
        let source_cached = cached.is_some();
        let source_open_start = Instant::now();
        let (published, source_open_ns, source_copy_ns) = if let Some((
            _storage,
            source,
            register_ns,
        )) = cached
        {
            // SAFETY: prepare_cached_source checked ordinary Task completion and
            // the offered Piece comes from that same opened file.
            let result = unsafe {
                transfer
                    .publish_cached_source_and_wait_read_done(
                        source,
                        register_ns,
                        self.transfer_timeout,
                    )
                    .await
            };
            (result, 0, 0)
        } else {
            let source = self
                .open_piece_source(locator.kind, &locator.task_id, &piece_id)
                .await?;
            let source_open_ns = source_open_start.elapsed().as_nanos() as u64;
            let source_copy_start = Instant::now();
            let memory = match source {
                PieceSource::Mapped(mapped) => {
                    // ReadSource retains this mapping through verified revocation.
                    // Its page-aligned VA can therefore be registered directly.
                    if mapped.offset() != piece.offset || mapped.len() as u64 != accepted_length {
                        return Err(ClientError::Unknown(format!(
                        "READ piece {piece_id} source range {}+{} diverges from expected {}+{accepted_length}",
                        mapped.offset(), mapped.len(), piece.offset
                    )));
                    }
                    ReadSourceMemory::Mapped(mapped)
                }
                PieceSource::Reader(mut reader) => {
                    let mut bytes = Vec::with_capacity(usize::try_from(piece.length).unwrap_or(0));
                    reader.read_to_end(&mut bytes).await?;
                    if bytes.len() as u64 != accepted_length {
                        return Err(ClientError::Unknown(format!(
                        "READ piece {piece_id} source bytes {} diverge from accepted length {accepted_length}",
                        bytes.len()
                    )));
                    }
                    ReadSourceMemory::Bytes(bytes.into_boxed_slice())
                }
            };
            let source_copy_ns = source_copy_start.elapsed().as_nanos() as u64;
            let token = ReadToken::new(next_read_token()?);

            // SAFETY: the existing Piece path provides completed immutable bytes.
            let result = unsafe {
                transfer
                    .publish_and_wait_read_done(
                        ReadSourceRequest {
                            peer_id: lane_id,
                            backing: ReadBacking::new(memory, ()),
                            token,
                        },
                        self.transfer_timeout,
                    )
                    .await
            };
            (result, source_open_ns, source_copy_ns)
        };
        let (parent, pending) = match published {
            Ok(published) => published,
            Err(failure) => {
                if let Some(retained) = failure.retained_source {
                    debug!(lane_id, source_id = ?retained.source_id, segment_generation = ?retained.segment_generation, "retaining READ source after transport failure");
                    // Fail closed: the source stays registered and budgeted
                    // until lane close plus the provider gate proves revocation.
                    lane.abort("READ source retained after transfer failure");
                    warn!(piece_id, "urma READ source owner retained for cleanup");
                }
                return Err(client_error(failure.error));
            }
        };
        collect_upload_piece_traffic_metrics(pending.completed_length);
        info!(
            task_id = %locator.task_id,
            piece_id,
            source_cached,
            source_backing = ?self.read.registration.backing,
            source_id = ?pending.source_id,
            source_e2e_ns = source_e2e_start.elapsed().as_nanos() as u64,
            source_open_ns,
            source_copy_ns,
            read_wr_count = pending.read_wr_count,
            register_ns = pending.register_ns,
            register_alloc_ns = pending.register_stages.alloc_ns,
            register_copy_ns = pending.register_stages.copy_ns,
            register_token_ns = pending.register_stages.token_ns,
            register_seg_ns = pending.register_stages.seg_ns,
            register_direct = pending.register_stages.direct,
            wait_read_done_ns = pending.wait_read_done_ns,
            "{}",
            if source_cached {
                "urma READ cached source fully read; releasing lease"
            } else {
                "urma READ source fully read; revoking export"
            }
        );

        // SAFETY: Construction of this handler required the deployment's
        // explicit provider-revocation gate. ReadDone/CancelDrained supplies
        // the cooperative Child drain, while the validated provider contract
        // supplies the independent guarantee for dedicated Source unregister.
        // Cached completion instead releases only this transfer's lease; the
        // physical Source remains registered until cache eviction.
        let revoke_start = Instant::now();
        unsafe { parent.finish(pending).await }.map_err(client_error)?;
        info!(
            task_id = %locator.task_id,
            piece_id,
            source_cached,
            revoke_ns = revoke_start.elapsed().as_nanos() as u64,
            "{}",
            if source_cached {
                "urma READ cached source lease released"
            } else {
                "urma READ source revoke finished"
            }
        );
        collect_upload_piece_finished_metrics();
        Ok(())
    }

    /// Reaps sources whose transfer failed after native registration. This is
    /// called only after the lane target has closed, and this handler exists
    /// only when startup supplied the provider revocation gate.
    async fn cleanup_retained_read_sources(&self, lane_id: u16) -> ClientResult<()> {
        let sources = self
            .retained_read_sources
            .lock()
            .unwrap()
            .remove(&lane_id)
            .unwrap_or_default();
        let remaining = Arc::new(std::sync::Mutex::new(sources.clone()));
        let restore = source_cleanup_guard(
            self.retained_read_sources.clone(),
            remaining.clone(),
            lane_id,
        );
        let mut retained = Vec::new();
        let mut first_error = None;
        for source_id in sources {
            let mut result = Ok(());
            for attempt in 0..3 {
                result = time::timeout(self.transfer_timeout, async {
                    let _ = self.fabric.retire_read_source(source_id).await;
                    // SAFETY: The lane target is closed and startup required the
                    // deployment provider's synchronous revocation contract.
                    unsafe {
                        self.fabric.unregister_read_source(source_id).await?;
                        if !self
                            .fabric
                            .release_read_source_after_revoke(source_id)
                            .await?
                        {
                            return Err(UrmaError::Protocol(
                                "retained READ source remained pending after lane close".into(),
                            ));
                        }
                    }
                    Ok::<(), UrmaError>(())
                })
                .await
                .unwrap_or_else(|_| {
                    Err(UrmaError::Protocol(
                        "retained READ source cleanup deadline expired".into(),
                    ))
                });
                if result.is_ok() {
                    break;
                }
                if attempt < 2 {
                    time::sleep(Duration::from_millis(if attempt == 0 { 100 } else { 500 })).await;
                }
            }
            if result.is_ok() {
                remaining.lock().unwrap().retain(|id| *id != source_id);
            }
            if let Err(error) = result {
                if first_error.is_none() {
                    first_error = Some(error.to_string());
                }
                retained.push(source_id);
            }
        }
        restore.disarm();
        if !retained.is_empty() {
            self.retained_read_sources
                .lock()
                .unwrap()
                .entry(lane_id)
                .or_default()
                .extend(retained);
            return Err(ClientError::Unknown(first_error.unwrap_or_else(|| {
                "retained READ source cleanup failed".to_string()
            })));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn read_token_allocator_never_wraps_or_reuses_zero() {
        let space = test_read_token_space();
        space.index.store(u32::MAX - 1, Ordering::Release);
        assert_ne!(allocate_read_token(&space).unwrap(), 0);
        // The space is exhausted, not wrapped: the next draw fails closed instead of
        // restarting the index sequence and reissuing tokens.
        assert!(allocate_read_token(&space).is_err());
        assert_eq!(space.index.load(Ordering::Acquire), u32::MAX);
    }

    #[test]
    fn read_token_allocator_is_a_permutation_of_the_token_space() {
        // Distinct indices must map to distinct tokens across the whole space: that is
        // what lets a stale offer never arm a new export without tracking issued
        // tokens. The Feistel structure guarantees it, so a sequential slice of the
        // index space is enough to catch a broken implementation.
        let space = test_read_token_space();
        let mut issued = HashSet::new();
        for _ in 0..(1 << 16) {
            let token = allocate_read_token(&space).unwrap();
            assert_ne!(token, 0, "reserved bearer value zero was issued");
            assert!(issued.insert(token), "token {token} was issued twice");
        }
    }

    #[test]
    fn read_token_permutation_has_stable_test_vector() {
        let space = test_read_token_space();
        assert_eq!(space.permute(0), 0xd367_1f1f);
        assert_eq!(space.permute(1), 0x0f6c_f728);
        assert_eq!(space.permute(u32::MAX), 0x3385_5c65);
    }

    fn test_read_token_space() -> ReadTokenSpace {
        let mut keys = [[0u8; 32]; READ_TOKEN_ROUNDS];
        for (round, key) in keys.iter_mut().enumerate() {
            for (index, byte) in key.iter_mut().enumerate() {
                *byte = (round * 32 + index) as u8;
            }
        }
        ReadTokenSpace::with_test_keys(keys)
    }
    fn source_ids() -> [ReadSourceId; 2] {
        use crate::urma::read_registry::{
            ReadBudget, ReadCapacity, ReadDirection, ReadOwnerRegistry, ReadPeer,
        };
        let cap = ReadCapacity {
            bytes: 64,
            entries: 4,
        };
        let mut registry = ReadOwnerRegistry::<()>::new(ReadBudget {
            total: ReadCapacity {
                bytes: 128,
                entries: 8,
            },
            source: cap,
            destination: cap,
            per_peer_source: cap,
            per_peer_destination: cap,
            quarantine: cap,
        })
        .unwrap();
        let peer = ReadPeer {
            id: 1,
            generation: 1,
        };
        registry.activate_peer(peer).unwrap();
        [
            ReadSourceId(registry.reserve(peer, ReadDirection::Source, 8).unwrap()),
            ReadSourceId(registry.reserve(peer, ReadDirection::Source, 8).unwrap()),
        ]
    }
    #[test]
    fn source_ledger_retains_failed_revoke_and_does_not_resurrect_released_ids() {
        let ledger = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let id = source_ids()[0];
        record_source_state(&ledger, 7, id, SourceState::Registered);
        record_source_state(&ledger, 7, id, SourceState::Retained);
        assert_eq!(ledger.lock().unwrap()[&7], vec![id]);
        record_source_state(&ledger, 7, id, SourceState::Released);
        record_source_state(&ledger, 7, id, SourceState::Retained);
        assert!(ledger.lock().unwrap()[&7].is_empty());
    }
    #[test]
    fn cancelled_cleanup_batch_restores_only_unreleased_sources_without_duplicates() {
        let ledger = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let ids = source_ids();
        let remaining = Arc::new(std::sync::Mutex::new(ids.to_vec()));
        let guard = source_cleanup_guard(ledger.clone(), remaining.clone(), 7);
        // First source finished; cancellation occurs while processing the second.
        remaining.lock().unwrap().remove(0);
        record_source_state(&ledger, 7, ids[1], SourceState::Registered);
        drop(guard);
        assert_eq!(ledger.lock().unwrap()[&7], vec![ids[1]]);
    }
}
