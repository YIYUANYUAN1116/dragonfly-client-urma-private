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
use crate::rendezvous::{
    PieceKind, ERROR_CODE_BUSY, ERROR_CODE_INTERNAL, ERROR_CODE_NOT_FOUND, ERROR_CODE_TOO_LARGE,
};
use crate::urma::fabric::{FabricReadiness, PeerTargetConfig, UrmaFabric, UrmaFabricHandle};
use crate::urma::ffi::read::source::{ReadBacking, ReadSourceMemory};
use crate::urma::ffi::read::ReadToken;
use crate::urma::read_control::{
    read_handshake, write_handshake, AcceptedReadTransfer, ReadHandshake, ReadLaneCapability,
    ReadLaneControl,
};
use crate::urma::read_protocol::{ReadCapability, READ_DESCRIPTOR_VERSION, READ_DFUR_VERSION};
use crate::urma::read_session::ParentSourceSession;
use crate::urma::rendezvous::{
    write_frame, CapabilityRegistry, CommonPieceRequest, Frame, PieceMetadata, RendezvousError,
    UrmaAdvertisement, UrmaCapability, SESSION_TRANSFER_ID,
};
use crate::urma::runtime::{ReadRuntimeConfig, ReadSourceId, ReadSourceRequest};
use crate::urma::server_session_idle_timeout;
use crate::urma::session::{RegisteredSendTiming, UrmaServerSession, UrmaServerTransfer};
use crate::urma::Error as UrmaError;
use crate::urma::TxWindowLease;
use crate::urma::{TpType, TransportMode};
use crate::Storage;
use dragonfly_client_config::dfdaemon::{Config, UrmaReadServer};
use dragonfly_client_core::{Error as ClientError, Result as ClientResult};
use dragonfly_client_metric::{
    collect_upload_piece_failure_metrics, collect_upload_piece_finished_metrics,
    collect_upload_piece_started_metrics, collect_upload_piece_traffic_metrics,
    collect_urma_budget_pressure_metrics, collect_urma_registered_bytes_metrics,
};
use leaky_bucket::RateLimiter;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU32, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{debug, error, info, instrument, warn, Span};

use dragonfly_client_util::shutdown;

const REQUIRED_TX_RETRY_INTERVAL: Duration = Duration::from_millis(1);

/// Absorbs short scheduler hand-off delays while a completed persistent-lane
/// Piece releases its process-wide transfer permit. Sustained overload still
/// receives a transfer-local BUSY response.
const PROCESS_TRANSFER_ADMISSION_GRACE: Duration = Duration::from_millis(10);

struct ProcessTransferAdmission {
    permit: OwnedSemaphorePermit,
    waited: bool,
    wait_ns: u64,
}

struct ProcessTransferPermitGuard {
    permit: Option<OwnedSemaphorePermit>,
    admission: Arc<Semaphore>,
    admission_limit: usize,
    lane_id: u16,
    transfer_id: u32,
}

impl ProcessTransferPermitGuard {
    fn new(
        permit: OwnedSemaphorePermit,
        admission: Arc<Semaphore>,
        admission_limit: usize,
        lane_id: u16,
        transfer_id: u32,
    ) -> Self {
        Self {
            permit: Some(permit),
            admission,
            admission_limit,
            lane_id,
            transfer_id,
        }
    }
}

impl Drop for ProcessTransferPermitGuard {
    fn drop(&mut self) {
        self.permit.take();
        let available_permits = self.admission.available_permits();
        debug!(
            lane_id = self.lane_id,
            transfer_id = self.transfer_id,
            admission_limit = self.admission_limit,
            available_permits,
            active_transfers = self.admission_limit.saturating_sub(available_permits),
            "released URMA process transfer admission"
        );
    }
}

async fn acquire_process_transfer(
    admission: Arc<Semaphore>,
    grace: Duration,
) -> Option<ProcessTransferAdmission> {
    match admission.clone().try_acquire_owned() {
        Ok(permit) => Some(ProcessTransferAdmission {
            permit,
            waited: false,
            wait_ns: 0,
        }),
        Err(TryAcquireError::Closed) => None,
        Err(TryAcquireError::NoPermits) => {
            let wait_start = Instant::now();
            let permit = match time::timeout(grace, admission.acquire_owned()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) | Err(_) => return None,
            };
            Some(ProcessTransferAdmission {
                permit,
                waited: true,
                wait_ns: u64::try_from(wait_start.elapsed().as_nanos()).unwrap_or(u64::MAX),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SendDepths {
    window_chunks: u32,
}

fn send_depths(
    configured_window_chunks: u32,
    registered_window_capacity: u32,
    native_capacity: u32,
) -> SendDepths {
    let native_capacity = native_capacity.max(1);
    let window_chunks = configured_window_chunks
        .max(1)
        .min(registered_window_capacity.max(1))
        .min(native_capacity);
    SendDepths { window_chunks }
}

struct RequiredTxWaiter<'a> {
    waiters: &'a AtomicUsize,
}

impl<'a> RequiredTxWaiter<'a> {
    fn new(waiters: &'a AtomicUsize) -> Self {
        waiters.fetch_add(1, Ordering::AcqRel);
        Self { waiters }
    }
}

impl Drop for RequiredTxWaiter<'_> {
    fn drop(&mut self) {
        self.waiters.fetch_sub(1, Ordering::AcqRel);
    }
}

fn client_error(error: UrmaError) -> ClientError {
    ClientError::Unknown(error.to_string())
}

fn negotiate_transfer(
    request: &CommonPieceRequest,
    max_message_size: u64,
    send_depth: u32,
) -> ClientResult<(u64, u32)> {
    let chunk_size = request.chunk_size.min(max_message_size);
    let max_inflight_chunks = request.max_inflight_chunks.min(send_depth);
    if chunk_size == 0 || max_inflight_chunks == 0 {
        return Err(ClientError::InvalidParameter);
    }
    Ok((chunk_size, max_inflight_chunks))
}

fn tx_window_chunk_lengths(
    piece_length: u64,
    chunk_size: u64,
    max_inflight_chunks: u32,
    piece_offset: u64,
) -> ClientResult<Vec<usize>> {
    if piece_offset >= piece_length {
        return Err(ClientError::InvalidParameter);
    }
    let remaining = piece_length - piece_offset;
    let count = remaining
        .div_ceil(chunk_size)
        .min(u64::from(max_inflight_chunks));
    (0..count)
        .map(|index| {
            usize::try_from(chunk_size.min(remaining - index * chunk_size))
                .map_err(|_| ClientError::InvalidParameter)
        })
        .collect()
}

enum PieceSource {
    Mapped(MappedPiece),
    Reader(Box<dyn AsyncRead + Send + Unpin>),
}

impl PieceSource {
    async fn fill(&mut self, piece_offset: usize, lease: &mut TxWindowLease) -> ClientResult<()> {
        let mut offset = piece_offset;
        for index in 0..lease.part_count() {
            let dst = lease.part_mut(index).map_err(client_error)?;
            match self {
                Self::Mapped(mapped) => {
                    let end = offset
                        .checked_add(dst.len())
                        .ok_or(ClientError::InvalidParameter)?;
                    let src = mapped.as_slice().get(offset..end).ok_or_else(|| {
                        ClientError::Unknown(format!(
                            "URMA mmap piece underflow at offset {offset} length {}",
                            dst.len()
                        ))
                    })?;
                    dst.copy_from_slice(src);
                }
                Self::Reader(reader) => {
                    reader.read_exact(dst).await?;
                }
            }
            offset = offset
                .checked_add(dst.len())
                .ok_or(ClientError::InvalidParameter)?;
        }
        Ok(())
    }
}

/// Optional dfdaemon URMA rendezvous server. Native setup or listener failure disables only this
/// fast path; the normal TCP Piece server remains the discovery endpoint and fallback transport.
pub struct UrmaServer {
    config: Arc<Config>,
    addr: SocketAddr,
    storage: Arc<Storage>,
    upload_bandwidth_limiter: Arc<RateLimiter>,
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
        upload_bandwidth_limiter: Arc<RateLimiter>,
        shutdown: shutdown::Shutdown,
        shutdown_complete_tx: mpsc::UnboundedSender<()>,
    ) -> Self {
        Self {
            config,
            addr,
            storage,
            upload_bandwidth_limiter,
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

        let tp_type = match urma_config.tp_type {
            dragonfly_client_config::dfdaemon::UrmaTpType::Rtp => TpType::Rtp,
            dragonfly_client_config::dfdaemon::UrmaTpType::Ctp => TpType::Ctp,
        };
        let device = device.to_string();
        let eid_index = urma_config.eid_index;
        let max_registered_bytes = urma_config.max_registered_bytes.as_u64();
        let tx_registered_bytes = urma_config.tx_registered_bytes.as_u64();
        // When the READ plane is configured the fabric reserves its full
        // effective JFS depth for RM-READ and rejects legacy SEND/RECV posts.
        let read_runtime = urma_config
            .read
            .as_ref()
            .map(read_runtime_config)
            .transpose()?;
        let fabric = tokio::task::spawn_blocking(move || {
            if let Some(read) = read_runtime {
                UrmaFabric::get_or_start_with_budget_tp_and_read(
                    device,
                    eid_index,
                    max_registered_bytes,
                    tx_registered_bytes,
                    tp_type,
                    read,
                )
            } else {
                UrmaFabric::get_or_start_with_budget_and_tp_type(
                    device,
                    eid_index,
                    max_registered_bytes,
                    tx_registered_bytes,
                    tp_type,
                )
            }
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
            transport_mode = ?transport_mode,
            tp_type = ?tp_type,
            registered_bytes = fabric.registered_bytes(),
            tx_registered_bytes = fabric.tx_registered_bytes(),
            rx_registered_bytes = fabric.rx_registered_bytes(),
            pipeline_depth = urma_config.pipeline_depth,
            post_list_size = urma_config.post_list_size,
            "urma process registration budget ready"
        );
        collect_urma_registered_bytes_metrics(
            fabric.tx_registered_bytes(),
            fabric.rx_registered_bytes(),
        );
        let depths = send_depths(
            urma_config.max_inflight_chunks,
            fabric.max_tx_window_chunks(urma_config.pipeline_depth),
            fabric.max_native_send_depth(),
        );
        let peer_config = PeerTargetConfig {
            post_list_size: urma_config.post_list_size,
            pipeline_depth: urma_config.pipeline_depth,
            // This side only posts SEND. RX guarantees are registered by the
            // downloader-side PeerTarget created in `UrmaClientSession`.
            guaranteed_rx_credits: 0,
        };
        info!(
            native_send_depth = fabric.max_native_send_depth(),
            piece_window_chunks = depths.window_chunks,
            max_concurrent_transfers = urma_config.max_concurrent_transfers,
            pipeline_depth = urma_config.pipeline_depth,
            "configured URMA server send depths"
        );
        let read_parent = urma_config.read.as_ref().and_then(|read| {
            if read.provider_revocation_validated {
                Some(read_parent_config(read, &fabric, fabric_tag))
            } else {
                warn!(
                    "urma READ runtime is active but production publication is disabled until providerRevocationValidated is set"
                );
                None
            }
        });
        let publish_read = read_parent.is_some();
        let handler = Arc::new(UrmaServerHandler::new(
            self.storage.clone(),
            self.upload_bandwidth_limiter.clone(),
            fabric.clone(),
            capability.clone(),
            peer_config,
            depths.window_chunks,
            urma_config.transfer_timeout,
            urma_config.transfer_timeout,
            self.config.download.piece_timeout,
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
                read_port: if publish_read { self.addr.port() } else { 0 },
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
                        let timeout = urma_config.transfer_timeout;
                        connections.spawn(async move {
                            let mut stream = stream;
                            let _ = time::timeout(
                                timeout,
                                write_frame(
                                    &mut stream,
                                    &Frame::Error {
                                        transfer_id: SESSION_TRANSFER_ID,
                                        error: RendezvousError {
                                            code: ERROR_CODE_BUSY,
                                            message: "urma connection admission is full".to_string(),
                                        },
                                    },
                                ),
                            )
                            .await;
                        });
                        continue;
                    };
                    let handler = handler.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handler.handle(stream, remote_address.to_string()).await {
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
        fabric.shutdown().await.map_err(client_error)
    }
}

/// Storage-facing handler for one persistent URMA peer connection. Listener,
/// readiness publication and connection admission remain dfdaemon wiring
/// responsibilities; this type owns only the Piece upload contract.
struct UrmaServerHandler {
    storage: Arc<Storage>,
    upload_bandwidth_limiter: Arc<RateLimiter>,
    fabric: UrmaFabricHandle,
    capability: UrmaCapability,
    peer_config: PeerTargetConfig,
    max_send_inflight: u32,
    control_timeout: Duration,
    session_idle_timeout: Duration,
    transfer_timeout: Duration,
    piece_timeout: Duration,
    mmap_content: bool,
    max_concurrent_transfers: usize,
    transfer_admission: Arc<Semaphore>,
    required_tx_waiters: AtomicUsize,
    /// READ-only data plane. `None` rejects READ lanes at the version split.
    read: Option<ReadParentConfig>,
    retained_read_sources: Mutex<HashMap<u16, Vec<ReadSourceId>>>,
}

/// Parent-side READ lane parameters derived from the process configuration.
#[derive(Clone)]
struct ReadParentConfig {
    capability: ReadLaneCapability,
    _revocation_gate: ProviderRevocationValidated,
}

/// Startup evidence that the deployment provider passed the external source
/// revocation gate. It cannot be constructed from ReadDone/CancelDrained.
#[derive(Clone)]
struct ProviderRevocationValidated;

/// Converts the configured READ byte budgets into the runtime budget. Entry
/// counts follow the registered slot size so one entry equals one slot.
fn read_runtime_config(read: &UrmaReadServer) -> ClientResult<ReadRuntimeConfig> {
    ReadRuntimeConfig::try_from_config(read).map_err(client_error)
}

/// One-shot bearer token generator for READ source publications. Tokens are
/// process-unique so a stale offer can never arm a new export.
static NEXT_READ_TOKEN: AtomicU32 = AtomicU32::new(1);

fn next_read_token() -> ClientResult<u32> {
    allocate_read_token(&NEXT_READ_TOKEN)
}

fn allocate_read_token(counter: &AtomicU32) -> ClientResult<u32> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map_err(|_| ClientError::Unknown("urma READ token space exhausted".to_string()))
}

/// Builds the READ lane capability advertised during the version-5 handshake.
fn read_parent_config(
    read: &UrmaReadServer,
    fabric: &UrmaFabricHandle,
    fabric_tag: &str,
) -> ReadParentConfig {
    ReadParentConfig {
        capability: ReadLaneCapability {
            transport_type: fabric.transport_type(),
            tp_type: fabric.tp_type(),
            fabric_tag: fabric_tag.to_string(),
            read: ReadCapability {
                max_read_size: read.max_read_size.as_u64() as u32,
                max_jfs_sge: read.max_jfs_sge,
                descriptor_version: READ_DESCRIPTOR_VERSION,
            },
        },
        _revocation_gate: ProviderRevocationValidated,
    }
}

/// Peeks the shared 10-byte rendezvous envelope header without consuming it,
/// returning the wire version once a full header is buffered. `None` means the
/// peer closed before sending a header.
async fn peek_envelope_version(stream: &TcpStream, timeout: Duration) -> ClientResult<Option<u8>> {
    let deadline = time::Instant::now() + timeout;
    let mut header = [0u8; 10];
    loop {
        let filled = time::timeout_at(deadline, stream.peek(&mut header))
            .await
            .map_err(|_| ClientError::Unknown("urma envelope header peek timeout".to_string()))??;
        if filled >= header.len() {
            return Ok(Some(header[4]));
        }
        if filled == 0 {
            return Ok(None);
        }
    }
}

impl UrmaServerHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        storage: Arc<Storage>,
        upload_bandwidth_limiter: Arc<RateLimiter>,
        fabric: UrmaFabricHandle,
        capability: UrmaCapability,
        peer_config: PeerTargetConfig,
        max_send_inflight: u32,
        control_timeout: Duration,
        transfer_timeout: Duration,
        piece_timeout: Duration,
        mmap_content: bool,
        max_concurrent_transfers: usize,
        read: Option<ReadParentConfig>,
    ) -> Self {
        Self {
            storage,
            upload_bandwidth_limiter,
            fabric,
            capability,
            peer_config,
            max_send_inflight,
            control_timeout,
            session_idle_timeout: server_session_idle_timeout(control_timeout),
            transfer_timeout,
            piece_timeout,
            mmap_content,
            max_concurrent_transfers,
            transfer_admission: Arc::new(Semaphore::new(max_concurrent_transfers)),
            required_tx_waiters: AtomicUsize::new(0),
            read,
            retained_read_sources: Mutex::new(HashMap::new()),
        }
    }

    /// Accepts one peer lane and runs bounded concurrent Piece uploads. The
    /// lane dispatcher owns control I/O; each task owns one transfer state.
    #[instrument(skip_all, fields(remote_address))]
    async fn handle(
        self: Arc<Self>,
        stream: TcpStream,
        remote_address: String,
    ) -> ClientResult<()> {
        Span::current().record("remote_address", remote_address.as_str());
        // Version split: RM-READ lanes share the rendezvous MAGIC but speak
        // DFUR version 5. Peeking keeps the legacy session untouched.
        if let Some(version) = peek_envelope_version(&stream, self.control_timeout).await? {
            if version == READ_DFUR_VERSION {
                return self.handle_read_lane(stream, remote_address).await;
            }
        }
        let session = UrmaServerSession::accept(
            stream,
            self.fabric.clone(),
            self.peer_config,
            &self.capability,
            self.control_timeout,
            self.max_concurrent_transfers,
            self.max_send_inflight,
        )
        .await
        .map_err(client_error)?;

        let mut transfers = JoinSet::new();
        loop {
            let incoming = session.receive_request(self.session_idle_timeout).await;
            let Some((transfer, request)) = incoming.map_err(client_error)? else {
                if transfers.is_empty() {
                    debug!(
                        lane_id = session.lane_id(),
                        idle_timeout = ?self.session_idle_timeout,
                        "urma peer session idle timeout"
                    );
                    session.close().await.map_err(client_error)?;
                    return Ok(());
                }
                while let Some(completed) = transfers.join_next().await {
                    if let Err(error) = completed {
                        warn!(%error, "urma Piece upload task failed");
                    }
                }
                continue;
            };
            let piece_id = self
                .storage
                .piece_id(&request.task_id, request.piece_number);
            collect_upload_piece_started_metrics();
            info!(
                task_id = %request.task_id,
                piece_id = %piece_id,
                lane_id = session.lane_id(),
                transfer_id = transfer.transfer_id(),
                piece_kind = ?request.kind,
                piece_number = request.piece_number,
                "start upload piece content over urma"
            );
            let handler = self.clone();
            transfers
                .spawn(async move { handler.serve_transfer(transfer, request, piece_id).await });

            while let Some(completed) = transfers.try_join_next() {
                match completed {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        debug!(%error, "urma Piece upload ended with a Piece-local error");
                    }
                    Err(error) => warn!(%error, "urma Piece upload task failed"),
                }
            }
        }
    }

    async fn serve_transfer(
        self: Arc<Self>,
        mut transfer: UrmaServerTransfer,
        request: CommonPieceRequest,
        piece_id: String,
    ) -> ClientResult<()> {
        let lane_id = transfer.lane_id();
        let transfer_id = transfer.transfer_id();
        let admission_start = Instant::now();
        let Some(admission) = acquire_process_transfer(
            self.transfer_admission.clone(),
            PROCESS_TRANSFER_ADMISSION_GRACE,
        )
        .await
        else {
            let available_permits = self.transfer_admission.available_permits();
            let active_transfers = self
                .max_concurrent_transfers
                .saturating_sub(available_permits);
            debug!(
                lane_id,
                transfer_id,
                admission_limit = self.max_concurrent_transfers,
                available_permits,
                active_transfers,
                admission_wait_ns =
                    u64::try_from(admission_start.elapsed().as_nanos()).unwrap_or(u64::MAX),
                admission_grace_ms = PROCESS_TRANSFER_ADMISSION_GRACE.as_millis() as u64,
                admitted = false,
                "URMA process transfer admission is full after bounded wait"
            );
            collect_upload_piece_failure_metrics();
            transfer
                .reject_piece_transient(ERROR_CODE_BUSY, "URMA process transfer admission is full")
                .await
                .map_err(client_error)?;
            return Ok(());
        };
        let ProcessTransferAdmission {
            permit,
            waited,
            wait_ns,
        } = admission;
        if waited {
            let available_permits = self.transfer_admission.available_permits();
            debug!(
                lane_id,
                transfer_id,
                admission_limit = self.max_concurrent_transfers,
                available_permits,
                active_transfers = self
                    .max_concurrent_transfers
                    .saturating_sub(available_permits),
                admission_wait_ns = wait_ns,
                admitted = true,
                "URMA process transfer admitted after bounded wait"
            );
        }
        let permit = ProcessTransferPermitGuard::new(
            permit,
            self.transfer_admission.clone(),
            self.max_concurrent_transfers,
            lane_id,
            transfer_id,
        );
        let result = match time::timeout(
            self.piece_timeout,
            self.handle_piece(&mut transfer, &request, &piece_id, permit),
        )
        .await
        {
            Ok(Ok(Some(length))) => {
                collect_upload_piece_finished_metrics();
                collect_upload_piece_traffic_metrics(length);
                Ok(())
            }
            Ok(Ok(None)) => {
                collect_upload_piece_failure_metrics();
                Ok(())
            }
            Ok(Err(error)) => {
                collect_upload_piece_failure_metrics();
                Err(error)
            }
            Err(error) => {
                collect_upload_piece_failure_metrics();
                let message = format!(
                    "urma Piece transfer timed out after {:?}",
                    self.piece_timeout
                );
                let _ = transfer.abort_transfer(message).await;
                Err(error.into())
            }
        };
        result
    }

    // The per-Piece span is attached to this future via #[instrument], so it
    // is entered only while this future is polled. A manually held enter()
    // guard across the awaits leaked the thread-local span context into every
    // other task on the same worker (including the TCP accept loop), which
    // both accumulated fields into unrelated logs and eventually panicked the
    // subscriber with "tried to clone a span that already closed".
    #[instrument(skip_all, fields(task_id = %request.task_id, piece_id = %piece_id))]
    async fn handle_piece(
        &self,
        session: &mut UrmaServerTransfer,
        request: &CommonPieceRequest,
        piece_id: &str,
        process_permit: ProcessTransferPermitGuard,
    ) -> ClientResult<Option<u64>> {
        let piece_total_start = Instant::now();
        let piece = match self.piece_metadata(request.kind, piece_id) {
            Ok(Some(piece)) => piece,
            Ok(None) => {
                let message = format!("piece {piece_id} not found");
                session
                    .reject_piece(ERROR_CODE_NOT_FOUND, &message)
                    .await
                    .map_err(client_error)?;
                return Err(ClientError::PieceNotFound(piece_id.to_string()));
            }
            Err(error) => {
                let _ = session
                    .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                    .await;
                return Err(error);
            }
        };

        let piece_length = match usize::try_from(piece.length) {
            Ok(length) if length != 0 => length,
            _ => {
                let message = format!(
                    "piece {piece_id} has invalid or unaddressable length {}",
                    piece.length
                );
                session
                    .reject_piece(ERROR_CODE_TOO_LARGE, &message)
                    .await
                    .map_err(client_error)?;
                return Err(ClientError::Unknown(message));
            }
        };
        let (chunk_size, max_inflight_chunks) = match negotiate_transfer(
            request,
            self.capability.max_message_size,
            self.max_send_inflight,
        ) {
            Ok(parameters) => parameters,
            Err(error) => {
                let message = format!("piece {piece_id} has invalid URMA transfer parameters");
                session
                    .reject_piece(ERROR_CODE_INTERNAL, &message)
                    .await
                    .map_err(client_error)?;
                return Err(error);
            }
        };

        let limiter_start = Instant::now();
        self.upload_bandwidth_limiter.acquire(piece_length).await;
        let limiter_wait_ns = limiter_start.elapsed().as_nanos() as u64;
        let source_open_start = Instant::now();
        let mut source = match self.open_piece_source(request, piece_id).await {
            Ok(source) => source,
            Err(error) => {
                let _ = session
                    .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                    .await;
                return Err(error);
            }
        };
        let source_open_ns = source_open_start.elapsed().as_nanos() as u64;

        // TX ring observability. tx_ring_depth reports the effective ring
        // depth (2 only when at least one send overlapped a concurrent fill);
        // a single-window Piece trivially reports depth 1 without exercising
        // the ring. tx_second_lease_fallback marks a multi-window Piece that
        // ran with no spare lease (degraded ring=1 pipeline).
        let tx_source = if matches!(source, PieceSource::Mapped(_)) {
            "mmap"
        } else {
            "reader"
        };
        let mut tx_windows = 0u64;
        let mut tx_overlap_windows = 0u64;
        let mut tx_second_lease_fallback = false;
        let mut tx_fill_ns = 0u64;
        let mut tx_send_wait_ns = 0u64;
        let mut tx_required_acquire_attempts = 0u64;

        let first_lengths =
            tx_window_chunk_lengths(piece.length, chunk_size, max_inflight_chunks, 0)?;
        let tx_required_acquire_start = Instant::now();
        // Required windows wait for an existing owner to recycle its lease.
        // The allocator itself is intentionally non-blocking, so a timeout
        // around one call only bounded command latency and returned
        // BufferUnavailable immediately. While a required waiter exists,
        // optional second-ring allocations stand down to prevent starvation.
        let acquired = {
            let _waiter = RequiredTxWaiter::new(&self.required_tx_waiters);
            let deadline = time::Instant::now() + self.transfer_timeout;
            loop {
                let remaining = deadline.saturating_duration_since(time::Instant::now());
                if remaining.is_zero() {
                    break None;
                }
                tx_required_acquire_attempts += 1;
                match time::timeout(
                    remaining,
                    self.fabric.acquire_tx_window_chunks(first_lengths.clone()),
                )
                .await
                {
                    Ok(Err(UrmaError::BufferUnavailable { .. })) => {
                        time::sleep(REQUIRED_TX_RETRY_INTERVAL.min(remaining)).await;
                    }
                    Ok(result) => break Some(result),
                    Err(_) => break None,
                }
            }
        };
        let tx_required_acquire_ns = tx_required_acquire_start.elapsed().as_nanos() as u64;
        let mut current = match acquired {
            Some(Ok(lease)) => lease,
            Some(Err(error)) => {
                if matches!(error, UrmaError::BufferUnavailable { .. }) {
                    collect_urma_budget_pressure_metrics("tx", "required");
                    session
                        .reject_piece_transient(ERROR_CODE_BUSY, &error.to_string())
                        .await
                        .map_err(client_error)?;
                    return Ok(None);
                }
                let _ = session
                    .reject_piece(ERROR_CODE_TOO_LARGE, &error.to_string())
                    .await;
                return Err(client_error(error));
            }
            None => {
                let message = format!(
                    "URMA TX registration unavailable after {:?}",
                    self.transfer_timeout
                );
                collect_urma_budget_pressure_metrics("tx", "required");
                session
                    .reject_piece_transient(ERROR_CODE_BUSY, &message)
                    .await
                    .map_err(client_error)?;
                return Ok(None);
            }
        };
        let tx_required_pool_acquire_ns = current.pool_acquire_ns();
        let fill_start = Instant::now();
        if let Err(error) = source.fill(0, &mut current).await {
            let _ = session
                .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                .await;
            let _ = self.fabric.recycle_tx_window(current).await;
            return Err(error);
        }
        let tx_initial_fill_ns = fill_start.elapsed().as_nanos() as u64;
        tx_fill_ns += tx_initial_fill_ns;

        // A second exclusive lease is optional. Fixed pool pressure degrades
        // this transfer to a one-window pipeline without changing allocator
        // structure or blocking every admitted peer behind the ring.
        let first_window_len = current.len() as u64;
        let mut tx_optional_acquire_attempts = 0u64;
        let mut tx_optional_acquire_ns = 0u64;
        let mut tx_optional_pool_acquire_ns = 0u64;
        let mut spare = if self.peer_config.pipeline_depth > 1
            && first_window_len < piece.length
            && self.required_tx_waiters.load(Ordering::Acquire) == 0
        {
            let next_lengths = tx_window_chunk_lengths(
                piece.length,
                chunk_size,
                max_inflight_chunks,
                first_window_len,
            )?;
            let next_window_chunks = next_lengths.len();
            tx_optional_acquire_attempts += 1;
            let acquire_start = Instant::now();
            let acquire = self.fabric.try_acquire_tx_window_chunks(next_lengths).await;
            tx_optional_acquire_ns += acquire_start.elapsed().as_nanos() as u64;
            match acquire {
                Ok(lease) => {
                    tx_optional_pool_acquire_ns = lease.pool_acquire_ns();
                    debug!(
                        tx_ring_depth = 2,
                        window_chunks = next_window_chunks,
                        "URMA TX double ring enabled"
                    );
                    Some(lease)
                }
                Err(UrmaError::BufferUnavailable { .. }) => {
                    collect_urma_budget_pressure_metrics("tx", "optional");
                    debug!(
                        tx_ring_depth = 1,
                        "URMA TX second lease unavailable; falling back to single ring"
                    );
                    None
                }
                Err(error) => {
                    let _ = session
                        .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                        .await;
                    return Err(client_error(error));
                }
            }
        } else {
            if self.peer_config.pipeline_depth > 1
                && first_window_len < piece.length
                && self.required_tx_waiters.load(Ordering::Acquire) != 0
            {
                collect_urma_budget_pressure_metrics("tx", "optional");
                debug!(
                    tx_ring_depth = 1,
                    required_tx_waiters = self.required_tx_waiters.load(Ordering::Acquire),
                    "URMA TX second lease yielded to required waiter"
                );
            }
            None
        };
        let ready_start = Instant::now();
        session
            .ready(PieceMetadata {
                offset: piece.offset,
                length: piece.length,
                digest: piece.digest.clone(),
                chunk_size,
                max_inflight_chunks,
            })
            .await
            .map_err(client_error)?;
        let tx_ready_ns = ready_start.elapsed().as_nanos() as u64;

        let accumulate_send_timing =
            |total: &mut RegisteredSendTiming, timing: RegisteredSendTiming| {
                total.recv_posted_wait_ns += timing.recv_posted_wait_ns;
                total.grant_credit_ns += timing.grant_credit_ns;
                total.wr_post_ns += timing.wr_post_ns;
                total.send_cqe_wait_ns += timing.send_cqe_wait_ns;
            };
        let mut send_timing = RegisteredSendTiming::default();

        let mut sent = 0u64;
        while sent < piece.length {
            tx_windows += 1;
            let window_len = current.len() as u64;
            let next_offset = sent
                .checked_add(window_len)
                .ok_or(ClientError::InvalidParameter)?;
            if self.required_tx_waiters.load(Ordering::Acquire) != 0 {
                if let Some(lease) = spare.take() {
                    self.fabric
                        .recycle_tx_window(lease)
                        .await
                        .map_err(client_error)?;
                    collect_urma_budget_pressure_metrics("tx", "optional");
                    debug!(
                        tx_ring_depth = 1,
                        required_tx_waiters = self.required_tx_waiters.load(Ordering::Acquire),
                        "URMA TX released second lease for required waiter"
                    );
                }
            }
            if next_offset < piece.length {
                let next_lengths = tx_window_chunk_lengths(
                    piece.length,
                    chunk_size,
                    max_inflight_chunks,
                    next_offset,
                )?;
                if let Some(mut next) = spare.take() {
                    next.reshape(&next_lengths).map_err(client_error)?;
                    let send = async {
                        let start = Instant::now();
                        let result = session
                            .send_next_registered_window(current, self.transfer_timeout)
                            .await;
                        (start.elapsed().as_nanos() as u64, result)
                    };
                    let next_offset =
                        usize::try_from(next_offset).map_err(|_| ClientError::InvalidParameter)?;
                    let fill = async {
                        let start = Instant::now();
                        let result = source.fill(next_offset, &mut next).await;
                        (start.elapsed().as_nanos() as u64, result)
                    };
                    let ((send_ns, send_result), (fill_ns, fill_result)) = tokio::join!(send, fill);
                    tx_send_wait_ns += send_ns;
                    tx_fill_ns += fill_ns;
                    tx_overlap_windows += 1;
                    let (returned, timing) = send_result.map_err(client_error)?;
                    accumulate_send_timing(&mut send_timing, timing);
                    if let Err(error) = fill_result {
                        let _ = session
                            .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                            .await;
                        let _ = self.fabric.recycle_tx_window(returned).await;
                        let _ = self.fabric.recycle_tx_window(next).await;
                        return Err(error);
                    }
                    current = next;
                    spare = Some(returned);
                } else {
                    tx_second_lease_fallback = true;
                    let send_start = Instant::now();
                    let (mut returned, timing) = session
                        .send_next_registered_window(current, self.transfer_timeout)
                        .await
                        .map_err(client_error)?;
                    accumulate_send_timing(&mut send_timing, timing);
                    tx_send_wait_ns += send_start.elapsed().as_nanos() as u64;
                    returned.reshape(&next_lengths).map_err(client_error)?;
                    let fill_start = Instant::now();
                    if let Err(error) = source
                        .fill(
                            usize::try_from(next_offset)
                                .map_err(|_| ClientError::InvalidParameter)?,
                            &mut returned,
                        )
                        .await
                    {
                        let _ = session
                            .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                            .await;
                        let _ = self.fabric.recycle_tx_window(returned).await;
                        return Err(error);
                    }
                    tx_fill_ns += fill_start.elapsed().as_nanos() as u64;
                    current = returned;
                }
            } else {
                let send_start = Instant::now();
                let (returned, timing) = session
                    .send_next_registered_window(current, self.transfer_timeout)
                    .await
                    .map_err(client_error)?;
                current = returned;
                accumulate_send_timing(&mut send_timing, timing);
                tx_send_wait_ns += send_start.elapsed().as_nanos() as u64;
            }
            sent = sent
                .checked_add(window_len)
                .ok_or(ClientError::InvalidParameter)?;
        }
        if sent != piece.length {
            return Err(ClientError::Unknown(format!(
                "urma upload length mismatch: expected {}, sent {sent}",
                piece.length
            )));
        }
        self.fabric
            .recycle_tx_window(current)
            .await
            .map_err(client_error)?;
        if let Some(spare) = spare {
            self.fabric
                .recycle_tx_window(spare)
                .await
                .map_err(client_error)?;
        }
        // Once all data WRs have completed and their registered TX leases are
        // recycled, this transfer no longer consumes process data-path
        // capacity. Release admission before queuing Done: the client cannot
        // start its replacement Piece until it receives that terminal frame,
        // so this ordering removes permit hand-off lag without exceeding the
        // configured number of active data transfers. Error and cancellation
        // paths retain RAII release through ProcessTransferPermitGuard::drop.
        drop(process_permit);
        let done_start = Instant::now();
        session.finish_piece().await.map_err(client_error)?;
        let tx_done_ns = done_start.elapsed().as_nanos() as u64;
        let tx_recv_posted_wait_ns = send_timing.recv_posted_wait_ns;
        let tx_grant_credit_ns = send_timing.grant_credit_ns;
        let tx_wr_post_ns = send_timing.wr_post_ns;
        let tx_send_cqe_wait_ns = send_timing.send_cqe_wait_ns;
        let piece_total_ns = piece_total_start.elapsed().as_nanos() as u64;
        let tx_ring_depth = if tx_overlap_windows > 0 { 2 } else { 1 };
        debug!(
            lane_id = session.lane_id(),
            piece_id,
            tx_source,
            tx_windows,
            tx_ring_depth,
            tx_overlap_windows,
            tx_second_lease_fallback,
            configured_pipeline_depth = self.peer_config.pipeline_depth,
            max_window_chunks = self.max_send_inflight,
            limiter_wait_ns,
            source_open_ns,
            tx_ready_ns,
            tx_initial_fill_ns,
            tx_fill_ns,
            tx_send_wait_ns,
            tx_required_acquire_attempts,
            tx_required_acquire_ns,
            tx_required_pool_acquire_ns,
            tx_optional_acquire_attempts,
            tx_optional_acquire_ns,
            tx_optional_pool_acquire_ns,
            tx_recv_posted_wait_ns,
            tx_grant_credit_ns,
            tx_wr_post_ns,
            tx_send_cqe_wait_ns,
            tx_done_ns,
            piece_total_ns,
            "finished uploading piece content over urma"
        );
        Ok(Some(piece.length))
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

    async fn open_piece_source(
        &self,
        request: &CommonPieceRequest,
        piece_id: &str,
    ) -> ClientResult<PieceSource> {
        if self.mmap_content {
            match self
                .storage
                .map_upload_piece(piece_id, &request.task_id, request.kind)
                .await
            {
                Ok(mapped) => {
                    debug!(piece_id, "URMA upload using mmap content");
                    return Ok(PieceSource::Mapped(mapped));
                }
                Err(error) => {
                    warn!(piece_id, %error, "URMA mmap unavailable; falling back to reader");
                }
            }
        }
        let reader = match request.kind {
            PieceKind::Piece => self
                .storage
                .upload_piece(piece_id, &request.task_id, None)
                .await
                .map(|(_, reader)| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
            PieceKind::PersistentPiece => self
                .storage
                .upload_persistent_piece(piece_id, &request.task_id, None)
                .await
                .map(|(_, reader)| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
            PieceKind::PersistentCachePiece => self
                .storage
                .upload_persistent_cache_piece(piece_id, &request.task_id, None)
                .await
                .map(|(_, reader)| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
        }?;
        Ok(PieceSource::Reader(reader))
    }

    /// Serves one RM-READ lane: version-5 handshake, Child-side Jetty import, and
    /// Child-initiated transfer admission. Only control frames use this TCP
    /// stream; Piece bytes move inside the registered READ budget.
    async fn handle_read_lane(
        self: Arc<Self>,
        mut stream: TcpStream,
        remote_address: String,
    ) -> ClientResult<()> {
        let Some(read) = self.read.clone() else {
            debug!(%remote_address, "rejecting READ lane: READ plane is not configured");
            return Ok(());
        };
        let connect = match time::timeout(self.control_timeout, read_handshake(&mut stream)).await {
            Ok(Ok(connect)) => connect,
            Ok(Err(error)) => return Err(client_error(error)),
            Err(_) => {
                return Err(ClientError::Unknown(
                    "urma READ lane handshake timeout".to_string(),
                ));
            }
        };
        let (session_generation, effective_max_read_size, _) = connect
            .validate_connect(&read.capability)
            .map_err(client_error)?;

        // READ has a fixed one-sided direction. The Child imports this local
        // endpoint and posts READs; the Parent only registers source memory,
        // so importing the Child Jetty would create an unused reverse target.
        let (lane_id, parent_descriptor) = self
            .fabric
            .create_lane(self.peer_config)
            .await
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
            let _ = self.fabric.close_lane(lane_id).await;
            return Err(client_error(error));
        }
        info!(
            %remote_address,
            lane_id,
            session_generation,
            max_read_size = effective_max_read_size,
            "urma READ lane established"
        );

        let lane = match ReadLaneControl::spawn(
            stream,
            session_generation,
            self.max_concurrent_transfers,
            self.max_concurrent_transfers.saturating_mul(2).max(16),
        ) {
            Ok(lane) => lane,
            Err(error) => {
                let _ = self.fabric.close_lane(lane_id).await;
                return Err(client_error(error));
            }
        };
        let mut transfers = JoinSet::new();
        loop {
            let Some(accepted) = lane.accept_transfer(self.session_idle_timeout).await else {
                while transfers.join_next().await.is_some() {}
                debug!(lane_id, "urma READ lane closed or idle");
                break;
            };
            let handler = self.clone();
            transfers.spawn(async move {
                if let Err(error) = handler
                    .serve_read_transfer(lane_id, effective_max_read_size, accepted)
                    .await
                {
                    debug!(%error, "urma READ transfer ended with a Piece-local error");
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
    /// provider-revocation gate. The shim copies the source bytes into its
    /// page-aligned registration, so Storage mmap/reader stays authoritative.
    async fn serve_read_transfer(
        self: Arc<Self>,
        lane_id: u16,
        effective_max_read_size: u32,
        accepted: AcceptedReadTransfer,
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
        let source_e2e_start = Instant::now();
        info!(
            task_id = %locator.task_id,
            piece_id,
            lane_id,
            "start READ upload piece content"
        );
        let Some(piece) = self.piece_metadata(locator.kind, &piece_id)? else {
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
        let (session, locator) = ParentSourceSession::accept(
            self.fabric.clone(),
            lane_id,
            accepted.control,
            accepted.buffer_ready,
            piece.offset,
            piece.digest.clone(),
            effective_max_read_size,
        )
        .map_err(client_error)?;
        let source_request = CommonPieceRequest {
            kind: locator.kind,
            task_id: locator.task_id.clone(),
            piece_number: locator.piece_number,
            chunk_size: piece.length,
            max_inflight_chunks: 1,
        };
        let source_open_start = Instant::now();
        let source = self.open_piece_source(&source_request, &piece_id).await?;
        let source_open_ns = source_open_start.elapsed().as_nanos() as u64;
        let source_copy_start = Instant::now();
        let memory = match source {
            PieceSource::Mapped(mapped) => {
                // The shim copies synchronously during register, so the mapped
                // region only needs to outlive that call. Skip the 16MiB copy.
                if mapped.as_slice().len() as u64 != accepted_length {
                    return Err(ClientError::Unknown(format!(
                        "READ piece {piece_id} source bytes {} diverge from accepted length {accepted_length}",
                        mapped.as_slice().len()
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

        // SAFETY: The version-5 handshake authenticated this lane and the
        // accepted length was proven to match the immutable Storage Piece.
        let (parent, pending) = match unsafe {
            session.publish_and_wait_read_done(ReadSourceRequest {
                peer_id: lane_id,
                backing: ReadBacking::new(memory, ()),
                token,
            })
        }
        .await
        {
            Ok(published) => published,
            Err(failure) => {
                if let Some(retained) = failure.retained_source {
                    // Fail closed: the source stays registered and budgeted
                    // until lane close plus the provider gate proves revocation.
                    self.retained_read_sources
                        .lock()
                        .await
                        .entry(lane_id)
                        .or_default()
                        .push(retained.source_id);
                    warn!(piece_id, "urma READ source owner retained for cleanup");
                }
                return Err(client_error(failure.error));
            }
        };
        collect_upload_piece_traffic_metrics(pending.completed_length);
        info!(
            piece_id,
            source_e2e_ns = source_e2e_start.elapsed().as_nanos() as u64,
            source_open_ns,
            source_copy_ns,
            register_ns = pending.register_ns,
            wait_read_done_ns = pending.wait_read_done_ns,
            "urma READ source fully read; revoking export"
        );

        // SAFETY: Construction of this handler required the deployment's
        // explicit provider-revocation gate. ReadDone/CancelDrained supplies
        // the cooperative Child drain, while the validated provider contract
        // supplies the independent guarantee that successful unregister makes
        // this descriptor/token generation unable to resume remote access.
        let revoke_start = Instant::now();
        unsafe { parent.revoke_and_finish(pending).await }.map_err(client_error)?;
        info!(
            piece_id,
            revoke_ns = revoke_start.elapsed().as_nanos() as u64,
            "urma READ source revoke finished"
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
            .await
            .remove(&lane_id)
            .unwrap_or_default();
        let mut retained = Vec::new();
        let mut first_error = None;
        for source_id in sources {
            let result = async {
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
            }
            .await;
            if let Err(error) = result {
                if first_error.is_none() {
                    first_error = Some(error.to_string());
                }
                retained.push(source_id);
            }
        }
        if !retained.is_empty() {
            self.retained_read_sources
                .lock()
                .await
                .insert(lane_id, retained);
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
    use tokio::io::AsyncWriteExt;

    fn request(chunk_size: u64, max_inflight_chunks: u32) -> CommonPieceRequest {
        CommonPieceRequest {
            kind: PieceKind::Piece,
            task_id: "task".into(),
            piece_number: 1,
            chunk_size,
            max_inflight_chunks,
        }
    }

    #[test]
    fn server_negotiation_caps_message_and_send_depth() {
        assert_eq!(
            negotiate_transfer(&request(256 * 1024, 64), 64 * 1024, 8).unwrap(),
            (64 * 1024, 8)
        );
    }

    #[test]
    fn send_window_is_bounded_by_registered_and_shared_capacity() {
        assert_eq!(send_depths(32, 64, 128), SendDepths { window_chunks: 32 });
        assert_eq!(send_depths(32, 16, 128), SendDepths { window_chunks: 16 });
        assert_eq!(send_depths(32, 64, 8), SendDepths { window_chunks: 8 });
    }

    #[test]
    fn server_negotiation_rejects_zero_limits() {
        assert!(negotiate_transfer(&request(0, 1), 64 * 1024, 8).is_err());
        assert!(negotiate_transfer(&request(64 * 1024, 0), 64 * 1024, 8).is_err());
        assert!(negotiate_transfer(&request(64 * 1024, 1), 0, 8).is_err());
        assert!(negotiate_transfer(&request(64 * 1024, 1), 64 * 1024, 0).is_err());
    }

    #[test]
    fn tx_window_lengths_keep_chunks_in_distinct_slots_and_trim_tail() {
        assert_eq!(tx_window_chunk_lengths(13, 4, 2, 0).unwrap(), vec![4, 4]);
        assert_eq!(tx_window_chunk_lengths(13, 4, 2, 8).unwrap(), vec![4, 1]);
        assert!(tx_window_chunk_lengths(13, 4, 2, 13).is_err());
    }

    #[test]
    fn required_tx_waiter_is_removed_when_its_scope_ends() {
        let waiters = AtomicUsize::new(0);
        {
            let _first = RequiredTxWaiter::new(&waiters);
            assert_eq!(waiters.load(Ordering::Acquire), 1);
            {
                let _second = RequiredTxWaiter::new(&waiters);
                assert_eq!(waiters.load(Ordering::Acquire), 2);
            }
            assert_eq!(waiters.load(Ordering::Acquire), 1);
        }
        assert_eq!(waiters.load(Ordering::Acquire), 0);
    }

    #[test]
    fn read_token_allocator_never_wraps_or_reuses_zero() {
        let counter = AtomicU32::new(u32::MAX - 1);
        assert_eq!(allocate_read_token(&counter).unwrap(), u32::MAX - 1);
        assert!(allocate_read_token(&counter).is_err());
        assert_eq!(counter.load(Ordering::Acquire), u32::MAX);
    }

    #[tokio::test]
    async fn process_transfer_admission_succeeds_without_waiting_and_releases() {
        let admission = Arc::new(Semaphore::new(1));
        let acquired = acquire_process_transfer(admission.clone(), Duration::from_millis(10))
            .await
            .unwrap();
        let ProcessTransferAdmission {
            permit,
            waited,
            wait_ns,
        } = acquired;
        let permit = ProcessTransferPermitGuard::new(permit, admission.clone(), 1, 7, 11);

        assert!(!waited);
        assert_eq!(wait_ns, 0);
        assert_eq!(admission.available_permits(), 0);
        drop(permit);
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn process_transfer_admission_waits_for_a_released_permit() {
        let admission = Arc::new(Semaphore::new(1));
        let held = admission.clone().acquire_owned().await.unwrap();
        let release = tokio::spawn(async move {
            time::sleep(Duration::from_millis(2)).await;
            drop(held);
        });

        let acquired = acquire_process_transfer(admission.clone(), Duration::from_millis(100))
            .await
            .unwrap();
        let ProcessTransferAdmission {
            permit,
            waited,
            wait_ns,
        } = acquired;
        let permit = ProcessTransferPermitGuard::new(permit, admission.clone(), 1, 7, 12);

        assert!(waited);
        assert!(wait_ns > 0);
        assert_eq!(admission.available_permits(), 0);
        drop(permit);
        release.await.unwrap();
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn process_transfer_admission_times_out_without_leaking_a_permit() {
        let admission = Arc::new(Semaphore::new(1));
        let held = admission.clone().acquire_owned().await.unwrap();

        assert!(
            acquire_process_transfer(admission.clone(), Duration::from_millis(1))
                .await
                .is_none()
        );
        assert_eq!(admission.available_permits(), 0);
        drop(held);
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn reader_source_fills_registered_chunk_spans_directly() {
        let (mut writer, reader) = tokio::io::duplex(16);
        let write = tokio::spawn(async move {
            writer.write_all(b"direct!").await.unwrap();
        });
        let mut source = PieceSource::Reader(Box::new(reader));
        let mut lease = TxWindowLease::from_test_lengths(vec![4, 3]);

        source.fill(0, &mut lease).await.unwrap();
        write.await.unwrap();

        assert_eq!(lease.part_mut(0).unwrap(), b"dire");
        assert_eq!(lease.part_mut(1).unwrap(), b"ct!");
    }
}
