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
use crate::urma::fabric::{FabricReadiness, UrmaFabric, UrmaFabricHandle, UrmaLaneConfig};
use crate::urma::rendezvous::{
    write_frame, CapabilityRegistry, CommonPieceRequest, Frame, PieceMetadata, RendezvousError,
    UrmaAdvertisement, UrmaCapability,
};
use crate::urma::server_session_idle_timeout;
use crate::urma::session::{RegisteredSendTiming, UrmaServerSession};
use crate::urma::Error as UrmaError;
use crate::urma::TxWindowLease;
use crate::Storage;
use dragonfly_client_config::dfdaemon::Config;
use dragonfly_client_core::{Error as ClientError, Result as ClientResult};
use dragonfly_client_metric::{
    collect_upload_piece_failure_metrics, collect_upload_piece_finished_metrics,
    collect_upload_piece_started_metrics, collect_upload_piece_traffic_metrics,
};
use leaky_bucket::RateLimiter;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{debug, error, info, info_span, instrument, warn, Span};

use dragonfly_client_util::shutdown;

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

        let fabric =
            UrmaFabric::get_or_start(device, urma_config.eid_index).map_err(client_error)?;
        let capability = UrmaCapability {
            transport_type: fabric.transport_type(),
            fabric_tag: fabric_tag.to_string(),
            max_message_size: fabric.max_message_size(),
        };
        let lane_config = UrmaLaneConfig {
            send_depth: urma_config
                .max_inflight_chunks
                .min(fabric.max_tx_window_chunks()),
            recv_depth: urma_config.max_inflight_chunks,
            ..Default::default()
        };
        let handler = Arc::new(UrmaServerHandler::new(
            self.storage.clone(),
            self.upload_bandwidth_limiter.clone(),
            fabric.clone(),
            capability.clone(),
            lane_config,
            urma_config.transfer_timeout,
            urma_config.transfer_timeout,
            self.config.download.piece_timeout,
            urma_config.mmap_content,
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
                                    &Frame::Error(RendezvousError {
                                        code: ERROR_CODE_BUSY,
                                        message: "urma connection admission is full".to_string(),
                                    }),
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
    lane_config: UrmaLaneConfig,
    control_timeout: Duration,
    session_idle_timeout: Duration,
    transfer_timeout: Duration,
    piece_timeout: Duration,
    mmap_content: bool,
}

impl UrmaServerHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        storage: Arc<Storage>,
        upload_bandwidth_limiter: Arc<RateLimiter>,
        fabric: UrmaFabricHandle,
        capability: UrmaCapability,
        lane_config: UrmaLaneConfig,
        control_timeout: Duration,
        transfer_timeout: Duration,
        piece_timeout: Duration,
        mmap_content: bool,
    ) -> Self {
        Self {
            storage,
            upload_bandwidth_limiter,
            fabric,
            capability,
            lane_config,
            control_timeout,
            session_idle_timeout: server_session_idle_timeout(control_timeout),
            transfer_timeout,
            piece_timeout,
            mmap_content,
        }
    }

    /// Accepts one peer lane and serves sequential Piece requests until the
    /// peer disconnects or a conservative Phase A error retires the session.
    #[instrument(skip_all, fields(remote_address))]
    async fn handle(&self, stream: TcpStream, remote_address: String) -> ClientResult<()> {
        Span::current().record("remote_address", remote_address.as_str());
        let mut session = UrmaServerSession::accept(
            stream,
            self.fabric.clone(),
            self.lane_config,
            &self.capability,
            self.control_timeout,
        )
        .await
        .map_err(client_error)?;

        loop {
            let Some(request) = session
                .receive_request(self.session_idle_timeout)
                .await
                .map_err(client_error)?
            else {
                debug!(
                    lane_id = session.lane_id().unwrap_or_default(),
                    idle_timeout = ?self.session_idle_timeout,
                    "urma peer session idle timeout"
                );
                session.close().await.map_err(client_error)?;
                return Ok(());
            };
            let piece_id = self
                .storage
                .piece_id(&request.task_id, request.piece_number);
            // Per-Piece span with fields fixed at creation. Recording
            // task_id/piece_id repeatedly on the connection span made fmt
            // subscribers print every recorded value, so logs accumulated
            // one (task_id, piece_id) pair per served Piece.
            let piece_span =
                info_span!("urma_piece", task_id = %request.task_id, piece_id = %piece_id);
            let _piece_guard = piece_span.enter();

            collect_upload_piece_started_metrics();
            info!(
                lane_id = session.lane_id().unwrap_or_default(),
                piece_kind = ?request.kind,
                piece_number = request.piece_number,
                "start upload piece content over urma"
            );
            match time::timeout(
                self.piece_timeout,
                self.handle_piece(&mut session, &request, &piece_id),
            )
            .await
            {
                Ok(Ok(length)) => {
                    collect_upload_piece_finished_metrics();
                    collect_upload_piece_traffic_metrics(length);
                }
                Ok(Err(error)) => {
                    collect_upload_piece_failure_metrics();
                    return Err(error);
                }
                Err(error) => {
                    collect_upload_piece_failure_metrics();
                    let message = format!(
                        "urma Piece transfer timed out after {:?}",
                        self.piece_timeout
                    );
                    let _ = session.reject_piece(ERROR_CODE_INTERNAL, &message).await;
                    return Err(error.into());
                }
            }
        }
    }

    async fn handle_piece(
        &self,
        session: &mut UrmaServerSession<TcpStream>,
        request: &CommonPieceRequest,
        piece_id: &str,
    ) -> ClientResult<u64> {
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
            self.lane_config.send_depth,
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

        let first_lengths =
            tx_window_chunk_lengths(piece.length, chunk_size, max_inflight_chunks, 0)?;
        let acquired = time::timeout(
            self.transfer_timeout,
            self.fabric.acquire_tx_window_chunks(first_lengths),
        )
        .await;
        let mut current = match acquired {
            Ok(Ok(lease)) => lease,
            Ok(Err(error)) => {
                let code = if matches!(error, UrmaError::BufferUnavailable { .. }) {
                    ERROR_CODE_BUSY
                } else {
                    ERROR_CODE_TOO_LARGE
                };
                let _ = session.reject_piece(code, &error.to_string()).await;
                return Err(client_error(error));
            }
            Err(_) => {
                let message = format!(
                    "URMA TX registration unavailable after {:?}",
                    self.transfer_timeout
                );
                let _ = session.reject_piece(ERROR_CODE_BUSY, &message).await;
                return Err(ClientError::Unknown(message));
            }
        };
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
        let mut spare = if first_window_len < piece.length {
            let next_lengths = tx_window_chunk_lengths(
                piece.length,
                chunk_size,
                max_inflight_chunks,
                first_window_len,
            )?;
            let next_window_chunks = next_lengths.len();
            match time::timeout(
                self.transfer_timeout,
                self.fabric.acquire_tx_window_chunks(next_lengths),
            )
            .await
            {
                Ok(Ok(lease)) => {
                    debug!(
                        tx_ring_depth = 2,
                        window_chunks = next_window_chunks,
                        "URMA TX double ring enabled"
                    );
                    Some(lease)
                }
                Ok(Err(UrmaError::BufferUnavailable { .. })) | Err(_) => {
                    debug!(
                        tx_ring_depth = 1,
                        "URMA TX second lease unavailable; falling back to single ring"
                    );
                    None
                }
                Ok(Err(error)) => {
                    let _ = session
                        .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                        .await;
                    return Err(client_error(error));
                }
            }
        } else {
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
            lane_id = session.lane_id().unwrap_or_default(),
            piece_id,
            tx_source,
            tx_windows,
            tx_ring_depth,
            tx_overlap_windows,
            tx_second_lease_fallback,
            limiter_wait_ns,
            source_open_ns,
            tx_ready_ns,
            tx_initial_fill_ns,
            tx_fill_ns,
            tx_send_wait_ns,
            tx_recv_posted_wait_ns,
            tx_grant_credit_ns,
            tx_wr_post_ns,
            tx_send_cqe_wait_ns,
            tx_done_ns,
            piece_total_ns,
            "finished uploading piece content over urma"
        );
        Ok(piece.length)
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
                .map(|reader| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
            PieceKind::PersistentPiece => self
                .storage
                .upload_persistent_piece(piece_id, &request.task_id, None)
                .await
                .map(|reader| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
            PieceKind::PersistentCachePiece => self
                .storage
                .upload_persistent_cache_piece(piece_id, &request.task_id, None)
                .await
                .map(|reader| Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>),
        }?;
        Ok(PieceSource::Reader(reader))
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
