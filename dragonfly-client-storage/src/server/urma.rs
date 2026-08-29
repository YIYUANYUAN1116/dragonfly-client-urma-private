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

use crate::rendezvous::{
    PieceKind, ERROR_CODE_BUSY, ERROR_CODE_INTERNAL, ERROR_CODE_NOT_FOUND, ERROR_CODE_TOO_LARGE,
};
use crate::urma::fabric::{FabricReadiness, UrmaFabric, UrmaFabricHandle, UrmaLaneConfig};
use crate::urma::rendezvous::{
    write_frame, CapabilityRegistry, CommonPieceRequest, Frame, PieceMetadata, RendezvousError,
    UrmaAdvertisement, UrmaCapability,
};
use crate::urma::server_session_idle_timeout;
use crate::urma::session::UrmaServerSession;
use crate::urma::Error as UrmaError;
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
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time;
use tracing::{debug, error, info, instrument, warn, Span};

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
        let mut lane_config = UrmaLaneConfig::default();
        lane_config.send_depth = urma_config.max_inflight_chunks;
        lane_config.recv_depth = urma_config.max_inflight_chunks;
        let handler = Arc::new(UrmaServerHandler::new(
            self.storage.clone(),
            self.upload_bandwidth_limiter.clone(),
            fabric.clone(),
            capability.clone(),
            lane_config,
            urma_config.transfer_timeout,
            urma_config.transfer_timeout,
            self.config.download.piece_timeout,
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
        }
    }

    /// Accepts one peer lane and serves sequential Piece requests until the
    /// peer disconnects or a conservative Phase A error retires the session.
    #[instrument(skip_all, fields(remote_address, task_id, piece_id))]
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
            Span::current().record("task_id", request.task_id.as_str());
            Span::current().record("piece_id", piece_id.as_str());

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

        self.upload_bandwidth_limiter.acquire(piece_length).await;
        let mut reader = match self.open_piece_reader(request, piece_id).await {
            Ok(reader) => reader,
            Err(error) => {
                let _ = session
                    .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                    .await;
                return Err(error);
            }
        };
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

        // Reuse one bounded owned window. Session splits it into registered TX
        // slots and waits for all SEND completions before this buffer is filled
        // again, so RangeReader and native buffer lifetimes never overlap.
        let mut window = Vec::new();
        let mut sent = 0u64;
        while sent < piece.length {
            let window_len = session.next_window_len().map_err(client_error)?;
            window.resize(window_len, 0);
            if let Err(error) = reader.read_exact(&mut window).await {
                let _ = session
                    .reject_piece(ERROR_CODE_INTERNAL, &error.to_string())
                    .await;
                return Err(error.into());
            }
            session
                .send_next_window(&window, self.transfer_timeout)
                .await
                .map_err(client_error)?;
            sent = sent
                .checked_add(window_len as u64)
                .ok_or(ClientError::InvalidParameter)?;
        }
        if sent != piece.length {
            return Err(ClientError::Unknown(format!(
                "urma upload length mismatch: expected {}, sent {sent}",
                piece.length
            )));
        }
        session.finish_piece().await.map_err(client_error)?;
        debug!(
            lane_id = session.lane_id().unwrap_or_default(),
            piece_id, "finished uploading piece content over urma"
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

    async fn open_piece_reader(
        &self,
        request: &CommonPieceRequest,
        piece_id: &str,
    ) -> ClientResult<Box<dyn AsyncRead + Send + Unpin>> {
        match request.kind {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
