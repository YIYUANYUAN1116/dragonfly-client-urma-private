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

use super::PieceContentStream;
use crate::rendezvous::{PieceKind, ERROR_CODE_INCOMPATIBLE};
use crate::urma::fabric::{UrmaFabricHandle, UrmaLaneConfig};
use crate::urma::rendezvous::{
    read_frame, write_frame, CommonPieceRequest, Frame, UrmaAdvertisement, UrmaCapability,
};
use crate::urma::session::UrmaClientSession;
use crate::urma::Error as UrmaError;
use bytes::Bytes;
use dragonfly_client_config::dfdaemon::Config;
use dragonfly_client_core::{Error as ClientError, Result as ClientResult};
use futures::channel::mpsc;
use futures::SinkExt;
use futures::StreamExt;
use socket2::{SockRef, TcpKeepalive};
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time;
use tracing::{debug, error, instrument, Span};

/// Cap of concurrent receive windows buffered between the transfer task and the
/// storage writer, mirroring the TCP/QUIC client backpressure.
const WINDOW_CHANNEL_CAPACITY: usize = 2;

const TRANSFER_HEALTHY: u8 = 0;
const TRANSFER_ACTIVE: u8 = 1;
const TRANSFER_SUCCEEDED: u8 = 2;
const TRANSFER_FAILED: u8 = 3;

type SessionSlot = Arc<tokio::sync::Mutex<Option<UrmaClientSession<TcpStream>>>>;

/// discover asks the parent's already-advertised TCP piece endpoint for its live
/// URMA capability and rendezvous port. Non-URMA peers simply fail this optional
/// probe, leaving the downloader to fall back to the TCP piece transport.
#[instrument(skip_all, fields(parent_addr))]
pub async fn discover(addr: &str, timeout: Duration) -> ClientResult<UrmaAdvertisement> {
    Span::current().record("parent_addr", addr);
    time::timeout(timeout, async {
        let stream = TcpStream::connect(addr).await?;
        let socket = SockRef::from(&stream);
        socket.set_tcp_nodelay(true)?;
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_interval(super::DEFAULT_KEEPALIVE_INTERVAL)
                .with_time(super::DEFAULT_KEEPALIVE_TIME)
                .with_retries(super::DEFAULT_KEEPALIVE_RETRIES),
        )?;
        let (mut reader, mut writer) = stream.into_split();
        write_frame(&mut writer, &Frame::Discover).await?;
        match read_frame(&mut reader).await? {
            Frame::Capability(advertisement) if advertisement.port != 0 => Ok(advertisement),
            Frame::Capability(_) => Err(ClientError::Unsupported(
                "parent advertised an invalid urma rendezvous port".to_string(),
            )),
            Frame::Error(err) if err.code == ERROR_CODE_INCOMPATIBLE => {
                Err(ClientError::Unsupported(err.message))
            }
            Frame::Error(err) => Err(ClientError::Unknown(format!(
                "urma discovery error {}: {}",
                err.code, err.message
            ))),
            frame => Err(ClientError::Unknown(format!(
                "unexpected urma discovery frame: {frame:?}"
            ))),
        }
    })
    .await?
}

/// Maps the storage-internal [`UrmaError`] onto the core client error so URMA
/// failures fall back to the TCP piece transport exactly like RDMA.
fn urma_error(error: UrmaError) -> ClientError {
    match error {
        UrmaError::PeerRejected { code, message } if code == ERROR_CODE_INCOMPATIBLE => {
            ClientError::Unsupported(message)
        }
        UrmaError::PeerRejected { code, message } => {
            ClientError::Unknown(format!("urma peer rejected ({code}): {message}"))
        }
        other => ClientError::Unknown(other.to_string()),
    }
}

/// UrmaClient downloads pieces over UMDK/URMA: control frames ride a TCP
/// rendezvous connection to the parent's URMA port, bulk bytes arrive over a
/// bound RC Jetty as copy-received windows. Each error must let the caller fall
/// back to the TCP piece transport; URMA never has to succeed for a piece to
/// complete.
#[derive(Clone)]
pub struct UrmaClient {
    /// config is the configuration of the dfdaemon.
    config: Arc<Config>,

    /// fabric is the process-shared, Tokio-safe URMA facade.
    fabric: UrmaFabricHandle,

    /// capability is the local side of capability negotiation.
    capability: UrmaCapability,

    /// lane_config sizes the Jetty created for each transfer.
    lane_config: UrmaLaneConfig,

    /// remote_capability is the parent's advertised capability from `discover`.
    remote_capability: UrmaCapability,

    /// addr is the address of the parent's URMA rendezvous server.
    addr: String,

    /// control_timeout bounds the DFUR control handshake and per-window waits.
    control_timeout: Duration,

    /// transfer_timeout bounds each posted receive window's completion wait.
    transfer_timeout: Duration,

    /// session owns the one persistent control connection and RC lane used for
    /// sequential Piece transfers to this parent.
    session: SessionSlot,

    /// transfer_state lets the downloader observe failures that happen after
    /// this method has returned the streaming body.
    transfer_state: Arc<AtomicU8>,
}

/// UrmaClient implements the UMDK/URMA piece download client.
impl UrmaClient {
    /// Creates a new UrmaClient for one parent address. The remote capability
    /// is obtained from [`discover`] by the downloader before construction.
    pub fn new(
        config: Arc<Config>,
        fabric: UrmaFabricHandle,
        capability: UrmaCapability,
        remote_capability: UrmaCapability,
        addr: String,
    ) -> Self {
        let transfer_timeout = config.storage.server.urma.transfer_timeout;
        let mut lane_config = UrmaLaneConfig::default();
        lane_config.recv_depth = config.storage.server.urma.max_inflight_chunks;
        Self {
            config,
            fabric,
            capability,
            lane_config,
            remote_capability,
            addr,
            control_timeout: transfer_timeout,
            transfer_timeout,
            session: Arc::new(tokio::sync::Mutex::new(None)),
            transfer_state: Arc::new(AtomicU8::new(TRANSFER_HEALTHY)),
        }
    }

    /// fabric_failed reports whether the shared facade has entered a failed state
    /// and should be retired and recreated by the downloader before another URMA
    /// attempt.
    pub fn fabric_failed(&self) -> bool {
        self.fabric.is_failed()
    }

    /// take_transfer_outcome reports a completed background transfer once.
    /// `Some(false)` means the cached peer session must be retired.
    pub fn take_transfer_outcome(&self) -> Option<bool> {
        loop {
            let current = self.transfer_state.load(Ordering::Acquire);
            let outcome = match current {
                TRANSFER_SUCCEEDED => true,
                TRANSFER_FAILED => false,
                _ => return None,
            };
            if self
                .transfer_state
                .compare_exchange(
                    current,
                    TRANSFER_HEALTHY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(outcome);
            }
        }
    }

    /// Downloads a piece from the parent, returning the piece content stream,
    /// offset, and digest exactly like the TCP and QUIC clients so digest
    /// verification upstream is byte-identical.
    #[instrument(skip_all, fields(parent_addr))]
    pub async fn download_piece(
        &self,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(PieceContentStream, u64, String)> {
        Span::current().record("parent_addr", self.addr.as_str());
        time::timeout(
            self.config.download.piece_timeout,
            self.handle_download(PieceKind::Piece, number, task_id),
        )
        .await
        .inspect_err(|err| {
            error!("urma download timeout from {}: {}", self.addr, err);
        })?
    }

    /// Downloads a persistent piece from the parent.
    #[instrument(skip_all, fields(parent_addr))]
    pub async fn download_persistent_piece(
        &self,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(PieceContentStream, u64, String)> {
        Span::current().record("parent_addr", self.addr.as_str());
        time::timeout(
            self.config.download.piece_timeout,
            self.handle_download(PieceKind::PersistentPiece, number, task_id),
        )
        .await
        .inspect_err(|err| {
            error!("urma download timeout from {}: {}", self.addr, err);
        })?
    }

    /// Downloads a persistent cache piece from the parent.
    #[instrument(skip_all, fields(parent_addr))]
    pub async fn download_persistent_cache_piece(
        &self,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(PieceContentStream, u64, String)> {
        Span::current().record("parent_addr", self.addr.as_str());
        time::timeout(
            self.config.download.piece_timeout,
            self.handle_download(PieceKind::PersistentCachePiece, number, task_id),
        )
        .await
        .inspect_err(|err| {
            error!("urma download timeout from {}: {}", self.addr, err);
        })?
    }
}

impl UrmaClient {
    /// Runs one piece transfer: connect the control stream, negotiate a lane,
    /// request the piece, then hand each received window to storage through a
    /// bounded stream while the transfer task drives the session in the
    /// background.
    async fn handle_download(
        &self,
        kind: PieceKind,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(PieceContentStream, u64, String)> {
        // The owned guard is moved into the transfer task. This serializes
        // Piece requests on the persistent lane without exposing Session above
        // the storage adapter.
        let mut session_slot = self.session.clone().lock_owned().await;
        if self.transfer_state.load(Ordering::Acquire) == TRANSFER_FAILED {
            return Err(ClientError::Unknown(
                "previous urma transfer failed; retire the cached peer session".into(),
            ));
        }
        let mut session = match session_slot.take() {
            Some(session) => session,
            None => {
                let stream = TcpStream::connect(&self.addr).await?;
                let socket = SockRef::from(&stream);
                socket.set_tcp_nodelay(true)?;
                socket.set_tcp_keepalive(
                    &TcpKeepalive::new()
                        .with_interval(super::DEFAULT_KEEPALIVE_INTERVAL)
                        .with_time(super::DEFAULT_KEEPALIVE_TIME)
                        .with_retries(super::DEFAULT_KEEPALIVE_RETRIES),
                )?;
                UrmaClientSession::connect(
                    stream,
                    self.fabric.clone(),
                    self.lane_config,
                    self.capability.clone(),
                    &self.remote_capability,
                    self.control_timeout,
                )
                .await
                .map_err(urma_error)?
            }
        };

        // The control-plane negotiated the effective message size before the
        // lane was bound; a chunk of that size keeps uploads single-SGE.
        let max_message_size = self
            .capability
            .max_message_size
            .min(self.remote_capability.max_message_size);
        let request = CommonPieceRequest {
            kind,
            task_id: task_id.to_string(),
            piece_number: number,
            chunk_size: max_message_size,
            max_inflight_chunks: self.lane_config.recv_depth,
        };
        let metadata = session.request_piece(request).await.map_err(urma_error)?;
        let result_offset = metadata.offset;
        let result_digest = metadata.digest.clone();
        debug!(
            "urma piece ready: offset {}, length {}, chunk size {}, digest {}",
            metadata.offset, metadata.length, metadata.chunk_size, metadata.digest
        );

        let (mut window_tx, window_rx) =
            mpsc::channel::<io::Result<Bytes>>(WINDOW_CHANNEL_CAPACITY);
        let transfer_timeout = self.transfer_timeout;
        let piece_timeout = self.config.download.piece_timeout;
        let transfer_state = self.transfer_state.clone();
        transfer_state.store(TRANSFER_ACTIVE, Ordering::Release);
        tokio::spawn(async move {
            let mut transfer = Box::pin(async {
                loop {
                    let window = session.receive_next_window(transfer_timeout).await?;
                    if session.piece_complete() {
                        // Storage stops polling after it receives the expected
                        // byte count. Hold the final bytes until Done has been
                        // validated so a terminal protocol failure cannot be
                        // hidden behind a successful length/digest check.
                        session.finish_piece().await?;
                        *session_slot = Some(session);
                        drop(session_slot);
                        transfer_state.store(TRANSFER_SUCCEEDED, Ordering::Release);
                        let _ = window_tx.send(Ok(Bytes::from(window))).await;
                        return Ok::<(), UrmaError>(());
                    }
                    if window_tx.send(Ok(Bytes::from(window))).await.is_err() {
                        // This is local cancellation, not evidence that the
                        // parent is unhealthy. Dropping Session aborts the lane.
                        transfer_state.store(TRANSFER_HEALTHY, Ordering::Release);
                        return Ok(());
                    }
                }
            });
            let error = match tokio::select! {
                result = &mut transfer => result.map_err(|error| error.to_string()),
                _ = time::sleep(piece_timeout) => {
                    Err("complete urma piece transfer timed out".to_string())
                }
            } {
                Ok(()) => return,
                Err(error) => error,
            };
            // Publish failure while the transfer future still owns the Session
            // slot guard. A queued Piece therefore cannot race through with a
            // freshly reconnected lane before observing the failure.
            transfer_state.store(TRANSFER_FAILED, Ordering::Release);
            drop(transfer);
            let _ = window_tx.send(Err(io::Error::other(error))).await;
            // Session and its active lane are dropped here and abort through
            // the lifecycle command path. The empty slot forces reconnect.
        });

        Ok((window_rx.boxed(), result_offset, result_digest))
    }
}
