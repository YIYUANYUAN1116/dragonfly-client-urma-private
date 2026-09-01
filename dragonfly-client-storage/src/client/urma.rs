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
use crate::rendezvous::{PieceKind, ERROR_CODE_BUSY, ERROR_CODE_INCOMPATIBLE};
use crate::urma::fabric::{UrmaFabricHandle, UrmaLaneConfig};
use crate::urma::rendezvous::{
    read_frame, write_frame, CommonPieceRequest, Frame, UrmaAdvertisement, UrmaCapability,
};
use crate::urma::session::UrmaClientSession;
use crate::urma::Error as UrmaError;
use crate::urma::RegisteredRxWindowLease;
use bytes::Bytes;
use dragonfly_client_config::dfdaemon::Config;
use dragonfly_client_core::{Error as ClientError, Result as ClientResult};
use futures::channel::mpsc;
use futures::SinkExt;
use futures::StreamExt;
use socket2::{SockRef, TcpKeepalive};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time;
use tracing::{debug, error, instrument, warn, Span};

/// Cap of concurrent receive windows buffered between the transfer task and the
/// storage writer, mirroring the TCP/QUIC client backpressure.

#[derive(Default)]
struct TransferOutcomes {
    failed: AtomicBool,
    successes: AtomicU64,
}

impl TransferOutcomes {
    fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::Release);
    }

    fn record_failure(&self) {
        self.failed.store(true, Ordering::Release);
    }

    fn take(&self) -> Option<bool> {
        if self.failed.load(Ordering::Acquire) {
            return Some(false);
        }
        (self.successes.swap(0, Ordering::AcqRel) != 0).then_some(true)
    }
}

/// Validation-only failpoint. It is compiled out unless `urma-test-failpoints` is explicitly
/// enabled, so a production `urma` build cannot be faulted through its environment.
const FAIL_AFTER_RECV_WINDOWS_ENV: &str = "DF_URMA_FAIL_AFTER_RECV_WINDOWS";

#[cfg(any(feature = "urma-test-failpoints", test))]
fn parse_fail_after_recv_windows(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().filter(|windows| *windows > 0)
}

fn fail_after_recv_windows() -> Option<u64> {
    #[cfg(feature = "urma-test-failpoints")]
    {
        let value = std::env::var(FAIL_AFTER_RECV_WINDOWS_ENV).ok()?;
        match parse_fail_after_recv_windows(&value) {
            Some(windows) => Some(windows),
            None => {
                warn!(
                    env = FAIL_AFTER_RECV_WINDOWS_ENV,
                    value, "ignoring invalid urma receive-window failpoint"
                );
                None
            }
        }
    }
    #[cfg(not(feature = "urma-test-failpoints"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_fail_after_recv_windows, TransferOutcomes};

    #[test]
    fn receive_window_failpoint_requires_a_positive_integer() {
        assert_eq!(parse_fail_after_recv_windows("3"), Some(3));
        for invalid in ["", "0", "-1", "not-a-number"] {
            assert_eq!(parse_fail_after_recv_windows(invalid), None);
        }
    }

    #[test]
    fn concurrent_transfer_outcomes_coalesce_success_and_keep_failure_sticky() {
        let outcomes = TransferOutcomes::default();
        assert_eq!(outcomes.take(), None);
        outcomes.record_success();
        outcomes.record_success();
        assert_eq!(outcomes.take(), Some(true));
        assert_eq!(outcomes.take(), None);
        outcomes.record_success();
        outcomes.record_failure();
        assert_eq!(outcomes.take(), Some(false));
        assert_eq!(outcomes.take(), Some(false));
    }
}

type SessionSlot = Arc<tokio::sync::Mutex<Option<Arc<UrmaClientSession<TcpStream>>>>>;

type WindowRecycleFuture = Pin<Box<dyn Future<Output = Result<usize, UrmaError>> + Send + 'static>>;
type WindowRecycler =
    Arc<dyn Fn(RegisteredRxWindowLease) -> WindowRecycleFuture + Send + Sync + 'static>;

/// UrmaStreamReader exposes completed receive windows without copying their
/// registered backing. The Session transfer task owns the lane and produces
/// leases; Storage owns each delivered lease until its write and digest finish.
pub struct UrmaStreamReader {
    receiver: mpsc::Receiver<io::Result<RegisteredRxWindowLease>>,
    recycler: WindowRecycler,
}

impl std::fmt::Debug for UrmaStreamReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("UrmaStreamReader").finish()
    }
}

impl UrmaStreamReader {
    fn new(
        receiver: mpsc::Receiver<io::Result<RegisteredRxWindowLease>>,
        fabric: UrmaFabricHandle,
    ) -> Self {
        let recycler: WindowRecycler = Arc::new(move |lease| {
            let fabric = fabric.clone();
            Box::pin(async move { fabric.recycle_rx_window(lease).await })
        });
        Self { receiver, recycler }
    }

    /// Returns the next completed logical receive window. `None` is returned
    /// only after the transfer task has validated Done and closed the channel.
    pub async fn next_window(&mut self) -> io::Result<Option<UrmaReceivedWindow>> {
        match self.receiver.next().await {
            Some(Ok(lease)) => Ok(Some(UrmaReceivedWindow {
                lease: Some(lease),
                recycler: self.recycler.clone(),
            })),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    /// Adapts the registered-window reader to Dragonfly's transport-neutral
    /// stream contract. This is the compatibility path for generic Downloader
    /// users; the production Piece path consumes [`Self::next_window`]
    /// directly and performs no staging copy.
    pub fn into_content_stream(self) -> PieceContentStream {
        futures::stream::try_unfold(self, |mut reader| async move {
            let Some(window) = reader.next_window().await? else {
                return Ok(None);
            };
            let mut bytes = Vec::with_capacity(window.len());
            for part in window.parts() {
                bytes.extend_from_slice(part);
            }
            window.recycle().await?;
            Ok(Some((Bytes::from(bytes), reader)))
        })
        .boxed()
    }

    #[cfg(test)]
    pub(crate) fn from_test_windows(
        windows: Vec<Vec<Vec<u8>>>,
    ) -> (Self, Arc<std::sync::atomic::AtomicUsize>) {
        let (mut sender, receiver) = mpsc::channel(windows.len().max(1));
        for parts in windows {
            sender
                .try_send(Ok(RegisteredRxWindowLease::from_test_untracked_parts(
                    parts,
                )))
                .expect("test window channel capacity");
        }
        drop(sender);

        let recycled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let recycler: WindowRecycler = {
            let recycled = recycled.clone();
            Arc::new(move |lease| {
                let recycled = recycled.clone();
                Box::pin(async move {
                    let length = lease.len();
                    drop(lease);
                    recycled.fetch_add(1, Ordering::AcqRel);
                    Ok(length)
                })
            })
        };
        (Self { receiver, recycler }, recycled)
    }
}

/// One immutable logical URMA receive window. It can contain multiple
/// registered spans, including a short tail span. Explicit recycle waits for
/// the owner thread to validate and release every covered slot.
pub struct UrmaReceivedWindow {
    lease: Option<RegisteredRxWindowLease>,
    recycler: WindowRecycler,
}

impl UrmaReceivedWindow {
    pub fn len(&self) -> usize {
        self.lease.as_ref().map_or(0, RegisteredRxWindowLease::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn parts(&self) -> impl Iterator<Item = &[u8]> {
        self.lease
            .as_ref()
            .expect("URMA receive window was already recycled")
            .parts()
    }

    pub async fn recycle(mut self) -> io::Result<()> {
        let lease = self
            .lease
            .take()
            .expect("URMA receive window was already recycled");
        (self.recycler)(lease)
            .await
            .map(|_| ())
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

impl std::fmt::Debug for UrmaReceivedWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UrmaReceivedWindow")
            .field("length", &self.len())
            .finish()
    }
}

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
            Frame::Error { error: err, .. } if err.code == ERROR_CODE_INCOMPATIBLE => {
                Err(ClientError::Unsupported(err.message))
            }
            Frame::Error { error: err, .. } => Err(ClientError::Unknown(format!(
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
/// failures fall back to the TCP piece transport exactly like RDMA. A peer
/// BUSY rejection maps to [`ClientError::Busy`]: it is a transient budget
/// rejection, not evidence of a broken transport.
fn urma_error(error: UrmaError) -> ClientError {
    match error {
        UrmaError::PeerRejected { code, message } if code == ERROR_CODE_INCOMPATIBLE => {
            ClientError::Unsupported(message)
        }
        UrmaError::PeerRejected { code, message } if code == ERROR_CODE_BUSY => {
            ClientError::Busy(format!("urma peer busy ({code}): {message}"))
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

    /// session owns the persistent control connection and RC lane shared by
    /// bounded concurrent Piece transfers to this parent.
    session: SessionSlot,

    /// Completed outcomes are aggregated because several Piece streams may be
    /// active at once. A failure is sticky until this cached client is retired;
    /// successes are drained as one healthy-parent observation.
    transfer_outcomes: Arc<TransferOutcomes>,

    /// Number of real receive windows to complete before injecting a validation failure.
    fail_after_recv_windows: Option<u64>,
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
        lane_config.recv_depth = config
            .storage
            .server
            .urma
            .max_inflight_chunks
            .min(fabric.max_rx_window_chunks(config.storage.server.urma.pipeline_depth));
        lane_config.post_list_size = config.storage.server.urma.post_list_size;
        lane_config.pipeline_depth = config.storage.server.urma.pipeline_depth;
        let fail_after_recv_windows = fail_after_recv_windows();
        if let Some(windows) = fail_after_recv_windows {
            warn!(
                windows,
                env = FAIL_AFTER_RECV_WINDOWS_ENV,
                "urma real-provider receive failpoint armed"
            );
        }
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
            transfer_outcomes: Arc::new(TransferOutcomes::default()),
            fail_after_recv_windows,
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
        self.transfer_outcomes.take()
    }

    /// Downloads a piece through the transport-neutral compatibility stream.
    #[instrument(skip_all, fields(parent_addr))]
    pub async fn download_piece(
        &self,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(PieceContentStream, u64, String)> {
        Span::current().record("parent_addr", self.addr.as_str());
        let (reader, offset, digest) = time::timeout(
            self.config.download.piece_timeout,
            self.handle_download(PieceKind::Piece, number, task_id),
        )
        .await
        .inspect_err(|err| {
            error!("urma download timeout from {}: {}", self.addr, err);
        })??;
        Ok((reader.into_content_stream(), offset, digest))
    }

    /// Downloads a normal Piece while preserving registered RX window leases.
    pub async fn download_piece_stream(
        &self,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(UrmaStreamReader, u64, String)> {
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
        let (reader, offset, digest) = time::timeout(
            self.config.download.piece_timeout,
            self.handle_download(PieceKind::PersistentPiece, number, task_id),
        )
        .await
        .inspect_err(|err| {
            error!("urma download timeout from {}: {}", self.addr, err);
        })??;
        Ok((reader.into_content_stream(), offset, digest))
    }

    /// Downloads a persistent Piece while preserving registered RX leases.
    pub async fn download_persistent_piece_stream(
        &self,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(UrmaStreamReader, u64, String)> {
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
        let (reader, offset, digest) = time::timeout(
            self.config.download.piece_timeout,
            self.handle_download(PieceKind::PersistentCachePiece, number, task_id),
        )
        .await
        .inspect_err(|err| {
            error!("urma download timeout from {}: {}", self.addr, err);
        })??;
        Ok((reader.into_content_stream(), offset, digest))
    }

    /// Downloads a persistent-cache Piece while preserving registered RX leases.
    pub async fn download_persistent_cache_piece_stream(
        &self,
        number: u32,
        task_id: &str,
    ) -> ClientResult<(UrmaStreamReader, u64, String)> {
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
    ) -> ClientResult<(UrmaStreamReader, u64, String)> {
        let client_piece_total_start = Instant::now();
        // Serialize only lazy lane creation. Piece transfers release this
        // guard before rendezvous and then share the persistent lane.
        let session_queue_start = Instant::now();
        let mut session_slot = self.session.lock().await;
        let session_queue_wait_ns = session_queue_start.elapsed().as_nanos() as u64;
        if self.transfer_outcomes.failed.load(Ordering::Acquire) {
            return Err(ClientError::Unknown(
                "previous urma transfer failed; retire the cached peer session".into(),
            ));
        }
        let (session, reused_session) = match session_slot.as_ref() {
            Some(session) => (session.clone(), true),
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
                let session = UrmaClientSession::connect(
                    stream,
                    self.fabric.clone(),
                    self.lane_config,
                    self.capability.clone(),
                    &self.remote_capability,
                    self.control_timeout,
                    self.config.storage.server.urma.max_concurrent_transfers as usize,
                )
                .await
                .map_err(urma_error)?;
                let session = Arc::new(session);
                *session_slot = Some(session.clone());
                (session, false)
            }
        };
        drop(session_slot);
        debug!(
            parent_addr = self.addr,
            lane_id = session.lane_id(),
            reused_session,
            piece_kind = ?kind,
            piece_number = number,
            "urma client selected peer lane"
        );

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
        let request_ready_start = Instant::now();
        let (mut transfer, metadata) = match session.request_piece(request).await {
            Ok(transfer) => transfer,
            // Local or peer lane admission BUSY leaves the shared lane healthy
            // and falls back only this Piece to TCP.
            Err(UrmaError::PeerRejected { code, message }) if code == ERROR_CODE_BUSY => {
                return Err(ClientError::Busy(format!(
                    "urma peer busy ({code}): {message}"
                )));
            }
            Err(error) => return Err(urma_error(error)),
        };
        let request_ready_ns = request_ready_start.elapsed().as_nanos() as u64;
        let result_offset = metadata.offset;
        let result_digest = metadata.digest.clone();
        debug!(
            "urma piece ready: offset {}, length {}, chunk size {}, digest {}",
            metadata.offset, metadata.length, metadata.chunk_size, metadata.digest
        );

        let (mut window_tx, window_rx) = mpsc::channel::<io::Result<RegisteredRxWindowLease>>(
            self.lane_config.pipeline_depth as usize,
        );
        let reader = UrmaStreamReader::new(window_rx, self.fabric.clone());
        let transfer_timeout = self.transfer_timeout;
        let piece_timeout = self.config.download.piece_timeout;
        let transfer_outcomes = self.transfer_outcomes.clone();
        let fail_after_recv_windows = self.fail_after_recv_windows;
        let configured_pipeline_depth = self.lane_config.pipeline_depth;
        let max_window_chunks = self.lane_config.recv_depth;
        let log_task_id = task_id.to_string();
        tokio::spawn(async move {
            let mut transfer_future = Box::pin(async {
                let mut completed_windows = 0u64;
                let mut received_bytes = 0u64;
                let mut rx_window_wait_ns = 0u64;
                let mut window_publish_wait_ns = 0u64;
                let mut done_wait_ns = 0u64;
                loop {
                    let rx_window_wait_start = Instant::now();
                    let window = transfer
                        .receive_next_window_registered(transfer_timeout)
                        .await?;
                    rx_window_wait_ns += rx_window_wait_start.elapsed().as_nanos() as u64;
                    completed_windows += 1;
                    received_bytes += window.len() as u64;
                    if fail_after_recv_windows == Some(completed_windows) {
                        // Publish a non-final completed window first so Storage contains a real
                        // partial Piece when the normal error/fallback path resets it. The final
                        // window stays behind the existing Done gate.
                        if !transfer.piece_complete() {
                            let publish_start = Instant::now();
                            let published = window_tx.send(Ok(window)).await;
                            window_publish_wait_ns += publish_start.elapsed().as_nanos() as u64;
                            if published.is_err() {
                                return Ok(());
                            }
                        }
                        warn!(
                            lane_id = session.lane_id(),
                            completed_windows,
                            configured_pipeline_depth,
                            max_window_chunks,
                            window_publish_wait_ns,
                            "injecting urma failure after real receive completions"
                        );
                        return Err(UrmaError::Protocol(format!(
                            "injected failure after {completed_windows} completed receive windows"
                        )));
                    }
                    if transfer.piece_complete() {
                        // Storage stops polling after it receives the expected
                        // byte count. Hold the final bytes until Done has been
                        // validated so a terminal protocol failure cannot be
                        // hidden behind a successful length/digest check.
                        let done_wait_start = Instant::now();
                        transfer.finish_piece().await?;
                        done_wait_ns += done_wait_start.elapsed().as_nanos() as u64;
                        transfer_outcomes.record_success();
                        let publish_start = Instant::now();
                        let _ = window_tx.send(Ok(window)).await;
                        window_publish_wait_ns += publish_start.elapsed().as_nanos() as u64;
                        debug!(
                            task_id = %log_task_id,
                            piece_number = number,
                            received_bytes,
                            completed_windows,
                            session_queue_wait_ns,
                            request_ready_ns,
                            rx_window_wait_ns,
                            done_wait_ns,
                            window_publish_wait_ns,
                            client_piece_total_ns = client_piece_total_start.elapsed().as_nanos() as u64,
                            "finished receiving urma piece into registered windows"
                        );
                        return Ok::<(), UrmaError>(());
                    }
                    let publish_start = Instant::now();
                    let published = window_tx.send(Ok(window)).await;
                    window_publish_wait_ns += publish_start.elapsed().as_nanos() as u64;
                    if published.is_err() {
                        // This is local cancellation, not evidence that the
                        // parent or shared lane is unhealthy.
                        return Ok(());
                    }
                }
            });
            let error = match tokio::select! {
                result = &mut transfer_future => result.map_err(|error| error.to_string()),
                _ = time::sleep(piece_timeout) => {
                    Err("complete urma piece transfer timed out".to_string())
                }
            } {
                Ok(()) => return,
                Err(error) => error,
            };
            // A transport failure is sticky for the cached client and aborts
            // the shared lane, waking every sibling transfer fail-closed.
            transfer_outcomes.record_failure();
            drop(transfer_future);
            let _ = transfer.abort_transfer(error.clone()).await;
            let _ = window_tx.send(Err(io::Error::other(error))).await;
        });

        Ok((reader, result_offset, result_digest))
    }
}
