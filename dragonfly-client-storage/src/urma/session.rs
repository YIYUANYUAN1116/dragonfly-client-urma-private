//! Persistent peer session over the thread-owned URMA fabric.
//!
//! A TCP control connection and one bound Jetty are established once, then
//! shared by bounded concurrent logical Piece transfers. Storage lookup and
//! stream exposure stay in the `client::urma` / `server::urma` adapters.

use super::{
    buffer::{RegisteredRxWindowLease, TxWindowLease},
    completion::RegisteredRxCompletion,
    control::{LaneControl, TransferControl},
    fabric::{UrmaFabricHandle, UrmaLaneConfig, UrmaRegisteredRxOpHandle},
    rendezvous::{
        read_frame, write_frame, CommonPieceRequest, Frame, LaneConnect, LaneConnected,
        PieceMetadata, ReceiveWindow, RendezvousError, TransferId, UrmaCapability,
    },
    Error, Result,
};
use crate::rendezvous::{ERROR_CODE_BUSY, ERROR_CODE_INCOMPATIBLE, ERROR_CODE_INTERNAL};
use dragonfly_client_core::Error as ClientError;
use dragonfly_client_metric::{
    collect_urma_budget_pressure_metrics, collect_urma_required_admission_wait_metrics,
};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, Semaphore},
    time,
};
use tracing::{debug, info, warn};

const REQUIRED_RX_RETRY_INTERVAL: Duration = Duration::from_millis(1);

fn transfer_sequence(transfer_id: TransferId, chunk: u64) -> Result<u64> {
    if transfer_id == 0 || chunk > u64::from(u32::MAX) {
        return Err(Error::Protocol(format!(
            "invalid URMA transfer sequence: transfer_id={transfer_id} chunk={chunk}"
        )));
    }
    Ok((u64::from(transfer_id) << 32) | chunk)
}

fn decode_transfer_sequence(sequence: u64) -> Result<(TransferId, u64)> {
    let transfer_id = (sequence >> 32) as TransferId;
    let chunk = sequence & u64::from(u32::MAX);
    if transfer_id == 0 {
        return Err(Error::Protocol(format!(
            "invalid URMA SEND_IMM identity: sequence={sequence} transfer_id=0"
        )));
    }
    Ok((transfer_id, chunk))
}

fn control_error(error: ClientError) -> Error {
    Error::Protocol(format!("URMA rendezvous failed: {error}"))
}

fn unexpected(frame: Frame, phase: &str) -> Error {
    match frame {
        Frame::Error { error, .. } => Error::PeerRejected {
            code: error.code,
            message: error.message,
        },
        frame => Error::Protocol(format!("unexpected URMA frame during {phase}: {frame:?}")),
    }
}

/// Timing for the control, submission, and completion portions of one
/// registered TX window. Keeping these phases separate prevents the server's
/// Piece log from treating the old aggregate send wait as pure NIC time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RegisteredSendTiming {
    pub(crate) recv_posted_wait_ns: u64,
    pub(crate) grant_credit_ns: u64,
    pub(crate) wr_post_ns: u64,
    pub(crate) send_cqe_wait_ns: u64,
}

async fn read_control<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
    operation: &'static str,
) -> Result<Frame> {
    time::timeout(timeout, read_frame(stream))
        .await
        .map_err(|_| Error::ControlTimeout { operation })?
        .map_err(control_error)
}

async fn write_control<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &Frame,
    timeout: Duration,
    operation: &'static str,
) -> Result<()> {
    time::timeout(timeout, write_frame(stream, frame))
        .await
        .map_err(|_| Error::ControlTimeout { operation })?
        .map_err(control_error)
}

async fn receive_transfer_control(
    control: &mut TransferControl,
    timeout: Duration,
    operation: &'static str,
) -> Result<Frame> {
    time::timeout(timeout, control.receive())
        .await
        .map_err(|_| Error::ControlTimeout { operation })?
}

async fn send_transfer_control(
    control: &TransferControl,
    frame: Frame,
    timeout: Duration,
    operation: &'static str,
) -> Result<()> {
    time::timeout(timeout, control.send(frame))
        .await
        .map_err(|_| Error::ControlTimeout { operation })?
}

#[derive(Clone, Debug)]
struct TransferShape {
    metadata: PieceMetadata,
    chunk_count: u64,
}

impl TransferShape {
    fn negotiate(
        request: &CommonPieceRequest,
        metadata: PieceMetadata,
        max_message_size: u64,
        max_inflight_chunks: u32,
    ) -> Result<Self> {
        if request.task_id.is_empty()
            || request.chunk_size == 0
            || request.max_inflight_chunks == 0
            || metadata.length == 0
            || metadata.chunk_size == 0
            || metadata.chunk_size > request.chunk_size
            || metadata.chunk_size > max_message_size
            || metadata.max_inflight_chunks == 0
            || metadata.max_inflight_chunks > request.max_inflight_chunks
            || metadata.max_inflight_chunks > max_inflight_chunks
        {
            return Err(Error::Protocol(format!(
                "invalid URMA Piece negotiation: request chunk={} inflight={}, metadata length={} chunk={} inflight={}",
                request.chunk_size,
                request.max_inflight_chunks,
                metadata.length,
                metadata.chunk_size,
                metadata.max_inflight_chunks
            )));
        }
        Ok(Self {
            chunk_count: metadata.length.div_ceil(metadata.chunk_size),
            metadata,
        })
    }

    fn window(&self, start_chunk: u64) -> Result<ReceiveWindow> {
        if start_chunk >= self.chunk_count {
            return Err(Error::Protocol(
                "receive window starts after the final chunk".into(),
            ));
        }
        Ok(ReceiveWindow {
            start_chunk,
            chunk_count: (self.chunk_count - start_chunk)
                .min(u64::from(self.metadata.max_inflight_chunks)) as u32,
        })
    }

    fn chunk_len(&self, chunk: u64) -> Result<usize> {
        if chunk >= self.chunk_count {
            return Err(Error::Protocol("chunk index exceeds Piece length".into()));
        }
        let offset = chunk
            .checked_mul(self.metadata.chunk_size)
            .ok_or_else(|| Error::Protocol("chunk offset overflow".into()))?;
        usize::try_from(self.metadata.chunk_size.min(self.metadata.length - offset))
            .map_err(|_| Error::Protocol("chunk length exceeds addressable memory".into()))
    }

    fn window_len(&self, window: ReceiveWindow) -> Result<usize> {
        let remaining = self
            .chunk_count
            .checked_sub(window.start_chunk)
            .ok_or_else(|| Error::Protocol("receive window starts past Piece end".into()))?;
        window
            .validate(window.start_chunk, remaining)
            .map_err(control_error)?;
        let mut length = 0usize;
        for chunk in window.start_chunk..window.start_chunk + u64::from(window.chunk_count) {
            length = length
                .checked_add(self.chunk_len(chunk)?)
                .ok_or_else(|| Error::Protocol("receive window length overflow".into()))?;
        }
        Ok(length)
    }
}

struct ClientPiece {
    transfer_id: TransferId,
    shape: TransferShape,
    next_post_chunk: u64,
    next_deliver_chunk: u64,
    receive_window_count: u64,
    send_imm_chunk_count: u64,
    reordered_chunk_count: u64,
    cross_transfer_chunk_count: u64,
    pending: VecDeque<PendingReceiveWindow>,
    window_permits: std::sync::Arc<Semaphore>,
    pipeline_depth: usize,
}

struct PendingReceiveWindow {
    window: ReceiveWindow,
    expected_len: usize,
    operations: Vec<UrmaRegisteredRxOpHandle>,
    permit: OwnedSemaphorePermit,
    _native_receive_permit: NativeReceiveWindowPermit,
}

#[derive(Default)]
struct NativeReceiveAdmissionState {
    active_windows: usize,
    active_windows_by_transfer: HashMap<TransferId, usize>,
}

struct NativeReceiveWindowPermit {
    _permit: OwnedSemaphorePermit,
    state: Arc<Mutex<NativeReceiveAdmissionState>>,
    lane_id: u16,
    transfer_id: TransferId,
    window_start_chunk: u64,
}

impl NativeReceiveWindowPermit {
    fn new(
        permit: OwnedSemaphorePermit,
        state: Arc<Mutex<NativeReceiveAdmissionState>>,
        lane_id: u16,
        transfer_id: TransferId,
        window: ReceiveWindow,
    ) -> Self {
        let (active_windows, active_transfers) = {
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            state.active_windows += 1;
            *state
                .active_windows_by_transfer
                .entry(transfer_id)
                .or_default() += 1;
            (state.active_windows, state.active_windows_by_transfer.len())
        };
        debug!(
            role = "client",
            lane_id,
            transfer_id,
            window_start_chunk = window.start_chunk,
            window_chunk_count = window.chunk_count,
            active_native_rx_windows = active_windows,
            active_native_rx_transfers = active_transfers,
            "URMA native RX window admitted"
        );
        Self {
            _permit: permit,
            state,
            lane_id,
            transfer_id,
            window_start_chunk: window.start_chunk,
        }
    }
}

impl Drop for NativeReceiveWindowPermit {
    fn drop(&mut self) {
        let (active_windows, active_transfers) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.active_windows = state.active_windows.saturating_sub(1);
            if let Some(count) = state.active_windows_by_transfer.get_mut(&self.transfer_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.active_windows_by_transfer.remove(&self.transfer_id);
                }
            }
            (state.active_windows, state.active_windows_by_transfer.len())
        };
        debug!(
            role = "client",
            lane_id = self.lane_id,
            transfer_id = self.transfer_id,
            window_start_chunk = self.window_start_chunk,
            active_native_rx_windows = active_windows,
            active_native_rx_transfers = active_transfers,
            "URMA native RX window released"
        );
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReceiveWindowRoutingStats {
    reordered_chunk_count: u64,
    cross_transfer_chunk_count: u64,
}

fn reorder_receive_window_completions(
    lane_id: u16,
    transfer_id: TransferId,
    shape: &TransferShape,
    window: ReceiveWindow,
    completions: Vec<RegisteredRxCompletion>,
) -> Result<(Vec<RegisteredRxWindowLease>, ReceiveWindowRoutingStats)> {
    shape.window_len(window)?;
    let count = window.chunk_count as usize;
    if completions.len() != count {
        return Err(Error::Protocol(format!(
            "URMA receive window completion count mismatch: expected={count} received={}",
            completions.len()
        )));
    }
    let end_chunk = window
        .start_chunk
        .checked_add(u64::from(window.chunk_count))
        .ok_or_else(|| Error::Protocol("URMA receive window chunk range overflow".into()))?;
    let mut leases_by_chunk = (0..count).map(|_| None).collect::<Vec<_>>();
    let mut routing = ReceiveWindowRoutingStats::default();

    for completion in completions {
        if completion.lane_id != lane_id {
            return Err(Error::Protocol(format!(
                "URMA receive completion changed lane: expected={lane_id} received={}",
                completion.lane_id
            )));
        }
        let posted_sequence = completion.posted_sequence.ok_or_else(|| {
            Error::Protocol("registered URMA receive completion has no posted sequence".into())
        })?;
        let (posted_transfer_id, _posted_chunk) = decode_transfer_sequence(posted_sequence)?;

        let (received_transfer_id, received_chunk) = decode_transfer_sequence(completion.imm_data)?;
        if received_transfer_id != transfer_id {
            return Err(Error::Protocol(format!(
                "URMA SEND_IMM transfer mismatch: expected={transfer_id} received={received_transfer_id} sequence={}",
                completion.imm_data
            )));
        }
        if received_chunk < window.start_chunk || received_chunk >= end_chunk {
            return Err(Error::Protocol(format!(
                "URMA SEND_IMM chunk is outside the active window: transfer_id={transfer_id} window={window:?} received_chunk={received_chunk}"
            )));
        }
        let expected_len = shape.chunk_len(received_chunk)?;
        if completion.lease.len() != expected_len {
            return Err(Error::Protocol(format!(
                "URMA SEND_IMM chunk length mismatch: transfer_id={transfer_id} chunk={received_chunk} expected={expected_len} received={} rx_slot={}",
                completion.lease.len(),
                completion.slot.index()
            )));
        }
        let received_index = usize::try_from(received_chunk - window.start_chunk)
            .map_err(|_| Error::Protocol("received URMA chunk index exceeds usize".into()))?;
        if leases_by_chunk[received_index].is_some() {
            return Err(Error::Protocol(format!(
                "duplicate URMA SEND_IMM chunk: transfer_id={transfer_id} chunk={received_chunk}"
            )));
        }
        routing.reordered_chunk_count += u64::from(posted_sequence != completion.imm_data);
        routing.cross_transfer_chunk_count += u64::from(posted_transfer_id != transfer_id);
        leases_by_chunk[received_index] = Some(completion.lease);
    }

    let missing_received = leases_by_chunk
        .iter()
        .enumerate()
        .filter_map(|(index, lease)| lease.is_none().then_some(window.start_chunk + index as u64))
        .collect::<Vec<_>>();
    if !missing_received.is_empty() {
        return Err(Error::Protocol(format!(
            "URMA receive window identities are incomplete: transfer_id={transfer_id} missing_received={missing_received:?}"
        )));
    }

    debug!(
        lane_id,
        transfer_id,
        window_start_chunk = window.start_chunk,
        window_chunk_count = window.chunk_count,
        reordered_chunk_count = routing.reordered_chunk_count,
        cross_transfer_chunk_count = routing.cross_transfer_chunk_count,
        "validated URMA Piece receive window SEND_IMM identities"
    );

    Ok((
        leases_by_chunk
            .into_iter()
            .map(|lease| lease.expect("missing identities checked"))
            .collect(),
        routing,
    ))
}

struct ClientLane {
    control: LaneControl,
    fabric: UrmaFabricHandle,
    lane_id: u16,
    max_message_size: u64,
    max_receive_inflight: u32,
    receive_pipeline_depth: usize,
    control_timeout: Duration,
    next_transfer_id: AtomicU32,
    failed: AtomicBool,
    native_receive_permits: Arc<Semaphore>,
    native_receive_admission_state: Arc<Mutex<NativeReceiveAdmissionState>>,
}

impl Drop for ClientLane {
    fn drop(&mut self) {
        debug!(
            role = "client",
            lane_id = self.lane_id,
            "dropping urma peer lane"
        );
        self.control.abort("URMA client lane owner was dropped");
        let _ = self.fabric.try_abort_lane(self.lane_id);
    }
}

/// Downloader-side handle to one persistent control connection and RM Jetty.
/// Piece-local state lives in [`UrmaClientTransfer`], so this handle can be
/// shared by concurrent downloads to the same parent.
pub(crate) struct UrmaClientSession<S> {
    lane: Arc<ClientLane>,
    stream_type: PhantomData<S>,
}

pub(crate) struct UrmaClientTransfer {
    lane: Arc<ClientLane>,
    transfer_control: Option<TransferControl>,
    piece: Option<ClientPiece>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> UrmaClientSession<S> {
    pub(crate) async fn connect(
        mut stream: S,
        fabric: UrmaFabricHandle,
        lane_config: UrmaLaneConfig,
        local_capability: UrmaCapability,
        remote_capability: &UrmaCapability,
        control_timeout: Duration,
        max_concurrent_transfers: usize,
        max_receive_inflight: u32,
    ) -> Result<Self> {
        local_capability
            .compatible(remote_capability)
            .map_err(Error::Protocol)?;
        if max_receive_inflight == 0 || max_receive_inflight > lane_config.recv_depth {
            return Err(Error::InvalidConfiguration(format!(
                "URMA per-Piece receive inflight {max_receive_inflight} exceeds lane receive depth {}",
                lane_config.recv_depth
            )));
        }
        let max_message_size = local_capability
            .max_message_size
            .min(remote_capability.max_message_size);
        let (lane_id, client_descriptor) = fabric.create_lane(lane_config).await?;
        let handshake = async {
            write_control(
                &mut stream,
                &Frame::Connect(LaneConnect {
                    capability: local_capability,
                    client_descriptor,
                }),
                control_timeout,
                "send lane Connect",
            )
            .await?;
            let connected =
                match read_control(&mut stream, control_timeout, "receive lane Connected").await? {
                    Frame::Connected(connected) => connected,
                    frame => return Err(unexpected(frame, "lane connect")),
                };
            fabric
                .connect_lane(lane_id, connected.server_descriptor)
                .await
        }
        .await;
        if let Err(error) = handshake {
            let _ = fabric.abort_lane(lane_id).await;
            return Err(error);
        }
        info!(
            role = "client",
            lane_id,
            transport_mode = ?lane_config.transport_mode,
            "urma peer lane established"
        );
        Ok(Self {
            lane: Arc::new(ClientLane {
                control: LaneControl::spawn(stream, max_concurrent_transfers)?,
                fabric,
                lane_id,
                max_message_size,
                max_receive_inflight,
                receive_pipeline_depth: lane_config.pipeline_depth as usize,
                control_timeout,
                next_transfer_id: AtomicU32::new(1),
                failed: AtomicBool::new(false),
                native_receive_permits: Arc::new(Semaphore::new(lane_config.recv_depth as usize)),
                native_receive_admission_state: Arc::new(Mutex::new(
                    NativeReceiveAdmissionState::default(),
                )),
            }),
            stream_type: PhantomData,
        })
    }

    pub(crate) async fn request_piece(
        &self,
        request: CommonPieceRequest,
    ) -> Result<(UrmaClientTransfer, PieceMetadata)> {
        if self.lane.failed.load(Ordering::Acquire) {
            return Err(Error::Protocol("URMA client lane is failed".into()));
        }
        if request.task_id.is_empty()
            || request.chunk_size == 0
            || request.chunk_size > self.lane.max_message_size
            || request.max_inflight_chunks == 0
            || request.max_inflight_chunks > self.lane.max_receive_inflight
        {
            return Err(Error::Protocol("invalid URMA Piece request".into()));
        }
        let transfer_id = self
            .lane
            .next_transfer_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.wrapping_add(1).max(1))
            })
            .unwrap();
        debug!(
            role = "client",
            lane_id = self.lane.lane_id,
            transfer_id,
            piece_kind = ?request.kind,
            piece_number = request.piece_number,
            "urma piece request on peer lane"
        );
        let control = self.lane.control.register(transfer_id)?;
        if let Err(error) = send_transfer_control(
            &control,
            Frame::Request {
                transfer_id,
                request: request.clone(),
            },
            self.lane.control_timeout,
            "send Piece Request",
        )
        .await
        {
            return self.abort_lane(error).await;
        }
        let mut control = control;
        let metadata = match receive_transfer_control(
            &mut control,
            self.lane.control_timeout,
            "receive Piece Ready",
        )
        .await
        {
            Ok(Frame::Ready {
                transfer_id: response_id,
                metadata,
            }) if response_id == transfer_id => metadata,
            // A transient BUSY rejection leaves the peer lane alive: the
            // server rejected before posting any WR. Keep this session (and
            // its lane) usable for the next Piece instead of aborting.
            Ok(Frame::Error {
                transfer_id: response_id,
                error: err,
            }) if response_id == transfer_id && err.code == ERROR_CODE_BUSY => {
                control.finish();
                return Err(Error::PeerRejected {
                    code: err.code,
                    message: err.message,
                });
            }
            Ok(frame) => return self.abort_lane(unexpected(frame, "Piece request")).await,
            Err(error) => return self.abort_lane(error).await,
        };
        let shape = match TransferShape::negotiate(
            &request,
            metadata,
            self.lane.max_message_size,
            self.lane.max_receive_inflight,
        ) {
            Ok(shape) => shape,
            Err(error) => return self.abort_lane(error).await,
        };
        let metadata = shape.metadata.clone();
        let pipeline_depth = self.lane.receive_pipeline_depth;
        Ok((
            UrmaClientTransfer {
                lane: self.lane.clone(),
                transfer_control: Some(control),
                piece: Some(ClientPiece {
                    transfer_id,
                    shape,
                    next_post_chunk: 0,
                    next_deliver_chunk: 0,
                    receive_window_count: 0,
                    send_imm_chunk_count: 0,
                    reordered_chunk_count: 0,
                    cross_transfer_chunk_count: 0,
                    pending: VecDeque::with_capacity(pipeline_depth),
                    window_permits: Arc::new(Semaphore::new(pipeline_depth)),
                    pipeline_depth,
                }),
            },
            metadata,
        ))
    }

    pub(crate) fn lane_id(&self) -> u16 {
        self.lane.lane_id
    }

    async fn abort_lane<T>(&self, error: Error) -> Result<T> {
        self.lane.failed.store(true, Ordering::Release);
        self.lane.control.abort(error.to_string());
        warn!(role = "client", lane_id = self.lane.lane_id, %error, "aborting urma peer lane");
        let _ = self.lane.fabric.abort_lane(self.lane.lane_id).await;
        Err(error)
    }
}

impl UrmaClientTransfer {
    pub(crate) async fn abort_transfer(&mut self, message: impl Into<String>) -> Result<()> {
        self.abort(Error::Protocol(message.into())).await
    }

    async fn fill_receive_pipeline(&mut self, timeout: Duration) -> Result<()> {
        let lane_id = self.lane.lane_id;
        loop {
            let (window, expected_len, pending_count, permits) = {
                let piece = self
                    .piece
                    .as_ref()
                    .ok_or_else(|| Error::Protocol("no active URMA Piece".into()))?;
                if piece.pending.len() >= piece.pipeline_depth
                    || piece.next_post_chunk == piece.shape.chunk_count
                {
                    return Ok(());
                }
                let window = piece.shape.window(piece.next_post_chunk)?;
                (
                    window,
                    piece.shape.window_len(window)?,
                    piece.pending.len(),
                    piece.window_permits.clone(),
                )
            };
            // Every posted sequence is registered in the lane-global
            // completion dispatcher. Native RECV matching may therefore
            // cross Piece and window boundaries; SEND_IMM remains the
            // authoritative logical owner.
            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) if pending_count != 0 => return Ok(()),
                Err(_) => permits.acquire_owned().await.map_err(|_| Error::Shutdown {
                    failures: vec!["URMA RX window pipeline is closed".into()],
                })?,
            };
            let native_receive_credit = if pending_count == 0 {
                let requested = window.chunk_count;
                let available_before = self.lane.native_receive_permits.available_permits();
                let admission_start = time::Instant::now();
                let result = time::timeout(
                    timeout,
                    self.lane
                        .native_receive_permits
                        .clone()
                        .acquire_many_owned(requested),
                )
                .await;
                if available_before < requested as usize {
                    let wait = admission_start.elapsed();
                    collect_urma_required_admission_wait_metrics("rx", wait);
                    debug!(
                        lane_id,
                        required_rx_wait_count = 1u64,
                        required_rx_wait_ns = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX),
                        admitted = matches!(&result, Ok(Ok(_))),
                        "URMA native RX required admission wait finished"
                    );
                }
                match result {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => {
                        return self
                            .abort(Error::Shutdown {
                                failures: vec!["URMA native RX admission is closed".into()],
                            })
                            .await;
                    }
                    Err(_) => {
                        collect_urma_budget_pressure_metrics("rx", "required");
                        return self
                            .abort(Error::OperationTimeout {
                                sequence: Some(transfer_sequence(
                                    self.piece.as_ref().expect("active Piece").transfer_id,
                                    window.start_chunk,
                                )?),
                            })
                            .await;
                    }
                }
            } else {
                match self
                    .lane
                    .native_receive_permits
                    .clone()
                    .try_acquire_many_owned(window.chunk_count)
                {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(
                            lane_id,
                            requested = window.chunk_count,
                            available = self.lane.native_receive_permits.available_permits(),
                            "URMA RX second window unavailable at native JFR admission; continuing with one-window pipeline"
                        );
                        collect_urma_budget_pressure_metrics("rx", "optional");
                        return Ok(());
                    }
                }
            };
            let transfer_id = self.piece.as_ref().expect("active Piece").transfer_id;
            let chunks = (window.start_chunk..window.start_chunk + u64::from(window.chunk_count))
                .collect::<Vec<_>>();
            let sequences = chunks
                .iter()
                .map(|chunk| transfer_sequence(transfer_id, *chunk))
                .collect::<Result<Vec<_>>>()?;
            let post = if pending_count == 0 {
                // A Piece cannot make progress without its first RX window.
                // Keep its admission visible process-wide so optional second
                // windows on every lane yield while registered leases drain.
                let _required_waiter = self.lane.fabric.required_rx_waiter();
                let admission_start = time::Instant::now();
                let deadline = time::Instant::now() + timeout;
                let mut waited = false;
                let result = loop {
                    match self
                        .lane
                        .fabric
                        .post_receive_window_registered(lane_id, sequences.clone())
                        .await
                    {
                        Err(error @ Error::BufferUnavailable { .. }) => {
                            waited = true;
                            let remaining =
                                deadline.saturating_duration_since(time::Instant::now());
                            if remaining.is_zero() {
                                break Err(error);
                            }
                            time::sleep(REQUIRED_RX_RETRY_INTERVAL.min(remaining)).await;
                        }
                        result => break result,
                    }
                };
                if waited {
                    let wait = admission_start.elapsed();
                    collect_urma_required_admission_wait_metrics("rx", wait);
                    debug!(
                        lane_id,
                        required_rx_wait_count = 1u64,
                        required_rx_wait_ns = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX),
                        admitted = result.is_ok(),
                        "URMA RX required admission wait finished"
                    );
                }
                result
            } else {
                self.lane
                    .fabric
                    .try_post_receive_window_registered(lane_id, sequences.clone())
                    .await
            };
            let handles = match post {
                Ok(handles) => handles,
                Err(error @ Error::BufferUnavailable { .. }) if pending_count != 0 => {
                    // The first posted window guarantees forward progress. A
                    // second window is optional when the process-wide RX pool
                    // is under pressure.
                    debug!(
                        lane_id,
                        %error,
                        "URMA RX second window unavailable; continuing with one-window pipeline"
                    );
                    collect_urma_budget_pressure_metrics("rx", "optional");
                    return Ok(());
                }
                Err(error @ Error::BufferUnavailable { .. }) => {
                    collect_urma_budget_pressure_metrics("rx", "required");
                    return self.abort(error).await;
                }
                Err(error) => return self.abort(error).await,
            };
            let native_receive_permit = NativeReceiveWindowPermit::new(
                native_receive_credit,
                Arc::clone(&self.lane.native_receive_admission_state),
                lane_id,
                transfer_id,
                window,
            );
            if let Err(error) = send_transfer_control(
                self.transfer_control
                    .as_ref()
                    .expect("active Piece control"),
                Frame::RecvPosted {
                    transfer_id: self.piece.as_ref().expect("active Piece").transfer_id,
                    window,
                },
                self.lane.control_timeout,
                "send RecvPosted",
            )
            .await
            {
                return self.abort(error).await;
            }
            let piece = self.piece.as_mut().expect("active Piece");
            piece.next_post_chunk += u64::from(window.chunk_count);
            piece.pending.push_back(PendingReceiveWindow {
                window,
                expected_len,
                operations: handles,
                permit,
                _native_receive_permit: native_receive_permit,
            });
        }
    }

    pub(crate) async fn receive_next_window_registered(
        &mut self,
        timeout: Duration,
    ) -> Result<RegisteredRxWindowLease> {
        let lane_id = self.lane.lane_id;
        self.fill_receive_pipeline(timeout).await?;
        let pending = self
            .piece
            .as_mut()
            .and_then(|piece| piece.pending.pop_front())
            .ok_or_else(|| Error::Protocol("no pending URMA receive window".into()))?;
        let transfer_id = self.piece.as_ref().expect("active Piece").transfer_id;
        let mut completions = Vec::with_capacity(pending.operations.len());
        for operation in pending.operations {
            match operation.wait_timeout(timeout).await {
                Ok(completion) => completions.push(completion),
                Err(error) => return self.abort(error).await,
            }
        }
        let (leases, routing) = match reorder_receive_window_completions(
            lane_id,
            transfer_id,
            &self.piece.as_ref().expect("active Piece").shape,
            pending.window,
            completions,
        ) {
            Ok(leases) => leases,
            Err(error) => return self.abort(error).await,
        };
        let lease = match RegisteredRxWindowLease::merge(leases) {
            Ok(lease) if lease.len() == pending.expected_len => {
                lease.with_pipeline_permit(pending.permit)
            }
            Ok(lease) => {
                return self
                    .abort(Error::Protocol(format!(
                        "registered URMA window length mismatch: expected {}, got {}",
                        pending.expected_len,
                        lease.len()
                    )))
                    .await;
            }
            Err(error) => return self.abort(error).await,
        };
        let piece = self.piece.as_mut().expect("active Piece");
        piece.next_deliver_chunk += u64::from(pending.window.chunk_count);
        piece.receive_window_count += 1;
        piece.send_imm_chunk_count += u64::from(pending.window.chunk_count);
        piece.reordered_chunk_count += routing.reordered_chunk_count;
        piece.cross_transfer_chunk_count += routing.cross_transfer_chunk_count;
        Ok(lease)
    }

    pub(crate) fn piece_complete(&self) -> bool {
        self.piece
            .as_ref()
            .is_some_and(|piece| piece.next_deliver_chunk == piece.shape.chunk_count)
    }

    pub(crate) async fn finish_piece(&mut self) -> Result<()> {
        let piece = self
            .piece
            .as_ref()
            .ok_or_else(|| Error::Protocol("no active URMA Piece".into()))?;
        if piece.next_deliver_chunk != piece.shape.chunk_count || !piece.pending.is_empty() {
            return Err(Error::Protocol("URMA Piece is not fully received".into()));
        }
        let control = self
            .transfer_control
            .as_mut()
            .ok_or_else(|| Error::Protocol("no active URMA Piece control".into()))?;
        match receive_transfer_control(control, self.lane.control_timeout, "receive Piece Done")
            .await
        {
            Ok(Frame::Done { transfer_id }) if transfer_id == piece.transfer_id => {
                debug!(
                    role = "client",
                    lane_id = self.lane.lane_id,
                    transfer_id,
                    receive_window_count = piece.receive_window_count,
                    send_imm_chunk_count = piece.send_imm_chunk_count,
                    reordered_chunk_count = piece.reordered_chunk_count,
                    cross_transfer_chunk_count = piece.cross_transfer_chunk_count,
                    "urma piece finished on peer lane"
                );
                self.piece = None;
                self.transfer_control
                    .take()
                    .expect("active Piece control")
                    .finish();
                Ok(())
            }
            Ok(frame) => self.abort(unexpected(frame, "Piece finish")).await,
            Err(error) => self.abort(error).await,
        }
    }

    async fn abort<T>(&mut self, error: Error) -> Result<T> {
        if let Some(piece) = self.piece.as_mut() {
            piece.pending.clear();
        }
        self.transfer_control.take();
        self.lane.failed.store(true, Ordering::Release);
        self.lane.control.abort(error.to_string());
        warn!(role = "client", lane_id = self.lane.lane_id, %error, "aborting urma peer lane");
        let _ = self.lane.fabric.abort_lane(self.lane.lane_id).await;
        Err(error)
    }
}

struct ServerPiece {
    transfer_id: TransferId,
    request: CommonPieceRequest,
    shape: Option<TransferShape>,
    next_chunk: u64,
}

struct ServerLane {
    control: LaneControl,
    fabric: UrmaFabricHandle,
    lane_id: u16,
    max_message_size: u64,
    max_send_inflight: u32,
    native_send_permits: Arc<Semaphore>,
    control_timeout: Duration,
    failed: AtomicBool,
    closed: AtomicBool,
}

impl Drop for ServerLane {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            debug!(
                role = "server",
                lane_id = self.lane_id,
                "dropping urma peer lane"
            );
            self.control.abort("URMA server lane owner was dropped");
            let _ = self.fabric.try_abort_lane(self.lane_id);
        }
    }
}

/// Uploader-side handle to one persistent lane. Each accepted Piece is moved
/// into an independent [`UrmaServerTransfer`].
pub(crate) struct UrmaServerSession<S> {
    lane: Arc<ServerLane>,
    stream_type: PhantomData<S>,
}

pub(crate) struct UrmaServerTransfer {
    lane: Arc<ServerLane>,
    transfer_control: Option<TransferControl>,
    piece: Option<ServerPiece>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> UrmaServerSession<S> {
    pub(crate) async fn accept(
        mut stream: S,
        fabric: UrmaFabricHandle,
        lane_config: UrmaLaneConfig,
        local_capability: &UrmaCapability,
        control_timeout: Duration,
        max_concurrent_transfers: usize,
        max_send_inflight: u32,
    ) -> Result<Self> {
        let connect =
            match read_control(&mut stream, control_timeout, "receive lane Connect").await? {
                Frame::Connect(connect) => connect,
                frame => return Err(unexpected(frame, "lane accept")),
            };
        if let Err(reason) = local_capability.compatible(&connect.capability) {
            let _ = write_error(
                &mut stream,
                0,
                ERROR_CODE_INCOMPATIBLE,
                &reason,
                control_timeout,
            )
            .await;
            return Err(Error::Protocol(reason));
        }
        let max_message_size = local_capability
            .max_message_size
            .min(connect.capability.max_message_size);
        if max_send_inflight == 0 || max_send_inflight > lane_config.send_depth {
            return Err(Error::InvalidConfiguration(format!(
                "URMA per-Piece send inflight {max_send_inflight} exceeds lane send depth {}",
                lane_config.send_depth
            )));
        }
        let (lane_id, server_descriptor) = fabric.create_lane(lane_config).await?;
        let handshake = async {
            fabric
                .connect_lane(lane_id, connect.client_descriptor)
                .await?;
            write_control(
                &mut stream,
                &Frame::Connected(LaneConnected { server_descriptor }),
                control_timeout,
                "send lane Connected",
            )
            .await
        }
        .await;
        if let Err(error) = handshake {
            let _ = fabric.abort_lane(lane_id).await;
            return Err(error);
        }
        info!(
            role = "server",
            lane_id,
            transport_mode = ?lane_config.transport_mode,
            "urma peer lane established"
        );
        Ok(Self {
            lane: Arc::new(ServerLane {
                control: LaneControl::spawn(stream, max_concurrent_transfers)?,
                fabric,
                lane_id,
                max_message_size,
                max_send_inflight,
                native_send_permits: Arc::new(Semaphore::new(lane_config.send_depth as usize)),
                control_timeout,
                failed: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            }),
            stream_type: PhantomData,
        })
    }

    /// Waits for the next Piece request while the Session is idle. `Ok(None)` is a normal idle
    /// expiry: no Piece or native operation is active, so the server can close the lane without
    /// classifying the expiry as a transport failure.
    pub(crate) async fn receive_request(
        &self,
        idle_timeout: Duration,
    ) -> Result<Option<(UrmaServerTransfer, CommonPieceRequest)>> {
        if self.lane.failed.load(Ordering::Acquire) {
            return Err(Error::Protocol("URMA server lane is failed".into()));
        }
        let incoming = match time::timeout(idle_timeout, self.lane.control.accept()).await {
            Ok(Ok(incoming)) => incoming,
            Ok(Err(error)) => return self.abort_lane(error).await,
            Err(_) => return Ok(None),
        };
        let transfer_id = incoming.control.transfer_id();
        let request = incoming.request;
        let control = incoming.control;
        if request.task_id.is_empty()
            || request.chunk_size == 0
            || request.chunk_size > self.lane.max_message_size
            || request.max_inflight_chunks == 0
        {
            let error = Error::Protocol("invalid URMA Piece request".into());
            let _ = send_piece_error(
                &control,
                transfer_id,
                ERROR_CODE_INTERNAL,
                &error.to_string(),
                self.lane.control_timeout,
            )
            .await;
            return self.abort_lane(error).await;
        }
        debug!(
            role = "server",
            lane_id = self.lane.lane_id,
            transfer_id,
            piece_kind = ?request.kind,
            piece_number = request.piece_number,
            "urma piece request received on peer lane"
        );
        Ok(Some((
            UrmaServerTransfer {
                lane: self.lane.clone(),
                transfer_control: Some(control),
                piece: Some(ServerPiece {
                    transfer_id,
                    request: request.clone(),
                    shape: None,
                    next_chunk: 0,
                }),
            },
            request,
        )))
    }

    pub(crate) fn lane_id(&self) -> u16 {
        self.lane.lane_id
    }

    pub(crate) async fn close(self) -> Result<()> {
        info!(
            role = "server",
            lane_id = self.lane.lane_id,
            "closing urma peer lane"
        );
        let result = self.lane.fabric.close_lane(self.lane.lane_id).await;
        if result.is_ok() {
            self.lane.closed.store(true, Ordering::Release);
        }
        result
    }

    async fn abort_lane<T>(&self, error: Error) -> Result<T> {
        self.lane.failed.store(true, Ordering::Release);
        self.lane.control.abort(error.to_string());
        warn!(role = "server", lane_id = self.lane.lane_id, %error, "aborting urma peer lane");
        let _ = self.lane.fabric.abort_lane(self.lane.lane_id).await;
        Err(error)
    }
}

impl UrmaServerTransfer {
    pub(crate) fn lane_id(&self) -> u16 {
        self.lane.lane_id
    }

    pub(crate) fn transfer_id(&self) -> TransferId {
        self.piece.as_ref().expect("active Piece").transfer_id
    }
    pub(crate) async fn ready(&mut self, metadata: PieceMetadata) -> Result<()> {
        let piece = self
            .piece
            .as_ref()
            .ok_or_else(|| Error::Protocol("no pending URMA Piece".into()))?;
        if piece.shape.is_some() {
            return Err(Error::Protocol("URMA Piece is already ready".into()));
        }
        let shape = match TransferShape::negotiate(
            &piece.request,
            metadata.clone(),
            self.lane.max_message_size,
            self.lane.max_send_inflight,
        ) {
            Ok(shape) => shape,
            Err(error) => return self.abort_peer(error).await,
        };
        if let Err(error) = send_transfer_control(
            self.transfer_control
                .as_ref()
                .expect("pending Piece control"),
            Frame::Ready {
                transfer_id: piece.transfer_id,
                metadata,
            },
            self.lane.control_timeout,
            "send Piece Ready",
        )
        .await
        {
            return self.abort(error).await;
        }
        self.piece.as_mut().expect("pending Piece").shape = Some(shape);
        Ok(())
    }

    /// Sends one already-filled registered window without copying payload
    /// bytes through an owned Vec or back into TX slots.
    pub(crate) async fn send_next_registered_window(
        &mut self,
        lease: TxWindowLease,
        timeout: Duration,
    ) -> Result<(TxWindowLease, RegisteredSendTiming)> {
        let mut timing = RegisteredSendTiming::default();
        let lane_id = self.lane.lane_id;
        let piece = self
            .piece
            .as_ref()
            .ok_or_else(|| Error::Protocol("no active URMA Piece".into()))?;
        let shape = piece
            .shape
            .as_ref()
            .ok_or_else(|| Error::Protocol("URMA Piece is not ready".into()))?;
        let expected = shape.window(piece.next_chunk)?;
        let recv_posted_start = Instant::now();
        let window = match receive_transfer_control(
            self.transfer_control
                .as_mut()
                .expect("active Piece control"),
            self.lane.control_timeout,
            "receive RecvPosted",
        )
        .await
        {
            Ok(Frame::RecvPosted {
                transfer_id,
                window,
            }) if transfer_id == piece.transfer_id => window,
            Ok(frame) => return self.abort_peer(unexpected(frame, "receive credit")).await,
            Err(error) => return self.abort(error).await,
        };
        timing.recv_posted_wait_ns = recv_posted_start.elapsed().as_nanos() as u64;
        if window != expected {
            return self
                .abort_peer(Error::Protocol(format!(
                    "invalid URMA receive window: expected {expected:?}, got {window:?}"
                )))
                .await;
        }
        let expected_len = shape.window_len(window)?;
        if lease.len() != expected_len || lease.chunk_count() != window.chunk_count as usize {
            return self
                .abort_peer(Error::Protocol(format!(
                    "URMA registered TX window mismatch: expected {expected_len} bytes/{} chunks, got {} bytes/{} chunks",
                    window.chunk_count,
                    lease.len(),
                    lease.chunk_count()
                )))
                .await;
        }
        let requested = window.chunk_count;
        let available_before = self.lane.native_send_permits.available_permits();
        let admission_start = time::Instant::now();
        let admission = time::timeout(
            timeout,
            self.lane
                .native_send_permits
                .clone()
                .acquire_many_owned(requested),
        )
        .await;
        if available_before < requested as usize {
            let wait = admission_start.elapsed();
            collect_urma_required_admission_wait_metrics("tx", wait);
            debug!(
                lane_id,
                transfer_id = piece.transfer_id,
                requested,
                available_before,
                required_tx_wait_count = 1u64,
                required_tx_wait_ns = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX),
                admitted = matches!(&admission, Ok(Ok(_))),
                "URMA native TX required admission wait finished"
            );
        }
        let _native_send_permit = match admission {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return self
                    .abort(Error::Shutdown {
                        failures: vec!["URMA native TX admission is closed".into()],
                    })
                    .await;
            }
            Err(_) => {
                collect_urma_budget_pressure_metrics("tx", "required");
                return self
                    .abort_peer(Error::OperationTimeout {
                        sequence: Some(transfer_sequence(piece.transfer_id, window.start_chunk)?),
                    })
                    .await;
            }
        };
        let grant_credit_start = Instant::now();
        if let Err(error) = self
            .lane
            .fabric
            .grant_send_credit(lane_id, window.chunk_count)
            .await
        {
            return self.abort_peer(error).await;
        }
        timing.grant_credit_ns = grant_credit_start.elapsed().as_nanos() as u64;
        let sequences = (window.start_chunk..window.start_chunk + u64::from(window.chunk_count))
            .map(|chunk| transfer_sequence(piece.transfer_id, chunk))
            .collect::<Result<Vec<_>>>()?;
        let wr_post_start = Instant::now();
        let operation = match self
            .lane
            .fabric
            .send_registered_window(lane_id, lease, sequences.clone())
            .await
        {
            Ok(operation) => operation,
            Err(error) => return self.abort_peer(error).await,
        };
        timing.wr_post_ns = wr_post_start.elapsed().as_nanos() as u64;
        let send_cqe_start = Instant::now();
        let completed = match operation.wait_timeout(timeout).await {
            Ok(completed) => completed,
            Err(error) => return self.abort_peer(error).await,
        };
        timing.send_cqe_wait_ns = send_cqe_start.elapsed().as_nanos() as u64;
        if completed.lane_id != lane_id || completed.sequences != sequences {
            return self
                .abort_peer(Error::Protocol(
                    "invalid URMA registered TX window completion".into(),
                ))
                .await;
        }
        self.piece.as_mut().expect("active Piece").next_chunk += u64::from(window.chunk_count);
        Ok((completed.lease, timing))
    }

    pub(crate) async fn finish_piece(&mut self) -> Result<()> {
        let piece = self
            .piece
            .as_ref()
            .ok_or_else(|| Error::Protocol("no active URMA Piece".into()))?;
        let shape = piece
            .shape
            .as_ref()
            .ok_or_else(|| Error::Protocol("URMA Piece is not ready".into()))?;
        if piece.next_chunk != shape.chunk_count {
            return self
                .abort_peer(Error::Protocol("URMA Piece is not fully sent".into()))
                .await;
        }
        if let Err(error) = send_transfer_control(
            self.transfer_control
                .as_ref()
                .expect("active Piece control"),
            Frame::Done {
                transfer_id: piece.transfer_id,
            },
            self.lane.control_timeout,
            "send Piece Done",
        )
        .await
        {
            return self.abort(error).await;
        }
        debug!(
            role = "server",
            lane_id = self.lane.lane_id,
            transfer_id = piece.transfer_id,
            "urma piece finished on peer lane"
        );
        self.piece = None;
        self.transfer_control
            .take()
            .expect("active Piece control")
            .finish();
        Ok(())
    }

    /// Rejects this Piece and conservatively retires the multiplexed lane.
    /// Only BUSY is currently classified as transfer-local; expanding that
    /// set requires matching downloader cache/penalty policy.
    pub(crate) async fn reject_piece(&mut self, code: u32, message: &str) -> Result<()> {
        let piece = self
            .piece
            .as_ref()
            .ok_or_else(|| Error::Protocol("no pending URMA Piece to reject".into()))?;
        if piece.shape.is_some() {
            return self
                .abort_peer(Error::Protocol(format!(
                    "cannot reject active URMA Piece locally: code={code} message={message}"
                )))
                .await;
        }
        let transfer_id = piece.transfer_id;
        let write_result = send_piece_error(
            self.transfer_control
                .as_ref()
                .expect("pending Piece control"),
            transfer_id,
            code,
            message,
            self.lane.control_timeout,
        )
        .await;
        self.piece = None;
        self.transfer_control.take();
        self.lane.failed.store(true, Ordering::Release);
        self.lane.control.abort(message.to_string());
        let abort_result = self.lane.fabric.abort_lane(self.lane.lane_id).await;
        write_result.and(abort_result)
    }

    /// Rejects the pending BUSY Piece while keeping the peer lane and sibling
    /// transfers alive.
    pub(crate) async fn reject_piece_transient(&mut self, code: u32, message: &str) -> Result<()> {
        let piece = self
            .piece
            .as_ref()
            .ok_or_else(|| Error::Protocol("no pending URMA Piece to reject".into()))?;
        if piece.shape.is_some() {
            return self
                .abort_peer(Error::Protocol(format!(
                    "cannot reject active URMA Piece transiently: code={code} message={message}"
                )))
                .await;
        }
        let transfer_id = piece.transfer_id;
        let write_result = send_piece_error(
            self.transfer_control
                .as_ref()
                .expect("pending Piece control"),
            transfer_id,
            code,
            message,
            self.lane.control_timeout,
        )
        .await;
        self.piece = None;
        self.transfer_control
            .take()
            .expect("pending Piece control")
            .finish();
        write_result
    }

    pub(crate) async fn abort_transfer(&mut self, message: impl Into<String>) -> Result<()> {
        self.abort(Error::Protocol(message.into())).await
    }

    async fn abort<T>(&mut self, error: Error) -> Result<T> {
        self.transfer_control.take();
        self.lane.failed.store(true, Ordering::Release);
        self.lane.control.abort(error.to_string());
        warn!(role = "server", lane_id = self.lane.lane_id, %error, "aborting urma peer lane");
        let _ = self.lane.fabric.abort_lane(self.lane.lane_id).await;
        Err(error)
    }

    async fn abort_peer<T>(&mut self, error: Error) -> Result<T> {
        if let (Some(piece), Some(control)) = (&self.piece, &self.transfer_control) {
            let _ = send_piece_error(
                control,
                piece.transfer_id,
                ERROR_CODE_INTERNAL,
                &error.to_string(),
                self.lane.control_timeout,
            )
            .await;
        }
        self.lane.control.abort(error.to_string());
        self.abort(error).await
    }
}

async fn write_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    transfer_id: TransferId,
    code: u32,
    message: &str,
    timeout: Duration,
) -> Result<()> {
    write_control(
        stream,
        &Frame::Error {
            transfer_id,
            error: RendezvousError {
                code,
                message: message.to_string(),
            },
        },
        timeout,
        "send Error",
    )
    .await
}

async fn send_piece_error(
    control: &TransferControl,
    transfer_id: TransferId,
    code: u32,
    message: &str,
    timeout: Duration,
) -> Result<()> {
    send_transfer_control(
        control,
        Frame::Error {
            transfer_id,
            error: RendezvousError {
                code,
                message: message.to_string(),
            },
        },
        timeout,
        "send Error",
    )
    .await
}

#[cfg(test)]
async fn read_idle_control<S: AsyncRead + Unpin>(
    stream: &mut S,
    idle_timeout: Duration,
) -> Result<Option<Frame>> {
    match read_control(stream, idle_timeout, "wait for next Piece Request").await {
        Ok(frame) => Ok(Some(frame)),
        Err(Error::ControlTimeout { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::PieceKind;
    use crate::urma::buffer::SlotId;

    fn request() -> CommonPieceRequest {
        CommonPieceRequest {
            kind: PieceKind::Piece,
            task_id: "task".into(),
            piece_number: 1,
            chunk_size: 4,
            max_inflight_chunks: 2,
        }
    }

    fn reorder_shape() -> TransferShape {
        TransferShape {
            metadata: PieceMetadata {
                offset: 0,
                length: 10,
                digest: "crc32:1".into(),
                chunk_size: 4,
                max_inflight_chunks: 3,
            },
            chunk_count: 3,
        }
    }

    fn rx_completion(
        slot: usize,
        posted_transfer: TransferId,
        posted_chunk: u64,
        received_transfer: TransferId,
        received_chunk: u64,
        bytes: Vec<u8>,
    ) -> RegisteredRxCompletion {
        RegisteredRxCompletion {
            lane_id: 4,
            posted_sequence: Some(transfer_sequence(posted_transfer, posted_chunk).unwrap()),
            imm_data: transfer_sequence(received_transfer, received_chunk).unwrap(),
            slot: SlotId::new(slot, 1).unwrap(),
            lease: RegisteredRxWindowLease::from_test_untracked_parts(vec![bytes]),
        }
    }

    #[test]
    fn transfer_shape_bounds_windows_and_tail_chunk() {
        let shape = TransferShape::negotiate(
            &request(),
            PieceMetadata {
                offset: 0,
                length: 10,
                digest: "crc32:1".into(),
                chunk_size: 4,
                max_inflight_chunks: 2,
            },
            4,
            2,
        )
        .unwrap();
        assert_eq!(shape.chunk_count, 3);
        assert_eq!(
            shape.window(0).unwrap(),
            ReceiveWindow {
                start_chunk: 0,
                chunk_count: 2
            }
        );
        assert_eq!(shape.window_len(shape.window(0).unwrap()).unwrap(), 8);
        assert_eq!(shape.window_len(shape.window(2).unwrap()).unwrap(), 2);
    }

    #[test]
    fn transfer_sequences_namespace_equal_chunk_indexes() {
        assert_eq!(transfer_sequence(1, 0).unwrap(), 1u64 << 32);
        assert_eq!(transfer_sequence(2, 0).unwrap(), 2u64 << 32);
        assert_ne!(
            transfer_sequence(7, 42).unwrap(),
            transfer_sequence(8, 42).unwrap()
        );
        assert!(transfer_sequence(0, 0).is_err());
        assert!(transfer_sequence(1, u64::from(u32::MAX) + 1).is_err());
    }

    #[test]
    fn send_imm_reorders_receive_leases_by_actual_chunk_identity() {
        let shape = reorder_shape();
        let window = ReceiveWindow {
            start_chunk: 0,
            chunk_count: 3,
        };
        let completions = vec![
            // The short tail lands in the full-capacity WR posted for chunk 0.
            rx_completion(8, 7, 0, 7, 2, vec![2; 2]),
            rx_completion(9, 7, 1, 7, 0, vec![0; 4]),
            rx_completion(10, 7, 2, 7, 1, vec![1; 4]),
        ];

        let (leases, routing) =
            reorder_receive_window_completions(4, 7, &shape, window, completions).unwrap();
        let merged = RegisteredRxWindowLease::merge(leases).unwrap();
        assert_eq!(routing.reordered_chunk_count, 3);
        assert_eq!(routing.cross_transfer_chunk_count, 0);
        assert_eq!(merged.len(), 10);
        assert_eq!(
            merged.parts().collect::<Vec<_>>(),
            vec![&[0, 0, 0, 0][..], &[1, 1, 1, 1][..], &[2, 2][..]]
        );
    }

    #[test]
    fn send_imm_routes_a_slot_posted_for_another_transfer() {
        let shape = reorder_shape();
        let window = ReceiveWindow {
            start_chunk: 0,
            chunk_count: 1,
        };
        let (leases, routing) = reorder_receive_window_completions(
            4,
            7,
            &shape,
            window,
            vec![rx_completion(8, 9, 11, 7, 0, vec![0; 4])],
        )
        .unwrap();

        assert_eq!(leases.len(), 1);
        assert_eq!(routing.reordered_chunk_count, 1);
        assert_eq!(routing.cross_transfer_chunk_count, 1);
    }

    #[test]
    fn native_rx_admission_tracks_distinct_concurrent_transfers() {
        let permits = Arc::new(Semaphore::new(3));
        let state = Arc::new(Mutex::new(NativeReceiveAdmissionState::default()));
        let first = NativeReceiveWindowPermit::new(
            permits.clone().try_acquire_owned().unwrap(),
            Arc::clone(&state),
            4,
            7,
            ReceiveWindow {
                start_chunk: 0,
                chunk_count: 1,
            },
        );
        let same_transfer = NativeReceiveWindowPermit::new(
            permits.clone().try_acquire_owned().unwrap(),
            Arc::clone(&state),
            4,
            7,
            ReceiveWindow {
                start_chunk: 1,
                chunk_count: 1,
            },
        );
        let other_transfer = NativeReceiveWindowPermit::new(
            permits.try_acquire_owned().unwrap(),
            Arc::clone(&state),
            4,
            8,
            ReceiveWindow {
                start_chunk: 0,
                chunk_count: 1,
            },
        );
        {
            let state = state.lock().unwrap();
            assert_eq!(state.active_windows, 3);
            assert_eq!(state.active_windows_by_transfer.len(), 2);
        }

        drop(other_transfer);
        drop(same_transfer);
        drop(first);
        let state = state.lock().unwrap();
        assert_eq!(state.active_windows, 0);
        assert!(state.active_windows_by_transfer.is_empty());
    }

    #[test]
    fn send_imm_reordering_rejects_wrong_transfer_duplicate_and_out_of_window_chunk() {
        let shape = reorder_shape();
        let one = ReceiveWindow {
            start_chunk: 0,
            chunk_count: 1,
        };
        assert!(reorder_receive_window_completions(
            4,
            7,
            &shape,
            one,
            vec![rx_completion(8, 7, 0, 8, 0, vec![0; 4])],
        )
        .is_err());
        assert!(reorder_receive_window_completions(
            4,
            7,
            &shape,
            one,
            vec![rx_completion(8, 7, 0, 7, 1, vec![1; 4])],
        )
        .is_err());

        let two = ReceiveWindow {
            start_chunk: 0,
            chunk_count: 2,
        };
        assert!(reorder_receive_window_completions(
            4,
            7,
            &shape,
            two,
            vec![rx_completion(8, 7, 0, 7, 0, vec![0; 4])],
        )
        .is_err());
        assert!(reorder_receive_window_completions(
            4,
            7,
            &shape,
            two,
            vec![
                rx_completion(8, 7, 0, 7, 0, vec![0; 4]),
                rx_completion(9, 7, 1, 7, 0, vec![0; 4]),
            ],
        )
        .is_err());
        assert!(reorder_receive_window_completions(
            4,
            7,
            &shape,
            one,
            vec![rx_completion(8, 7, 0, 7, 0, vec![0; 3])],
        )
        .is_err());
    }

    #[test]
    fn transfer_shape_rejects_metadata_that_exceeds_negotiation() {
        let metadata = PieceMetadata {
            offset: 0,
            length: 10,
            digest: "crc32:1".into(),
            chunk_size: 5,
            max_inflight_chunks: 2,
        };
        assert!(TransferShape::negotiate(&request(), metadata, 4, 2).is_err());
    }

    #[test]
    fn window_past_piece_end_is_rejected_without_underflow() {
        let shape = TransferShape::negotiate(
            &request(),
            PieceMetadata {
                offset: 0,
                length: 4,
                digest: "crc32:1".into(),
                chunk_size: 4,
                max_inflight_chunks: 1,
            },
            4,
            1,
        )
        .unwrap();
        assert!(shape
            .window_len(ReceiveWindow {
                start_chunk: 2,
                chunk_count: 1,
            })
            .is_err());
    }

    #[test]
    fn transfer_shape_rejects_inflight_above_local_lane_depth() {
        let metadata = PieceMetadata {
            offset: 0,
            length: 8,
            digest: "crc32:1".into(),
            chunk_size: 4,
            max_inflight_chunks: 2,
        };
        assert!(TransferShape::negotiate(&request(), metadata, 4, 1).is_err());
    }

    #[test]
    fn peer_error_code_is_preserved_for_adapter_policy() {
        let error = unexpected(
            Frame::Error {
                transfer_id: 3,
                error: RendezvousError {
                    code: crate::rendezvous::ERROR_CODE_NOT_FOUND,
                    message: "missing Piece".into(),
                },
            },
            "Piece request",
        );
        assert_eq!(
            error,
            Error::PeerRejected {
                code: crate::rendezvous::ERROR_CODE_NOT_FOUND,
                message: "missing Piece".into(),
            }
        );
    }

    #[test]
    fn busy_is_distinguishable_from_terminal_peer_rejections() {
        // The BUSY guard in request_piece and the adapter mapping both key on
        // this code; NOT_FOUND must keep flowing through the terminal path.
        assert_ne!(
            crate::rendezvous::ERROR_CODE_BUSY,
            crate::rendezvous::ERROR_CODE_NOT_FOUND
        );
        assert_ne!(
            crate::rendezvous::ERROR_CODE_BUSY,
            crate::rendezvous::ERROR_CODE_INCOMPATIBLE
        );
    }

    #[tokio::test]
    async fn stalled_control_read_has_a_typed_timeout() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        assert_eq!(
            read_control(&mut reader, Duration::ZERO, "test read").await,
            Err(Error::ControlTimeout {
                operation: "test read"
            })
        );
    }

    #[tokio::test]
    async fn stalled_idle_request_is_a_normal_expiry() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        assert_eq!(
            read_idle_control(&mut reader, Duration::ZERO).await,
            Ok(None)
        );
    }
}
