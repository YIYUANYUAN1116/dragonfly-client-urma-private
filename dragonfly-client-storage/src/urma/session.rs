//! Persistent peer session over the thread-owned URMA fabric.
//!
//! A TCP control connection and one bound Jetty are established once, then
//! reused for sequential Piece transfers. Storage lookup and stream exposure
//! stay in the future `client::urma` / `server::urma` adapters.

use super::{
    buffer::{RegisteredRxWindowLease, TxWindowLease},
    fabric::{UrmaFabricHandle, UrmaLaneConfig, UrmaRegisteredRxOpHandle},
    rendezvous::{
        read_frame, write_frame, CommonPieceRequest, Frame, LaneConnect, LaneConnected,
        PieceMetadata, ReceiveWindow, RendezvousError, UrmaCapability,
    },
    Error, Result,
};
use crate::rendezvous::{ERROR_CODE_INCOMPATIBLE, ERROR_CODE_INTERNAL};
use dragonfly_client_core::Error as ClientError;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, Semaphore},
    time,
};
use tracing::{debug, info, warn};

fn control_error(error: ClientError) -> Error {
    Error::Protocol(format!("URMA rendezvous failed: {error}"))
}

fn unexpected(frame: Frame, phase: &str) -> Error {
    match frame {
        Frame::Error(error) => Error::PeerRejected {
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
    shape: TransferShape,
    next_post_chunk: u64,
    next_deliver_chunk: u64,
    pending: VecDeque<PendingReceiveWindow>,
    window_permits: std::sync::Arc<Semaphore>,
}

struct PendingReceiveWindow {
    window: ReceiveWindow,
    expected_len: usize,
    operations: Vec<(u64, UrmaRegisteredRxOpHandle)>,
    permit: OwnedSemaphorePermit,
}

const RECEIVE_PIPELINE_DEPTH: usize = 2;

/// Downloader-side peer session. `finish_piece` returns it to Idle so the
/// same control connection and Jetty can carry the next Piece.
pub(crate) struct UrmaClientSession<S> {
    stream: S,
    fabric: UrmaFabricHandle,
    lane_id: Option<u16>,
    max_message_size: u64,
    max_receive_inflight: u32,
    control_timeout: Duration,
    piece: Option<ClientPiece>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> UrmaClientSession<S> {
    pub(crate) async fn connect(
        mut stream: S,
        fabric: UrmaFabricHandle,
        lane_config: UrmaLaneConfig,
        local_capability: UrmaCapability,
        remote_capability: &UrmaCapability,
        control_timeout: Duration,
    ) -> Result<Self> {
        local_capability
            .compatible(remote_capability)
            .map_err(Error::Protocol)?;
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
            fabric.bind_lane(lane_id, connected.server_descriptor).await
        }
        .await;
        if let Err(error) = handshake {
            let _ = fabric.abort_lane(lane_id).await;
            return Err(error);
        }
        info!(role = "client", lane_id, "urma peer lane established");
        Ok(Self {
            stream,
            fabric,
            lane_id: Some(lane_id),
            max_message_size,
            max_receive_inflight: lane_config.recv_depth,
            control_timeout,
            piece: None,
        })
    }

    pub(crate) async fn request_piece(
        &mut self,
        request: CommonPieceRequest,
    ) -> Result<PieceMetadata> {
        if self.piece.is_some() {
            return Err(Error::Protocol("an URMA Piece is already active".into()));
        }
        if request.task_id.is_empty()
            || request.chunk_size == 0
            || request.chunk_size > self.max_message_size
            || request.max_inflight_chunks == 0
            || request.max_inflight_chunks > self.max_receive_inflight
        {
            return Err(Error::Protocol("invalid URMA Piece request".into()));
        }
        debug!(
            role = "client",
            lane_id = self.open_lane()?,
            piece_kind = ?request.kind,
            piece_number = request.piece_number,
            "urma piece request on peer lane"
        );
        if let Err(error) = write_control(
            &mut self.stream,
            &Frame::Request(request.clone()),
            self.control_timeout,
            "send Piece Request",
        )
        .await
        {
            return self.abort(error).await;
        }
        let metadata = match read_control(
            &mut self.stream,
            self.control_timeout,
            "receive Piece Ready",
        )
        .await
        {
            Ok(Frame::Ready(metadata)) => metadata,
            Ok(frame) => return self.abort(unexpected(frame, "Piece request")).await,
            Err(error) => return self.abort(error).await,
        };
        let shape = match TransferShape::negotiate(
            &request,
            metadata,
            self.max_message_size,
            self.max_receive_inflight,
        ) {
            Ok(shape) => shape,
            Err(error) => return self.abort(error).await,
        };
        let metadata = shape.metadata.clone();
        self.piece = Some(ClientPiece {
            shape,
            next_post_chunk: 0,
            next_deliver_chunk: 0,
            pending: VecDeque::with_capacity(RECEIVE_PIPELINE_DEPTH),
            window_permits: std::sync::Arc::new(Semaphore::new(RECEIVE_PIPELINE_DEPTH)),
        });
        Ok(metadata)
    }

    async fn fill_receive_pipeline(&mut self) -> Result<()> {
        let lane_id = self.open_lane()?;
        loop {
            let (window, expected_len, pending_count, permits) = {
                let piece = self
                    .piece
                    .as_ref()
                    .ok_or_else(|| Error::Protocol("no active URMA Piece".into()))?;
                if piece.pending.len() >= RECEIVE_PIPELINE_DEPTH
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
            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) if pending_count != 0 => return Ok(()),
                Err(_) => permits.acquire_owned().await.map_err(|_| Error::Shutdown {
                    failures: vec!["URMA RX window pipeline is closed".into()],
                })?,
            };
            let sequences = (window.start_chunk
                ..window.start_chunk + u64::from(window.chunk_count))
                .collect::<Vec<_>>();
            let handles = match self
                .fabric
                .post_receive_window_registered(lane_id, sequences.clone())
                .await
            {
                Ok(handles) => handles,
                Err(Error::BufferUnavailable { .. }) if pending_count != 0 => {
                    // The first posted window guarantees forward progress. A
                    // second window is optional when the process-wide RX pool
                    // is under pressure.
                    return Ok(());
                }
                Err(error) => return self.abort(error).await,
            };
            if let Err(error) = write_control(
                &mut self.stream,
                &Frame::RecvPosted(window),
                self.control_timeout,
                "send RecvPosted",
            )
            .await
            {
                return self.abort(error).await;
            }
            let operations = sequences.into_iter().zip(handles).collect();
            let piece = self.piece.as_mut().expect("active Piece");
            piece.next_post_chunk += u64::from(window.chunk_count);
            piece.pending.push_back(PendingReceiveWindow {
                window,
                expected_len,
                operations,
                permit,
            });
        }
    }

    pub(crate) async fn receive_next_window_registered(
        &mut self,
        timeout: Duration,
    ) -> Result<RegisteredRxWindowLease> {
        let lane_id = self.open_lane()?;
        self.fill_receive_pipeline().await?;
        let pending = self
            .piece
            .as_mut()
            .and_then(|piece| piece.pending.pop_front())
            .ok_or_else(|| Error::Protocol("no pending URMA receive window".into()))?;
        let mut leases = Vec::with_capacity(pending.operations.len());
        for (chunk, operation) in pending.operations {
            let expected_len = self
                .piece
                .as_ref()
                .expect("active Piece")
                .shape
                .chunk_len(chunk)?;
            match operation.wait_timeout(timeout).await {
                Ok(completion)
                    if completion.lane_id == lane_id
                        && completion.sequence == Some(chunk)
                        && completion.lease.len() == expected_len =>
                {
                    leases.push(completion.lease);
                }
                Ok(completion) => {
                    return self
                        .abort(Error::Protocol(format!(
                            "invalid registered URMA receive completion for chunk {chunk}: lane={} sequence={:?} length={}",
                            completion.lane_id,
                            completion.sequence,
                            completion.lease.len()
                        )))
                        .await;
                }
                Err(error) => return self.abort(error).await,
            }
        }
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
        self.piece
            .as_mut()
            .expect("active Piece")
            .next_deliver_chunk += u64::from(pending.window.chunk_count);
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
        match read_control(&mut self.stream, self.control_timeout, "receive Piece Done").await {
            Ok(Frame::Done) => {
                debug!(
                    role = "client",
                    lane_id = self.open_lane()?,
                    "urma piece finished on peer lane"
                );
                self.piece = None;
                Ok(())
            }
            Ok(frame) => self.abort(unexpected(frame, "Piece finish")).await,
            Err(error) => self.abort(error).await,
        }
    }

    pub(crate) async fn close(mut self) -> Result<()> {
        if self.piece.is_some() {
            return self
                .abort(Error::Protocol(
                    "cannot close with an active URMA Piece".into(),
                ))
                .await;
        }
        let lane_id = self.lane_id.take().expect("open peer lane");
        info!(role = "client", lane_id, "closing urma peer lane");
        self.fabric.close_lane(lane_id).await
    }

    pub(crate) fn lane_id(&self) -> Option<u16> {
        self.lane_id
    }

    fn open_lane(&self) -> Result<u16> {
        self.lane_id
            .ok_or_else(|| Error::Protocol("URMA client session is closed".into()))
    }

    async fn abort<T>(&mut self, error: Error) -> Result<T> {
        if let Some(piece) = self.piece.as_mut() {
            piece.pending.clear();
        }
        if let Some(lane_id) = self.lane_id.take() {
            warn!(role = "client", lane_id, %error, "aborting urma peer lane");
            let _ = self.fabric.abort_lane(lane_id).await;
        }
        Err(error)
    }
}

impl<S> Drop for UrmaClientSession<S> {
    fn drop(&mut self) {
        if let Some(lane_id) = self.lane_id.take() {
            debug!(role = "client", lane_id, "dropping active urma peer lane");
            let _ = self.fabric.try_abort_lane(lane_id);
        }
    }
}

struct ServerPiece {
    request: CommonPieceRequest,
    shape: Option<TransferShape>,
    next_chunk: u64,
}

/// Uploader-side peer session. Storage reads `receive_request`, supplies
/// metadata via `ready`, then feeds one bounded window at a time.
pub(crate) struct UrmaServerSession<S> {
    stream: S,
    fabric: UrmaFabricHandle,
    lane_id: Option<u16>,
    max_message_size: u64,
    max_send_inflight: u32,
    control_timeout: Duration,
    piece: Option<ServerPiece>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> UrmaServerSession<S> {
    pub(crate) async fn accept(
        mut stream: S,
        fabric: UrmaFabricHandle,
        lane_config: UrmaLaneConfig,
        local_capability: &UrmaCapability,
        control_timeout: Duration,
    ) -> Result<Self> {
        let connect =
            match read_control(&mut stream, control_timeout, "receive lane Connect").await? {
                Frame::Connect(connect) => connect,
                frame => return Err(unexpected(frame, "lane accept")),
            };
        if let Err(reason) = local_capability.compatible(&connect.capability) {
            let _ = write_error(
                &mut stream,
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
        let (lane_id, server_descriptor) = fabric.create_lane(lane_config).await?;
        let handshake = async {
            fabric.bind_lane(lane_id, connect.client_descriptor).await?;
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
        info!(role = "server", lane_id, "urma peer lane established");
        Ok(Self {
            stream,
            fabric,
            lane_id: Some(lane_id),
            max_message_size,
            max_send_inflight: lane_config.send_depth,
            control_timeout,
            piece: None,
        })
    }

    /// Waits for the next Piece request while the Session is idle. `Ok(None)` is a normal idle
    /// expiry: no Piece or native operation is active, so the server can close the lane without
    /// classifying the expiry as a transport failure.
    pub(crate) async fn receive_request(
        &mut self,
        idle_timeout: Duration,
    ) -> Result<Option<CommonPieceRequest>> {
        if self.piece.is_some() {
            return Err(Error::Protocol("an URMA Piece is already active".into()));
        }
        let request = match read_idle_control(&mut self.stream, idle_timeout).await {
            Ok(Some(Frame::Request(request))) => request,
            Ok(Some(frame)) => return self.abort(unexpected(frame, "Piece request")).await,
            Ok(None) => return Ok(None),
            Err(error) => return self.abort(error).await,
        };
        if request.task_id.is_empty()
            || request.chunk_size == 0
            || request.chunk_size > self.max_message_size
            || request.max_inflight_chunks == 0
        {
            let error = Error::Protocol("invalid URMA Piece request".into());
            let _ = write_error(
                &mut self.stream,
                ERROR_CODE_INTERNAL,
                &error.to_string(),
                self.control_timeout,
            )
            .await;
            return self.abort(error).await;
        }
        self.piece = Some(ServerPiece {
            request: request.clone(),
            shape: None,
            next_chunk: 0,
        });
        debug!(
            role = "server",
            lane_id = self.open_lane()?,
            piece_kind = ?request.kind,
            piece_number = request.piece_number,
            "urma piece request received on peer lane"
        );
        Ok(Some(request))
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
            self.max_message_size,
            self.max_send_inflight,
        ) {
            Ok(shape) => shape,
            Err(error) => return self.abort_peer(error).await,
        };
        if let Err(error) = write_control(
            &mut self.stream,
            &Frame::Ready(metadata),
            self.control_timeout,
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
        let lane_id = self.open_lane()?;
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
        let window = match read_control(
            &mut self.stream,
            self.control_timeout,
            "receive RecvPosted",
        )
        .await
        {
            Ok(Frame::RecvPosted(window)) => window,
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
        let grant_credit_start = Instant::now();
        if let Err(error) = self
            .fabric
            .grant_send_credit(lane_id, window.chunk_count)
            .await
        {
            return self.abort_peer(error).await;
        }
        timing.grant_credit_ns = grant_credit_start.elapsed().as_nanos() as u64;
        let sequences = (window.start_chunk..window.start_chunk + u64::from(window.chunk_count))
            .collect::<Vec<_>>();
        let wr_post_start = Instant::now();
        let operation = match self
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
        if let Err(error) = write_control(
            &mut self.stream,
            &Frame::Done,
            self.control_timeout,
            "send Piece Done",
        )
        .await
        {
            return self.abort(error).await;
        }
        debug!(
            role = "server",
            lane_id = self.open_lane()?,
            "urma piece finished on peer lane"
        );
        self.piece = None;
        Ok(())
    }

    /// Rejects the pending Piece with a typed rendezvous error and retires the
    /// lane. Phase A treats any Piece rejection as terminal for the sequential
    /// peer session, matching the existing conservative error policy.
    pub(crate) async fn reject_piece(&mut self, code: u32, message: &str) -> Result<()> {
        if self.piece.is_none() {
            return Err(Error::Protocol("no pending URMA Piece to reject".into()));
        }
        let write_result = write_error(&mut self.stream, code, message, self.control_timeout).await;
        self.piece = None;
        let abort_result = match self.lane_id.take() {
            Some(lane_id) => self.fabric.abort_lane(lane_id).await,
            None => Ok(()),
        };
        write_result.and(abort_result)
    }

    pub(crate) async fn close(mut self) -> Result<()> {
        if self.piece.is_some() {
            return self
                .abort(Error::Protocol(
                    "cannot close with an active URMA Piece".into(),
                ))
                .await;
        }
        let lane_id = self.lane_id.take().expect("open peer lane");
        info!(role = "server", lane_id, "closing urma peer lane");
        self.fabric.close_lane(lane_id).await
    }

    pub(crate) fn lane_id(&self) -> Option<u16> {
        self.lane_id
    }

    fn open_lane(&self) -> Result<u16> {
        self.lane_id
            .ok_or_else(|| Error::Protocol("URMA server session is closed".into()))
    }

    async fn abort<T>(&mut self, error: Error) -> Result<T> {
        if let Some(lane_id) = self.lane_id.take() {
            warn!(role = "server", lane_id, %error, "aborting urma peer lane");
            let _ = self.fabric.abort_lane(lane_id).await;
        }
        Err(error)
    }

    async fn abort_peer<T>(&mut self, error: Error) -> Result<T> {
        let _ = write_error(
            &mut self.stream,
            ERROR_CODE_INTERNAL,
            &error.to_string(),
            self.control_timeout,
        )
        .await;
        self.abort(error).await
    }
}

impl<S> Drop for UrmaServerSession<S> {
    fn drop(&mut self) {
        if let Some(lane_id) = self.lane_id.take() {
            debug!(role = "server", lane_id, "dropping active urma peer lane");
            let _ = self.fabric.try_abort_lane(lane_id);
        }
    }
}

async fn write_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u32,
    message: &str,
    timeout: Duration,
) -> Result<()> {
    write_control(
        stream,
        &Frame::Error(RendezvousError {
            code,
            message: message.to_string(),
        }),
        timeout,
        "send Error",
    )
    .await
}

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

    fn request() -> CommonPieceRequest {
        CommonPieceRequest {
            kind: PieceKind::Piece,
            task_id: "task".into(),
            piece_number: 1,
            chunk_size: 4,
            max_inflight_chunks: 2,
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
            Frame::Error(RendezvousError {
                code: crate::rendezvous::ERROR_CODE_NOT_FOUND,
                message: "missing Piece".into(),
            }),
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
