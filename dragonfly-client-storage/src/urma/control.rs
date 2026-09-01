//! Transfer-scoped control dispatcher for one persistent URMA lane.
//!
//! One reader and one writer task own the TCP stream. Logical Piece transfers
//! receive independent inboxes keyed by `transfer_id`, so interleaved control
//! frames cannot be consumed by the wrong Piece task.

use super::{
    rendezvous::{read_frame, write_frame, CommonPieceRequest, Frame, TransferId},
    Error, Result,
};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
};

const FRAME_QUEUE_CAPACITY: usize = 16;

fn protocol_error(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

#[derive(Debug)]
enum TransferEvent {
    Frame(Frame),
    Closed(String),
}

pub(crate) struct IncomingTransfer {
    pub(crate) request: CommonPieceRequest,
    pub(crate) control: TransferControl,
}

pub(crate) struct TransferControl {
    transfer_id: TransferId,
    writer: mpsc::Sender<Frame>,
    receiver: mpsc::Receiver<TransferEvent>,
    routes: Arc<Mutex<HashMap<TransferId, mpsc::Sender<TransferEvent>>>>,
    retired: Arc<Mutex<HashSet<TransferId>>>,
    completed: bool,
    _permit: OwnedSemaphorePermit,
}

impl TransferControl {
    pub(crate) fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    pub(crate) async fn send(&self, frame: Frame) -> Result<()> {
        if frame.transfer_id() != Some(self.transfer_id) {
            return Err(protocol_error(format!(
                "attempted to send a frame for {:?} through transfer {}",
                frame.transfer_id(),
                self.transfer_id
            )));
        }
        self.writer
            .send(frame)
            .await
            .map_err(|_| protocol_error("URMA control writer is closed"))
    }

    pub(crate) async fn receive(&mut self) -> Result<Frame> {
        match self.receiver.recv().await {
            Some(TransferEvent::Frame(frame)) => Ok(frame),
            Some(TransferEvent::Closed(message)) => Err(protocol_error(message)),
            None => Err(protocol_error("URMA transfer control inbox is closed")),
        }
    }

    /// Removes a normally completed transfer without creating a cancellation
    /// tombstone. The caller must invoke this only after its terminal frame.
    pub(crate) fn finish(mut self) {
        self.routes.lock().unwrap().remove(&self.transfer_id);
        self.completed = true;
    }
}

impl Drop for TransferControl {
    fn drop(&mut self) {
        self.routes.lock().unwrap().remove(&self.transfer_id);
        if !self.completed {
            self.retired.lock().unwrap().insert(self.transfer_id);
        }
    }
}

pub(crate) struct LaneControl {
    writer: mpsc::Sender<Frame>,
    routes: Arc<Mutex<HashMap<TransferId, mpsc::Sender<TransferEvent>>>>,
    retired: Arc<Mutex<HashSet<TransferId>>>,
    incoming: Arc<AsyncMutex<mpsc::Receiver<IncomingTransfer>>>,
    admission: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
}

impl Drop for LaneControl {
    fn drop(&mut self) {
        self.abort("URMA lane control owner was dropped");
    }
}

impl LaneControl {
    pub(crate) fn spawn<S>(stream: S, max_concurrent_transfers: usize) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if max_concurrent_transfers == 0 {
            return Err(protocol_error(
                "URMA lane must allow at least one concurrent transfer",
            ));
        }

        let (mut reader, mut writer) = tokio::io::split(stream);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(FRAME_QUEUE_CAPACITY);
        let (incoming_tx, incoming_rx) =
            mpsc::channel::<IncomingTransfer>(max_concurrent_transfers);
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let retired = Arc::new(Mutex::new(HashSet::new()));
        let admission = Arc::new(Semaphore::new(max_concurrent_transfers));
        let (shutdown, shutdown_rx) = watch::channel(false);

        let writer_routes = routes.clone();
        let writer_shutdown = shutdown.clone();
        let mut writer_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = writer_shutdown_rx.changed() => return,
                    frame = writer_rx.recv() => match frame {
                        Some(frame) => frame,
                        None => return,
                    },
                };
                if let Err(error) = write_frame(&mut writer, &frame).await {
                    close_all(
                        &writer_routes,
                        format!("URMA control write failed: {error}"),
                    );
                    let _ = writer_shutdown.send(true);
                    return;
                }
            }
        });

        let reader_writer = writer_tx.clone();
        let reader_routes = routes.clone();
        let reader_retired = retired.clone();
        let reader_admission = admission.clone();
        let reader_shutdown = shutdown.clone();
        let mut reader_shutdown_rx = shutdown_rx;
        tokio::spawn(async move {
            loop {
                let read = tokio::select! {
                    _ = reader_shutdown_rx.changed() => return,
                    read = read_frame(&mut reader) => read,
                };
                let frame = match read {
                    Ok(frame) => frame,
                    Err(error) => {
                        close_all(&reader_routes, format!("URMA control read failed: {error}"));
                        let _ = reader_shutdown.send(true);
                        return;
                    }
                };

                if let Frame::Request {
                    transfer_id,
                    request,
                } = frame
                {
                    if transfer_id == 0 {
                        close_all(
                            &reader_routes,
                            "received an URMA Piece request with transfer_id 0".into(),
                        );
                        let _ = reader_shutdown.send(true);
                        return;
                    }
                    let permit = match reader_admission.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            let _ = reader_writer
                                .send(Frame::Error {
                                    transfer_id,
                                    error: crate::rendezvous::RendezvousError {
                                        code: crate::rendezvous::ERROR_CODE_BUSY,
                                        message: "URMA lane transfer admission is full".into(),
                                    },
                                })
                                .await;
                            continue;
                        }
                    };
                    let control = match register_transfer(
                        transfer_id,
                        reader_writer.clone(),
                        reader_routes.clone(),
                        reader_retired.clone(),
                        permit,
                    ) {
                        Ok(control) => control,
                        Err(error) => {
                            close_all(&reader_routes, error.to_string());
                            let _ = reader_shutdown.send(true);
                            return;
                        }
                    };
                    if incoming_tx
                        .send(IncomingTransfer { request, control })
                        .await
                        .is_err()
                    {
                        close_all(
                            &reader_routes,
                            "URMA incoming transfer queue is closed".into(),
                        );
                        let _ = reader_shutdown.send(true);
                        return;
                    }
                    continue;
                }

                let Some(transfer_id) = frame.transfer_id() else {
                    close_all(
                        &reader_routes,
                        format!("unexpected lane control frame: {frame:?}"),
                    );
                    let _ = reader_shutdown.send(true);
                    return;
                };
                let route = reader_routes.lock().unwrap().get(&transfer_id).cloned();
                let Some(route) = route else {
                    if reader_retired.lock().unwrap().contains(&transfer_id) {
                        continue;
                    }
                    close_all(
                        &reader_routes,
                        format!("control frame for unknown URMA transfer {transfer_id}"),
                    );
                    let _ = reader_shutdown.send(true);
                    return;
                };
                if route.send(TransferEvent::Frame(frame)).await.is_err() {
                    // Cancellation removes only this Piece route. A late
                    // Piece-local frame must not poison sibling transfers.
                    reader_routes.lock().unwrap().remove(&transfer_id);
                }
            }
        });

        Ok(Self {
            writer: writer_tx,
            routes,
            retired,
            incoming: Arc::new(AsyncMutex::new(incoming_rx)),
            admission,
            shutdown,
        })
    }

    pub(crate) fn register(&self, transfer_id: TransferId) -> Result<TransferControl> {
        if transfer_id == 0 {
            return Err(protocol_error("transfer_id 0 is reserved for the lane"));
        }
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| protocol_error("URMA lane transfer admission is full"))?;
        register_transfer(
            transfer_id,
            self.writer.clone(),
            self.routes.clone(),
            self.retired.clone(),
            permit,
        )
    }

    pub(crate) async fn accept(&self) -> Result<IncomingTransfer> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| protocol_error("URMA incoming transfer queue is closed"))
    }

    pub(crate) fn abort(&self, message: impl Into<String>) {
        close_all(&self.routes, message.into());
        let _ = self.shutdown.send(true);
    }
}

fn register_transfer(
    transfer_id: TransferId,
    writer: mpsc::Sender<Frame>,
    routes: Arc<Mutex<HashMap<TransferId, mpsc::Sender<TransferEvent>>>>,
    retired: Arc<Mutex<HashSet<TransferId>>>,
    permit: OwnedSemaphorePermit,
) -> Result<TransferControl> {
    if retired.lock().unwrap().contains(&transfer_id) {
        return Err(protocol_error(format!(
            "retired URMA transfer id {transfer_id} cannot be reused"
        )));
    }
    let (sender, receiver) = mpsc::channel(FRAME_QUEUE_CAPACITY);
    match routes.lock().unwrap().entry(transfer_id) {
        Entry::Vacant(entry) => {
            entry.insert(sender);
        }
        Entry::Occupied(_) => {
            return Err(protocol_error(format!(
                "duplicate URMA transfer id {transfer_id}"
            )));
        }
    }
    Ok(TransferControl {
        transfer_id,
        writer,
        receiver,
        routes,
        retired,
        completed: false,
        _permit: permit,
    })
}

fn close_all(
    routes: &Arc<Mutex<HashMap<TransferId, mpsc::Sender<TransferEvent>>>>,
    message: String,
) {
    let senders = routes
        .lock()
        .unwrap()
        .drain()
        .map(|(_, sender)| sender)
        .collect::<Vec<_>>();
    for sender in senders {
        let _ = sender.try_send(TransferEvent::Closed(message.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::PieceKind;

    fn request(number: u32) -> CommonPieceRequest {
        CommonPieceRequest {
            kind: PieceKind::Piece,
            task_id: format!("task-{number}"),
            piece_number: number,
            chunk_size: 4096,
            max_inflight_chunks: 2,
        }
    }

    #[tokio::test]
    async fn interleaved_frames_are_routed_to_their_piece() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let client = LaneControl::spawn(client_stream, 2).unwrap();
        let server = LaneControl::spawn(server_stream, 2).unwrap();
        let mut first = client.register(1).unwrap();
        let mut second = client.register(2).unwrap();

        first
            .send(Frame::Request {
                transfer_id: 1,
                request: request(1),
            })
            .await
            .unwrap();
        second
            .send(Frame::Request {
                transfer_id: 2,
                request: request(2),
            })
            .await
            .unwrap();

        let incoming_first = server.accept().await.unwrap();
        let incoming_second = server.accept().await.unwrap();
        assert_eq!(incoming_first.request.piece_number, 1);
        assert_eq!(incoming_second.request.piece_number, 2);

        incoming_second
            .control
            .send(Frame::Done { transfer_id: 2 })
            .await
            .unwrap();
        incoming_first
            .control
            .send(Frame::Done { transfer_id: 1 })
            .await
            .unwrap();

        assert_eq!(
            second.receive().await.unwrap(),
            Frame::Done { transfer_id: 2 }
        );
        assert_eq!(
            first.receive().await.unwrap(),
            Frame::Done { transfer_id: 1 }
        );
    }

    #[tokio::test]
    async fn piece_error_does_not_close_sibling_route() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let client = LaneControl::spawn(client_stream, 2).unwrap();
        let server = LaneControl::spawn(server_stream, 2).unwrap();
        let mut first = client.register(1).unwrap();
        let mut second = client.register(2).unwrap();
        first
            .send(Frame::Request {
                transfer_id: 1,
                request: request(1),
            })
            .await
            .unwrap();
        second
            .send(Frame::Request {
                transfer_id: 2,
                request: request(2),
            })
            .await
            .unwrap();
        let server_first = server.accept().await.unwrap();
        let server_second = server.accept().await.unwrap();

        server_first
            .control
            .send(Frame::Error {
                transfer_id: 1,
                error: crate::rendezvous::RendezvousError {
                    code: crate::rendezvous::ERROR_CODE_BUSY,
                    message: "busy".into(),
                },
            })
            .await
            .unwrap();
        server_second
            .control
            .send(Frame::Done { transfer_id: 2 })
            .await
            .unwrap();

        assert!(matches!(
            first.receive().await.unwrap(),
            Frame::Error { transfer_id: 1, .. }
        ));
        assert_eq!(
            second.receive().await.unwrap(),
            Frame::Done { transfer_id: 2 }
        );
    }

    #[tokio::test]
    async fn late_frames_for_a_cancelled_piece_do_not_poison_siblings() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let client = LaneControl::spawn(client_stream, 2).unwrap();
        let server = LaneControl::spawn(server_stream, 2).unwrap();
        let first = client.register(1).unwrap();
        let mut second = client.register(2).unwrap();
        first
            .send(Frame::Request {
                transfer_id: 1,
                request: request(1),
            })
            .await
            .unwrap();
        second
            .send(Frame::Request {
                transfer_id: 2,
                request: request(2),
            })
            .await
            .unwrap();
        let server_first = server.accept().await.unwrap();
        let server_second = server.accept().await.unwrap();
        drop(first);

        server_first
            .control
            .send(Frame::Done { transfer_id: 1 })
            .await
            .unwrap();
        server_second
            .control
            .send(Frame::Done { transfer_id: 2 })
            .await
            .unwrap();

        assert_eq!(
            second.receive().await.unwrap(),
            Frame::Done { transfer_id: 2 }
        );
    }

    #[tokio::test]
    async fn server_admission_rejects_only_the_excess_piece() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let client = LaneControl::spawn(client_stream, 2).unwrap();
        let server = LaneControl::spawn(server_stream, 1).unwrap();
        let first = client.register(1).unwrap();
        let mut second = client.register(2).unwrap();
        first
            .send(Frame::Request {
                transfer_id: 1,
                request: request(1),
            })
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();
        second
            .send(Frame::Request {
                transfer_id: 2,
                request: request(2),
            })
            .await
            .unwrap();

        assert!(matches!(
            second.receive().await.unwrap(),
            Frame::Error {
                transfer_id: 2,
                error: crate::rendezvous::RendezvousError {
                    code: crate::rendezvous::ERROR_CODE_BUSY,
                    ..
                }
            }
        ));
        assert_eq!(accepted.request.piece_number, 1);
    }

    #[tokio::test]
    async fn registration_is_bounded() {
        let (stream, _peer) = tokio::io::duplex(1024);
        let lane = LaneControl::spawn(stream, 1).unwrap();
        let first = lane.register(1).unwrap();
        assert!(lane.register(2).is_err());
        drop(first);
        assert!(lane.register(2).is_ok());
    }
}
