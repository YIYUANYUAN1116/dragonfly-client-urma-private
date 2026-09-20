//! Version 5 READ lane handshake and transfer dispatcher.
//!
//! Handshake ownership stays outside the dispatcher so native lane creation and
//! rollback remain explicit. After handshake, one reader and writer task route
//! only generation-bound READ frames.

use super::{
    lane::TpType,
    read_protocol::{
        read_read_frame, write_read_frame, ReadCapability, ReadFrame, ReadTombstones,
        ReadTransferIdentity, READ_DESCRIPTOR_VERSION, READ_DFUR_VERSION,
    },
    rendezvous::MAGIC,
    Error, Result,
};
use crate::rendezvous::{
    put_bytes, read_envelope, write_envelope, PayloadReader, MAX_PAYLOAD_LENGTH, MAX_STRING_LENGTH,
};
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
};

const CONNECT: u8 = 1;
const CONNECTED: u8 = 2;
const MAX_DESCRIPTOR_LENGTH: usize = 64 * 1024;
const FRAME_QUEUE_CAPACITY: usize = 16;
static NEXT_SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

pub(crate) fn next_session_generation() -> Result<u64> {
    NEXT_SESSION_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| protocol("READ session generation space exhausted"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadLaneCapability {
    pub(crate) transport_type: u32,
    pub(crate) tp_type: TpType,
    pub(crate) fabric_tag: String,
    pub(crate) read: ReadCapability,
}

impl ReadLaneCapability {
    pub(crate) fn compatible(&self, remote: &Self) -> Result<u32> {
        if self.transport_type != remote.transport_type
            || self.tp_type != remote.tp_type
            || self.fabric_tag.is_empty()
            || self.fabric_tag != remote.fabric_tag
        {
            return Err(protocol("incompatible READ lane transport/fabric"));
        }
        self.read.effective_max_read_size(&remote.read)
    }

    fn encode(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.transport_type.to_be_bytes());
        payload.push(self.tp_type.wire_value());
        put_bytes(payload, self.fabric_tag.as_bytes());
        self.read.encode(payload);
    }

    fn decode(reader: &mut PayloadReader<'_>) -> Result<Self> {
        let capability = Self {
            transport_type: wire(reader.u32())?,
            tp_type: TpType::from_wire(wire(reader.u8())?).map_err(protocol)?,
            fabric_tag: wire(reader.string(MAX_STRING_LENGTH))?,
            read: ReadCapability {
                max_read_size: wire(reader.u32())?,
                max_jfs_sge: wire(reader.u32())?,
                descriptor_version: wire(reader.u32())?,
            },
        };
        capability.read.compatible(&capability.read)?;
        if capability.fabric_tag.is_empty() {
            return Err(protocol("empty READ fabric tag"));
        }
        Ok(capability)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReadHandshake {
    Connect {
        capability: ReadLaneCapability,
        session_generation: u64,
        descriptor: Vec<u8>,
    },
    Connected {
        capability: ReadLaneCapability,
        session_generation: u64,
        descriptor: Vec<u8>,
    },
}

impl ReadHandshake {
    pub(crate) fn session_generation(&self) -> u64 {
        match self {
            Self::Connect {
                session_generation, ..
            }
            | Self::Connected {
                session_generation, ..
            } => *session_generation,
        }
    }

    pub(crate) fn validate_connect(&self, local: &ReadLaneCapability) -> Result<(u64, u32, &[u8])> {
        let Self::Connect {
            capability,
            session_generation,
            descriptor,
        } = self
        else {
            return Err(protocol("expected READ Connect"));
        };
        let max_read_size = local.compatible(capability)?;
        Ok((*session_generation, max_read_size, descriptor))
    }

    pub(crate) fn validate_connected(
        &self,
        local: &ReadLaneCapability,
        expected_generation: u64,
    ) -> Result<(u32, &[u8])> {
        let Self::Connected {
            capability,
            session_generation,
            descriptor,
        } = self
        else {
            return Err(protocol("expected READ Connected"));
        };
        if *session_generation != expected_generation {
            return Err(protocol("READ Connected did not echo session generation"));
        }
        Ok((local.compatible(capability)?, descriptor))
    }
}

pub(crate) async fn write_handshake<W: AsyncWrite + Unpin>(
    writer: &mut W,
    handshake: &ReadHandshake,
) -> Result<()> {
    if handshake.session_generation() == 0 {
        return Err(protocol("zero READ session generation"));
    }
    let mut payload = Vec::new();
    let (kind, capability, generation, descriptor) = match handshake {
        ReadHandshake::Connect {
            capability,
            session_generation,
            descriptor,
        } => (CONNECT, capability, session_generation, descriptor),
        ReadHandshake::Connected {
            capability,
            session_generation,
            descriptor,
        } => (CONNECTED, capability, session_generation, descriptor),
    };
    capability.compatible(capability)?;
    if descriptor.is_empty() || descriptor.len() > MAX_DESCRIPTOR_LENGTH {
        return Err(protocol("invalid READ lane descriptor length"));
    }
    capability.encode(&mut payload);
    payload.extend_from_slice(&generation.to_be_bytes());
    put_bytes(&mut payload, descriptor);
    write_envelope(
        writer,
        MAGIC,
        READ_DFUR_VERSION,
        kind,
        &payload,
        MAX_PAYLOAD_LENGTH,
    )
    .await
    .map_err(|error| protocol(format!("write READ handshake failed: {error}")))
}

pub(crate) async fn read_handshake<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ReadHandshake> {
    let (kind, payload) = read_envelope(reader, MAGIC, READ_DFUR_VERSION, MAX_PAYLOAD_LENGTH)
        .await
        .map_err(|error| protocol(format!("read READ handshake failed: {error}")))?;
    let mut reader = PayloadReader::new(&payload);
    let capability = ReadLaneCapability::decode(&mut reader)?;
    let session_generation = wire(reader.u64())?;
    if session_generation == 0 {
        return Err(protocol("zero READ session generation"));
    }
    let descriptor = wire(reader.bytes(MAX_DESCRIPTOR_LENGTH))?;
    if descriptor.is_empty() {
        return Err(protocol("empty READ lane descriptor"));
    }
    wire(reader.finish())?;
    match kind {
        CONNECT => Ok(ReadHandshake::Connect {
            capability,
            session_generation,
            descriptor,
        }),
        CONNECTED => Ok(ReadHandshake::Connected {
            capability,
            session_generation,
            descriptor,
        }),
        _ => Err(protocol(format!("unexpected READ handshake type {kind}"))),
    }
}

fn wire<T>(result: dragonfly_client_core::Result<T>) -> Result<T> {
    result.map_err(|error| protocol(format!("invalid READ handshake: {error}")))
}

#[derive(Debug)]
enum TransferEvent {
    Frame(ReadFrame),
    Closed(String),
}

type RouteMap = Arc<Mutex<HashMap<u32, (ReadTransferIdentity, mpsc::Sender<TransferEvent>)>>>;

pub(crate) struct ReadTransferControl {
    identity: ReadTransferIdentity,
    writer: mpsc::Sender<ReadFrame>,
    receiver: mpsc::Receiver<TransferEvent>,
    routes: RouteMap,
    tombstones: Arc<Mutex<ReadTombstones>>,
    completed: bool,
    _permit: OwnedSemaphorePermit,
}

impl ReadTransferControl {
    pub(crate) fn identity(&self) -> ReadTransferIdentity {
        self.identity
    }

    pub(crate) async fn send(&self, frame: ReadFrame) -> Result<()> {
        if frame.identity() != self.identity {
            return Err(protocol("READ frame sent through the wrong transfer route"));
        }
        self.writer
            .send(frame)
            .await
            .map_err(|_| protocol("READ lane writer is closed"))
    }

    pub(crate) async fn receive(&mut self) -> Result<ReadFrame> {
        match self.receiver.recv().await {
            Some(TransferEvent::Frame(frame)) => Ok(frame),
            Some(TransferEvent::Closed(message)) => Err(protocol(message)),
            None => Err(protocol("READ transfer inbox is closed")),
        }
    }

    pub(crate) fn finish(mut self, segment_generation: Option<u64>) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .remove(&self.identity.transfer_id);
        self.tombstones
            .lock()
            .unwrap()
            .insert(self.identity, segment_generation)?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for ReadTransferControl {
    fn drop(&mut self) {
        self.routes
            .lock()
            .unwrap()
            .remove(&self.identity.transfer_id);
        if !self.completed {
            let _ = self.tombstones.lock().unwrap().insert(self.identity, None);
        }
    }
}

pub(crate) struct ReadLaneControl {
    session_generation: u64,
    writer: mpsc::Sender<ReadFrame>,
    routes: RouteMap,
    tombstones: Arc<Mutex<ReadTombstones>>,
    admission: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
}

impl ReadLaneControl {
    pub(crate) fn spawn<S>(
        stream: S,
        session_generation: u64,
        max_concurrent_transfers: usize,
        tombstone_capacity: usize,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if session_generation == 0 || max_concurrent_transfers == 0 {
            return Err(protocol("invalid READ lane control limits"));
        }
        let tombstones = Arc::new(Mutex::new(ReadTombstones::new(tombstone_capacity)?));
        let routes: RouteMap = Arc::new(Mutex::new(HashMap::new()));
        let admission = Arc::new(Semaphore::new(max_concurrent_transfers));
        let (writer_tx, mut writer_rx) = mpsc::channel::<ReadFrame>(FRAME_QUEUE_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (mut reader, mut writer) = tokio::io::split(stream);

        let writer_routes = routes.clone();
        let writer_shutdown = shutdown.clone();
        let mut writer_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = writer_shutdown_rx.changed() => return,
                    frame = writer_rx.recv() => match frame { Some(frame) => frame, None => return },
                };
                if let Err(error) = write_read_frame(&mut writer, &frame).await {
                    close_all(
                        &writer_routes,
                        format!("READ control write failed: {error}"),
                    );
                    let _ = writer_shutdown.send(true);
                    return;
                }
            }
        });

        let reader_routes = routes.clone();
        let reader_tombstones = tombstones.clone();
        let reader_shutdown = shutdown.clone();
        let mut reader_shutdown_rx = shutdown_rx;
        tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = reader_shutdown_rx.changed() => return,
                    frame = read_read_frame(&mut reader) => match frame {
                        Ok(frame) => frame,
                        Err(error) => {
                            close_all(&reader_routes, format!("READ control read failed: {error}"));
                            let _ = reader_shutdown.send(true);
                            return;
                        }
                    },
                };
                let identity = frame.identity();
                if identity.session_generation != session_generation {
                    close_all(&reader_routes, "READ session generation mismatch".into());
                    let _ = reader_shutdown.send(true);
                    return;
                }
                let route = reader_routes
                    .lock()
                    .unwrap()
                    .get(&identity.transfer_id)
                    .cloned();
                let Some((expected, sender)) = route else {
                    if terminal_generation(&frame).is_some_and(|generation| {
                        reader_tombstones
                            .lock()
                            .unwrap()
                            .contains(identity, generation)
                    }) {
                        continue;
                    }
                    close_all(&reader_routes, "READ frame for unknown transfer".into());
                    let _ = reader_shutdown.send(true);
                    return;
                };
                if expected != identity {
                    close_all(&reader_routes, "READ transfer identity mismatch".into());
                    let _ = reader_shutdown.send(true);
                    return;
                }
                if sender.send(TransferEvent::Frame(frame)).await.is_err() {
                    reader_routes.lock().unwrap().remove(&identity.transfer_id);
                }
            }
        });

        Ok(Self {
            session_generation,
            writer: writer_tx,
            routes,
            tombstones,
            admission,
            shutdown,
        })
    }

    pub(crate) fn register(&self, identity: ReadTransferIdentity) -> Result<ReadTransferControl> {
        identity.validate()?;
        if identity.session_generation != self.session_generation {
            return Err(protocol("READ route uses the wrong session generation"));
        }
        if self.tombstones.lock().unwrap().contains_transfer(identity) {
            return Err(protocol("retired READ transfer identity cannot be reused"));
        }
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| protocol("READ lane transfer admission is full"))?;
        let (sender, receiver) = mpsc::channel(FRAME_QUEUE_CAPACITY);
        match self.routes.lock().unwrap().entry(identity.transfer_id) {
            Entry::Vacant(entry) => {
                entry.insert((identity, sender));
            }
            Entry::Occupied(_) => return Err(protocol("duplicate READ transfer id")),
        }
        Ok(ReadTransferControl {
            identity,
            writer: self.writer.clone(),
            receiver,
            routes: self.routes.clone(),
            tombstones: self.tombstones.clone(),
            completed: false,
            _permit: permit,
        })
    }

    pub(crate) fn abort(&self, message: impl Into<String>) {
        close_all(&self.routes, message.into());
        let _ = self.shutdown.send(true);
    }
}

impl Drop for ReadLaneControl {
    fn drop(&mut self) {
        self.abort("READ lane control owner was dropped");
    }
}

fn terminal_generation(frame: &ReadFrame) -> Option<Option<u64>> {
    match frame {
        ReadFrame::Done {
            segment_generation, ..
        } => Some(Some(*segment_generation)),
        ReadFrame::Cancelled {
            segment_generation, ..
        } => Some(*segment_generation),
        _ => None,
    }
}

fn close_all(routes: &RouteMap, message: String) {
    let senders = routes
        .lock()
        .unwrap()
        .drain()
        .map(|(_, (_, sender))| sender)
        .collect::<Vec<_>>();
    for sender in senders {
        let _ = sender.try_send(TransferEvent::Closed(message.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> ReadLaneCapability {
        ReadLaneCapability {
            transport_type: 3,
            tp_type: TpType::Rtp,
            fabric_tag: "rack-a".into(),
            read: ReadCapability {
                max_read_size: 256 * 1024 * 1024,
                max_jfs_sge: 13,
                descriptor_version: READ_DESCRIPTOR_VERSION,
            },
        }
    }

    fn identity(transfer_id: u32) -> ReadTransferIdentity {
        ReadTransferIdentity {
            session_generation: 41,
            transfer_id,
            metadata_generation: u64::from(transfer_id) + 100,
        }
    }

    fn done(identity: ReadTransferIdentity, generation: u64) -> ReadFrame {
        ReadFrame::Done {
            identity,
            segment_generation: generation,
        }
    }

    #[tokio::test]
    async fn version_five_handshake_round_trips_and_echoes_session_generation() {
        let frame = ReadHandshake::Connect {
            capability: capability(),
            session_generation: 41,
            descriptor: vec![1, 2, 3],
        };
        let (mut client, mut server) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        write_handshake(&mut client, &frame).await.unwrap();
        let decoded = read_handshake(&mut server).await.unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(decoded.validate_connect(&capability()).unwrap().0, 41);

        let connected = ReadHandshake::Connected {
            capability: capability(),
            session_generation: 42,
            descriptor: vec![4, 5, 6],
        };
        assert!(connected.validate_connected(&capability(), 41).is_err());
    }

    #[tokio::test]
    async fn dispatcher_routes_interleaved_generation_bound_transfers() {
        let (client_stream, server_stream) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        let client = ReadLaneControl::spawn(client_stream, 41, 2, 4).unwrap();
        let server = ReadLaneControl::spawn(server_stream, 41, 2, 4).unwrap();
        let mut client_one = client.register(identity(1)).unwrap();
        let mut client_two = client.register(identity(2)).unwrap();
        let server_one = server.register(identity(1)).unwrap();
        let server_two = server.register(identity(2)).unwrap();
        server_two.send(done(identity(2), 12)).await.unwrap();
        server_one.send(done(identity(1), 11)).await.unwrap();
        assert_eq!(client_two.receive().await.unwrap(), done(identity(2), 12));
        assert_eq!(client_one.receive().await.unwrap(), done(identity(1), 11));
    }

    #[tokio::test]
    async fn retired_terminal_duplicate_does_not_poison_sibling() {
        let (client_stream, server_stream) = tokio::io::duplex(MAX_PAYLOAD_LENGTH + 1024);
        let client = ReadLaneControl::spawn(client_stream, 41, 2, 4).unwrap();
        let server = ReadLaneControl::spawn(server_stream, 41, 2, 4).unwrap();
        let first = client.register(identity(1)).unwrap();
        let mut second = client.register(identity(2)).unwrap();
        let server_first = server.register(identity(1)).unwrap();
        let server_second = server.register(identity(2)).unwrap();
        first.finish(Some(11)).unwrap();
        server_first.send(done(identity(1), 11)).await.unwrap();
        server_second.send(done(identity(2), 12)).await.unwrap();
        assert_eq!(second.receive().await.unwrap(), done(identity(2), 12));
    }

    #[tokio::test]
    async fn route_rejects_wrong_session_generation_and_duplicate_transfer() {
        let (stream, _peer) = tokio::io::duplex(1024);
        let lane = ReadLaneControl::spawn(stream, 41, 1, 2).unwrap();
        assert!(lane
            .register(ReadTransferIdentity {
                session_generation: 42,
                ..identity(1)
            })
            .is_err());
        let first = lane.register(identity(1)).unwrap();
        assert!(lane.register(identity(1)).is_err());
        drop(first);
        assert!(lane.register(identity(1)).is_err());
    }
}
