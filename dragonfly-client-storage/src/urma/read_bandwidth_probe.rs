//! Explicit, ignored dual-host probes. No application download/Storage metadata
//! is created. B uses production native wrappers; C uses production cached
//! leases, SEND/RECV and Piece state machines. All integrity work is untimed.
use super::{
    fabric::{UrmaFabric, UrmaFabricHandle},
    ffi::{
        self,
        read::{
            source::{ReadBacking, ReadSource, ReadSourceMemory, SourceRegistration},
            ImportedReadSegment, ReadBufferCreation, ReadDescriptor, ReadPost, ReadRequest,
            ReadToken, ReadWrHandle,
        },
        CompletionEventKind, CompletionRecord, JettyHandle, JfcHandle, NativeRuntime,
        SegmentHandle,
    },
    lane::JettyDescriptor,
    read_control::{
        next_session_generation, read_handshake, write_handshake, ReadHandshake,
        ReadLaneCapability, ReadLaneControl,
    },
    read_protocol::{
        read_read_frame, write_read_frame, ReadCapability, ReadFrame, ReadPieceLocator,
        ReadSegmentOffer, ReadTransferIdentity, READ_DESCRIPTOR_VERSION,
    },
    read_registry::{ReadBudget, ReadCapacity},
    read_transfer::{child::ChildTransfer, parent::ParentTransfer},
    runtime::{ReadCachedSourceRequest, ReadRuntimeConfig, RuntimeConfig},
    Error, Result, TpType,
};
use crate::{content::ReadSourceFile, rendezvous::PieceKind};
use dragonfly_client_config::dfdaemon::UrmaControlTransport;
use futures::{stream::FuturesUnordered, StreamExt};
use std::{
    collections::{HashMap, VecDeque},
    ffi::CString,
    fmt::Debug,
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const MAGIC: u64 = 0x4446555242573031; // DFURBW01: private probe supervisor, not discovery.
const FINISHED: u64 = 0x4257445241494e31;
const CLOSED: u64 = 0x4257434c4f534531;
const TIMEOUT: Duration = Duration::from_secs(120);
const TASK: &str = "urma-bandwidth-immutable-file";

fn checked<T, E: Debug>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|error| Error::Protocol(format!("bandwidth probe: {error:?}")))
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Protocol(message.into()))
    }
}

#[derive(Clone, Debug)]
struct Options {
    parent: bool,
    device: String,
    eid: u32,
    address: String,
    file: PathBuf,
    file_bytes: u64,
    piece: u64,
    region: u64,
    depth: usize,
    warmup: Duration,
    duration: Duration,
    threads: usize,
}
impl Options {
    fn env() -> Result<Self> {
        let number = |key: &str, default: u64| -> Result<u64> {
            match std::env::var(key) {
                Ok(value) => checked(value.parse()),
                Err(_) => Ok(default),
            }
        };
        let role = std::env::var("URMA_BW_ROLE").unwrap_or_default();
        require(
            role == "parent" || role == "child",
            "set URMA_BW_ROLE=parent|child",
        )?;
        let o = Self {
            parent: role == "parent",
            device: std::env::var("URMA_BW_DEVICE").unwrap_or_else(|_| "udmac0d1e2".into()),
            eid: checked(u32::try_from(number("URMA_BW_EID_INDEX", 0)?))?,
            address: std::env::var("URMA_BW_ADDR").unwrap_or_else(|_| "127.0.0.1:31918".into()),
            file: std::env::var("URMA_BW_FILE").unwrap_or_default().into(),
            file_bytes: number("URMA_BW_FILE_BYTES", 1 << 30)?,
            piece: number("URMA_BW_PIECE_BYTES", 32 << 20)?,
            region: number("URMA_BW_REGION_BYTES", 256 << 20)?,
            depth: checked(usize::try_from(number("URMA_BW_DEPTH", 16)?))?,
            warmup: Duration::from_secs(number("URMA_BW_WARMUP_SECONDS", 1)?),
            duration: Duration::from_secs(number("URMA_BW_SECONDS", 10)?),
            threads: checked(usize::try_from(number("URMA_BW_TOKIO_THREADS", 32)?))?,
        };
        o.validate()?;
        Ok(o)
    }
    fn validate(&self) -> Result<()> {
        require(
            !self.parent || !self.file.as_os_str().is_empty(),
            "Parent requires URMA_BW_FILE",
        )?;
        require(
            self.piece != 0 && self.piece <= u64::from(u32::MAX) && self.piece % 4096 == 0,
            "piece must be page-aligned and fit one READ WR",
        )?;
        require(
            self.file_bytes >= self.piece
                && self.file_bytes <= 16 << 30
                && self.file_bytes % self.piece == 0,
            "file must contain whole Pieces, at most 16 GiB",
        )?;
        require(
            self.region >= self.piece
                && self.region <= self.file_bytes
                && self.region % self.piece == 0,
            "region must contain whole Pieces and fit the file",
        )?;
        require(
            self.file_bytes.div_ceil(self.region) <= 1024,
            "probe supports at most 1024 Source regions",
        )?;
        require(
            (1..=64).contains(&self.depth) && (1..=64).contains(&self.threads),
            "depth/threads must be 1..64",
        )?;
        require(
            self.depth as u64 * self.piece <= 8 << 30,
            "destination window exceeds 8 GiB",
        )?;
        require(
            !self.duration.is_zero()
                && self.duration <= Duration::from_secs(60)
                && self.warmup <= Duration::from_secs(10),
            "measurement must be 1..60s, warmup 0..10s",
        )
    }
    fn pieces(&self) -> u64 {
        self.file_bytes / self.piece
    }
    fn signature(&self, cached: bool) -> [u64; 8] {
        [
            MAGIC,
            u64::from(cached),
            self.file_bytes,
            self.piece,
            self.region,
            self.depth as u64,
            self.warmup.as_secs(),
            self.duration.as_secs(),
        ]
    }
    fn identity(&self, session: u64, id: u32) -> ReadTransferIdentity {
        ReadTransferIdentity {
            session_generation: session,
            transfer_id: id,
            metadata_generation: 1,
        }
    }
}

fn capability(transport: u32, max_read: u32, cached: bool) -> ReadLaneCapability {
    ReadLaneCapability {
        control_transport: if cached {
            UrmaControlTransport::Sendrecv
        } else {
            UrmaControlTransport::Tcp
        },
        transport_type: transport,
        tp_type: TpType::Ctp,
        fabric_tag: "read-bandwidth-probe".into(),
        read: ReadCapability {
            max_read_size: max_read,
            max_jfs_sge: 1,
            descriptor_version: READ_DESCRIPTOR_VERSION,
        },
    }
}
async fn connect(o: &Options, cached: bool) -> Result<(TcpStream, Option<TcpListener>)> {
    let (mut stream, listener) = if o.parent {
        let listener = checked(TcpListener::bind(&o.address).await)?;
        println!(
            "URMA_BW_LISTEN mode={} address={}",
            if cached { "C" } else { "B" },
            o.address
        );
        let (stream, _) = checked(checked(
            tokio::time::timeout(TIMEOUT, listener.accept()).await,
        )?)?;
        (stream, Some(listener))
    } else {
        (checked(TcpStream::connect(&o.address).await)?, None)
    };
    checked(stream.set_nodelay(true))?;
    for value in o.signature(cached) {
        checked(stream.write_u64(value).await)?;
    }
    for value in o.signature(cached) {
        require(
            checked(stream.read_u64().await)? == value,
            "B/C peers have different probe parameters",
        )?;
    }
    Ok((stream, listener))
}
async fn supervisor(
    o: &Options,
    listener: Option<&TcpListener>,
    session: u64,
) -> Result<TcpStream> {
    let mut stream = if let Some(listener) = listener {
        checked(listener.accept().await)?.0
    } else {
        checked(TcpStream::connect(&o.address).await)?
    };
    checked(stream.set_nodelay(true))?;
    checked(stream.write_u64(session).await)?;
    require(
        checked(stream.read_u64().await)? == session,
        "supervisor session mismatch",
    )?;
    // Checksum list doubles as readiness: Parent completes all registration
    // before replying, so no cold Source work is included in either timer.
    if o.parent {
        println!(
            "URMA_BW_SOURCE_READY regions={}",
            o.file_bytes.div_ceil(o.region)
        );
    }
    Ok(stream)
}
fn file_and_digests(o: &Options) -> Result<(Arc<ReadSourceFile>, Vec<u32>)> {
    let file = checked(ReadSourceFile::open(&o.file))?;
    require(
        file.opened_length() == o.file_bytes,
        "input file size does not match URMA_BW_FILE_BYTES",
    )?;
    let mut digests = Vec::new();
    for piece in 0..o.pieces() {
        // SAFETY: explicit hardware probe requires this completed input inode
        // to remain immutable through remote shutdown, like production cache.
        let mapped = checked(unsafe { file.map_range(piece * o.piece, o.piece) })?;
        digests.push(crc32fast::hash(mapped.as_slice()));
    }
    Ok((file, digests))
}
async fn checksums(o: &Options, stream: &mut TcpStream, local: Vec<u32>) -> Result<Vec<u32>> {
    if o.parent {
        for digest in &local {
            checked(stream.write_u32(*digest).await)?;
        }
        Ok(local)
    } else {
        let mut values = Vec::new();
        for _ in 0..o.pieces() {
            values.push(checked(stream.read_u32().await)?);
        }
        Ok(values)
    }
}
#[derive(Clone, Copy)]
enum Limit {
    Pieces(u64),
    Time(Duration),
}
impl Limit {
    fn allows(self, start: Instant, now: Instant, submitted: u64) -> bool {
        match self {
            Self::Pieces(n) => submitted < n,
            Self::Time(duration) => now.duration_since(start) < duration,
        }
    }
}
struct Measurement {
    pieces: u64,
    elapsed: Duration,
}
impl Measurement {
    fn rates(&self, o: &Options) -> Result<(u64, f64, f64)> {
        require(
            self.pieces != 0 && !self.elapsed.is_zero(),
            "no completed READ bandwidth sample",
        )?;
        let bytes = self
            .pieces
            .checked_mul(o.piece)
            .ok_or_else(|| Error::Protocol("completed byte count overflow".into()))?;
        let seconds = self.elapsed.as_secs_f64();
        Ok((
            bytes,
            bytes as f64 / seconds / (1u64 << 30) as f64,
            bytes as f64 * 8.0 / seconds / 1e9,
        ))
    }
    fn report(&self, o: &Options, cached: bool) -> Result<()> {
        let (bytes, gibps, gbps) = self.rates(o)?;
        println!("URMA_BW_RESULT mode={} completed_bytes={} completed_pieces={} elapsed_ns={} GiBps={:.4} Gbps={:.4} storage=false crc_timed=false drain_included=true",
            if cached { "C" } else { "B" }, bytes, self.pieces, self.elapsed.as_nanos(),
            gibps, gbps);
        Ok(())
    }
}

// B: same production native shim/CTP/TABLE source registration as Cached,
// imported once; no Fabric, per-Piece protocol or async notification in timer.
struct NativeLane {
    native: NativeRuntime,
    send: JfcHandle,
    recv: JfcHandle,
    jetty: JettyHandle,
}
impl NativeLane {
    fn new(o: &Options) -> Result<Self> {
        let name = checked(CString::new(o.device.as_str()))?;
        let mut native = checked(NativeRuntime::open(&name, o.eid))?;
        let cap = checked(native.query_device())?;
        require(
            cap.max_read_size as u64 >= o.piece && cap.max_jfs_depth as usize >= o.depth,
            "provider cannot support requested READ size/depth",
        )?;
        let send = checked(JfcHandle::create(&mut native, (o.depth as u32).max(16)))?;
        let recv = checked(JfcHandle::create(&mut native, 16))?;
        let jetty = checked(JettyHandle::create(
            &mut native,
            &send,
            &recv,
            &ffi::JettyConfig {
                send_depth: o.depth as u32,
                recv_depth: 16,
                max_send_sge: 1,
                max_recv_sge: 1,
                token: 0,
                tp_type: TpType::Ctp as u32,
            },
        ))?;
        Ok(Self {
            native,
            send,
            recv,
            jetty,
        })
    }
    fn close(&mut self) -> Result<()> {
        checked(self.jetty.close())?;
        checked(self.recv.close())?;
        checked(self.send.close())?;
        checked(self.native.close())
    }
}
fn wire_offer(d: ReadDescriptor, token: u32, offset: u64, piece: u64) -> ReadSegmentOffer {
    ReadSegmentOffer {
        descriptor_version: d.version,
        eid: d.eid,
        uasid: d.uasid,
        va: d.va,
        length: d.length,
        source_offset: 0,
        piece_length: piece,
        token_id: d.token_id,
        access: d.access,
        token_policy: d.token_policy,
        token,
        segment_generation: 1,
        effective_max_read_size: piece as u32,
        piece_offset: offset,
        digest: String::new(),
    }
}
fn descriptor(offer: &ReadSegmentOffer) -> ReadDescriptor {
    ReadDescriptor {
        version: offer.descriptor_version,
        eid: offer.eid,
        uasid: offer.uasid,
        va: offer.va,
        length: offer.length,
        token_id: offer.token_id,
        access: offer.access,
        token_policy: offer.token_policy,
    }
}
struct Pending {
    slot: usize,
    piece: usize,
    wr: ReadWrHandle,
}
fn native_context(cqe: &CompletionRecord, jetty: u32) -> Result<u64> {
    require(
        cqe.event_kind == CompletionEventKind::WorkRequest
            && cqe.user_ctx_valid
            && !cqe.is_recv
            && cqe.is_jetty
            && cqe.local_id == jetty,
        "native probe CQE identity/queue mismatch",
    )?;
    Ok(cqe.user_ctx)
}
fn native_phase(
    o: &Options,
    lane: &mut NativeLane,
    target: &ffi::TargetHandle,
    remote: &[ImportedReadSegment],
    local: &[SegmentHandle],
    digests: &[u32],
    limit: Limit,
    verify: bool,
    next: &mut u64,
) -> Result<Measurement> {
    let start = Instant::now();
    let mut pending = HashMap::<u64, Pending>::new();
    let mut free: VecDeque<_> = (0..o.depth).collect();
    let mut submitted = 0;
    let mut completed = 0;
    let jetty = checked(lane.jetty.local_ids())?.0;
    loop {
        while !free.is_empty() && limit.allows(start, Instant::now(), submitted) {
            let slot = free.pop_front().unwrap();
            let piece = submitted % o.pieces();
            let offset = piece * o.piece;
            let context = *next;
            *next = next
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("probe context exhausted".into()))?;
            // SAFETY: each destination Slot is exclusively owned until its
            // validated CQE, and the immutable Source was checked at setup.
            let post = checked(unsafe {
                lane.jetty.post_read(
                    target,
                    &local[slot],
                    &remote[(offset / o.region) as usize],
                    &ReadRequest {
                        local_offset: 0,
                        remote_offset: offset % o.region,
                        length: o.piece as u32,
                        user_ctx: context,
                    },
                )
            })?;
            let wr = match post {
                ReadPost::Posted(wr) => wr,
                ReadPost::Rejected(error) => return checked(Err(error)),
                ReadPost::Uncertain { wr, error } => {
                    // Retain ambiguous WR and all dependent shim allocations.
                    std::mem::forget(wr);
                    return checked(Err(error));
                }
            };
            pending.insert(
                context,
                Pending {
                    slot,
                    piece: piece as usize,
                    wr,
                },
            );
            submitted += 1;
        }
        if pending.is_empty() {
            break;
        }
        require(
            start.elapsed() < o.duration + TIMEOUT,
            "native READ drain timed out; resources retained",
        )?;
        let mut cqes = [CompletionRecord::default(); 16];
        let count = checked(lane.send.poll_into(&mut cqes))?;
        // Busy poll intentionally matches perftest, unlike the Fabric owner.
        for cqe in cqes.iter().take(count) {
            let context = native_context(cqe, jetty)?;
            let item = pending
                .remove(&context)
                .ok_or_else(|| Error::Protocol("unknown/duplicate probe CQE".into()))?;
            // SAFETY: exact live context on the matching send-CQ/Jetty proves
            // retirement; opcode/length are not populated for READ by udma.
            unsafe { item.wr.complete() };
            require(cqe.status == 0, "native READ completion failed")?;
            if verify {
                let (ptr, length) = checked(local[item.slot].data())?;
                require(length as u64 == o.piece, "destination length mismatch")?;
                let bytes = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), length) };
                require(
                    crc32fast::hash(bytes) == digests[item.piece],
                    "native READ CRC mismatch",
                )?;
            }
            completed += 1;
            free.push_back(item.slot);
        }
    }
    require(completed == submitted, "native phase lost completions")?;
    Ok(Measurement {
        pieces: completed,
        elapsed: start.elapsed(),
    })
}
async fn native_probe(o: &Options) -> Result<()> {
    let (mut stream, listener) = connect(o, false).await?;
    let mut lane = NativeLane::new(o)?;
    let cap = checked(lane.native.query_device())?;
    let cap = capability(cap.transport_type as u32, cap.max_read_size, false);
    let local_descriptor = checked(JettyDescriptor::from_ffi(checked(
        lane.jetty.export_descriptor(),
    )?))?
    .serialize()?;
    if o.parent {
        let connect = read_handshake(&mut stream).await?;
        let (session, _, _) = connect.validate_connect(&cap)?;
        write_handshake(
            &mut stream,
            &ReadHandshake::Connected {
                capability: cap,
                session_generation: session,
                descriptor: local_descriptor,
            },
        )
        .await?;
        let (file, digests) = file_and_digests(o)?;
        let mut sources = Vec::new();
        for offset in (0..o.file_bytes).step_by(o.region as usize) {
            let token = 0xb7000000 + sources.len() as u32 + 1;
            let mapped =
                checked(unsafe { file.map_range(offset, o.region.min(o.file_bytes - offset)) })?;
            let source = match unsafe {
                ReadSource::register(
                    &mut lane.native,
                    ReadBacking::new(ReadSourceMemory::Mapped(mapped), ()),
                    &ReadToken::new(token),
                )
            } {
                SourceRegistration::Registered(source) => source,
                SourceRegistration::Rejected { error, .. }
                | SourceRegistration::Uncertain { error, .. } => return checked(Err(error)),
            };
            let offer = wire_offer(checked(source.descriptor())?, token, offset, o.piece);
            write_read_frame(
                &mut stream,
                &ReadFrame::SegmentOffer {
                    identity: o.identity(session, sources.len() as u32 + 1),
                    offer,
                },
            )
            .await?;
            sources.push(source);
        }
        let mut supervisor = supervisor(o, listener.as_ref(), session).await?;
        checksums(o, &mut supervisor, digests).await?;
        // Child sends this only after draining every WR, checking content,
        // unimporting all sources and closing its native runtime.
        require(
            checked(supervisor.read_u64().await)? == FINISHED,
            "missing drained Child proof",
        )?;
        for source in &mut sources {
            unsafe {
                checked(source.unregister())?;
                checked(source.release_after_revoke())?;
            }
        }
        lane.close()?;
        checked(supervisor.write_u64(CLOSED).await)?;
    } else {
        let session = next_session_generation()?;
        write_handshake(
            &mut stream,
            &ReadHandshake::Connect {
                capability: cap.clone(),
                session_generation: session,
                descriptor: local_descriptor,
            },
        )
        .await?;
        let connected = read_handshake(&mut stream).await?;
        let (max_read, parent) = connected.validate_connected(&cap, session)?;
        require(
            max_read as u64 >= o.piece,
            "negotiated READ limit would split probe WRs",
        )?;
        let parent = JettyDescriptor::deserialize(parent)?.to_ffi()?;
        let mut target = checked(lane.jetty.import_target(&parent, 0))?;
        let mut remote = Vec::new();
        for index in 0..o.file_bytes.div_ceil(o.region) {
            let ReadFrame::SegmentOffer { identity, offer } = read_read_frame(&mut stream).await?
            else {
                return Err(Error::Protocol("missing setup Source descriptor".into()));
            };
            offer.validate()?;
            require(
                identity == o.identity(session, index as u32 + 1)
                    && offer.piece_offset == index * o.region
                    && offer.length == o.region.min(o.file_bytes - index * o.region),
                "Source setup geometry mismatch",
            )?;
            remote.push(checked(target.import_read_segment(
                &descriptor(&offer),
                &ReadToken::new(offer.token),
                max_read,
            ))?);
        }
        let mut local = Vec::new();
        for _ in 0..o.depth {
            match SegmentHandle::create_read_buffer(&mut lane.native, o.piece, 4096) {
                ReadBufferCreation::Ready(buffer) => local.push(buffer),
                ReadBufferCreation::Rejected(error)
                | ReadBufferCreation::Uncertain { error, .. } => return checked(Err(error)),
            }
        }
        let mut supervisor = supervisor(o, None, session).await?;
        let digests = checksums(o, &mut supervisor, Vec::new()).await?;
        let mut next = 1;
        native_phase(
            o,
            &mut lane,
            &target,
            &remote,
            &local,
            &digests,
            Limit::Pieces(o.pieces()),
            true,
            &mut next,
        )?;
        native_phase(
            o,
            &mut lane,
            &target,
            &remote,
            &local,
            &digests,
            Limit::Time(o.warmup),
            false,
            &mut next,
        )?;
        let measured = native_phase(
            o,
            &mut lane,
            &target,
            &remote,
            &local,
            &digests,
            Limit::Time(o.duration),
            false,
            &mut next,
        )?;
        native_phase(
            o,
            &mut lane,
            &target,
            &remote,
            &local,
            &digests,
            Limit::Pieces(o.pieces()),
            true,
            &mut next,
        )?;
        for remote in &mut remote {
            checked(remote.close())?;
        }
        for buffer in &mut local {
            checked(buffer.close())?;
        }
        checked(target.close())?;
        lane.close()?;
        checked(supervisor.write_u64(FINISHED).await)?;
        require(
            checked(supervisor.read_u64().await)? == CLOSED,
            "Parent shutdown failed",
        )?;
        measured.report(o, false)?;
    }
    println!(
        "URMA_BW_PASS mode=B role={} integrity=all-pieces-before-and-after shutdown=both-sides",
        if o.parent { "parent" } else { "child" }
    );
    Ok(())
}

// C: production Fabric/cache/READ state machines; no Storage FD, pwrite, CRC
// consumer or application Task commit in timed phases. Registration is hot.
fn fabric(o: &Options) -> Result<UrmaFabricHandle> {
    // A small file may be leased repeatedly by all concurrent Pieces. Peer
    // lease bytes must cover the window, not only the physical file size.
    let source = o.file_bytes.max(o.depth as u64 * o.piece) * 2;
    let destination = o.depth as u64 * o.piece * 2;
    let cap = |bytes| ReadCapacity {
        bytes,
        entries: 4096,
    };
    UrmaFabric::start(
        RuntimeConfig::new(
            &o.device,
            o.eid,
            ReadRuntimeConfig {
                budget: ReadBudget {
                    total: cap(source + destination),
                    source: cap(source),
                    destination: cap(destination),
                    per_peer_source: cap(source),
                    per_peer_destination: cap(destination),
                    quarantine: cap(source),
                },
                max_outstanding_per_peer: o.depth,
                max_outstanding_per_piece: 1,
                buffer_alignment: 4096,
                source_workers: 0,
                provider_revocation_validated: true,
                control_bytes: 16 << 20,
            },
        )
        .with_tp_type(TpType::Ctp),
    )
}
async fn cached_lane(
    o: &Options,
    fabric: &UrmaFabricHandle,
    stream: &mut Option<TcpStream>,
) -> Result<(u16, u64, Arc<ReadLaneControl>)> {
    let (lane_id, descriptor) = fabric.create_lane().await?;
    let cap = capability(fabric.transport_type(), fabric.max_read_size(), true);
    require(
        cap.read.max_read_size as u64 >= o.piece,
        "provider would split Piece READ",
    )?;
    let setup = fabric.create_control(lane_id).await?;
    let descriptor = super::sendrecv_control::pack_descriptors(descriptor, Some(&setup))?;
    let tcp = stream.as_mut().unwrap();
    let session;
    if o.parent {
        let connect = read_handshake(tcp).await?;
        let (generation, _, remote) = connect.validate_connect(&cap)?;
        session = generation;
        let (_, control) = super::sendrecv_control::unpack_descriptors(remote, true)?;
        fabric.connect_control(lane_id, setup.id, control).await?;
        write_handshake(
            tcp,
            &ReadHandshake::Connected {
                capability: cap,
                session_generation: session,
                descriptor,
            },
        )
        .await?;
    } else {
        session = next_session_generation()?;
        write_handshake(
            tcp,
            &ReadHandshake::Connect {
                capability: cap.clone(),
                session_generation: session,
                descriptor,
            },
        )
        .await?;
        let connected = read_handshake(tcp).await?;
        let (_, remote) = connected.validate_connected(&cap, session)?;
        let (data, control) = super::sendrecv_control::unpack_descriptors(remote, true)?;
        fabric.connect_lane(lane_id, data).await?;
        fabric.connect_control(lane_id, setup.id, control).await?;
    }
    let bridge = super::sendrecv_control::spawn(
        fabric.clone(),
        lane_id,
        session,
        setup,
        stream.take().unwrap(),
    );
    let lane = ReadLaneControl::spawn(bridge, session, o.depth, o.depth * 4)?;
    Ok((lane_id, session, Arc::new(lane)))
}
async fn cached_piece(
    o: Options,
    fabric: UrmaFabricHandle,
    lane: Arc<ReadLaneControl>,
    lane_id: u16,
    identity: ReadTransferIdentity,
    piece: u64,
    digest: u32,
    verify: bool,
    validation_barrier: Option<Arc<tokio::sync::Barrier>>,
) -> Result<()> {
    let control = lane.register(identity)?;
    let transfer = ChildTransfer::new(
        fabric.clone(),
        lane_id,
        control,
        identity,
        ReadPieceLocator {
            kind: PieceKind::Piece,
            task_id: TASK.into(),
            piece_number: piece as u32,
        },
        o.piece,
        o.piece,
        o.piece as u32,
        1,
        TIMEOUT,
    )?;
    let success =
        unsafe { transfer.run_transport_only().await }.map_err(|failure| failure.error)?;
    require(
        success.completed_bytes == o.piece
            && success.read_wr_count == 1
            && success.piece_offset == piece * o.piece
            && success.digest == digest.to_string(),
        "Cached Piece completion/metadata mismatch",
    )?;
    // Untimed validation holds a full window of leases once, ensuring every
    // destination Slot exists before measurement even with zero warmup.
    if let Some(barrier) = validation_barrier {
        barrier.wait().await;
    }
    if verify {
        let bytes = unsafe {
            std::slice::from_raw_parts(success.lease.span.data, success.lease.span.length)
        };
        require(crc32fast::hash(bytes) == digest, "Cached READ CRC mismatch")?;
    }
    require(
        fabric
            .recycle_published_child_lease(success.lease.child_id)
            .await?,
        "destination recycle did not drain",
    )?;
    success.lease.guard.disarm();
    Ok(())
}
async fn cached_phase(
    o: &Options,
    fabric: &UrmaFabricHandle,
    lane: &Arc<ReadLaneControl>,
    lane_id: u16,
    session: u64,
    digests: &[u32],
    limit: Limit,
    verify: bool,
    ids: &AtomicU32,
) -> Result<Measurement> {
    let limit = match (verify, limit) {
        (true, Limit::Pieces(pieces)) => {
            Limit::Pieces(pieces.div_ceil(o.depth as u64) * o.depth as u64)
        }
        _ => limit,
    };
    let validation_barrier = verify.then(|| Arc::new(tokio::sync::Barrier::new(o.depth)));
    let start = Instant::now();
    let mut submitted = 0;
    let mut completed = 0;
    let mut tasks = FuturesUnordered::new();
    loop {
        while tasks.len() < o.depth && limit.allows(start, Instant::now(), submitted) {
            let piece = submitted % o.pieces();
            let id = ids
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .map_err(|_| Error::Protocol("probe transfer identity exhausted".into()))?;
            tasks.push(cached_piece(
                o.clone(),
                fabric.clone(),
                lane.clone(),
                lane_id,
                o.identity(session, id),
                piece,
                digests[piece as usize],
                verify,
                validation_barrier.clone(),
            ));
            submitted += 1;
        }
        let Some(result) = tasks.next().await else {
            break;
        };
        result?;
        completed += 1;
    }
    require(completed == submitted, "Cached phase lost completions")?;
    Ok(Measurement {
        pieces: completed,
        elapsed: start.elapsed(),
    })
}
async fn cached_probe(o: &Options) -> Result<()> {
    let (stream, listener) = connect(o, true).await?;
    let fabric = fabric(o)?;
    let (lane_id, session, lane) = cached_lane(o, &fabric, &mut Some(stream)).await?;
    if o.parent {
        let (file, digests) = file_and_digests(o)?;
        let mut sources = Vec::new();
        for offset in (0..o.file_bytes).step_by(o.region as usize) {
            // SAFETY: controlled immutable file, fully populated before probe;
            // every range is retained by the ordinary production Source cache.
            sources.push(unsafe {
                fabric
                    .register_cached_source(
                        ReadCachedSourceRequest {
                            peer_id: lane_id,
                            kind: PieceKind::Piece,
                            task: TASK.into(),
                            file: file.clone(),
                            piece_length: o.piece,
                            max_region_bytes: o.region,
                            piece_offset: offset,
                            completed: vec![0..o.file_bytes],
                            token: ReadToken::new(0xb7000000 + sources.len() as u32 + 1),
                        },
                        TIMEOUT,
                    )
                    .await?
            });
        }
        let sources = Arc::new(sources);
        let mut supervisor = supervisor(o, listener.as_ref(), session).await?;
        checksums(o, &mut supervisor, digests.clone()).await?;
        let done = async {
            require(
                checked(supervisor.read_u64().await)? == FINISHED,
                "missing drained Child proof",
            )
        };
        tokio::pin!(done);
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = &mut done => { result?; break; },
                result = tasks.join_next(), if !tasks.is_empty() => { checked(result.unwrap())??; },
                accepted = lane.accept_transfer(TIMEOUT) => {
                    let Some(accepted) = accepted else { done.await?; break; };
                    while let Some(result) = tasks.try_join_next() { checked(result)??; }
                    let ReadFrame::BufferReady { request, accepted_length, .. } = &accepted.buffer_ready else {
                        return Err(Error::Protocol("expected BufferReady".into()));
                    };
                    require(request.kind == PieceKind::Piece && request.task_id == TASK && accepted_length == &o.piece
                        && u64::from(request.piece_number) < o.pieces(), "probe Piece request mismatch")?;
                    let piece = request.piece_number as usize;
                    let cached = &sources[(piece as u64 * o.piece / o.region) as usize];
                    let expected_source = cached.source;
                    let fixture_path = o.file.clone();
                    let expected_file = file.identity();
                    let file_bytes = o.file_bytes;
                    let worker_fabric = fabric.clone();
                    let piece_bytes = o.piece;
                    let region_bytes = o.region;
                    let (parent, _) = ParentTransfer::accept(fabric.clone(), lane_id, accepted.control,
                        accepted.buffer_ready, piece as u64 * o.piece, digests[piece].to_string(), o.piece as u32)?;
                    tasks.spawn(async move {
                        // Preserve the production lookup-only cache command on
                        // every Piece. Match the production current-FD open on
                        // a blocking worker; fixture metadata/digests are hot.
                        // A miss fails; no registration occurs in the timer.
                        let fixture_file = checked(checked(tokio::task::spawn_blocking(move ||
                            ReadSourceFile::open(&fixture_path)).await)?)?;
                        require(fixture_file.identity() == expected_file && fixture_file.opened_length() == file_bytes,
                            "immutable fixture inode/length changed")?;
                        let source = unsafe { worker_fabric.register_cached_source(ReadCachedSourceRequest {
                            peer_id: lane_id, kind: PieceKind::Piece, task: TASK.into(), file: fixture_file,
                            piece_length: piece_bytes, max_region_bytes: region_bytes,
                            piece_offset: piece as u64 * piece_bytes, completed: Vec::new(), token: ReadToken::new(0),
                        }, TIMEOUT).await? };
                        require(source.source == expected_source, "warm cache Source identity changed")?;
                        let (parent, pending) = unsafe { parent.publish_cached_source_and_wait_read_done(source, 0, TIMEOUT).await }
                            .map_err(|failure| failure.error)?;
                        unsafe { parent.finish(pending).await }
                    });
                }
            }
        }
        while let Some(result) = tasks.join_next().await {
            checked(result)??;
        }
        drop(lane);
        fabric.close_lane(lane_id).await?;
        fabric.shutdown().await?;
        checked(supervisor.write_u64(CLOSED).await)?;
    } else {
        let mut supervisor = supervisor(o, None, session).await?;
        let digests = checksums(o, &mut supervisor, Vec::new()).await?;
        let ids = AtomicU32::new(1);
        cached_phase(
            o,
            &fabric,
            &lane,
            lane_id,
            session,
            &digests,
            Limit::Pieces(o.pieces()),
            true,
            &ids,
        )
        .await?;
        cached_phase(
            o,
            &fabric,
            &lane,
            lane_id,
            session,
            &digests,
            Limit::Time(o.warmup),
            false,
            &ids,
        )
        .await?;
        let measured = cached_phase(
            o,
            &fabric,
            &lane,
            lane_id,
            session,
            &digests,
            Limit::Time(o.duration),
            false,
            &ids,
        )
        .await?;
        cached_phase(
            o,
            &fabric,
            &lane,
            lane_id,
            session,
            &digests,
            Limit::Pieces(o.pieces()),
            true,
            &ids,
        )
        .await?;
        drop(lane);
        fabric.close_lane(lane_id).await?;
        fabric.shutdown().await?;
        checked(supervisor.write_u64(FINISHED).await)?;
        require(
            checked(supervisor.read_u64().await)? == CLOSED,
            "Parent shutdown failed",
        )?;
        measured.report(o, true)?;
    }
    println!(
        "URMA_BW_PASS mode=C role={} integrity=all-pieces-before-and-after shutdown=both-sides",
        if o.parent { "parent" } else { "child" }
    );
    Ok(())
}
fn run(cached: bool) {
    let o = Options::env().expect("invalid bandwidth probe options");
    println!("URMA_BW_CONFIG mode={} role={} device={} eid={} file_bytes={} piece_bytes={} region_bytes={} depth={} warmup_s={} measure_s={} poll={} tokio_threads={}",
        if cached { "C" } else { "B" }, if o.parent { "parent" } else { "child" }, o.device, o.eid,
        o.file_bytes, o.piece, o.region, o.depth, o.warmup.as_secs(), o.duration.as_secs(),
        if cached { "fabric-owner" } else { "busy" }, if cached { o.threads } else { 1 });
    let mut builder = if cached {
        let mut b = tokio::runtime::Builder::new_multi_thread();
        b.worker_threads(o.threads);
        b
    } else {
        tokio::runtime::Builder::new_current_thread()
    };
    let runtime = builder.enable_all().build().unwrap();
    let result = runtime.block_on(async {
        checked(
            tokio::time::timeout(TIMEOUT + o.duration + o.warmup, async {
                if cached {
                    cached_probe(&o).await
                } else {
                    native_probe(&o).await
                }
            })
            .await,
        )?
    });
    result.expect("URMA bandwidth probe failed (no successful bandwidth result)");
}
#[test]
#[ignore = "opens real provider; run explicit parent and child on separate hosts"]
fn rm_read_native_bandwidth() {
    run(false);
}
#[test]
#[ignore = "opens real provider; run explicit parent and child on separate hosts"]
fn rm_read_cached_piece_bandwidth() {
    run(true);
}

#[test]
fn bandwidth_probe_limits_do_not_submit_after_deadline_but_finite_validation_covers_all_pieces() {
    let start = Instant::now();
    let limit = Limit::Time(Duration::from_secs(10));
    assert!(limit.allows(start, start + Duration::from_secs(9), 123));
    assert!(!limit.allows(start, start + Duration::from_secs(10), 123));
    let validation = Limit::Pieces(32);
    assert!(validation.allows(start, start + TIMEOUT, 31));
    assert!(!validation.allows(start, start, 32));
}

#[test]
fn bandwidth_probe_geometry_and_peer_signature_are_bounded() {
    let o = Options {
        parent: true,
        device: "fixture".into(),
        eid: 0,
        address: "fixture".into(),
        file: "immutable-fixture".into(),
        file_bytes: 1 << 30,
        piece: 32 << 20,
        region: 256 << 20,
        depth: 16,
        warmup: Duration::from_secs(1),
        duration: Duration::from_secs(10),
        threads: 32,
    };
    o.validate().unwrap();
    assert_eq!(o.pieces(), 32);
    assert_ne!(o.signature(false), o.signature(true));
    for change in [0, 1, 2, 3, 4, 5] {
        let mut bad = o.clone();
        match change {
            0 => bad.piece += 1,
            1 => bad.region += 4096,
            2 => bad.file_bytes -= 1,
            3 => bad.depth = 0,
            4 => bad.duration = Duration::ZERO,
            _ => bad.file = PathBuf::new(),
        }
        assert!(
            bad.validate().is_err(),
            "invalid geometry accepted: {change}"
        );
    }
    let mut peer = o.clone();
    peer.parent = false;
    peer.address = "different-bind-address".into();
    peer.file = PathBuf::new();
    assert_eq!(o.signature(true), peer.signature(true));
    peer.depth = 8;
    assert_ne!(o.signature(true), peer.signature(true));
    let measured = Measurement {
        pieces: 32,
        elapsed: Duration::from_millis(500),
    };
    let (bytes, gibps, gbps) = measured.rates(&o).unwrap();
    assert_eq!(bytes, 1 << 30);
    assert_eq!(gibps, 2.0);
    assert!((gbps - 17.179869184).abs() < 1e-9);
    assert!(Measurement {
        pieces: 0,
        elapsed: Duration::from_secs(1)
    }
    .rates(&o)
    .is_err());
}
#[test]
fn bandwidth_probe_read_cqe_uses_context_not_submit_opcode() {
    let mut cqe = CompletionRecord {
        local_id: 7,
        user_ctx: 19,
        user_ctx_valid: true,
        is_jetty: true,
        opcode: 0,
        completion_len: 0,
        ..Default::default()
    };
    assert_eq!(native_context(&cqe, 7).unwrap(), 19);
    assert!(native_context(&cqe, 8).is_err());
    cqe.is_recv = true;
    assert!(native_context(&cqe, 7).is_err());
    cqe.is_recv = false;
    cqe.event_kind = CompletionEventKind::FlushErrorDone;
    assert!(native_context(&cqe, 7).is_err());
    cqe.event_kind = CompletionEventKind::WorkRequest;
    cqe.user_ctx_valid = false;
    assert!(native_context(&cqe, 7).is_err());
}
