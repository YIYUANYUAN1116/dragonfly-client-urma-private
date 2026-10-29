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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourcePattern {
    Sequential,
    Fixed,
}
impl SourcePattern {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "sequential" => Ok(Self::Sequential),
            "fixed" => Ok(Self::Fixed),
            _ => Err(Error::Protocol(
                "source pattern must be sequential|fixed".into(),
            )),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::Fixed => "fixed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceBacking {
    File,
    Anonymous,
}
impl SourceBacking {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "file" => Ok(Self::File),
            "anonymous" => Ok(Self::Anonymous),
            _ => Err(Error::Protocol(
                "source backing must be file|anonymous".into(),
            )),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Anonymous => "anonymous",
        }
    }
}

// Setup only: both variants register directly through the same Source API.
// Copying the entire Region materializes every anonymous page before timing.
fn source_memory(
    file: &Arc<ReadSourceFile>,
    offset: u64,
    length: u64,
    backing: SourceBacking,
) -> Result<ReadSourceMemory> {
    let mapped = checked(unsafe { file.map_range(offset, length) })?;
    match backing {
        SourceBacking::File => Ok(ReadSourceMemory::Mapped(mapped)),
        SourceBacking::Anonymous => {
            let mut anonymous = checked(memmap2::MmapMut::map_anon(checked(usize::try_from(
                length,
            ))?))?;
            anonymous.copy_from_slice(mapped.as_slice());
            Ok(ReadSourceMemory::ProbeAnonymous(checked(
                anonymous.make_read_only(),
            )?))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationLayout {
    Segments,
    Contiguous,
}
impl DestinationLayout {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "segments" => Ok(Self::Segments),
            "contiguous" => Ok(Self::Contiguous),
            _ => Err(Error::Protocol(
                "destination layout must be segments|contiguous".into(),
            )),
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Segments => "segments",
            Self::Contiguous => "contiguous",
        }
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
    source_pattern: SourcePattern,
    source_backing: SourceBacking,
    destination_layout: DestinationLayout,
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
            source_pattern: SourcePattern::parse(
                &std::env::var("URMA_BW_SOURCE_PATTERN").unwrap_or_else(|_| "sequential".into()),
            )?,
            source_backing: SourceBacking::parse(
                &std::env::var("URMA_BW_SOURCE_BACKING").unwrap_or_else(|_| "file".into()),
            )?,
            destination_layout: DestinationLayout::parse(
                &std::env::var("URMA_BW_DESTINATION_LAYOUT").unwrap_or_else(|_| "segments".into()),
            )?,
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
    fn validate_mode(&self, cached: bool) -> Result<()> {
        require(
            !cached || self.source_backing == SourceBacking::File,
            "anonymous source backing is supported only by probe B",
        )?;
        require(
            !cached || matches!(self.destination_layout, DestinationLayout::Segments),
            "contiguous destination layout is supported only by probe B",
        )?;
        require(
            !cached || self.source_pattern == SourcePattern::Sequential,
            "fixed source pattern is supported only by probe B",
        )
    }
    fn native_piece(&self, submitted: u64, verify: bool) -> u64 {
        // Integrity passes still cover the entire file. Only warmup and the
        // measurement change their source working set; destinations stay private.
        if !verify && self.source_pattern == SourcePattern::Fixed {
            0
        } else {
            submitted % self.pieces()
        }
    }
    fn signature(&self, cached: bool) -> [u64; 8] {
        [
            MAGIC,
            u64::from(cached)
                | (u64::from(self.source_backing == SourceBacking::Anonymous) << 3)
                | (u64::from(self.source_pattern == SourcePattern::Fixed) << 1)
                | (u64::from(matches!(
                    self.destination_layout,
                    DestinationLayout::Contiguous
                )) << 2),
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
    native: Option<NativeObservation>,
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
        if let Some(native) = &self.native {
            native.report(o, self.elapsed);
        }
        Ok(())
    }
}

// Counts accepted WRs until the owner polls their CQEs. This includes device
// completions not yet polled, and is not hardware queue occupancy or NIC busy%.
struct NativeObservation {
    last: Instant,
    depth: usize,
    peak: usize,
    area_ns: u128,
    full_ns: u128,
    zero_ns: u128,
    window: usize,
    posts: u64,
    completions: u64,
    polls: u64,
    empty_polls: u64,
    post_ns: u128,
    post_max_ns: u128,
    cqe_ns: u128,
    cqe_min_ns: u128,
    cqe_max_ns: u128,
    refills: u64,
    refill_ns: u128,
    refill_max_ns: u128,
}
impl NativeObservation {
    fn new(start: Instant, window: usize) -> Self {
        Self {
            last: start,
            depth: 0,
            peak: 0,
            area_ns: 0,
            full_ns: 0,
            zero_ns: 0,
            window,
            posts: 0,
            completions: 0,
            polls: 0,
            empty_polls: 0,
            post_ns: 0,
            post_max_ns: 0,
            cqe_ns: 0,
            cqe_min_ns: u128::MAX,
            cqe_max_ns: 0,
            refills: 0,
            refill_ns: 0,
            refill_max_ns: 0,
        }
    }
    fn advance(&mut self, now: Instant) {
        let ns = now.duration_since(self.last).as_nanos();
        self.area_ns += ns * self.depth as u128;
        if self.depth == self.window {
            self.full_ns += ns;
        }
        if self.depth == 0 {
            self.zero_ns += ns;
        }
        self.last = now;
    }
    fn posted(&mut self, started: Instant, returned: Instant, recycled: Option<Instant>) {
        self.advance(started);
        self.depth += 1;
        self.peak = self.peak.max(self.depth);
        self.posts += 1;
        let ns = returned.duration_since(started).as_nanos();
        self.post_ns += ns;
        self.post_max_ns = self.post_max_ns.max(ns);
        if let Some(recycled) = recycled {
            let ns = started.duration_since(recycled).as_nanos();
            self.refills += 1;
            self.refill_ns += ns;
            self.refill_max_ns = self.refill_max_ns.max(ns);
        }
    }
    fn completed(&mut self, posted: Instant, observed: Instant) {
        self.advance(observed);
        self.depth -= 1;
        self.completions += 1;
        let ns = observed.duration_since(posted).as_nanos();
        self.cqe_ns += ns;
        self.cqe_min_ns = self.cqe_min_ns.min(ns);
        self.cqe_max_ns = self.cqe_max_ns.max(ns);
    }
    fn polled(&mut self, count: usize) {
        self.polls += 1;
        self.empty_polls += u64::from(count == 0);
    }
    fn report(&self, o: &Options, elapsed: Duration) {
        let ns = elapsed.as_nanos().max(1) as f64;
        let mean_us = |total: u128, count: u64| total as f64 / count.max(1) as f64 / 1000.0;
        println!("URMA_BW_NATIVE mode=B source_pattern={} source_backing={} destination_layout={} wrs={} polls={} empty_polls={} empty_poll_pct={:.3} avg_unretired={:.3} peak_unretired={} full_window_pct={:.3} zero_unretired_pct={:.3} post_call_ms={:.3} post_call_mean_us={:.3} post_call_max_us={:.3} post_to_cqe_mean_us={:.3} post_to_cqe_min_us={:.3} post_to_cqe_max_us={:.3} refill_count={} refill_mean_us={:.3} refill_max_us={:.3} outstanding_scope=host-post-to-polled-cqe drain_included=true",
            o.source_pattern.name(), o.source_backing.name(), o.destination_layout.name(), self.completions, self.polls, self.empty_polls,
            100.0 * self.empty_polls as f64 / self.polls.max(1) as f64,
            self.area_ns as f64 / ns, self.peak, 100.0 * self.full_ns as f64 / ns,
            100.0 * self.zero_ns as f64 / ns, self.post_ns as f64 / 1e6,
            mean_us(self.post_ns, self.posts), self.post_max_ns as f64 / 1000.0,
            mean_us(self.cqe_ns, self.completions), self.cqe_min_ns as f64 / 1000.0,
            self.cqe_max_ns as f64 / 1000.0, self.refills,
            mean_us(self.refill_ns, self.refills), self.refill_max_ns as f64 / 1000.0);
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
// The same Slot plan is used for post offsets and CRC ranges. All Slots stay
// disjoint in either layout, and each native Segment has exactly one owner.
struct DestinationPlan {
    segment_count: usize,
    segment_bytes: u64,
    slot_bytes: u64,
    slots: Vec<(usize, u64)>,
}
impl DestinationPlan {
    fn new(o: &Options) -> Self {
        // Options::validate bounds depth*piece to 8 GiB without overflow.
        let contiguous = o.destination_layout == DestinationLayout::Contiguous;
        Self {
            segment_count: if contiguous { 1 } else { o.depth },
            segment_bytes: if contiguous {
                o.piece * o.depth as u64
            } else {
                o.piece
            },
            slot_bytes: o.piece,
            slots: (0..o.depth)
                .map(|slot| {
                    if contiguous {
                        (0, slot as u64 * o.piece)
                    } else {
                        (slot, 0)
                    }
                })
                .collect(),
        }
    }
    fn range(&self, slot: usize, buffer_length: usize) -> Result<std::ops::Range<usize>> {
        let (_, offset) = self
            .slots
            .get(slot)
            .ok_or_else(|| Error::Protocol("invalid destination Slot".into()))?;
        let start = checked(usize::try_from(*offset))?;
        let length = checked(usize::try_from(self.slot_bytes))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Error::Protocol("destination range overflow".into()))?;
        require(
            buffer_length as u64 == self.segment_bytes && end <= buffer_length,
            "destination length/range mismatch",
        )?;
        Ok(start..end)
    }
}
struct NativeDestinations {
    buffers: Vec<SegmentHandle>,
    plan: DestinationPlan,
}
impl NativeDestinations {
    fn create(native: &mut NativeRuntime, o: &Options) -> Result<Self> {
        let plan = DestinationPlan::new(o);
        let mut buffers = Vec::with_capacity(plan.segment_count);
        for _ in 0..plan.segment_count {
            match SegmentHandle::create_read_buffer(native, plan.segment_bytes, 4096) {
                ReadBufferCreation::Ready(buffer) => buffers.push(buffer),
                ReadBufferCreation::Rejected(error)
                | ReadBufferCreation::Uncertain { error, .. } => return checked(Err(error)),
            }
        }
        println!("URMA_BW_DESTINATION layout={} segments={} segment_bytes={} registered_bytes={} slots={} slot_bytes={}",
            o.destination_layout.name(), plan.segment_count, plan.segment_bytes,
            plan.segment_count as u64 * plan.segment_bytes, plan.slots.len(), plan.slot_bytes);
        Ok(Self { buffers, plan })
    }
    fn slot(&self, slot: usize) -> (&SegmentHandle, u64) {
        let (buffer, offset) = self.plan.slots[slot];
        (&self.buffers[buffer], offset)
    }
    fn verify(&self, slot: usize, digest: u32) -> Result<()> {
        let (buffer, _) = self.slot(slot);
        let (ptr, length) = checked(buffer.data())?;
        let range = self.plan.range(slot, length)?;
        // SAFETY: validated in-bounds private Slot, its matching CQE consumed,
        // no repost/CPU write until this function returns. Entire Segment lives.
        let bytes =
            unsafe { std::slice::from_raw_parts(ptr.as_ptr().add(range.start), range.len()) };
        require(crc32fast::hash(bytes) == digest, "native READ CRC mismatch")
    }
    fn close(&mut self) -> Result<()> {
        for buffer in &mut self.buffers {
            checked(buffer.close())?;
        }
        Ok(())
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
    local: &NativeDestinations,
    digests: &[u32],
    limit: Limit,
    verify: bool,
    next: &mut u64,
) -> Result<Measurement> {
    // Even a one-Piece fixture must initialize/check every private destination
    // Slot before measurement. Cycling the source still covers the whole file.
    let limit = match (verify, limit) {
        (true, Limit::Pieces(pieces)) => Limit::Pieces(pieces.max(o.depth as u64)),
        _ => limit,
    };
    let start = Instant::now();
    let mut pending = HashMap::<u64, Pending>::new();
    let mut free: VecDeque<_> = (0..o.depth).map(|slot| (slot, None)).collect();
    let mut observation = NativeObservation::new(start, o.depth);
    let mut submitted = 0;
    let mut completed = 0;
    let jetty = checked(lane.jetty.local_ids())?.0;
    loop {
        while !free.is_empty() && limit.allows(start, Instant::now(), submitted) {
            let (slot, recycled) = free.pop_front().unwrap();
            let piece = o.native_piece(submitted, verify);
            let offset = piece * o.piece;
            let context = *next;
            *next = next
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("probe context exhausted".into()))?;
            // SAFETY: each destination Slot is exclusively owned until its
            // validated CQE, and the immutable Source was checked at setup.
            let (destination, local_offset) = local.slot(slot);
            let post = checked(unsafe {
                lane.jetty.post_read(
                    target,
                    destination,
                    &remote[(offset / o.region) as usize],
                    &ReadRequest {
                        local_offset,
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
            observation.posted(wr.timing().started_at, wr.timing().returned_at, recycled);
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
        observation.polled(count);
        // Busy poll intentionally matches perftest, unlike the Fabric owner.
        for cqe in cqes.iter().take(count) {
            let context = native_context(cqe, jetty)?;
            let item = pending
                .remove(&context)
                .ok_or_else(|| Error::Protocol("unknown/duplicate probe CQE".into()))?;
            let observed = cqe
                .observed_at
                .ok_or_else(|| Error::Protocol("missing CQE host timestamp".into()))?;
            observation.completed(item.wr.timing().started_at, observed);
            // SAFETY: exact live context on the matching send-CQ/Jetty proves
            // retirement; opcode/length are not populated for READ by udma.
            unsafe { item.wr.complete() };
            require(cqe.status == 0, "native READ completion failed")?;
            if verify {
                local.verify(item.slot, digests[item.piece])?;
            }
            completed += 1;
            free.push_back((item.slot, Some(observed)));
        }
    }
    require(completed == submitted, "native phase lost completions")?;
    require(
        observation.depth == 0 && observation.posts == observation.completions,
        "native observation lost WR retirement",
    )?;
    let end = Instant::now();
    observation.advance(end);
    Ok(Measurement {
        pieces: completed,
        elapsed: end.duration_since(start),
        native: Some(observation),
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
            let memory = source_memory(
                &file,
                offset,
                o.region.min(o.file_bytes - offset),
                o.source_backing,
            )?;
            let source = match unsafe {
                ReadSource::register(
                    &mut lane.native,
                    ReadBacking::new(memory, ()),
                    &ReadToken::new(token),
                )
            } {
                SourceRegistration::Registered(source) => source,
                SourceRegistration::Rejected { error, .. }
                | SourceRegistration::Uncertain { error, .. } => return checked(Err(error)),
            };
            require(
                checked(source.register_stages())?.direct,
                "bandwidth Source must use direct registration",
            )?;
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
        println!(
            "URMA_BW_SOURCE backing={} segments={} registered_bytes={} region_bytes={} direct=true",
            o.source_backing.name(),
            sources.len(),
            o.file_bytes,
            o.region
        );
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
        let mut local = NativeDestinations::create(&mut lane.native, o)?;
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
        local.close()?;
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
fn cached_budget(o: &Options) -> ReadBudget {
    // A small file may be leased repeatedly by all concurrent Pieces. Peer
    // lease bytes must cover the window, not only the physical file size.
    let source = o.file_bytes.max(o.depth as u64 * o.piece) * 2;
    let destination = o.depth as u64 * o.piece * 2;
    let cap = |bytes| ReadCapacity {
        bytes,
        entries: 4096,
    };
    let source = cap(source);
    let destination = cap(destination);
    ReadBudget {
        total: ReadCapacity {
            bytes: source.bytes + destination.bytes,
            entries: source.entries + destination.entries,
        },
        source,
        destination,
        per_peer_source: source,
        per_peer_destination: destination,
        quarantine: source,
    }
}
fn fabric(o: &Options) -> Result<UrmaFabricHandle> {
    UrmaFabric::start(
        RuntimeConfig::new(
            &o.device,
            o.eid,
            ReadRuntimeConfig {
                budget: cached_budget(o),
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
        native: None,
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
    o.validate_mode(cached)
        .expect("invalid bandwidth probe mode");
    println!("URMA_BW_CONFIG mode={} role={} device={} eid={} file_bytes={} piece_bytes={} region_bytes={} depth={} warmup_s={} measure_s={} poll={} tokio_threads={} source_pattern={} source_backing={} destination_layout={}",
        if cached { "C" } else { "B" }, if o.parent { "parent" } else { "child" }, o.device, o.eid,
        o.file_bytes, o.piece, o.region, o.depth, o.warmup.as_secs(), o.duration.as_secs(),
        if cached { "fabric-owner" } else { "busy" }, if cached { o.threads } else { 1 }, o.source_pattern.name(), o.source_backing.name(), o.destination_layout.name());
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
fn bandwidth_probe_anonymous_source_preserves_region_contents_without_file_alias() {
    use std::io::Write;
    let mut fixture = tempfile::NamedTempFile::new().unwrap();
    let bytes: Vec<u8> = (0..16384)
        .map(|index| (index / 4096 + index % 251) as u8)
        .collect();
    fixture.write_all(&bytes).unwrap();
    let file = ReadSourceFile::open(fixture.path()).unwrap();
    let region = source_memory(&file, 4096, 8192, SourceBacking::File).unwrap();
    let anonymous = source_memory(&file, 4096, 8192, SourceBacking::Anonymous).unwrap();
    let ReadSourceMemory::Mapped(mapped) = region else {
        panic!("not file-backed")
    };
    let ReadSourceMemory::ProbeAnonymous(copy) = anonymous else {
        panic!("not anonymous")
    };
    assert_eq!(copy.as_ref(), &bytes[4096..12288]);
    assert_eq!(copy.as_ref(), mapped.as_slice());
    assert_ne!(copy.as_ptr(), mapped.as_slice().as_ptr());
    assert_eq!(copy.as_ptr() as usize % 4096, 0);
    assert!(source_memory(&file, 12288, 8192, SourceBacking::Anonymous).is_err());
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
        source_pattern: SourcePattern::Sequential,
        source_backing: SourceBacking::File,
        destination_layout: DestinationLayout::Segments,
    };
    o.validate().unwrap();
    let budget = cached_budget(&o);
    assert_eq!(budget.total.entries, 8192);
    assert!(super::read_registry::ReadOwnerRegistry::<()>::new(budget).is_ok());
    // Reproduce the original probe configuration: both directions had 4096
    // entries but their shared total was also only 4096. No provider needed.
    let mut invalid = budget;
    invalid.total.entries = 4096;
    assert!(matches!(
        super::read_registry::ReadOwnerRegistry::<()>::new(invalid),
        Err(super::read_registry::OwnerError::InvalidBudget)
    ));
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
    let mut fixed = o.clone();
    fixed.source_pattern = SourcePattern::parse("fixed").unwrap();
    assert!(SourcePattern::parse("typo").is_err());
    assert_ne!(o.signature(false), fixed.signature(false));
    fixed.validate_mode(false).unwrap();
    assert!(fixed.validate_mode(true).is_err());
    for index in 0..96 {
        assert_eq!(o.native_piece(index, false), index % o.pieces());
        assert_eq!(fixed.native_piece(index, false), 0);
        assert_eq!(fixed.native_piece(index, true), index % o.pieces());
    }
    let mut anonymous = o.clone();
    anonymous.source_backing = SourceBacking::parse("anonymous").unwrap();
    assert!(SourceBacking::parse("typo").is_err());
    anonymous.validate_mode(false).unwrap();
    assert!(anonymous.validate_mode(true).is_err());
    assert_ne!(anonymous.signature(false), o.signature(false));
    let mut anonymous_peer = anonymous.clone();
    anonymous_peer.parent = false;
    assert_eq!(anonymous.signature(false), anonymous_peer.signature(false));
    assert_eq!(fixed.file_bytes, o.file_bytes);
    assert_eq!(fixed.region, o.region);
    assert_eq!(fixed.depth, o.depth);
    assert!(DestinationLayout::parse("typo").is_err());
    for depth in [1, 16, 64] {
        for layout in [DestinationLayout::Segments, DestinationLayout::Contiguous] {
            let mut cfg = o.clone();
            cfg.depth = depth;
            cfg.destination_layout = layout;
            cfg.validate().unwrap();
            cfg.validate_mode(false).unwrap();
            let plan = DestinationPlan::new(&cfg);
            assert_eq!(
                plan.segment_count as u64 * plan.segment_bytes,
                depth as u64 * o.piece
            );
            for slot in 0..depth {
                let (segment, offset) = plan.slots[slot];
                assert!(segment < plan.segment_count);
                let range = plan.range(slot, plan.segment_bytes as usize).unwrap();
                assert_eq!(range.start as u64, offset);
                assert_eq!(range.len() as u64, o.piece);
                for previous in 0..slot {
                    let (other_segment, _) = plan.slots[previous];
                    let other = plan.range(previous, plan.segment_bytes as usize).unwrap();
                    assert!(
                        segment != other_segment
                            || range.end <= other.start
                            || other.end <= range.start
                    );
                }
            }
            assert!(plan.range(depth, plan.segment_bytes as usize).is_err());
            assert!(plan.range(0, plan.segment_bytes as usize - 1).is_err());
            if layout == DestinationLayout::Contiguous {
                assert_eq!(plan.segment_count, 1);
                assert_ne!(cfg.signature(false), {
                    let mut separate = cfg.clone();
                    separate.destination_layout = DestinationLayout::Segments;
                    separate.signature(false)
                });
                assert!(cfg.validate_mode(true).is_err());
            }
        }
    }
    let measured = Measurement {
        pieces: 32,
        elapsed: Duration::from_millis(500),
        native: None,
    };
    let (bytes, gibps, gbps) = measured.rates(&o).unwrap();
    assert_eq!(bytes, 1 << 30);
    assert_eq!(gibps, 2.0);
    assert!((gbps - 17.179869184).abs() < 1e-9);
    assert!(Measurement {
        pieces: 0,
        elapsed: Duration::from_secs(1),
        native: None,
    }
    .rates(&o)
    .is_err());
}
#[test]
fn bandwidth_probe_observation_weights_depth_and_refill_by_time() {
    let start = Instant::now();
    let at = |ns| start + Duration::from_nanos(ns);
    let mut stats = NativeObservation::new(start, 2);
    stats.posted(at(1000), at(2000), None);
    stats.posted(at(3000), at(4000), None);
    stats.polled(0);
    stats.polled(1);
    stats.completed(at(1000), at(5000));
    stats.posted(at(6000), at(6500), Some(at(5000)));
    stats.polled(2);
    stats.completed(at(3000), at(7000));
    stats.completed(at(6000), at(8000));
    stats.advance(at(10000));
    assert_eq!(
        (stats.depth, stats.peak, stats.posts, stats.completions),
        (0, 2, 3, 3)
    );
    assert_eq!((stats.polls, stats.empty_polls), (3, 1));
    assert_eq!(
        (stats.area_ns, stats.full_ns, stats.zero_ns),
        (10000, 3000, 3000)
    );
    // Every accepted WR contributes its post-to-polled-CQE duration once;
    // overlapping WR durations equal the time integral of unretired depth.
    assert_eq!(stats.area_ns, stats.cqe_ns);
    assert_eq!((stats.cqe_min_ns, stats.cqe_max_ns), (2000, 4000));
    assert_eq!((stats.post_ns, stats.post_max_ns), (2500, 1000));
    assert_eq!(
        (stats.refills, stats.refill_ns, stats.refill_max_ns),
        (1, 1000, 1000)
    );

    let mut batch = NativeObservation::new(start, 2);
    batch.posted(at(0), at(100), None);
    batch.posted(at(200), at(300), None);
    // All CQEs from one poll share its host observation timestamp.
    batch.completed(at(0), at(1000));
    batch.completed(at(200), at(1000));
    batch.advance(at(1100));
    assert_eq!(batch.area_ns, batch.cqe_ns);
    assert_eq!(batch.area_ns, 1800);
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
