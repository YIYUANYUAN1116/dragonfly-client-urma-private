//! Thread-owned URMA fabric boundary for Dragonfly storage.
//!
//! Endpoint native wrappers remain `!Send` and `!Sync`. The fabric creates,
//! uses, and destroys [`UrmaRuntime`] on one OS thread. Optional source workers
//! own their native source handles locally and hold restricted context leases.
//! Async Dragonfly code communicates with that thread through bounded business
//! admission plus a non-dropping lifecycle path, and never receives a raw
//! UMDK handle.

use super::read_handoff::{ResourceGuard, ResourceReply};
use super::{
    lane::{JettyDescriptor, TransportMode},
    runtime::{
        ReadCachedLeaseOffer, ReadCachedLeaseRequest, ReadCachedSource, ReadCachedSourceRequest,
        ReadChildAdmission, ReadChildId, ReadChildProgress, ReadChildRequest, ReadChildUpdate,
        ReadLeaseSpan, ReadSourceAdmission, ReadSourceId, ReadSourceRequest, RuntimeConfig,
        UrmaRuntime,
    },
    Error, Result,
};
use std::thread::{self, JoinHandle};
use std::{
    sync::{
        mpsc::{self as std_mpsc, RecvTimeoutError},
        Arc, Mutex, OnceLock, Weak,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

/// Default number of commands that may wait for the owner thread.
const DEFAULT_COMMAND_CAPACITY: usize = 16;

/// Bounds command latency while completions are actively being polled.
const MAX_COMMANDS_PER_TICK: usize = 16;

/// Pure polling is used because this runtime has no JFCE. Keep the
/// idle interval short without allowing an outstanding WR to consume one CPU.
/// Commands unpark the owner before this timeout; CQ-only work is polled on
/// expiry because the device does not currently provide a wakeup event here.
const PROGRESS_IDLE_INTERVAL: Duration = Duration::from_micros(100);

/// Native device discovery should normally finish immediately. Bound the
/// synchronous hand-off so a wedged provider cannot pin an async caller and
/// the process-wide Fabric registry forever.
const FABRIC_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

type StartupProbe = (u32, u32, u64, u32);
type StartupResult = Result<StartupProbe>;

/// Process-wide weak registry used by dfdaemon's server and downloader adapters. Native UMDK
/// permits one Runtime owner in this implementation, so independently starting both adapters
/// would make the second one fail with `AlreadyInitialized`.
static SHARED_FABRIC: OnceLock<Mutex<Weak<FabricInner>>> = OnceLock::new();

fn validate_shared_config(active: &RuntimeConfig, requested: &RuntimeConfig) -> Result<()> {
    if active == requested {
        return Ok(());
    }
    Err(Error::InvalidConfiguration(format!(
        "URMA Fabric is already running for device {} EID {} TP {:?}, requested device {} EID {} TP {:?}",
        active.device_name,
        active.eid_index,
        active.tp_type,
        requested.device_name,
        requested.eid_index,
        requested.tp_type
    )))
}

/// Observable process-level fabric state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FabricReadiness {
    /// The owner thread has started but native initialization is incomplete.
    Starting,
    /// Runtime and JFCs are ready to admit READ owners.
    Ready,
    /// Native initialization, progress, or shutdown failed.
    Failed(String),
    /// The native resource tree has shut down cleanly.
    Stopped,
}

/// Namespace for starting the process-level URMA fabric.
pub struct UrmaFabric;

impl UrmaFabric {
    /// Starts the owner thread and waits until native initialization either
    /// succeeds or rolls back. A successful return therefore means the runtime
    /// is ready, not merely that a thread was spawned.
    pub(crate) fn start(config: RuntimeConfig) -> Result<UrmaFabricHandle> {
        Self::start_with_capacity(config, DEFAULT_COMMAND_CAPACITY)
    }

    pub fn get_or_start_with_read_config(
        device_name: impl Into<String>,
        eid_index: u32,
        tp_type: crate::urma::TpType,
        read: &dragonfly_client_config::dfdaemon::UrmaReadServer,
    ) -> Result<UrmaFabricHandle> {
        let read = super::runtime::ReadRuntimeConfig::try_from_config(read)?;
        Self::get_or_start_config(
            RuntimeConfig::new(device_name, eid_index, read).with_tp_type(tp_type),
        )
    }

    fn get_or_start_config(config: RuntimeConfig) -> Result<UrmaFabricHandle> {
        let mut shared = SHARED_FABRIC
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .unwrap();
        if let Some(inner) = shared.upgrade() {
            validate_shared_config(&inner.runtime_config, &config)?;
            let readiness = inner.readiness.borrow().clone();
            return match readiness {
                FabricReadiness::Ready => Ok(UrmaFabricHandle { inner }),
                FabricReadiness::Starting => Err(Error::InvalidConfiguration(
                    "shared URMA Fabric is still starting".into(),
                )),
                FabricReadiness::Failed(error) => Err(Error::Protocol(format!(
                    "shared URMA Fabric failed: {error}"
                ))),
                FabricReadiness::Stopped => Err(fabric_stopped()),
            };
        }

        let handle = Self::start(config)?;
        *shared = Arc::downgrade(&handle.inner);
        Ok(handle)
    }

    fn start_with_capacity(
        config: RuntimeConfig,
        command_capacity: usize,
    ) -> Result<UrmaFabricHandle> {
        if command_capacity == 0 {
            return Err(Error::InvalidConfiguration(
                "URMA fabric command capacity must be non-zero".into(),
            ));
        }

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let command_slots = Arc::new(Semaphore::new(command_capacity));
        let (readiness_tx, readiness_rx) = watch::channel(FabricReadiness::Starting);
        let (startup_tx, startup_rx) = std_mpsc::sync_channel(1);

        let runtime_config = config.clone();
        let join = thread::Builder::new()
            .name("dragonfly-urma-fabric".to_string())
            .spawn(move || run_owner(config, command_rx, readiness_tx, startup_tx))
            .map_err(|error| {
                Error::InvalidConfiguration(format!("failed to spawn URMA owner thread: {error}"))
            })?;

        match startup_rx.recv_timeout(FABRIC_STARTUP_TIMEOUT) {
            Ok(Ok((transport_type, transport_modes, max_message_size, max_read_size))) => {
                let command_tx = CommandSender {
                    tx: command_tx,
                    owner: Some(join.thread().clone()),
                };
                Ok(UrmaFabricHandle {
                    inner: Arc::new(FabricInner {
                        command_tx: Mutex::new(Some(command_tx)),
                        command_slots,
                        readiness: readiness_rx,
                        runtime_config,
                        transport_type,
                        transport_modes,
                        max_message_size,
                        max_read_size,
                        shutdown: AsyncMutex::new(()),
                        join: Mutex::new(Some(join)),
                    }),
                })
            }
            Ok(Err(error)) => {
                let _ = join.join();
                Err(error)
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = join.join();
                Err(Error::InvalidConfiguration(
                    "URMA owner thread exited during startup".to_string(),
                ))
            }
            Err(RecvTimeoutError::Timeout) => {
                // Detach the still-running owner. If native startup eventually
                // returns, its failed startup reply makes it shut itself down
                // and release the process-global liburma guard.
                drop(join);
                Err(Error::StartupTimeout {
                    timeout: FABRIC_STARTUP_TIMEOUT,
                })
            }
        }
    }
}

/// Cloneable, Tokio-safe facade for the thread-owned URMA runtime.
#[derive(Clone)]
pub struct UrmaFabricHandle {
    inner: Arc<FabricInner>,
}

/// One cached transfer's lease. The cancellation guard never owns the physical
/// source; the owner decides whether abandonment may release an unpublished
/// lease or must retain an exposed one.
pub(crate) struct ReadCachedSourceLease {
    lease: super::read_source_cache::CacheLease,
    guard: Option<ResourceGuard>,
    pub(crate) offer: super::runtime::ReadSourceOffer,
    pub(crate) source_offset: u64,
}

impl UrmaFabricHandle {
    pub(crate) fn control_guard(&self, lane_id: u16, control_id: u64) -> ResourceGuard {
        self.resource_guard(Abandoned::Control(lane_id, control_id))
    }
    pub(crate) async fn create_control(
        &self,
        lane_id: u16,
    ) -> Result<super::native_control::ControlSetup> {
        self.submit(|reply| FabricCommand::CreateControl { lane_id, reply })
            .await
    }
    pub(crate) async fn connect_control(
        &self,
        lane_id: u16,
        control_id: u64,
        descriptor: Vec<u8>,
    ) -> Result<()> {
        self.submit(|reply| FabricCommand::ConnectControl {
            lane_id,
            control_id,
            descriptor,
            reply,
        })
        .await
    }
    pub(crate) async fn send_control(
        &self,
        lane_id: u16,
        control_id: u64,
        bytes: Vec<u8>,
    ) -> Result<()> {
        self.submit_urgent(|reply| FabricCommand::SendControl {
            lane_id,
            control_id,
            bytes,
            reply,
        })
        .await
    }

    /// # Safety
    /// Storage completion evidence matches this exact immutable opened file.
    /// Native producer ownership belongs to the cache, including on timeout.
    pub(crate) async unsafe fn register_cached_source(
        &self,
        request: ReadCachedSourceRequest,
        completion_timeout: Duration,
    ) -> Result<ReadCachedSource> {
        if completion_timeout.is_zero() {
            return Err(Error::Protocol("zero cached registration timeout".into()));
        }
        tokio::time::timeout(completion_timeout, async {
            let mut source = self
                .submit(|reply| FabricCommand::RegisterCachedSource { request, reply })
                .await?;
            loop {
                let state = *source.updates.borrow_and_update();
                match state {
                    super::read_source_cache::CacheState::Ready => return Ok(source),
                    super::read_source_cache::CacheState::Reserved
                    | super::read_source_cache::CacheState::Registering => {
                        source
                            .updates
                            .changed()
                            .await
                            .map_err(|_| fabric_stopped())?;
                    }
                    state => {
                        return Err(Error::Protocol(format!(
                            "cached source registration unavailable: {state:?}"
                        )))
                    }
                }
            }
        })
        .await
        .map_err(|_| Error::Protocol("cached source registration deadline expired".into()))?
    }

    /// # Safety
    /// Authenticate this peer/transfer and prove Storage authorized the exact
    /// Piece in this cached source. The Runtime enforces bounds and admission.
    pub(crate) async unsafe fn acquire_cached_source_lease(
        &self,
        request: ReadCachedLeaseRequest,
    ) -> Result<ReadCachedSourceLease> {
        let acquired = self
            .submit_resource(
                |reply| FabricCommand::AcquireCachedSourceLease { request, reply },
                |acquired| Abandoned::CachedSourceLease(acquired.lease),
            )
            .await?;
        // No await between claiming the handoff and rearming its guard.
        let guard = self.resource_guard(Abandoned::CachedSourceLease(acquired.lease));
        Ok(ReadCachedSourceLease {
            lease: acquired.lease,
            guard: Some(guard),
            offer: acquired.offer,
            source_offset: acquired.source_offset,
        })
    }

    /// Complete this owner transition before sending a SegmentOffer. Cancelling
    /// this command may leave an exposed lease, which the guard safely retains.
    pub(crate) async fn expose_cached_source_lease(
        &self,
        lease: &ReadCachedSourceLease,
        generation: u64,
    ) -> Result<()> {
        if lease.guard.is_none() {
            return Err(Error::Protocol(
                "cached source lease already released".into(),
            ));
        }
        self.submit_urgent(|reply| FabricCommand::ExposeCachedSourceLease {
            lease: lease.lease,
            generation,
            reply,
        })
        .await
    }

    /// # Safety
    /// This exact transfer must have drained under the cached lease contract.
    /// No Segment/backing is freed by this operation. Keep the guard armed until
    /// the owner confirms completion; reply loss conservatively abandons it.
    pub(crate) async unsafe fn release_cached_source_lease(
        &self,
        lease: &mut ReadCachedSourceLease,
        transfer: super::read_protocol::ReadTransferIdentity,
        generation: u64,
    ) -> Result<()> {
        if lease.guard.is_none() {
            return Err(Error::Protocol(
                "cached source lease already released".into(),
            ));
        }
        self.submit_urgent(|reply| FabricCommand::ReleaseCachedSourceLease {
            lease: lease.lease,
            transfer,
            generation,
            reply,
        })
        .await?;
        lease.guard.take().expect("armed lease").disarm();
        Ok(())
    }
}

impl UrmaFabricHandle {
    /// Returns a receiver for readiness and terminal-state changes.
    pub(crate) fn subscribe_readiness(&self) -> watch::Receiver<FabricReadiness> {
        self.inner.readiness.clone()
    }

    /// transport_type returns the URMA transport type negotiated from the
    /// device at startup, used as one side of peer capability negotiation.
    pub fn transport_type(&self) -> u32 {
        self.inner.transport_type
    }

    pub fn tp_type(&self) -> crate::urma::TpType {
        self.inner.runtime_config.tp_type
    }

    /// Reports whether the provider advertised the selected transport mode.
    pub fn supports_rm(&self) -> bool {
        self.inner.transport_modes & TransportMode::Rm as u32 != 0
    }

    /// max_message_size returns the effective single-message payload limit: the
    /// reported by the device.
    pub fn max_message_size(&self) -> u64 {
        self.inner.max_message_size
    }

    /// Provider READ payload ceiling copied at startup; no native handle crosses
    /// threads. Keep this separate from the device's ordinary message limit.
    pub(crate) fn max_read_size(&self) -> u32 {
        self.inner.max_read_size
    }

    /// is_failed reports whether the owner thread has entered a failed state
    /// and the shared facade should be retired and recreated.
    pub fn is_failed(&self) -> bool {
        matches!(*self.inner.readiness.borrow(), FabricReadiness::Failed(_))
    }

    /// Creates a local lane and returns its stable id plus the serialized local
    /// Jetty descriptor for the existing Dragonfly control plane.
    pub(crate) async fn create_lane(&self) -> Result<(u16, Vec<u8>)> {
        self.submit_resource(
            |reply| FabricCommand::CreateLane { reply },
            |(lane_id, _)| Abandoned::Lane(*lane_id),
        )
        .await
    }

    /// Imports the peer descriptor and transitions the lane to Ready.
    pub(crate) async fn connect_lane(&self, lane_id: u16, descriptor: Vec<u8>) -> Result<()> {
        self.submit(|reply| FabricCommand::ConnectLane {
            lane_id,
            descriptor,
            reply,
        })
        .await
    }

    /// # Safety
    /// The caller must authenticate and generation-bind the READ descriptor and
    /// token, and guarantee exclusive ownership of the destination Piece.
    pub(crate) async unsafe fn create_read_child(
        &self,
        request: ReadChildRequest,
    ) -> Result<ReadChildAdmission> {
        self.submit_resource(
            |reply| FabricCommand::CreateReadChild { request, reply },
            |admission| {
                Abandoned::Child(match admission {
                    ReadChildAdmission::Ready(id) | ReadChildAdmission::Quarantined { id, .. } => {
                        *id
                    }
                })
            },
        )
        .await
    }

    pub(crate) async fn post_read_child_batch(
        &self,
        id: ReadChildId,
        lengths: Vec<u32>,
    ) -> Result<usize> {
        let admission_start = std::time::Instant::now();
        self.submit(|reply| FabricCommand::PostReadChildBatch {
            id,
            lengths,
            reply,
            admission_wait_ns: admission_start.elapsed().as_nanos() as u64,
            enqueued_at: std::time::Instant::now(),
        })
        .await
    }

    pub(crate) async fn subscribe_read_child_progress(
        &self,
        id: ReadChildId,
    ) -> Result<watch::Receiver<ReadChildUpdate>> {
        self.submit(|reply| FabricCommand::SubscribeReadChildProgress { id, reply })
            .await
    }

    pub(crate) async fn read_child_progress(&self, id: ReadChildId) -> Result<ReadChildProgress> {
        self.submit(|reply| FabricCommand::ReadChildProgress { id, reply })
            .await
    }

    pub(crate) async fn retire_read_child_for_cleanup(&self, id: ReadChildId) -> Result<bool> {
        self.submit_urgent(|reply| FabricCommand::RetireReadChild { id, reply })
            .await
    }

    /// First lease stage: stop posting and close the native import while
    /// keeping the registered destination buffer and the full budget charge.
    pub(crate) async fn drain_read_child_for_lease(&self, id: ReadChildId) -> Result<()> {
        self.submit(|reply| FabricCommand::DrainReadChildForLease { id, reply })
            .await
    }

    /// Extracts the CPU span of the fully read registered destination buffer
    /// for Storage. The lease itself stays on the owner thread until recycle.
    pub(crate) async fn publish_read_child_lease(&self, id: ReadChildId) -> Result<ReadLeaseSpan> {
        self.submit_resource(
            |reply| FabricCommand::PublishReadChildLease { id, reply },
            move |_| Abandoned::Child(id),
        )
        .await
    }

    /// Consumes a published destination lease: retires the Child owner and
    /// recycles its buffer, releasing the owner charge. Idle registrations may
    /// remain in the destination pool and charged to its budget. Call only after Storage
    /// consumers have joined and the published span will never be dereferenced
    /// again. `Ok(true)` proves the owner release; `Ok(false)` or an error
    /// keeps the owner retained for a later cleanup pass.
    pub(crate) async fn recycle_published_child_lease(&self, id: ReadChildId) -> Result<bool> {
        // Retire is a state transition the recycle stage requires; a repeated
        // retire of an already retiring owner is harmless.
        self.submit_urgent(|reply| FabricCommand::RetireReadChild { id, reply })
            .await?;
        self.submit_urgent(|reply| FabricCommand::RecycleReadChildLease { id, reply })
            .await
    }

    /// # Safety
    /// The caller must hold immutable exact-Piece backing and authenticate and
    /// generation-bind this source to the requesting peer and transfer.
    pub(crate) async unsafe fn register_read_source(
        &self,
        request: ReadSourceRequest,
    ) -> Result<ReadSourceAdmission> {
        self.submit_resource(
            |reply| FabricCommand::RegisterReadSource { request, reply },
            |admission| match admission {
                ReadSourceAdmission::Ready(offer) => Abandoned::Source(offer.id, true),
                ReadSourceAdmission::Quarantined { id, .. } => Abandoned::Source(*id, false),
            },
        )
        .await
    }

    pub(crate) async fn retire_read_source(&self, id: ReadSourceId) -> Result<()> {
        self.submit_urgent(|reply| FabricCommand::RetireReadSource { id, reply })
            .await
    }

    /// # Safety
    /// The caller must hold the provider drain proof for this exact source.
    pub(crate) async unsafe fn unregister_read_source(&self, id: ReadSourceId) -> Result<bool> {
        self.submit_urgent(|reply| FabricCommand::UnregisterReadSource { id, reply })
            .await
    }

    /// # Safety
    /// The caller must independently prove that remote access to this source has
    /// ceased and cannot resume, including access through stale tokens.
    pub(crate) async unsafe fn release_read_source_after_revoke(
        &self,
        id: ReadSourceId,
    ) -> Result<bool> {
        self.submit_urgent(|reply| FabricCommand::ReleaseReadSourceAfterRevoke { id, reply })
            .await
    }

    /// Starts provider-backed retirement. The owner keeps the native lane
    /// until every WR and the shared-JFC flush sentinel have been consumed.
    pub(crate) async fn close_lane(&self, lane_id: u16) -> Result<()> {
        self.submit(|reply| FabricCommand::CloseLane { lane_id, reply })
            .await
    }

    async fn submit_resource<T>(
        &self,
        make_command: impl FnOnce(ResourceReply<T>) -> FabricCommand,
        abandoned: impl Fn(&T) -> Abandoned + Send + 'static,
    ) -> Result<T> {
        let command_tx = self.command_sender()?;
        let permit = self
            .inner
            .command_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| fabric_stopped())?;
        let (sender, receiver) = oneshot::channel();
        let cleanup_tx = command_tx.clone();
        let reply = ResourceReply::new(sender, move |value| {
            let action = abandoned(value);
            let tx = cleanup_tx.clone();
            ResourceGuard::new(move || {
                let _ = tx.send(CommandEnvelope::urgent(FabricCommand::Abandon { action }));
            })
        });
        command_tx
            .send(CommandEnvelope::admitted(make_command(reply), permit))
            .map_err(|_| fabric_stopped())?;
        Ok(receiver.await.map_err(|_| fabric_stopped())??.claim())
    }

    pub(crate) fn child_guard(&self, id: ReadChildId) -> ResourceGuard {
        self.resource_guard(Abandoned::Child(id))
    }
    pub(crate) fn lane_guard(&self, id: u16) -> ResourceGuard {
        self.resource_guard(Abandoned::Lane(id))
    }
    pub(crate) fn source_guard(&self, id: ReadSourceId) -> ResourceGuard {
        self.resource_guard(Abandoned::Source(id, true))
    }
    pub(crate) fn retained_source_guard(&self, id: ReadSourceId) -> ResourceGuard {
        self.resource_guard(Abandoned::Source(id, false))
    }
    fn resource_guard(&self, action: Abandoned) -> ResourceGuard {
        let tx = self.command_sender().ok();
        ResourceGuard::new(move || {
            if let Some(tx) = tx {
                let _ = tx.send(CommandEnvelope::urgent(FabricCommand::Abandon { action }));
            }
        })
    }

    async fn submit<T>(
        &self,
        make_command: impl FnOnce(oneshot::Sender<Result<T>>) -> FabricCommand,
    ) -> Result<T> {
        let command_tx = self.command_sender()?;
        let permit = self
            .inner
            .command_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| fabric_stopped())?;
        let (reply_tx, reply_rx) = oneshot::channel();
        command_tx
            .send(CommandEnvelope::admitted(make_command(reply_tx), permit))
            .map_err(|_| fabric_stopped())?;
        reply_rx.await.map_err(|_| fabric_stopped())?
    }

    async fn submit_urgent<T>(
        &self,
        make_command: impl FnOnce(oneshot::Sender<Result<T>>) -> FabricCommand,
    ) -> Result<T> {
        let command_tx = self.command_sender()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        command_tx
            .send(CommandEnvelope::urgent(make_command(reply_tx)))
            .map_err(|_| fabric_stopped())?;
        reply_rx.await.map_err(|_| fabric_stopped())?
    }

    fn command_sender(&self) -> Result<CommandSender> {
        self.inner
            .command_tx
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(fabric_stopped)
    }

    /// Shuts the native resource tree down and joins the owner thread.
    /// Concurrent callers serialize; later calls observe the completed state.
    pub(crate) async fn shutdown(&self) -> Result<()> {
        let _shutdown = self.inner.shutdown.lock().await;
        let command_tx = self.inner.command_tx.lock().unwrap().take();

        let shutdown_result = if let Some(command_tx) = command_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            match command_tx.send(CommandEnvelope::urgent(FabricCommand::Shutdown {
                reply: Some(reply_tx),
            })) {
                Ok(()) => reply_rx.await.unwrap_or_else(|_| {
                    Err(Error::Shutdown {
                        failures: vec!["URMA owner thread dropped shutdown reply".into()],
                    })
                }),
                Err(_) => Err(Error::Shutdown {
                    failures: vec!["URMA owner thread stopped before shutdown command".into()],
                }),
            }
        } else {
            Ok(())
        };

        let join_result = join_owner(&self.inner.join);
        shutdown_result.and(join_result)
    }
}

/// Wakes a parked cache owner on every command, including guard-driven cleanup.
/// unpark's stored token closes the enqueue-before-park race.
#[derive(Clone)]
struct CommandSender {
    tx: mpsc::UnboundedSender<CommandEnvelope>,
    owner: Option<thread::Thread>,
}
impl CommandSender {
    fn send(
        &self,
        command: CommandEnvelope,
    ) -> std::result::Result<(), mpsc::error::SendError<CommandEnvelope>> {
        self.tx.send(command)?;
        if let Some(owner) = &self.owner {
            owner.unpark();
        }
        Ok(())
    }
}

struct FabricInner {
    command_tx: Mutex<Option<CommandSender>>,
    command_slots: Arc<Semaphore>,
    readiness: watch::Receiver<FabricReadiness>,
    runtime_config: RuntimeConfig,
    transport_type: u32,
    transport_modes: u32,
    max_message_size: u64,
    max_read_size: u32,
    shutdown: AsyncMutex<()>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for FabricInner {
    fn drop(&mut self) {
        if let Some(command_tx) = self.command_tx.get_mut().unwrap().take() {
            let _ = command_tx.send(CommandEnvelope::urgent(FabricCommand::Shutdown {
                reply: None,
            }));
            drop(command_tx);
        }
        if let Some(join) = self.join.get_mut().unwrap().take() {
            let _ = join.join();
        }
    }
}

pub(crate) enum Abandoned {
    Control(u16, u64),
    Lane(u16),
    Child(ReadChildId),
    Source(ReadSourceId, bool),
    CachedSourceLease(super::read_source_cache::CacheLease),
}

enum FabricCommand {
    CreateControl {
        lane_id: u16,
        reply: oneshot::Sender<Result<super::native_control::ControlSetup>>,
    },
    ConnectControl {
        lane_id: u16,
        control_id: u64,
        descriptor: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    SendControl {
        lane_id: u16,
        control_id: u64,
        bytes: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    Abandon {
        action: Abandoned,
    },
    AcquireCachedSourceLease {
        request: ReadCachedLeaseRequest,
        reply: ResourceReply<ReadCachedLeaseOffer>,
    },
    RegisterCachedSource {
        request: ReadCachedSourceRequest,
        reply: oneshot::Sender<Result<ReadCachedSource>>,
    },
    ExposeCachedSourceLease {
        lease: super::read_source_cache::CacheLease,
        generation: u64,
        reply: oneshot::Sender<Result<()>>,
    },
    ReleaseCachedSourceLease {
        lease: super::read_source_cache::CacheLease,
        transfer: super::read_protocol::ReadTransferIdentity,
        generation: u64,
        reply: oneshot::Sender<Result<()>>,
    },
    CreateLane {
        reply: ResourceReply<(u16, Vec<u8>)>,
    },
    ConnectLane {
        lane_id: u16,
        descriptor: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },

    CreateReadChild {
        request: ReadChildRequest,
        reply: ResourceReply<ReadChildAdmission>,
    },

    PostReadChildBatch {
        admission_wait_ns: u64,
        enqueued_at: std::time::Instant,
        id: ReadChildId,
        lengths: Vec<u32>,
        reply: oneshot::Sender<Result<usize>>,
    },

    ReadChildProgress {
        id: ReadChildId,
        reply: oneshot::Sender<Result<ReadChildProgress>>,
    },
    SubscribeReadChildProgress {
        id: ReadChildId,
        reply: oneshot::Sender<Result<watch::Receiver<ReadChildUpdate>>>,
    },

    RetireReadChild {
        id: ReadChildId,
        reply: oneshot::Sender<Result<bool>>,
    },

    DrainReadChildForLease {
        id: ReadChildId,
        reply: oneshot::Sender<Result<()>>,
    },

    PublishReadChildLease {
        id: ReadChildId,
        reply: ResourceReply<ReadLeaseSpan>,
    },

    RecycleReadChildLease {
        id: ReadChildId,
        reply: oneshot::Sender<Result<bool>>,
    },

    RegisterReadSource {
        request: ReadSourceRequest,
        reply: ResourceReply<ReadSourceAdmission>,
    },

    RetireReadSource {
        id: ReadSourceId,
        reply: oneshot::Sender<Result<()>>,
    },

    UnregisterReadSource {
        id: ReadSourceId,
        reply: oneshot::Sender<Result<bool>>,
    },

    ReleaseReadSourceAfterRevoke {
        id: ReadSourceId,
        reply: oneshot::Sender<Result<bool>>,
    },

    CloseLane {
        lane_id: u16,
        reply: oneshot::Sender<Result<()>>,
    },

    Shutdown {
        reply: Option<oneshot::Sender<Result<()>>>,
    },
}

struct CommandEnvelope {
    command: FabricCommand,
    _permit: Option<OwnedSemaphorePermit>,
}

impl CommandEnvelope {
    fn admitted(command: FabricCommand, permit: OwnedSemaphorePermit) -> Self {
        Self {
            command,
            _permit: Some(permit),
        }
    }

    fn urgent(command: FabricCommand) -> Self {
        Self {
            command,
            _permit: None,
        }
    }
}

fn run_owner(
    config: RuntimeConfig,
    mut command_rx: mpsc::UnboundedReceiver<CommandEnvelope>,
    readiness_tx: watch::Sender<FabricReadiness>,
    startup_tx: std_mpsc::SyncSender<StartupResult>,
) {
    let source_workers = config.read.source_workers;
    let mut runtime = match UrmaRuntime::start(config) {
        Ok(runtime) => runtime,
        Err(error) => {
            readiness_tx.send_replace(FabricReadiness::Failed(error.to_string()));
            let _ = startup_tx.send(Err(error));
            return;
        }
    };

    if let Err(error) = runtime.enable_source_workers(source_workers) {
        readiness_tx.send_replace(FabricReadiness::Failed(error.to_string()));
        let _ = startup_tx.send(Err(error));
        let _ = runtime.shutdown();
        return;
    }
    let probe = (
        runtime.transport_type(),
        runtime.transport_modes(),
        runtime.max_message_size(),
        runtime.max_read_size(),
    );
    readiness_tx.send_replace(FabricReadiness::Ready);
    if startup_tx.send(Ok(probe)).is_err() {
        let _ = shutdown_runtime(runtime, &readiness_tx);
        return;
    }

    let mut runtime = runtime;
    let mut poisoned = None;
    loop {
        runtime.poll_source_workers();
        runtime.maintain_cached_sources();
        if runtime.outstanding() == 0
            && !runtime.source_work_pending()
            && !runtime.controls_present()
        {
            // Cached sources need maintenance even without commands or CQEs.
            // Keep the original blocking path when the cache is empty; an
            // idle cache wakes at low frequency without polling the device CQ.
            let command = if runtime.cached_sources_present() {
                match command_rx.try_recv() {
                    Ok(command) => Some(command),
                    Err(mpsc::error::TryRecvError::Empty) => {
                        thread::park_timeout(Duration::from_secs(1));
                        continue;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => None,
                }
            } else {
                command_rx.blocking_recv()
            };
            match command {
                Some(envelope) => {
                    if let OwnerControl::Shutdown(reply) =
                        handle_command(envelope.command, &mut runtime, poisoned.as_deref())
                    {
                        finish_owner(runtime, &readiness_tx, reply, &mut command_rx);
                        return;
                    }
                }
                None => {
                    finish_owner(runtime, &readiness_tx, None, &mut command_rx);
                    return;
                }
            }
            continue;
        }

        let mut commands_processed = 0;
        for _ in 0..MAX_COMMANDS_PER_TICK {
            match command_rx.try_recv() {
                Ok(envelope) => {
                    commands_processed += 1;
                    if let OwnerControl::Shutdown(reply) =
                        handle_command(envelope.command, &mut runtime, poisoned.as_deref())
                    {
                        finish_owner(runtime, &readiness_tx, reply, &mut command_rx);
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    finish_owner(runtime, &readiness_tx, None, &mut command_rx);
                    return;
                }
            }
        }

        match runtime.poll_once() {
            Ok(completed) => {
                let idle = completed == 0 && commands_processed == 0;
                if idle {
                    thread::park_timeout(PROGRESS_IDLE_INTERVAL);
                } else {
                    thread::yield_now();
                }
            }
            Err(error) => {
                if poisoned.is_none() {
                    runtime.interrupt_read_waiters();
                }
                poison_once(&mut poisoned, error.to_string(), &readiness_tx);
                thread::park_timeout(PROGRESS_IDLE_INTERVAL);
            }
        }
    }
}

enum OwnerControl {
    Continue,
    Shutdown(Option<oneshot::Sender<Result<()>>>),
}

fn handle_command(
    command: FabricCommand,
    runtime: &mut UrmaRuntime,
    poisoned: Option<&str>,
) -> OwnerControl {
    match command {
        FabricCommand::CreateControl { lane_id, reply } => {
            let result =
                reject_if_poisoned(poisoned).and_then(|()| runtime.create_control(lane_id));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::ConnectControl {
            lane_id,
            control_id,
            descriptor,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.connect_control(lane_id, control_id, descriptor));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::SendControl {
            lane_id,
            control_id,
            bytes,
            reply,
        } => {
            match reject_if_poisoned(poisoned) {
                Ok(()) => runtime.send_control(lane_id, control_id, bytes, reply),
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            }
            OwnerControl::Continue
        }

        FabricCommand::Abandon { action } => {
            match action {
                Abandoned::Control(lane, id) => {
                    runtime.stop_control(lane, id);
                }
                Abandoned::Lane(id) => {
                    let _ = runtime.close_peer_target(id);
                }
                Abandoned::Child(id) => runtime.abandon_read_child(id),
                Abandoned::Source(id, ready) => runtime.abandon_read_source(id, ready),
                Abandoned::CachedSourceLease(lease) => runtime.abandon_cached_source_lease(lease),
            }
            OwnerControl::Continue
        }
        FabricCommand::CreateLane { reply } => {
            let result = reject_if_poisoned(poisoned).and_then(|()| {
                let (lane_id, descriptor) = runtime.create_peer_target()?;
                match descriptor.serialize() {
                    Ok(descriptor) => Ok((lane_id, descriptor)),
                    Err(error) => {
                        let _ = runtime.close_peer_target(lane_id);
                        Err(error)
                    }
                }
            });
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::ConnectLane {
            lane_id,
            descriptor,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned).and_then(|()| {
                let descriptor = JettyDescriptor::deserialize(&descriptor)?;
                runtime.connect_peer_target(lane_id, &descriptor)
            });
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::CreateReadChild { request, reply } => {
            let result = reject_if_poisoned(poisoned).and_then(|()| {
                // SAFETY: This command can only be constructed by the unsafe
                // facade whose caller supplies descriptor/generation proofs.
                unsafe { runtime.create_read_child(request) }
            });
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::PostReadChildBatch {
            id,
            lengths,
            reply,
            admission_wait_ns,
            enqueued_at,
        } => {
            let queue_wait_ns = enqueued_at.elapsed().as_nanos() as u64;
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| {
                    runtime.record_read_post_command_wait(id, admission_wait_ns, queue_wait_ns)
                })
                .and_then(|()| runtime.post_read_child_batch(id, &lengths));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::SubscribeReadChildProgress { id, reply } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.subscribe_read_child_progress(id));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::ReadChildProgress { id, reply } => {
            let result =
                reject_if_poisoned(poisoned).and_then(|()| runtime.read_child_progress(id));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::RetireReadChild { id, reply } => {
            let _ = reply.send(runtime.retire_read_child_for_cleanup(id));
            OwnerControl::Continue
        }
        FabricCommand::DrainReadChildForLease { id, reply } => {
            let result =
                reject_if_poisoned(poisoned).and_then(|()| runtime.drain_read_child_for_lease(id));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::PublishReadChildLease { id, reply } => {
            let result =
                reject_if_poisoned(poisoned).and_then(|()| runtime.publish_read_child_lease(id));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::RecycleReadChildLease { id, reply } => {
            let result = runtime.recycle_read_child_lease(id);
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::RegisterReadSource { request, reply } => {
            match reject_if_poisoned(poisoned) {
                Ok(()) => unsafe { runtime.submit_source_registration(request, reply) },
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            }
            OwnerControl::Continue
        }
        FabricCommand::AcquireCachedSourceLease { request, reply } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.acquire_cached_source_lease(request));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::RegisterCachedSource { request, reply } => {
            match reject_if_poisoned(poisoned) {
                Ok(()) => unsafe { runtime.submit_cached_source_registration(request, reply) },
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            }
            OwnerControl::Continue
        }
        FabricCommand::ExposeCachedSourceLease {
            lease,
            generation,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.expose_cached_source_lease(lease, generation));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::ReleaseCachedSourceLease {
            lease,
            transfer,
            generation,
            reply,
        } => {
            // SAFETY: only the unsafe Fabric facade constructs this command.
            let _ = reply
                .send(unsafe { runtime.release_cached_source_lease(lease, transfer, generation) });
            OwnerControl::Continue
        }
        FabricCommand::RetireReadSource { id, reply } => {
            let _ = reply.send(runtime.retire_read_source(id));
            OwnerControl::Continue
        }
        FabricCommand::UnregisterReadSource { id, reply } => {
            // SAFETY: Construction is restricted to the unsafe facade.
            unsafe { runtime.submit_source_cleanup(id, false, reply) };
            OwnerControl::Continue
        }
        FabricCommand::ReleaseReadSourceAfterRevoke { id, reply } => {
            // SAFETY: Construction is restricted to the unsafe facade.
            unsafe { runtime.submit_source_cleanup(id, true, reply) };
            OwnerControl::Continue
        }

        FabricCommand::CloseLane { lane_id, reply } => {
            let _ = reply.send(runtime.close_peer_target(lane_id));
            OwnerControl::Continue
        }

        FabricCommand::Shutdown { reply } => OwnerControl::Shutdown(reply),
    }
}

fn poison_once(
    poisoned: &mut Option<String>,
    failure: String,
    readiness_tx: &watch::Sender<FabricReadiness>,
) {
    if poisoned.is_none() {
        readiness_tx.send_replace(FabricReadiness::Failed(failure.clone()));
        *poisoned = Some(failure);
    }
}

fn reject_if_poisoned(poisoned: Option<&str>) -> Result<()> {
    match poisoned {
        Some(failure) => Err(Error::Protocol(format!(
            "URMA fabric is poisoned: {failure}"
        ))),
        None => Ok(()),
    }
}

fn fabric_stopped() -> Error {
    Error::Shutdown {
        failures: vec!["URMA owner thread is stopped".into()],
    }
}

fn finish_owner(
    runtime: UrmaRuntime,
    readiness_tx: &watch::Sender<FabricReadiness>,
    reply: Option<oneshot::Sender<Result<()>>>,
    commands: &mut mpsc::UnboundedReceiver<CommandEnvelope>,
) {
    let result = runtime.shutdown_with_progress(|runtime| {
        for _ in 0..MAX_COMMANDS_PER_TICK {
            let Ok(envelope) = commands.try_recv() else {
                break;
            };
            if let OwnerControl::Shutdown(Some(reply)) =
                handle_command(envelope.command, runtime, Some("shutting down"))
            {
                let _ = reply.send(Err(fabric_stopped()));
            }
        }
    });
    readiness_tx.send_replace(match &result {
        Ok(()) => FabricReadiness::Stopped,
        Err(error) => FabricReadiness::Failed(error.to_string()),
    });
    if let Some(reply) = reply {
        let _ = reply.send(result);
    }
}

fn shutdown_runtime(
    runtime: UrmaRuntime,
    readiness_tx: &watch::Sender<FabricReadiness>,
) -> Result<()> {
    match runtime.shutdown() {
        Ok(()) => {
            readiness_tx.send_replace(FabricReadiness::Stopped);
            Ok(())
        }
        Err(error) => {
            readiness_tx.send_replace(FabricReadiness::Failed(error.to_string()));
            Err(error)
        }
    }
}

fn join_owner(join: &Mutex<Option<JoinHandle<()>>>) -> Result<()> {
    let Some(join) = join.lock().unwrap().take() else {
        return Ok(());
    };
    join.join().map_err(|_| Error::Shutdown {
        failures: vec!["URMA owner thread panicked".into()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_enqueued_before_owner_parks_preserves_wakeup() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (park_tx, park_rx) = std_mpsc::sync_channel(0);
        let (done_tx, done_rx) = std_mpsc::sync_channel(1);
        let join = thread::spawn(move || {
            // The command is enqueued before this rendezvous permits parking.
            park_rx.recv().unwrap();
            thread::park_timeout(Duration::from_secs(30));
            done_tx.send(()).unwrap();
        });
        let sender = CommandSender {
            tx,
            owner: Some(join.thread().clone()),
        };
        sender
            .send(CommandEnvelope::urgent(FabricCommand::Shutdown {
                reply: None,
            }))
            .unwrap();
        park_tx.send(()).unwrap();
        let result = done_rx.recv_timeout(Duration::from_secs(2));
        // Always unblock/join on failure so the regression cannot hang tests.
        join.thread().unpark();
        join.join().unwrap();
        assert!(result.is_ok(), "enqueue lost the owner's wake token");
    }

    fn lease_test_handle() -> (UrmaFabricHandle, mpsc::UnboundedReceiver<CommandEnvelope>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (_, readiness) = watch::channel(FabricReadiness::Ready);
        let read = super::super::runtime::ReadRuntimeConfig::try_from_config(
            &dragonfly_client_config::dfdaemon::UrmaReadServer::default(),
        )
        .unwrap();
        (
            UrmaFabricHandle {
                inner: Arc::new(FabricInner {
                    command_tx: Mutex::new(Some(CommandSender { tx, owner: None })),
                    command_slots: Arc::new(Semaphore::new(1)),
                    readiness,
                    runtime_config: RuntimeConfig::new("test-only", 0, read),
                    transport_type: 0,
                    transport_modes: 0,
                    max_message_size: 0,
                    max_read_size: 4096,
                    shutdown: AsyncMutex::new(()),
                    join: Mutex::new(None),
                }),
            },
            rx,
        )
    }

    fn lease_test_cache() -> (
        tempfile::TempDir,
        super::super::read_source_cache::ReadSourceCache,
        super::super::read_registry::ReadOwnerRegistry<u32>,
        ReadSourceId,
    ) {
        use super::super::{
            read_registry::{ReadBudget, ReadCapacity, ReadOwnerRegistry, ReadPeer},
            read_source_cache::{CacheRequest, ReadSourceCache},
        };
        let cap = ReadCapacity {
            bytes: 64,
            entries: 8,
        };
        let mut registry = ReadOwnerRegistry::new(ReadBudget {
            total: ReadCapacity {
                bytes: 128,
                entries: 16,
            },
            source: cap,
            destination: cap,
            per_peer_source: cap,
            per_peer_destination: cap,
            quarantine: cap,
        })
        .unwrap();
        registry
            .activate_peer(ReadPeer {
                id: 1,
                generation: 1,
            })
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("task");
        std::fs::write(&path, vec![1; 64]).unwrap();
        let file = crate::content::ReadSourceFile::open(&path).unwrap();
        let mut cache = ReadSourceCache::new();
        let claim = cache
            .claim(
                &mut registry,
                CacheRequest {
                    kind: crate::rendezvous::PieceKind::Piece,
                    task: "task",
                    file,
                    piece_length: 8,
                    max_region_bytes: 64,
                    piece_offset: 0,
                    completed: &[0..64],
                },
                std::time::Instant::now(),
            )
            .unwrap();
        cache.start_registration(claim.source).unwrap();
        cache
            .registered(&mut registry, claim.source, 7, false)
            .unwrap();
        (dir, cache, registry, ReadSourceId(claim.source))
    }

    fn lease_test_offer(
        lease: super::super::read_source_cache::CacheLease,
        source: ReadSourceId,
    ) -> ReadCachedLeaseOffer {
        ReadCachedLeaseOffer {
            lease,
            source_offset: 0,
            offer: super::super::runtime::ReadSourceOffer {
                id: source,
                descriptor: super::super::ffi::read::ReadDescriptor {
                    version: 1,
                    eid: [1; 16],
                    uasid: 1,
                    va: 4096,
                    length: 64,
                    token_id: 1,
                    access: 1,
                    token_policy: 0,
                },
                token: super::super::ffi::read::ReadToken::new(7),
                register_stages: Default::default(),
            },
        }
    }

    fn lease_test_identity() -> super::super::read_protocol::ReadTransferIdentity {
        super::super::read_protocol::ReadTransferIdentity {
            session_generation: 1,
            transfer_id: 2,
            metadata_generation: 3,
        }
    }

    async fn queued<F: std::future::Future + Unpin>(
        pending: &mut F,
        rx: &mut mpsc::UnboundedReceiver<CommandEnvelope>,
    ) -> FabricCommand {
        tokio::select! {
            command = rx.recv() => command.expect("queued owner command").command,
            _ = pending => panic!("request completed without an owner reply"),
        }
    }

    fn abandoned_lease(command: FabricCommand) -> super::super::read_source_cache::CacheLease {
        match command {
            FabricCommand::Abandon {
                action: Abandoned::CachedSourceLease(lease),
            } => lease,
            _ => panic!("expected lease abandonment, not physical source retirement"),
        }
    }

    #[tokio::test]
    async fn cached_registration_reply_loss_keeps_producer_owned_by_cache() {
        use super::super::{
            read_registry::{ReapDecision, VerifiedRetirement},
            read_source_cache::CacheRequest,
        };
        for cancel_before_reply in [true, false] {
            let (dir, mut cache, mut registry, old) = lease_test_cache();
            cache.retire(&mut registry, old.0).unwrap();
            // SAFETY: this fixture has an integer owner and no native access.
            registry
                .reap_with(old.0, |_| {
                    Ok::<_, ()>(ReapDecision::Retired(unsafe {
                        VerifiedRetirement::new(old.0)
                    }))
                })
                .unwrap();
            cache.observe_cleanup(&registry, old.0).unwrap();
            let (fabric, mut rx) = lease_test_handle();
            let file = crate::content::ReadSourceFile::open(&dir.path().join("task")).unwrap();
            let request = || ReadCachedSourceRequest {
                peer_id: 1,
                kind: crate::rendezvous::PieceKind::Piece,
                task: "task".into(),
                file: file.clone(),
                piece_length: 8,
                max_region_bytes: 64,
                piece_offset: 0,
                completed: vec![0..64],
                token: super::super::ffi::read::ReadToken::new(9),
            };
            // SAFETY: immutable test file, mock owner, no provider access.
            let mut registering = Box::pin(unsafe {
                fabric.register_cached_source(request(), Duration::from_secs(3))
            });
            let FabricCommand::RegisterCachedSource {
                request: command,
                reply,
            } = queued(&mut registering, &mut rx).await
            else {
                panic!("expected cache-owned registration");
            };
            let claim = cache
                .claim(
                    &mut registry,
                    CacheRequest {
                        kind: command.kind,
                        task: &command.task,
                        file: command.file,
                        piece_length: command.piece_length,
                        max_region_bytes: command.max_region_bytes,
                        piece_offset: command.piece_offset,
                        completed: &command.completed,
                    },
                    std::time::Instant::now(),
                )
                .unwrap();
            assert!(claim.register);
            cache.start_registration(claim.source).unwrap();
            let result = ReadCachedSource {
                source: ReadSourceId(claim.source),
                peer_generation: 1,
                range: claim.range,
                updates: claim.updates,
            };
            if cancel_before_reply {
                drop(registering);
                assert!(reply.send(Ok(result)).is_err());
            } else {
                assert!(reply.send(Ok(result)).is_ok());
                tokio::select! {
                    _ = &mut registering => panic!("must wait while native registration is pending"),
                    _ = tokio::task::yield_now() => {}
                }
                drop(registering);
            }
            assert!(matches!(
                rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            assert_eq!(registry.usage().source_bytes, 64);
            cache
                .registered(&mut registry, claim.source, 7, false)
                .unwrap();
            // A later request can observe the completed registration, with no
            // second producer and no guard tied to the departed first request.
            let mut later = Box::pin(unsafe {
                fabric.register_cached_source(request(), Duration::from_secs(3))
            });
            let FabricCommand::RegisterCachedSource { reply, .. } =
                queued(&mut later, &mut rx).await
            else {
                panic!("expected cached lookup");
            };
            let hit = cache
                .claim(
                    &mut registry,
                    CacheRequest {
                        kind: crate::rendezvous::PieceKind::Piece,
                        task: "task",
                        file: file.clone(),
                        piece_length: 8,
                        max_region_bytes: 64,
                        piece_offset: 0,
                        completed: &[0..64],
                    },
                    std::time::Instant::now(),
                )
                .unwrap();
            assert!(!hit.register);
            assert!(reply
                .send(Ok(ReadCachedSource {
                    source: ReadSourceId(hit.source),
                    peer_generation: 1,
                    range: hit.range,
                    updates: hit.updates
                }))
                .is_ok());
            assert_eq!(later.await.unwrap().source, ReadSourceId(claim.source));
            assert_eq!(registry.usage().source_entries, 1);
        }
    }

    #[tokio::test]
    async fn cached_parent_publishes_region_and_finishes_only_its_lease() {
        use super::super::{
            read_control::ReadLaneControl,
            read_protocol::{ReadFrame, ReadPieceLocator},
            read_registry::ReadPeer,
            read_source_cache::{CacheRequest, CacheState},
            read_transfer::parent::ParentTransfer,
        };
        let (dir, mut cache, mut registry, source) = lease_test_cache();
        registry
            .activate_peer(ReadPeer {
                id: 2,
                generation: 1,
            })
            .unwrap();
        let file = crate::content::ReadSourceFile::open(&dir.path().join("task")).unwrap();
        let (fabric, mut rx) = lease_test_handle();
        for peer_id in [1, 2] {
            let identity = lease_test_identity();
            let piece_offset = u64::from(peer_id) * 8;
            let (client_stream, server_stream) = tokio::io::duplex(4096);
            let child_lane =
                ReadLaneControl::spawn(client_stream, identity.session_generation, 2, 4).unwrap();
            let parent_lane =
                ReadLaneControl::spawn(server_stream, identity.session_generation, 2, 4).unwrap();
            let mut child = child_lane.register(identity).unwrap();
            let mut control = parent_lane.register(identity).unwrap();
            child
                .send(ReadFrame::BufferReady {
                    identity,
                    accepted_length: 8,
                    request: ReadPieceLocator {
                        kind: crate::rendezvous::PieceKind::Piece,
                        task_id: "task".into(),
                        piece_number: u32::from(peer_id),
                    },
                })
                .await
                .unwrap();
            let ready = control.receive().await.unwrap();
            let (parent, _) = ParentTransfer::accept(
                fabric.clone(),
                peer_id,
                control,
                ready,
                piece_offset,
                String::new(),
                4096,
            )
            .unwrap();
            let parent = parent.on_source_state(|_, _| {
                panic!("cached source must not enter the dedicated per-lane cleanup ledger")
            });
            // SAFETY: immutable test file, integer owner, no native grants/READ.
            let mut publishing = Box::pin(unsafe {
                parent.publish_cached_and_wait_read_done(
                    ReadCachedSourceRequest {
                        peer_id,
                        kind: crate::rendezvous::PieceKind::Piece,
                        task: "task".into(),
                        file: file.clone(),
                        piece_length: 8,
                        max_region_bytes: 64,
                        piece_offset,
                        completed: vec![0..64],
                        token: super::super::ffi::read::ReadToken::new(7),
                    },
                    Duration::from_secs(3),
                )
            });
            let FabricCommand::RegisterCachedSource { request, reply } =
                queued(&mut publishing, &mut rx).await
            else {
                panic!("expected cached registration");
            };
            let claim = cache
                .claim(
                    &mut registry,
                    CacheRequest {
                        kind: request.kind,
                        task: &request.task,
                        file: request.file,
                        piece_length: request.piece_length,
                        max_region_bytes: request.max_region_bytes,
                        piece_offset: request.piece_offset,
                        completed: &request.completed,
                    },
                    std::time::Instant::now(),
                )
                .unwrap();
            assert!(!claim.register);
            assert_eq!(claim.source, source.0);
            assert!(reply
                .send(Ok(ReadCachedSource {
                    source,
                    peer_generation: 1,
                    range: claim.range,
                    updates: claim.updates
                }))
                .is_ok());
            let FabricCommand::AcquireCachedSourceLease { request, reply } =
                queued(&mut publishing, &mut rx).await
            else {
                panic!("expected lease acquisition");
            };
            let lease = cache
                .acquire(
                    &mut registry,
                    source.0,
                    ReadPeer {
                        id: peer_id,
                        generation: 1,
                    },
                    request.transfer,
                    request.piece,
                    std::time::Instant::now(),
                )
                .unwrap();
            let mut offered = lease_test_offer(lease, source);
            offered.source_offset = piece_offset;
            assert!(reply.send(Ok(offered)).is_ok());
            let FabricCommand::ExposeCachedSourceLease {
                lease,
                generation,
                reply,
            } = queued(&mut publishing, &mut rx).await
            else {
                panic!("expected exposure before wire publication");
            };
            cache.expose(lease, generation).unwrap();
            reply.send(Ok(())).unwrap();
            let frame = tokio::select! {
                frame = child.receive() => frame.unwrap(),
                _ = &mut publishing => panic!("Parent must wait for Child drain"),
            };
            let ReadFrame::SegmentOffer { offer, .. } = frame else {
                panic!("expected Region Offer");
            };
            assert_eq!(
                (
                    offer.length,
                    offer.source_offset,
                    offer.piece_length,
                    offer.piece_offset
                ),
                (64, piece_offset, 8, piece_offset)
            );
            assert_eq!(offer.segment_generation, generation);
            if peer_id == 1 {
                child
                    .send(ReadFrame::ReadDone {
                        identity,
                        segment_generation: generation,
                        completed_length: 8,
                        read_wr_count: 1,
                    })
                    .await
                    .unwrap();
            } else {
                child
                    .send(ReadFrame::Cancel {
                        identity,
                        segment_generation: Some(generation),
                        reason: "cancelled before post".into(),
                    })
                    .await
                    .unwrap();
                child
                    .send(ReadFrame::CancelDrained {
                        identity,
                        segment_generation: Some(generation),
                        accepted_wr_count: 0,
                        retired_wr_count: 0,
                    })
                    .await
                    .unwrap();
            }
            let (parent, pending) = publishing.await.map_err(|failure| failure.error).unwrap();
            // SAFETY: mock transport has no native accesses; the protocol has
            // validated this exact ReadDone/CancelDrained identity/generation.
            let mut finishing = Box::pin(unsafe { parent.finish(pending) });
            let FabricCommand::ReleaseCachedSourceLease {
                lease,
                transfer,
                generation,
                reply,
            } = queued(&mut finishing, &mut rx).await
            else {
                panic!("must release the lease, never unregister the shared source");
            };
            unsafe {
                cache.release_drained(
                    &mut registry,
                    lease,
                    transfer,
                    generation,
                    std::time::Instant::now(),
                )
            }
            .unwrap();
            reply.send(Ok(())).unwrap();
            finishing.await.unwrap();
            let terminal = child.receive().await.unwrap();
            if peer_id == 1 {
                assert!(matches!(terminal, ReadFrame::Done { .. }));
            } else {
                assert!(matches!(terminal, ReadFrame::Cancelled { .. }));
            }
            assert_eq!(registry.usage().source_bytes, 64);
            assert_eq!(
                registry
                    .peer_usage(ReadPeer {
                        id: peer_id,
                        generation: 1
                    })
                    .source_bytes,
                0
            );
            assert_eq!(
                *cache
                    .claim(
                        &mut registry,
                        CacheRequest {
                            kind: crate::rendezvous::PieceKind::Piece,
                            task: "task",
                            file: file.clone(),
                            piece_length: 8,
                            max_region_bytes: 64,
                            piece_offset,
                            completed: &[0..64]
                        },
                        std::time::Instant::now()
                    )
                    .unwrap()
                    .updates
                    .borrow(),
                CacheState::Ready
            );
            assert!(matches!(
                rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[tokio::test]
    async fn cached_acquire_reply_loss_before_or_after_send_only_releases_its_lease() {
        use super::super::read_registry::ReadPeer;
        for cancel_stage in 0..3 {
            let (_dir, mut cache, mut registry, source) = lease_test_cache();
            let (fabric, mut rx) = lease_test_handle();
            // SAFETY: device-free cache with integer owners and no remote accesses.
            let mut acquire = Box::pin(unsafe {
                fabric.acquire_cached_source_lease(ReadCachedLeaseRequest {
                    source,
                    peer_id: 1,
                    peer_generation: 1,
                    transfer: lease_test_identity(),
                    piece: 0..8,
                })
            });
            let FabricCommand::AcquireCachedSourceLease { request, reply } =
                queued(&mut acquire, &mut rx).await
            else {
                panic!("expected acquire");
            };
            let lease = cache
                .acquire(
                    &mut registry,
                    request.source.0,
                    ReadPeer {
                        id: 1,
                        generation: 1,
                    },
                    request.transfer,
                    request.piece,
                    std::time::Instant::now(),
                )
                .unwrap();
            if cancel_stage == 0 {
                drop(acquire);
                assert!(reply.send(Ok(lease_test_offer(lease, source))).is_err());
            } else {
                assert!(reply.send(Ok(lease_test_offer(lease, source))).is_ok());
                if cancel_stage == 1 {
                    drop(acquire);
                } else {
                    drop(acquire.await.unwrap());
                }
            }
            let lease = abandoned_lease(rx.recv().await.unwrap().command);
            cache
                .abandon(&mut registry, lease, std::time::Instant::now())
                .unwrap();
            assert_eq!(
                registry
                    .peer_usage(ReadPeer {
                        id: 1,
                        generation: 1
                    })
                    .source_bytes,
                0
            );
            assert_eq!(registry.usage().source_bytes, 64);
        }
    }

    #[tokio::test]
    async fn cached_expose_cancel_retains_and_release_reply_loss_cannot_free_another_lease() {
        use super::super::{
            read_registry::{OwnerError, ReadPeer},
            read_source_cache::CacheError,
        };
        for outcome in 0..3 {
            let (_dir, mut cache, mut registry, source) = lease_test_cache();
            let (fabric, mut rx) = lease_test_handle();
            let peer = ReadPeer {
                id: 1,
                generation: 1,
            };
            // SAFETY: no native resources or remote accesses exist in this test.
            let mut acquire = Box::pin(unsafe {
                fabric.acquire_cached_source_lease(ReadCachedLeaseRequest {
                    source,
                    peer_id: 1,
                    peer_generation: 1,
                    transfer: lease_test_identity(),
                    piece: 0..8,
                })
            });
            let FabricCommand::AcquireCachedSourceLease { request, reply } =
                queued(&mut acquire, &mut rx).await
            else {
                panic!("expected acquire");
            };
            let identity = cache
                .acquire(
                    &mut registry,
                    source.0,
                    peer,
                    request.transfer,
                    request.piece,
                    std::time::Instant::now(),
                )
                .unwrap();
            assert!(reply.send(Ok(lease_test_offer(identity, source))).is_ok());
            let mut lease = acquire.await.unwrap();
            let mut expose = Box::pin(fabric.expose_cached_source_lease(&lease, 11));
            let FabricCommand::ExposeCachedSourceLease {
                lease: identity,
                generation,
                reply,
            } = queued(&mut expose, &mut rx).await
            else {
                panic!("expected expose");
            };
            cache.expose(identity, generation).unwrap();
            if outcome == 0 {
                // Exposure was processed but its caller was cancelled before
                // receiving the reply. The subsequent lease guard must retain.
                drop(expose);
                drop(reply);
                drop(lease);
                let identity = abandoned_lease(rx.recv().await.unwrap().command);
                cache
                    .abandon(&mut registry, identity, std::time::Instant::now())
                    .unwrap();
                assert!(matches!(
                    cache.check_cleanup(&registry, source.0),
                    Err(CacheError::Registry(OwnerError::SourceBusy))
                ));
                assert_eq!(registry.peer_usage(peer).source_bytes, 8);
            } else {
                reply.send(Ok(())).unwrap();
                expose.await.unwrap();
                // SAFETY: test integer owners have no outstanding access.
                let mut release = Box::pin(unsafe {
                    fabric.release_cached_source_lease(&mut lease, lease_test_identity(), 11)
                });
                let FabricCommand::ReleaseCachedSourceLease {
                    lease: identity,
                    transfer,
                    generation,
                    reply,
                } = queued(&mut release, &mut rx).await
                else {
                    panic!("expected release");
                };
                // SAFETY: no native registration or READ exists.
                unsafe {
                    cache.release_drained(
                        &mut registry,
                        identity,
                        transfer,
                        generation,
                        std::time::Instant::now(),
                    )
                }
                .unwrap();
                reply.send(Ok(())).unwrap();
                if outcome == 2 {
                    release.await.unwrap();
                    drop(lease);
                    assert!(matches!(
                        rx.try_recv(),
                        Err(mpsc::error::TryRecvError::Empty)
                    ));
                    assert_eq!(registry.peer_usage(peer).source_bytes, 0);
                    assert_eq!(registry.usage().source_bytes, 64);
                    continue;
                }
                drop(release);
                let later = cache
                    .acquire(
                        &mut registry,
                        source.0,
                        peer,
                        super::super::read_protocol::ReadTransferIdentity {
                            transfer_id: 4,
                            ..lease_test_identity()
                        },
                        8..16,
                        std::time::Instant::now(),
                    )
                    .unwrap();
                drop(lease);
                let stale = abandoned_lease(rx.recv().await.unwrap().command);
                assert!(matches!(
                    cache.abandon(&mut registry, stale, std::time::Instant::now()),
                    Err(CacheError::Missing)
                ));
                assert_eq!(registry.peer_usage(peer).source_bytes, 8);
                cache
                    .abandon(&mut registry, later, std::time::Instant::now())
                    .unwrap();
            }
            assert_eq!(registry.usage().source_bytes, 64);
        }
    }

    #[tokio::test]
    async fn control_bridge_segments_bytes_and_guards_exact_endpoint_on_drop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (fabric, mut commands) = lease_test_handle();
        let (incoming, receiver) = mpsc::channel(32);
        let (watchdog, _remote_watchdog) = tokio::io::duplex(32);
        let setup = super::super::native_control::ControlSetup {
            id: 91,
            descriptor: vec![1],
            incoming: receiver,
        };
        let mut stream = super::super::sendrecv_control::spawn(fabric, 7, 41, setup, watchdog);
        let bytes: Vec<_> = (0..20_000).map(|n| (n % 251) as u8).collect();
        stream.write_all(&bytes).await.unwrap();
        let mut received = vec![0; bytes.len()];
        let mut reading = Box::pin(stream.read_exact(&mut received));
        let mut packets = 0;
        loop {
            tokio::select! {
                result = &mut reading => { result.unwrap(); break; }
                command = commands.recv() => {
                    let FabricCommand::SendControl { lane_id, control_id, bytes, reply } = command.unwrap().command else {
                        panic!("expected native SEND, never TCP frame fallback");
                    };
                    assert_eq!((lane_id, control_id), (7, 91));
                    assert!(bytes.len() <= 4096);
                    assert_eq!(u64::from_be_bytes(bytes[..8].try_into().unwrap()), 41);
                    reply.send(Ok(())).unwrap();
                    incoming.send(Ok(bytes)).await.unwrap();
                    packets += 1;
                }
            }
        }
        drop(reading);
        assert!(packets >= 5);
        assert_eq!(received, bytes);
        drop(stream);
        let closing = tokio::time::timeout(Duration::from_secs(1), commands.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            closing.command,
            FabricCommand::Abandon {
                action: Abandoned::Control(7, 91)
            }
        ));
    }

    #[test]
    fn zero_command_capacity_is_rejected_before_spawning() {
        let result = UrmaFabric::start_with_capacity(
            RuntimeConfig::new(
                "urma0",
                0,
                super::super::runtime::ReadRuntimeConfig::try_from_config(
                    &dragonfly_client_config::dfdaemon::UrmaReadServer::default(),
                )
                .unwrap(),
            ),
            0,
        );
        assert!(matches!(result, Err(Error::InvalidConfiguration(_))));
    }

    #[test]
    fn shared_fabric_requires_identical_runtime_configuration() {
        let active = RuntimeConfig::new(
            "urma0",
            2,
            super::super::runtime::ReadRuntimeConfig::try_from_config(
                &dragonfly_client_config::dfdaemon::UrmaReadServer::default(),
            )
            .unwrap(),
        );
        assert!(validate_shared_config(&active, &active).is_ok());
        assert!(validate_shared_config(
            &active,
            &RuntimeConfig::new(
                "urma1",
                2,
                super::super::runtime::ReadRuntimeConfig::try_from_config(
                    &dragonfly_client_config::dfdaemon::UrmaReadServer::default()
                )
                .unwrap()
            )
        )
        .is_err());
        assert!(validate_shared_config(
            &active,
            &RuntimeConfig::new(
                "urma0",
                3,
                super::super::runtime::ReadRuntimeConfig::try_from_config(
                    &dragonfly_client_config::dfdaemon::UrmaReadServer::default()
                )
                .unwrap()
            )
        )
        .is_err());
        let mut workers_changed = active.clone();
        workers_changed.read.source_workers = 1;
        assert!(validate_shared_config(&active, &workers_changed).is_err());
        let mut budget_changed = active.clone();
        budget_changed.read.budget.source.bytes -= 64 * 1024;
        assert!(validate_shared_config(&active, &budget_changed).is_err());
    }
    #[test]
    fn handle_is_safe_to_move_between_tokio_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UrmaFabricHandle>();
    }

    #[test]
    fn first_progress_failure_poison_is_stable_and_observable() {
        let (readiness_tx, readiness_rx) = watch::channel(FabricReadiness::Ready);
        let mut poisoned = None;

        poison_once(&mut poisoned, "first".into(), &readiness_tx);
        poison_once(&mut poisoned, "later".into(), &readiness_tx);

        assert_eq!(poisoned.as_deref(), Some("first"));
        assert_eq!(
            *readiness_rx.borrow(),
            FabricReadiness::Failed("first".into())
        );
        assert!(matches!(
            reject_if_poisoned(poisoned.as_deref()),
            Err(Error::Protocol(detail)) if detail.contains("first")
        ));
    }
}
