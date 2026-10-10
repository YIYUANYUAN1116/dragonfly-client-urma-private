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
const PROGRESS_IDLE_INTERVAL: Duration = Duration::from_micros(100);

/// Native device discovery should normally finish immediately. Bound the
/// synchronous hand-off so a wedged provider cannot pin an async caller and
/// the process-wide Fabric registry forever.
const FABRIC_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

type StartupProbe = (u32, u32, u64);
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
            Ok(Ok((transport_type, transport_modes, max_message_size))) => Ok(UrmaFabricHandle {
                inner: Arc::new(FabricInner {
                    command_tx: Mutex::new(Some(command_tx)),
                    command_slots,
                    readiness: readiness_rx,
                    runtime_config,
                    transport_type,
                    transport_modes,
                    max_message_size,
                    shutdown: AsyncMutex::new(()),
                    join: Mutex::new(Some(join)),
                }),
            }),
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
    /// closes the lease buffer, releasing the budget. Call only after Storage
    /// consumers have joined and the published span will never be dereferenced
    /// again. `Ok(true)` proves the full release; `Ok(false)` or an error
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

    fn command_sender(&self) -> Result<mpsc::UnboundedSender<CommandEnvelope>> {
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

struct FabricInner {
    command_tx: Mutex<Option<mpsc::UnboundedSender<CommandEnvelope>>>,
    command_slots: Arc<Semaphore>,
    readiness: watch::Receiver<FabricReadiness>,
    runtime_config: RuntimeConfig,
    transport_type: u32,
    transport_modes: u32,
    max_message_size: u64,
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
    Lane(u16),
    Child(ReadChildId),
    Source(ReadSourceId, bool),
}

enum FabricCommand {
    Abandon {
        action: Abandoned,
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
        if runtime.outstanding() == 0 && !runtime.source_work_pending() {
            match command_rx.blocking_recv() {
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

        for _ in 0..MAX_COMMANDS_PER_TICK {
            match command_rx.try_recv() {
                Ok(envelope) => {
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
                let idle = completed == 0;
                if idle {
                    thread::sleep(PROGRESS_IDLE_INTERVAL);
                } else {
                    thread::yield_now();
                }
            }
            Err(error) => {
                if poisoned.is_none() {
                    runtime.interrupt_read_waiters();
                }
                poison_once(&mut poisoned, error.to_string(), &readiness_tx);
                thread::sleep(PROGRESS_IDLE_INTERVAL);
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
        FabricCommand::Abandon { action } => {
            match action {
                Abandoned::Lane(id) => {
                    let _ = runtime.close_peer_target(id);
                }
                Abandoned::Child(id) => runtime.abandon_read_child(id),
                Abandoned::Source(id, ready) => runtime.abandon_read_source(id, ready),
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
