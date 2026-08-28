//! Thread-owned URMA fabric boundary for Dragonfly storage.
//!
//! The migrated native wrappers are deliberately `!Send` and `!Sync`. The
//! fabric creates, uses, and destroys [`UrmaRuntime`] on one OS thread. Async
//! Dragonfly code communicates with that thread through bounded business
//! admission plus a non-dropping lifecycle path, and never receives a raw
//! UMDK handle.

use super::{
    completion::{LaneCompletion, OperationCompletionTx},
    lane::{JettyConfig, JettyDescriptor},
    runtime::{RuntimeConfig, UrmaRuntime},
    Error, Result,
};
use std::thread::{self, JoinHandle};
use std::{
    sync::{mpsc as std_mpsc, Arc, Mutex, OnceLock, Weak},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

/// Default number of commands that may wait for the owner thread.
const DEFAULT_COMMAND_CAPACITY: usize = 16;

/// Bounds command latency while completions are actively being polled.
const MAX_COMMANDS_PER_TICK: usize = 16;

/// Pure polling is required because Phase A deliberately has no JFCE. Keep the
/// idle interval short without allowing an outstanding WR to consume one CPU.
const PROGRESS_IDLE_INTERVAL: Duration = Duration::from_micros(100);

/// Process-wide weak registry used by dfdaemon's server and downloader adapters. Native UMDK
/// permits one Runtime owner in this implementation, so independently starting both adapters
/// would make the second one fail with `AlreadyInitialized`.
static SHARED_FABRIC: OnceLock<Mutex<Weak<FabricInner>>> = OnceLock::new();

fn validate_shared_config(active: &RuntimeConfig, requested: &RuntimeConfig) -> Result<()> {
    if active == requested {
        return Ok(());
    }
    Err(Error::InvalidConfiguration(format!(
        "URMA Fabric is already running for device {} EID {}, requested device {} EID {}",
        active.device_name, active.eid_index, requested.device_name, requested.eid_index
    )))
}

/// Dragonfly-facing Jetty sizing. Native tokens and handles remain private to
/// the owner thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UrmaLaneConfig {
    pub send_depth: u32,
    pub recv_depth: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub token: u32,
}

impl Default for UrmaLaneConfig {
    fn default() -> Self {
        Self {
            send_depth: 128,
            recv_depth: 512,
            max_send_sge: 1,
            max_recv_sge: 1,
            token: 0,
        }
    }
}

impl From<UrmaLaneConfig> for JettyConfig {
    fn from(config: UrmaLaneConfig) -> Self {
        Self {
            send_depth: config.send_depth,
            recv_depth: config.recv_depth,
            max_send_sge: config.max_send_sge,
            max_recv_sge: config.max_recv_sge,
            token: config.token,
        }
    }
}

/// Completion DTO crossing from the native owner thread to async Dragonfly
/// code. It contains no UMDK handle or registered-memory borrow.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FabricCompletion {
    Sent {
        lane_id: u16,
        sequence: Option<u64>,
    },
    Received {
        lane_id: u16,
        sequence: Option<u64>,
        bytes: Vec<u8>,
    },
}

/// Observable process-level fabric state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FabricReadiness {
    /// The owner thread has started but native initialization is incomplete.
    Starting,
    /// Runtime, JFCs, shared JFR, and registered memory are ready.
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

    /// Returns the ready process Fabric for an identical runtime configuration, or starts it.
    /// The weak registry does not extend the native lifetime; the last handle still owns shutdown.
    pub fn get_or_start(
        device_name: impl Into<String>,
        eid_index: u32,
    ) -> Result<UrmaFabricHandle> {
        let config = RuntimeConfig::new(device_name, eid_index);
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

        match startup_rx.recv() {
            Ok(Ok((transport_type, max_message_size))) => Ok(UrmaFabricHandle {
                inner: Arc::new(FabricInner {
                    command_tx: Mutex::new(Some(command_tx)),
                    command_slots,
                    readiness: readiness_rx,
                    runtime_config,
                    transport_type,
                    max_message_size,
                    shutdown: AsyncMutex::new(()),
                    join: Mutex::new(Some(join)),
                }),
            }),
            Ok(Err(error)) => {
                let _ = join.join();
                Err(error)
            }
            Err(error) => {
                let _ = join.join();
                Err(Error::InvalidConfiguration(format!(
                    "URMA owner thread exited during startup: {error}"
                )))
            }
        }
    }
}

/// Cloneable, Tokio-safe facade for the thread-owned URMA runtime.
#[derive(Clone)]
pub struct UrmaFabricHandle {
    inner: Arc<FabricInner>,
}

/// One posted URMA operation. Dropping this handle abandons only the async
/// wait; the owner thread keeps the native WR and registered slot alive until
/// its CQE is reaped.
pub(crate) struct UrmaOpHandle {
    sequence: Option<u64>,
    completion: oneshot::Receiver<Result<LaneCompletion>>,
    abort: Option<(mpsc::UnboundedSender<CommandEnvelope>, u16)>,
}

impl UrmaOpHandle {
    pub(crate) async fn wait(self) -> Result<FabricCompletion> {
        self.completion
            .await
            .map_err(|_| fabric_stopped())?
            .map(Into::into)
    }

    /// Times out the logical wait and marks its lane ERROR without pretending
    /// that liburma cancelled this individual WR. Native ownership remains in
    /// CompletionRouter until a CQE or shutdown flush retires it.
    pub(crate) async fn wait_timeout(self, timeout: Duration) -> Result<FabricCompletion> {
        match tokio::time::timeout(timeout, self.completion).await {
            Ok(result) => result.map_err(|_| fabric_stopped())?.map(Into::into),
            Err(_) => {
                if let Some((command_tx, lane_id)) = self.abort {
                    abort_lane(command_tx, lane_id).await?;
                }
                Err(Error::OperationTimeout {
                    sequence: self.sequence,
                })
            }
        }
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

    /// max_message_size returns the effective single-message payload limit: the
    /// smaller of the device capability and one registered buffer slot.
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
    pub(crate) async fn create_lane(&self, config: UrmaLaneConfig) -> Result<(u16, Vec<u8>)> {
        self.submit(|reply| FabricCommand::CreateLane { config, reply })
            .await
    }

    /// Imports the peer descriptor and transitions the lane to Ready.
    pub(crate) async fn bind_lane(&self, lane_id: u16, descriptor: Vec<u8>) -> Result<()> {
        self.submit(|reply| FabricCommand::BindLane {
            lane_id,
            descriptor,
            reply,
        })
        .await
    }

    pub(crate) async fn post_receive(
        &self,
        lane_id: u16,
        sequence: Option<u64>,
    ) -> Result<UrmaOpHandle> {
        self.submit_operation(lane_id, sequence, |completion, reply| {
            FabricCommand::PostReceive {
                lane_id,
                sequence,
                completion,
                reply,
            }
        })
        .await
    }

    /// Applies a validated peer RecvPosted window to the lane. Window ordering
    /// remains a Piece-session responsibility; the Fabric owns only the count.
    pub(crate) async fn grant_send_credit(&self, lane_id: u16, count: u32) -> Result<()> {
        self.submit(|reply| FabricCommand::GrantSendCredit {
            lane_id,
            count,
            reply,
        })
        .await
    }

    pub(crate) async fn send(
        &self,
        lane_id: u16,
        bytes: Vec<u8>,
        sequence: Option<u64>,
    ) -> Result<UrmaOpHandle> {
        self.submit_operation(lane_id, sequence, |completion, reply| FabricCommand::Send {
            lane_id,
            bytes,
            sequence,
            completion,
            reply,
        })
        .await
    }

    pub(crate) async fn close_lane(&self, lane_id: u16) -> Result<()> {
        self.submit(|reply| FabricCommand::CloseLane { lane_id, reply })
            .await
    }

    pub(crate) async fn abort_lane(&self, lane_id: u16) -> Result<()> {
        let command_tx = self.command_sender()?;
        abort_lane(command_tx, lane_id).await
    }

    /// Cancellation hook for Drop paths that cannot await. Lifecycle commands
    /// bypass normal command admission so a full business queue cannot lose an
    /// abort request.
    pub(crate) fn try_abort_lane(&self, lane_id: u16) -> Result<()> {
        let command_tx = self.command_sender()?;
        let (reply, _ignored) = oneshot::channel();
        command_tx
            .send(CommandEnvelope::urgent(FabricCommand::AbortLane {
                lane_id,
                reply,
            }))
            .map_err(|_| fabric_stopped())
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

    fn command_sender(&self) -> Result<mpsc::UnboundedSender<CommandEnvelope>> {
        self.inner
            .command_tx
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(fabric_stopped)
    }

    async fn submit_operation(
        &self,
        lane_id: u16,
        sequence: Option<u64>,
        make_command: impl FnOnce(OperationCompletionTx, oneshot::Sender<Result<()>>) -> FabricCommand,
    ) -> Result<UrmaOpHandle> {
        let (completion_tx, completion_rx) = oneshot::channel();
        self.submit(|reply| make_command(completion_tx, reply))
            .await?;
        let command_tx = self.command_sender()?;
        Ok(UrmaOpHandle {
            sequence,
            completion: completion_rx,
            abort: Some((command_tx, lane_id)),
        })
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

enum FabricCommand {
    CreateLane {
        config: UrmaLaneConfig,
        reply: oneshot::Sender<Result<(u16, Vec<u8>)>>,
    },
    BindLane {
        lane_id: u16,
        descriptor: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    PostReceive {
        lane_id: u16,
        sequence: Option<u64>,
        completion: OperationCompletionTx,
        reply: oneshot::Sender<Result<()>>,
    },
    GrantSendCredit {
        lane_id: u16,
        count: u32,
        reply: oneshot::Sender<Result<()>>,
    },
    Send {
        lane_id: u16,
        bytes: Vec<u8>,
        sequence: Option<u64>,
        completion: OperationCompletionTx,
        reply: oneshot::Sender<Result<()>>,
    },
    CloseLane {
        lane_id: u16,
        reply: oneshot::Sender<Result<()>>,
    },
    AbortLane {
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
    startup_tx: std_mpsc::SyncSender<Result<(u32, u64)>>,
) {
    let runtime = match UrmaRuntime::start(config) {
        Ok(runtime) => runtime,
        Err(error) => {
            readiness_tx.send_replace(FabricReadiness::Failed(error.to_string()));
            let _ = startup_tx.send(Err(error));
            return;
        }
    };

    let probe = (runtime.transport_type(), runtime.max_message_size());
    readiness_tx.send_replace(FabricReadiness::Ready);
    if startup_tx.send(Ok(probe)).is_err() {
        let _ = shutdown_runtime(runtime, &readiness_tx);
        return;
    }

    let mut runtime = runtime;
    let mut poisoned = None;
    loop {
        if runtime.outstanding() == 0 {
            match command_rx.blocking_recv() {
                Some(envelope) => {
                    if let OwnerControl::Shutdown(reply) =
                        handle_command(envelope.command, &mut runtime, poisoned.as_deref())
                    {
                        finish_owner(runtime, &readiness_tx, reply);
                        return;
                    }
                }
                None => {
                    finish_owner(runtime, &readiness_tx, None);
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
                        finish_owner(runtime, &readiness_tx, reply);
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    finish_owner(runtime, &readiness_tx, None);
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
        FabricCommand::CreateLane { config, reply } => {
            let result = reject_if_poisoned(poisoned).and_then(|()| {
                let (lane_id, descriptor) = runtime.create_lane(config.into())?;
                match descriptor.serialize() {
                    Ok(descriptor) => Ok((lane_id, descriptor)),
                    Err(error) => {
                        let _ = runtime.close_lane(lane_id);
                        Err(error)
                    }
                }
            });
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::BindLane {
            lane_id,
            descriptor,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned).and_then(|()| {
                let descriptor = JettyDescriptor::deserialize(&descriptor)?;
                runtime.bind_lane(lane_id, &descriptor)
            });
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::PostReceive {
            lane_id,
            sequence,
            completion,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.post_receive(lane_id, sequence, completion));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::GrantSendCredit {
            lane_id,
            count,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.grant_send_credit(lane_id, count));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::Send {
            lane_id,
            bytes,
            sequence,
            completion,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.send(lane_id, &bytes, sequence, completion));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::CloseLane { lane_id, reply } => {
            let _ = reply.send(runtime.close_lane(lane_id));
            OwnerControl::Continue
        }
        FabricCommand::AbortLane { lane_id, reply } => {
            let _ = reply.send(runtime.abort_lane(lane_id));
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

async fn abort_lane(
    command_tx: mpsc::UnboundedSender<CommandEnvelope>,
    lane_id: u16,
) -> Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    command_tx
        .send(CommandEnvelope::urgent(FabricCommand::AbortLane {
            lane_id,
            reply: reply_tx,
        }))
        .map_err(|_| fabric_stopped())?;
    reply_rx.await.map_err(|_| fabric_stopped())?
}

impl From<LaneCompletion> for FabricCompletion {
    fn from(completion: LaneCompletion) -> Self {
        match completion {
            LaneCompletion::Sent { lane_id, sequence } => Self::Sent { lane_id, sequence },
            LaneCompletion::Received {
                lane_id,
                sequence,
                chunk,
            } => Self::Received {
                lane_id,
                sequence,
                bytes: chunk.into_bytes(),
            },
        }
    }
}

fn finish_owner(
    runtime: UrmaRuntime,
    readiness_tx: &watch::Sender<FabricReadiness>,
    reply: Option<oneshot::Sender<Result<()>>>,
) {
    let result = shutdown_runtime(runtime, readiness_tx);
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
        let result = UrmaFabric::start_with_capacity(RuntimeConfig::new("urma0", 0), 0);
        assert!(matches!(result, Err(Error::InvalidConfiguration(_))));
    }

    #[test]
    fn shared_fabric_requires_identical_runtime_configuration() {
        let active = RuntimeConfig::new("urma0", 2);
        assert!(validate_shared_config(&active, &active).is_ok());
        assert!(validate_shared_config(&active, &RuntimeConfig::new("urma1", 2)).is_err());
        assert!(validate_shared_config(&active, &RuntimeConfig::new("urma0", 3)).is_err());
    }

    #[test]
    fn handle_is_safe_to_move_between_tokio_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UrmaFabricHandle>();
        assert_send_sync::<UrmaOpHandle>();
    }

    #[tokio::test]
    async fn operation_handle_receives_its_own_completion() {
        let (tx, rx) = oneshot::channel();
        let handle = UrmaOpHandle {
            sequence: Some(9),
            completion: rx,
            abort: None,
        };
        tx.send(Ok(LaneCompletion::Sent {
            lane_id: 7,
            sequence: Some(9),
        }))
        .unwrap();

        assert_eq!(
            handle.wait().await.unwrap(),
            FabricCompletion::Sent {
                lane_id: 7,
                sequence: Some(9)
            }
        );
    }

    #[tokio::test]
    async fn operation_timeout_abandons_only_the_waiter() {
        let (_tx, rx) = oneshot::channel();
        let handle = UrmaOpHandle {
            sequence: Some(11),
            completion: rx,
            abort: None,
        };

        assert_eq!(
            handle.wait_timeout(Duration::ZERO).await,
            Err(Error::OperationTimeout { sequence: Some(11) })
        );
    }

    #[test]
    fn lane_config_maps_to_native_jetty_config() {
        let config = UrmaLaneConfig {
            send_depth: 1,
            recv_depth: 2,
            max_send_sge: 3,
            max_recv_sge: 4,
            token: 5,
        };
        let native: JettyConfig = config.into();
        assert_eq!(native.send_depth, 1);
        assert_eq!(native.recv_depth, 2);
        assert_eq!(native.max_send_sge, 3);
        assert_eq!(native.max_recv_sge, 4);
        assert_eq!(native.token, 5);
    }

    #[test]
    fn sent_completion_crosses_the_thread_boundary_without_native_state() {
        let completion = FabricCompletion::from(LaneCompletion::Sent {
            lane_id: 7,
            sequence: Some(9),
        });
        assert_eq!(
            completion,
            FabricCompletion::Sent {
                lane_id: 7,
                sequence: Some(9)
            }
        );
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
