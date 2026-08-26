//! Thread-owned URMA fabric boundary for Dragonfly storage.
//!
//! The migrated native wrappers are deliberately `!Send` and `!Sync`. The
//! fabric creates, uses, and destroys [`UrmaRuntime`] on one OS thread. Async
//! Dragonfly code communicates with that thread through bounded commands and
//! never receives a raw UMDK handle.

use super::{
    completion::LaneCompletion,
    lane::{JettyConfig, JettyDescriptor},
    runtime::{RuntimeConfig, UrmaRuntime},
    Error, Result,
};
use std::thread::{self, JoinHandle};
use std::{
    sync::{mpsc as std_mpsc, Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};

/// Default number of commands that may wait for the owner thread.
const DEFAULT_COMMAND_CAPACITY: usize = 16;

/// Number of completion events retained until the async consumer catches up.
const DEFAULT_COMPLETION_CAPACITY: usize = 128;

/// Bounds command latency while completions are actively being polled.
const MAX_COMMANDS_PER_TICK: usize = 16;

/// Pure polling is required because Phase A deliberately has no JFCE. Keep the
/// idle interval short without allowing an outstanding WR to consume one CPU.
const PROGRESS_IDLE_INTERVAL: Duration = Duration::from_micros(100);

/// Dragonfly-facing Jetty sizing. Native tokens and handles remain private to
/// the owner thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UrmaLaneConfig {
    pub(crate) send_depth: u32,
    pub(crate) recv_depth: u32,
    pub(crate) max_send_sge: u32,
    pub(crate) max_recv_sge: u32,
    pub(crate) token: u32,
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
pub(crate) struct UrmaFabric;

impl UrmaFabric {
    /// Starts the owner thread and waits until native initialization either
    /// succeeds or rolls back. A successful return therefore means the runtime
    /// is ready, not merely that a thread was spawned.
    pub(crate) fn start(config: RuntimeConfig) -> Result<UrmaFabricHandle> {
        Self::start_with_capacity(config, DEFAULT_COMMAND_CAPACITY)
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

        let (command_tx, command_rx) = mpsc::channel(command_capacity);
        let (completion_tx, completion_rx) = mpsc::channel(DEFAULT_COMPLETION_CAPACITY);
        let (readiness_tx, readiness_rx) = watch::channel(FabricReadiness::Starting);
        let (startup_tx, startup_rx) = std_mpsc::sync_channel(1);

        let join = thread::Builder::new()
            .name("dragonfly-urma-fabric".to_string())
            .spawn(move || run_owner(config, command_rx, completion_tx, readiness_tx, startup_tx))
            .map_err(|error| {
                Error::InvalidConfiguration(format!("failed to spawn URMA owner thread: {error}"))
            })?;

        match startup_rx.recv() {
            Ok(Ok(())) => Ok(UrmaFabricHandle {
                inner: Arc::new(FabricInner {
                    command_tx: Mutex::new(Some(command_tx)),
                    completion_rx: AsyncMutex::new(completion_rx),
                    readiness: readiness_rx,
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
pub(crate) struct UrmaFabricHandle {
    inner: Arc<FabricInner>,
}

impl UrmaFabricHandle {
    /// Returns a receiver for readiness and terminal-state changes.
    pub(crate) fn subscribe_readiness(&self) -> watch::Receiver<FabricReadiness> {
        self.inner.readiness.clone()
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

    pub(crate) async fn post_receive(&self, lane_id: u16, sequence: Option<u64>) -> Result<()> {
        self.submit(|reply| FabricCommand::PostReceive {
            lane_id,
            sequence,
            reply,
        })
        .await
    }

    pub(crate) async fn send(
        &self,
        lane_id: u16,
        bytes: Vec<u8>,
        sequence: Option<u64>,
    ) -> Result<()> {
        self.submit(|reply| FabricCommand::Send {
            lane_id,
            bytes,
            sequence,
            reply,
        })
        .await
    }

    /// Receives the next successfully routed CQE. Only one logical consumer
    /// should call this method; concurrent clones serialize on the receiver.
    pub(crate) async fn recv_completion(&self) -> Option<FabricCompletion> {
        self.inner.completion_rx.lock().await.recv().await
    }

    pub(crate) async fn close_lane(&self, lane_id: u16) -> Result<()> {
        self.submit(|reply| FabricCommand::CloseLane { lane_id, reply })
            .await
    }

    async fn submit<T>(
        &self,
        make_command: impl FnOnce(oneshot::Sender<Result<T>>) -> FabricCommand,
    ) -> Result<T> {
        let command_tx = self
            .inner
            .command_tx
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(fabric_stopped)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        command_tx
            .send(make_command(reply_tx))
            .await
            .map_err(|_| fabric_stopped())?;
        reply_rx.await.map_err(|_| fabric_stopped())?
    }

    /// Shuts the native resource tree down and joins the owner thread.
    /// Concurrent callers serialize; later calls observe the completed state.
    pub(crate) async fn shutdown(&self) -> Result<()> {
        let _shutdown = self.inner.shutdown.lock().await;
        let command_tx = self.inner.command_tx.lock().unwrap().take();

        let shutdown_result = if let Some(command_tx) = command_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            match command_tx
                .send(FabricCommand::Shutdown {
                    reply: Some(reply_tx),
                })
                .await
            {
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
    command_tx: Mutex<Option<mpsc::Sender<FabricCommand>>>,
    completion_rx: AsyncMutex<mpsc::Receiver<FabricCompletion>>,
    readiness: watch::Receiver<FabricReadiness>,
    shutdown: AsyncMutex<()>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for FabricInner {
    fn drop(&mut self) {
        if let Some(command_tx) = self.command_tx.get_mut().unwrap().take() {
            let _ = command_tx.try_send(FabricCommand::Shutdown { reply: None });
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
        reply: oneshot::Sender<Result<()>>,
    },
    Send {
        lane_id: u16,
        bytes: Vec<u8>,
        sequence: Option<u64>,
        reply: oneshot::Sender<Result<()>>,
    },
    CloseLane {
        lane_id: u16,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        reply: Option<oneshot::Sender<Result<()>>>,
    },
}

fn run_owner(
    config: RuntimeConfig,
    mut command_rx: mpsc::Receiver<FabricCommand>,
    completion_tx: mpsc::Sender<FabricCompletion>,
    readiness_tx: watch::Sender<FabricReadiness>,
    startup_tx: std_mpsc::SyncSender<Result<()>>,
) {
    let runtime = match UrmaRuntime::start(config) {
        Ok(runtime) => runtime,
        Err(error) => {
            readiness_tx.send_replace(FabricReadiness::Failed(error.to_string()));
            let _ = startup_tx.send(Err(error));
            return;
        }
    };

    readiness_tx.send_replace(FabricReadiness::Ready);
    if startup_tx.send(Ok(())).is_err() {
        let _ = shutdown_runtime(runtime, &readiness_tx);
        return;
    }

    let mut runtime = runtime;
    let mut poisoned = None;
    loop {
        if runtime.outstanding() == 0 {
            match command_rx.blocking_recv() {
                Some(command) => {
                    if let OwnerControl::Shutdown(reply) =
                        handle_command(command, &mut runtime, poisoned.as_deref())
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
                Ok(command) => {
                    if let OwnerControl::Shutdown(reply) =
                        handle_command(command, &mut runtime, poisoned.as_deref())
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
            Ok(completions) => {
                let idle = completions.is_empty();
                for completion in completions {
                    if let Err(error) = completion_tx.try_send(completion.into()) {
                        poison_once(
                            &mut poisoned,
                            format!("URMA completion consumer is unavailable: {error}"),
                            &readiness_tx,
                        );
                    }
                }
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
            reply,
        } => {
            let result =
                reject_if_poisoned(poisoned).and_then(|()| runtime.post_receive(lane_id, sequence));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::Send {
            lane_id,
            bytes,
            sequence,
            reply,
        } => {
            let result =
                reject_if_poisoned(poisoned).and_then(|()| runtime.send(lane_id, &bytes, sequence));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::CloseLane { lane_id, reply } => {
            let _ = reply.send(runtime.close_lane(lane_id));
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
    fn handle_is_safe_to_move_between_tokio_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UrmaFabricHandle>();
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
