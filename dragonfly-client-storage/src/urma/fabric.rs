//! Thread-owned URMA fabric boundary for Dragonfly storage.
//!
//! The migrated native wrappers are deliberately `!Send` and `!Sync`. The
//! fabric creates, uses, and destroys [`UrmaRuntime`] on one OS thread. Async
//! Dragonfly code communicates with that thread through bounded business
//! admission plus a non-dropping lifecycle path, and never receives a raw
//! UMDK handle.

use super::{
    buffer::{LeaseRecycle, LeaseRecycleNotifier, RegisteredRxWindowLease, TxWindowLease},
    completion::{
        RegisteredRxCompletion, RegisteredRxCompletionTx, RegisteredTxCompletion,
        RegisteredTxCompletionTx,
    },
    credit::{PeerCreditAdmission, PeerCreditPermit},
    lane::{JettyDescriptor, TransportMode},
    runtime::{RuntimeConfig, UrmaRuntime},
    Error, Result,
};
use std::thread::{self, JoinHandle};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
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

/// Pure polling is required because Phase A deliberately has no JFCE. Keep the
/// idle interval short without allowing an outstanding WR to consume one CPU.
const PROGRESS_IDLE_INTERVAL: Duration = Duration::from_micros(100);

/// Native device discovery should normally finish immediately. Bound the
/// synchronous hand-off so a wedged provider cannot pin an async caller and
/// the process-wide Fabric registry forever.
const FABRIC_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

type StartupProbe = (u32, u32, u64, u32, u32);
type StartupResult = Result<StartupProbe>;

#[derive(Clone, Default)]
struct RequiredRxWaiters(Arc<AtomicUsize>);

impl RequiredRxWaiters {
    fn enter(&self) -> RequiredRxWaiter {
        self.0.fetch_add(1, Ordering::AcqRel);
        RequiredRxWaiter(Arc::clone(&self.0))
    }

    fn has_waiters(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }
}

struct RequiredRxWaiter(Arc<AtomicUsize>);

impl Drop for RequiredRxWaiter {
    fn drop(&mut self) {
        let previous = self.0.fetch_sub(1, Ordering::AcqRel);
        debug_assert_ne!(previous, 0, "required RX waiter count underflow");
    }
}

fn try_acquire_optional_rx_permit(
    required_waiters: &RequiredRxWaiters,
    admission: &PeerCreditAdmission,
    peer_id: u16,
    requested: u32,
) -> Result<PeerCreditPermit> {
    if required_waiters.has_waiters() {
        return Err(Error::BufferUnavailable {
            kind: "shared RX optional",
            requested: requested as usize,
            available: 0,
        });
    }
    let permit = admission.try_acquire(peer_id, requested)?;
    // Close the check/acquire race as far as the async facade can: if a
    // required first window appeared while the non-blocking acquire ran,
    // immediately return the borrowed surplus. The later Fabric post gate
    // performs the same check before submitting native work.
    if required_waiters.has_waiters() {
        drop(permit);
        return Err(Error::BufferUnavailable {
            kind: "shared RX optional",
            requested: requested as usize,
            available: 0,
        });
    }
    Ok(permit)
}

#[derive(Default)]
struct SharedDepthAdmission {
    endpoint: Option<(u32, Arc<Semaphore>)>,
}

impl SharedDepthAdmission {
    fn permits(&mut self, depth: u32, direction: &'static str) -> Result<Arc<Semaphore>> {
        if depth == 0 {
            return Err(Error::InvalidConfiguration(format!(
                "shared RM {direction} depth must be non-zero"
            )));
        }
        if let Some((active_depth, permits)) = &self.endpoint {
            if *active_depth != depth {
                return Err(Error::InvalidConfiguration(format!(
                    "shared RM {direction} admission depth differs: active={active_depth} requested={depth}"
                )));
            }
            return Ok(Arc::clone(permits));
        }
        let permits = Arc::new(Semaphore::new(depth as usize));
        self.endpoint = Some((depth, Arc::clone(&permits)));
        Ok(permits)
    }
}

fn window_chunks_for_slots(slots: usize, pipeline_depth: u32) -> u32 {
    let depth = usize::try_from(pipeline_depth).unwrap_or(usize::MAX).max(1);
    u32::try_from((slots / depth).max(1)).unwrap_or(u32::MAX)
}

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

/// Dragonfly-facing PeerTarget batching and Piece pipeline policy. Native
/// endpoint sizing, tokens, and handles remain private to the owner thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerTargetConfig {
    pub post_list_size: u32,
    pub pipeline_depth: u32,
    pub guaranteed_rx_credits: u32,
}

impl Default for PeerTargetConfig {
    fn default() -> Self {
        Self {
            post_list_size: 1,
            pipeline_depth: 2,
            guaranteed_rx_credits: 0,
        }
    }
}

impl PeerTargetConfig {
    fn validate(self) -> Result<()> {
        if self.post_list_size == 0 || self.post_list_size > crate::urma::ffi::MAX_POST_LIST {
            return Err(Error::InvalidConfiguration(format!(
                "RM PeerTarget post_list_size={} is outside 1..={}",
                self.post_list_size,
                crate::urma::ffi::MAX_POST_LIST
            )));
        }
        if !(1..=2).contains(&self.pipeline_depth) {
            return Err(Error::InvalidConfiguration(format!(
                "RM PeerTarget pipeline_depth={} is outside 1..=2",
                self.pipeline_depth
            )));
        }
        Ok(())
    }
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
        Self::get_or_start_config(RuntimeConfig::new(device_name, eid_index))
    }

    pub fn get_or_start_with_budget(
        device_name: impl Into<String>,
        eid_index: u32,
        max_registered_bytes: u64,
        tx_registered_bytes: u64,
    ) -> Result<UrmaFabricHandle> {
        let config = RuntimeConfig::new(device_name, eid_index)
            .with_registered_budget(max_registered_bytes, tx_registered_bytes)?;
        Self::get_or_start_config(config)
    }

    /// Returns the process Fabric for the requested RM transport-path type.
    /// RTP remains the default of the older constructors.
    pub fn get_or_start_with_budget_and_tp_type(
        device_name: impl Into<String>,
        eid_index: u32,
        max_registered_bytes: u64,
        tx_registered_bytes: u64,
        tp_type: crate::urma::TpType,
    ) -> Result<UrmaFabricHandle> {
        let config = RuntimeConfig::new(device_name, eid_index)
            .with_registered_budget(max_registered_bytes, tx_registered_bytes)?
            .with_tp_type(tp_type);
        Self::get_or_start_config(config)
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
        let recycle_command_tx = command_tx.clone();
        let join = thread::Builder::new()
            .name("dragonfly-urma-fabric".to_string())
            .spawn(move || {
                run_owner(
                    config,
                    command_rx,
                    recycle_command_tx,
                    readiness_tx,
                    startup_tx,
                )
            })
            .map_err(|error| {
                Error::InvalidConfiguration(format!("failed to spawn URMA owner thread: {error}"))
            })?;

        match startup_rx.recv_timeout(FABRIC_STARTUP_TIMEOUT) {
            Ok(Ok((
                transport_type,
                transport_modes,
                max_message_size,
                max_jfr_depth,
                max_jfs_depth,
            ))) => {
                let shared_rx_depth = runtime_config.recv_jfc_depth.min(max_jfr_depth).min(
                    u32::try_from(runtime_config.buffer_pool.rx_slot_count).unwrap_or(u32::MAX),
                );
                Ok(UrmaFabricHandle {
                    inner: Arc::new(FabricInner {
                        command_tx: Mutex::new(Some(command_tx)),
                        command_slots,
                        readiness: readiness_rx,
                        runtime_config,
                        transport_type,
                        transport_modes,
                        max_message_size,
                        max_jfr_depth,
                        max_jfs_depth,
                        required_rx_waiters: RequiredRxWaiters::default(),
                        shared_rx_admission: PeerCreditAdmission::new(shared_rx_depth)?,
                        shared_tx_admission: Mutex::new(SharedDepthAdmission::default()),
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

pub(crate) struct UrmaRegisteredRxOpHandle {
    sequence: u64,
    completion: oneshot::Receiver<Result<RegisteredRxCompletion>>,
    abort: Option<(mpsc::UnboundedSender<CommandEnvelope>, u16)>,
}

pub(crate) struct UrmaRegisteredTxOpHandle {
    sequence: u64,
    completion: oneshot::Receiver<Result<RegisteredTxCompletion>>,
    abort: Option<(mpsc::UnboundedSender<CommandEnvelope>, u16)>,
}

impl UrmaRegisteredTxOpHandle {
    pub(crate) async fn wait_timeout(self, timeout: Duration) -> Result<RegisteredTxCompletion> {
        match tokio::time::timeout(timeout, self.completion).await {
            Ok(result) => result.map_err(|_| fabric_stopped())?,
            Err(_) => {
                if let Some((command_tx, lane_id)) = self.abort {
                    abort_lane(command_tx, lane_id).await?;
                }
                Err(Error::OperationTimeout {
                    sequence: Some(self.sequence),
                })
            }
        }
    }
}

impl UrmaRegisteredRxOpHandle {
    pub(crate) async fn wait_timeout(self, timeout: Duration) -> Result<RegisteredRxCompletion> {
        match tokio::time::timeout(timeout, self.completion).await {
            Ok(result) => result.map_err(|_| fabric_stopped())?,
            Err(_) => {
                if let Some((command_tx, lane_id)) = self.abort {
                    abort_lane(command_tx, lane_id).await?;
                }
                Err(Error::OperationTimeout {
                    sequence: Some(self.sequence),
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

    pub fn tp_type(&self) -> crate::urma::TpType {
        self.inner.runtime_config.tp_type
    }

    /// Reports whether the provider advertised the selected transport mode.
    pub fn supports_rm(&self) -> bool {
        self.inner.transport_modes & TransportMode::Rm as u32 != 0
    }

    /// max_message_size returns the effective single-message payload limit: the
    /// smaller of the device capability and one registered buffer slot.
    pub fn max_message_size(&self) -> u64 {
        self.inner.max_message_size
    }

    pub fn registered_bytes(&self) -> u64 {
        u64::try_from(
            self.inner
                .runtime_config
                .buffer_pool
                .total_len()
                .unwrap_or_default(),
        )
        .unwrap_or(u64::MAX)
    }

    pub fn tx_registered_bytes(&self) -> u64 {
        let pool = &self.inner.runtime_config.buffer_pool;
        u64::try_from(pool.slot_size.saturating_mul(pool.tx_slot_count)).unwrap_or(u64::MAX)
    }

    pub fn rx_registered_bytes(&self) -> u64 {
        let pool = &self.inner.runtime_config.buffer_pool;
        u64::try_from(pool.slot_size.saturating_mul(pool.rx_slot_count)).unwrap_or(u64::MAX)
    }

    /// Maximum logical SEND window after dividing the TX reserve across the
    /// configured per-Piece pipeline. A one-slot pool still supports depth one.
    pub(crate) fn max_tx_window_chunks(&self, pipeline_depth: u32) -> u32 {
        let slots = self.inner.runtime_config.buffer_pool.tx_slot_count;
        window_chunks_for_slots(slots, pipeline_depth)
    }

    /// Maximum number of native RECV WRs the process-wide shared JFR can keep
    /// outstanding, bounded by provider capability and registered RX slots.
    pub(crate) fn max_native_receive_depth(&self) -> u32 {
        self.inner
            .runtime_config
            .recv_jfc_depth
            .min(self.inner.max_jfr_depth)
            .min(
                u32::try_from(self.inner.runtime_config.buffer_pool.rx_slot_count)
                    .unwrap_or(u32::MAX),
            )
    }

    /// Maximum number of native SEND WRs the process-wide shared JFS can keep
    /// outstanding, bounded by provider capability and registered TX slots.
    pub(crate) fn max_native_send_depth(&self) -> u32 {
        self.inner
            .runtime_config
            .send_jfc_depth
            .min(self.inner.max_jfs_depth)
            .min(
                u32::try_from(self.inner.runtime_config.buffer_pool.tx_slot_count)
                    .unwrap_or(u32::MAX),
            )
    }

    /// is_failed reports whether the owner thread has entered a failed state
    /// and the shared facade should be retired and recreated.
    pub fn is_failed(&self) -> bool {
        matches!(*self.inner.readiness.borrow(), FabricReadiness::Failed(_))
    }

    /// Creates a local lane and returns its stable id plus the serialized local
    /// Jetty descriptor for the existing Dragonfly control plane.
    pub(crate) async fn create_lane(&self, config: PeerTargetConfig) -> Result<(u16, Vec<u8>)> {
        config.validate()?;
        self.submit(|reply| FabricCommand::CreateLane { config, reply })
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

    pub(crate) async fn post_receive_window_registered(
        &self,
        lane_id: u16,
        sequences: Vec<u64>,
    ) -> Result<Vec<UrmaRegisteredRxOpHandle>> {
        self.post_receive_window_registered_with_admission(lane_id, sequences, false)
            .await
    }

    pub(crate) fn required_rx_waiter(&self) -> impl Drop {
        self.inner.required_rx_waiters.enter()
    }

    pub(crate) fn register_rx_peer(&self, peer_id: u16, guaranteed_credits: u32) -> Result<()> {
        self.inner
            .shared_rx_admission
            .register_peer(peer_id, guaranteed_credits)
    }

    pub(crate) fn retire_rx_peer(&self, peer_id: u16) -> Result<()> {
        self.inner.shared_rx_admission.retire_peer(peer_id)
    }

    pub(crate) async fn acquire_required_rx_permit(
        &self,
        peer_id: u16,
        requested: u32,
    ) -> Result<PeerCreditPermit> {
        self.inner
            .shared_rx_admission
            .acquire(peer_id, requested)
            .await
    }

    pub(crate) fn shared_rx_available(&self) -> usize {
        self.inner.shared_rx_admission.available_permits()
    }

    /// Returns the one process-wide TX admission semaphore. PeerTargets share
    /// the same RM JFS and registered TX arena, so per-peer semaphores would
    /// multiply logical capacity beyond the native endpoint depth.
    pub(crate) fn shared_tx_permits(&self, depth: u32) -> Result<Arc<Semaphore>> {
        self.inner
            .shared_tx_admission
            .lock()
            .unwrap()
            .permits(depth, "send")
    }

    pub(crate) fn try_acquire_optional_rx_permit(
        &self,
        peer_id: u16,
        requested: u32,
    ) -> Result<PeerCreditPermit> {
        try_acquire_optional_rx_permit(
            &self.inner.required_rx_waiters,
            &self.inner.shared_rx_admission,
            peer_id,
            requested,
        )
    }

    pub(crate) async fn try_post_receive_window_registered(
        &self,
        lane_id: u16,
        sequences: Vec<u64>,
    ) -> Result<Vec<UrmaRegisteredRxOpHandle>> {
        self.post_receive_window_registered_with_admission(lane_id, sequences, true)
            .await
    }

    async fn post_receive_window_registered_with_admission(
        &self,
        lane_id: u16,
        sequences: Vec<u64>,
        try_admission: bool,
    ) -> Result<Vec<UrmaRegisteredRxOpHandle>> {
        if sequences.is_empty() {
            return Err(Error::InvalidConfiguration(
                "registered RX window cannot be empty".into(),
            ));
        }
        if try_admission && self.inner.required_rx_waiters.has_waiters() {
            return Err(Error::BufferUnavailable {
                kind: "RX",
                requested: sequences.len(),
                available: 0,
            });
        }
        let command_tx = self.command_sender()?;
        let mut completion_txs: Vec<RegisteredRxCompletionTx> = Vec::with_capacity(sequences.len());
        let mut handles = Vec::with_capacity(sequences.len());
        for &sequence in &sequences {
            let (completion_tx, completion_rx) = oneshot::channel();
            completion_txs.push(completion_tx);
            handles.push(UrmaRegisteredRxOpHandle {
                sequence,
                completion: completion_rx,
                abort: Some((command_tx.clone(), lane_id)),
            });
        }
        if try_admission {
            self.try_submit(|reply| FabricCommand::PostReceiveWindowRegistered {
                lane_id,
                sequences,
                completion_txs,
                reply,
            })
            .await?;
        } else {
            self.submit(|reply| FabricCommand::PostReceiveWindowRegistered {
                lane_id,
                sequences,
                completion_txs,
                reply,
            })
            .await?;
        }
        Ok(handles)
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

    #[allow(dead_code)] // B1 ownership API, consumed by B4.
    pub(crate) async fn acquire_tx_window(&self, length: usize) -> Result<TxWindowLease> {
        self.submit(|reply| FabricCommand::AcquireTxWindow { length, reply })
            .await
    }

    pub(crate) async fn acquire_tx_window_chunks(
        &self,
        chunk_lengths: Vec<usize>,
    ) -> Result<TxWindowLease> {
        self.submit(|reply| FabricCommand::AcquireTxWindowChunks {
            chunk_lengths,
            reply,
        })
        .await
    }

    #[allow(dead_code)] // B1 ownership API, consumed by B4.
    pub(crate) async fn recycle_tx_window(&self, lease: TxWindowLease) -> Result<usize> {
        self.submit_urgent(|reply| FabricCommand::RecycleTxWindow { lease, reply })
            .await
    }

    /// Non-blocking admission variant used while a Piece already owns its
    /// first TX window. This prevents a full command queue from turning an
    /// optional overlap window into a circular resource wait.
    pub(crate) async fn try_acquire_tx_window_chunks(
        &self,
        chunk_lengths: Vec<usize>,
    ) -> Result<TxWindowLease> {
        self.try_submit(|reply| FabricCommand::AcquireTxWindowChunks {
            chunk_lengths,
            reply,
        })
        .await
    }

    #[allow(dead_code)] // B1 ownership API, consumed by B2/B3.
    pub(crate) async fn recycle_rx_window(&self, lease: RegisteredRxWindowLease) -> Result<usize> {
        self.submit_urgent(|reply| FabricCommand::RecycleRxWindow { lease, reply })
            .await
    }

    pub(crate) async fn send_registered_window(
        &self,
        lane_id: u16,
        lease: TxWindowLease,
        sequences: Vec<u64>,
    ) -> Result<UrmaRegisteredTxOpHandle> {
        let sequence = sequences.first().copied().ok_or_else(|| {
            Error::InvalidConfiguration("registered TX sequence window is empty".into())
        })?;
        let command_tx = self.command_sender()?;
        let (completion_tx, completion_rx) = oneshot::channel();
        self.submit(|reply| FabricCommand::SendRegisteredWindow {
            lane_id,
            lease,
            sequences,
            completion: completion_tx,
            reply,
        })
        .await?;
        Ok(UrmaRegisteredTxOpHandle {
            sequence,
            completion: completion_rx,
            abort: Some((command_tx, lane_id)),
        })
    }

    /// Starts provider-backed retirement. The owner keeps the native lane
    /// until every WR and the shared-JFC flush sentinel have been consumed.
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

    async fn try_submit<T>(
        &self,
        make_command: impl FnOnce(oneshot::Sender<Result<T>>) -> FabricCommand,
    ) -> Result<T> {
        let command_tx = self.command_sender()?;
        let available = self.inner.command_slots.available_permits();
        let permit = self
            .inner
            .command_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::BufferUnavailable {
                kind: "fabric command",
                requested: 1,
                available,
            })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        command_tx
            .send(CommandEnvelope::admitted(make_command(reply_tx), permit))
            .map_err(|_| fabric_stopped())?;
        reply_rx.await.map_err(|_| fabric_stopped())?
    }

    #[allow(dead_code)] // Called by the B1 lease APIs once B2/B4 select them.
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
    max_jfr_depth: u32,
    max_jfs_depth: u32,
    required_rx_waiters: RequiredRxWaiters,
    shared_rx_admission: PeerCreditAdmission,
    shared_tx_admission: Mutex<SharedDepthAdmission>,
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
        config: PeerTargetConfig,
        reply: oneshot::Sender<Result<(u16, Vec<u8>)>>,
    },
    ConnectLane {
        lane_id: u16,
        descriptor: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    PostReceiveWindowRegistered {
        lane_id: u16,
        sequences: Vec<u64>,
        completion_txs: Vec<RegisteredRxCompletionTx>,
        reply: oneshot::Sender<Result<()>>,
    },
    GrantSendCredit {
        lane_id: u16,
        count: u32,
        reply: oneshot::Sender<Result<()>>,
    },
    #[allow(dead_code)] // B1 foundation, selected by B4.
    AcquireTxWindow {
        length: usize,
        reply: oneshot::Sender<Result<TxWindowLease>>,
    },
    AcquireTxWindowChunks {
        chunk_lengths: Vec<usize>,
        reply: oneshot::Sender<Result<TxWindowLease>>,
    },
    #[allow(dead_code)] // B1 foundation, selected by B4.
    RecycleTxWindow {
        lease: TxWindowLease,
        reply: oneshot::Sender<Result<usize>>,
    },
    #[allow(dead_code)] // B1 foundation, selected by B2/B3.
    RecycleRxWindow {
        lease: RegisteredRxWindowLease,
        reply: oneshot::Sender<Result<usize>>,
    },
    SendRegisteredWindow {
        lane_id: u16,
        lease: TxWindowLease,
        sequences: Vec<u64>,
        completion: RegisteredTxCompletionTx,
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
    RecycleLease {
        recycle: LeaseRecycle,
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
    recycle_command_tx: mpsc::UnboundedSender<CommandEnvelope>,
    readiness_tx: watch::Sender<FabricReadiness>,
    startup_tx: std_mpsc::SyncSender<StartupResult>,
) {
    let recycle_notifier: LeaseRecycleNotifier = Arc::new(move |recycle| {
        let _ = recycle_command_tx.send(CommandEnvelope::urgent(FabricCommand::RecycleLease {
            recycle,
        }));
    });
    let runtime = match UrmaRuntime::start(config, recycle_notifier) {
        Ok(runtime) => runtime,
        Err(error) => {
            readiness_tx.send_replace(FabricReadiness::Failed(error.to_string()));
            let _ = startup_tx.send(Err(error));
            return;
        }
    };

    let probe = (
        runtime.transport_type(),
        runtime.transport_modes(),
        runtime.max_message_size(),
        runtime.max_jfr_depth(),
        runtime.max_jfs_depth(),
    );
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
                let (lane_id, descriptor) = runtime.create_peer_target(config.post_list_size)?;
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
        FabricCommand::PostReceiveWindowRegistered {
            lane_id,
            sequences,
            completion_txs,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned).and_then(|()| {
                runtime.post_receive_window_registered(lane_id, sequences, completion_txs)
            });
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
        FabricCommand::AcquireTxWindow { length, reply } => {
            let result =
                reject_if_poisoned(poisoned).and_then(|()| runtime.acquire_tx_window(length));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::AcquireTxWindowChunks {
            chunk_lengths,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned)
                .and_then(|()| runtime.acquire_tx_window_chunks(&chunk_lengths));
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::RecycleTxWindow { lease, reply } => {
            let _ = reply.send(runtime.recycle_tx_window(lease));
            OwnerControl::Continue
        }
        FabricCommand::RecycleRxWindow { lease, reply } => {
            let _ = reply.send(runtime.recycle_rx_window(lease));
            OwnerControl::Continue
        }
        FabricCommand::SendRegisteredWindow {
            lane_id,
            lease,
            sequences,
            completion,
            reply,
        } => {
            let result = reject_if_poisoned(poisoned).and_then(|()| {
                runtime.send_registered_window(lane_id, lease, sequences, completion)
            });
            let _ = reply.send(result);
            OwnerControl::Continue
        }
        FabricCommand::CloseLane { lane_id, reply } => {
            let _ = reply.send(runtime.close_peer_target(lane_id));
            OwnerControl::Continue
        }
        FabricCommand::AbortLane { lane_id, reply } => {
            let _ = reply.send(runtime.abort_peer_target(lane_id));
            OwnerControl::Continue
        }
        FabricCommand::RecycleLease { recycle } => {
            if let Err(error) = runtime.recycle_dropped_lease(recycle) {
                tracing::error!(%error, "failed to recycle dropped URMA registered lease");
            }
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
    use crate::urma::buffer::{LeaseBook, LeaseKind, SlotId};

    #[test]
    fn zero_command_capacity_is_rejected_before_spawning() {
        let result = UrmaFabric::start_with_capacity(RuntimeConfig::new("urma0", 0), 0);
        assert!(matches!(result, Err(Error::InvalidConfiguration(_))));
    }

    #[test]
    fn required_rx_waiter_is_counted_and_released_on_drop() {
        let waiters = RequiredRxWaiters::default();
        assert!(!waiters.has_waiters());

        let first = waiters.enter();
        let second = waiters.enter();
        assert!(waiters.has_waiters());

        drop(first);
        assert!(waiters.has_waiters());
        drop(second);
        assert!(!waiters.has_waiters());
    }

    #[test]
    fn optional_rx_borrow_yields_to_required_waiters_and_capacity() {
        let waiters = RequiredRxWaiters::default();
        let admission = PeerCreditAdmission::new(2).unwrap();
        admission.register_peer(1, 0).unwrap();

        let borrowed = try_acquire_optional_rx_permit(&waiters, &admission, 1, 2).unwrap();
        assert!(try_acquire_optional_rx_permit(&waiters, &admission, 1, 1).is_err());
        drop(borrowed);

        let required = waiters.enter();
        assert!(try_acquire_optional_rx_permit(&waiters, &admission, 1, 1).is_err());
        assert_eq!(admission.available_permits(), 2);
        drop(required);

        assert!(try_acquire_optional_rx_permit(&waiters, &admission, 1, 1).is_ok());
    }

    #[test]
    fn shared_depth_admission_reuses_one_global_semaphore_and_rejects_depth_changes() {
        let mut admission = SharedDepthAdmission::default();
        let first = admission.permits(8, "send").unwrap();
        let second = admission.permits(8, "send").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let permit = first.clone().try_acquire_many_owned(8).unwrap();
        assert!(second.clone().try_acquire_owned().is_err());
        drop(permit);
        assert!(second.try_acquire_owned().is_ok());
        assert!(admission.permits(7, "receive").is_err());
        assert!(SharedDepthAdmission::default().permits(0, "send").is_err());
    }

    #[test]
    fn dropped_registered_lease_uses_urgent_owner_command() {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let notifier: LeaseRecycleNotifier = Arc::new(move |recycle| {
            command_tx
                .send(CommandEnvelope::urgent(FabricCommand::RecycleLease {
                    recycle,
                }))
                .unwrap();
        });
        let mut leases = LeaseBook::new();
        let recycle = leases
            .issue(LeaseKind::Rx, vec![SlotId::new(7, 3).unwrap()])
            .unwrap();
        let lease =
            RegisteredRxWindowLease::from_test_parts(vec![vec![1, 2, 3]], recycle, notifier);

        drop(lease);
        let envelope = command_rx.try_recv().unwrap();
        assert!(envelope._permit.is_none());
        assert!(matches!(
            envelope.command,
            FabricCommand::RecycleLease { recycle: actual } if actual == recycle
        ));
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
    }

    #[test]
    fn peer_target_config_contains_only_peer_local_pipeline_policy() {
        let config = PeerTargetConfig {
            post_list_size: 5,
            pipeline_depth: 2,
            guaranteed_rx_credits: 3,
        };
        assert_eq!(config.post_list_size, 5);
        assert_eq!(config.pipeline_depth, 2);
        assert_eq!(config.guaranteed_rx_credits, 3);
        assert!(config.validate().is_ok());
        assert!(PeerTargetConfig {
            pipeline_depth: 0,
            ..config
        }
        .validate()
        .is_err());
    }

    #[test]
    fn pipeline_depth_reserves_slots_for_each_window() {
        assert_eq!(window_chunks_for_slots(128, 1), 128);
        assert_eq!(window_chunks_for_slots(128, 2), 64);
        assert_eq!(window_chunks_for_slots(1, 2), 1);
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
