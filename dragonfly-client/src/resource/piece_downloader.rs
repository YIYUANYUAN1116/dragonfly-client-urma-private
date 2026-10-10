/*
 *     Copyright 2024 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use async_trait::async_trait;
use dragonfly_client_config::dfdaemon::Config;
use dragonfly_client_core::{Error, Result};
use dragonfly_client_storage::{
    client::quic::QUICClient, client::tcp::TCPClient, client::PieceContentStream,
};
use dragonfly_client_util::pool::{Builder as PoolBuilder, Entry, Factory, Pool};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, instrument};

/// The default capacity of the downloader to store the clients.
const DEFAULT_DOWNLOADER_CAPACITY: usize = 2000;

/// The default idle timeout for the downloader.
const DEFAULT_DOWNLOADER_IDLE_TIMEOUT: Duration = Duration::from_secs(420);

/// The interface for downloading pieces, which is implemented by different
/// protocols. The downloader is used to download pieces from the other peers.
#[async_trait]
pub trait Downloader: Send + Sync {
    /// Downloads a piece from the other peer by different protocols.
    async fn download_piece(
        &self,
        addr: &str,
        number: u32,
        host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)>;

    /// Downloads a persistent piece from the other peer by different
    /// protocols.
    async fn download_persistent_piece(
        &self,
        addr: &str,
        number: u32,
        host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)>;

    /// Downloads a persistent cache piece from the other peer by different
    /// protocols.
    async fn download_persistent_cache_piece(
        &self,
        addr: &str,
        number: u32,
        host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)>;
}

#[cfg(feature = "urma")]
pub mod urma {
    use super::*;
    use dragonfly_client_storage::client::urma_discovery::discover;
    use dragonfly_client_storage::client::urma_read::{UrmaReadClient, UrmaReadPieceLease};
    use dragonfly_client_storage::urma::fabric::{UrmaFabric, UrmaFabricHandle};
    use dragonfly_client_storage::urma::rendezvous::{
        PieceKind, UrmaAdvertisement, UrmaCapability,
    };
    use dragonfly_client_storage::urma::{TpType, TransportMode, PEER_SESSION_IDLE_TIMEOUT};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    #[cfg(test)]
    use std::sync::atomic::Ordering;
    use std::sync::Weak;
    use std::time::Instant;
    use tracing::{debug, info, warn};

    /// FABRIC_RETRY_INTERVAL is how long to wait before retrying fabric initialization after a
    /// failure.
    const FABRIC_RETRY_INTERVAL: Duration = Duration::from_secs(300);

    /// INCOMPATIBLE_PARENT_TTL is how long a parent that reported fabric incompatibility is
    /// skipped before URMA is attempted again. Incompatibility is a property of the peer's
    /// configuration, so retrying sooner than this cannot succeed.
    const INCOMPATIBLE_PARENT_TTL: Duration = Duration::from_secs(60);

    /// UNHEALTHY_PARENT_MIN_BACKOFF is how long a parent is skipped after its first URMA transfer
    /// failure. A transfer failure, unlike incompatibility, may be a transient blip, so the first
    /// penalty is short enough that one bad piece does not cost a working parent its fast path.
    const UNHEALTHY_PARENT_MIN_BACKOFF: Duration = Duration::from_secs(2);

    /// UNHEALTHY_PARENT_MAX_BACKOFF caps the penalty applied to a parent that keeps failing.
    /// Without a cap a parent that recovers would stay on the TCP path indefinitely.
    const UNHEALTHY_PARENT_MAX_BACKOFF: Duration = Duration::from_secs(60);

    /// CAPABLE_PARENT_TTL bounds how long a successful discovery result is reused.
    const CAPABLE_PARENT_TTL: Duration = Duration::from_secs(60);

    /// Failure says why URMA to a parent did not work, which decides how long to avoid it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Failure {
        /// Incompatible means the peers cannot form a URMA pair at all.
        Incompatible,

        /// Transport means an attempt failed, which may or may not repeat: an unreachable parent,
        /// a parent at its transfer admission limit, or a transfer that died part way.
        Transport,
    }

    fn classify_failure(error: &Error) -> Failure {
        if matches!(error, Error::Unsupported(_)) {
            Failure::Incompatible
        } else {
            Failure::Transport
        }
    }

    /// Reports whether the error is a transient BUSY rejection from a peer at
    /// its URMA registration budget. The cached client, its lane and the
    /// parent's reputation all stay healthy: only this piece should fall back
    /// to TCP. Every other error keeps the existing retire + penalty policy.
    fn is_transient_busy(error: &Error) -> bool {
        matches!(error, Error::Busy(_))
    }

    /// ParentPenalty skips URMA for a parent that just failed.
    struct ParentPenalty {
        /// until is when URMA may be attempted against this parent again.
        until: Instant,

        /// backoff is the penalty applied on the most recent failure, and the basis for the next.
        backoff: Duration,
    }

    /// FabricState tracks the lazily initialized process-shared fabric endpoint.
    enum FabricState {
        /// Uninitialized means no initialization has been attempted yet.
        Uninitialized,

        /// Failed records when initialization last failed, for retry backoff.
        Failed(Instant),

        /// Ready holds the shared facade and the local negotiation capability.
        Ready(UrmaFabricHandle, UrmaCapability),
    }

    /// CachedReadClient keeps one persistent READ lane slot per parent. Any
    /// transfer failure retires the cached lane; the next request rebuilds it.
    struct CachedReadClient {
        last_used: Instant,
        client: UrmaReadClient,
    }

    /// URMADownloader downloads pieces over UMDK/URMA with a shared fabric endpoint. The endpoint
    /// is opened lazily on the first download so a misconfigured or unsupported host degrades to
    /// TCP instead of failing at startup.
    pub struct URMADownloader {
        /// config is the configuration of the dfdaemon.
        config: Arc<Config>,

        /// fabric is the lazily initialized shared endpoint.
        fabric: tokio::sync::Mutex<FabricState>,

        /// unhealthy_parents skips parents whose last URMA attempt failed, so every piece does not
        /// pay a doomed rendezvous round trip.
        unhealthy_parents: std::sync::Mutex<HashMap<String, ParentPenalty>>,

        /// capable_parents caches successful discovery so every piece does not add a control round
        /// trip. Transfer failures evict the entry immediately.
        capable_parents: std::sync::Mutex<HashMap<String, (Instant, UrmaAdvertisement)>>,

        /// read_clients keeps one persistent READ lane slot per parent, used
        /// only when the daemon configures the RM-READ data plane.
        read_clients: tokio::sync::Mutex<HashMap<String, CachedReadClient>>,

        /// client_init_gates singleflight client creation per parent. Weak values avoid retaining
        /// an entry after no request is checking or constructing that parent's client, while
        /// separate parents never wait on each other's discovery or setup.
        client_init_gates: std::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
    }

    /// URMADownloader implements the downloader over the UMDK/URMA transport.
    impl URMADownloader {
        /// new returns a new URMADownloader.
        pub fn new(config: Arc<Config>) -> Self {
            Self {
                config,
                fabric: tokio::sync::Mutex::new(FabricState::Uninitialized),
                unhealthy_parents: std::sync::Mutex::new(HashMap::new()),
                capable_parents: std::sync::Mutex::new(HashMap::new()),
                read_clients: tokio::sync::Mutex::new(HashMap::new()),
                client_init_gates: std::sync::Mutex::new(HashMap::new()),
            }
        }

        /// fabric returns the shared facade and local capability, initializing them on first use
        /// and applying retry backoff after failures.
        async fn fabric(&self) -> Result<(UrmaFabricHandle, UrmaCapability)> {
            let mut state = self.fabric.lock().await;
            match &*state {
                FabricState::Ready(fabric, capability) if !fabric.is_failed() => {
                    return Ok((fabric.clone(), capability.clone()));
                }
                FabricState::Ready(_, _) => {
                    // A retired facade cannot recover by returning errors forever. Drop it and let
                    // the normal initialization path create a fresh device endpoint.
                    *state = FabricState::Uninitialized;
                }
                FabricState::Failed(at) if at.elapsed() < FABRIC_RETRY_INTERVAL => {
                    return Err(Error::Unsupported(
                        "urma fabric initialization failed recently".to_string(),
                    ));
                }
                _ => {}
            }

            let urma_config = &self.config.storage.server.urma;
            if urma_config.deprecated.configured() {
                warn!("URMA SEND/RECV settings are deprecated and ignored; use storage.server.urma.read budgets and limits");
            }

            let Some(device) = urma_config.device.as_deref().filter(|d| !d.is_empty()) else {
                *state = FabricState::Failed(Instant::now());
                return Err(Error::Unsupported(
                    "urma requires storage.server.urma.device".to_string(),
                ));
            };
            let Some(fabric_tag) = urma_config.fabric_tag.as_deref().filter(|t| !t.is_empty())
            else {
                *state = FabricState::Failed(Instant::now());
                return Err(Error::Unsupported(
                    "urma requires storage.server.urma.fabricTag".to_string(),
                ));
            };

            let tp_type = match urma_config.tp_type {
                dragonfly_client_config::dfdaemon::UrmaTpType::Rtp => TpType::Rtp,
                dragonfly_client_config::dfdaemon::UrmaTpType::Ctp => TpType::Ctp,
            };
            let device = device.to_string();
            let eid_index = urma_config.eid_index;
            let read_config = urma_config
                .read
                .clone()
                .ok_or_else(|| Error::Unsupported("URMA READ is not configured".into()))?;
            let startup = tokio::task::spawn_blocking(move || {
                UrmaFabric::get_or_start_with_read_config(device, eid_index, tp_type, &read_config)
            })
            .await;
            let startup = match startup {
                Ok(startup) => startup,
                Err(error) => {
                    warn!(%error, "urma Fabric startup worker failed");
                    *state = FabricState::Failed(Instant::now());
                    return Err(Error::Unknown(format!(
                        "urma Fabric startup worker failed: {error}"
                    )));
                }
            };
            match startup {
                Ok(fabric) => {
                    let transport_mode = TransportMode::Rm;
                    if !fabric.supports_rm() {
                        *state = FabricState::Failed(Instant::now());
                        return Err(Error::Unsupported(format!(
                            "URMA device does not advertise {transport_mode:?} mode"
                        )));
                    }
                    let capability = UrmaCapability {
                        transport_type: fabric.transport_type(),
                        transport_mode,
                        tp_type: fabric.tp_type(),
                        fabric_tag: fabric_tag.to_string(),
                        max_message_size: fabric.max_message_size(),
                    };
                    info!(
                        transport_mode = ?transport_mode,
                        tp_type = ?tp_type,
                        "urma downloader ready: transport type {}, fabric tag {}",
                        capability.transport_type,
                        capability.fabric_tag
                    );
                    *state = FabricState::Ready(fabric.clone(), capability.clone());
                    Ok((fabric, capability))
                }
                Err(err) => {
                    warn!("urma fabric initialization failed: {}", err);
                    *state = FabricState::Failed(Instant::now());
                    Err(Error::Unknown(format!(
                        "urma fabric initialization failed: {err}"
                    )))
                }
            }
        }

        /// retire_failed_fabric removes a poisoned shared endpoint after a transfer failure.
        /// Ordinary peer incompatibility leaves the shared endpoint intact.
        async fn retire_failed_fabric(&self) {
            let mut state = self.fabric.lock().await;
            let mut retired = false;
            if matches!(&*state, FabricState::Ready(fabric, _) if fabric.is_failed()) {
                *state = FabricState::Uninitialized;
                retired = true;
            }
            drop(state);
            if retired {
                self.read_clients.lock().await.clear();
            }
        }

        /// client_init_gate returns the shared construction gate for one parent. The gate covers
        /// the cache re-check and any slow discovery/setup, closing the check-then-insert race
        /// without holding the global clients map lock across network I/O.
        fn client_init_gate(&self, addr: &str) -> Arc<tokio::sync::Mutex<()>> {
            let mut gates = self.client_init_gates.lock().unwrap();
            gates.retain(|_, gate| gate.strong_count() != 0);
            if let Some(gate) = gates.get(addr).and_then(Weak::upgrade) {
                return gate;
            }

            let gate = Arc::new(tokio::sync::Mutex::new(()));
            gates.insert(addr.to_string(), Arc::downgrade(&gate));
            gate
        }

        /// check_parent errors fast for parents that are still serving a penalty.
        fn check_parent(&self, addr: &str) -> Result<()> {
            match self.unhealthy_parents.lock().unwrap().get(addr) {
                Some(penalty) if penalty.until > Instant::now() => Err(Error::Unsupported(
                    format!("parent {addr} recently failed over urma"),
                )),
                _ => Ok(()),
            }
        }

        /// record_failure penalizes a parent whose URMA attempt failed, and drops any discovery
        /// result cached for it.
        fn record_failure(&self, addr: &str, failure: Failure) {
            self.capable_parents.lock().unwrap().remove(addr);

            let mut unhealthy_parents = self.unhealthy_parents.lock().unwrap();
            let backoff = match failure {
                Failure::Incompatible => INCOMPATIBLE_PARENT_TTL,
                Failure::Transport => unhealthy_parents
                    .get(addr)
                    .map(|penalty| (penalty.backoff * 2).min(UNHEALTHY_PARENT_MAX_BACKOFF))
                    .unwrap_or(UNHEALTHY_PARENT_MIN_BACKOFF),
            };

            unhealthy_parents.insert(
                addr.to_string(),
                ParentPenalty {
                    until: Instant::now() + backoff,
                    backoff,
                },
            );
        }

        /// record_success clears a parent's penalty once an attempt against it works again.
        fn record_success(&self, addr: &str) {
            self.unhealthy_parents.lock().unwrap().remove(addr);
        }

        /// advertisement returns a cached live capability or discovers it through the parent's
        /// advertised TCP piece endpoint.
        async fn advertisement(
            &self,
            addr: &str,
            local: &UrmaCapability,
        ) -> Result<UrmaAdvertisement> {
            let cached = self.capable_parents.lock().unwrap().get(addr).cloned();
            if let Some((at, advertisement)) = cached {
                if at.elapsed() < CAPABLE_PARENT_TTL {
                    return Ok(advertisement);
                }
                self.capable_parents.lock().unwrap().remove(addr);
            }

            let advertisement = discover(addr, self.config.storage.server.urma.transfer_timeout)
                .await
                .map_err(|err| {
                    self.record_failure(addr, classify_failure(&err));
                    Error::Unsupported(format!("urma discovery from {addr} failed: {err}"))
                })?;
            local
                .compatible(&advertisement.capability)
                .map_err(|reason| {
                    self.record_failure(addr, Failure::Incompatible);
                    Error::Unsupported(format!("urma incompatible: {reason}"))
                })?;
            self.capable_parents
                .lock()
                .unwrap()
                .insert(addr.to_string(), (Instant::now(), advertisement.clone()));
            Ok(advertisement)
        }

        /// read_client returns the cached persistent READ lane client for one
        /// parent, discovering the parent's READ rendezvous port on first use.
        /// `Ok(None)` means the parent does not advertise the READ data plane:
        /// the Piece caller uses TCP fallback. Other errors follow the shared failure policy.
        async fn read_client(&self, addr: &str) -> Result<Option<UrmaReadClient>> {
            self.check_parent(addr)?;
            let init_gate = self.client_init_gate(addr);
            let _init = init_gate.lock().await;
            // A concurrent request may have recorded a failure while this one
            // waited for the parent gate. Re-check before reusing anything.
            self.check_parent(addr)?;
            let retired = {
                let mut clients = self.read_clients.lock().await;
                match clients.get_mut(addr) {
                    Some(cached) if cached.last_used.elapsed() < PEER_SESSION_IDLE_TIMEOUT => {
                        if cached.client.fabric_failed() {
                            warn!(
                                parent_addr = addr,
                                "retiring cached urma READ client after fabric failure"
                            );
                            clients.remove(addr).map(|cached| cached.client)
                        } else {
                            cached.last_used = Instant::now();
                            return Ok(Some(cached.client.clone()));
                        }
                    }
                    Some(_) => {
                        debug!(parent_addr = addr, "retiring idle cached urma READ client");
                        clients.remove(addr).map(|cached| cached.client)
                    }
                    None => None,
                }
            };
            if let Some(retired) = retired {
                if let Err(error) = retired.close().await {
                    warn!(parent_addr = addr, %error, "failed to close retired urma READ lane");
                }
            }
            let (fabric, capability) = self.fabric().await?;
            // Advertisement lookup records failures and caches discovery results.
            let advertisement = self.advertisement(addr, &capability).await?;
            if advertisement.read_port == 0 {
                return Ok(None);
            }
            let mut read_addr: SocketAddr = addr.parse().map_err(|err| {
                Error::Unsupported(format!("invalid parent piece address {addr}: {err}"))
            })?;
            read_addr.set_port(advertisement.read_port);
            let client = UrmaReadClient::new(self.config.clone(), fabric, read_addr.to_string());
            info!(
                parent_addr = addr,
                read_addr = %read_addr,
                "created cached urma READ client"
            );
            self.read_clients.lock().await.insert(
                addr.to_string(),
                CachedReadClient {
                    last_used: Instant::now(),
                    client: client.clone(),
                },
            );
            Ok(Some(client))
        }

        /// download_piece_lease reads one Piece into a published READ lease
        /// plus the Parent's Piece metadata offset and digest. Errors follow
        /// the shared failure policy: BUSY is transient (keep the cached lane
        /// and parent reputation), anything else retires the READ lane and
        /// penalizes the parent.
        pub async fn download_piece_lease(
            &self,
            addr: &str,
            kind: PieceKind,
            number: u32,
            task_id: &str,
            piece_length: u64,
        ) -> Result<(UrmaReadPieceLease, u64, String)> {
            let Some(client) = self.read_client(addr).await? else {
                return Err(Error::Unsupported(format!(
                    "parent {addr} does not advertise the RM-READ data plane"
                )));
            };
            match client
                .download_piece(kind, number, task_id, piece_length)
                .await
            {
                Ok(downloaded) => {
                    self.record_success(addr);
                    Ok(downloaded)
                }
                Err(err) if is_transient_busy(&err) => Err(err),
                Err(err) => {
                    let fabric_failed = client.fabric_failed();
                    self.read_clients.lock().await.remove(addr);
                    if let Err(close_error) = client.close().await {
                        warn!(parent_addr = addr, %close_error, "failed to close failed urma READ lane");
                    }
                    if fabric_failed {
                        self.retire_failed_fabric().await;
                    }
                    self.record_failure(addr, classify_failure(&err));
                    Err(err)
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn test_downloader() -> URMADownloader {
            URMADownloader::new(Arc::new(Config::default()))
        }

        fn backoff_of(downloader: &URMADownloader, addr: &str) -> Duration {
            downloader.unhealthy_parents.lock().unwrap()[addr].backoff
        }

        #[test]
        fn transport_failures_park_a_parent_and_back_off() {
            let downloader = test_downloader();
            let addr = "127.0.0.1:4001";
            assert!(downloader.check_parent(addr).is_ok());

            downloader.record_failure(addr, Failure::Transport);
            assert!(downloader.check_parent(addr).is_err());
            assert_eq!(backoff_of(&downloader, addr), UNHEALTHY_PARENT_MIN_BACKOFF);

            downloader.record_failure(addr, Failure::Transport);
            assert_eq!(
                backoff_of(&downloader, addr),
                UNHEALTHY_PARENT_MIN_BACKOFF * 2
            );

            for _ in 0..16 {
                downloader.record_failure(addr, Failure::Transport);
            }
            assert_eq!(
                backoff_of(&downloader, addr),
                UNHEALTHY_PARENT_MAX_BACKOFF,
                "backoff must stay bounded so a recovered parent is retried"
            );
        }

        #[test]
        fn incompatible_parents_skip_the_doubling() {
            let downloader = test_downloader();
            let addr = "127.0.0.1:4001";

            downloader.record_failure(addr, Failure::Incompatible);
            assert_eq!(backoff_of(&downloader, addr), INCOMPATIBLE_PARENT_TTL);
            assert!(downloader.check_parent(addr).is_err());
        }

        #[test]
        fn urma_unsupported_errors_are_classified_as_incompatible() {
            assert_eq!(
                classify_failure(&Error::Unsupported("fabric mismatch".into())),
                Failure::Incompatible
            );
            assert_eq!(
                classify_failure(&Error::Unknown("completion failed".into())),
                Failure::Transport
            );
        }

        #[test]
        fn busy_errors_are_transient_and_skip_the_failure_policy() {
            // BUSY maps to Error::Busy and must be intercepted by the
            // is_transient_busy guard before the retire/penalty policy runs:
            // classify_failure alone still buckets it as Transport.
            let busy = Error::Busy("urma peer busy".into());
            assert!(is_transient_busy(&busy));
            assert!(matches!(classify_failure(&busy), Failure::Transport));

            // Every other error keeps the existing policy unchanged.
            assert!(!is_transient_busy(&Error::Unknown("cqe error".into())));
            assert!(!is_transient_busy(&Error::Unsupported("no device".into())));
        }

        #[test]
        fn success_clears_the_penalty() {
            let downloader = test_downloader();
            let addr = "127.0.0.1:4001";

            downloader.record_failure(addr, Failure::Transport);
            downloader.record_success(addr);
            assert!(downloader.check_parent(addr).is_ok());
        }

        #[test]
        fn an_expired_penalty_allows_a_retry_without_resetting_the_backoff() {
            let downloader = test_downloader();
            let addr = "127.0.0.1:4001";

            downloader.record_failure(addr, Failure::Transport);
            downloader.record_failure(addr, Failure::Transport);
            downloader
                .unhealthy_parents
                .lock()
                .unwrap()
                .get_mut(addr)
                .unwrap()
                .until = Instant::now() - Duration::from_secs(1);

            assert!(downloader.check_parent(addr).is_ok());
            downloader.record_failure(addr, Failure::Transport);
            assert_eq!(
                backoff_of(&downloader, addr),
                UNHEALTHY_PARENT_MIN_BACKOFF * 4,
                "a retry that fails again must keep escalating"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn client_initialization_is_serialized_per_parent() {
            use std::sync::atomic::AtomicUsize;

            const REQUESTS: usize = 8;
            let downloader = Arc::new(test_downloader());
            let ready = Arc::new(tokio::sync::Barrier::new(REQUESTS));
            let active = Arc::new(AtomicUsize::new(0));
            let maximum = Arc::new(AtomicUsize::new(0));
            let mut requests = Vec::with_capacity(REQUESTS);

            for _ in 0..REQUESTS {
                let downloader = downloader.clone();
                let ready = ready.clone();
                let active = active.clone();
                let maximum = maximum.clone();
                requests.push(tokio::spawn(async move {
                    // Obtain every Arc before releasing the barrier. If the per-parent map fails
                    // to return the same gate, the critical sections below overlap.
                    let gate = downloader.client_init_gate("127.0.0.1:4001");
                    ready.wait().await;
                    let _guard = gate.lock().await;
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                }));
            }

            for request in requests {
                request.await.unwrap();
            }
            assert_eq!(maximum.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn client_initialization_does_not_share_a_global_gate() {
            let downloader = test_downloader();
            let first = downloader.client_init_gate("127.0.0.1:4001");
            let same_parent = downloader.client_init_gate("127.0.0.1:4001");
            let other_parent = downloader.client_init_gate("127.0.0.2:4001");

            assert!(Arc::ptr_eq(&first, &same_parent));
            assert!(!Arc::ptr_eq(&first, &other_parent));
        }
    }
}

/// The factory for creating different downloaders by different protocols.
pub struct DownloaderFactory {
    /// The downloader for downloading pieces, which is implemented by different
    /// protocols.
    downloader: Arc<dyn Downloader + Send + Sync>,
}

/// DownloadFactory implements the DownloadFactory trait.
impl DownloaderFactory {
    /// Returns a new DownloadFactory.
    pub fn new(protocol: &str, config: Arc<Config>) -> Result<Self> {
        let downloader: Arc<dyn Downloader> = match protocol {
            "tcp" => Arc::new(TCPDownloader::new(
                config.clone(),
                DEFAULT_DOWNLOADER_CAPACITY,
                DEFAULT_DOWNLOADER_IDLE_TIMEOUT,
            )),
            "quic" => Arc::new(QUICDownloader::new(
                config.clone(),
                DEFAULT_DOWNLOADER_CAPACITY,
                DEFAULT_DOWNLOADER_IDLE_TIMEOUT,
            )),
            _ => {
                error!("unsupported protocol: {}", protocol);
                return Err(Error::InvalidParameter);
            }
        };

        Ok(Self { downloader })
    }

    /// Returns the downloader.
    pub fn build(&self) -> Arc<dyn Downloader> {
        self.downloader.clone()
    }
}

/// The downloader for downloading pieces by the QUIC protocol.
/// It will reuse the quic clients to download pieces from the other peers by
/// peer's address.
pub struct QUICDownloader {
    /// The pool of the quic clients.
    client_pool: Pool<String, String, QUICClient, QUICClientFactory>,
}

/// Factory for creating QUICClient instances.
struct QUICClientFactory {
    config: Arc<Config>,
}

/// Implements the Factory trait for creating QUICClient instances.
#[async_trait]
impl Factory<String, QUICClient> for QUICClientFactory {
    type Error = Error;

    /// Creates a new QUICClient connected to the given address.
    async fn make_client(&self, addr: &String) -> Result<QUICClient> {
        QUICClient::new(self.config.clone(), addr.clone()).await
    }
}

/// Implements the downloader with the QUIC protocol.
impl QUICDownloader {
    /// The maximum number of connections per address.
    const MAX_CONNECTIONS_PER_ADDRESS: usize = 32;

    /// Returns a new QUICDownloader.
    pub fn new(config: Arc<Config>, capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            client_pool: PoolBuilder::new(QUICClientFactory {
                config: config.clone(),
            })
            .capacity(capacity)
            .idle_timeout(idle_timeout)
            .build(),
        }
    }

    /// Returns a client entry by the address, recreating the client if its
    /// connection is closed.
    async fn get_client_entry(&self, key: String, addr: String) -> Result<Entry<QUICClient>> {
        let entry = self.client_pool.entry(&key, &addr).await?;
        if !entry.client.is_closed() {
            return Ok(entry);
        }

        self.client_pool.remove_entry(&key).await;
        self.client_pool.entry(&key, &addr).await
    }

    /// Removes the client if it is idle.
    async fn remove_client_entry(&self, key: String) {
        self.client_pool.remove_entry(&key).await;
    }
    /// Generates a semi-random key by combining the client address with
    /// a random number. The randomization helps distribute connections across multiple
    /// slots when the same address attempts to establish multiple concurrent connections.
    fn get_entry_key(&self, addr: &str) -> String {
        format!(
            "{}-{}",
            addr,
            fastrand::usize(..Self::MAX_CONNECTIONS_PER_ADDRESS)
        )
    }
}

/// Implements the Downloader trait.
#[async_trait]
impl Downloader for QUICDownloader {
    /// Downloads a piece from the other peer by the QUIC protocol.
    #[instrument(skip_all)]
    async fn download_piece(
        &self,
        addr: &str,
        number: u32,
        _host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)> {
        let key = self.get_entry_key(addr);
        let entry = self.get_client_entry(key.clone(), addr.to_string()).await?;
        let request_guard = entry.request_guard();

        match entry.client.download_piece(number, task_id).await {
            Ok((stream, offset, digest)) => Ok((stream, offset, digest)),
            Err(err) => {
                // If the request fails, it will drop the request guard and remove the client
                // entry to avoid using the invalid client.
                drop(request_guard);
                self.remove_client_entry(key).await;
                Err(err)
            }
        }
    }

    /// Downloads a persistent piece from the other peer by
    /// the QUIC protocol.
    #[instrument(skip_all)]
    async fn download_persistent_piece(
        &self,
        addr: &str,
        number: u32,
        _host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)> {
        let key = self.get_entry_key(addr);
        let entry = self.get_client_entry(key.clone(), addr.to_string()).await?;
        let request_guard = entry.request_guard();

        match entry
            .client
            .download_persistent_piece(number, task_id)
            .await
        {
            Ok((stream, offset, digest)) => Ok((stream, offset, digest)),
            Err(err) => {
                // If the request fails, it will drop the request guard and remove the client
                // entry to avoid using the invalid client.
                drop(request_guard);
                self.remove_client_entry(key).await;
                Err(err)
            }
        }
    }

    /// Downloads a persistent cache piece from the other peer by
    /// the QUIC protocol.
    #[instrument(skip_all)]
    async fn download_persistent_cache_piece(
        &self,
        addr: &str,
        number: u32,
        _host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)> {
        let key = self.get_entry_key(addr);
        let entry = self.get_client_entry(key.clone(), addr.to_string()).await?;
        let request_guard = entry.request_guard();

        match entry
            .client
            .download_persistent_cache_piece(number, task_id)
            .await
        {
            Ok((stream, offset, digest)) => Ok((stream, offset, digest)),
            Err(err) => {
                // If the request fails, it will drop the request guard and remove the client
                // entry to avoid using the invalid client.
                drop(request_guard);
                self.remove_client_entry(key).await;
                Err(err)
            }
        }
    }
}

/// The downloader for downloading pieces by the TCP protocol.
/// It will reuse the tcp clients to download pieces from the other peers by
/// peer's address.
pub struct TCPDownloader {
    /// The pool of the tcp clients.
    client_pool: Pool<String, String, TCPClient, TCPClientFactory>,
}

/// Factory for creating TCPClient instances.
struct TCPClientFactory {
    config: Arc<Config>,
}

/// Implements the Factory trait for creating TCPClient instances.
#[async_trait]
impl Factory<String, TCPClient> for TCPClientFactory {
    type Error = Error;

    /// Creates a new TCPClient for the given address.
    async fn make_client(&self, addr: &String) -> Result<TCPClient> {
        Ok(TCPClient::new(self.config.clone(), addr.clone()))
    }
}

/// Implements the downloader with the TCP protocol.
impl TCPDownloader {
    /// The maximum number of connections per address.
    const MAX_CONNECTIONS_PER_ADDRESS: usize = 32;

    /// Returns a new TCPDownloader.
    pub fn new(config: Arc<Config>, capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            client_pool: PoolBuilder::new(TCPClientFactory {
                config: config.clone(),
            })
            .capacity(capacity)
            .idle_timeout(idle_timeout)
            .build(),
        }
    }

    /// Returns a client entry by the address.
    async fn get_client_entry(&self, key: String, addr: String) -> Result<Entry<TCPClient>> {
        self.client_pool.entry(&key, &addr).await
    }

    /// Removes the client if it is idle.
    async fn remove_client_entry(&self, key: String) {
        self.client_pool.remove_entry(&key).await;
    }

    /// Generates a semi-random key by combining the client address with
    /// a random number. The randomization helps distribute connections across multiple
    /// slots when the same address attempts to establish multiple concurrent connections.
    fn get_entry_key(&self, addr: &str) -> String {
        format!(
            "{}-{}",
            addr,
            fastrand::usize(..Self::MAX_CONNECTIONS_PER_ADDRESS)
        )
    }
}

/// Implements the Downloader trait.
#[async_trait]
impl Downloader for TCPDownloader {
    /// Downloads a piece from the other peer by the TCP protocol.
    #[instrument(skip_all)]
    async fn download_piece(
        &self,
        addr: &str,
        number: u32,
        _host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)> {
        let key = self.get_entry_key(addr);
        let entry = self.get_client_entry(key.clone(), addr.to_string()).await?;
        let request_guard = entry.request_guard();

        match entry.client.download_piece(number, task_id).await {
            Ok((stream, offset, digest)) => Ok((stream, offset, digest)),
            Err(err) => {
                // If the request fails, it will drop the request guard and remove the client
                // entry to avoid using the invalid client.
                drop(request_guard);
                self.remove_client_entry(key).await;
                Err(err)
            }
        }
    }

    /// Downloads a persistent piece from the other peer by
    /// the TCP protocol.
    #[instrument(skip_all)]
    async fn download_persistent_piece(
        &self,
        addr: &str,
        number: u32,
        _host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)> {
        let key = self.get_entry_key(addr);
        let entry = self.get_client_entry(key.clone(), addr.to_string()).await?;
        let request_guard = entry.request_guard();

        match entry
            .client
            .download_persistent_piece(number, task_id)
            .await
        {
            Ok((stream, offset, digest)) => Ok((stream, offset, digest)),
            Err(err) => {
                // If the request fails, it will drop the request guard and remove the client
                // entry to avoid using the invalid client.
                drop(request_guard);
                self.remove_client_entry(key).await;
                Err(err)
            }
        }
    }

    /// Downloads a persistent cache piece from the other peer by
    /// the TCP protocol.
    #[instrument(skip_all)]
    async fn download_persistent_cache_piece(
        &self,
        addr: &str,
        number: u32,
        _host_id: &str,
        task_id: &str,
    ) -> Result<(PieceContentStream, u64, String)> {
        let key = self.get_entry_key(addr);
        let entry = self.get_client_entry(key.clone(), addr.to_string()).await?;
        let request_guard = entry.request_guard();

        match entry
            .client
            .download_persistent_cache_piece(number, task_id)
            .await
        {
            Ok((stream, offset, digest)) => Ok((stream, offset, digest)),
            Err(err) => {
                // If the request fails, it will drop the request guard and remove the client
                // entry to avoid using the invalid client.
                drop(request_guard);
                self.remove_client_entry(key).await;
                Err(err)
            }
        }
    }
}
