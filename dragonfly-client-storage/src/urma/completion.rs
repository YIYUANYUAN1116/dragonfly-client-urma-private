use super::{
    buffer::{RegisteredRxWindowLease, TxWindowLease, UrmaBufferPool},
    ffi,
    lane::{OperationType, WrToken},
    native_error,
    target::PeerTargetRegistry,
    transfer::RoutingToken,
    Error, Result,
};
use dragonfly_client_metric::collect_urma_rx_anomaly_metrics;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::oneshot;

const MAX_POLL_BATCH: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompletionStats {
    pub(crate) send_post: u64,
    pub(crate) recv_post: u64,
    pub(crate) send_cqe: u64,
    pub(crate) recv_cqe: u64,
    pub(crate) cqe_error: u64,
    pub(crate) poll_calls: u64,
    pub(crate) empty_polls: u64,
    pub(crate) max_outstanding: u64,
    pub(crate) rx_unknown_source: u64,
    pub(crate) rx_invalid_token: u64,
    pub(crate) rx_stale_token: u64,
    pub(crate) rx_over_credit: u64,
    pub(crate) rx_ambiguous_token: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RxRouteFailure {
    MissingSource,
    UnauthorizedSource,
    InvalidToken,
    StaleToken,
    OverCredit,
    AmbiguousToken,
}

impl RxRouteFailure {
    fn into_error(self) -> Error {
        Error::Protocol(
            match self {
                Self::MissingSource => "receive CQE has no remote Jetty identity",
                Self::UnauthorizedSource => "receive CQE source is not an authorized PeerTarget",
                Self::InvalidToken => "receive CQE has an invalid routing token",
                Self::StaleToken => "receive CQE routing token refers to no active transfer",
                Self::OverCredit => {
                    "receive CQE chunk exceeds its source PeerTarget transfer credit"
                }
                Self::AmbiguousToken => {
                    "receive CQE routing token is ambiguous across PeerTarget aliases"
                }
            }
            .into(),
        )
    }
}

pub(crate) struct RegisteredRxCompletion {
    pub(crate) lane_id: u16,
    /// Sequence assigned when this receive WR was posted. SEND/RECV matching
    /// on the provider is not FIFO, so this is only a local bookkeeping hint;
    /// `imm_data` is the authoritative logical transfer/chunk identity.
    pub(crate) posted_sequence: Option<u64>,
    pub(crate) imm_data: u64,
    pub(crate) slot: crate::urma::buffer::SlotId,
    pub(crate) lease: RegisteredRxWindowLease,
}

pub(crate) type RegisteredRxCompletionTx = oneshot::Sender<Result<RegisteredRxCompletion>>;

pub(crate) struct RegisteredTxCompletion {
    pub(crate) lane_id: u16,
    pub(crate) sequences: Vec<u64>,
    pub(crate) lease: TxWindowLease,
}

pub(crate) type RegisteredTxCompletionTx = oneshot::Sender<Result<RegisteredTxCompletion>>;

struct RegisteredTxWindowInner {
    pending: usize,
    posting_finished: bool,
    first_error: Option<Error>,
    lane_id: u16,
    sequences: Vec<u64>,
    lease: Option<TxWindowLease>,
    completion: Option<RegisteredTxCompletionTx>,
}

#[derive(Clone)]
pub(crate) struct RegisteredTxWindowState(Arc<Mutex<RegisteredTxWindowInner>>);

impl RegisteredTxWindowState {
    pub(crate) fn new(
        lane_id: u16,
        sequences: Vec<u64>,
        lease: TxWindowLease,
        completion: RegisteredTxCompletionTx,
    ) -> Self {
        Self(Arc::new(Mutex::new(RegisteredTxWindowInner {
            pending: 0,
            posting_finished: false,
            first_error: None,
            lane_id,
            sequences,
            lease: Some(lease),
            completion: Some(completion),
        })))
    }

    fn posted(&self) {
        self.0.lock().unwrap().pending += 1;
    }

    pub(crate) fn finish_posting(&self, error: Option<Error>) {
        let mut inner = self.0.lock().unwrap();
        inner.posting_finished = true;
        if inner.first_error.is_none() {
            inner.first_error = error;
        }
        Self::resolve(&mut inner);
    }

    fn completed(&self, result: &Result<RoutedCompletion>) {
        let mut inner = self.0.lock().unwrap();
        debug_assert_ne!(inner.pending, 0);
        inner.pending -= 1;
        if inner.first_error.is_none() {
            if let Err(error) = result {
                inner.first_error = Some(error.clone());
            }
        }
        Self::resolve(&mut inner);
    }

    fn fail(&self, error: Error) {
        let mut inner = self.0.lock().unwrap();
        if inner.first_error.is_none() {
            inner.first_error = Some(error.clone());
        }
        if let Some(completion) = inner.completion.take() {
            let _ = completion.send(Err(error));
        }
    }

    fn resolve(inner: &mut RegisteredTxWindowInner) {
        if !inner.posting_finished || inner.pending != 0 {
            return;
        }
        let Some(completion) = inner.completion.take() else {
            return;
        };
        if let Some(error) = inner.first_error.take() {
            // Dropping only after every posted CQE has restored its slot to
            // LeasedTx makes the lease's owner-thread recycle notification safe.
            inner.lease.take();
            let _ = completion.send(Err(error));
        } else {
            let lease = inner.lease.take().expect("registered TX lease is owned");
            let _ = completion.send(Ok(RegisteredTxCompletion {
                lane_id: inner.lane_id,
                sequences: std::mem::take(&mut inner.sequences),
                lease,
            }));
        }
    }
}

enum CompletionTarget {
    RegisteredRx(RegisteredRxCompletionTx),
    RegisteredTx(RegisteredTxWindowState),
}

enum RoutedCompletion {
    RegisteredRx(RegisteredRxCompletion),
    RegisteredTx,
}

fn validate_recv_immediate(record: ffi::CompletionRecord) -> Result<u64> {
    if record.opcode != ffi::CR_OPCODE_SEND_WITH_IMM || !record.imm_data_valid {
        return Err(Error::Protocol(format!(
            "URMA receive CQE lacks SEND_WITH_IMM identity: opcode={} imm_data_valid={}",
            record.opcode, record.imm_data_valid
        )));
    }
    Ok(record.imm_data)
}

impl CompletionTarget {
    fn send(self, result: Result<RoutedCompletion>) {
        match (self, result) {
            (Self::RegisteredRx(completion), Ok(RoutedCompletion::RegisteredRx(value))) => {
                let _ = completion.send(Ok(value));
            }
            (Self::RegisteredTx(completion), result) => completion.completed(&result),
            (Self::RegisteredRx(completion), Err(error)) => {
                let _ = completion.send(Err(error));
            }
            (Self::RegisteredRx(completion), Ok(RoutedCompletion::RegisteredTx)) => {
                let _ = completion.send(Err(Error::Protocol(
                    "registered TX completion routed to RX receiver".into(),
                )));
            }
        }
    }

    fn fail(self, error: Error) {
        match self {
            Self::RegisteredRx(completion) => {
                let _ = completion.send(Err(error));
            }
            Self::RegisteredTx(completion) => completion.fail(error),
        }
    }
}

struct OutstandingWr {
    user_ctx: u64,
    // Reserved before the native post and filled only for the prefix accepted
    // by the provider. The owner thread cannot poll CQEs while a command is
    // being handled, so a committed entry is always visible before its CQE.
    handle: Option<ffi::WrHandle>,
    sequence: Option<u64>,
    /// Only signaled SENDs may produce a successful local CQE. RECV entries
    /// are always effectively signaled and do not use the SEND frontier.
    signaled: bool,
    completion: Option<CompletionTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointLifecycle {
    jetty_id: u32,
    jfr_id: u32,
    waiting_for_flush: bool,
    flush_done: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PeerSendCompletionStats {
    posted: u64,
    retired: u64,
    cqes: u64,
}

/// The single completion consumer for the process-shared JFCs. A JFC must not
/// be polled independently by individual PeerTargets because any poll may return a
/// completion belonging to any Jetty attached to that JFC.
pub(crate) struct CompletionRouter {
    batch: usize,
    outstanding: Vec<Option<OutstandingWr>>,
    outstanding_total: usize,
    outstanding_send: usize,
    outstanding_recv: usize,
    /// Provider post order for the one process-wide RM JFS. A signaled SEND
    /// CQE retires this ordered prefix, including preceding unsignaled WRs
    /// belonging to other logical PeerTargets.
    send_order: VecDeque<u64>,
    outstanding_by_peer: HashMap<u16, usize>,
    send_stats_by_peer: HashMap<u16, PeerSendCompletionStats>,
    /// The one process-shared RM endpoint; receive CQEs must resolve their
    /// source through the PeerTargetRegistry because posted RECV WRs are
    /// anonymous on the shared receive queue.
    endpoint: Option<EndpointLifecycle>,
    targets: PeerTargetRegistry<RegisteredRxCompletionTx>,
    failed_peers: Vec<u16>,
    stats: CompletionStats,
}

impl CompletionRouter {
    pub(crate) fn new(batch: usize) -> Result<Self> {
        if batch == 0 || batch > MAX_POLL_BATCH {
            return Err(Error::InvalidConfiguration(format!(
                "completion poll batch must be in 1..={MAX_POLL_BATCH}"
            )));
        }
        Ok(Self {
            batch,
            outstanding: Vec::new(),
            outstanding_total: 0,
            outstanding_send: 0,
            outstanding_recv: 0,
            send_order: VecDeque::new(),
            outstanding_by_peer: HashMap::new(),
            send_stats_by_peer: HashMap::new(),
            endpoint: None,
            targets: PeerTargetRegistry::default(),
            failed_peers: Vec::new(),
            stats: CompletionStats::default(),
        })
    }

    pub(crate) fn register_endpoint(&mut self, jetty_id: u32, jfr_id: u32) -> Result<()> {
        if self.endpoint.is_some() {
            return Err(Error::Protocol(
                "the shared RM endpoint is already registered".into(),
            ));
        }
        self.endpoint = Some(EndpointLifecycle {
            jetty_id,
            jfr_id,
            waiting_for_flush: false,
            flush_done: false,
        });
        Ok(())
    }

    pub(crate) fn begin_peer_retirement(&mut self, peer_id: u16) -> Result<()> {
        // Per-peer retirement only marks the PeerTarget draining: the shared
        // Jetty must keep serving the remaining peers, so no flush is armed
        // here. Endpoint-level flush escalation lives in `begin_endpoint_flush`.
        let completions = if self.targets.contains(peer_id) {
            self.targets.begin_draining(peer_id)?;
            self.targets.drain_routing_tokens(peer_id)?
        } else {
            Vec::new()
        };
        let error = Error::Protocol(format!("URMA PeerTarget {peer_id} is retiring"));
        for completion in completions {
            let _ = completion.send(Err(error.clone()));
        }
        tracing::debug!(peer_id, "waiting for URMA PeerTarget WRs to drain");
        Ok(())
    }

    /// Fatal escalation for the whole shared endpoint (shutdown timeout or
    /// process teardown): forces every stranded WR to complete with an error.
    pub(crate) fn begin_endpoint_flush(&mut self) -> bool {
        match self.endpoint.as_mut() {
            Some(endpoint) if !endpoint.waiting_for_flush => {
                endpoint.waiting_for_flush = true;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn endpoint_is_flushing(&self) -> bool {
        self.endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.waiting_for_flush)
    }

    pub(crate) fn authorize_remote(
        &mut self,
        peer_id: u16,
        generation: u8,
        remote_id: ffi::RemoteJettyId,
    ) -> Result<()> {
        self.targets.register(peer_id, generation, remote_id)
    }

    /// Resolves the authorized PeerTarget that sourced a receive CQE. On the
    /// shared receive queue the posting WR's token lane does not imply the
    /// data source: any peer's SEND may consume any posted RECV, so the
    /// source peer is resolved from the hardware-reported remote identity.
    fn classify_source(
        &self,
        remote_id: Option<ffi::RemoteJettyId>,
        routing_token: u64,
    ) -> std::result::Result<u16, RxRouteFailure> {
        let remote_id = remote_id.ok_or(RxRouteFailure::MissingSource)?;
        let routing_token =
            RoutingToken::decode(routing_token).map_err(|_| RxRouteFailure::InvalidToken)?;
        let routes = self
            .targets
            .routes(remote_id)
            .map_err(|_| RxRouteFailure::UnauthorizedSource)?;
        let matches = routes
            .iter()
            .filter(|route| self.targets.contains_routing_token(route.id, routing_token))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [route] => Ok(route.id),
            [] if routes
                .iter()
                .any(|route| self.targets.contains_transfer(route.id, routing_token)) =>
            {
                Err(RxRouteFailure::OverCredit)
            }
            [] => Err(RxRouteFailure::StaleToken),
            _ => Err(RxRouteFailure::AmbiguousToken),
        }
    }

    fn resolve_source(
        &self,
        remote_id: Option<ffi::RemoteJettyId>,
        routing_token: u64,
    ) -> Result<u16> {
        self.classify_source(remote_id, routing_token)
            .map_err(RxRouteFailure::into_error)
    }

    fn record_rx_route_failure(&mut self, failure: RxRouteFailure) {
        let reason = match failure {
            RxRouteFailure::MissingSource => "missing_source",
            RxRouteFailure::UnauthorizedSource => "unknown_source",
            RxRouteFailure::InvalidToken => "invalid_token",
            RxRouteFailure::StaleToken => "stale_token",
            RxRouteFailure::OverCredit => "over_credit",
            RxRouteFailure::AmbiguousToken => "ambiguous_token",
        };
        collect_urma_rx_anomaly_metrics(reason);
        match failure {
            RxRouteFailure::MissingSource | RxRouteFailure::UnauthorizedSource => {
                self.stats.rx_unknown_source += 1;
            }
            RxRouteFailure::InvalidToken => self.stats.rx_invalid_token += 1,
            RxRouteFailure::StaleToken => self.stats.rx_stale_token += 1,
            RxRouteFailure::OverCredit => self.stats.rx_over_credit += 1,
            RxRouteFailure::AmbiguousToken => self.stats.rx_ambiguous_token += 1,
        }
    }

    pub(crate) fn ensure_recv_capacity(&self, requested: usize, depth: usize) -> Result<()> {
        let available = depth.saturating_sub(self.outstanding_recv);
        if requested > available {
            return Err(Error::BufferUnavailable {
                kind: "shared JFR",
                requested,
                available,
            });
        }
        Ok(())
    }

    /// Number of already-posted anonymous RQEs that currently have no logical
    /// routing token. Peer retirement deliberately leaves these endpoint-owned
    /// RQEs live, so later peers must reuse them instead of posting another RQE.
    pub(crate) fn unassigned_recv_capacity(&self) -> Result<usize> {
        let logical = self.targets.routing_token_count();
        self.outstanding_recv.checked_sub(logical).ok_or_else(|| {
            Error::Protocol(format!(
                "shared RM logical RX credits exceed posted RQEs: logical={logical} posted={}",
                self.outstanding_recv
            ))
        })
    }

    pub(crate) fn endpoint_ready_to_close(&self) -> bool {
        self.outstanding_total == 0
            && self
                .endpoint
                .as_ref()
                .is_none_or(|endpoint| !endpoint.waiting_for_flush || endpoint.flush_done)
    }

    pub(crate) fn unregister_peer(&mut self, peer_id: u16) -> Result<()> {
        if self.targets.has_routing_tokens(peer_id) {
            return Err(Error::Protocol(format!(
                "cannot unregister PeerTarget {peer_id} with registered RX identities"
            )));
        }
        if self.targets.contains(peer_id) {
            self.targets.remove(peer_id)?;
        }
        if let Some(stats) = self.send_stats_by_peer.remove(&peer_id) {
            let sends_per_cqe = if stats.cqes == 0 {
                0.0
            } else {
                stats.retired as f64 / stats.cqes as f64
            };
            tracing::info!(
                peer_id,
                send_posted = stats.posted,
                send_retired = stats.retired,
                send_cqe = stats.cqes,
                sends_per_cqe,
                "urma SEND completion summary"
            );
        }
        Ok(())
    }

    fn has_pending_flush(&self) -> bool {
        self.endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.waiting_for_flush && !endpoint.flush_done)
    }

    #[cfg(test)]
    pub(crate) fn track_registered_rx(
        &mut self,
        peer_id: u16,
        user_ctx: u64,
        handle: ffi::WrHandle,
        sequence: Option<u64>,
        completion: RegisteredRxCompletionTx,
    ) -> Result<()> {
        let sequence = sequence.ok_or_else(|| {
            Error::InvalidConfiguration(
                "registered RX completion requires a SEND_IMM identity".into(),
            )
        })?;
        if peer_id == 0 {
            return Err(Error::InvalidConfiguration(
                "registered RX owner must be a PeerTarget".into(),
            ));
        }
        let routing_token = RoutingToken::decode(sequence)?;
        self.targets
            .validate_routing_token(peer_id, routing_token)?;
        self.targets
            .register_routing_token(peer_id, routing_token, completion)?;
        if let Err(error) = self.track_anonymous_rx(user_ctx, handle, Some(sequence)) {
            // Registration was prevalidated and inserted only for this call.
            // Roll it back if physical ownership could not be recorded.
            let _ = self.targets.take_routing_token(peer_id, routing_token);
            return Err(error);
        }
        Ok(())
    }

    /// Records one provider-accepted anonymous receive WR. Logical ownership is
    /// registered separately because an existing endpoint RQE may be reused by
    /// a later PeerTarget after its original waiter is retired.
    pub(crate) fn reserve_anonymous_rx(
        &mut self,
        user_ctx: u64,
        posted_sequence: Option<u64>,
    ) -> Result<()> {
        let token = WrToken::decode(user_ctx)?;
        if token.operation != OperationType::Recv || token.peer_id != 0 {
            return Err(Error::Protocol(
                "anonymous RX ownership requires a peerless RECV WR".into(),
            ));
        }
        self.reserve_outstanding(OutstandingWr {
            user_ctx,
            handle: None,
            sequence: posted_sequence,
            signaled: true,
            completion: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn track_anonymous_rx(
        &mut self,
        user_ctx: u64,
        handle: ffi::WrHandle,
        posted_sequence: Option<u64>,
    ) -> Result<()> {
        self.reserve_anonymous_rx(user_ctx, posted_sequence)?;
        self.commit_posted(user_ctx, handle);
        Ok(())
    }

    /// Registers logical receive consumers against the endpoint's anonymous
    /// posted-RQE pool. Callers must ensure enough unassigned RQEs exist first.
    pub(crate) fn register_rx_window(
        &mut self,
        peer_id: u16,
        sequences: Vec<u64>,
        completions: Vec<RegisteredRxCompletionTx>,
    ) -> Result<()> {
        if sequences.is_empty() || sequences.len() != completions.len() {
            return Err(Error::InvalidConfiguration(
                "registered RX window requires matching non-empty identities and completions"
                    .into(),
            ));
        }
        self.validate_registered_rx_identities(peer_id, &sequences)?;
        let available = self.unassigned_recv_capacity()?;
        if sequences.len() > available {
            return Err(Error::BufferUnavailable {
                kind: "shared RM anonymous RQE",
                requested: sequences.len(),
                available,
            });
        }
        for (sequence, completion) in sequences.into_iter().zip(completions) {
            let token = RoutingToken::decode(sequence)?;
            // The whole window was prevalidated on this single owner thread,
            // therefore insertion cannot conflict part-way through the loop.
            self.targets
                .register_routing_token(peer_id, token, completion)?;
        }
        Ok(())
    }

    pub(crate) fn validate_registered_rx_identities(
        &self,
        peer_id: u16,
        sequences: &[u64],
    ) -> Result<()> {
        let mut identities = std::collections::HashSet::with_capacity(sequences.len());
        for &sequence in sequences {
            if !identities.insert(sequence) {
                return Err(Error::Protocol(format!(
                    "duplicate RX identity in registered window: peer_id={peer_id} sequence={sequence}"
                )));
            }
            let routing_token = RoutingToken::decode(sequence)?;
            self.targets
                .validate_routing_token(peer_id, routing_token)?;
        }
        Ok(())
    }

    pub(crate) fn validate_send_owner(&self, peer_id: u16, generation: u8) -> Result<()> {
        self.targets.validate_active_generation(peer_id, generation)
    }

    pub(crate) fn reserve_registered_tx(
        &mut self,
        user_ctx: u64,
        sequence: u64,
        signaled: bool,
        completion: RegisteredTxWindowState,
    ) -> Result<()> {
        let token = WrToken::decode(user_ctx)?;
        if token.operation != OperationType::Send {
            return Err(Error::Protocol(
                "registered TX completion requires a SEND WR".into(),
            ));
        }
        self.validate_send_owner(token.peer_id, token.generation)?;
        self.reserve_outstanding(OutstandingWr {
            user_ctx,
            handle: None,
            sequence: Some(sequence),
            signaled,
            completion: Some(CompletionTarget::RegisteredTx(completion)),
        })
    }

    #[cfg(test)]
    pub(crate) fn track_registered_tx(
        &mut self,
        user_ctx: u64,
        handle: ffi::WrHandle,
        sequence: u64,
        completion: RegisteredTxWindowState,
    ) -> Result<()> {
        self.track_registered_tx_with_signal(user_ctx, handle, sequence, true, completion)
    }

    #[cfg(test)]
    fn track_registered_tx_with_signal(
        &mut self,
        user_ctx: u64,
        handle: ffi::WrHandle,
        sequence: u64,
        signaled: bool,
        completion: RegisteredTxWindowState,
    ) -> Result<()> {
        self.reserve_registered_tx(user_ctx, sequence, signaled, completion)?;
        self.commit_posted(user_ctx, handle);
        Ok(())
    }

    fn reserve_outstanding(&mut self, outstanding: OutstandingWr) -> Result<()> {
        let token = WrToken::decode(outstanding.user_ctx)?;
        let slot = token.slot.index();
        if self.outstanding.len() <= slot {
            self.outstanding.resize_with(slot + 1, || None);
        }
        if self.outstanding[slot].is_some() {
            return Err(Error::Protocol("duplicate outstanding slot".into()));
        }
        self.outstanding[slot] = Some(outstanding);
        Ok(())
    }

    /// Commits ownership for a WR already accepted by the provider. Every
    /// fallible identity/slot check ran during reservation, before native state
    /// changed; a failure here therefore denotes an internal invariant break.
    pub(crate) fn commit_posted(&mut self, user_ctx: u64, handle: ffi::WrHandle) {
        let token = WrToken::decode(user_ctx)
            .expect("a committed WR identity was validated during reservation");
        let entry = self
            .outstanding
            .get_mut(token.slot.index())
            .and_then(Option::as_mut)
            .expect("a posted WR has an outstanding reservation");
        assert_eq!(
            entry.user_ctx, user_ctx,
            "posted WR reservation identity changed"
        );
        assert!(
            entry.handle.is_none(),
            "posted WR reservation was committed twice"
        );
        if let Some(CompletionTarget::RegisteredTx(completion)) = &entry.completion {
            completion.posted();
        }
        entry.handle = Some(handle);
        self.outstanding_total += 1;
        match token.operation {
            OperationType::Send => {
                self.send_order.push_back(user_ctx);
                self.outstanding_send += 1;
                *self.outstanding_by_peer.entry(token.peer_id).or_default() += 1;
                let stats = self.send_stats_by_peer.entry(token.peer_id).or_default();
                stats.posted = stats.posted.saturating_add(1);
                self.stats.send_post += 1;
            }
            OperationType::Recv => {
                self.outstanding_recv += 1;
                self.stats.recv_post += 1;
            }
        }
        self.stats.max_outstanding = self
            .stats
            .max_outstanding
            .max(self.outstanding_total as u64);
    }

    pub(crate) fn cancel_reservation(&mut self, user_ctx: u64) -> Result<()> {
        let token = WrToken::decode(user_ctx)?;
        let entry = self
            .outstanding
            .get_mut(token.slot.index())
            .ok_or_else(|| Error::Protocol("WR reservation slot is outside table".into()))?;
        if !entry.as_ref().is_some_and(|outstanding| {
            outstanding.user_ctx == user_ctx && outstanding.handle.is_none()
        }) {
            return Err(Error::Protocol(
                "cannot cancel a missing or committed WR reservation".into(),
            ));
        }
        entry.take();
        Ok(())
    }

    fn take_registered_rx(
        &mut self,
        peer_id: u16,
        imm_data: u64,
    ) -> Result<RegisteredRxCompletionTx> {
        let routing_token = RoutingToken::decode(imm_data)?;
        self.targets
            .take_routing_token(peer_id, routing_token)
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "URMA SEND_IMM completion has no registered RX identity: peer_id={peer_id} sequence={imm_data}"
                ))
            })
    }

    pub(crate) fn poll_once(
        &mut self,
        send_jfc: &ffi::JfcHandle,
        recv_jfc: &ffi::JfcHandle,
        pool: &mut UrmaBufferPool,
    ) -> Result<usize> {
        self.stats.poll_calls += 1;
        let mut completed = 0;
        let mut first_error = None;
        if self.outstanding_send != 0 || self.has_pending_flush() {
            match self.poll_jfc(send_jfc, false, pool) {
                Ok(count) => completed += count,
                Err(error) => first_error = Some(error),
            }
        }
        if self.outstanding_recv != 0 {
            match self.poll_jfc(recv_jfc, true, pool) {
                Ok(count) => completed += count,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if completed == 0 {
            self.stats.empty_polls += 1;
            std::hint::spin_loop();
        }
        Ok(completed)
    }

    fn poll_jfc(
        &mut self,
        jfc: &ffi::JfcHandle,
        recv_queue: bool,
        pool: &mut UrmaBufferPool,
    ) -> Result<usize> {
        let mut records = [ffi::CompletionRecord::default(); MAX_POLL_BATCH];
        let count = jfc
            .poll_into(&mut records[..self.batch])
            .map_err(|error| native_error("poll_jfc", error))?;
        drain_batch(records.into_iter().take(count), |record| {
            self.route(record, recv_queue, pool)
        })
    }

    fn route(
        &mut self,
        record: ffi::CompletionRecord,
        recv_queue: bool,
        pool: &mut UrmaBufferPool,
    ) -> Result<()> {
        match record.event_kind {
            ffi::CompletionEventKind::FlushErrorDone => {
                return self.route_flush_done(record, recv_queue);
            }
            ffi::CompletionEventKind::SuspendDone => {
                self.stats.cqe_error += 1;
                return Err(Error::Protocol(format!(
                    "unexpected WR_SUSPEND_DONE lifecycle CQE on native object {}",
                    record.local_id
                )));
            }
            ffi::CompletionEventKind::Unknown(kind) => {
                self.stats.cqe_error += 1;
                return Err(Error::Protocol(format!(
                    "unknown URMA completion event kind {kind}"
                )));
            }
            ffi::CompletionEventKind::WorkRequest => {}
        }
        if !record.user_ctx_valid {
            self.stats.cqe_error += 1;
            return Err(Error::Completion {
                status: record.status,
                opcode: record.opcode,
                user_ctx: 0,
                sequence: None,
                post_call: None,
            });
        }
        let token = WrToken::decode(record.user_ctx)?;
        // Cross-validate the hardware-written native Jetty identity against
        // the one shared RM endpoint before touching any WR ownership. UMDK
        // stamps local_id = jetty->jetty_id.id with is_jetty=1 on both SEND
        // and RECV CQEs of the shared-JFR Jetty (udma_u_parse_cqe_for_jfc
        // resolves source identity through the Jetty table; udma_u_delete_jetty
        // cleans the send and receive JFCs by Jetty id, and udma_u_clean_jfc
        // matches local_id against it), so local_id must name the single
        // registered endpoint. A mismatch means corrupt routing identity:
        // fail closed without retiring the WR through the untrusted user_ctx;
        // the poll error fails the fabric owner via fail_pending and poison.
        if self
            .endpoint
            .as_ref()
            .is_none_or(|endpoint| endpoint.jetty_id != record.local_id)
        {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(format!(
                "CQE native Jetty {} does not belong to the shared RM endpoint",
                record.local_id
            )));
        }
        let expected_recv = token.operation == OperationType::Recv;
        let recv_shape_valid = expected_recv && recv_queue && record.is_recv && record.is_jetty;
        // Resolve the data source from the hardware-reported remote identity.
        // With the shared receive queue, a CQE's posting WR (token lane) is
        // anonymous: any authorized peer's SEND may consume any posted RECV.
        // The source peer must still be an authorized PeerTarget; anything
        // else fails closed.
        let source = if recv_shape_valid && record.status == 0 {
            let routing_token = match validate_recv_immediate(record) {
                Ok(routing_token) => routing_token,
                Err(error) => {
                    self.stats.cqe_error += 1;
                    self.record_rx_route_failure(RxRouteFailure::InvalidToken);
                    return self.retire_rejected_recv(record.user_ctx, pool, error);
                }
            };
            match self.classify_source(record.remote_id, routing_token) {
                Ok(source) => Some(source),
                Err(failure) => {
                    self.stats.cqe_error += 1;
                    self.record_rx_route_failure(failure);
                    return self.retire_rejected_recv(record.user_ctx, pool, failure.into_error());
                }
            }
        } else if expected_recv {
            // Error CQE field validity is provider/status dependent. Resolve a
            // Peer only when both source and routing token are usable; otherwise
            // the error remains fabric-scoped and ownership is still retired.
            record
                .remote_id
                .filter(|_| record.opcode == ffi::CR_OPCODE_SEND_WITH_IMM && record.imm_data_valid)
                .and_then(|remote_id| self.resolve_source(Some(remote_id), record.imm_data).ok())
        } else if self.targets.contains(token.peer_id) {
            Some(token.peer_id)
        } else {
            None
        };
        let retiring = self
            .endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.waiting_for_flush);
        if token.operation == OperationType::Send {
            return self.route_send_frontier(record, recv_queue, pool, retiring, source);
        }
        let mut outstanding = self.take_outstanding(record.user_ctx)?;
        outstanding
            .handle
            .take()
            .expect("committed outstanding WR has a native handle")
            .complete();
        debug_assert_eq!(token.operation, OperationType::Recv);
        let result = if expected_recv != recv_queue
            || record.is_recv != recv_queue
            || !record.is_jetty
        {
            self.stats.cqe_error += 1;
            self.decrement_operation(token.operation);
            pool.complete_error(token.slot, token.operation)
                .and_then(|()| pool.release(token.slot))
                .and(Err(Error::Protocol(
                    "CQE queue/operation flags disagree".into(),
                )))
        } else if record.status != 0 {
            self.stats.cqe_error += 1;
            self.decrement_operation(token.operation);
            pool.complete_error(token.slot, token.operation)
                .and_then(|()| pool.release(token.slot))
                .and(Err(Error::Completion {
                    status: record.status,
                    opcode: record.opcode,
                    user_ctx: record.user_ctx,
                    sequence: outstanding.sequence,
                    post_call: None,
                }))
        } else {
            (|| {
                self.outstanding_recv -= 1;
                self.stats.recv_cqe += 1;
                let imm_data = record.imm_data;
                let completion = match self.take_registered_rx(
                    source.expect("successful receive resolved a source"),
                    imm_data,
                ) {
                    Ok(completion) => completion,
                    Err(error) => {
                        pool.complete_error(token.slot, token.operation)?;
                        pool.release(token.slot)?;
                        return Err(error);
                    }
                };
                outstanding.completion = Some(CompletionTarget::RegisteredRx(completion));
                if let Err(error) = pool.complete_recv_leased(token.slot, record.completion_len) {
                    pool.complete_error(token.slot, token.operation)?;
                    pool.release(token.slot)?;
                    return Err(error);
                }
                let lease =
                    match pool.lease_completed_rx_window(&[(token.slot, record.completion_len)]) {
                        Ok(lease) => lease,
                        Err(error) => {
                            pool.release(token.slot)?;
                            return Err(error);
                        }
                    };
                Ok(RoutedCompletion::RegisteredRx(RegisteredRxCompletion {
                    // The source peer owns the transfer identity; the
                    // lease remains attached to the anonymous physical
                    // receive slot named by user_ctx.
                    lane_id: source.expect("successful receive resolved a source"),
                    posted_sequence: outstanding.sequence,
                    imm_data,
                    slot: token.slot,
                    lease,
                }))
            })()
        };

        let owner_error = result.as_ref().err().cloned();
        if let Some(completion) = outstanding.completion.take() {
            completion.send(result);
        }
        match owner_error {
            Some(Error::Completion { .. }) if retiring => Ok(()),
            Some(Error::Completion { .. }) if source.is_some() => {
                let lane_id = source.expect("known source checked above");
                if !self.failed_peers.contains(&lane_id) {
                    self.failed_peers.push(lane_id);
                }
                Ok(())
            }
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Retires the globally ordered prefix of the one shared RM JFS. With
    /// `outorder_comp=0`, a successful signaled completion proves that every
    /// earlier SEND has stopped accessing its registered slot. The ordering
    /// scope is the physical JFS, not a logical PeerTarget.
    fn route_send_frontier(
        &mut self,
        record: ffi::CompletionRecord,
        recv_queue: bool,
        pool: &mut UrmaBufferPool,
        retiring: bool,
        source: Option<u16>,
    ) -> Result<()> {
        let frontier = self
            .send_order
            .iter()
            .position(|user_ctx| *user_ctx == record.user_ctx)
            .ok_or_else(|| Error::Protocol("SEND CQE has no ordered frontier".into()))?;
        let frontier_token = WrToken::decode(record.user_ctx)?;
        let (frontier_signaled, frontier_sequence) = {
            let frontier_entry = self.outstanding_for(record.user_ctx)?;
            (frontier_entry.signaled, frontier_entry.sequence)
        };
        let stats = self
            .send_stats_by_peer
            .entry(frontier_token.peer_id)
            .or_default();
        stats.cqes = stats.cqes.saturating_add(1);
        if record.status == 0 && !frontier_signaled {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(
                "successful SEND CQE corresponds to an unsignaled WR".into(),
            ));
        }
        let completion_error = if recv_queue || record.is_recv || !record.is_jetty {
            Some(Error::Protocol("CQE queue/operation flags disagree".into()))
        } else if record.status != 0 {
            Some(Error::Completion {
                status: record.status,
                opcode: record.opcode,
                user_ctx: record.user_ctx,
                sequence: frontier_sequence,
                post_call: None,
            })
        } else {
            None
        };

        if completion_error.is_some() {
            self.stats.cqe_error += 1;
        } else {
            self.stats.send_cqe += 1;
        }
        let mut first_routing_error = None;
        for index in 0..=frontier {
            let user_ctx = self
                .send_order
                .pop_front()
                .expect("frontier position proves a queued SEND");
            let token = WrToken::decode(user_ctx)?;
            let stats = self.send_stats_by_peer.entry(token.peer_id).or_default();
            stats.retired = stats.retired.saturating_add(1);
            let mut outstanding = self.take_outstanding(user_ctx)?;
            outstanding
                .handle
                .take()
                .expect("committed outstanding WR has a native handle")
                .complete();
            self.outstanding_send -= 1;

            let result = if index == frontier {
                completion_error
                    .as_ref()
                    .map_or(Ok(RoutedCompletion::RegisteredTx), |error| {
                        Err(error.clone())
                    })
            } else {
                Ok(RoutedCompletion::RegisteredTx)
            };
            let result = if matches!(
                outstanding.completion,
                Some(CompletionTarget::RegisteredTx(_))
            ) {
                match pool.complete_tx_lease_send(token.slot) {
                    Ok(()) => result,
                    Err(error) => {
                        if first_routing_error.is_none() {
                            first_routing_error = Some(error.clone());
                        }
                        Err(error)
                    }
                }
            } else {
                let error =
                    Error::Protocol("SEND frontier entry has no registered TX owner".into());
                let cleanup_error = pool
                    .complete_error(token.slot, token.operation)
                    .and_then(|()| pool.release(token.slot))
                    .err();
                if first_routing_error.is_none() {
                    first_routing_error = Some(cleanup_error.unwrap_or_else(|| error.clone()));
                }
                Err(error)
            };
            if let Some(completion) = outstanding.completion.take() {
                completion.send(result);
            }
        }

        if let Some(error) = first_routing_error {
            return Err(error);
        }

        match completion_error {
            Some(Error::Completion { .. }) if retiring => Ok(()),
            Some(Error::Completion { .. }) if source.is_some() => {
                let peer_id = source.expect("known source checked above");
                if !self.failed_peers.contains(&peer_id) {
                    self.failed_peers.push(peer_id);
                }
                Ok(())
            }
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn outstanding_for(&self, user_ctx: u64) -> Result<&OutstandingWr> {
        let token = WrToken::decode(user_ctx)?;
        self.outstanding
            .get(token.slot.index())
            .and_then(Option::as_ref)
            .filter(|outstanding| outstanding.user_ctx == user_ctx && outstanding.handle.is_some())
            .ok_or_else(|| Error::Protocol("CQE has no outstanding WR".into()))
    }

    /// A receive CQE has already consumed its provider-side RQE even when its
    /// source or routing token is invalid. Retire the trusted local physical
    /// ownership before propagating the logical routing failure; otherwise no
    /// later CQE (including endpoint flush) can release this WR and slot.
    fn retire_rejected_recv(
        &mut self,
        user_ctx: u64,
        pool: &mut UrmaBufferPool,
        error: Error,
    ) -> Result<()> {
        let token = WrToken::decode(user_ctx)?;
        if token.operation != OperationType::Recv || token.peer_id != 0 {
            return Err(Error::Protocol(
                "rejected shared RX CQE does not reference an anonymous RECV WR".into(),
            ));
        }
        let mut outstanding = self.take_outstanding(user_ctx)?;
        outstanding
            .handle
            .take()
            .expect("committed outstanding WR has a native handle")
            .complete();
        self.outstanding_recv -= 1;
        self.stats.recv_cqe += 1;
        pool.complete_error(token.slot, OperationType::Recv)?;
        pool.release(token.slot)?;
        if let Some(completion) = outstanding.completion.take() {
            completion.send(Err(error.clone()));
        }
        Err(error)
    }

    fn route_flush_done(&mut self, record: ffi::CompletionRecord, recv_queue: bool) -> Result<()> {
        if recv_queue {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(
                "WR_FLUSH_ERR_DONE arrived on the receive JFC".into(),
            ));
        }
        let endpoint = self.endpoint.as_mut().ok_or_else(|| {
            Error::Protocol("WR_FLUSH_ERR_DONE arrived without a shared RM endpoint".into())
        })?;
        if endpoint.jetty_id != record.local_id {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(format!(
                "WR_FLUSH_ERR_DONE references unknown native Jetty {}",
                record.local_id
            )));
        }
        if !endpoint.waiting_for_flush {
            self.stats.cqe_error += 1;
            return Err(Error::Protocol(
                "shared RM endpoint received WR_FLUSH_ERR_DONE before retirement".into(),
            ));
        }
        endpoint.flush_done = true;
        tracing::debug!(
            native_jetty_id = record.local_id,
            "received URMA shared endpoint flush completion"
        );
        Ok(())
    }

    fn take_outstanding(&mut self, user_ctx: u64) -> Result<OutstandingWr> {
        let token = WrToken::decode(user_ctx)?;
        let entry = self
            .outstanding
            .get_mut(token.slot.index())
            .ok_or_else(|| Error::Protocol("CQE slot is outside outstanding table".into()))?;
        if !entry.as_ref().is_some_and(|outstanding| {
            outstanding.user_ctx == user_ctx && outstanding.handle.is_some()
        }) {
            return Err(Error::Protocol("CQE has no outstanding WR".into()));
        }
        self.outstanding_total -= 1;
        if token.peer_id != 0 {
            let peer_count = self
                .outstanding_by_peer
                .get_mut(&token.peer_id)
                .ok_or_else(|| Error::Protocol("CQE PeerTarget has no outstanding WR".into()))?;
            *peer_count -= 1;
            if *peer_count == 0 {
                self.outstanding_by_peer.remove(&token.peer_id);
            }
        }
        Ok(entry.take().expect("entry checked above"))
    }

    fn decrement_operation(&mut self, operation: OperationType) {
        match operation {
            OperationType::Send => self.outstanding_send -= 1,
            OperationType::Recv => self.outstanding_recv -= 1,
        }
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding_total
    }

    pub(crate) fn outstanding_recv(&self) -> usize {
        self.outstanding_recv
    }

    pub(crate) fn logical_rx_credits(&self) -> usize {
        self.targets.routing_token_count()
    }

    pub(crate) fn outstanding_for_peer(&self, peer_id: u16) -> usize {
        self.outstanding_by_peer
            .get(&peer_id)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn take_failed_peers(&mut self) -> Vec<u16> {
        std::mem::take(&mut self.failed_peers)
    }

    /// Wakes every logical waiter after a fatal progress failure without
    /// releasing native WR or buffer ownership. Later CQEs still retire those
    /// resources through the normal route path.
    pub(crate) fn fail_pending(&mut self, error: &Error) {
        for completion in self.targets.drain_all_routing_tokens() {
            let _ = completion.send(Err(error.clone()));
        }
        for outstanding in self.outstanding.iter_mut().flatten() {
            if let Some(completion) = outstanding.completion.take() {
                completion.fail(error.clone());
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> CompletionStats {
        self.stats
    }
}

/// A provider poll consumes the complete batch. Route every record even when
/// one record fails, otherwise later WR ownership and buffer slots are lost.
fn drain_batch<T, E>(
    records: impl IntoIterator<Item = T>,
    mut route: impl FnMut(T) -> std::result::Result<(), E>,
) -> std::result::Result<usize, E> {
    let mut routed = 0;
    let mut first_error = None;
    for record in records {
        match route(record) {
            Ok(()) => routed += 1,
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    first_error.map_or(Ok(routed), Err)
}

pub(crate) fn deadline_after(timeout: std::time::Duration) -> Instant {
    Instant::now() + timeout
}

pub(crate) fn deadline_expired(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::buffer::{
        LeaseBook, LeaseKind, LeaseRecycleNotifier, SlotId, SlotKind, SlotState, UrmaBufferPool,
    };
    use std::sync::{Arc, Mutex};

    fn authorize_test_peer(router: &mut CompletionRouter, lane_id: u16) {
        router
            .authorize_remote(
                lane_id,
                1,
                ffi::RemoteJettyId {
                    eid: [lane_id as u8; ffi::EID_SIZE],
                    uasid: u32::from(lane_id),
                    id: u32::from(lane_id),
                },
            )
            .unwrap();
    }

    #[test]
    fn deadline_helper_expires() {
        assert!(deadline_expired(Instant::now()));
    }

    #[test]
    fn completion_router_rejects_invalid_batch() {
        assert!(CompletionRouter::new(0).is_err());
        assert!(CompletionRouter::new(MAX_POLL_BATCH + 1).is_err());
    }

    #[test]
    fn unposted_wr_reservation_can_be_cancelled_without_counting_ownership() {
        let mut router = CompletionRouter::new(4).unwrap();
        let user_ctx = WrToken::anonymous_recv(SlotId::new(3, 1).unwrap())
            .encode()
            .unwrap();

        router.reserve_anonymous_rx(user_ctx, Some(7)).unwrap();
        assert_eq!(router.outstanding(), 0);
        assert!(router.reserve_anonymous_rx(user_ctx, Some(7)).is_err());

        router.cancel_reservation(user_ctx).unwrap();
        router.reserve_anonymous_rx(user_ctx, Some(7)).unwrap();
        router.commit_posted(user_ctx, ffi::WrHandle::without_native());
        assert_eq!(router.outstanding(), 1);
        assert_eq!(router.outstanding_recv(), 1);
    }

    #[test]
    fn shared_jfr_capacity_is_global_across_logical_peers() {
        let mut router = CompletionRouter::new(4).unwrap();
        authorize_test_peer(&mut router, 1);
        let context = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        router
            .track_registered_rx(
                1,
                context,
                ffi::WrHandle::without_native(),
                Some((1u64 << 32) | 1),
                oneshot::channel().0,
            )
            .unwrap();

        assert!(router.ensure_recv_capacity(1, 1).is_err());
        assert!(router.ensure_recv_capacity(1, 2).is_ok());
        assert_eq!(router.outstanding_for_peer(1), 0);
    }

    #[test]
    fn retiring_peer_cancels_logical_rx_without_owning_anonymous_rqe() {
        let mut router = CompletionRouter::new(4).unwrap();
        let remote = ffi::RemoteJettyId {
            eid: [1; ffi::EID_SIZE],
            uasid: 2,
            id: 3,
        };
        router.authorize_remote(7, 1, remote).unwrap();
        let context = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        let (completion, receiver) = oneshot::channel();
        router
            .track_registered_rx(
                7,
                context,
                ffi::WrHandle::without_native(),
                Some((1u64 << 32) | 11),
                completion,
            )
            .unwrap();

        router.begin_peer_retirement(7).unwrap();
        assert!(matches!(
            receiver.blocking_recv().unwrap(),
            Err(Error::Protocol(_))
        ));
        assert_eq!(router.outstanding_for_peer(7), 0);
        router.unregister_peer(7).unwrap();
        assert_eq!(router.outstanding(), 1);
    }

    #[test]
    fn retired_peers_anonymous_rqe_can_be_reassigned_without_another_post() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);
        authorize_test_peer(&mut router, 2);
        let context = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        let old_sequence = RoutingToken::encode(1, 0).unwrap();
        router
            .track_registered_rx(
                1,
                context,
                ffi::WrHandle::without_native(),
                Some(old_sequence),
                oneshot::channel().0,
            )
            .unwrap();
        router.begin_peer_retirement(1).unwrap();
        router.unregister_peer(1).unwrap();
        assert_eq!(router.unassigned_recv_capacity().unwrap(), 1);

        let new_sequence = RoutingToken::encode(2, 0).unwrap();
        let (completion, _receiver) = oneshot::channel();
        router
            .register_rx_window(2, vec![new_sequence], vec![completion])
            .unwrap();
        assert_eq!(router.unassigned_recv_capacity().unwrap(), 0);
        assert_eq!(router.logical_rx_credits(), 1);
        assert_eq!(router.outstanding_recv(), 1);
    }

    #[test]
    fn anonymous_rqe_survives_repeated_peer_churn_without_capacity_growth() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        let context = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        router
            .track_anonymous_rx(context, ffi::WrHandle::without_native(), None)
            .unwrap();

        for peer_id in 1..=32 {
            authorize_test_peer(&mut router, peer_id);
            let sequence = RoutingToken::encode(u32::from(peer_id), 0).unwrap();
            router
                .register_rx_window(peer_id, vec![sequence], vec![oneshot::channel().0])
                .unwrap();
            assert_eq!(router.outstanding_recv(), 1);
            assert_eq!(router.logical_rx_credits(), 1);

            router.begin_peer_retirement(peer_id).unwrap();
            router.unregister_peer(peer_id).unwrap();
            assert_eq!(router.unassigned_recv_capacity().unwrap(), 1);
        }

        assert_eq!(router.outstanding_recv(), 1);
        assert_eq!(router.stats().recv_post, 1);
    }

    #[test]
    fn rejected_receive_route_still_retires_consumed_physical_rqe() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);
        let context = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        let sequence = RoutingToken::encode(1, 0).unwrap();
        let (completion, receiver) = oneshot::channel();
        router
            .track_registered_rx(
                1,
                context,
                ffi::WrHandle::without_native(),
                Some(sequence),
                completion,
            )
            .unwrap();
        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Rx, SlotState::PostedRecv)]);

        assert!(router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    opcode: ffi::CR_OPCODE_SEND_WITH_IMM,
                    user_ctx: context,
                    imm_data: sequence,
                    completion_len: 1,
                    local_id: 101,
                    remote_id: Some(ffi::RemoteJettyId {
                        eid: [9; ffi::EID_SIZE],
                        uasid: 9,
                        id: 9,
                    }),
                    is_recv: true,
                    is_jetty: true,
                    user_ctx_valid: true,
                    imm_data_valid: true,
                    ..Default::default()
                },
                true,
                &mut pool,
            )
            .is_err());
        assert_eq!(router.outstanding_recv(), 0);
        assert_eq!(pool.rx_state_counts().free, 1);
        router.fail_pending(&Error::Protocol("fabric failed".into()));
        assert!(matches!(
            receiver.blocking_recv().unwrap(),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn batch_drain_routes_records_after_an_error() {
        let mut visited = Vec::new();
        let result = drain_batch(0..4, |record| {
            visited.push(record);
            if record == 1 {
                Err("first failure")
            } else if record == 2 {
                Err("later failure")
            } else {
                Ok(())
            }
        });

        assert_eq!(visited, vec![0, 1, 2, 3]);
        assert_eq!(result, Err("first failure"));
    }

    #[test]
    fn registered_completion_preserves_lease_ownership_across_oneshot() {
        let mut leases = LeaseBook::new();
        let recycle = leases
            .issue(LeaseKind::Rx, vec![SlotId::new(2, 5).unwrap()])
            .unwrap();
        let returned = Arc::new(Mutex::new(None));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| *returned.lock().unwrap() = Some(recycle))
        };
        let lease =
            RegisteredRxWindowLease::from_test_parts(vec![vec![7, 8, 9]], recycle, notifier);
        let (tx, rx) = oneshot::channel();
        CompletionTarget::RegisteredRx(tx).send(Ok(RoutedCompletion::RegisteredRx(
            RegisteredRxCompletion {
                lane_id: 4,
                posted_sequence: Some(12),
                imm_data: 12,
                slot: SlotId::new(2, 5).unwrap(),
                lease,
            },
        )));

        let completion = rx.blocking_recv().unwrap().unwrap();
        assert_eq!(completion.lane_id, 4);
        assert_eq!(completion.posted_sequence, Some(12));
        assert_eq!(completion.imm_data, 12);
        assert_eq!(completion.slot, SlotId::new(2, 5).unwrap());
        assert_eq!(completion.lease.parts().next().unwrap(), &[7, 8, 9]);
        drop(completion);
        assert_eq!(*returned.lock().unwrap(), Some(recycle));
    }

    #[test]
    fn registered_rx_identity_routes_across_posted_wr_ownership() {
        let mut router = CompletionRouter::new(4).unwrap();
        authorize_test_peer(&mut router, 1);
        let sequence_a = (7u64 << 32) | 3;
        let sequence_b = (8u64 << 32) | 5;
        let context_a = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        let context_b = WrToken::anonymous_recv(SlotId::new(1, 1).unwrap())
            .encode()
            .unwrap();
        let (completion_a, receiver_a) = oneshot::channel();
        let (completion_b, receiver_b) = oneshot::channel();
        router
            .track_registered_rx(
                1,
                context_a,
                ffi::WrHandle::without_native(),
                Some(sequence_a),
                completion_a,
            )
            .unwrap();
        router
            .track_registered_rx(
                1,
                context_b,
                ffi::WrHandle::without_native(),
                Some(sequence_b),
                completion_b,
            )
            .unwrap();

        // Provider matching crosses the two logical transfers: the CQE for
        // posted WR A carries B's SEND_IMM identity, and vice versa. Logical
        // ownership follows SEND_IMM while the actual slot remains attached
        // to the WR that completed.
        assert!(router
            .take_registered_rx(1, sequence_b)
            .unwrap()
            .send(Ok(RegisteredRxCompletion {
                lane_id: 1,
                posted_sequence: Some(sequence_a),
                imm_data: sequence_b,
                slot: SlotId::new(0, 1).unwrap(),
                lease: RegisteredRxWindowLease::from_test_untracked_parts(vec![vec![2; 4]]),
            }))
            .is_ok());
        assert!(router
            .take_registered_rx(1, sequence_a)
            .unwrap()
            .send(Ok(RegisteredRxCompletion {
                lane_id: 1,
                posted_sequence: Some(sequence_b),
                imm_data: sequence_a,
                slot: SlotId::new(1, 1).unwrap(),
                lease: RegisteredRxWindowLease::from_test_untracked_parts(vec![vec![1; 4]]),
            }))
            .is_ok());

        let routed_a = receiver_a.blocking_recv().unwrap().unwrap();
        let routed_b = receiver_b.blocking_recv().unwrap().unwrap();
        assert_eq!(routed_a.imm_data, sequence_a);
        assert_eq!(routed_a.posted_sequence, Some(sequence_b));
        assert_eq!(routed_a.slot, SlotId::new(1, 1).unwrap());
        assert_eq!(routed_b.imm_data, sequence_b);
        assert_eq!(routed_b.posted_sequence, Some(sequence_a));
        assert_eq!(routed_b.slot, SlotId::new(0, 1).unwrap());
        assert!(router.take_registered_rx(1, sequence_a).is_err());
    }

    #[test]
    fn registered_rx_identity_preflight_is_peer_scoped_and_fails_pending() {
        let mut router = CompletionRouter::new(4).unwrap();
        authorize_test_peer(&mut router, 1);
        authorize_test_peer(&mut router, 2);
        let sequence = (7u64 << 32) | 3;
        assert!(router
            .validate_registered_rx_identities(1, &[sequence, sequence])
            .is_err());

        let context = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        let (completion, receiver) = oneshot::channel();
        router
            .track_registered_rx(
                1,
                context,
                ffi::WrHandle::without_native(),
                Some(sequence),
                completion,
            )
            .unwrap();
        assert!(router
            .validate_registered_rx_identities(1, &[sequence])
            .is_err());
        assert!(router
            .validate_registered_rx_identities(2, &[sequence])
            .is_ok());

        router.fail_pending(&Error::Protocol("fabric failed".into()));
        assert!(matches!(
            receiver.blocking_recv().unwrap(),
            Err(Error::Protocol(_))
        ));
        assert!(router.take_registered_rx(1, sequence).is_err());
    }

    #[test]
    fn registered_tx_window_returns_lease_only_after_every_cqe() {
        let slots = vec![SlotId::new(0, 1).unwrap(), SlotId::new(1, 1).unwrap()];
        let mut leases = LeaseBook::new();
        let recycle = leases.issue(LeaseKind::Tx, slots).unwrap();
        let returned = Arc::new(Mutex::new(None));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| *returned.lock().unwrap() = Some(recycle))
        };
        let lease = TxWindowLease::from_test_parts(vec![4, 1], recycle, notifier);
        let (tx, mut rx) = oneshot::channel();
        let state = RegisteredTxWindowState::new(7, vec![10, 11], lease, tx);
        state.posted();
        state.posted();
        state.finish_posting(None);

        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(*returned.lock().unwrap(), None);

        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        let completion = rx.blocking_recv().unwrap().unwrap();
        assert_eq!(completion.lane_id, 7);
        assert_eq!(completion.sequences, vec![10, 11]);
        assert_eq!(completion.lease.len(), 5);
        drop(completion);
        assert_eq!(*returned.lock().unwrap(), Some(recycle));
    }

    #[test]
    fn partial_post_failure_waits_only_for_the_submitted_prefix() {
        let slots = vec![
            SlotId::new(0, 1).unwrap(),
            SlotId::new(1, 1).unwrap(),
            SlotId::new(2, 1).unwrap(),
        ];
        let mut leases = LeaseBook::new();
        let recycle = leases.issue(LeaseKind::Tx, slots).unwrap();
        let returned = Arc::new(Mutex::new(None));
        let notifier: LeaseRecycleNotifier = {
            let returned = returned.clone();
            Arc::new(move |recycle| *returned.lock().unwrap() = Some(recycle))
        };
        let lease = TxWindowLease::from_test_parts(vec![4, 4, 4], recycle, notifier);
        let (tx, mut rx) = oneshot::channel();
        let state = RegisteredTxWindowState::new(3, vec![20, 21, 22], lease, tx);

        // The provider accepted only the first two WRs. The unposted suffix
        // owns no CQE and must not extend the lease's completion gate.
        state.posted();
        state.posted();
        state.finish_posting(Some(Error::Protocol("partial post".into())));
        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        state.completed(&Ok(RoutedCompletion::RegisteredTx));
        assert!(matches!(
            rx.blocking_recv().unwrap(),
            Err(Error::Protocol(_))
        ));
        assert_eq!(*returned.lock().unwrap(), Some(recycle));
    }

    #[test]
    fn flush_done_is_routed_by_native_jetty_id_and_gates_shutdown() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 202).unwrap();
        assert!(router.endpoint_ready_to_close());
        router.begin_endpoint_flush();
        assert!(router.has_pending_flush());
        assert!(!router.endpoint_ready_to_close());

        router
            .route_flush_done(
                ffi::CompletionRecord {
                    status: 13,
                    local_id: 101,
                    event_kind: ffi::CompletionEventKind::FlushErrorDone,
                    ..Default::default()
                },
                false,
            )
            .unwrap();

        assert!(router.endpoint_ready_to_close());
        assert!(!router.has_pending_flush());
    }

    #[test]
    fn flush_done_requires_endpoint_retirement_and_known_jetty() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(303, 404).unwrap();
        let record = ffi::CompletionRecord {
            status: 13,
            local_id: 303,
            event_kind: ffi::CompletionEventKind::FlushErrorDone,
            ..Default::default()
        };
        // Without an armed endpoint flush, the lifecycle CQE must be rejected.
        assert!(router.route_flush_done(record, false).is_err());
        router.begin_endpoint_flush();
        assert!(router.route_flush_done(record, true).is_err());
        assert!(router
            .route_flush_done(
                ffi::CompletionRecord {
                    local_id: 999,
                    ..record
                },
                false,
            )
            .is_err());
    }

    #[test]
    fn shutdown_waits_for_anonymous_rx_and_flush_after_peer_retirement() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);
        let recv_ctx = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        let (completion, receiver) = oneshot::channel();
        router
            .track_registered_rx(
                1,
                recv_ctx,
                ffi::WrHandle::without_native(),
                Some(RoutingToken::encode(1, 1).unwrap()),
                completion,
            )
            .unwrap();

        // Peer retirement cancels only logical routing ownership. The
        // anonymous native RQE remains endpoint-owned until its flush CQE.
        router.begin_peer_retirement(1).unwrap();
        assert!(matches!(
            receiver.blocking_recv().unwrap(),
            Err(Error::Protocol(_))
        ));
        router.unregister_peer(1).unwrap();
        assert_eq!(router.outstanding(), 1);
        assert!(router.begin_endpoint_flush());
        assert!(!router.endpoint_ready_to_close());

        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Rx, SlotState::PostedRecv)]);
        router
            .route(
                ffi::CompletionRecord {
                    status: 11,
                    user_ctx: recv_ctx,
                    user_ctx_valid: true,
                    is_recv: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                true,
                &mut pool,
            )
            .unwrap();
        assert_eq!(router.outstanding(), 0);
        assert!(!router.endpoint_ready_to_close());

        router
            .route_flush_done(
                ffi::CompletionRecord {
                    status: 13,
                    local_id: 101,
                    event_kind: ffi::CompletionEventKind::FlushErrorDone,
                    ..Default::default()
                },
                false,
            )
            .unwrap();
        assert!(router.endpoint_ready_to_close());
    }

    #[test]
    fn send_cqe_fails_closed_on_unknown_native_jetty() {
        // UMDK stamps local_id = jetty->jetty_id.id with is_jetty=1 on both
        // SEND and RECV CQEs of the shared-JFR endpoint, so a CQE whose
        // native Jetty (102) does not name the registered shared endpoint
        // (101) carries corrupt routing identity. The router must fail closed
        // without consuming the WR ownership referenced by the untrusted
        // user_ctx; the poll error then fails the fabric owner.
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);

        let send_ctx = WrToken {
            peer_id: 1,
            generation: 1,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        router
            .track_registered_tx(
                send_ctx,
                ffi::WrHandle::without_native(),
                7,
                RegisteredTxWindowState::new(
                    1,
                    vec![7],
                    TxWindowLease::from_test_lengths(vec![8]),
                    oneshot::channel().0,
                ),
            )
            .unwrap();

        // The pool is never consulted: the CQE is rejected before ownership
        // is touched.
        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Tx, SlotState::SendPosted)]);

        let error = router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: send_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 102,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .expect_err("unknown native Jetty identity must fail closed");
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        assert_eq!(router.outstanding(), 1);
        assert_eq!(router.outstanding_for_peer(1), 1);
    }

    #[test]
    fn recv_cqe_fails_closed_on_unknown_native_jetty() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);

        let recv_ctx = WrToken::anonymous_recv(SlotId::new(0, 1).unwrap())
            .encode()
            .unwrap();
        router
            .track_registered_rx(
                1,
                recv_ctx,
                ffi::WrHandle::without_native(),
                Some((1u64 << 32) | 1),
                oneshot::channel().0,
            )
            .unwrap();

        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Rx, SlotState::PostedRecv)]);

        let error = router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: recv_ctx,
                    user_ctx_valid: true,
                    is_recv: true,
                    is_jetty: true,
                    local_id: 102,
                    ..Default::default()
                },
                true,
                &mut pool,
            )
            .expect_err("unknown native Jetty identity must fail closed");
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        assert_eq!(router.outstanding(), 1);
        assert_eq!(router.outstanding_for_peer(1), 0);
    }

    #[test]
    fn send_cqe_routes_when_native_jetty_matches_shared_endpoint() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);

        let send_ctx = WrToken {
            peer_id: 1,
            generation: 1,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        router
            .track_registered_tx(
                send_ctx,
                ffi::WrHandle::without_native(),
                7,
                RegisteredTxWindowState::new(
                    1,
                    vec![7],
                    TxWindowLease::from_test_lengths(vec![8]),
                    oneshot::channel().0,
                ),
            )
            .unwrap();

        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Tx, SlotState::SendPosted)]);

        router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: send_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .expect("matching native Jetty identity must route");
        assert_eq!(router.outstanding(), 0);
    }

    #[test]
    fn signaled_send_cqe_retires_preceding_unsignaled_prefix() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);
        let contexts = (0..3)
            .map(|index| {
                WrToken {
                    peer_id: 1,
                    generation: 1,
                    operation: OperationType::Send,
                    slot: SlotId::new(index, 1).unwrap(),
                }
                .encode()
                .unwrap()
            })
            .collect::<Vec<_>>();
        let (completion, receiver) = oneshot::channel();
        let state = RegisteredTxWindowState::new(
            1,
            vec![10, 11, 12],
            TxWindowLease::from_test_lengths(vec![8, 8, 8]),
            completion,
        );
        for (index, &user_ctx) in contexts.iter().enumerate() {
            router
                .track_registered_tx_with_signal(
                    user_ctx,
                    ffi::WrHandle::without_native(),
                    10 + index as u64,
                    index == 2,
                    state.clone(),
                )
                .unwrap();
        }
        state.finish_posting(None);
        let mut pool = UrmaBufferPool::from_test_slot_states(&[
            (SlotKind::Tx, SlotState::SendPosted),
            (SlotKind::Tx, SlotState::SendPosted),
            (SlotKind::Tx, SlotState::SendPosted),
        ]);

        router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: contexts[2],
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .unwrap();

        let completion = receiver.blocking_recv().unwrap().unwrap();
        assert_eq!(completion.sequences, vec![10, 11, 12]);
        assert_eq!(router.outstanding(), 0);
        assert_eq!(router.outstanding_for_peer(1), 0);
        assert_eq!(router.stats().send_post, 3);
        assert_eq!(router.stats().send_cqe, 1);
        assert_eq!(
            router.send_stats_by_peer.get(&1),
            Some(&PeerSendCompletionStats {
                posted: 3,
                retired: 3,
                cqes: 1,
            })
        );
        router.begin_peer_retirement(1).unwrap();
        router.unregister_peer(1).unwrap();
        assert!(!router.send_stats_by_peer.contains_key(&1));
    }

    #[test]
    fn successful_cqe_for_unsignaled_send_fails_without_releasing_prefix() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);
        let user_ctx = WrToken {
            peer_id: 1,
            generation: 1,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        router
            .track_registered_tx_with_signal(
                user_ctx,
                ffi::WrHandle::without_native(),
                7,
                false,
                RegisteredTxWindowState::new(
                    1,
                    vec![7],
                    TxWindowLease::from_test_lengths(vec![8]),
                    oneshot::channel().0,
                ),
            )
            .unwrap();
        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Tx, SlotState::SendPosted)]);

        assert!(router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .is_err());
        assert_eq!(router.outstanding(), 1);
        assert_eq!(router.outstanding_for_peer(1), 1);
    }

    #[test]
    fn error_cqe_may_name_unsignaled_send_and_later_frontier_still_drains() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);
        let contexts = (0..2)
            .map(|index| {
                WrToken {
                    peer_id: 1,
                    generation: 1,
                    operation: OperationType::Send,
                    slot: SlotId::new(index, 1).unwrap(),
                }
                .encode()
                .unwrap()
            })
            .collect::<Vec<_>>();
        let (completion, mut receiver) = oneshot::channel();
        let state = RegisteredTxWindowState::new(
            1,
            vec![10, 11],
            TxWindowLease::from_test_lengths(vec![8, 8]),
            completion,
        );
        for (index, &user_ctx) in contexts.iter().enumerate() {
            router
                .track_registered_tx_with_signal(
                    user_ctx,
                    ffi::WrHandle::without_native(),
                    10 + index as u64,
                    index == 1,
                    state.clone(),
                )
                .unwrap();
        }
        state.finish_posting(None);
        let mut pool = UrmaBufferPool::from_test_slot_states(&[
            (SlotKind::Tx, SlotState::SendPosted),
            (SlotKind::Tx, SlotState::SendPosted),
        ]);

        router
            .route(
                ffi::CompletionRecord {
                    status: 9,
                    user_ctx: contexts[0],
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(router.outstanding(), 1);

        router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: contexts[1],
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .unwrap();
        assert!(matches!(
            receiver.blocking_recv().unwrap(),
            Err(Error::Completion { status: 9, .. })
        ));
        assert_eq!(router.outstanding(), 0);
        assert_eq!(router.take_failed_peers(), vec![1]);
    }

    #[test]
    fn peer_send_error_retires_only_that_peer_while_sibling_continues() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        authorize_test_peer(&mut router, 1);
        authorize_test_peer(&mut router, 2);
        let peer_1_ctx = WrToken {
            peer_id: 1,
            generation: 1,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        let peer_2_ctx = WrToken {
            peer_id: 2,
            generation: 1,
            operation: OperationType::Send,
            slot: SlotId::new(1, 1).unwrap(),
        }
        .encode()
        .unwrap();
        let (peer_1_completion, peer_1_receiver) = oneshot::channel();
        let peer_1_state = RegisteredTxWindowState::new(
            1,
            vec![7],
            TxWindowLease::from_test_lengths(vec![8]),
            peer_1_completion,
        );
        router
            .track_registered_tx(
                peer_1_ctx,
                ffi::WrHandle::without_native(),
                7,
                peer_1_state.clone(),
            )
            .unwrap();
        peer_1_state.finish_posting(None);
        let (peer_2_completion, peer_2_receiver) = oneshot::channel();
        let peer_2_state = RegisteredTxWindowState::new(
            2,
            vec![8],
            TxWindowLease::from_test_lengths(vec![8]),
            peer_2_completion,
        );
        router
            .track_registered_tx(
                peer_2_ctx,
                ffi::WrHandle::without_native(),
                8,
                peer_2_state.clone(),
            )
            .unwrap();
        peer_2_state.finish_posting(None);
        let mut pool = UrmaBufferPool::from_test_slot_states(&[
            (SlotKind::Tx, SlotState::SendPosted),
            (SlotKind::Tx, SlotState::SendPosted),
        ]);

        router
            .route(
                ffi::CompletionRecord {
                    status: 9,
                    user_ctx: peer_1_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .unwrap();

        assert!(matches!(
            peer_1_receiver.blocking_recv().unwrap(),
            Err(Error::Completion { status: 9, .. })
        ));
        assert_eq!(router.take_failed_peers(), vec![1]);
        assert_eq!(router.outstanding_for_peer(1), 0);
        assert_eq!(router.outstanding_for_peer(2), 1);

        router.begin_peer_retirement(1).unwrap();
        assert!(router.validate_send_owner(1, 1).is_err());
        router.validate_send_owner(2, 1).unwrap();
        router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: peer_2_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .unwrap();

        let peer_2_completion = peer_2_receiver.blocking_recv().unwrap().unwrap();
        assert_eq!(peer_2_completion.lane_id, 2);
        assert_eq!(router.outstanding(), 0);
        router.unregister_peer(1).unwrap();
        router.validate_send_owner(2, 1).unwrap();
    }

    #[test]
    fn stale_send_generation_is_rejected_before_outstanding_registration() {
        let mut router = CompletionRouter::new(4).unwrap();
        authorize_test_peer(&mut router, 7);
        let stale_ctx = WrToken {
            peer_id: 7,
            generation: 2,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();

        assert!(router
            .track_registered_tx(
                stale_ctx,
                ffi::WrHandle::without_native(),
                9,
                RegisteredTxWindowState::new(
                    7,
                    vec![9],
                    TxWindowLease::from_test_lengths(vec![8]),
                    oneshot::channel().0,
                ),
            )
            .is_err());
        assert_eq!(router.outstanding(), 0);
        assert_eq!(router.outstanding_for_peer(7), 0);
    }

    #[test]
    fn late_send_cqe_cannot_consume_current_generation_ownership() {
        let mut router = CompletionRouter::new(4).unwrap();
        router.register_endpoint(101, 201).unwrap();
        router
            .authorize_remote(
                7,
                2,
                ffi::RemoteJettyId {
                    eid: [7; ffi::EID_SIZE],
                    uasid: 7,
                    id: 7,
                },
            )
            .unwrap();
        let current_ctx = WrToken {
            peer_id: 7,
            generation: 2,
            operation: OperationType::Send,
            slot: SlotId::new(0, 1).unwrap(),
        }
        .encode()
        .unwrap();
        let late_ctx = WrToken {
            generation: 1,
            ..WrToken::decode(current_ctx).unwrap()
        }
        .encode()
        .unwrap();
        let (completion, receiver) = oneshot::channel();
        let state = RegisteredTxWindowState::new(
            7,
            vec![9],
            TxWindowLease::from_test_lengths(vec![8]),
            completion,
        );
        router
            .track_registered_tx(
                current_ctx,
                ffi::WrHandle::without_native(),
                9,
                state.clone(),
            )
            .unwrap();
        state.finish_posting(None);
        let mut pool =
            UrmaBufferPool::from_test_slot_states(&[(SlotKind::Tx, SlotState::SendPosted)]);

        assert!(router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: late_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .is_err());
        assert_eq!(router.outstanding(), 1);
        assert_eq!(router.outstanding_for_peer(7), 1);

        router
            .route(
                ffi::CompletionRecord {
                    status: 0,
                    user_ctx: current_ctx,
                    user_ctx_valid: true,
                    is_jetty: true,
                    local_id: 101,
                    ..Default::default()
                },
                false,
                &mut pool,
            )
            .unwrap();
        assert_eq!(receiver.blocking_recv().unwrap().unwrap().lane_id, 7);
        assert_eq!(router.outstanding(), 0);
    }

    #[test]
    fn send_imm_receive_identity_preserves_full_64_bits() {
        let identity = 0xfedc_ba98_7654_3210;
        let record = ffi::CompletionRecord {
            opcode: ffi::CR_OPCODE_SEND_WITH_IMM,
            imm_data: identity,
            imm_data_valid: true,
            ..Default::default()
        };
        assert_eq!(validate_recv_immediate(record), Ok(identity));
    }

    #[test]
    fn ordinary_send_or_invalid_immediate_flag_is_rejected() {
        let ordinary_send = ffi::CompletionRecord {
            // shim.c statically verifies UMDK's ordinary SEND CQE opcode is 0.
            opcode: 0,
            imm_data: 7,
            imm_data_valid: false,
            ..Default::default()
        };
        assert!(validate_recv_immediate(ordinary_send).is_err());

        let invalid_flag = ffi::CompletionRecord {
            opcode: ffi::CR_OPCODE_SEND_WITH_IMM,
            imm_data: 7,
            imm_data_valid: false,
            ..Default::default()
        };
        assert!(validate_recv_immediate(invalid_flag).is_err());
    }

    #[test]
    fn receive_source_authorization_is_full_identity_and_fail_closed() {
        let mut router = CompletionRouter::new(4).unwrap();
        let token_a = (7u64 << 32) | 99;
        let token_b = (8u64 << 32) | 100;
        let expected = ffi::RemoteJettyId {
            eid: [7; ffi::EID_SIZE],
            uasid: 11,
            id: 13,
        };
        let different = ffi::RemoteJettyId { id: 14, ..expected };

        // Without an authorized PeerTarget the remote identity resolves to
        // nothing: fail closed.
        assert!(matches!(
            router.resolve_source(Some(expected), token_a),
            Err(Error::Protocol(_))
        ));
        router.authorize_remote(1, 1, expected).unwrap();
        router
            .targets
            .register_routing_token(
                1,
                RoutingToken::decode(token_a).unwrap(),
                oneshot::channel().0,
            )
            .unwrap();
        assert_eq!(router.resolve_source(Some(expected), token_a).unwrap(), 1);
        assert!(matches!(
            router.resolve_source(None, token_a),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            router.resolve_source(Some(different), token_a),
            Err(Error::Protocol(_))
        ));
        // An unassigned remote identity (id 0) must also fail closed.
        assert!(matches!(
            router.resolve_source(Some(ffi::RemoteJettyId { id: 0, ..expected }), token_a),
            Err(Error::Protocol(_))
        ));

        // Rebinding the same PeerTarget to a new remote identity for a new
        // generation is rejected while the old binding stays authoritative.
        assert!(router.authorize_remote(1, 2, different).is_err());
        assert_eq!(router.resolve_source(Some(expected), token_a).unwrap(), 1);
        // A second control session may alias the same process-wide endpoint;
        // its distinct routing tokens disambiguate receive ownership.
        router.authorize_remote(2, 1, expected).unwrap();
        router
            .targets
            .register_routing_token(
                2,
                RoutingToken::decode(token_b).unwrap(),
                oneshot::channel().0,
            )
            .unwrap();
        assert_eq!(router.resolve_source(Some(expected), token_b).unwrap(), 2);
        router
            .targets
            .register_routing_token(
                2,
                RoutingToken::decode(token_a).unwrap(),
                oneshot::channel().0,
            )
            .unwrap();
        assert!(matches!(
            router.resolve_source(Some(expected), token_a),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn receive_route_failures_are_classified_without_peer_cardinality() {
        let mut router = CompletionRouter::new(4).unwrap();
        let remote = ffi::RemoteJettyId {
            eid: [9; ffi::EID_SIZE],
            uasid: 9,
            id: 9,
        };
        let token = RoutingToken::encode(4, 2).unwrap();

        assert_eq!(
            router.classify_source(None, token),
            Err(RxRouteFailure::MissingSource)
        );
        assert_eq!(
            router.classify_source(Some(remote), token),
            Err(RxRouteFailure::UnauthorizedSource)
        );
        router.authorize_remote(1, 1, remote).unwrap();
        assert_eq!(
            router.classify_source(Some(remote), token),
            Err(RxRouteFailure::StaleToken)
        );
        assert_eq!(
            router.classify_source(Some(remote), 2),
            Err(RxRouteFailure::InvalidToken)
        );
        router.authorize_remote(2, 1, remote).unwrap();
        let decoded = RoutingToken::decode(token).unwrap();
        router
            .targets
            .register_routing_token(1, decoded, oneshot::channel().0)
            .unwrap();
        assert_eq!(
            router.classify_source(Some(remote), RoutingToken::encode(4, 3).unwrap()),
            Err(RxRouteFailure::OverCredit)
        );
        router
            .targets
            .register_routing_token(2, decoded, oneshot::channel().0)
            .unwrap();
        assert_eq!(
            router.classify_source(Some(remote), token),
            Err(RxRouteFailure::AmbiguousToken)
        );

        for failure in [
            RxRouteFailure::MissingSource,
            RxRouteFailure::UnauthorizedSource,
            RxRouteFailure::InvalidToken,
            RxRouteFailure::StaleToken,
            RxRouteFailure::OverCredit,
            RxRouteFailure::AmbiguousToken,
        ] {
            router.record_rx_route_failure(failure);
        }
        let stats = router.stats();
        assert_eq!(stats.rx_unknown_source, 2);
        assert_eq!(stats.rx_invalid_token, 1);
        assert_eq!(stats.rx_stale_token, 1);
        assert_eq!(stats.rx_over_credit, 1);
        assert_eq!(stats.rx_ambiguous_token, 1);
    }
}
