//! Bounded-by-admission source executor. Native sources never leave their
//! worker. Only owned immutable backing, identities, proofs and DTOs cross.
use super::{
    ffi::{
        read::{
            source::{ReadBacking, ReadSourceStages, SourceContext, SourceRegistration},
            ReadDescriptor, ReadToken,
        },
        FfiError,
    },
    read_owner::{ReadOwnerId, ReapDecision},
    read_source_owner::{SourceOwner, SourceRevoked, UnregisterPermit},
    runtime::ReadSourceAdmission,
    Error, Result,
};
use std::time::Instant;
use std::{
    collections::BTreeMap,
    sync::mpsc,
    thread::{self, JoinHandle},
};
use tokio::sync::oneshot;

pub(crate) enum Registration {
    Ready {
        descriptor: ReadDescriptor,
        token: ReadToken,
        stages: ReadSourceStages,
    },
    Rejected(FfiError),
    Uncertain(FfiError),
}
// Constructed inside its thread, so Backend itself need not move native sources.
struct NativeBackend {
    context: SourceContext,
    sources: BTreeMap<ReadOwnerId, SourceOwner<()>>,
}
// Do not implement Backend for NativeBackend (native sources are !Send). The
// executor takes a Send factory and creates its thread-local backend there.
trait LocalBackend {
    fn register(
        &mut self,
        id: ReadOwnerId,
        backing: ReadBacking<()>,
        token: ReadToken,
    ) -> Registration;
    fn cleanup(
        &mut self,
        id: ReadOwnerId,
        permit: UnregisterPermit,
        revoked: Option<SourceRevoked>,
    ) -> std::result::Result<ReapDecision, FfiError>;
}
impl LocalBackend for NativeBackend {
    fn register(
        &mut self,
        id: ReadOwnerId,
        backing: ReadBacking<()>,
        token: ReadToken,
    ) -> Registration {
        // SAFETY: the owner reserved the exact bytes and the unsafe Fabric caller
        // supplied backing/provider facts. This context has an independent lease.
        let (source, error) = match unsafe { self.context.register(backing, &token) } {
            SourceRegistration::Registered(source) => (source, None),
            SourceRegistration::Uncertain { source, error } => (source, Some(error)),
            SourceRegistration::Rejected { error, backing } => {
                drop(backing);
                return Registration::Rejected(error);
            }
        };
        let source = SourceOwner::worker_source(source, error.is_some());
        let result = match error {
            Some(error) => Registration::Uncertain(error),
            None => match source.descriptor() {
                Ok(descriptor) => Registration::Ready {
                    descriptor,
                    token,
                    stages: source.register_stages().unwrap_or_default(),
                },
                Err(error) => Registration::Uncertain(error),
            },
        };
        self.sources.insert(id, source);
        result
    }
    fn cleanup(
        &mut self,
        id: ReadOwnerId,
        permit: UnregisterPermit,
        revoked: Option<SourceRevoked>,
    ) -> std::result::Result<ReapDecision, FfiError> {
        let source = self
            .sources
            .get_mut(&id)
            .ok_or(FfiError::Contract("worker source missing"))?;
        let result = source.worker_reap(id, &permit, revoked.as_ref());
        if matches!(&result, Ok(ReapDecision::Retired(_))) {
            self.sources.remove(&id);
        }
        result
    }
}

enum Job {
    Register {
        submitted: Instant,
        id: ReadOwnerId,
        backing: ReadBacking<()>,
        token: ReadToken,
    },
    Cleanup {
        submitted: Instant,
        id: ReadOwnerId,
        permit: UnregisterPermit,
        revoked: Option<SourceRevoked>,
    },
    Stop,
}
pub(crate) enum Outcome {
    Register(Registration),
    Cleanup(std::result::Result<ReapDecision, FfiError>),
    Lost,
}
pub(crate) struct Completion {
    pub(crate) id: ReadOwnerId,
    pub(crate) worker: usize,
    pub(crate) outcome: Outcome,
}
pub(crate) enum Reply {
    Register(oneshot::Sender<Result<ReadSourceAdmission>>),
    Cleanup(oneshot::Sender<Result<bool>>),
    OrphanCleanup,
}
struct Pending {
    worker: usize,
    reply: Reply,
}
struct Worker {
    tx: mpsc::Sender<Job>,
    join: Option<JoinHandle<()>>,
    failed: bool,
}
/// Owner-only bookkeeping; entries hold identities, never native resources.
/// Only definitely registered, unpublished offers may be automatically reaped.
#[derive(Default)]
pub(crate) struct OrphanSources {
    entries: BTreeMap<ReadOwnerId, Orphan>,
}
struct Orphan {
    attempts: usize,
    next: Option<Instant>,
    in_flight: bool,
}
impl OrphanSources {
    pub(crate) fn track(&mut self, id: ReadOwnerId, unpublished_ready: bool, now: Instant) {
        self.entries.entry(id).or_insert(Orphan {
            attempts: 0,
            next: unpublished_ready.then_some(now),
            in_flight: false,
        });
    }
    pub(crate) fn pending(&self) -> bool {
        self.entries
            .values()
            .any(|entry| entry.in_flight || entry.next.is_some())
    }
    pub(crate) fn due(&self, now: Instant) -> Vec<ReadOwnerId> {
        self.entries
            .iter()
            .filter_map(|(&id, entry)| {
                (!entry.in_flight && entry.next.is_some_and(|next| next <= now)).then_some(id)
            })
            .collect()
    }
    pub(crate) fn dispatched(&mut self, id: ReadOwnerId) {
        let entry = self.entries.get_mut(&id).expect("tracked orphan");
        entry.attempts += 1;
        entry.next = None;
        entry.in_flight = true;
    }
    /// Returns true when retrying stops. A dead worker must never be retried.
    pub(crate) fn failed(&mut self, id: ReadOwnerId, now: Instant, worker_lost: bool) -> bool {
        let entry = self.entries.get_mut(&id).expect("tracked orphan");
        entry.in_flight = false;
        let terminal = worker_lost || entry.attempts >= 3;
        entry.next = (!terminal).then(|| {
            now + std::time::Duration::from_millis(if entry.attempts <= 1 { 100 } else { 500 })
        });
        terminal
    }
    pub(crate) fn retired(&mut self, id: ReadOwnerId) {
        self.entries.remove(&id);
    }
}

pub(crate) struct SourceWorkers {
    workers: Vec<Worker>,
    completed: mpsc::Receiver<Completion>,
    pending: BTreeMap<ReadOwnerId, Pending>,
    next: usize,
    stopping: bool,
}
impl SourceWorkers {
    pub(crate) fn start(contexts: Vec<SourceContext>) -> Result<Self> {
        Self::start_factories(
            contexts
                .into_iter()
                .map(|context| {
                    move || NativeBackend {
                        context,
                        sources: BTreeMap::new(),
                    }
                })
                .collect(),
        )
    }
    fn start_factories<F, B>(factories: Vec<F>) -> Result<Self>
    where
        F: FnOnce() -> B + Send + 'static,
        B: LocalBackend + 'static,
    {
        let (completed_tx, completed) = mpsc::channel();
        let mut workers: Vec<Worker> = Vec::new();
        for (index, factory) in factories.into_iter().enumerate() {
            let (tx, rx) = mpsc::channel();
            let completed_tx = completed_tx.clone();
            let join = match thread::Builder::new()
                .name(format!("urma-source-{index}"))
                .spawn(move || {
                    let mut backend = factory();
                    while let Ok(job) = rx.recv() {
                        let started = Instant::now();
                        let (id, submitted, operation, outcome) = match job {
                            Job::Register {
                                id,
                                backing,
                                token,
                                submitted,
                            } => (
                                id,
                                submitted,
                                "register",
                                Outcome::Register(backend.register(id, backing, token)),
                            ),
                            Job::Cleanup {
                                id,
                                permit,
                                revoked,
                                submitted,
                            } => (
                                id,
                                submitted,
                                if revoked.is_some() {
                                    "release"
                                } else {
                                    "unregister"
                                },
                                Outcome::Cleanup(backend.cleanup(id, permit, revoked)),
                            ),
                            Job::Stop => break,
                        };
                        tracing::debug!(
                            source_worker_index = index,
                            source_worker_operation = operation,
                            source_worker_queue_ns =
                                started.duration_since(submitted).as_nanos() as u64,
                            source_worker_execution_ns = started.elapsed().as_nanos() as u64,
                            "urma READ source worker operation completed"
                        );
                        if completed_tx
                            .send(Completion {
                                id,
                                worker: index,
                                outcome,
                            })
                            .is_err()
                        {
                            break; // Native source Drop retains backing and native refs.
                        }
                    }
                }) {
                Ok(join) => join,
                Err(error) => {
                    for worker in workers {
                        let _ = worker.tx.send(Job::Stop);
                    }
                    return Err(Error::Protocol(format!(
                        "source worker start failed: {error}"
                    )));
                }
            };
            workers.push(Worker {
                tx,
                join: Some(join),
                failed: false,
            });
        }
        Ok(Self {
            workers,
            completed,
            pending: BTreeMap::new(),
            next: 0,
            stopping: false,
        })
    }
    pub(crate) fn register(
        &mut self,
        id: ReadOwnerId,
        backing: ReadBacking<()>,
        token: ReadToken,
        reply: oneshot::Sender<Result<ReadSourceAdmission>>,
    ) -> std::result::Result<(), Reply> {
        let reply = Reply::Register(reply);
        if self.stopping || self.pending.contains_key(&id) {
            return Err(reply);
        }
        let Some(worker) = (0..self.workers.len())
            .map(|n| (self.next + n) % self.workers.len())
            .find(|&i| !self.workers[i].failed)
        else {
            return Err(reply);
        };
        self.next = (worker + 1) % self.workers.len();
        if self.workers[worker]
            .tx
            .send(Job::Register {
                id,
                backing,
                token,
                submitted: Instant::now(),
            })
            .is_err()
        {
            self.workers[worker].failed = true;
            return Err(reply); // No native call occurred; caller releases reservation.
        }
        self.pending.insert(id, Pending { worker, reply });
        Ok(())
    }
    pub(crate) fn cleanup(
        &mut self,
        id: ReadOwnerId,
        worker: usize,
        permit: UnregisterPermit,
        revoked: Option<SourceRevoked>,
        reply: oneshot::Sender<Result<bool>>,
    ) -> std::result::Result<(), Reply> {
        let reply = Reply::Cleanup(reply);
        self.enqueue_cleanup(id, worker, permit, revoked, reply)
    }
    pub(crate) fn orphan_cleanup(
        &mut self,
        id: ReadOwnerId,
        worker: usize,
        permit: UnregisterPermit,
        revoked: SourceRevoked,
    ) -> bool {
        self.enqueue_cleanup(id, worker, permit, Some(revoked), Reply::OrphanCleanup)
            .is_ok()
    }
    fn enqueue_cleanup(
        &mut self,
        id: ReadOwnerId,
        worker: usize,
        permit: UnregisterPermit,
        revoked: Option<SourceRevoked>,
        reply: Reply,
    ) -> std::result::Result<(), Reply> {
        if self.stopping || self.pending.contains_key(&id) || self.workers[worker].failed {
            return Err(reply);
        }
        if self.workers[worker]
            .tx
            .send(Job::Cleanup {
                submitted: Instant::now(),
                id,
                permit,
                revoked,
            })
            .is_err()
        {
            self.workers[worker].failed = true;
            return Err(reply);
        }
        self.pending.insert(id, Pending { worker, reply });
        Ok(())
    }
    pub(crate) fn completions(&mut self) -> Vec<(Completion, Reply)> {
        let finished = self.finished_workers();
        self.complete_finished(finished)
    }
    fn finished_workers(&self) -> Vec<usize> {
        // Snapshot before draining: every completion from these threads has
        // already been sent. Threads finishing later are handled next poll.
        self.workers
            .iter()
            .enumerate()
            .filter_map(|(index, worker)| {
                (!self.stopping && worker.join.as_ref().is_some_and(|join| join.is_finished()))
                    .then_some(index)
            })
            .collect()
    }
    fn complete_finished(&mut self, finished: Vec<usize>) -> Vec<(Completion, Reply)> {
        let mut results = Vec::new();
        while let Ok(completion) = self.completed.try_recv() {
            if let Some(pending) = self.pending.remove(&completion.id) {
                assert_eq!(pending.worker, completion.worker);
                results.push((completion, pending.reply));
            }
        }
        for index in finished {
            self.workers[index].failed = true;
            let ids = self
                .pending
                .iter()
                .filter(|(_, pending)| pending.worker == index)
                .map(|(&id, _)| id)
                .collect::<Vec<_>>();
            for id in ids {
                let pending = self.pending.remove(&id).unwrap();
                results.push((
                    Completion {
                        id,
                        worker: index,
                        outcome: Outcome::Lost,
                    },
                    pending.reply,
                ));
            }
        }
        results
    }
    pub(crate) fn pending(&self) -> bool {
        !self.pending.is_empty()
    }
    pub(crate) fn stop(&mut self) {
        self.stopping = true;
        for worker in &self.workers {
            let _ = worker.tx.send(Job::Stop);
        }
    }
    pub(crate) fn stopped(&self) -> bool {
        self.workers
            .iter()
            .all(|worker| worker.join.as_ref().is_none_or(|join| join.is_finished()))
    }
    pub(crate) fn join(&mut self) -> Result<()> {
        for worker in &mut self.workers {
            if let Some(join) = worker.join.take() {
                join.join().map_err(|_| {
                    Error::Protocol("source worker panicked; resources retained".into())
                })?;
            }
        }
        Ok(())
    }
}
impl Drop for SourceWorkers {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::read_owner::{
        ReadBudget, ReadCapacity, ReadDirection, ReadOwnerRegistry, ReadPeer, VerifiedRetirement,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    };
    use std::time::{Duration, Instant};

    struct Gate {
        open: Mutex<bool>,
        changed: Condvar,
        entered: mpsc::Sender<thread::ThreadId>,
        cleanup_attempts: AtomicUsize,
        mode: AtomicUsize, // 0 success, 1 uncertain, 2 clean reject, 3 panic
    }
    impl Gate {
        fn unblock(&self) {
            *self.open.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }
    struct FakeBackend {
        gate: Arc<Gate>,
        sources: BTreeMap<ReadOwnerId, ReadBacking<()>>,
    }
    impl LocalBackend for FakeBackend {
        fn register(
            &mut self,
            id: ReadOwnerId,
            backing: ReadBacking<()>,
            token: ReadToken,
        ) -> Registration {
            self.gate.entered.send(thread::current().id()).unwrap();
            let mut open = self.gate.open.lock().unwrap();
            while !*open {
                open = self.gate.changed.wait(open).unwrap();
            }
            drop(open);
            let mode = self.gate.mode.load(Ordering::SeqCst);
            if mode == 3 {
                panic!("injected worker failure");
            }
            if mode == 2 {
                return Registration::Rejected(FfiError::Status(-12));
            }
            let length = backing.len();
            self.sources.insert(id, backing);
            if mode == 1 {
                return Registration::Uncertain(FfiError::Status(-5));
            }
            Registration::Ready {
                descriptor: ReadDescriptor {
                    version: 1,
                    eid: [1; 16],
                    uasid: 1,
                    va: 4096,
                    length,
                    token_id: 1,
                    access: 2,
                    token_policy: 0,
                },
                token,
                stages: ReadSourceStages::default(),
            }
        }
        fn cleanup(
            &mut self,
            id: ReadOwnerId,
            _: UnregisterPermit,
            proof: Option<SourceRevoked>,
        ) -> std::result::Result<ReapDecision, FfiError> {
            assert!(self.sources.contains_key(&id));
            if self.gate.cleanup_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(FfiError::Status(-5));
            }
            if proof.is_none() {
                return Ok(ReapDecision::Pending);
            }
            self.sources.remove(&id);
            Ok(ReapDecision::Retired(unsafe {
                VerifiedRetirement::new(id)
            }))
        }
    }
    fn setup(count: usize) -> (SourceWorkers, Arc<Gate>, mpsc::Receiver<thread::ThreadId>) {
        let (tx, rx) = mpsc::channel();
        let gate = Arc::new(Gate {
            open: Mutex::new(false),
            changed: Condvar::new(),
            entered: tx,
            cleanup_attempts: AtomicUsize::new(0),
            mode: AtomicUsize::new(0),
        });
        let factories = (0..count)
            .map(|_| {
                let gate = gate.clone();
                move || FakeBackend {
                    gate,
                    sources: BTreeMap::new(),
                }
            })
            .collect();
        (SourceWorkers::start_factories(factories).unwrap(), gate, rx)
    }
    fn registry() -> ReadOwnerRegistry<()> {
        let cap = ReadCapacity {
            bytes: 64,
            entries: 8,
        };
        let mut registry = ReadOwnerRegistry::<()>::new(ReadBudget {
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
        let peer = ReadPeer {
            id: 1,
            generation: 1,
        };
        registry.activate_peer(peer).unwrap();
        registry
    }
    fn id() -> ReadOwnerId {
        registry()
            .reserve(
                ReadPeer {
                    id: 1,
                    generation: 1,
                },
                ReadDirection::Source,
                8,
            )
            .unwrap()
    }
    fn backing() -> ReadBacking<()> {
        ReadBacking::new(
            super::super::ffi::read::source::ReadSourceMemory::Bytes(vec![7; 8].into_boxed_slice()),
            (),
        )
    }
    fn submit(
        pool: &mut SourceWorkers,
        id: ReadOwnerId,
    ) -> oneshot::Receiver<Result<ReadSourceAdmission>> {
        let (tx, rx) = oneshot::channel();
        assert!(pool.register(id, backing(), ReadToken::new(7), tx).is_ok());
        rx
    }
    fn wait(pool: &mut SourceWorkers, count: usize) -> Vec<(Completion, Reply)> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut results = Vec::new();
        while results.len() < count {
            results.extend(pool.completions());
            assert!(Instant::now() < deadline, "worker completion timed out");
            thread::yield_now();
        }
        results
    }
    fn finish(pool: &mut SourceWorkers) {
        pool.stop();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !pool.stopped() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        pool.join().unwrap();
    }
    #[test]
    fn completion_sent_after_exit_snapshot_is_preserved_before_lost_detection() {
        let completed_id = id();
        let lost_id = id();
        let (completed_tx, completed) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            release_rx.recv().unwrap();
            completed_tx
                .send(Completion {
                    id: completed_id,
                    worker: 0,
                    outcome: Outcome::Cleanup(Ok(ReapDecision::Retired(unsafe {
                        VerifiedRetirement::new(completed_id)
                    }))),
                })
                .unwrap();
            drop(rx);
            panic!("next operation lost");
        });
        let mut pool = SourceWorkers {
            workers: vec![Worker {
                tx,
                join: Some(join),
                failed: false,
            }],
            completed,
            pending: [
                (
                    completed_id,
                    Pending {
                        worker: 0,
                        reply: Reply::OrphanCleanup,
                    },
                ),
                (
                    lost_id,
                    Pending {
                        worker: 0,
                        reply: Reply::OrphanCleanup,
                    },
                ),
            ]
            .into_iter()
            .collect(),
            next: 0,
            stopping: false,
        };
        let snapshot = pool.finished_workers();
        assert!(snapshot.is_empty());
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !pool.stopped() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        let results = pool.complete_finished(snapshot);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.id, completed_id);
        assert!(matches!(
            results[0].0.outcome,
            Outcome::Cleanup(Ok(ReapDecision::Retired(_)))
        ));
        let results = pool.completions();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.id, lost_id);
        assert!(matches!(results[0].0.outcome, Outcome::Lost));
        assert!(!pool.pending());
        assert!(pool.join().is_err());
    }
    #[test]
    fn orphan_cleanup_retries_without_new_requests_then_releases_budget() {
        let (mut pool, gate, entered) = setup(1);
        let mut registry = registry();
        let source = registry
            .reserve(
                ReadPeer {
                    id: 1,
                    generation: 1,
                },
                ReadDirection::Source,
                8,
            )
            .unwrap();
        registry.attach(source, ()).unwrap();
        registry.retire(source).unwrap();
        drop(submit(&mut pool, source));
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        gate.unblock();
        let (completion, reply) = wait(&mut pool, 1).pop().unwrap();
        assert!(matches!(
            completion.outcome,
            Outcome::Register(Registration::Ready { .. })
        ));
        let Reply::Register(reply) = reply else {
            panic!()
        };
        assert!(reply.is_closed());
        let mut orphans = OrphanSources::default();
        let now = Instant::now();
        orphans.track(source, true, now);
        for attempt in 0..2 {
            let tick = now + Duration::from_secs(attempt);
            assert_eq!(orphans.due(tick), vec![source]);
            orphans.dispatched(source);
            assert!(orphans.due(tick).is_empty());
            assert!(pool.orphan_cleanup(
                source,
                0,
                unsafe { UnregisterPermit::new(source) },
                unsafe { SourceRevoked::new(source) }
            ));
            let (completion, reply) = wait(&mut pool, 1).pop().unwrap();
            assert!(matches!(reply, Reply::OrphanCleanup));
            match completion.outcome {
                Outcome::Cleanup(Err(_)) if attempt == 0 => {
                    assert!(registry
                        .reap_with(source, |_| Err::<ReapDecision, _>(FfiError::Status(-5)))
                        .is_err());
                    assert_eq!(registry.usage().source_bytes, 8);
                    assert!(!orphans.failed(source, tick, false));
                    assert!(orphans.pending());
                    assert!(orphans.due(tick).is_empty());
                }
                Outcome::Cleanup(Ok(ReapDecision::Retired(proof))) if attempt == 1 => {
                    assert_eq!(
                        registry
                            .reap_with(source, |_| Ok::<_, FfiError>(ReapDecision::Retired(proof))),
                        Ok(true)
                    );
                    assert_eq!(registry.usage().source_bytes, 0);
                    orphans.retired(source);
                }
                _ => panic!("unexpected orphan cleanup result"),
            }
        }
        assert!(!orphans.pending());
        assert!(orphans.entries.is_empty());
        finish(&mut pool);
    }
    #[test]
    fn orphan_cleanup_result_survives_worker_stop_and_clears_shutdown_pending() {
        let (mut pool, gate, entered) = setup(1);
        let source = id();
        drop(submit(&mut pool, source));
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        gate.unblock();
        wait(&mut pool, 1);
        gate.cleanup_attempts.store(1, Ordering::SeqCst);
        let mut orphans = OrphanSources::default();
        orphans.track(source, true, Instant::now());
        orphans.dispatched(source);
        assert!(pool.orphan_cleanup(
            source,
            0,
            unsafe { UnregisterPermit::new(source) },
            unsafe { SourceRevoked::new(source) }
        ));
        assert!(orphans.pending());
        pool.stop();
        let (completion, reply) = wait(&mut pool, 1).pop().unwrap();
        assert!(matches!(reply, Reply::OrphanCleanup));
        assert!(matches!(
            completion.outcome,
            Outcome::Cleanup(Ok(ReapDecision::Retired(_)))
        ));
        orphans.retired(source);
        assert!(!orphans.pending());
        assert!(!pool.pending());
        finish(&mut pool);
    }

    #[test]
    fn orphan_retry_exhaustion_and_uncertainty_stop_progress_without_forgetting_ids() {
        let mut orphans = OrphanSources::default();
        let source = id();
        let uncertain = id();
        let lost = id();
        let now = Instant::now();
        orphans.track(source, true, now);
        orphans.track(uncertain, false, now);
        orphans.track(lost, true, now);
        orphans.dispatched(lost);
        assert!(orphans.failed(lost, now, true));
        for attempt in 0..3 {
            let tick = now + Duration::from_secs(attempt);
            assert_eq!(orphans.due(tick), vec![source]);
            orphans.dispatched(source);
            assert_eq!(orphans.failed(source, tick, false), attempt == 2);
        }
        assert!(!orphans.pending());
        assert!(orphans.due(now + Duration::from_secs(60)).is_empty());
        assert_eq!(orphans.entries.len(), 3);
    }

    #[test]
    fn blocked_native_calls_overlap_on_distinct_workers_without_blocking_owner() {
        let (mut pool, gate, entered) = setup(2);
        let a = id();
        let b = id();
        let _a = submit(&mut pool, a);
        let _b = submit(&mut pool, b);
        let first = entered.recv_timeout(Duration::from_secs(3)).unwrap();
        let second = entered.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_ne!(first, second);
        assert_ne!(first, thread::current().id());
        assert!(pool.pending());
        assert!(pool.completions().is_empty());
        gate.unblock();
        for (completion, _) in wait(&mut pool, 2) {
            assert!(matches!(
                completion.outcome,
                Outcome::Register(Registration::Ready { .. })
            ));
        }
        assert!(!pool.pending());
        finish(&mut pool);
    }
    #[test]
    fn dropped_receiver_retains_completed_registration_for_owner_cleanup() {
        let (mut pool, gate, entered) = setup(1);
        let source = id();
        drop(submit(&mut pool, source));
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(pool.pending());
        gate.unblock();
        let (completion, reply) = wait(&mut pool, 1).pop().unwrap();
        assert_eq!(completion.id, source);
        assert!(matches!(
            completion.outcome,
            Outcome::Register(Registration::Ready { .. })
        ));
        let Reply::Register(reply) = reply else {
            panic!()
        };
        assert!(reply.is_closed()); // runtime must retire/revoke rather than discard this event
        finish(&mut pool);
    }
    #[test]
    fn cleanup_is_serial_per_source_and_failed_or_unproven_reap_retains_resource() {
        let (mut pool, gate, entered) = setup(1);
        let source = id();
        let _rx = submit(&mut pool, source);
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        gate.unblock();
        wait(&mut pool, 1);
        for expected in 0..3 {
            let (tx, _rx) = oneshot::channel();
            let proof = (expected == 2).then(|| unsafe { SourceRevoked::new(source) });
            assert!(pool
                .cleanup(
                    source,
                    0,
                    unsafe { UnregisterPermit::new(source) },
                    proof,
                    tx
                )
                .is_ok());
            let (duplicate, _rx) = oneshot::channel();
            assert!(pool
                .cleanup(
                    source,
                    0,
                    unsafe { UnregisterPermit::new(source) },
                    None,
                    duplicate
                )
                .is_err());
            let (completion, _) = wait(&mut pool, 1).pop().unwrap();
            match (expected, completion.outcome) {
                (0, Outcome::Cleanup(Err(_)))
                | (1, Outcome::Cleanup(Ok(ReapDecision::Pending)))
                | (2, Outcome::Cleanup(Ok(ReapDecision::Retired(_)))) => {}
                _ => panic!("wrong cleanup transition"),
            }
        }
        finish(&mut pool);
    }
    #[test]
    fn shutdown_keeps_inflight_result_and_does_not_join_a_blocked_worker() {
        let (mut pool, gate, entered) = setup(1);
        let source = id();
        let _rx = submit(&mut pool, source);
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        pool.stop();
        assert!(!pool.stopped());
        assert!(pool.pending());
        gate.unblock();
        assert!(matches!(
            wait(&mut pool, 1).pop().unwrap().0.outcome,
            Outcome::Register(Registration::Ready { .. })
        ));
        finish(&mut pool);
    }
    #[test]
    fn worker_failure_resolves_waiters_as_lost_and_rejects_new_dispatch() {
        let (mut pool, gate, entered) = setup(1);
        gate.mode.store(3, Ordering::SeqCst);
        let source = id();
        let _rx = submit(&mut pool, source);
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        gate.unblock();
        assert!(matches!(
            wait(&mut pool, 1).pop().unwrap().0.outcome,
            Outcome::Lost
        ));
        let (tx, _rx) = oneshot::channel();
        assert!(pool
            .register(id(), backing(), ReadToken::new(9), tx)
            .is_err());
        pool.stop();
        assert!(pool.join().is_err());
    }
    #[test]
    fn clean_rejection_and_uncertain_native_result_remain_distinct() {
        for mode in [1, 2] {
            let (mut pool, gate, entered) = setup(1);
            gate.mode.store(mode, Ordering::SeqCst);
            let _rx = submit(&mut pool, id());
            entered.recv_timeout(Duration::from_secs(3)).unwrap();
            gate.unblock();
            match (mode, wait(&mut pool, 1).pop().unwrap().0.outcome) {
                (1, Outcome::Register(Registration::Uncertain(_)))
                | (2, Outcome::Register(Registration::Rejected(_))) => {}
                _ => panic!("wrong registration classification"),
            }
            finish(&mut pool);
        }
    }
}
