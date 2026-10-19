//! Ordinary Task metadata/file publication. Guards end before any URMA work.
//! Mutations keep running if their caller is cancelled: an already queued
//! filesystem operation must not outlive the guard and unlink a replacement.

use dragonfly_client_core::{Error, Result};
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::RwLock;

#[derive(Default)]
pub(crate) struct TaskFileLifecycle {
    gates: Mutex<HashMap<String, Weak<RwLock<()>>>>,
}

impl TaskFileLifecycle {
    pub(crate) fn gate(&self, task: &str) -> Arc<RwLock<()>> {
        let mut gates = self.gates.lock().unwrap();
        if let Some(gate) = gates.get(task).and_then(Weak::upgrade) {
            return gate;
        }
        // Only weak entries are retained; periodically discard dead Task keys.
        if gates.len() >= 64 {
            gates.retain(|_, gate| gate.strong_count() != 0);
        }
        let gate = Arc::new(RwLock::new(()));
        gates.insert(task.to_owned(), Arc::downgrade(&gate));
        gate
    }

    pub(crate) async fn mutate<T: Send + 'static>(
        gate: Arc<RwLock<()>>,
        operation: impl Future<Output = T> + Send + 'static,
    ) -> Result<T> {
        tokio::spawn(async move {
            let _guard = gate.write_owned().await;
            operation.await
        })
        .await
        .map_err(|error| Error::Unknown(format!("Task file lifecycle operation failed: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancelled_caller_keeps_mutation_exclusive_until_filesystem_work_finishes() {
        let lifecycle = TaskFileLifecycle::default();
        let gate = lifecycle.gate("task");
        let (entered_tx, entered_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = oneshot::channel();
        let worker_gate = gate.clone();
        let caller = tokio::spawn(async move {
            TaskFileLifecycle::mutate(worker_gate, async move {
                entered_tx.send(()).unwrap();
                finish_rx.await.unwrap();
            })
            .await
            .unwrap();
        });
        entered_rx.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(gate.try_write().is_err());
        assert!(Arc::ptr_eq(&gate, &lifecycle.gate("task")));
        // Other Task creation/deletion does not share this guard.
        assert!(lifecycle.gate("other").try_write().is_ok());
        finish_tx.send(()).unwrap();
        let _guard = tokio::time::timeout(std::time::Duration::from_secs(2), gate.write())
            .await
            .unwrap();
    }
}
