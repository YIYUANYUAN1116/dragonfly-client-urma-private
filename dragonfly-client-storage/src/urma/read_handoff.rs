//! Resource replies keep cancellation cleanup armed until the receiver claims them.
use super::Result;
use tokio::sync::oneshot;

pub(crate) struct ResourceGuard(Option<Box<dyn FnOnce() + Send + Sync>>);
impl ResourceGuard {
    pub(crate) fn new(cleanup: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self(Some(Box::new(cleanup)))
    }
    pub(crate) fn disarm(mut self) {
        self.0 = None;
    }
}
impl Drop for ResourceGuard {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            cleanup();
        }
    }
}

pub(crate) struct Handoff<T> {
    value: T,
    guard: ResourceGuard,
}
impl<T> Handoff<T> {
    pub(crate) fn claim(self) -> T {
        self.guard.disarm();
        self.value
    }
}

pub(crate) struct ResourceReply<T> {
    sender: oneshot::Sender<Result<Handoff<T>>>,
    guard: Box<dyn Fn(&T) -> ResourceGuard + Send>,
}
impl<T> ResourceReply<T> {
    pub(crate) fn new(
        sender: oneshot::Sender<Result<Handoff<T>>>,
        guard: impl Fn(&T) -> ResourceGuard + Send + 'static,
    ) -> Self {
        Self {
            sender,
            guard: Box::new(guard),
        }
    }
    #[cfg(test)]
    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
    pub(crate) fn send(self, result: Result<T>) -> std::result::Result<(), ()> {
        let result = result.map(|value| Handoff {
            guard: (self.guard)(&value),
            value,
        });
        self.sender.send(result).map_err(|_| ())
    }
    #[cfg(test)]
    pub(crate) fn test_channel() -> (Self, oneshot::Receiver<Result<Handoff<T>>>) {
        let (sender, receiver) = oneshot::channel();
        (Self::new(sender, |_| ResourceGuard::new(|| {})), receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urma::Error;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    #[tokio::test]
    async fn cancellation_before_or_after_send_runs_cleanup_but_claim_does_not() {
        for stage in 0..3 {
            let count = Arc::new(AtomicUsize::new(0));
            let (sender, receiver) = oneshot::channel();
            let cleanup_count = count.clone();
            let reply = ResourceReply::new(sender, move |_: &u32| {
                let count = cleanup_count.clone();
                ResourceGuard::new(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                })
            });
            if stage == 0 {
                drop(receiver);
                assert!(reply.send(Ok(7)).is_err());
            } else {
                assert!(reply.send(Ok(7)).is_ok());
                if stage == 1 {
                    drop(receiver);
                } else {
                    assert_eq!(receiver.await.unwrap().unwrap().claim(), 7);
                }
            }
            assert_eq!(count.load(Ordering::SeqCst), usize::from(stage != 2));
        }
    }
    #[tokio::test]
    async fn error_reply_does_not_create_resource_guard() {
        let (sender, receiver) = oneshot::channel();
        let reply = ResourceReply::<u32>::new(sender, |_| panic!("no resource on rejection"));
        assert!(reply.send(Err(Error::Protocol("rejected".into()))).is_ok());
        assert!(receiver.await.unwrap().is_err());
    }
}
