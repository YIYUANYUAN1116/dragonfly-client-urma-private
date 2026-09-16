//! Single owner-thread WR credits. Accepted/uncertain WRs own credits until
//! verified completion; accidental Drop does not return native capacity.
use super::{
    ffi::{read::ReadRequest, FfiError},
    read_child_owner::{ChildPost, ChildResources},
    read_owner::ReadPeer,
};
use std::{cell::RefCell, collections::BTreeMap, mem::ManuallyDrop, rc::Rc};

pub(crate) struct ReadWrCredits {
    capacity: usize,
    per_peer: usize,
    used: usize,
    peers: BTreeMap<ReadPeer, usize>,
}
impl ReadWrCredits {
    pub(crate) fn new(capacity: usize, per_peer: usize) -> Result<Rc<RefCell<Self>>, FfiError> {
        if capacity == 0 || per_peer == 0 || per_peer > capacity {
            return Err(FfiError::Contract("invalid READ WR credits"));
        }
        Ok(Rc::new(RefCell::new(Self {
            capacity,
            per_peer,
            used: 0,
            peers: BTreeMap::new(),
        })))
    }
    pub(crate) fn used(&self) -> usize {
        self.used
    }
    fn acquire(shared: &Rc<RefCell<Self>>, peer: ReadPeer) -> Result<WrPermit, FfiError> {
        let mut state = shared.borrow_mut();
        let used = state.peers.get(&peer).copied().unwrap_or(0);
        if state.used >= state.capacity || used >= state.per_peer {
            return Err(FfiError::Contract("READ WR credits exhausted"));
        }
        state.used += 1;
        state.peers.insert(peer, used + 1);
        Ok(WrPermit {
            shared: shared.clone(),
            peer,
        })
    }
}
struct WrPermit {
    shared: Rc<RefCell<ReadWrCredits>>,
    peer: ReadPeer,
}
impl Drop for WrPermit {
    fn drop(&mut self) {
        let mut state = self.shared.borrow_mut();
        state.used -= 1;
        let count = state.peers.get_mut(&self.peer).expect("owned WR credit");
        *count -= 1;
        if *count == 0 {
            state.peers.remove(&self.peer);
        }
    }
}
pub(crate) struct CreditedWr<W> {
    wr: W,
    permit: ManuallyDrop<WrPermit>,
}
pub(crate) struct CreditedChild<R> {
    resources: R,
    credits: Rc<RefCell<ReadWrCredits>>,
    peer: ReadPeer,
}
impl<R> CreditedChild<R> {
    /// One shared instance must correspond to the actual JFS available depth.
    /// Production SEND/RECV users must share that capacity if used concurrently.
    pub(crate) fn new(resources: R, credits: Rc<RefCell<ReadWrCredits>>, peer: ReadPeer) -> Self {
        Self {
            resources,
            credits,
            peer,
        }
    }
}
impl<R: ChildResources> ChildResources for CreditedChild<R> {
    type Wr = CreditedWr<R::Wr>;
    fn post(&mut self, request: &ReadRequest) -> Result<ChildPost<Self::Wr>, FfiError> {
        let permit = match ReadWrCredits::acquire(&self.credits, self.peer) {
            Ok(permit) => permit,
            Err(error) => return Ok(ChildPost::Rejected(error)),
        };
        match self.resources.post(request) {
            Ok(ChildPost::Posted(wr)) => Ok(ChildPost::Posted(CreditedWr {
                wr,
                permit: ManuallyDrop::new(permit),
            })),
            Ok(ChildPost::Uncertain(wr, error)) => Ok(ChildPost::Uncertain(
                CreditedWr {
                    wr,
                    permit: ManuallyDrop::new(permit),
                },
                error,
            )),
            Ok(ChildPost::Rejected(error)) => {
                drop(permit);
                Ok(ChildPost::Rejected(error))
            }
            Err(error) => {
                std::mem::forget(permit);
                Err(error)
            }
        }
    }
    unsafe fn complete(&mut self, wr: Self::Wr) {
        let CreditedWr { wr, permit } = wr;
        // SAFETY: Caller validated exact native retirement. Return credit only
        // after native accounting has retired the WR.
        unsafe { self.resources.complete(wr) };
        drop(ManuallyDrop::into_inner(permit));
    }
    fn unimport(&mut self) -> Result<(), FfiError> {
        self.resources.unimport()
    }
    fn close_buffer(&mut self) -> Result<(), FfiError> {
        self.resources.close_buffer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mock(u8);
    impl ChildResources for Mock {
        type Wr = ();
        fn post(&mut self, _: &ReadRequest) -> Result<ChildPost<()>, FfiError> {
            match self.0 {
                1 => Ok(ChildPost::Rejected(FfiError::Status(-1))),
                2 => Ok(ChildPost::Uncertain((), FfiError::Status(-2))),
                3 => Err(FfiError::NullHandle),
                _ => Ok(ChildPost::Posted(())),
            }
        }
        unsafe fn complete(&mut self, _: ()) {}
        fn unimport(&mut self) -> Result<(), FfiError> {
            Ok(())
        }
        fn close_buffer(&mut self) -> Result<(), FfiError> {
            Ok(())
        }
    }
    fn request() -> ReadRequest {
        ReadRequest {
            local_offset: 0,
            remote_offset: 0,
            length: 4,
            user_ctx: 1,
        }
    }
    #[test]
    fn shared_and_peer_limits_hold_until_verified_retirement() {
        let credits = ReadWrCredits::new(2, 1).unwrap();
        let mut a = CreditedChild::new(
            Mock(0),
            credits.clone(),
            ReadPeer {
                id: 1,
                generation: 1,
            },
        );
        let mut b = CreditedChild::new(
            Mock(0),
            credits.clone(),
            ReadPeer {
                id: 2,
                generation: 1,
            },
        );
        let ChildPost::Posted(first) = a.post(&request()).unwrap() else {
            panic!()
        };
        assert!(matches!(a.post(&request()), Ok(ChildPost::Rejected(_))));
        let ChildPost::Posted(second) = b.post(&request()).unwrap() else {
            panic!()
        };
        assert_eq!(credits.borrow().used(), 2);
        unsafe {
            a.complete(first);
            b.complete(second);
        }
        assert_eq!(credits.borrow().used(), 0);
        assert!(credits.borrow().peers.is_empty());
    }
    #[test]
    fn rejection_returns_credit_uncertainty_keeps_it() {
        let credits = ReadWrCredits::new(1, 1).unwrap();
        let mut child = CreditedChild::new(
            Mock(1),
            credits.clone(),
            ReadPeer {
                id: 1,
                generation: 1,
            },
        );
        assert!(matches!(child.post(&request()), Ok(ChildPost::Rejected(_))));
        assert_eq!(credits.borrow().used(), 0);
        child.resources.0 = 2;
        let ChildPost::Uncertain(wr, _) = child.post(&request()).unwrap() else {
            panic!()
        };
        assert_eq!(credits.borrow().used(), 1);
        unsafe { child.complete(wr) };
        assert_eq!(credits.borrow().used(), 0);
    }
    #[test]
    fn lost_handle_keeps_credit_and_blocks_new_posts() {
        let credits = ReadWrCredits::new(1, 1).unwrap();
        let mut child = CreditedChild::new(
            Mock(3),
            credits.clone(),
            ReadPeer {
                id: 1,
                generation: 1,
            },
        );
        assert!(child.post(&request()).is_err());
        assert_eq!(credits.borrow().used(), 1);
        assert!(matches!(child.post(&request()), Ok(ChildPost::Rejected(_))));
    }
}
