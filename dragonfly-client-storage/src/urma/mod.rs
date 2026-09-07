//! UMDK/URMA piece transport internals for Dragonfly storage.
//!
//! Native resource ownership is derived from the verified
//! `urma-transport-lab` implementation. Dragonfly's storage client/server and
//! rendezvous contracts remain the source of truth for integration structure.

use std::time::Duration;

mod buffer;
mod completion;
pub(crate) mod control;
mod credit;
mod error;
pub mod fabric;
mod ffi;
mod lane;
pub mod rendezvous;
pub(crate) mod runtime;
pub(crate) mod session;
mod target;
mod transfer;

pub(crate) use buffer::{RegisteredRxWindowLease, TxWindowLease};
pub(crate) use error::native_error;
pub use error::{Error, Result};
pub use lane::{TpType, TransportMode};

/// PEER_SESSION_IDLE_TIMEOUT is how long the downloader keeps an unused persistent peer Session.
/// The server adds one control-timeout grace period before closing its side, ensuring the client
/// retires its cache before the server can invalidate an otherwise reusable lane.
pub const PEER_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(420);

pub(crate) fn server_session_idle_timeout(control_timeout: Duration) -> Duration {
    PEER_SESSION_IDLE_TIMEOUT
        .checked_add(control_timeout)
        .unwrap_or(Duration::MAX)
}
