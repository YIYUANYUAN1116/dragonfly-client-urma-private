//! UMDK/URMA piece transport internals for Dragonfly storage.
//!
//! Native resource ownership is derived from the verified
//! `urma-transport-lab` implementation. Dragonfly's storage client/server and
//! rendezvous contracts remain the source of truth for integration structure.

use std::time::Duration;

pub(crate) mod buffer;
mod completion;
pub(crate) mod control;
mod credit;
mod error;
pub mod fabric;
pub(crate) mod ffi;
mod lane;
// Offline READ foundation; not advertised or dispatched until provider gates pass.
#[allow(dead_code)]
mod read;
#[allow(dead_code)]
mod read_buffer_pool;
mod read_child_owner;
#[allow(dead_code)]
pub(crate) mod read_control;
#[allow(dead_code)]
pub(crate) mod read_owner;
#[allow(dead_code)]
mod read_owners;
#[allow(dead_code)]
pub(crate) mod read_protocol;
#[allow(dead_code)]
pub(crate) mod read_session;
#[cfg(test)]
mod read_session_harness;
#[allow(dead_code)]
mod read_source_owner;
#[allow(dead_code)]
mod read_wr_credit;
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
