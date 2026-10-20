//! UMDK/URMA piece transport internals for Dragonfly storage.
//!
//! Native resource ownership is derived from the verified
//! `urma-transport-lab` implementation. Dragonfly's storage client/server and
//! rendezvous contracts remain the source of truth for integration structure.

use std::time::Duration;
mod completion;
mod destination_pool;
mod error;
pub mod fabric;
pub(crate) mod ffi;
mod lane;
mod native_control;
#[cfg(test)]
mod read_bandwidth_probe;
mod read_child_owner;
pub(crate) mod read_control;
pub(crate) mod read_handoff;
pub(crate) mod read_protocol;
pub(crate) mod read_registry;
#[cfg(test)]
mod read_session_harness;
mod read_source_cache;
mod read_source_lease;
mod read_source_owner;
mod read_source_workers;
mod read_table;
pub(crate) mod read_transfer;
pub mod rendezvous;
pub(crate) mod runtime;
pub(crate) mod sendrecv_control;
mod wr_admission;

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
