//! UMDK/URMA piece transport internals for Dragonfly storage.
//!
//! Native resource ownership is derived from the verified
//! `urma-transport-lab` implementation. Dragonfly's storage client/server and
//! rendezvous contracts remain the source of truth for integration structure.

mod buffer;
mod completion;
mod error;
pub mod fabric;
mod ffi;
mod lane;
pub mod rendezvous;
pub mod runtime;
pub(crate) mod session;

pub(crate) use error::native_error;
pub use error::{Error, Result};
