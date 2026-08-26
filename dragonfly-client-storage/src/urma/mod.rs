//! UMDK/URMA piece transport internals for Dragonfly storage.
//!
//! Native resource ownership is derived from the verified
//! `urma-transport-lab` implementation. Dragonfly's storage client/server and
//! rendezvous contracts remain the source of truth for integration structure.

mod buffer;
mod completion;
mod error;
pub(crate) mod fabric;
mod ffi;
mod lane;
mod runtime;

pub(crate) use error::{native_error, Error, Result};
