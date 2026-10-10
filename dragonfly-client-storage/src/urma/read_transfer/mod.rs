//! Single-Piece RM READ transfer adapters. Persistent TCP lanes live in
//! `read_control`; native resources remain on the Fabric owner thread.

pub(crate) mod child;
pub(crate) mod parent;

fn protocol(message: impl Into<String>) -> super::Error {
    super::Error::Protocol(message.into())
}
