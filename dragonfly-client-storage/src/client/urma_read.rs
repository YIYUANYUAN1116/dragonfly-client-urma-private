/*
 *     Copyright 2026 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! RM-READ piece download client (DFUR version 5).
//!
//! One persistent lane per parent carries READ transfers: the Child owns a
//! fabric-registered destination, sends BufferReady with the Piece locator,
//! receives the SegmentOffer, and reads the immutable Parent source directly
//! into its registered buffer. The fully read lease is handed to Storage and
//! must be recycled afterwards to release the destination budget.

use super::{DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_KEEPALIVE_RETRIES, DEFAULT_KEEPALIVE_TIME};
use crate::rendezvous::PieceKind;
use crate::urma::fabric::{PeerTargetConfig, UrmaFabricHandle};
use crate::urma::read_control::{
    next_session_generation, read_handshake, write_handshake, ReadHandshake, ReadLaneCapability,
    ReadLaneControl,
};
use crate::urma::read_protocol::{
    ReadCapability, ReadPieceLocator, ReadTransferIdentity, READ_DESCRIPTOR_VERSION,
};
use crate::urma::read_session::ChildTransportSession;
use crate::urma::runtime::{ReadChildId, ReadLeaseSpan};
use dragonfly_client_config::dfdaemon::Config;
use dragonfly_client_core::{Error as ClientError, Result as ClientResult};
use socket2::SockRef;
use socket2::TcpKeepalive;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, instrument, warn};

/// Poll interval for the Child transfer completion wait.
const COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(1);

type ReadSessionSlot = Arc<tokio::sync::Mutex<Option<Arc<ReadLaneSession>>>>;

/// A persistent READ lane bound to one parent connection.
struct ReadLaneSession {
    lane_id: u16,
    session_generation: u64,
    control: Arc<ReadLaneControl>,
}

/// A fully read destination lease. The registered buffer content is final
/// (every READ WR retired before publication); Storage must consume the span
/// and then call [`UrmaReadPieceLease::recycle`] to close the buffer and
/// release the transfer budget. Dropping the lease without recycling keeps
/// the native owner registered (fail closed) and the budget charged.
pub struct UrmaReadPieceLease {
    fabric: UrmaFabricHandle,
    child_id: ReadChildId,
    span: ReadLeaseSpan,
}

impl UrmaReadPieceLease {
    /// Length of the final READ content.
    pub fn len(&self) -> usize {
        self.span.length
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the final READ content. The backing registered buffer is
    /// exclusively owned by this lease until recycle, so no other reader or
    /// DMA can touch the span.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: Every READ WR retired before publication, the span is valid
        // for the lease lifetime, and recycle closes the buffer afterwards.
        unsafe { std::slice::from_raw_parts(self.span.data, self.span.length) }
    }

    /// Releases the registered destination buffer and the transfer budget.
    /// Returns false when the native owner could not prove a full close; the
    /// id stays registered for a later cleanup pass.
    pub async fn recycle(self) -> ClientResult<()> {
        match self.fabric.recycle_published_child_lease(self.child_id).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(ClientError::Unknown(
                "recycled READ lease did not prove full budget release".to_string(),
            )),
            Err(error) => Err(ClientError::Unknown(error.to_string())),
        }
    }
}

impl Drop for UrmaReadPieceLease {
    fn drop(&mut self) {
        // Fail closed: an unconsumed lease keeps its native owner registered
        // and the destination budget charged until a cleanup pass recovers.
        warn!(
            "dropped an unread RM-READ lease; its owner stays retained and budgeted"
        );
    }
}

/// UrmaReadClient downloads pieces over the RM-READ data plane. Errors must
/// let the caller fall back to the TCP piece transport; READ never has to
/// succeed for a piece to complete.
pub struct UrmaReadClient {
    /// config is the configuration of the dfdaemon.
    config: Arc<Config>,

    /// fabric is the process-shared READ-enabled URMA facade.
    fabric: UrmaFabricHandle,

    /// capability is the local READ lane capability advertised in Connect.
    capability: ReadLaneCapability,

    /// addr is the address of the parent's URMA rendezvous server.
    addr: String,

    /// transfer_timeout bounds the handshake, each transfer completion wait,
    /// and the accept gate.
    transfer_timeout: Duration,

    /// session owns the persistent READ lane shared by pieces of this parent.
    session: ReadSessionSlot,

    /// next_transfer_id allocates per-lane transfer identities. Clones share
    /// the counter so concurrent transfers never collide on one identity.
    next_transfer_id: Arc<AtomicU32>,
}

impl Clone for UrmaReadClient {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            fabric: self.fabric.clone(),
            capability: self.capability.clone(),
            addr: self.addr.clone(),
            transfer_timeout: self.transfer_timeout,
            session: Arc::clone(&self.session),
            next_transfer_id: Arc::clone(&self.next_transfer_id),
        }
    }
}

impl UrmaReadClient {
    /// Creates a new UrmaReadClient for one parent address. The fabric must
    /// have been started with the READ-only data plane enabled.
    pub fn new(config: Arc<Config>, fabric: UrmaFabricHandle, addr: String) -> Self {
        let urma_config = &config.storage.server.urma;
        let read_config = urma_config
            .read
            .as_ref()
            .expect("READ client requires the storage.server.urma.read config");
        let capability = ReadLaneCapability {
            transport_type: fabric.transport_type(),
            tp_type: fabric.tp_type(),
            fabric_tag: urma_config
                .fabric_tag
                .clone()
                .unwrap_or_else(|| String::new()),
            read: ReadCapability {
                max_read_size: read_config.max_read_size.as_u64() as u32,
                max_jfs_sge: read_config.max_jfs_sge,
                descriptor_version: READ_DESCRIPTOR_VERSION,
            },
        };
        Self {
            transfer_timeout: urma_config.transfer_timeout,
            config,
            fabric,
            capability,
            addr,
            session: Arc::new(tokio::sync::Mutex::new(None)),
            next_transfer_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// fabric_failed reports whether the shared facade has entered a failed
    /// state and should be retired and recreated by the downloader.
    pub fn fabric_failed(&self) -> bool {
        self.fabric.is_failed()
    }

    /// Downloads one Piece as a published READ lease. The caller consumes the
    /// lease span and recycles it; the returned offset and digest are the
    /// Parent's Piece metadata position and recorded Piece digest.
    #[instrument(skip_all, fields(parent_addr))]
    pub async fn download_piece(
        &self,
        kind: PieceKind,
        number: u32,
        task_id: &str,
        piece_length: u64,
    ) -> ClientResult<(UrmaReadPieceLease, u64, String)> {
        let (lane, reused_session) = self.lane().await?;
        let transfer_id = self.next_transfer_id.fetch_add(1, Ordering::Relaxed);
        let identity = ReadTransferIdentity {
            session_generation: lane.session_generation,
            transfer_id,
            // The metadata generation has no dedicated state machine yet; it
            // rides the identity like the wire tests allocate it.
            metadata_generation: u64::from(transfer_id) + 100,
        };
        let control = lane.control.register(identity).map_err(|error| {
            ClientError::Unknown(format!("urma READ lane register failed: {error}"))
        })?;
        let locator = ReadPieceLocator {
            kind,
            task_id: task_id.to_string(),
            piece_number: number,
        };
        let read_config = self
            .config
            .storage
            .server
            .urma
            .read
            .as_ref()
            .expect("READ client requires the storage.server.urma.read config");
        debug!(
            parent_addr = self.addr,
            lane_id = lane.lane_id,
            reused_session,
            transfer_id,
            piece_number = number,
            "urma READ child starting transfer"
        );
        // SAFETY: The lane identity was bound to an authenticated version-5
        // handshake and the destination allocation below is exclusively owned
        // by this transfer for its whole lifetime.
        let session = ChildTransportSession::new(
            self.fabric.clone(),
            lane.lane_id,
            control,
            identity,
            locator,
            piece_length,
            piece_length,
            read_config.max_read_size.as_u64() as u32,
            read_config.max_outstanding_per_peer as usize,
            COMPLETION_POLL_INTERVAL,
            self.transfer_timeout,
        )
        .map_err(|error| ClientError::Unknown(error.to_string()))?;
        let success = unsafe { session.run_transport_only().await }
            .map_err(|failure| ClientError::Unknown(failure.error.to_string()))?;
        let lease = UrmaReadPieceLease {
            fabric: self.fabric.clone(),
            child_id: success.lease.child_id,
            span: success.lease.span,
        };
        debug!(
            parent_addr = self.addr,
            completed_bytes = success.completed_bytes,
            read_wr_count = success.read_wr_count,
            piece_offset = success.piece_offset,
            digest = %success.digest,
            "urma READ child finished transfer"
        );
        Ok((lease, success.piece_offset, success.digest))
    }

    /// Returns the persistent lane, connecting and handshaking on first use.
    /// The caller must treat any later transfer error as lane failure and
    /// retire the cached client; the next client rebuilds a fresh lane.
    async fn lane(&self) -> ClientResult<(Arc<ReadLaneSession>, bool)> {
        let mut slot = self.session.lock().await;
        if let Some(lane) = slot.as_ref() {
            return Ok((lane.clone(), true));
        }
        let mut stream = TcpStream::connect(&self.addr).await?;
        let socket = SockRef::from(&stream);
        socket.set_tcp_nodelay(true)?;
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_interval(DEFAULT_KEEPALIVE_INTERVAL)
                .with_time(DEFAULT_KEEPALIVE_TIME)
                .with_retries(DEFAULT_KEEPALIVE_RETRIES),
        )?;

        let urma_config = &self.config.storage.server.urma;
        let peer_config = PeerTargetConfig {
            post_list_size: urma_config.post_list_size,
            pipeline_depth: urma_config.pipeline_depth,
            // The READ Child only posts READ; SEND credits are not needed.
            guaranteed_rx_credits: 0,
        };
        let (lane_id, descriptor) = self
            .fabric
            .create_lane(peer_config)
            .await
            .map_err(|error| ClientError::Unknown(format!("urma READ lane create failed: {error}")))?;
        let session_generation = next_session_generation().map_err(|error| {
            ClientError::Unknown(format!("urma READ session generation failed: {error}"))
        })?;
        write_handshake(
            &mut stream,
            &ReadHandshake::Connect {
                capability: self.capability.clone(),
                session_generation,
                descriptor,
            },
        )
        .await
        .map_err(|error| {
            ClientError::Unknown(format!("urma READ handshake write failed: {error}"))
        })?;
        let connected = read_handshake(&mut stream)
            .await
            .map_err(|error| {
                ClientError::Unknown(format!("urma READ handshake read failed: {error}"))
            })?;
        let (effective_max_read_size, parent_descriptor) = connected
            .validate_connected(&self.capability, session_generation)
            .map_err(|error| {
                ClientError::Unknown(format!("urma READ Connected rejected: {error}"))
            })?;
        self.fabric
            .connect_lane(lane_id, parent_descriptor.to_vec())
            .await
            .map_err(|error| {
                ClientError::Unknown(format!("urma READ lane connect failed: {error}"))
            })?;
        let max_concurrent = urma_config.max_concurrent_transfers as usize;
        let control = ReadLaneControl::spawn(stream, session_generation, max_concurrent, 16)
            .map_err(|error| {
                ClientError::Unknown(format!("urma READ lane spawn failed: {error}"))
            })?;
        debug!(
            parent_addr = self.addr,
            lane_id,
            effective_max_read_size,
            "urma READ lane established"
        );
        let lane = Arc::new(ReadLaneSession {
            lane_id,
            session_generation,
            control: Arc::new(control),
        });
        *slot = Some(lane.clone());
        Ok((lane, false))
    }
}
