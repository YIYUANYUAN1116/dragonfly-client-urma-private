//! Single-process memory-to-memory READ session harness.
//!
//! One process runs both endpoints on one real URMA fabric: the Parent hosts a
//! boxed in-memory source, the Child owns a fabric-registered destination, and
//! the control plane is a tokio duplex pair. The test proves the full lease
//! flow end to end: wire handshake → registration → READ → drain → publish →
//! CPU consumption of the final span → recycle (budget release).
//!
//! Gated behind `#[ignore]` because initialization opens a real provider.
//! Run with:
//! `URMA_TEST_DEVICE=urma0 cargo test -p dragonfly-client-storage --features urma \
//!  single_process_memory_to_memory -- --ignored`

use super::{
    fabric::{PeerTargetConfig, UrmaFabric},
    ffi::read::{
        source::{ReadBacking, ReadSourceMemory},
        ReadToken,
    },
    read_control::{
        next_session_generation, read_handshake, write_handshake, ReadHandshake,
        ReadLaneCapability, ReadLaneControl,
    },
    read_protocol::{
        ReadCapability, ReadPieceLocator, ReadTransferIdentity, READ_DESCRIPTOR_VERSION,
    },
    read_session::{ChildTransportSession, ParentSourceSession},
    runtime::{ReadRuntimeConfig, RuntimeConfig},
    Error, Result,
};
use crate::urma::{
    fabric::UrmaFabricHandle,
    read_owner::{ReadBudget, ReadCapacity},
    TpType,
};
use std::time::Duration;

const PIECE_LENGTH: u64 = 256 * 1024;
const MAX_READ_SIZE: u32 = 1024 * 1024;
const MAX_JFS_SGE: u32 = 4;
const MAX_OUTSTANDING: usize = 8;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(1);

fn read_budget() -> ReadRuntimeConfig {
    let cap = |bytes: u64, entries| ReadCapacity { bytes, entries };
    ReadRuntimeConfig {
        budget: ReadBudget {
            total: cap(4 * 1024 * 1024, 8),
            source: cap(2 * 1024 * 1024, 4),
            destination: cap(2 * 1024 * 1024, 4),
            per_peer_source: cap(2 * 1024 * 1024, 2),
            per_peer_destination: cap(2 * 1024 * 1024, 2),
            quarantine: cap(1024 * 1024, 2),
        },
        max_outstanding_per_peer: MAX_OUTSTANDING,
        buffer_alignment: 4096,
    }
}

fn harness_fabric(device: &str, eid_index: u32) -> Result<UrmaFabricHandle> {
    // The source registration and the destination allocation both live in the
    // registered budget; tx bytes only reserve room for the source direction.
    let config = RuntimeConfig::new(device, eid_index)
        .with_registered_budget(4 * 1024 * 1024, 2 * 1024 * 1024)?
        .with_tp_type(TpType::Rtp)
        .with_read_only(read_budget());
    UrmaFabric::start(config)
}

fn lane_capability(fabric: &UrmaFabricHandle) -> ReadLaneCapability {
    ReadLaneCapability {
        transport_type: fabric.transport_type(),
        tp_type: fabric.tp_type(),
        fabric_tag: "rm-read-harness".to_string(),
        read: ReadCapability {
            max_read_size: MAX_READ_SIZE,
            max_jfs_sge: MAX_JFS_SGE,
            descriptor_version: READ_DESCRIPTOR_VERSION,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a real URMA provider; set URMA_TEST_DEVICE and URMA_TEST_EID_INDEX"]
async fn single_process_memory_to_memory_read_session() -> Result<()> {
    let device = std::env::var("URMA_TEST_DEVICE").unwrap_or_else(|_| "urma0".to_string());
    let eid_index: u32 = std::env::var("URMA_TEST_EID_INDEX")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let fabric = harness_fabric(&device, eid_index)?;

    // Lanes: created in the fabric namespace, then cross-connected so each
    // side resolves the other as its RM peer target.
    let (parent_lane_id, parent_descriptor) =
        fabric.create_lane(PeerTargetConfig::default()).await?;
    let (child_lane_id, child_descriptor) = fabric.create_lane(PeerTargetConfig::default()).await?;
    fabric
        .connect_lane(child_lane_id, parent_descriptor)
        .await
        .map_err(|error| Error::Protocol(format!("Child lane connect failed: {error}")))?;
    fabric
        .connect_lane(parent_lane_id, child_descriptor)
        .await
        .map_err(|error| Error::Protocol(format!("Parent lane connect failed: {error}")))?;

    // Version 5 READ handshake over a duplex stream: the Child sends Connect,
    // the Parent validates it and answers with Connected. Each side then
    // spawns its transfer dispatcher on the same stream.
    let (mut parent_io, mut child_io) = tokio::io::duplex(64 * 1024);
    let session_generation = next_session_generation()?;
    let parent_capability = lane_capability(&fabric);
    let child_capability = lane_capability(&fabric);
    let parent_side = async {
        let connect = read_handshake(&mut parent_io)
            .await
            .map_err(|error| Error::Protocol(format!("Parent handshake read failed: {error}")))?;
        connect
            .validate_connect(&parent_capability)
            .map_err(|error| Error::Protocol(format!("Parent Connect rejected: {error}")))?;
        write_handshake(
            &mut parent_io,
            &ReadHandshake::Connected {
                capability: parent_capability,
                session_generation: connect.session_generation(),
                descriptor: b"parent-lane".to_vec(),
            },
        )
        .await
        .map_err(|error| Error::Protocol(format!("Parent Connected write failed: {error}")))?;
        ReadLaneControl::spawn(parent_io, session_generation, 4, 16)
    };
    let child_side = async {
        write_handshake(
            &mut child_io,
            &ReadHandshake::Connect {
                capability: child_capability.clone(),
                session_generation,
                descriptor: b"child-lane".to_vec(),
            },
        )
        .await
        .map_err(|error| Error::Protocol(format!("Child Connect write failed: {error}")))?;
        let connected = read_handshake(&mut child_io)
            .await
            .map_err(|error| Error::Protocol(format!("Child handshake read failed: {error}")))?;
        connected
            .validate_connected(&child_capability, session_generation)
            .map_err(|error| Error::Protocol(format!("Child Connected rejected: {error}")))?;
        ReadLaneControl::spawn(child_io, session_generation, 4, 16)
    };
    let (parent_lane, child_lane) = tokio::join!(parent_side, child_side);
    let parent_lane = parent_lane?;
    let child_lane = child_lane?;

    // Route the transfer identity through the lane dispatchers. The Child
    // registers statically (it knows its own identity); the Parent admits the
    // transfer dynamically when the initiating BufferReady arrives.
    let identity = ReadTransferIdentity {
        session_generation,
        transfer_id: 1,
        metadata_generation: 1,
    };
    let child_control = child_lane.register(identity)?;
    let parent_fabric = fabric.clone();

    let mut source_bytes = vec![0u8; PIECE_LENGTH as usize];
    for (index, byte) in source_bytes.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    let expected_bytes = source_bytes.clone();

    // Child: run the lease-flow transport, consume the published span, recycle.
    let child_fabric = fabric.clone();
    let child_task = tokio::spawn(async move {
        // SAFETY: The harness performs the authenticated duplex handshake and
        // the destination allocation is exclusively owned by this transfer.
        let session = ChildTransportSession::new(
            child_fabric.clone(),
            child_lane_id,
            child_control,
            identity,
            ReadPieceLocator {
                kind: crate::rendezvous::PieceKind::Piece,
                task_id: "harness-task".to_string(),
                piece_number: 1,
            },
            PIECE_LENGTH,
            PIECE_LENGTH,
            MAX_READ_SIZE,
            MAX_OUTSTANDING,
            POLL_INTERVAL,
            COMPLETION_TIMEOUT,
        )?;
        let success =
            unsafe { session.run_transport_only().await }.map_err(|failure| failure.error)?;
        let lease = success.lease;
        assert_eq!(lease.span.length as u64, PIECE_LENGTH);
        // SAFETY: Every READ WR retired before publication, so the content is
        // final and no DMA touches the buffer until recycle closes it.
        let consumed = unsafe { std::slice::from_raw_parts(lease.span.data, lease.span.length) };
        if consumed != expected_bytes.as_slice() {
            return Err(Error::Protocol(
                "published READ lease content diverged from the Parent source".into(),
            ));
        }
        if !child_fabric
            .recycle_published_child_lease(lease.child_id)
            .await?
        {
            return Err(Error::Protocol(
                "recycled READ lease did not prove full budget release".into(),
            ));
        }
        Ok(())
    });

    // Parent: accept the dynamically admitted transfer, publish the immutable
    // in-memory source, and wait at the revoke gate until the Child reports
    // ReadDone.
    let accepted = parent_lane
        .accept_transfer(COMPLETION_TIMEOUT)
        .await
        .ok_or_else(|| Error::Protocol("Parent READ accept timed out".into()))?;
    if accepted.identity != identity {
        return Err(Error::Protocol(
            "Parent accepted a READ transfer with the wrong identity".into(),
        ));
    }
    let (parent_session, _locator) = ParentSourceSession::accept(
        parent_fabric,
        parent_lane_id,
        accepted.control,
        accepted.buffer_ready,
        0,
        String::new(),
        MAX_READ_SIZE,
    )?;
    let (parent, pending) = unsafe {
        parent_session
            .publish_and_wait_read_done(super::runtime::ReadSourceRequest {
                peer_id: parent_lane_id,
                backing: ReadBacking::new(
                    ReadSourceMemory::Bytes(source_bytes.into_boxed_slice()),
                    (),
                ),
                token: ReadToken::new(0x1234_5678),
            })
            .await
    }
    .map_err(|failure| failure.error)?;
    assert_eq!(
        pending.terminal,
        super::read_session::ParentTerminal::Success
    );
    assert_eq!(pending.completed_length, PIECE_LENGTH);

    // Provider revocation proof: single-process harness where the Child has
    // closed its import and the Parent received the matching ReadDone, so
    // remote access to this source generation has ceased.
    unsafe { parent.revoke_and_finish(pending).await }?;

    child_task
        .await
        .map_err(|error| Error::Protocol(format!("Child task failed: {error}")))??;
    Ok(())
}
