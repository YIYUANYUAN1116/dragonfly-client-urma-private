//! Two-process memory-to-memory READ session harness.
//!
//! Parent and Child can run on separate hosts so each endpoint owns an
//! independent real URMA context, EID, and RM Jetty. The Parent hosts a boxed
//! in-memory source, the Child owns a fabric-registered destination, and TCP
//! carries the production version-5 control protocol. With no explicit role,
//! the test also starts a local Child process for providers that support RM
//! loopback. This covers handshake, peer import, transfer routing, READ
//! completion, publication, CPU consumption, recycle, and native shutdown.
//!
//! Gated behind `#[ignore]` because initialization opens a real provider.
//! Run with:
//! `URMA_TEST_DEVICE=urma0 cargo test -p dragonfly-client-storage --features urma \
//!  rm_read_memory_to_memory_session -- --ignored --nocapture`

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
use std::{
    process::{Command, ExitStatus, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PIECE_LENGTH: u64 = 256 * 1024;
const MAX_READ_SIZE: u32 = 1024 * 1024;
const MAX_JFS_SGE: u32 = 4;
const MAX_OUTSTANDING: usize = 8;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(1);
const CHILD_ROLE_ENV: &str = "DRAGONFLY_URMA_READ_HARNESS_CHILD";
const CONTROL_ADDR_ENV: &str = "DRAGONFLY_URMA_READ_HARNESS_ADDR";
const TEST_ROLE_ENV: &str = "URMA_TEST_ROLE";
const TEST_CONTROL_ADDR_ENV: &str = "URMA_TEST_CONTROL_ADDR";
const CHILD_COMPLETED: &[u8] = b"DFUR-RM-READ-PASS";
const EXACT_TEST_NAME: &str = "urma::read_session_harness::rm_read_memory_to_memory_session";

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
    let config = RuntimeConfig::new(device, eid_index)
        .with_registered_budget(4 * 1024 * 1024, 2 * 1024 * 1024)?
        .with_tp_type(TpType::Ctp)
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

fn source_bytes() -> Vec<u8> {
    (0..PIECE_LENGTH).map(|index| (index % 251) as u8).collect()
}

async fn run_child(device: &str, eid_index: u32, address: &str) -> Result<()> {
    let fabric = harness_fabric(device, eid_index)?;
    let (lane_id, descriptor) = fabric.create_lane(PeerTargetConfig::default()).await?;
    let capability = lane_capability(&fabric);
    let session_generation = next_session_generation()?;
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|error| Error::Protocol(format!("Child control connect failed: {error}")))?;

    write_handshake(
        &mut stream,
        &ReadHandshake::Connect {
            capability: capability.clone(),
            session_generation,
            descriptor,
        },
    )
    .await
    .map_err(|error| Error::Protocol(format!("Child Connect write failed: {error}")))?;
    let connected = read_handshake(&mut stream)
        .await
        .map_err(|error| Error::Protocol(format!("Child handshake read failed: {error}")))?;
    let (_, parent_descriptor) = connected
        .validate_connected(&capability, session_generation)
        .map_err(|error| Error::Protocol(format!("Child Connected rejected: {error}")))?;
    fabric
        .connect_lane(lane_id, parent_descriptor.to_vec())
        .await
        .map_err(|error| Error::Protocol(format!("Child lane connect failed: {error}")))?;

    let lane = ReadLaneControl::spawn(stream, session_generation, 4, 16)?;
    let identity = ReadTransferIdentity {
        session_generation,
        transfer_id: 1,
        metadata_generation: 1,
    };
    let control = lane.register(identity)?;
    // SAFETY: The version-5 handshake generation-binds the authenticated peer
    // descriptor and this process exclusively owns the destination Piece.
    let session = ChildTransportSession::new(
        fabric.clone(),
        lane_id,
        control,
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
    let success = unsafe { session.run_transport_only().await }.map_err(|failure| failure.error)?;
    let lease = success.lease;
    if lease.span.length as u64 != PIECE_LENGTH {
        return Err(Error::Protocol(
            "published READ lease length mismatch".into(),
        ));
    }
    // SAFETY: all READ WRs retired before publication. The lease prevents
    // recycle while the immutable span is consumed here.
    let consumed = unsafe { std::slice::from_raw_parts(lease.span.data, lease.span.length) };
    if consumed != source_bytes().as_slice() {
        return Err(Error::Protocol(
            "published READ lease content diverged from the Parent source".into(),
        ));
    }
    if !fabric.recycle_published_child_lease(lease.child_id).await? {
        return Err(Error::Protocol(
            "recycled READ lease did not prove full budget release".into(),
        ));
    }

    drop(lane);
    fabric.close_lane(lane_id).await?;
    fabric.shutdown().await
}

struct ActiveParent {
    lane: ReadLaneControl,
    fabric: UrmaFabricHandle,
    lane_id: u16,
}

impl ActiveParent {
    async fn shutdown(self) -> Result<()> {
        drop(self.lane);
        self.fabric.close_lane(self.lane_id).await?;
        self.fabric.shutdown().await
    }
}

async fn wait_child(child: &mut std::process::Child) -> Result<ExitStatus> {
    let deadline = tokio::time::Instant::now() + COMPLETION_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| Error::Protocol(format!("wait for Child process failed: {error}")))?
        {
            return Ok(status);
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Protocol("Child process exit timed out".into()));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn report_child_completed(address: &str) -> Result<()> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|error| Error::Protocol(format!("Child result connect failed: {error}")))?;
    stream
        .write_all(CHILD_COMPLETED)
        .await
        .map_err(|error| Error::Protocol(format!("Child result write failed: {error}")))
}

async fn wait_child_completed(listener: &TcpListener) -> Result<()> {
    let result = tokio::time::timeout(PEER_TIMEOUT, async {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|error| Error::Protocol(format!("Parent result accept failed: {error}")))?;
        let mut completed = [0u8; CHILD_COMPLETED.len()];
        stream
            .read_exact(&mut completed)
            .await
            .map_err(|error| Error::Protocol(format!("Parent result read failed: {error}")))?;
        if completed != CHILD_COMPLETED {
            return Err(Error::Protocol("Child result marker mismatch".into()));
        }
        Ok(())
    })
    .await;
    result.map_err(|_| Error::Protocol("Child completion report timed out".into()))?
}

async fn run_parent(device: &str, eid_index: u32, listener: &TcpListener) -> Result<ActiveParent> {
    let fabric = harness_fabric(device, eid_index)?;
    let (mut stream, _) = tokio::time::timeout(PEER_TIMEOUT, listener.accept())
        .await
        .map_err(|_| Error::Protocol("Parent control accept timed out".into()))?
        .map_err(|error| Error::Protocol(format!("Parent control accept failed: {error}")))?;
    let connect = read_handshake(&mut stream)
        .await
        .map_err(|error| Error::Protocol(format!("Parent handshake read failed: {error}")))?;
    let capability = lane_capability(&fabric);
    let (session_generation, _, child_descriptor) = connect
        .validate_connect(&capability)
        .map_err(|error| Error::Protocol(format!("Parent Connect rejected: {error}")))?;
    let child_descriptor = child_descriptor.to_vec();
    let (lane_id, parent_descriptor) = fabric.create_lane(PeerTargetConfig::default()).await?;
    write_handshake(
        &mut stream,
        &ReadHandshake::Connected {
            capability,
            session_generation,
            descriptor: parent_descriptor,
        },
    )
    .await
    .map_err(|error| Error::Protocol(format!("Parent Connected write failed: {error}")))?;
    // CTP TP-aware import needs both peers to know the opposite EID before
    // either side activates its local TP handle. Publish our descriptor before
    // importing the Child so both sides can enter connect concurrently.
    fabric
        .connect_lane(lane_id, child_descriptor)
        .await
        .map_err(|error| Error::Protocol(format!("Parent lane connect failed: {error}")))?;

    let lane = ReadLaneControl::spawn(stream, session_generation, 4, 16)?;
    let identity = ReadTransferIdentity {
        session_generation,
        transfer_id: 1,
        metadata_generation: 1,
    };
    let accepted = lane
        .accept_transfer(COMPLETION_TIMEOUT)
        .await
        .ok_or_else(|| Error::Protocol("Parent READ accept timed out".into()))?;
    if accepted.identity != identity {
        return Err(Error::Protocol(
            "Parent accepted a READ transfer with the wrong identity".into(),
        ));
    }
    let (session, _locator) = ParentSourceSession::accept(
        fabric.clone(),
        lane_id,
        accepted.control,
        accepted.buffer_ready,
        0,
        String::new(),
        MAX_READ_SIZE,
    )?;
    let (parent, pending) = unsafe {
        session
            .publish_and_wait_read_done(super::runtime::ReadSourceRequest {
                peer_id: lane_id,
                backing: ReadBacking::new(
                    ReadSourceMemory::Bytes(source_bytes().into_boxed_slice()),
                    (),
                ),
                token: ReadToken::new(0x1234_5678),
            })
            .await
    }
    .map_err(|failure| failure.error)?;
    if pending.terminal != super::read_session::ParentTerminal::Success
        || pending.completed_length != PIECE_LENGTH
    {
        return Err(Error::Protocol(
            "Parent received an invalid READ terminal state".into(),
        ));
    }

    // SAFETY: this controlled child is the only descriptor recipient and its
    // state machine closed the import before sending the matching ReadDone.
    // This proves this test's cooperative lifetime; it does not establish the
    // provider-wide stale-descriptor revocation property used by production.
    unsafe { parent.revoke_and_finish(pending).await }?;

    // Done is queued on the control writer. Keep the lane alive until the
    // Child exits so dropping it cannot race delivery of the terminal frame.
    Ok(ActiveParent {
        lane,
        fabric,
        lane_id,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a real URMA provider; set URMA_TEST_DEVICE and URMA_TEST_EID_INDEX"]
async fn rm_read_memory_to_memory_session() -> Result<()> {
    let device = std::env::var("URMA_TEST_DEVICE").unwrap_or_else(|_| "urma0".to_string());
    let eid_index: u32 = std::env::var("URMA_TEST_EID_INDEX")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    let external_role = std::env::var(TEST_ROLE_ENV).ok();
    let is_child =
        std::env::var_os(CHILD_ROLE_ENV).is_some() || external_role.as_deref() == Some("child");
    if is_child {
        let address = std::env::var(TEST_CONTROL_ADDR_ENV)
            .or_else(|_| std::env::var(CONTROL_ADDR_ENV))
            .map_err(|_| {
                Error::InvalidConfiguration(format!("{TEST_CONTROL_ADDR_ENV} is not set for Child"))
            })?;
        run_child(&device, eid_index, &address).await?;
        return report_child_completed(&address).await;
    }

    if external_role
        .as_deref()
        .is_some_and(|role| role != "parent")
    {
        return Err(Error::InvalidConfiguration(format!(
            "{TEST_ROLE_ENV} must be parent or child"
        )));
    }

    let bind_address = if external_role.as_deref() == Some("parent") {
        std::env::var(TEST_CONTROL_ADDR_ENV).map_err(|_| {
            Error::InvalidConfiguration(format!("{TEST_CONTROL_ADDR_ENV} is not set for Parent"))
        })?
    } else {
        "127.0.0.1:0".to_string()
    };
    let listener = TcpListener::bind(&bind_address)
        .await
        .map_err(|error| Error::Protocol(format!("Parent control bind failed: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| Error::Protocol(format!("Parent local address failed: {error}")))?;
    let mut child = if external_role.as_deref() == Some("parent") {
        None
    } else {
        let executable = std::env::current_exe()
            .map_err(|error| Error::Protocol(format!("resolve test executable failed: {error}")))?;
        Some(
            Command::new(executable)
                .args([
                    "--exact",
                    EXACT_TEST_NAME,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ROLE_ENV, "1")
                .env(CONTROL_ADDR_ENV, address.to_string())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|error| {
                    Error::Protocol(format!("spawn Child test process failed: {error}"))
                })?,
        )
    };

    let parent = match run_parent(&device, eid_index, &listener).await {
        Ok(parent) => parent,
        Err(error) => {
            if let Some(child) = child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(error);
        }
    };
    let completed = wait_child_completed(&listener).await;
    let status = match child.as_mut() {
        Some(child) => Some(wait_child(child).await),
        None => None,
    };
    let shutdown = parent.shutdown().await;
    completed?;
    if let Some(status) = status {
        let status = status?;
        if !status.success() {
            return Err(Error::Protocol(format!(
                "Child test process exited with {status}"
            )));
        }
    }
    shutdown?;
    Ok(())
}
