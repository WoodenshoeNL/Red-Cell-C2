use std::io;

use red_cell_common::demon::{DemonCommand, DemonSocketCommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::types::SOCKS_REPLY_SUCCEEDED;
use super::super::{register_pending_client, sample_agent, test_manager};

/// `write_client_data` forwards bytes from the agent to the local SOCKS client socket.
#[tokio::test]
async fn write_client_data_delivers_bytes_to_local_socks_client() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let socket_id: u32 = 0xCAFE_0001;
    let (mut peer_read, _peer_write) =
        register_pending_client(&manager, agent_id, socket_id).await?;

    manager
        .write_client_data(agent_id, socket_id, b"relay payload")
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut buf = vec![0_u8; 13];
    peer_read.read_exact(&mut buf).await?;
    assert_eq!(
        &buf, b"relay payload",
        "bytes written by write_client_data must arrive at the peer reader"
    );

    Ok(())
}

/// `close_client` removes the client from state and shuts down its write half so the peer
/// reader sees EOF.
#[tokio::test]
async fn close_client_removes_state_and_shuts_down_writer() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let socket_id: u32 = 0xCAFE_0003;
    let (mut peer_read, _peer_write) =
        register_pending_client(&manager, agent_id, socket_id).await?;

    manager.close_client(agent_id, socket_id).await.map_err(|e| io::Error::other(e.to_string()))?;

    {
        let state = manager.state.read().await;
        let agent_state =
            state.get(&agent_id).expect("agent state still present after close_client");
        assert!(
            !agent_state.clients.contains_key(&socket_id),
            "client entry must be removed by close_client"
        );
    }

    let mut buf = vec![0_u8; 1];
    let n = peer_read.read(&mut buf).await?;
    assert_eq!(n, 0, "peer reader must see EOF after close_client shuts down the writer");

    Ok(())
}

/// Verify the full data-relay round-trip after a successful `finish_connect`:
/// 1. Data written by the SOCKS client produces a `SOCKET_COMMAND_WRITE` job.
/// 2. Data delivered via `write_client_data` appears on the SOCKS client socket.
#[tokio::test]
async fn finish_connect_success_relays_data_round_trip() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xCAFE_BABE))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xCAFE_BABE;
    let socket_id: u32 = 0x0000_00AA;
    let (mut peer_read, mut peer_write) =
        register_pending_client(&manager, agent_id, socket_id).await?;

    manager
        .finish_connect(agent_id, socket_id, true, 0)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut reply = [0_u8; 10];
    peer_read.read_exact(&mut reply).await?;
    assert_eq!(reply[1], SOCKS_REPLY_SUCCEEDED, "SOCKS reply must indicate success");

    let client_payload = b"hello from client";
    peer_write.write_all(client_payload).await?;
    peer_write.flush().await?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let jobs =
        registry.dequeue_jobs(agent_id).await.map_err(|e| io::Error::other(e.to_string()))?;

    let write_cmd_le = u32::from(DemonSocketCommand::Write).to_le_bytes();
    let write_job = jobs.iter().find(|j| {
        j.command == u32::from(DemonCommand::CommandSocket)
            && j.payload.len() >= 4
            && j.payload[..4] == write_cmd_le
    });
    assert!(write_job.is_some(), "expected a SOCKET_COMMAND_WRITE job in the agent queue");

    let job = write_job.expect("write job is present");
    let job_socket_id =
        u32::from_le_bytes(job.payload[4..8].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(job_socket_id, socket_id, "job must target the correct socket_id");
    let data_len =
        u32::from_le_bytes(job.payload[8..12].try_into().expect("fixed-size slice for try_into"))
            as usize;
    assert_eq!(data_len, client_payload.len());
    assert_eq!(
        &job.payload[12..12 + data_len],
        client_payload,
        "job payload must contain the exact bytes written by the SOCKS client"
    );

    let agent_payload = b"hello from agent";
    manager
        .write_client_data(agent_id, socket_id, agent_payload)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut received = vec![0_u8; agent_payload.len()];
    peer_read.read_exact(&mut received).await?;
    assert_eq!(
        received.as_slice(),
        agent_payload,
        "SOCKS client must receive the exact bytes sent by the agent"
    );

    Ok(())
}
