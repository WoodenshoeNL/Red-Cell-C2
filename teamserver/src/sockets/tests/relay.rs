use std::io;

use tokio::io::AsyncReadExt;

use super::super::SocketRelayError;
use super::super::types::{
    SOCKS_ATYP_IPV4, SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCEEDED, SOCKS_VERSION,
};
use super::{register_pending_client, sample_agent, test_manager};

#[tokio::test]
async fn write_client_data_returns_client_not_found_for_unknown_agent()
-> Result<(), SocketRelayError> {
    let (_database, _registry, manager) = test_manager().await?;

    let result = manager.write_client_data(0xDEAD_BEEF, 0x1234_5678, b"relay").await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));

    Ok(())
}

#[tokio::test]
async fn write_client_data_returns_client_not_found_for_unknown_socket()
-> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;
    manager.add_socks_server(0xDEAD_BEEF, "0").await?;

    let result = manager.write_client_data(0xDEAD_BEEF, 0x1234_5678, b"relay").await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));
    manager.clear_socks_servers(0xDEAD_BEEF).await?;

    Ok(())
}

#[tokio::test]
async fn close_client_returns_client_not_found_for_unknown_agent() -> Result<(), SocketRelayError> {
    let (_database, _registry, manager) = test_manager().await?;

    let result = manager.close_client(0xDEAD_BEEF, 0x1234_5678).await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));

    Ok(())
}

#[tokio::test]
async fn close_client_returns_client_not_found_for_unknown_socket() -> Result<(), SocketRelayError>
{
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;
    manager.add_socks_server(0xDEAD_BEEF, "0").await?;

    let result = manager.close_client(0xDEAD_BEEF, 0x1234_5678).await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));
    manager.clear_socks_servers(0xDEAD_BEEF).await?;

    Ok(())
}

#[tokio::test]
async fn finish_connect_success_sends_succeeded_reply_and_retains_client() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let socket_id: u32 = 0x0000_0001;
    let (mut peer_read, _peer_write) =
        register_pending_client(&manager, agent_id, socket_id).await?;

    manager
        .finish_connect(agent_id, socket_id, true, 0)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    // SOCKS5 reply: VER=5, REP=0(succeeded), RSV=0, ATYP=1(IPv4), ADDR=127.0.0.1,
    // PORT=80 big-endian → [0, 80]
    let mut response = [0_u8; 10];
    peer_read.read_exact(&mut response).await?;
    assert_eq!(
        response,
        [SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, 0, SOCKS_ATYP_IPV4, 127, 0, 0, 1, 0, 80,],
        "finish_connect(success=true) must send SOCKS_REPLY_SUCCEEDED to the client"
    );

    // On success the client entry must remain in the manager state so that subsequent
    // write_client_data and close_client calls can find it.
    let state = manager.state.read().await;
    assert!(
        state.get(&agent_id).is_some_and(|s| s.clients.contains_key(&socket_id)),
        "client must remain in state after a successful connect"
    );

    Ok(())
}

#[tokio::test]
async fn finish_connect_failure_sends_error_reply_and_removes_client() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let socket_id: u32 = 0x0000_0002;
    let (mut peer_read, _peer_write) =
        register_pending_client(&manager, agent_id, socket_id).await?;

    // error_code=5 fits in u8, so the reply byte must be exactly 5.
    manager
        .finish_connect(agent_id, socket_id, false, 5)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut response = [0_u8; 10];
    peer_read.read_exact(&mut response).await?;
    assert_eq!(
        response,
        [SOCKS_VERSION, 5, 0, SOCKS_ATYP_IPV4, 127, 0, 0, 1, 0, 80],
        "finish_connect(success=false, error_code=5) must send reply byte 5"
    );

    // On failure the client must be removed so no further relay traffic is forwarded.
    let state = manager.state.read().await;
    assert!(
        !state.get(&agent_id).is_some_and(|s| s.clients.contains_key(&socket_id)),
        "client must be removed from state after a failed connect"
    );

    Ok(())
}

#[tokio::test]
async fn finish_connect_failure_out_of_range_error_code_uses_general_failure() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let socket_id: u32 = 0x0000_0003;
    let (mut peer_read, _peer_write) =
        register_pending_client(&manager, agent_id, socket_id).await?;

    // error_code=300 does not fit in u8; the implementation falls back to
    // SOCKS_REPLY_GENERAL_FAILURE (1).
    manager
        .finish_connect(agent_id, socket_id, false, 300)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut response = [0_u8; 10];
    peer_read.read_exact(&mut response).await?;
    assert_eq!(
        response[1], SOCKS_REPLY_GENERAL_FAILURE,
        "error_code values that do not fit in u8 must fall back to SOCKS_REPLY_GENERAL_FAILURE"
    );

    let state = manager.state.read().await;
    assert!(
        !state.get(&agent_id).is_some_and(|s| s.clients.contains_key(&socket_id)),
        "client must be removed from state after a failed connect"
    );

    Ok(())
}

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

    // The client entry must be gone from state.
    {
        let state = manager.state.read().await;
        let agent_state =
            state.get(&agent_id).expect("agent state still present after close_client");
        assert!(
            !agent_state.clients.contains_key(&socket_id),
            "client entry must be removed by close_client"
        );
    }

    // The writer shutdown must have propagated as EOF to the peer reader.
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
    use red_cell_common::demon::{DemonCommand, DemonSocketCommand};
    use tokio::io::AsyncWriteExt;

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

    // Complete the SOCKS5 handshake successfully.
    manager
        .finish_connect(agent_id, socket_id, true, 0)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    // Consume the SOCKS5 CONNECT reply (10 bytes for IPv4).
    let mut reply = [0_u8; 10];
    peer_read.read_exact(&mut reply).await?;
    assert_eq!(reply[1], SOCKS_REPLY_SUCCEEDED, "SOCKS reply must indicate success");

    // --- Direction 1: SOCKS client → agent (produces a write job) ---
    let client_payload = b"hello from client";
    peer_write.write_all(client_payload).await?;
    // Flush to ensure the reader task picks it up.
    peer_write.flush().await?;

    // Give the spawned reader task a moment to process.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let jobs =
        registry.dequeue_jobs(agent_id).await.map_err(|e| io::Error::other(e.to_string()))?;

    // Find the write job among any queued jobs.
    let write_cmd_le = u32::from(DemonSocketCommand::Write).to_le_bytes();
    let write_job = jobs.iter().find(|j| {
        j.command == u32::from(DemonCommand::CommandSocket)
            && j.payload.len() >= 4
            && j.payload[..4] == write_cmd_le
    });
    assert!(write_job.is_some(), "expected a SOCKET_COMMAND_WRITE job in the agent queue");

    let job = write_job.expect("unwrap");
    // Payload layout: [subcmd:4][socket_id:4][len:4][data:len]
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

    // --- Direction 2: agent → SOCKS client (write_client_data) ---
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
