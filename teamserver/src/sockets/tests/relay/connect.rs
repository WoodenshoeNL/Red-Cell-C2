use std::io;

use tokio::io::AsyncReadExt;

use super::super::super::types::{
    SOCKS_ATYP_IPV4, SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCEEDED, SOCKS_VERSION,
};
use super::super::{register_pending_client, sample_agent, test_manager};

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

    let mut response = [0_u8; 10];
    peer_read.read_exact(&mut response).await?;
    assert_eq!(
        response,
        [SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, 0, SOCKS_ATYP_IPV4, 127, 0, 0, 1, 0, 80,],
        "finish_connect(success=true) must send SOCKS_REPLY_SUCCEEDED to the client"
    );

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
