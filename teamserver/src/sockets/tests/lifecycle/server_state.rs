use tokio::sync::oneshot;

use super::super::super::{SocketRelayError, SocksServerHandle};
use super::super::{register_pending_client, sample_agent, test_manager};

#[tokio::test]
async fn socks_server_lifecycle_commands_track_state() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;

    let start = manager.add_socks_server(0xDEAD_BEEF, "0").await;
    assert!(start.is_ok());
    assert!(start.as_deref().is_ok_and(|message| message.contains("127.0.0.1:")));
    assert!(manager.list_socks_servers(0xDEAD_BEEF).await.contains("SOCKS5 servers"));
    let cleared = manager.clear_socks_servers(0xDEAD_BEEF).await;
    assert!(cleared.is_ok());
    assert_eq!(manager.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

    Ok(())
}

#[tokio::test]
async fn add_socks_server_rejects_invalid_port() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;

    let invalid_text = manager.add_socks_server(0xDEAD_BEEF, "not-a-port").await;
    assert!(matches!(
        invalid_text,
        Err(SocketRelayError::InvalidPort { port }) if port == "not-a-port"
    ));

    let out_of_range = manager.add_socks_server(0xDEAD_BEEF, "99999").await;
    assert!(matches!(
        out_of_range,
        Err(SocketRelayError::InvalidPort { port }) if port == "99999"
    ));

    Ok(())
}

#[tokio::test]
async fn add_socks_server_rejects_duplicate_server_registration() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;

    let duplicate_port = 0;
    let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    {
        let mut state = manager.state.write().await;
        let agent_state = state.entry(0xDEAD_BEEF).or_default();
        agent_state.servers.insert(
            duplicate_port,
            SocksServerHandle {
                local_addr: "127.0.0.1:0".to_owned(),
                shutdown: Some(shutdown_tx),
                task,
            },
        );
    }

    let duplicate = manager.add_socks_server(0xDEAD_BEEF, &duplicate_port.to_string()).await;
    assert!(matches!(
        duplicate,
        Err(SocketRelayError::DuplicateServer { agent_id, port })
            if agent_id == 0xDEAD_BEEF && port == duplicate_port
    ));

    manager.clear_socks_servers(0xDEAD_BEEF).await?;

    Ok(())
}

#[tokio::test]
async fn remove_socks_server_returns_server_not_found_for_unknown_agent()
-> Result<(), SocketRelayError> {
    let (_database, _registry, manager) = test_manager().await?;

    let result = manager.remove_socks_server(0xDEAD_BEEF, "1080").await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ServerNotFound { agent_id, port })
            if agent_id == 0xDEAD_BEEF && port == 1080
    ));

    Ok(())
}

#[tokio::test]
async fn remove_socks_server_returns_server_not_found_for_unknown_port()
-> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;
    manager.add_socks_server(0xDEAD_BEEF, "0").await?;

    let result = manager.remove_socks_server(0xDEAD_BEEF, "65535").await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ServerNotFound { agent_id, port })
            if agent_id == 0xDEAD_BEEF && port == 65535
    ));
    manager.clear_socks_servers(0xDEAD_BEEF).await?;

    Ok(())
}

#[tokio::test]
async fn clear_socks_servers_returns_error_for_invalid_local_addr() -> Result<(), SocketRelayError>
{
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;

    let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    {
        let mut state = manager.state.write().await;
        let agent_state = state.entry(0xDEAD_BEEF).or_default();
        agent_state.servers.insert(
            1080,
            SocksServerHandle {
                local_addr: "invalid-address".to_owned(),
                shutdown: Some(shutdown_tx),
                task,
            },
        );
    }

    let result = manager.clear_socks_servers(0xDEAD_BEEF).await;

    assert!(matches!(
        result,
        Err(SocketRelayError::InvalidLocalAddress { local_addr }) if local_addr == "invalid-address"
    ));

    Ok(())
}

/// `remove_socks_server` returns a close message and removes both the server entry and any
/// clients that were on that port from the manager state.
///
/// `add_socks_server("0")` stores the server under key `0` (the *requested* port), so
/// `remove_socks_server` must also use `"0"`. The `local_addr` field in the handle carries
/// the real ephemeral port assigned by the OS, which appears in the close message.
#[tokio::test]
async fn remove_socks_server_returns_close_message_and_removes_client_state() -> std::io::Result<()>
{
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| std::io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    let start_msg = manager
        .add_socks_server(agent_id, "0")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    assert!(
        start_msg.starts_with("Started SOCKS5 server on 127.0.0.1:"),
        "unexpected start message: {start_msg}"
    );

    let socket_id: u32 = 0xCAFE_0002;
    let (_, _peer_write) = register_pending_client(&manager, agent_id, socket_id).await?;
    {
        let mut state = manager.state.write().await;
        let agent_state = state.get_mut(&agent_id).expect("agent state present");
        let client = agent_state.clients.get_mut(&socket_id).expect("client present");
        client.server_port = 0;
    }

    let close_msg = manager
        .remove_socks_server(agent_id, "0")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    assert!(
        close_msg.starts_with("Closed SOCKS5 server on 127.0.0.1:"),
        "close message should contain the bound address, got: {close_msg}"
    );

    let state = manager.state.read().await;
    let agent_state = state.get(&agent_id).expect("agent state still present after remove");
    assert!(
        !agent_state.servers.contains_key(&0_u16),
        "server entry must be removed after remove_socks_server"
    );
    assert!(
        !agent_state.clients.contains_key(&socket_id),
        "client entry must be removed when its server is stopped"
    );

    Ok(())
}
