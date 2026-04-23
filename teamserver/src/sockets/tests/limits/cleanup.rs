use std::io;

use tokio::sync::oneshot;

use crate::sockets::SocksServerHandle;

use super::super::{register_pending_client, sample_agent, test_manager};

#[tokio::test]
async fn clear_socks_servers_drains_multiple_listeners_and_clients() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    let (shutdown_tx_a, _shutdown_rx_a) = oneshot::channel::<()>();
    let (shutdown_tx_b, _shutdown_rx_b) = oneshot::channel::<()>();
    let task_a = tokio::spawn(std::future::pending::<()>());
    let task_b = tokio::spawn(std::future::pending::<()>());
    {
        let mut state = manager.state.write().await;
        let agent_state = state.entry(agent_id).or_default();
        agent_state.servers.insert(
            100,
            SocksServerHandle {
                local_addr: "127.0.0.1:100".to_owned(),
                shutdown: Some(shutdown_tx_a),
                task: task_a,
            },
        );
        agent_state.servers.insert(
            200,
            SocksServerHandle {
                local_addr: "127.0.0.1:200".to_owned(),
                shutdown: Some(shutdown_tx_b),
                task: task_b,
            },
        );
    }

    let socket_a1: u32 = 0xCAFE_0010;
    let socket_a2: u32 = 0xCAFE_0011;
    let socket_b1: u32 = 0xCAFE_0020;
    let (_peer_read_a1, _peer_write_a1) =
        register_pending_client(&manager, agent_id, socket_a1).await?;
    let (_peer_read_a2, _peer_write_a2) =
        register_pending_client(&manager, agent_id, socket_a2).await?;
    let (_peer_read_b1, _peer_write_b1) =
        register_pending_client(&manager, agent_id, socket_b1).await?;
    {
        let mut state = manager.state.write().await;
        let agent_state = state.get_mut(&agent_id).expect("agent state present");
        agent_state.clients.get_mut(&socket_a1).expect("client a1").server_port = 100;
        agent_state.clients.get_mut(&socket_a2).expect("client a2").server_port = 100;
        agent_state.clients.get_mut(&socket_b1).expect("client b1").server_port = 200;
    }

    let list_before = manager.list_socks_servers(agent_id).await;
    assert!(
        list_before.contains("SOCKS5 servers"),
        "expected active servers listed, got: {list_before}"
    );

    let clear_msg =
        manager.clear_socks_servers(agent_id).await.map_err(|e| io::Error::other(e.to_string()))?;

    assert_eq!(clear_msg, "Closed 2 SOCKS5 server(s)");
    assert_eq!(manager.list_socks_servers(agent_id).await, "No active SOCKS5 servers");

    let state = manager.state.read().await;
    if let Some(agent_state) = state.get(&agent_id) {
        assert!(!agent_state.clients.contains_key(&socket_a1), "client a1 must be removed");
        assert!(!agent_state.clients.contains_key(&socket_a2), "client a2 must be removed");
        assert!(!agent_state.clients.contains_key(&socket_b1), "client b1 must be removed");
        assert!(agent_state.servers.is_empty(), "all server entries must be removed");
    }

    Ok(())
}

#[tokio::test]
async fn state_is_reclaimed_after_mass_client_removal() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let count = 200_usize;

    for i in 0..count {
        let socket_id = i as u32;
        let (_peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;
    }

    {
        let state = manager.state.read().await;
        assert_eq!(state.get(&agent_id).map_or(0, |s| s.clients.len()), count);
    }

    for i in 0..count {
        let socket_id = i as u32;
        manager
            .close_client(agent_id, socket_id)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
    }

    let state = manager.state.read().await;
    let remaining = state.get(&agent_id).map_or(0, |s| s.clients.len());
    assert_eq!(remaining, 0, "all client entries must be removed after close_client");

    Ok(())
}

#[tokio::test]
async fn remove_agent_clears_all_clients_under_load() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let count = 200_usize;

    for i in 0..count {
        let socket_id = i as u32;
        let (_peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;
    }

    assert!(manager.remove_agent(agent_id).await);
    assert!(!manager.state.read().await.contains_key(&agent_id));

    Ok(())
}
