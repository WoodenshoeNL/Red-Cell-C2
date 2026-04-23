use std::io;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::sockets::types::{
    MAX_GLOBAL_SOCKETS, MAX_SOCKETS_PER_AGENT, PendingClient, SOCKS_ATYP_IPV4,
};
use crate::sockets::{SocketRelayError, SocksServerHandle};

use super::super::{register_pending_client, sample_agent, test_manager};

#[tokio::test]
async fn register_client_rejects_when_per_agent_limit_reached() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    for i in 0..MAX_SOCKETS_PER_AGENT {
        let socket_id = i as u32;
        let (_peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;
    }

    {
        let state = manager.state.read().await;
        let agent_state = state.get(&agent_id).expect("agent state present");
        assert_eq!(agent_state.clients.len(), MAX_SOCKETS_PER_AGENT);
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
    let (server_stream, _) = listener.accept().await?;
    let client_stream = connect_task.await.map_err(|e| io::Error::other(e.to_string()))??;
    let (client_read, client_write) = client_stream.into_split();
    let (_server_read, _server_write) = server_stream.into_split();

    let result = manager
        .register_client(
            agent_id,
            0xFFFF_FFFF,
            PendingClient {
                server_port: 1080,
                atyp: SOCKS_ATYP_IPV4,
                address: vec![127, 0, 0, 1],
                port: 80,
                connected: false,
                writer: Arc::new(tokio::sync::Mutex::new(client_write)),
                read_half: Some(client_read),
            },
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SocketRelayError::AgentConnectionLimit { agent_id: id, limit })
                if id == agent_id && limit == MAX_SOCKETS_PER_AGENT
        ),
        "expected AgentConnectionLimit, got: {result:?}"
    );

    Ok(())
}

#[tokio::test]
async fn register_client_rejects_when_global_limit_reached() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;

    let agents_needed = MAX_GLOBAL_SOCKETS.div_ceil(MAX_SOCKETS_PER_AGENT);
    let clients_per_agent = MAX_GLOBAL_SOCKETS / agents_needed;

    for agent_idx in 0..agents_needed {
        let agent_id = (agent_idx as u32) + 1;
        registry
            .insert(sample_agent(agent_id))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
    }

    let mut total_inserted = 0_usize;
    for agent_idx in 0..agents_needed {
        let agent_id = (agent_idx as u32) + 1;
        let to_insert = if total_inserted + clients_per_agent > MAX_GLOBAL_SOCKETS {
            MAX_GLOBAL_SOCKETS - total_inserted
        } else {
            clients_per_agent
        };
        for i in 0..to_insert {
            let socket_id = ((agent_idx * clients_per_agent) + i) as u32;
            let (_peer_read, _peer_write) =
                register_pending_client(&manager, agent_id, socket_id).await?;
        }
        total_inserted += to_insert;
        if total_inserted >= MAX_GLOBAL_SOCKETS {
            break;
        }
    }

    {
        let state = manager.state.read().await;
        let global_count: usize = state.values().map(|s| s.clients.len()).sum();
        assert_eq!(global_count, MAX_GLOBAL_SOCKETS);
    }

    let target_agent = 1_u32;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
    let (server_stream, _) = listener.accept().await?;
    let client_stream = connect_task.await.map_err(|e| io::Error::other(e.to_string()))??;
    let (client_read, client_write) = client_stream.into_split();
    let (_server_read, _server_write) = server_stream.into_split();

    let result = manager
        .register_client(
            target_agent,
            0xFFFF_FFFF,
            PendingClient {
                server_port: 1080,
                atyp: SOCKS_ATYP_IPV4,
                address: vec![127, 0, 0, 1],
                port: 80,
                connected: false,
                writer: Arc::new(tokio::sync::Mutex::new(client_write)),
                read_half: Some(client_read),
            },
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SocketRelayError::GlobalConnectionLimit { limit })
                if limit == MAX_GLOBAL_SOCKETS
        ),
        "expected GlobalConnectionLimit, got: {result:?}"
    );

    Ok(())
}

#[tokio::test]
async fn add_socks_server_rejects_when_listener_limit_reached() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;

    let agents_needed = crate::sockets::MAX_RELAY_LISTENERS.div_ceil(10);
    for agent_idx in 0..agents_needed {
        let agent_id = (agent_idx as u32) + 1;
        registry.insert(sample_agent(agent_id)).await?;
    }

    let mut total_inserted = 0_usize;
    {
        let mut state = manager.state.write().await;
        for agent_idx in 0..agents_needed {
            let agent_id = (agent_idx as u32) + 1;
            let agent_state = state.entry(agent_id).or_default();
            let to_insert = std::cmp::min(10, crate::sockets::MAX_RELAY_LISTENERS - total_inserted);
            for i in 0..to_insert {
                let port = ((agent_idx * 10) + i) as u16 + 10000;
                let (shutdown_tx, _shutdown_rx) = oneshot::channel::<()>();
                let task = tokio::spawn(std::future::pending::<()>());
                agent_state.servers.insert(
                    port,
                    SocksServerHandle {
                        local_addr: format!("127.0.0.1:{port}"),
                        shutdown: Some(shutdown_tx),
                        task,
                    },
                );
            }
            total_inserted += to_insert;
            if total_inserted >= crate::sockets::MAX_RELAY_LISTENERS {
                break;
            }
        }
    }

    {
        let state = manager.state.read().await;
        let total: usize = state.values().map(|s| s.servers.len()).sum();
        assert_eq!(total, crate::sockets::MAX_RELAY_LISTENERS);
    }

    let new_agent_id = (agents_needed as u32) + 100;
    registry.insert(sample_agent(new_agent_id)).await?;
    let result = manager.add_socks_server(new_agent_id, "0").await;

    assert!(
        matches!(
            result,
            Err(SocketRelayError::ListenerLimit { limit })
                if limit == crate::sockets::MAX_RELAY_LISTENERS
        ),
        "expected ListenerLimit, got: {result:?}"
    );

    Ok(())
}
