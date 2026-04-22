use std::io;

use tokio::net::{TcpListener, TcpStream};

use super::super::types::{
    MAX_GLOBAL_SOCKETS, MAX_SOCKETS_PER_AGENT, PendingClient, SOCKS_ATYP_IPV4,
};
use super::super::{SocketRelayError, SocksServerHandle};
use super::{register_pending_client, sample_agent, test_manager};
use std::sync::Arc;
use tokio::sync::oneshot;

#[tokio::test]
async fn register_client_rejects_when_per_agent_limit_reached() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    // Fill up to the per-agent limit by inserting fake clients directly.
    for i in 0..MAX_SOCKETS_PER_AGENT {
        let socket_id = i as u32;
        let (_peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;
    }

    // Verify the agent has exactly MAX_SOCKETS_PER_AGENT clients.
    {
        let state = manager.state.read().await;
        let agent_state = state.get(&agent_id).expect("agent state present");
        assert_eq!(agent_state.clients.len(), MAX_SOCKETS_PER_AGENT);
    }

    // The next registration must be rejected.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
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

    // Spread clients across multiple agents to hit the global limit without hitting
    // the per-agent limit. We need MAX_GLOBAL_SOCKETS total clients.
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

    // Verify global count.
    {
        let state = manager.state.read().await;
        let global_count: usize = state.values().map(|s| s.clients.len()).sum();
        assert_eq!(global_count, MAX_GLOBAL_SOCKETS);
    }

    // The next registration on any agent must fail with GlobalConnectionLimit.
    let target_agent = 1_u32;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
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

    // Fill up to the listener limit by inserting fake server handles.
    let agents_needed = super::super::MAX_RELAY_LISTENERS.div_ceil(10); // ≤10 servers per agent
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
            let to_insert = std::cmp::min(10, super::super::MAX_RELAY_LISTENERS - total_inserted);
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
            if total_inserted >= super::super::MAX_RELAY_LISTENERS {
                break;
            }
        }
    }

    // Verify total listener count.
    {
        let state = manager.state.read().await;
        let total: usize = state.values().map(|s| s.servers.len()).sum();
        assert_eq!(total, super::super::MAX_RELAY_LISTENERS);
    }

    // The next server addition must fail.
    let new_agent_id = (agents_needed as u32) + 100;
    registry.insert(sample_agent(new_agent_id)).await?;
    let result = manager.add_socks_server(new_agent_id, "0").await;

    assert!(
        matches!(
            result,
            Err(SocketRelayError::ListenerLimit { limit })
                if limit == super::super::MAX_RELAY_LISTENERS
        ),
        "expected ListenerLimit, got: {result:?}"
    );

    Ok(())
}

/// `clear_socks_servers` with multiple listeners shuts down every server, removes all
/// client state tied to each port, and returns the correct count message.
#[tokio::test]
async fn clear_socks_servers_drains_multiple_listeners_and_clients() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    // Insert two fake server handles on distinct ports (100 and 200).
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

    // Register two clients on port 100 and one on port 200.
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

    // Verify pre-condition: list reports both servers.
    let list_before = manager.list_socks_servers(agent_id).await;
    assert!(
        list_before.contains("SOCKS5 servers"),
        "expected active servers listed, got: {list_before}"
    );

    // Clear all servers for the agent.
    let clear_msg =
        manager.clear_socks_servers(agent_id).await.map_err(|e| io::Error::other(e.to_string()))?;

    // The message must report 2 servers closed.
    assert_eq!(clear_msg, "Closed 2 SOCKS5 server(s)");

    // list_socks_servers must report none.
    assert_eq!(manager.list_socks_servers(agent_id).await, "No active SOCKS5 servers");

    // All client entries must be gone.
    let state = manager.state.read().await;
    if let Some(agent_state) = state.get(&agent_id) {
        assert!(!agent_state.clients.contains_key(&socket_a1), "client a1 must be removed");
        assert!(!agent_state.clients.contains_key(&socket_a2), "client a2 must be removed");
        assert!(!agent_state.clients.contains_key(&socket_b1), "client b1 must be removed");
        assert!(agent_state.servers.is_empty(), "all server entries must be removed");
    }

    Ok(())
}

/// Many clients registering concurrently on the same agent must all succeed up to the limit,
/// and the state must be consistent afterward (no lost entries, no duplicates).
#[tokio::test]
async fn concurrent_client_registrations_on_same_agent_are_consistent() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let count = 100_usize;

    // Spawn `count` concurrent registration tasks.
    let mut handles = Vec::with_capacity(count);
    for i in 0..count {
        let m = manager.clone();
        handles.push(tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
            let (server_stream, _) = listener.accept().await?;
            let client_stream =
                connect_task.await.map_err(|e| io::Error::other(e.to_string()))??;
            let (client_read, client_write) = client_stream.into_split();
            let (_server_read, _server_write) = server_stream.into_split();

            let socket_id = i as u32;
            let result = m
                .register_client(
                    agent_id,
                    socket_id,
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
            io::Result::Ok(result.is_ok())
        }));
    }

    let mut success_count = 0_usize;
    for handle in handles {
        if handle.await.map_err(|e| io::Error::other(e.to_string()))?? {
            success_count += 1;
        }
    }

    // All 100 should succeed (well under the 256 per-agent limit).
    assert_eq!(success_count, count, "all concurrent registrations should succeed");

    let state = manager.state.read().await;
    let agent_state = state.get(&agent_id).expect("agent state present");
    assert_eq!(
        agent_state.clients.len(),
        count,
        "all {count} clients must be present in state after concurrent registration"
    );

    Ok(())
}

/// When concurrent registrations push past the per-agent limit, excess clients must be
/// rejected with `AgentConnectionLimit` — no more than `MAX_SOCKETS_PER_AGENT` succeed.
#[tokio::test]
async fn concurrent_registrations_respect_per_agent_limit() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    // Try to register more than the limit concurrently.
    let attempt_count = MAX_SOCKETS_PER_AGENT + 50;

    let mut handles = Vec::with_capacity(attempt_count);
    for i in 0..attempt_count {
        let m = manager.clone();
        handles.push(tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
            let (server_stream, _) = listener.accept().await?;
            let client_stream =
                connect_task.await.map_err(|e| io::Error::other(e.to_string()))??;
            let (client_read, client_write) = client_stream.into_split();
            let (_server_read, _server_write) = server_stream.into_split();

            let socket_id = i as u32;
            let result = m
                .register_client(
                    agent_id,
                    socket_id,
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
            io::Result::Ok(result.is_ok())
        }));
    }

    let mut success_count = 0_usize;
    for handle in handles {
        if handle.await.map_err(|e| io::Error::other(e.to_string()))?? {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, MAX_SOCKETS_PER_AGENT,
        "exactly MAX_SOCKETS_PER_AGENT registrations should succeed"
    );

    let state = manager.state.read().await;
    let agent_state = state.get(&agent_id).expect("agent state present");
    assert_eq!(agent_state.clients.len(), MAX_SOCKETS_PER_AGENT);

    Ok(())
}

/// After registering and removing many clients, the state map must be empty — verifying that
/// connection teardown actually reclaims entries and does not leak state.
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

    // Register many clients.
    for i in 0..count {
        let socket_id = i as u32;
        let (_peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, socket_id).await?;
    }

    {
        let state = manager.state.read().await;
        assert_eq!(state.get(&agent_id).map_or(0, |s| s.clients.len()), count);
    }

    // Remove them all.
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

/// `remove_agent` under load — clearing an agent with many clients must remove all state
/// and not leave orphaned entries.
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

/// `next_socket_id` starts near `u32::MAX` and wraps to 0 — the allocation must not panic.
#[tokio::test]
async fn socket_id_allocation_wraps_around_u32_max() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    // Set the counter just below u32::MAX.
    manager.next_socket_id.store(u32::MAX - 2, std::sync::atomic::Ordering::SeqCst);

    // Allocate 5 IDs — should cross the wraparound boundary.
    let id1 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id2 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id3 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id4 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id5 = manager.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    assert_eq!(id1, u32::MAX - 2);
    assert_eq!(id2, u32::MAX - 1);
    assert_eq!(id3, u32::MAX);
    assert_eq!(id4, 0, "AtomicU32 must wrap around to 0 after u32::MAX");
    assert_eq!(id5, 1);

    Ok(())
}

/// After wraparound, clients registered with wrapped IDs must be individually addressable
/// and not collide with pre-existing entries.
#[tokio::test]
async fn wrapped_socket_ids_do_not_collide() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    // Register a client at socket_id = 0 (what we'd get after wraparound).
    let (_peer_read_0, _peer_write_0) = register_pending_client(&manager, agent_id, 0).await?;
    // Register another at u32::MAX.
    let (_peer_read_max, _peer_write_max) =
        register_pending_client(&manager, agent_id, u32::MAX).await?;

    // Both must be independently present.
    {
        let state = manager.state.read().await;
        let agent_state = state.get(&agent_id).expect("agent state present");
        assert!(agent_state.clients.contains_key(&0));
        assert!(agent_state.clients.contains_key(&u32::MAX));
        assert_eq!(agent_state.clients.len(), 2);
    }

    // Closing one must not affect the other.
    manager.close_client(agent_id, 0).await.map_err(|e| io::Error::other(e.to_string()))?;
    {
        let state = manager.state.read().await;
        let agent_state = state.get(&agent_id).expect("agent state present");
        assert!(!agent_state.clients.contains_key(&0));
        assert!(agent_state.clients.contains_key(&u32::MAX));
    }

    Ok(())
}
