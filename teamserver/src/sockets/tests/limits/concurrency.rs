use std::io;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use crate::sockets::types::{MAX_SOCKETS_PER_AGENT, PendingClient, SOCKS_ATYP_IPV4};

use super::super::{sample_agent, test_manager};

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

    let mut handles = Vec::with_capacity(count);
    for i in 0..count {
        let manager = manager.clone();
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
            let result = manager
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

#[tokio::test]
async fn concurrent_registrations_respect_per_agent_limit() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;
    let attempt_count = MAX_SOCKETS_PER_AGENT + 50;

    let mut handles = Vec::with_capacity(attempt_count);
    for i in 0..attempt_count {
        let manager = manager.clone();
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
            let result = manager
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
