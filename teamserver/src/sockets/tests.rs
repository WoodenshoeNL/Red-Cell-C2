use std::io;
use std::sync::Arc;

use red_cell_common::AgentEncryptionInfo;
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use super::types::{PendingClient, SOCKS_ATYP_IPV4};
use super::{SocketRelayError, SocketRelayManager};
use crate::{AgentRegistry, Database, EventBus};

mod lifecycle;
mod limits;
mod relay;
mod stale;

pub(crate) async fn test_manager()
-> Result<(Database, AgentRegistry, SocketRelayManager), SocketRelayError> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let manager = SocketRelayManager::new(registry.clone(), EventBus::default());
    Ok((database, registry, manager))
}

pub(crate) fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0u8; 32]),
            aes_iv: Zeroizing::new(vec![0u8; 16]),
            monotonic_ctr: false,
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "LAB".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 0,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-10T10:00:00Z".to_owned(),
        last_call_in: "2026-03-10T10:00:00Z".to_owned(),
        archon_magic: None,
    }
}

/// Build a registered `PendingClient` for `agent_id`/`socket_id` and return the read half of
/// the peer socket so the caller can verify what the manager writes to the client.
///
/// The caller receives `(peer_read, peer_write)`:
/// - `peer_read` reads everything that the manager writes via `PendingClient.writer`
/// - `peer_write` keeps the connection alive so the spawned `spawn_client_reader` task does
///   not see EOF prematurely
pub(crate) async fn register_pending_client(
    manager: &SocketRelayManager,
    agent_id: u32,
    socket_id: u32,
) -> io::Result<(tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
    let (server_stream, _) = listener.accept().await?;
    let client_stream = connect_task.await.map_err(|e| io::Error::other(e.to_string()))??;
    // client_stream (stream A): write_A sends to read_B, read_A receives from write_B
    // server_stream (stream B): read_B receives what write_A sent, write_B sends to read_A
    let (client_read, client_write) = client_stream.into_split();
    let (server_read, server_write) = server_stream.into_split();

    {
        let mut state = manager.state.write().await;
        let agent_state = state.entry(agent_id).or_default();
        agent_state.clients.insert(
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
        );
    }

    // server_read: verifies what the manager writes to PendingClient.writer (write_A → read_B)
    // server_write: held by the caller to prevent EOF on client_read inside the reader task
    Ok((server_read, server_write))
}
