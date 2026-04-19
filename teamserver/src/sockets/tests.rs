use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use red_cell_common::AgentEncryptionInfo;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::types::{
    MAX_GLOBAL_SOCKETS, MAX_SOCKETS_PER_AGENT, PendingClient, SOCKS_ATYP_IPV4,
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCEEDED, SOCKS_VERSION,
};
use super::{SocketRelayError, SocketRelayManager, SocksServerHandle};
use crate::{AgentRegistry, Database, EventBus};

async fn test_manager() -> Result<(Database, AgentRegistry, SocketRelayManager), SocketRelayError> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let manager = SocketRelayManager::new(registry.clone(), EventBus::default());
    Ok((database, registry, manager))
}

fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0u8; 32]),
            aes_iv: Zeroizing::new(vec![0u8; 16]),
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
async fn remove_agent_clears_tracked_socket_state() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;

    manager.add_socks_server(0xDEAD_BEEF, "0").await?;
    assert!(manager.state.read().await.contains_key(&0xDEAD_BEEF));

    assert!(manager.remove_agent(0xDEAD_BEEF).await);
    assert!(!manager.state.read().await.contains_key(&0xDEAD_BEEF));
    assert_eq!(manager.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

    Ok(())
}

#[tokio::test]
async fn prune_stale_agents_removes_inactive_agent_state() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;
    registry.insert(sample_agent(0xFEED_FACE)).await?;

    manager.add_socks_server(0xDEAD_BEEF, "0").await?;
    manager.add_socks_server(0xFEED_FACE, "0").await?;
    registry.mark_dead(0xDEAD_BEEF, "lost contact").await?;

    assert_eq!(manager.prune_stale_agents().await, 1);
    let state = manager.state.read().await;
    assert!(!state.contains_key(&0xDEAD_BEEF));
    assert!(state.contains_key(&0xFEED_FACE));

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
async fn socks_server_handle_shutdown_signals_graceful_exit() {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let graceful_exit = Arc::new(AtomicBool::new(false));
    let graceful_exit_task = Arc::clone(&graceful_exit);
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_rx => graceful_exit_task.store(true, Ordering::SeqCst),
            _ = std::future::pending::<()>() => {}
        }
    });
    let mut handle = SocksServerHandle {
        local_addr: "127.0.0.1:0".to_owned(),
        shutdown: Some(shutdown_tx),
        task,
    };

    handle.shutdown();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !handle.task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown task should finish");
    assert!(graceful_exit.load(Ordering::SeqCst));
    assert!(handle.shutdown.is_none());
}

#[tokio::test]
async fn socks_server_handle_port_returns_error_for_invalid_local_addr() {
    let task = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    let handle =
        SocksServerHandle { local_addr: "invalid-address".to_owned(), shutdown: None, task };

    assert!(matches!(
        handle.port(),
        Err(SocketRelayError::InvalidLocalAddress { local_addr }) if local_addr == "invalid-address"
    ));
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

/// Build a registered `PendingClient` for `agent_id`/`socket_id` and return the read half of
/// the peer socket so the caller can verify what the manager writes to the client.
///
/// The caller receives `(peer_read, peer_write)`:
/// - `peer_read` reads everything that the manager writes via `PendingClient.writer`
/// - `peer_write` keeps the connection alive so the spawned `spawn_client_reader` task does
///   not see EOF prematurely
async fn register_pending_client(
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

// --- Happy-path coverage for the three previously untested public lifecycle APIs ---

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

/// `remove_socks_server` returns a close message and removes both the server entry and any
/// clients that were on that port from the manager state.
///
/// `add_socks_server("0")` stores the server under key `0` (the *requested* port), so
/// `remove_socks_server` must also use `"0"`.  The `local_addr` field in the handle carries
/// the real ephemeral port assigned by the OS, which appears in the close message.
#[tokio::test]
async fn remove_socks_server_returns_close_message_and_removes_client_state() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    let agent_id: u32 = 0xDEAD_BEEF;

    // Start a real listener on port "0" (OS-assigned ephemeral port).
    // The server is stored under key 0 in the servers BTreeMap.
    let start_msg = manager
        .add_socks_server(agent_id, "0")
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    assert!(
        start_msg.starts_with("Started SOCKS5 server on 127.0.0.1:"),
        "unexpected start message: {start_msg}"
    );

    // Inject a fake client with server_port=0 so close_clients_for_port picks it up.
    let socket_id: u32 = 0xCAFE_0002;
    let (_, _peer_write) = register_pending_client(&manager, agent_id, socket_id).await?;
    {
        let mut state = manager.state.write().await;
        let agent_state = state.get_mut(&agent_id).expect("agent state present");
        let client = agent_state.clients.get_mut(&socket_id).expect("client present");
        client.server_port = 0; // match the key used by add_socks_server("0")
    }

    // Remove using the same port string that was used to add.
    let close_msg = manager
        .remove_socks_server(agent_id, "0")
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

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

/// The SOCKS5 server must bind exclusively to the loopback interface (`127.0.0.1`) and must
/// NOT advertise itself on any external or wildcard address (`0.0.0.0`).
///
/// # Security boundary — no authentication
///
/// The SOCKS5 relay uses `NO_AUTH` (method 0x00) by design: only operators who already have
/// an authenticated WebSocket session with the teamserver are expected to obtain a SOCKS5 port
/// (via the `COMMAND_SOCKET` task response), and the port is never exposed outside
/// `127.0.0.1`.  Localhost-only binding is therefore the **sole** access-control layer for
/// this tunnel.  This is a known, intentional security boundary: any local OS process that
/// learns the ephemeral port could connect without further authentication.  Accept this
/// trade-off consciously — do not relax the loopback-only constraint without adding an
/// authentication layer.
#[tokio::test]
async fn socks5_server_binds_to_localhost_only() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    // Start the server on an OS-assigned ephemeral port.
    let start_msg = manager
        .add_socks_server(0xDEAD_BEEF, "0")
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    // The reported bind address must be on the loopback interface, not a wildcard.
    assert!(
        start_msg.contains("127.0.0.1:"),
        "SOCKS5 server must report a 127.0.0.1 bind address, got: {start_msg}"
    );
    assert!(
        !start_msg.contains("0.0.0.0:"),
        "SOCKS5 server must not bind to the wildcard address, got: {start_msg}"
    );

    // Extract the port from the reported address so we can attempt an external connection.
    let bound_port: u16 = start_msg
        .trim_start_matches("Started SOCKS5 server on 127.0.0.1:")
        .trim()
        .parse()
        .map_err(|e| io::Error::other(format!("could not parse port from '{start_msg}': {e}")))?;

    // If this machine has a non-loopback IP, a connection to it on `bound_port` must be
    // refused — the listener is bound only to 127.0.0.1 so external interfaces are not
    // reachable.  We discover the outbound IP with a connected UDP socket (no packet is
    // actually sent; connecting UDP just populates the kernel routing table entry).
    // `192.0.2.1` is TEST-NET-1 (RFC 5737) — routable but unassigned, safe to use here.
    let non_loopback_ip: Option<std::net::IpAddr> = (|| {
        use std::net::UdpSocket;
        let udp = UdpSocket::bind("0.0.0.0:0").ok()?;
        udp.connect("192.0.2.1:80").ok()?;
        let ip = udp.local_addr().ok()?.ip();
        if ip.is_loopback() { None } else { Some(ip) }
    })();

    if let Some(ext_ip) = non_loopback_ip {
        let external_connect = TcpStream::connect(format!("{ext_ip}:{bound_port}")).await;
        assert!(
            external_connect.is_err(),
            "connection to {ext_ip}:{bound_port} must be refused — SOCKS5 must not be \
             reachable on non-loopback addresses"
        );
    }

    // A connection to 127.0.0.1 on the same port must succeed, confirming the server is
    // reachable only via loopback.
    TcpStream::connect(format!("127.0.0.1:{bound_port}")).await.map_err(|e| {
        io::Error::other(format!("loopback connection to 127.0.0.1:{bound_port} failed: {e}"))
    })?;

    Ok(())
}

// --- Connection limit tests ---

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
    let agents_needed = super::MAX_RELAY_LISTENERS.div_ceil(10); // ≤10 servers per agent
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
            let to_insert = std::cmp::min(10, super::MAX_RELAY_LISTENERS - total_inserted);
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
            if total_inserted >= super::MAX_RELAY_LISTENERS {
                break;
            }
        }
    }

    // Verify total listener count.
    {
        let state = manager.state.read().await;
        let total: usize = state.values().map(|s| s.servers.len()).sum();
        assert_eq!(total, super::MAX_RELAY_LISTENERS);
    }

    // The next server addition must fail.
    let new_agent_id = (agents_needed as u32) + 100;
    registry.insert(sample_agent(new_agent_id)).await?;
    let result = manager.add_socks_server(new_agent_id, "0").await;

    assert!(
        matches!(
            result,
            Err(SocketRelayError::ListenerLimit { limit })
                if limit == super::MAX_RELAY_LISTENERS
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

// --- Concurrent connection tests ---

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

// --- Memory pressure tests ---

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

// --- Socket ID wraparound tests ---

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

// --- Stale agent sweeper under load tests ---

/// `prune_stale_agents` with many agents: marks half as dead and verifies the sweeper
/// removes exactly those agents while retaining the rest.
#[tokio::test]
async fn prune_stale_agents_under_load_removes_only_dead_agents() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;

    let total_agents = 50_u32;
    for agent_id in 1..=total_agents {
        registry
            .insert(sample_agent(agent_id))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
    }

    // Give each agent a few clients so there is real state to sweep.
    for agent_id in 1..=total_agents {
        for i in 0..5_u32 {
            let socket_id = agent_id * 1000 + i;
            let (_peer_read, _peer_write) =
                register_pending_client(&manager, agent_id, socket_id).await?;
        }
    }

    // Mark odd-numbered agents as dead.
    let dead_count = (1..=total_agents).filter(|id| id % 2 == 1).count();
    for agent_id in 1..=total_agents {
        if agent_id % 2 == 1 {
            registry
                .mark_dead(agent_id, "test sweep")
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
    }

    let removed = manager.prune_stale_agents().await;
    assert_eq!(removed, dead_count, "sweeper must remove exactly the dead agents");

    let state = manager.state.read().await;
    for agent_id in 1..=total_agents {
        if agent_id % 2 == 1 {
            assert!(
                !state.contains_key(&agent_id),
                "dead agent {agent_id} must be removed from state"
            );
        } else {
            assert!(
                state.contains_key(&agent_id),
                "live agent {agent_id} must be retained in state"
            );
            assert_eq!(
                state.get(&agent_id).map_or(0, |s| s.clients.len()),
                5,
                "live agent {agent_id} must retain all its clients"
            );
        }
    }

    Ok(())
}

/// Successive sweeper runs are idempotent — a second prune after no state changes must
/// remove nothing.
#[tokio::test]
async fn prune_stale_agents_is_idempotent() -> io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| io::Error::other(e.to_string()))?;

    for agent_id in 1..=10_u32 {
        registry
            .insert(sample_agent(agent_id))
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let (_peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, agent_id * 100).await?;
    }

    // Kill agents 1–5.
    for agent_id in 1..=5_u32 {
        registry.mark_dead(agent_id, "gone").await.map_err(|e| io::Error::other(e.to_string()))?;
    }

    let first_sweep = manager.prune_stale_agents().await;
    assert_eq!(first_sweep, 5);

    let second_sweep = manager.prune_stale_agents().await;
    assert_eq!(second_sweep, 0, "second sweep with no new state changes must remove nothing");

    // Remaining agents still intact.
    let state = manager.state.read().await;
    for agent_id in 6..=10_u32 {
        assert!(state.contains_key(&agent_id));
    }

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

#[tokio::test]
async fn agent_socket_snapshot_empty_for_unknown_agent() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");

    let snap = manager.agent_socket_snapshot(0xDEAD_BEEF).await;
    assert!(snap.port_fwds.is_empty(), "unknown agent must have no port fwds");
    assert!(snap.socks_svr.is_empty(), "unknown agent must have no SOCKS servers");
    assert!(snap.socks_cli.is_empty(), "unknown agent must have no SOCKS clients");
}

#[tokio::test]
async fn agent_socket_snapshot_includes_port_fwd() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0x1234_5678_u32;

    manager.add_port_fwd(agent_id, 1, "127.0.0.1:8080 -> 10.0.0.1:80".to_owned()).await;
    manager.add_port_fwd(agent_id, 2, "127.0.0.1:9090 -> 10.0.0.2:443".to_owned()).await;

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert_eq!(snap.port_fwds.len(), 2, "snapshot must include 2 port forwards");
    assert!(
        snap.port_fwds.contains(&"127.0.0.1:8080 -> 10.0.0.1:80".to_owned()),
        "snapshot must contain first port fwd"
    );
}

#[tokio::test]
async fn remove_port_fwd_removes_entry_from_snapshot() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0x1234_5678_u32;

    manager.add_port_fwd(agent_id, 1, "127.0.0.1:8080 -> 10.0.0.1:80".to_owned()).await;
    manager.add_port_fwd(agent_id, 2, "127.0.0.1:9090 -> 10.0.0.2:443".to_owned()).await;
    manager.remove_port_fwd(agent_id, 1).await;

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert_eq!(snap.port_fwds.len(), 1, "one port fwd must remain after removal");
    assert!(
        !snap.port_fwds.contains(&"127.0.0.1:8080 -> 10.0.0.1:80".to_owned()),
        "removed port fwd must not appear in snapshot"
    );
    assert!(
        snap.port_fwds.contains(&"127.0.0.1:9090 -> 10.0.0.2:443".to_owned()),
        "remaining port fwd must appear in snapshot"
    );
}

#[tokio::test]
async fn clear_port_fwds_empties_snapshot() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0x1234_5678_u32;

    manager.add_port_fwd(agent_id, 1, "127.0.0.1:8080 -> 10.0.0.1:80".to_owned()).await;
    manager.add_port_fwd(agent_id, 2, "127.0.0.1:9090 -> 10.0.0.2:443".to_owned()).await;
    manager.clear_port_fwds(agent_id).await;

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert!(snap.port_fwds.is_empty(), "all port fwds must be gone after clear");
}

#[tokio::test]
async fn agent_socket_snapshot_socks_svr_reflects_active_listeners() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0xABCD_1234_u32;

    let _result = manager.add_socks_server(agent_id, "0").await.expect("started socks server");

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert_eq!(snap.socks_svr.len(), 1, "snapshot must include 1 SOCKS server");
    assert!(
        snap.socks_svr[0].starts_with("127.0.0.1:"),
        "socks_svr entry must be a 127.0.0.1 bind address"
    );
    assert!(snap.socks_cli.is_empty(), "no clients connected yet");
}
