use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::TcpStream;
use tokio::sync::oneshot;

use super::super::{SocketRelayError, SocksServerHandle};
use super::{register_pending_client, sample_agent, test_manager};

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

/// `remove_socks_server` returns a close message and removes both the server entry and any
/// clients that were on that port from the manager state.
///
/// `add_socks_server("0")` stores the server under key `0` (the *requested* port), so
/// `remove_socks_server` must also use `"0"`.  The `local_addr` field in the handle carries
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

    // Start a real listener on port "0" (OS-assigned ephemeral port).
    // The server is stored under key 0 in the servers BTreeMap.
    let start_msg = manager
        .add_socks_server(agent_id, "0")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
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
async fn socks5_server_binds_to_localhost_only() -> std::io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| std::io::Error::other(e.to_string()))?;
    registry
        .insert(sample_agent(0xDEAD_BEEF))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Start the server on an OS-assigned ephemeral port.
    let start_msg = manager
        .add_socks_server(0xDEAD_BEEF, "0")
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

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
        .map_err(|e| {
            std::io::Error::other(format!("could not parse port from '{start_msg}': {e}"))
        })?;

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
        std::io::Error::other(format!("loopback connection to 127.0.0.1:{bound_port} failed: {e}"))
    })?;

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
