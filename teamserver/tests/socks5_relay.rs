//! SOCKS5 relay integration tests.
//!
//! These tests exercise the [`SocketRelayManager`] end-to-end using real in-process
//! TCP connections.  They cover: SOCKS5 CONNECT negotiation (IPv4, domain, IPv6),
//! the data-relay path after the agent completes the connect, relay teardown on agent
//! disconnect, the server lifecycle (add / remove / clear), and `handle_socket_callback`
//! dispatch routing via the full HTTP → listener → dispatch pipeline.

mod common;

use std::time::Duration;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::AgentEncryptionInfo;
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
use red_cell_common::demon::{DemonCommand, DemonSocketCommand, DemonSocketType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

// SOCKS5 constants (mirrored from the implementation for test clarity).
const SOCKS_VERSION: u8 = 5;
const SOCKS_METHOD_NO_AUTH: u8 = 0;
const SOCKS_COMMAND_CONNECT: u8 = 1;
const SOCKS_REPLY_SUCCEEDED: u8 = 0;
const SOCKS_ATYP_IPV4: u8 = 1;
const SOCKS_ATYP_DOMAIN: u8 = 3;
const SOCKS_ATYP_IPV6: u8 = 4;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn test_manager()
-> Result<(Database, AgentRegistry, SocketRelayManager), Box<dyn std::error::Error>> {
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
    }
}

/// Send a SOCKS5 no-auth negotiation greeting and read the server's response.
async fn socks5_handshake(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    // Client greeting: VER=5, NMETHODS=1, METHOD=0 (no-auth).
    stream.write_all(&[SOCKS_VERSION, 1, SOCKS_METHOD_NO_AUTH]).await?;
    stream.flush().await?;

    // Server response: VER=5, METHOD=0.
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    assert_eq!(response[0], SOCKS_VERSION, "server must respond with SOCKS5");
    assert_eq!(response[1], SOCKS_METHOD_NO_AUTH, "server must select no-auth method");
    Ok(())
}

/// Send a SOCKS5 CONNECT request for an IPv4 target.
async fn socks5_connect_ipv4(
    stream: &mut TcpStream,
    addr: [u8; 4],
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = vec![SOCKS_VERSION, SOCKS_COMMAND_CONNECT, 0, SOCKS_ATYP_IPV4];
    request.extend_from_slice(&addr);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(())
}

/// Send a SOCKS5 CONNECT request for a domain name target.
async fn socks5_connect_domain(
    stream: &mut TcpStream,
    domain: &[u8],
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let len = u8::try_from(domain.len())?;
    let mut request = vec![SOCKS_VERSION, SOCKS_COMMAND_CONNECT, 0, SOCKS_ATYP_DOMAIN, len];
    request.extend_from_slice(domain);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(())
}

/// Send a SOCKS5 CONNECT request for an IPv6 target.
async fn socks5_connect_ipv6(
    stream: &mut TcpStream,
    addr: [u8; 16],
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = vec![SOCKS_VERSION, SOCKS_COMMAND_CONNECT, 0, SOCKS_ATYP_IPV6];
    request.extend_from_slice(&addr);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(())
}

/// Read and return a SOCKS5 connect-reply atyp byte and a 6-byte BND.ADDR+BND.PORT.
///
/// Returns `(reply_code, atyp, address_bytes, port)`.
async fn read_socks5_reply(
    stream: &mut TcpStream,
    atyp: u8,
) -> Result<(u8, Vec<u8>, u16), Box<dyn std::error::Error>> {
    let mut header = [0u8; 4]; // VER, REP, RSV, ATYP
    stream.read_exact(&mut header).await?;
    let reply = header[1];
    let reply_atyp = header[3];
    assert_eq!(reply_atyp, atyp, "reply atyp must match request");

    let addr_len = match atyp {
        SOCKS_ATYP_IPV4 => 4,
        SOCKS_ATYP_IPV6 => 16,
        SOCKS_ATYP_DOMAIN => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            usize::from(len_byte[0])
        }
        _ => return Err("unexpected atyp in reply".into()),
    };
    let mut addr = vec![0u8; addr_len];
    stream.read_exact(&mut addr).await?;
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    Ok((reply, addr, u16::from_be_bytes(port_bytes)))
}

/// Extract the `socket_id` from the first queued SOCKS job payload.
///
/// The SOCKS connect job payload layout:
///   [0..4]  command (LE)
///   [4..8]  socket_id (LE)
///   ...
async fn dequeue_socket_id(
    registry: &AgentRegistry,
    agent_id: u32,
) -> Result<u32, Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let jobs = registry.queued_jobs(agent_id).await?;
        if !jobs.is_empty() {
            let payload = &jobs[0].payload;
            if payload.len() >= 8 {
                let socket_id = u32::from_le_bytes(payload[4..8].try_into()?);
                return Ok(socket_id);
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
    Err("timed out waiting for socket job to appear in agent queue".into())
}

// ---------------------------------------------------------------------------
// Server lifecycle tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_socks_server_starts_listener_on_requested_port()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0001_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    let result = manager.add_socks_server(agent_id, &port.to_string()).await?;

    assert!(result.contains(&port.to_string()), "result should mention the bound port");

    // The local port should now be accepting connections.
    let connected =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    drop(connected);

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

#[tokio::test]
async fn remove_socks_server_stops_listener() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0002_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;
    manager.remove_socks_server(agent_id, &port.to_string()).await?;

    // Wait briefly for the task to terminate, then the port should be free.
    sleep(Duration::from_millis(50)).await;
    let result =
        timeout(Duration::from_millis(200), TcpStream::connect(format!("127.0.0.1:{port}"))).await;
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "port should no longer accept connections after remove"
    );
    Ok(())
}

#[tokio::test]
async fn duplicate_port_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0003_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let result = manager.add_socks_server(agent_id, &port.to_string()).await;
    assert!(result.is_err(), "adding a duplicate SOCKS server on the same port must fail");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

#[tokio::test]
async fn clear_socks_servers_removes_all_for_agent() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0004_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port_a, guard_a) = common::available_port()?;
    let (port_b, guard_b) = common::available_port_excluding(port_a)?;
    drop(guard_a);
    manager.add_socks_server(agent_id, &port_a.to_string()).await?;
    drop(guard_b);
    manager.add_socks_server(agent_id, &port_b.to_string()).await?;

    let result = manager.clear_socks_servers(agent_id).await?;
    assert!(
        result.contains('2') || result.contains("2"),
        "clear should report 2 servers removed; got: {result}"
    );

    // List should now be empty.
    let list = manager.list_socks_servers(agent_id).await;
    assert!(list.contains("No active"), "list after clear should say no servers; got: {list}");
    Ok(())
}

#[tokio::test]
async fn remove_agent_tears_down_relay_state() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0005_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let removed = manager.remove_agent(agent_id).await;
    assert!(removed, "remove_agent should return true when agent state existed");

    // Calling again should return false — state was already removed.
    let removed_again = manager.remove_agent(agent_id).await;
    assert!(!removed_again, "remove_agent should return false when agent state is absent");
    Ok(())
}

#[tokio::test]
async fn invalid_port_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0006_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let result = manager.add_socks_server(agent_id, "not-a-port").await;
    assert!(result.is_err(), "invalid port string must return an error");
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS5 CONNECT handshake tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks5_connect_ipv4_handshake_enqueues_connect_job()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0010_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;
    socks5_connect_ipv4(&mut client, [93, 184, 216, 34], 80).await?;

    // A connect job should appear in the agent queue.
    let socket_id = dequeue_socket_id(&registry, agent_id).await?;
    assert_ne!(socket_id, 0, "socket_id must be non-zero");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

#[tokio::test]
async fn socks5_connect_domain_handshake_enqueues_connect_job()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0011_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;
    socks5_connect_domain(&mut client, b"example.com", 80).await?;

    let socket_id = dequeue_socket_id(&registry, agent_id).await?;
    assert_ne!(socket_id, 0, "socket_id must be non-zero");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

#[tokio::test]
async fn socks5_connect_ipv6_handshake_enqueues_connect_job()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0012_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;
    // ::1 (loopback)
    socks5_connect_ipv6(&mut client, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 80).await?;

    let socket_id = dequeue_socket_id(&registry, agent_id).await?;
    assert_ne!(socket_id, 0, "socket_id must be non-zero");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Data relay tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finish_connect_success_allows_data_relay_to_client()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0020_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;
    socks5_connect_ipv4(&mut client, [93, 184, 216, 34], 80).await?;

    // Wait for the relay to register the client and enqueue the connect job.
    let socket_id = dequeue_socket_id(&registry, agent_id).await?;

    // Simulate the agent completing the connection successfully.
    manager.finish_connect(agent_id, socket_id, true, 0).await?;

    // The client should receive a SOCKS5 success reply.
    let (reply, _addr, _port) =
        timeout(Duration::from_secs(2), read_socks5_reply(&mut client, SOCKS_ATYP_IPV4)).await??;
    assert_eq!(reply, SOCKS_REPLY_SUCCEEDED, "client must receive a success reply");

    // Write data via the relay — the client should receive it.
    let relay_data = b"hello from agent";
    manager.write_client_data(agent_id, socket_id, relay_data).await?;

    let mut received = vec![0u8; relay_data.len()];
    timeout(Duration::from_secs(2), client.read_exact(&mut received)).await??;
    assert_eq!(received, relay_data, "relay data must arrive at the SOCKS5 client verbatim");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

#[tokio::test]
async fn finish_connect_failure_closes_client_socket() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0021_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;
    socks5_connect_ipv4(&mut client, [93, 184, 216, 34], 80).await?;

    let socket_id = dequeue_socket_id(&registry, agent_id).await?;

    // Simulate the agent failing the connection (general failure code 1).
    manager.finish_connect(agent_id, socket_id, false, 1).await?;

    // The client should receive a failure reply.
    let (reply, _addr, _port) =
        timeout(Duration::from_secs(2), read_socks5_reply(&mut client, SOCKS_ATYP_IPV4)).await??;
    assert_ne!(reply, SOCKS_REPLY_SUCCEEDED, "client must receive a failure reply");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

#[tokio::test]
async fn write_client_data_after_remove_agent_returns_error()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0022_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;
    socks5_connect_ipv4(&mut client, [93, 184, 216, 34], 80).await?;

    let socket_id = dequeue_socket_id(&registry, agent_id).await?;
    manager.finish_connect(agent_id, socket_id, true, 0).await?;
    // Drain the success reply so the client socket is in a clean state.
    let _ = timeout(Duration::from_secs(1), read_socks5_reply(&mut client, SOCKS_ATYP_IPV4)).await;

    // Simulate the agent disconnecting — all relay state is removed.
    manager.remove_agent(agent_id).await;

    // write_client_data must now return an error since the relay state is gone.
    let result = manager.write_client_data(agent_id, socket_id, b"orphaned data").await;
    assert!(result.is_err(), "write_client_data must fail after remove_agent");
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_socket_callback dispatch routing tests
//
// These tests verify that the HTTP → listener → dispatch pipeline correctly
// routes CommandSocket callbacks to the SocketRelayManager.  A full teamserver
// (HTTP listener + WebSocket + relay) is used so the path mirrors production.
// ---------------------------------------------------------------------------

const DISPATCH_PROFILE: &str = r#"
    Teamserver {
      Host = "127.0.0.1"
      Port = 0
    }

    Operators {
      user "operator" {
        Password = "password1234"
        Role = "Operator"
      }
    }

    Demon {}
"#;

/// Boot a full teamserver and return its WS address, the listener manager,
/// the agent registry, and a clone of the socket relay manager.
async fn start_dispatch_server() -> Result<
    (std::net::SocketAddr, ListenerManager, AgentRegistry, SocketRelayManager),
    Box<dyn std::error::Error>,
> {
    let profile = Profile::parse(DISPATCH_PROFILE)?;
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    );
    let state = TeamserverState {
        profile: profile.clone(),
        database,
        auth: AuthService::from_profile(&profile).expect("auth service should init"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry: registry.clone(),
        listeners: listeners.clone(),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets: sockets.clone(),
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: red_cell::ShutdownController::new(),
    };

    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    tokio::spawn(async move {
        let app = websocket_routes().with_state(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });

    Ok((addr, listeners, registry, sockets))
}

/// Build an HTTP listener config bound to `port` with the given `name`.
fn dispatch_http_listener(name: &str, port: u16) -> red_cell_common::ListenerConfig {
    red_cell_common::ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
    })
}

/// Register an agent via `DEMON_INIT` and return the AES-CTR block offset after init.
async fn dispatch_register_agent(
    client: &reqwest::Client,
    listener_port: u16,
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Result<u64, Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let bytes = resp.bytes().await?;
    Ok(ctr_blocks_for_len(bytes.len()))
}

/// A `CommandSocket/Connect` callback with `success=1` must call
/// `relay.finish_connect`, which causes the pending SOCKS5 client to receive
/// a success reply.
#[tokio::test]
async fn socket_connect_callback_routes_to_relay_finish_connect()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners, registry, relay) = start_dispatch_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    listeners.create(dispatch_http_listener("sock-dispatch-connect", listener_port)).await?;
    drop(listener_guard);
    listeners.start("sock-dispatch-connect").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xBB01_0001_u32;
    let key = [0x11; AGENT_KEY_LENGTH];
    let iv = [0x22; AGENT_IV_LENGTH];
    let ctr_offset = dispatch_register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Start a SOCKS server on the relay so a client can connect.
    let (socks_port, socks_guard) = common::available_port()?;
    drop(socks_guard);
    relay.add_socks_server(agent_id, &socks_port.to_string()).await?;

    // Connect a SOCKS5 client and issue an IPv4 CONNECT request.
    let mut socks_client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{socks_port}")))
            .await??;
    socks5_handshake(&mut socks_client).await?;
    socks5_connect_ipv4(&mut socks_client, [93, 184, 216, 34], 80).await?;

    // Retrieve the socket_id that the relay assigned for this connection.
    let socket_id = dequeue_socket_id(&registry, agent_id).await?;

    // Build and send the CommandSocket/Connect callback (success=1, error_code=0).
    let mut connect_payload = Vec::new();
    connect_payload.extend_from_slice(&u32::from(DemonSocketCommand::Connect).to_le_bytes());
    connect_payload.extend_from_slice(&1_u32.to_le_bytes()); // success
    connect_payload.extend_from_slice(&socket_id.to_le_bytes());
    connect_payload.extend_from_slice(&0_u32.to_le_bytes()); // error_code

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSocket),
            0x01,
            &connect_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // The relay should have called finish_connect, which sends the SOCKS5 success
    // reply to the waiting client.
    let (reply, _addr, _port) =
        timeout(Duration::from_secs(2), read_socks5_reply(&mut socks_client, SOCKS_ATYP_IPV4))
            .await??;
    assert_eq!(
        reply, SOCKS_REPLY_SUCCEEDED,
        "SOCKS client must receive a success reply after the Connect callback"
    );

    relay.clear_socks_servers(agent_id).await?;
    listeners.stop("sock-dispatch-connect").await?;
    Ok(())
}

/// A `CommandSocket/Close` callback for a `ReverseProxy` socket must call
/// `relay.close_client`, which closes the SOCKS5 client connection (EOF).
#[tokio::test]
async fn socket_close_callback_routes_to_relay_close_client()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners, registry, relay) = start_dispatch_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    listeners.create(dispatch_http_listener("sock-dispatch-close", listener_port)).await?;
    drop(listener_guard);
    listeners.start("sock-dispatch-close").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xBB01_0002_u32;
    let key = [0x33; AGENT_KEY_LENGTH];
    let iv = [0x44; AGENT_IV_LENGTH];
    let ctr_offset = dispatch_register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Start a SOCKS server and connect a client.
    let (socks_port, socks_guard) = common::available_port()?;
    drop(socks_guard);
    relay.add_socks_server(agent_id, &socks_port.to_string()).await?;

    let mut socks_client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{socks_port}")))
            .await??;
    socks5_handshake(&mut socks_client).await?;
    socks5_connect_ipv4(&mut socks_client, [93, 184, 216, 34], 80).await?;

    // Get the socket_id and complete the relay setup directly so the client is
    // in the relay's connected-socket table.
    let socket_id = dequeue_socket_id(&registry, agent_id).await?;
    relay.finish_connect(agent_id, socket_id, true, 0).await?;
    // Drain the SOCKS5 success reply so the client is in a clean read state.
    let _ = timeout(Duration::from_secs(1), read_socks5_reply(&mut socks_client, SOCKS_ATYP_IPV4))
        .await;

    // Build and send the CommandSocket/Close callback for a ReverseProxy socket.
    let mut close_payload = Vec::new();
    close_payload.extend_from_slice(&u32::from(DemonSocketCommand::Close).to_le_bytes());
    close_payload.extend_from_slice(&socket_id.to_le_bytes());
    close_payload.extend_from_slice(&u32::from(DemonSocketType::ReverseProxy).to_le_bytes());

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSocket),
            0x02,
            &close_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // The relay should have called close_client — reading from the SOCKS client
    // must now return EOF (0 bytes).
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(2), socks_client.read(&mut buf)).await??;
    assert_eq!(n, 0, "SOCKS client must be closed (EOF) after the Close callback");

    relay.clear_socks_servers(agent_id).await?;
    listeners.stop("sock-dispatch-close").await?;
    Ok(())
}
