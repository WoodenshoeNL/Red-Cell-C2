//! SOCKS5 relay integration tests.
//!
//! These tests exercise the [`SocketRelayManager`] end-to-end using real in-process
//! TCP connections.  They cover: SOCKS5 CONNECT negotiation (IPv4, domain, IPv6),
//! the data-relay path after the agent completes the connect, relay teardown on agent
//! disconnect, the server lifecycle (add / remove / clear), and `handle_socket_callback`
//! dispatch routing via the full HTTP → listener → dispatch pipeline.

mod common;

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, SocketRelayManager};
use red_cell_common::AgentEncryptionInfo;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
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
        archon_magic: None,
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

    // Poll until the listener task terminates (port stops accepting) or 2-second deadline.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let port_closed = loop {
        let conn =
            timeout(Duration::from_millis(50), TcpStream::connect(format!("127.0.0.1:{port}")))
                .await;
        match conn {
            // timeout or connection refused — port is closed
            Err(_) | Ok(Err(_)) => break true,
            // connected — listener still up, keep waiting
            Ok(Ok(_)) => {
                if tokio::time::Instant::now() >= deadline {
                    break false;
                }
                sleep(Duration::from_millis(10)).await;
            }
        }
    };
    assert!(port_closed, "port should no longer accept connections after remove");
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
// SOCKS5 unsupported auth method rejection
// ---------------------------------------------------------------------------

/// When a SOCKS5 client offers only unsupported authentication methods (e.g.,
/// username/password `0x02` with no no-auth `0x00`), the server must respond
/// with `VER=5, METHOD=0xFF` (no acceptable method) and close the connection.
#[tokio::test]
async fn socks5_rejects_unsupported_auth_method() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_000F_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;

    // Send greeting with only username/password auth (METHOD=0x02), no no-auth.
    client.write_all(&[SOCKS_VERSION, 1, 0x02]).await?;
    client.flush().await?;

    // Server must respond with VER=5, METHOD=0xFF (no acceptable method).
    let mut response = [0u8; 2];
    timeout(Duration::from_secs(2), client.read_exact(&mut response)).await??;
    assert_eq!(response[0], SOCKS_VERSION, "server must respond with SOCKS5 version");
    assert_eq!(response[1], 0xFF, "server must reject with METHOD=0xFF (no acceptable method)");

    // The server should close the connection — subsequent reads must return EOF.
    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf)).await??;
    assert_eq!(n, 0, "server must close the connection after rejecting auth methods");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS5 unsupported command rejection (BIND, UDP ASSOCIATE)
// ---------------------------------------------------------------------------

/// Helper: send a SOCKS5 request with an arbitrary command byte (IPv4 target).
async fn socks5_send_command(
    stream: &mut TcpStream,
    command: u8,
    addr: [u8; 4],
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = vec![SOCKS_VERSION, command, 0, SOCKS_ATYP_IPV4];
    request.extend_from_slice(&addr);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(())
}

/// SOCKS5 BIND command (0x02) must be rejected with REP=0x07
/// (command not supported). No job should be enqueued for the agent.
#[tokio::test]
async fn socks5_rejects_bind_command() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_00A0_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;

    // Send BIND command (0x02) instead of CONNECT.
    socks5_send_command(&mut client, 0x02, [93, 184, 216, 34], 80).await?;

    // Read the SOCKS5 reply — expect REP=0x07 (command not supported).
    // The server sends an IPv4 reply with zeroed bind address (10 bytes total)
    // and then drops the connection. Use a bulk read to capture whatever the
    // server sends before the RST/FIN arrives.
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf)).await??;
    assert!(n >= 10, "server must send at least 10-byte SOCKS5 reply; got {n} bytes");
    assert_eq!(buf[0], SOCKS_VERSION, "reply must be SOCKS5");
    assert_eq!(buf[1], 0x07, "REP must be 0x07 (command not supported) for BIND");

    // Verify no job was enqueued for the agent.
    let jobs = registry.queued_jobs(agent_id).await?;
    assert!(jobs.is_empty(), "no job should be enqueued for a rejected BIND command");

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

/// SOCKS5 UDP ASSOCIATE command (0x03) must be rejected with REP=0x07
/// (command not supported). No job should be enqueued for the agent.
#[tokio::test]
async fn socks5_rejects_udp_associate_command() -> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_00A1_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;

    // Send UDP ASSOCIATE command (0x03) instead of CONNECT.
    socks5_send_command(&mut client, 0x03, [0, 0, 0, 0], 0).await?;

    // Read the SOCKS5 reply — expect REP=0x07 (command not supported).
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf)).await??;
    assert!(n >= 10, "server must send at least 10-byte SOCKS5 reply; got {n} bytes");
    assert_eq!(buf[0], SOCKS_VERSION, "reply must be SOCKS5");
    assert_eq!(buf[1], 0x07, "REP must be 0x07 (command not supported) for UDP ASSOCIATE");

    // Verify no job was enqueued for the agent.
    let jobs = registry.queued_jobs(agent_id).await?;
    assert!(jobs.is_empty(), "no job should be enqueued for a rejected UDP ASSOCIATE command");

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

/// When a SOCKS5 client sends data (e.g. an HTTP request) after the CONNECT
/// request but *before* the agent calls `finish_connect`, the relay must not
/// panic or corrupt state.  The data sits in the kernel TCP buffer until the
/// reader task is spawned by `finish_connect(success=true)`, at which point it
/// should be forwarded to the agent as a normal `CommandSocket/Write` job.
#[tokio::test]
async fn client_data_before_finish_connect_is_buffered_and_relayed()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0025_u32;
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

    // Drain the connect job so we can cleanly detect subsequent write jobs.
    let _ = registry.dequeue_jobs(agent_id).await?;

    // --- KEY: send data BEFORE finish_connect is called. ---
    // In a real scenario this is an eager HTTP client writing its request
    // immediately after the SOCKS5 CONNECT, not waiting for the reply.
    let premature_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    client.write_all(premature_data).await?;
    client.flush().await?;

    // Give the data a moment to arrive at the relay's TCP buffer.
    sleep(Duration::from_millis(50)).await;

    // Now simulate the agent completing the connection successfully.
    // This spawns the reader task which should pick up the buffered data.
    manager.finish_connect(agent_id, socket_id, true, 0).await?;

    // The client should receive a SOCKS5 success reply.
    let (reply, _addr, _port) =
        timeout(Duration::from_secs(2), read_socks5_reply(&mut client, SOCKS_ATYP_IPV4)).await??;
    assert_eq!(reply, SOCKS_REPLY_SUCCEEDED, "client must receive a success reply");

    // The premature data should now be forwarded as a CommandSocket/Write job.
    let write_cmd = u32::from(DemonSocketCommand::Write).to_le_bytes();
    let mut write_job_payload = None;
    for _ in 0..50 {
        let jobs = registry.queued_jobs(agent_id).await?;
        if let Some(job) = jobs.iter().find(|j| {
            j.command == u32::from(DemonCommand::CommandSocket)
                && j.payload.len() >= 4
                && j.payload[..4] == write_cmd
        }) {
            write_job_payload = Some(job.payload.clone());
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }

    let payload = write_job_payload.expect("premature client data must be relayed as a Write job");

    // Verify the payload contains the exact bytes the client sent.
    // Layout: [subcmd:4][socket_id:4][data_len:4][data:N]
    assert!(payload.len() >= 12, "payload must contain at least header fields");
    let job_socket_id = u32::from_le_bytes(payload[4..8].try_into()?);
    assert_eq!(job_socket_id, socket_id, "write job must reference the correct socket_id");
    let data_len = u32::from_le_bytes(payload[8..12].try_into()?) as usize;
    assert_eq!(data_len, premature_data.len(), "data length must match sent bytes");
    assert_eq!(
        &payload[12..12 + data_len],
        premature_data.as_slice(),
        "write job must contain the exact premature bytes"
    );

    // Verify the relay is still fully functional — write_client_data should work.
    let relay_data = b"response after early send";
    manager.write_client_data(agent_id, socket_id, relay_data).await?;

    let mut received = vec![0u8; relay_data.len()];
    timeout(Duration::from_secs(2), client.read_exact(&mut received)).await??;
    assert_eq!(
        received,
        relay_data.as_slice(),
        "relay must still deliver agent data to the client after premature send"
    );

    manager.clear_socks_servers(agent_id).await?;
    Ok(())
}

#[tokio::test]
async fn client_write_enqueues_socket_write_job_for_agent() -> Result<(), Box<dyn std::error::Error>>
{
    let (_database, registry, manager) = test_manager().await?;
    let agent_id = 0xAABB_0030_u32;
    registry.insert(sample_agent(agent_id)).await?;

    let (port, guard) = common::available_port()?;
    drop(guard);
    manager.add_socks_server(agent_id, &port.to_string()).await?;

    let mut client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{port}"))).await??;
    socks5_handshake(&mut client).await?;
    socks5_connect_ipv4(&mut client, [93, 184, 216, 34], 80).await?;

    // Wait for the connect job and retrieve the socket_id.
    let socket_id = dequeue_socket_id(&registry, agent_id).await?;

    // Drain the connect job so we can cleanly detect the write job.
    let _ = registry.dequeue_jobs(agent_id).await?;

    // Complete the connection — this starts the client reader task.
    manager.finish_connect(agent_id, socket_id, true, 0).await?;

    // Drain the SOCKS5 success reply so the client is in relay mode.
    let (reply, _addr, _port) =
        timeout(Duration::from_secs(2), read_socks5_reply(&mut client, SOCKS_ATYP_IPV4)).await??;
    assert_eq!(reply, SOCKS_REPLY_SUCCEEDED);

    // Write data from the SOCKS5 client — this should be enqueued as a
    // CommandSocket/Write job for the agent.
    let upstream_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    client.write_all(upstream_data).await?;
    client.flush().await?;

    // Poll the agent's job queue for the write job.
    let write_cmd = u32::from(DemonSocketCommand::Write).to_le_bytes();
    let mut write_job_payload = None;
    for _ in 0..50 {
        let jobs = registry.queued_jobs(agent_id).await?;
        if let Some(job) = jobs.iter().find(|j| {
            j.command == u32::from(DemonCommand::CommandSocket)
                && j.payload.len() >= 4
                && j.payload[..4] == write_cmd
        }) {
            write_job_payload = Some(job.payload.clone());
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }

    let payload = write_job_payload.expect("CommandSocket/Write job must appear in agent queue");

    // Verify payload layout: [subcmd:4][socket_id:4][data_len:4][data:N]
    assert!(payload.len() >= 12, "payload must contain at least header fields");
    let job_socket_id = u32::from_le_bytes(payload[4..8].try_into()?);
    assert_eq!(job_socket_id, socket_id, "write job must reference the correct socket_id");
    let data_len = u32::from_le_bytes(payload[8..12].try_into()?) as usize;
    assert_eq!(data_len, upstream_data.len(), "data length field must match sent bytes");
    assert_eq!(
        &payload[12..12 + data_len],
        upstream_data.as_slice(),
        "write job must contain the exact bytes the SOCKS5 client sent"
    );

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

// The dispatch tests below use `common::spawn_test_server` and
// `common::register_agent` — no per-file server/profile boilerplate needed.

/// A `CommandSocket/Connect` callback with `success=1` must call
/// `relay.finish_connect`, which causes the pending SOCKS5 client to receive
/// a success reply.
#[tokio::test]
async fn socket_connect_callback_routes_to_relay_finish_connect()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    server
        .listeners
        .create(common::http_listener_config("sock-dispatch-connect", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("sock-dispatch-connect").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xBB01_0001_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Start a SOCKS server on the relay so a client can connect.
    let (socks_port, socks_guard) = common::available_port()?;
    drop(socks_guard);
    server.sockets.add_socks_server(agent_id, &socks_port.to_string()).await?;

    // Connect a SOCKS5 client and issue an IPv4 CONNECT request.
    let mut socks_client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{socks_port}")))
            .await??;
    socks5_handshake(&mut socks_client).await?;
    socks5_connect_ipv4(&mut socks_client, [93, 184, 216, 34], 80).await?;

    // Retrieve the socket_id that the relay assigned for this connection.
    let socket_id = dequeue_socket_id(&server.agent_registry, agent_id).await?;

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

    server.sockets.clear_socks_servers(agent_id).await?;
    server.listeners.stop("sock-dispatch-connect").await?;
    Ok(())
}

/// A `CommandSocket/Connect` callback with `success=0` must call
/// `relay.finish_connect` with `success=false`, causing the pending SOCKS5
/// client to receive a failure reply.
#[tokio::test]
async fn socket_connect_failure_callback_sends_socks_failure_reply()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    server
        .listeners
        .create(common::http_listener_config("sock-dispatch-connect-fail", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("sock-dispatch-connect-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xBB01_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF,
        0x02,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Start a SOCKS server and connect a client.
    let (socks_port, socks_guard) = common::available_port()?;
    drop(socks_guard);
    server.sockets.add_socks_server(agent_id, &socks_port.to_string()).await?;

    let mut socks_client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{socks_port}")))
            .await??;
    socks5_handshake(&mut socks_client).await?;
    socks5_connect_ipv4(&mut socks_client, [93, 184, 216, 34], 80).await?;

    let socket_id = dequeue_socket_id(&server.agent_registry, agent_id).await?;

    // Build and send the CommandSocket/Connect callback with success=0 (failure).
    let mut connect_payload = Vec::new();
    connect_payload.extend_from_slice(&u32::from(DemonSocketCommand::Connect).to_le_bytes());
    connect_payload.extend_from_slice(&0_u32.to_le_bytes()); // success=0 (failure)
    connect_payload.extend_from_slice(&socket_id.to_le_bytes());
    connect_payload.extend_from_slice(&1_u32.to_le_bytes()); // error_code=1

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSocket),
            0x03,
            &connect_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // The relay should have called finish_connect(success=false), which sends
    // a SOCKS5 failure reply to the waiting client.
    let (reply, _addr, _port) =
        timeout(Duration::from_secs(2), read_socks5_reply(&mut socks_client, SOCKS_ATYP_IPV4))
            .await??;
    assert_ne!(
        reply, SOCKS_REPLY_SUCCEEDED,
        "SOCKS client must receive a failure reply after a Connect callback with success=0"
    );

    server.sockets.clear_socks_servers(agent_id).await?;
    server.listeners.stop("sock-dispatch-connect-fail").await?;
    Ok(())
}

/// A `CommandSocket/Read` callback with `success=1` for a `ReverseProxy` socket
/// must call `relay.write_client_data`, delivering the payload bytes to the
/// waiting SOCKS5 client.
#[tokio::test]
async fn socket_read_callback_delivers_data_to_socks_client()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    server
        .listeners
        .create(common::http_listener_config("sock-dispatch-read", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("sock-dispatch-read").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xBB01_0004_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1A, 0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24,
        0x37,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Start a SOCKS server and connect a client.
    let (socks_port, socks_guard) = common::available_port()?;
    drop(socks_guard);
    server.sockets.add_socks_server(agent_id, &socks_port.to_string()).await?;

    let mut socks_client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{socks_port}")))
            .await??;
    socks5_handshake(&mut socks_client).await?;
    socks5_connect_ipv4(&mut socks_client, [93, 184, 216, 34], 80).await?;

    // Get the socket_id and complete the relay setup directly so the client is
    // in the relay's connected-socket table.
    let socket_id = dequeue_socket_id(&server.agent_registry, agent_id).await?;
    server.sockets.finish_connect(agent_id, socket_id, true, 0).await?;
    // Drain the SOCKS5 success reply so the client is in a clean read state.
    let _ = timeout(Duration::from_secs(1), read_socks5_reply(&mut socks_client, SOCKS_ATYP_IPV4))
        .await;

    // Build the CommandSocket/Read callback with success=1 carrying relay data.
    let relay_data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let mut read_payload = Vec::new();
    read_payload.extend_from_slice(&u32::from(DemonSocketCommand::Read).to_le_bytes());
    read_payload.extend_from_slice(&socket_id.to_le_bytes());
    read_payload.extend_from_slice(&u32::from(DemonSocketType::ReverseProxy).to_le_bytes());
    read_payload.extend_from_slice(&1_u32.to_le_bytes()); // success=1
    // Length-prefixed data (LE u32 length followed by bytes).
    read_payload.extend_from_slice(&u32::try_from(relay_data.len()).expect("unwrap").to_le_bytes());
    read_payload.extend_from_slice(relay_data);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSocket),
            0x04,
            &read_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // The relay should have called write_client_data — the SOCKS client
    // must receive the exact payload bytes.
    let mut received = vec![0u8; relay_data.len()];
    timeout(Duration::from_secs(2), socks_client.read_exact(&mut received)).await??;
    assert_eq!(
        received,
        relay_data.as_slice(),
        "SOCKS client must receive the exact data from the Read callback"
    );

    server.sockets.clear_socks_servers(agent_id).await?;
    server.listeners.stop("sock-dispatch-read").await?;
    Ok(())
}

/// A `CommandSocket/Close` callback for a `ReverseProxy` socket must call
/// `relay.close_client`, which closes the SOCKS5 client connection (EOF).
#[tokio::test]
async fn socket_close_callback_routes_to_relay_close_client()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    server
        .listeners
        .create(common::http_listener_config("sock-dispatch-close", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("sock-dispatch-close").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xBB01_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59,
        0x6C,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Start a SOCKS server and connect a client.
    let (socks_port, socks_guard) = common::available_port()?;
    drop(socks_guard);
    server.sockets.add_socks_server(agent_id, &socks_port.to_string()).await?;

    let mut socks_client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{socks_port}")))
            .await??;
    socks5_handshake(&mut socks_client).await?;
    socks5_connect_ipv4(&mut socks_client, [93, 184, 216, 34], 80).await?;

    // Get the socket_id and complete the relay setup directly so the client is
    // in the relay's connected-socket table.
    let socket_id = dequeue_socket_id(&server.agent_registry, agent_id).await?;
    server.sockets.finish_connect(agent_id, socket_id, true, 0).await?;
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

    server.sockets.clear_socks_servers(agent_id).await?;
    server.listeners.stop("sock-dispatch-close").await?;
    Ok(())
}

/// A `CommandSocket` callback with an unknown/invalid `DemonSocketCommand`
/// discriminant must not panic or corrupt relay state.  The HTTP response
/// should be a non-panic error (the listener returns a fake-404), and
/// subsequent valid callbacks must still be processed correctly.
#[tokio::test]
async fn unknown_socket_subcommand_does_not_panic_or_corrupt_state()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    server
        .listeners
        .create(common::http_listener_config("sock-dispatch-unknown", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("sock-dispatch-unknown").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xBB01_0099_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
        0xB3, 0xB4,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x84, 0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E,
        0xA1,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Start a SOCKS server and connect a client so we have relay state to verify.
    let (socks_port, socks_guard) = common::available_port()?;
    drop(socks_guard);
    server.sockets.add_socks_server(agent_id, &socks_port.to_string()).await?;

    let mut socks_client =
        timeout(Duration::from_secs(2), TcpStream::connect(format!("127.0.0.1:{socks_port}")))
            .await??;
    socks5_handshake(&mut socks_client).await?;
    socks5_connect_ipv4(&mut socks_client, [93, 184, 216, 34], 80).await?;

    let socket_id = dequeue_socket_id(&server.agent_registry, agent_id).await?;

    // --- Send a CommandSocket callback with an unknown subcommand value (99). ---
    let unknown_subcommand: u32 = 99;
    let mut unknown_payload = Vec::new();
    unknown_payload.extend_from_slice(&unknown_subcommand.to_le_bytes());
    // Append some dummy bytes to simulate a plausible but invalid payload.
    unknown_payload.extend_from_slice(&[0u8; 16]);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSocket),
            0x99,
            &unknown_payload,
        ))
        .send()
        .await?;

    // The listener should respond without panicking.  On dispatch errors the HTTP
    // listener returns a fake-404 (the standard evasion response), so we accept
    // either 200 or 404 — the important thing is no 5xx / connection reset.
    let status = response.status().as_u16();
    assert!(
        status == 200 || status == 404,
        "expected 200 or 404 for unknown subcommand, got {status}"
    );

    // --- Verify relay state is not corrupted: finish_connect still works. ---
    server.sockets.finish_connect(agent_id, socket_id, true, 0).await?;

    let (reply, _addr, _port) =
        timeout(Duration::from_secs(2), read_socks5_reply(&mut socks_client, SOCKS_ATYP_IPV4))
            .await??;
    assert_eq!(
        reply, SOCKS_REPLY_SUCCEEDED,
        "SOCKS client must still receive a success reply after an unknown subcommand callback"
    );

    // --- Verify subsequent valid callbacks still work. ---
    // Send relay data to the client via write_client_data (not through HTTP this
    // time, since the ctr_offset after the error is indeterminate — the key point
    // is that the relay state is intact).
    let relay_data = b"post-error data";
    server.sockets.write_client_data(agent_id, socket_id, relay_data).await?;

    let mut received = vec![0u8; relay_data.len()];
    timeout(Duration::from_secs(2), socks_client.read_exact(&mut received)).await??;
    assert_eq!(
        received,
        relay_data.as_slice(),
        "SOCKS client must receive data after an unknown subcommand callback"
    );

    server.sockets.clear_socks_servers(agent_id).await?;
    server.listeners.stop("sock-dispatch-unknown").await?;
    Ok(())
}
