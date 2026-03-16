//! SOCKS5 relay integration tests.
//!
//! These tests exercise the [`SocketRelayManager`] end-to-end using real in-process
//! TCP connections.  They cover: SOCKS5 CONNECT negotiation (IPv4, domain, IPv6),
//! the data-relay path after the agent completes the connect, relay teardown on agent
//! disconnect, and the server lifecycle (add / remove / clear).

mod common;

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, SocketRelayManager};
use red_cell_common::AgentEncryptionInfo;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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

    let port_a = common::available_port()?;
    let port_b = common::available_port_excluding(port_a)?;
    manager.add_socks_server(agent_id, &port_a.to_string()).await?;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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

    let port = common::available_port()?;
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
