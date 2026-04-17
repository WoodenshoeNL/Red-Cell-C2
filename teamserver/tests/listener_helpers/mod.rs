//! Shared helpers for listener lifecycle integration tests.
//!
//! Import this module in each listener-lifecycle test file with
//! `mod listener_helpers;`. These helpers build minimal listener configs and
//! provide readiness probes for the protocols the [`ListenerManager`] supports.

// Not every test file uses every helper; suppress dead_code warnings for this module.
#![allow(dead_code)]

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, ListenerConfig,
    SmbListenerConfig,
};
use tokio::time::timeout;

/// Create a minimal in-memory [`ListenerManager`] for testing.
pub async fn test_manager() -> Result<ListenerManager, Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    Ok(ListenerManager::new(database, registry, events, sockets, None))
}

/// Build a minimal HTTP listener config bound to `port`.
pub fn http_config(name: &str, port: u16) -> ListenerConfig {
    http_config_with_time(name, port, None, None)
}

/// Build an HTTP listener config with optional `kill_date` and `working_hours`.
pub fn http_config_with_time(
    name: &str,
    port: u16,
    kill_date: Option<&str>,
    working_hours: Option<&str>,
) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: kill_date.map(str::to_owned),
        working_hours: working_hours.map(str::to_owned),
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
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    })
}

/// Build a minimal SMB listener config with the given `pipe_name`.
pub fn smb_config(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

/// Compute a unique pipe name for each test to avoid collisions.
pub fn unique_pipe_name(suffix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    format!("red-cell-lc-test-{suffix}-{ts}")
}

/// Build a minimal DNS listener config bound to `port`.
pub fn dns_config(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "test.c2.local".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    })
}

/// Build a minimal External listener config with the given `endpoint`.
pub fn external_config(name: &str, endpoint: &str) -> ListenerConfig {
    ListenerConfig::from(ExternalListenerConfig {
        name: name.to_owned(),
        endpoint: endpoint.to_owned(),
    })
}

/// Build a minimal DNS query packet for probing listener readiness.
pub fn build_dns_probe_query() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xFFFF_u16.to_be_bytes()); // ID
    buf.extend_from_slice(&0x0100_u16.to_be_bytes()); // flags: QR=0, RD=1
    buf.extend_from_slice(&1_u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // arcount
    for label in "probe.other.domain.com".split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // zero terminator
    buf.extend_from_slice(&16_u16.to_be_bytes()); // QTYPE TXT
    buf.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN
    buf
}

/// Poll until the DNS listener on `port` is ready to accept queries.
pub async fn wait_for_dns_listener(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::net::UdpSocket;
    use tokio::time::sleep;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{port}")).await?;
    let probe = build_dns_probe_query();

    for _ in 0..40 {
        let _ = client.send(&probe).await;
        let mut buf = vec![0u8; 512];
        if timeout(Duration::from_millis(50), client.recv(&mut buf)).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("DNS listener on port {port} did not become ready").into())
}

/// Poll until the SMB listener's named pipe is ready to accept connections.
#[cfg(unix)]
pub async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    use interprocess::local_socket::ToNsName as _;
    use interprocess::local_socket::tokio::Stream as LocalSocketStream;
    use interprocess::local_socket::traits::tokio::Stream as _;
    use interprocess::os::unix::local_socket::AbstractNsUdSocket;
    use tokio::time::sleep;

    let smb_prefix = r"\\.\pipe\";
    let trimmed = pipe_name.trim();
    let full = if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{smb_prefix}{trimmed}")
    };
    let socket_name = full.to_ns_name::<AbstractNsUdSocket>()?.into_owned();

    for _ in 0..40 {
        if LocalSocketStream::connect(socket_name.clone()).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("SMB listener on pipe `{pipe_name}` did not become ready within 1 s").into())
}
