mod dns;
mod external;
mod http_body_precheck;
mod http_callbacks;
mod http_proxy_headers;
mod http_rate_limiting;
mod http_registration;
mod http_request_matching;
mod http_response_headers;
mod http_tls;
mod lifecycle;
mod lifecycle_dns;
mod lifecycle_external;
mod lifecycle_http;
mod lifecycle_smb;
mod smb;

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use super::{
    DemonInitRateLimiter, DownloadTracker, ListenerManager, ListenerManagerError, ListenerStatus,
    ListenerSummary, ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter,
};
use crate::{
    AgentRegistry, Database, DemonInitSecretConfig, EventBus, PersistedListenerState,
    ShutdownController, SocketRelayManager,
};
use red_cell_common::AgentEncryptionInfo;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{DemonCommand, DemonEnvelope};
use red_cell_common::operator::ListenerInfo;
use red_cell_common::{
    ExternalListenerConfig, HttpListenerConfig, ListenerConfig, ListenerProtocol, SmbListenerConfig,
};
use reqwest::Client;
use tokio::time::sleep;
use zeroize::Zeroizing;

/// Generate a non-degenerate test key from a seed byte.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

fn http_listener(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
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
        legacy_mode: true,
        suppress_opsec_warnings: true,
    })
}

fn https_listener(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: true,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    })
}

fn http_listener_with_redirector(
    name: &str,
    port: u16,
    trusted_proxy_peers: Vec<String>,
) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: true,
        trusted_proxy_peers,
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
        legacy_mode: true,
        suppress_opsec_warnings: true,
    })
}

fn smb_listener(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

async fn manager() -> Result<ListenerManager, ListenerManagerError> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    Ok(ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true))
}

/// Return a port that is free on 127.0.0.1 and is unique across all concurrent callers
/// within this test binary.
///
/// Binds to port 0 so the OS kernel assigns an ephemeral port. This is safe
/// across nextest process boundaries because the kernel's ephemeral allocator
/// avoids handing out the same port to concurrent callers. The socket is
/// dropped after reading the assigned port — callers that start real
/// listeners should use [`create_and_start_http`] which retries on
/// `EADDRINUSE` to cover the brief TOCTOU window.
fn available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Create and start an HTTP listener, retrying with a fresh port when the
/// initial candidate was stolen between `available_port()` and the actual
/// `TcpListener::bind` inside the listener runtime (TOCTOU race).
async fn create_and_start_http(
    manager: &ListenerManager,
    name: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    const MAX_ATTEMPTS: usize = 5;
    for attempt in 0..MAX_ATTEMPTS {
        let port = available_port()?;
        manager.create(http_listener(name, port)).await?;
        match manager.start(name).await {
            Ok(_) => return Ok(port),
            Err(ListenerManagerError::StartFailed { ref message, .. })
                if message.contains("Address already in use")
                    || message.contains("os error 98") =>
            {
                // Port was stolen — delete the listener and retry.
                tracing::debug!(
                    %name,
                    %port,
                    %attempt,
                    "port conflict during start, retrying with a new port"
                );
                manager.delete(name).await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!("failed to start listener `{name}` after {MAX_ATTEMPTS} port attempts").into())
}

/// Same as [`create_and_start_http`] but creates an HTTPS/TLS listener.
async fn create_and_start_https(
    manager: &ListenerManager,
    name: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    const MAX_ATTEMPTS: usize = 5;
    for attempt in 0..MAX_ATTEMPTS {
        let port = available_port()?;
        manager.create(https_listener(name, port)).await?;
        match manager.start(name).await {
            Ok(_) => return Ok(port),
            Err(ListenerManagerError::StartFailed { ref message, .. })
                if message.contains("Address already in use")
                    || message.contains("os error 98") =>
            {
                tracing::debug!(
                    %name,
                    %port,
                    %attempt,
                    "port conflict during start, retrying with a new port"
                );
                manager.delete(name).await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!("failed to start HTTPS listener `{name}` after {MAX_ATTEMPTS} port attempts")
        .into())
}

async fn wait_for_listener_status(
    manager: &ListenerManager,
    name: &str,
    expected: ListenerStatus,
) -> Result<(), ListenerManagerError> {
    for _ in 0..40 {
        if manager.summary(name).await?.state.status == expected {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }

    Err(ListenerManagerError::InvalidConfig {
        message: format!("listener `{name}` did not reach expected status {expected:?}"),
    })
}

async fn wait_for_listener(port: u16, secure: bool) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder().danger_accept_invalid_certs(true).build()?;
    let scheme = if secure { "https" } else { "http" };
    let url = format!("{scheme}://127.0.0.1:{port}/");

    for _ in 0..40 {
        match client.get(&url).send().await {
            Ok(_) => return Ok(()),
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }

    Err(format!("listener on port {port} did not become ready").into())
}

fn valid_demon_request_body(agent_id: u32) -> Vec<u8> {
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| {
            panic!("failed to build valid demon request body: {error}");
        })
        .to_bytes()
}

fn sample_agent_info(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "REDCELL".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x401000,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 15,
        sleep_jitter: 20,
        kill_date: Some(1_893_456_000),
        working_hours: Some(0b101010),
        first_call_in: "2026-03-09T19:00:00Z".to_owned(),
        last_call_in: "2026-03-09T19:01:00Z".to_owned(),
        archon_magic: None,
    }
}

fn valid_demon_init_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes(&mut metadata, b"operator");
    add_length_prefixed_bytes(&mut metadata, b"REDCELL");
    add_length_prefixed_bytes(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

    let encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata)
        .expect("metadata encryption should succeed");
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
        .to_bytes()
}

fn valid_demon_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    command_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    valid_demon_multi_callback_body(
        agent_id,
        key,
        iv,
        (command_id, request_id, payload.to_vec()),
        &[],
    )
}

fn valid_demon_multi_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    first: (u32, u32, Vec<u8>),
    additional: &[(u32, u32, Vec<u8>)],
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(
        &u32::try_from(first.2.len()).expect("test data fits in u32").to_be_bytes(),
    );
    decrypted.extend_from_slice(&first.2);

    for (command_id, request_id, payload) in additional {
        decrypted.extend_from_slice(&command_id.to_be_bytes());
        decrypted.extend_from_slice(&request_id.to_be_bytes());
        decrypted.extend_from_slice(
            &u32::try_from(payload.len()).expect("test data fits in u32").to_be_bytes(),
        );
        decrypted.extend_from_slice(payload);
    }

    let encrypted =
        encrypt_agent_data(&key, &iv, &decrypted).expect("callback encryption should succeed");
    let payload =
        [first.0.to_be_bytes().as_slice(), first.1.to_be_bytes().as_slice(), encrypted.as_slice()]
            .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon callback request body: {error}"))
        .to_bytes()
}

fn add_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(
        &u32::try_from(bytes.len()).expect("test data fits in u32").to_be_bytes(),
    );
    buf.extend_from_slice(bytes);
}

fn add_length_prefixed_utf16(buf: &mut Vec<u8>, value: &str) {
    let encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    add_length_prefixed_bytes(buf, &encoded);
}

fn add_checkin_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn add_checkin_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn add_checkin_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    add_checkin_u32(buf, u32::try_from(bytes.len()).expect("test data fits in u32"));
    buf.extend_from_slice(bytes);
}

fn add_checkin_utf16(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_checkin_bytes(buf, &encoded);
}

fn sample_checkin_metadata_payload(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    add_checkin_u32(&mut payload, agent_id);
    add_checkin_bytes(&mut payload, b"wkstn-02");
    add_checkin_bytes(&mut payload, b"svc-op");
    add_checkin_bytes(&mut payload, b"research");
    add_checkin_bytes(&mut payload, b"10.10.10.50");
    add_checkin_utf16(&mut payload, "C:\\Windows\\System32\\cmd.exe");
    add_checkin_u32(&mut payload, 4040);
    add_checkin_u32(&mut payload, 5050);
    add_checkin_u32(&mut payload, 3030);
    add_checkin_u32(&mut payload, 1);
    add_checkin_u32(&mut payload, 0);
    add_checkin_u64(&mut payload, 0x401000);
    add_checkin_u32(&mut payload, 10);
    add_checkin_u32(&mut payload, 0);
    add_checkin_u32(&mut payload, 1);
    add_checkin_u32(&mut payload, 0);
    add_checkin_u32(&mut payload, 22_621);
    add_checkin_u32(&mut payload, 9);
    add_checkin_u32(&mut payload, 45);
    add_checkin_u32(&mut payload, 5);
    add_checkin_u64(&mut payload, 1_725_000_000);
    add_checkin_u32(&mut payload, 0x00FF_00FF);
    payload
}

// --- listener lifecycle event payload helpers ---

fn minimal_http_summary(name: &str) -> ListenerSummary {
    ListenerSummary {
        name: name.to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: http_listener(name, 8080),
    }
}

fn valid_http_listener_info() -> ListenerInfo {
    ListenerInfo {
        name: Some("http-test".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("false".to_owned()),
        ..ListenerInfo::default()
    }
}

async fn manager_with_secret(
    secret: Vec<u8>,
) -> Result<(ListenerManager, AgentRegistry, Database, EventBus), ListenerManagerError> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true)
            .with_demon_init_secret(Some(secret));
    Ok((manager, registry, database, events))
}

/// HTTP listener configured with `with_demon_init_secret` accepts a
/// DEMON_INIT packet and the returned ACK is encrypted with the derived
/// (HKDF) session keys — not the raw agent keys.

fn external_listener_config(name: &str, endpoint: &str) -> ListenerConfig {
    ListenerConfig::from(ExternalListenerConfig {
        name: name.to_owned(),
        endpoint: endpoint.to_owned(),
    })
}

fn dns_listener_config(name: &str, port: u16, domain: &str) -> ListenerConfig {
    ListenerConfig::from(red_cell_common::DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    })
}

fn free_udp_port() -> u16 {
    // Bind on :0 to let the OS pick an ephemeral port, then return it.
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}
