//! Integration tests for malformed Demon protocol packet handling.
//!
//! These tests verify that every listener type (HTTP, DNS, SMB) gracefully
//! rejects malformed Demon packets without crashing, leaking state, or
//! corrupting the agent registry.  Each test sends deliberately invalid input
//! and asserts that:
//!
//! 1. The listener returns an error response (HTTP 404, DNS "err"/"ack", SMB
//!    connection close).
//! 2. No agent state is created in the registry.
//! 3. The listener remains alive and can process a valid packet afterward.

mod common;

use std::time::Duration;

#[cfg(unix)]
use interprocess::local_socket::ToNsName as _;
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::Stream as _;
#[cfg(unix)]
use interprocess::os::unix::local_socket::AbstractNsUdSocket;
use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope};
use red_cell_common::{DnsListenerConfig, HttpListenerConfig, ListenerConfig, SmbListenerConfig};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Non-degenerate test AES key from a seed byte.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Non-degenerate test AES IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Build a raw packet with the given size field, magic, agent_id, and payload.
///
/// This bypasses `DemonEnvelope::new` so we can craft intentionally broken
/// wire-format packets.
fn raw_demon_packet(size: u32, magic: u32, agent_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + payload.len());
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(&magic.to_be_bytes());
    buf.extend_from_slice(&agent_id.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Build a valid-looking DemonEnvelope with a correct header but whose payload
/// is pure garbage (not valid init or callback data).
fn garbage_payload_packet(agent_id: u32, garbage_len: usize) -> Vec<u8> {
    let garbage: Vec<u8> = (0..garbage_len).map(|i| (i & 0xFF) as u8).collect();
    DemonEnvelope::new(agent_id, garbage)
        .unwrap_or_else(|e| panic!("envelope construction failed: {e}"))
        .to_bytes()
}

/// Build a packet with valid DemonInit command but corrupted encrypted metadata.
///
/// The key/IV are present and non-degenerate, but the "encrypted" block is
/// random garbage that will fail AES-CTR decryption/parsing.
fn corrupted_init_packet(agent_id: u32) -> Vec<u8> {
    let key = test_key(0x50);
    let iv = test_iv(0x60);

    // Use garbage instead of properly encrypted metadata.
    let corrupted_encrypted: Vec<u8> = (0..128).map(|i| (i * 7 + 13) as u8).collect();

    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        corrupted_encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|e| panic!("envelope construction failed: {e}"))
        .to_bytes()
}

/// Build a DemonInit packet with an oversized length-prefixed field inside
/// the encrypted metadata.
///
/// The outer envelope is valid and the key/IV are correct, but one of the
/// BE-length-prefixed strings inside the metadata claims a length far beyond
/// the remaining buffer.
fn oversized_inner_field_init_packet(agent_id: u32) -> Vec<u8> {
    let key = test_key(0x70);
    let iv = test_iv(0x80);

    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    // First field (hostname): claim 0xFFFFFF bytes but only provide 4
    metadata.extend_from_slice(&0x00FF_FFFF_u32.to_be_bytes());
    metadata.extend_from_slice(b"test");

    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");

    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|e| panic!("envelope construction failed: {e}"))
        .to_bytes()
}

/// Build a callback packet with correct envelope and agent_id but garbage
/// encrypted payload (simulating CTR desync).
fn ctr_desync_callback_packet(agent_id: u32) -> Vec<u8> {
    // Use a completely wrong key to encrypt — the server will try to decrypt
    // with the registered key and get garbage.
    let wrong_key = test_key(0xEE);
    let wrong_iv = test_iv(0xFF);
    let fake_payload = vec![0x42; 32];

    let encrypted = encrypt_agent_data_at_offset(&wrong_key, &wrong_iv, 0, &fake_payload)
        .expect("encryption should succeed");

    let body = [
        u32::from(DemonCommand::CommandGetJob).to_be_bytes().as_slice(),
        99_u32.to_be_bytes().as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, body)
        .unwrap_or_else(|e| panic!("envelope construction failed: {e}"))
        .to_bytes()
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

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
        legacy_mode: true,
        suppress_opsec_warnings: true,
    })
}

async fn setup_http_listener(
    name: &str,
) -> Result<(u16, AgentRegistry, ListenerManager), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;

    manager.create(http_listener(name, port)).await?;
    drop(guard);
    manager.start(name).await?;
    common::wait_for_listener(port).await?;

    Ok((port, registry, manager))
}

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

fn base32hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(char::from(BASE32HEX_ALPHABET[((buf >> bits) & 0x1F) as usize]));
        }
    }
    if bits > 0 {
        buf <<= 5 - bits;
        result.push(char::from(BASE32HEX_ALPHABET[(buf & 0x1F) as usize]));
    }
    result
}

fn dns_upload_qname(agent_id: u32, seq: u16, total: u16, chunk: &[u8], domain: &str) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100_u16.to_be_bytes());
    buf.extend_from_slice(&1_u16.to_be_bytes());
    buf.extend_from_slice(&0_u16.to_be_bytes());
    buf.extend_from_slice(&0_u16.to_be_bytes());
    buf.extend_from_slice(&0_u16.to_be_bytes());
    for label in qname.split('.') {
        buf.push(u8::try_from(label.len()).expect("label too long"));
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1_u16.to_be_bytes());
    buf
}

fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, 16)
}

fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    let mut pos = 12;
    while pos < packet.len() {
        let len = usize::from(packet[pos]);
        pos += 1;
        if len == 0 {
            break;
        }
        pos = pos.checked_add(len)?;
    }
    pos = pos.checked_add(4)?;
    pos = pos.checked_add(2 + 2 + 2 + 4 + 2)?;
    let txt_len = usize::from(*packet.get(pos)?);
    let start = pos.checked_add(1)?;
    let end = start.checked_add(txt_len)?;
    std::str::from_utf8(packet.get(start..end)?).ok().map(str::to_owned)
}

fn free_udp_port() -> u16 {
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

fn dns_listener(name: &str, port: u16, domain: &str) -> ListenerConfig {
    ListenerConfig::from(DnsListenerConfig {
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

async fn dns_upload_demon_packet(
    client: &UdpSocket,
    agent_id: u32,
    payload: &[u8],
    domain: &str,
    query_id_base: u16,
) -> Result<String, Box<dyn std::error::Error>> {
    let chunks: Vec<&[u8]> = payload.chunks(39).collect();
    let total = u16::try_from(chunks.len())?;
    let mut last_txt = String::new();

    for (seq, chunk) in chunks.iter().enumerate() {
        let seq_u16 = u16::try_from(seq)?;
        let qname = dns_upload_qname(agent_id, seq_u16, total, chunk, domain);
        let packet = build_dns_txt_query(query_id_base.wrapping_add(seq_u16), &qname);
        client.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        last_txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    }

    Ok(last_txt)
}

async fn wait_for_dns_listener(port: u16) -> Result<UdpSocket, Box<dyn std::error::Error>> {
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{port}")).await?;

    for _ in 0..40 {
        let packet = build_dns_txt_query(0xFFFF, "probe.other.domain.com");
        let _ = client.send(&packet).await;
        let mut buf = vec![0u8; 512];
        if timeout(Duration::from_millis(50), client.recv(&mut buf)).await.is_ok() {
            return Ok(client);
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("DNS listener on port {port} did not become ready").into())
}

async fn setup_dns_listener(
    name: &str,
    domain: &str,
) -> Result<(UdpSocket, AgentRegistry, ListenerManager), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = free_udp_port();

    manager.create(dns_listener(name, port, domain)).await?;
    manager.start(name).await?;
    let client = wait_for_dns_listener(port).await?;

    Ok((client, registry, manager))
}

// ---------------------------------------------------------------------------
// SMB helpers
// ---------------------------------------------------------------------------

const SMB_PIPE_PREFIX: &str = r"\\.\pipe\";

fn smb_config(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

fn unique_pipe_name(suffix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    format!("red-cell-malform-test-{suffix}-{ts}")
}

#[cfg(unix)]
fn resolve_socket_name(
    pipe_name: &str,
) -> Result<interprocess::local_socket::Name<'static>, Box<dyn std::error::Error>> {
    let trimmed = pipe_name.trim();
    let full = if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{SMB_PIPE_PREFIX}{trimmed}")
    };
    Ok(full.to_ns_name::<AbstractNsUdSocket>()?.into_owned())
}

#[cfg(unix)]
async fn connect_smb(pipe_name: &str) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
    let socket_name = resolve_socket_name(pipe_name)?;
    Ok(LocalSocketStream::connect(socket_name).await?)
}

#[cfg(unix)]
async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..40 {
        if connect_smb(pipe_name).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("SMB listener on pipe `{pipe_name}` did not become ready within 1 s").into())
}

#[cfg(unix)]
async fn write_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(u32::try_from(payload.len())?).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(unix)]
async fn read_smb_frame(
    stream: &mut LocalSocketStream,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
    let agent_id = stream.read_u32_le().await?;
    let payload_len = usize::try_from(stream.read_u32_le().await?)?;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((agent_id, payload))
}

#[cfg(unix)]
async fn setup_smb_listener(
    name: &str,
    pipe_suffix: &str,
) -> Result<(String, AgentRegistry, ListenerManager), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let pipe_name = unique_pipe_name(pipe_suffix);

    manager.create(smb_config(name, &pipe_name)).await?;
    manager.start(name).await?;
    wait_for_smb_listener(&pipe_name).await?;

    Ok((pipe_name, registry, manager))
}

// ===========================================================================
// HTTP malformed packet tests
// ===========================================================================

/// Invalid magic value in an otherwise well-formed DemonInit envelope.
#[tokio::test]
async fn http_rejects_invalid_magic_in_init() -> Result<(), Box<dyn std::error::Error>> {
    let (port, registry, manager) = setup_http_listener("http-bad-magic").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    // Correct size field (8 for magic+agent_id + 4 padding = 12), but wrong magic.
    let packet = raw_demon_packet(12, 0xCAFE_BABE, 0x1111_2222, &[0x00; 4]);
    let response = client.post(&url).body(packet).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(registry.get(0x1111_2222).await.is_none());

    // Verify listener survived.
    let valid_response = client
        .post(&url)
        .body(common::valid_demon_init_body(0xAAAA_0001, test_key(0x01), test_iv(0x02)))
        .send()
        .await?
        .error_for_status()?;
    assert!(!valid_response.bytes().await?.is_empty());

    manager.stop("http-bad-magic").await?;
    Ok(())
}

/// Size field claims more data than actually present (truncated body).
#[tokio::test]
async fn http_rejects_size_mismatch_truncated() -> Result<(), Box<dyn std::error::Error>> {
    let (port, registry, manager) = setup_http_listener("http-trunc").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    // Size says 200 bytes follow, but we only provide magic + agent_id (8 bytes).
    let packet = raw_demon_packet(200, DEMON_MAGIC_VALUE, 0x2222_3333, &[]);
    let response = client.post(&url).body(packet).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(registry.get(0x2222_3333).await.is_none());

    manager.stop("http-trunc").await?;
    Ok(())
}

/// Size field claims fewer bytes than actually present (size underflow).
#[tokio::test]
async fn http_rejects_size_mismatch_underflow() -> Result<(), Box<dyn std::error::Error>> {
    let (port, registry, manager) = setup_http_listener("http-underflow").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    // Size says 8 bytes follow (just magic+agent_id), but we append 64 extra bytes.
    let packet = raw_demon_packet(8, DEMON_MAGIC_VALUE, 0x3333_4444, &[0xBB; 64]);
    let response = client.post(&url).body(packet).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(registry.get(0x3333_4444).await.is_none());

    manager.stop("http-underflow").await?;
    Ok(())
}

/// Corrupted encryption block: valid DemonInit header with garbage encrypted
/// metadata that will fail decryption/parsing.
#[tokio::test]
async fn http_rejects_corrupted_encrypted_init() -> Result<(), Box<dyn std::error::Error>> {
    let (port, registry, manager) = setup_http_listener("http-corrupt-enc").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    let agent_id = 0x4444_5555;
    let response = client.post(&url).body(corrupted_init_packet(agent_id)).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(registry.get(agent_id).await.is_none());

    // Listener still alive.
    let valid_response = client
        .post(&url)
        .body(common::valid_demon_init_body(0xAAAA_0002, test_key(0x03), test_iv(0x04)))
        .send()
        .await?
        .error_for_status()?;
    assert!(!valid_response.bytes().await?.is_empty());

    manager.stop("http-corrupt-enc").await?;
    Ok(())
}

/// Oversized length-prefixed field inside the encrypted init metadata.
#[tokio::test]
async fn http_rejects_oversized_inner_field() -> Result<(), Box<dyn std::error::Error>> {
    let (port, registry, manager) = setup_http_listener("http-oversized-field").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    let agent_id = 0x5555_6666;
    let response =
        client.post(&url).body(oversized_inner_field_init_packet(agent_id)).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("http-oversized-field").await?;
    Ok(())
}

/// Garbage payload with valid DemonEnvelope header (not init, not callback).
#[tokio::test]
async fn http_rejects_garbage_payload_with_valid_header() -> Result<(), Box<dyn std::error::Error>>
{
    let (port, registry, manager) = setup_http_listener("http-garbage-payload").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    let agent_id = 0x6666_7777;
    let response = client.post(&url).body(garbage_payload_packet(agent_id, 256)).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("http-garbage-payload").await?;
    Ok(())
}

/// CTR desync scenario: register an agent, then send a callback encrypted with
/// the wrong key.  The server must reject the packet without corrupting the
/// agent's CTR state.
#[tokio::test]
async fn http_rejects_ctr_desync_callback_preserves_state() -> Result<(), Box<dyn std::error::Error>>
{
    let (port, registry, manager) = setup_http_listener("http-ctr-desync").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");
    let agent_id = 0x7777_8888;
    let key = test_key(0x10);
    let iv = test_iv(0x20);

    // Register the agent first.
    client
        .post(&url)
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    assert!(registry.get(agent_id).await.is_some());

    let ctr_before = registry.ctr_offset(agent_id).await?;

    // Send a callback encrypted with the wrong key (CTR desync).
    let response = client.post(&url).body(ctr_desync_callback_packet(agent_id)).send().await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "CTR desync callback must be rejected"
    );

    // CTR offset must not have advanced.
    let ctr_after = registry.ctr_offset(agent_id).await?;
    assert_eq!(ctr_before, ctr_after, "CTR offset must not advance on failed decryption");

    // Agent must still be functional — send a valid callback.
    let checkin_response = client
        .post(&url)
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_before,
            u32::from(DemonCommand::CommandCheckin),
            42,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(checkin_response.bytes().await?.is_empty());

    manager.stop("http-ctr-desync").await?;
    Ok(())
}

/// Rapid-fire mixed malformed packets must not crash the listener or leak state.
#[tokio::test]
async fn http_survives_rapid_fire_malformed_barrage() -> Result<(), Box<dyn std::error::Error>> {
    let (port, registry, manager) = setup_http_listener("http-barrage").await?;
    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    let malformed_packets: Vec<Vec<u8>> = vec![
        vec![],                                                            // empty
        vec![0xFF; 3],                                                     // sub-minimum
        raw_demon_packet(8, 0x0000_0000, 0xBBBB_0001, &[]),                // zero magic
        raw_demon_packet(8, DEMON_MAGIC_VALUE, 0xBBBB_0002, &[]),          // no payload
        raw_demon_packet(500, DEMON_MAGIC_VALUE, 0xBBBB_0003, &[0xCC; 4]), // size too large
        raw_demon_packet(9, DEMON_MAGIC_VALUE, 0xBBBB_0004, &[0xDD; 64]),  // size too small
        corrupted_init_packet(0xBBBB_0005),
        garbage_payload_packet(0xBBBB_0006, 64),
        garbage_payload_packet(0xBBBB_0007, 1024),
    ];

    for (i, packet) in malformed_packets.iter().enumerate() {
        let response = client.post(&url).body(packet.clone()).send().await?;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "malformed packet {i} must be rejected with 404"
        );
    }

    // No agents should have been registered.
    assert!(registry.list_active().await.is_empty(), "no agents should exist after barrage");

    // Listener must still accept valid traffic.
    let valid_response = client
        .post(&url)
        .body(common::valid_demon_init_body(0xBBBB_FFFF, test_key(0x30), test_iv(0x40)))
        .send()
        .await?
        .error_for_status()?;
    assert!(!valid_response.bytes().await?.is_empty());
    assert!(registry.get(0xBBBB_FFFF).await.is_some());

    manager.stop("http-barrage").await?;
    Ok(())
}

// ===========================================================================
// DNS malformed packet tests
// ===========================================================================

/// Truncated/incomplete DemonEnvelope uploaded via DNS.
#[tokio::test]
async fn dns_rejects_truncated_demon_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let (client, registry, manager) =
        setup_dns_listener("dns-trunc", "c2-trunc.example.com").await?;
    let domain = "c2-trunc.example.com";
    let agent_id = 0xDD00_1111;

    // Upload a truncated packet: just the size field + partial magic.
    let truncated = vec![0x00, 0x00, 0x00, 0x08, 0xDE, 0xAD];
    let result = dns_upload_demon_packet(&client, agent_id, &truncated, domain, 0x100).await?;
    assert!(
        result == "ack" || result == "err",
        "truncated DNS upload must return 'ack' or 'err', got '{result}'"
    );
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("dns-trunc").await?;
    Ok(())
}

/// Invalid magic value in DemonEnvelope uploaded via DNS.
#[tokio::test]
async fn dns_rejects_invalid_magic() -> Result<(), Box<dyn std::error::Error>> {
    let (client, registry, manager) =
        setup_dns_listener("dns-bad-magic", "c2-magic.example.com").await?;
    let domain = "c2-magic.example.com";
    let agent_id = 0xDD00_2222;

    let packet = raw_demon_packet(12, 0x0BAD_CA5E, agent_id, &[0x00; 4]);
    let result = dns_upload_demon_packet(&client, agent_id, &packet, domain, 0x200).await?;
    assert!(
        result == "ack" || result == "err",
        "bad magic DNS upload must return 'ack' or 'err', got '{result}'"
    );
    assert!(registry.get(agent_id).await.is_none());

    // Verify listener still works with a valid init.
    let valid_body = common::valid_demon_init_body(0xDD00_AAAA, test_key(0xA0), test_iv(0xB0));
    let valid_result =
        dns_upload_demon_packet(&client, 0xDD00_AAAA, &valid_body, domain, 0x300).await?;
    assert_eq!(valid_result, "ack", "valid init must succeed after malformed input");
    assert!(registry.get(0xDD00_AAAA).await.is_some());

    manager.stop("dns-bad-magic").await?;
    Ok(())
}

/// Size field mismatch in DemonEnvelope uploaded via DNS.
#[tokio::test]
async fn dns_rejects_size_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let (client, registry, manager) =
        setup_dns_listener("dns-size-mm", "c2-size.example.com").await?;
    let domain = "c2-size.example.com";
    let agent_id = 0xDD00_3333;

    // Claim 500 bytes follow, but only provide magic + agent_id.
    let packet = raw_demon_packet(500, DEMON_MAGIC_VALUE, agent_id, &[]);
    let result = dns_upload_demon_packet(&client, agent_id, &packet, domain, 0x400).await?;
    assert!(
        result == "ack" || result == "err",
        "size mismatch DNS upload must return 'ack' or 'err', got '{result}'"
    );
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("dns-size-mm").await?;
    Ok(())
}

/// Corrupted encrypted init metadata uploaded via DNS.
#[tokio::test]
async fn dns_rejects_corrupted_encrypted_init() -> Result<(), Box<dyn std::error::Error>> {
    let (client, registry, manager) =
        setup_dns_listener("dns-corrupt-enc", "c2-enc.example.com").await?;
    let domain = "c2-enc.example.com";
    let agent_id = 0xDD00_4444;

    let packet = corrupted_init_packet(agent_id);
    let result = dns_upload_demon_packet(&client, agent_id, &packet, domain, 0x500).await?;
    assert!(
        result == "ack" || result == "err",
        "corrupted encrypted init DNS upload must return 'ack' or 'err', got '{result}'"
    );
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("dns-corrupt-enc").await?;
    Ok(())
}

/// Garbage payload with valid header uploaded via DNS.
#[tokio::test]
async fn dns_rejects_garbage_payload() -> Result<(), Box<dyn std::error::Error>> {
    let (client, registry, manager) =
        setup_dns_listener("dns-garbage", "c2-garbage.example.com").await?;
    let domain = "c2-garbage.example.com";
    let agent_id = 0xDD00_5555;

    let packet = garbage_payload_packet(agent_id, 128);
    let result = dns_upload_demon_packet(&client, agent_id, &packet, domain, 0x600).await?;
    assert!(
        result == "ack" || result == "err",
        "garbage payload DNS upload must return 'ack' or 'err', got '{result}'"
    );
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("dns-garbage").await?;
    Ok(())
}

/// CTR desync scenario via DNS: register agent, then send callback encrypted
/// with wrong key.
#[tokio::test]
async fn dns_rejects_ctr_desync_callback() -> Result<(), Box<dyn std::error::Error>> {
    let (client, registry, manager) =
        setup_dns_listener("dns-ctr-desync", "c2-desync.example.com").await?;
    let domain = "c2-desync.example.com";
    let agent_id = 0xDD00_6666;
    let key = test_key(0xC0);
    let iv = test_iv(0xD0);

    // Register the agent.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result = dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0x700).await?;
    assert_eq!(init_result, "ack");
    assert!(registry.get(agent_id).await.is_some());

    let ctr_before = registry.ctr_offset(agent_id).await?;

    // Send desync callback (wrong key).
    let desync_packet = ctr_desync_callback_packet(agent_id);
    let desync_result =
        dns_upload_demon_packet(&client, agent_id, &desync_packet, domain, 0x800).await?;
    assert!(
        desync_result == "ack" || desync_result == "err",
        "CTR desync DNS callback must return 'ack' or 'err', got '{desync_result}'"
    );

    // CTR offset must be unchanged.
    let ctr_after = registry.ctr_offset(agent_id).await?;
    assert_eq!(ctr_before, ctr_after, "CTR offset must not advance on failed DNS callback");

    manager.stop("dns-ctr-desync").await?;
    Ok(())
}

// ===========================================================================
// SMB malformed packet tests
// ===========================================================================

/// Truncated DemonEnvelope sent via SMB named pipe.
#[cfg(unix)]
#[tokio::test]
async fn smb_rejects_truncated_demon_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let (pipe_name, registry, manager) = setup_smb_listener("smb-trunc", "trunc").await?;
    let agent_id = 0xEE00_1111;

    let mut stream = connect_smb(&pipe_name).await?;
    // Send a frame with only 3 bytes of DemonEnvelope (below MIN_ENVELOPE_SIZE).
    write_smb_frame(&mut stream, agent_id, &[0xDE, 0xAD, 0xBE]).await?;

    // The server should close the connection or return an error.
    // Give it a moment to process, then verify no agent was registered.
    sleep(Duration::from_millis(100)).await;
    assert!(registry.get(agent_id).await.is_none());

    // Verify listener survives: open a new connection and do a valid init.
    let valid_agent_id = 0xEE00_AAAA;
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let mut stream2 = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut stream2,
        valid_agent_id,
        &common::valid_demon_init_body(valid_agent_id, key, iv),
    )
    .await?;
    let result = timeout(Duration::from_secs(5), read_smb_frame(&mut stream2)).await;
    assert!(result.is_ok(), "listener must still accept valid connections after malformed input");
    assert!(registry.get(valid_agent_id).await.is_some());

    manager.stop("smb-trunc").await?;
    Ok(())
}

/// Invalid magic value sent via SMB named pipe.
#[cfg(unix)]
#[tokio::test]
async fn smb_rejects_invalid_magic() -> Result<(), Box<dyn std::error::Error>> {
    let (pipe_name, registry, manager) = setup_smb_listener("smb-bad-magic", "badmagic").await?;
    let agent_id = 0xEE00_2222;

    let mut stream = connect_smb(&pipe_name).await?;
    let packet = raw_demon_packet(12, 0xBAD_CAFE, agent_id, &[0x00; 4]);
    write_smb_frame(&mut stream, agent_id, &packet).await?;

    sleep(Duration::from_millis(100)).await;
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("smb-bad-magic").await?;
    Ok(())
}

/// Size field mismatch sent via SMB named pipe.
#[cfg(unix)]
#[tokio::test]
async fn smb_rejects_size_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let (pipe_name, registry, manager) = setup_smb_listener("smb-size-mm", "sizemm").await?;
    let agent_id = 0xEE00_3333;

    let mut stream = connect_smb(&pipe_name).await?;
    // Declare 200 bytes in header but provide only 8 (magic + agent_id).
    let packet = raw_demon_packet(200, DEMON_MAGIC_VALUE, agent_id, &[]);
    write_smb_frame(&mut stream, agent_id, &packet).await?;

    sleep(Duration::from_millis(100)).await;
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("smb-size-mm").await?;
    Ok(())
}

/// Corrupted encrypted init metadata sent via SMB named pipe.
#[cfg(unix)]
#[tokio::test]
async fn smb_rejects_corrupted_encrypted_init() -> Result<(), Box<dyn std::error::Error>> {
    let (pipe_name, registry, manager) =
        setup_smb_listener("smb-corrupt-enc", "corruptenc").await?;
    let agent_id = 0xEE00_4444;

    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, &corrupted_init_packet(agent_id)).await?;

    sleep(Duration::from_millis(100)).await;
    assert!(registry.get(agent_id).await.is_none());

    // Verify listener survives.
    let valid_agent_id = 0xEE00_BBBB;
    let key = test_key(0x51);
    let iv = test_iv(0x34);
    let mut stream2 = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut stream2,
        valid_agent_id,
        &common::valid_demon_init_body(valid_agent_id, key, iv),
    )
    .await?;
    let result = timeout(Duration::from_secs(5), read_smb_frame(&mut stream2)).await;
    assert!(result.is_ok(), "listener must survive corrupted init");
    assert!(registry.get(valid_agent_id).await.is_some());

    manager.stop("smb-corrupt-enc").await?;
    Ok(())
}

/// Garbage payload with valid header sent via SMB named pipe.
#[cfg(unix)]
#[tokio::test]
async fn smb_rejects_garbage_payload() -> Result<(), Box<dyn std::error::Error>> {
    let (pipe_name, registry, manager) = setup_smb_listener("smb-garbage", "garbage").await?;
    let agent_id = 0xEE00_5555;

    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, &garbage_payload_packet(agent_id, 256)).await?;

    sleep(Duration::from_millis(100)).await;
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("smb-garbage").await?;
    Ok(())
}

/// CTR desync via SMB: register agent, then send callback with wrong key.
#[cfg(unix)]
#[tokio::test]
async fn smb_rejects_ctr_desync_callback() -> Result<(), Box<dyn std::error::Error>> {
    let (pipe_name, registry, manager) = setup_smb_listener("smb-ctr-desync", "ctrdesync").await?;
    let agent_id = 0xEE00_6666;
    let key = test_key(0x61);
    let iv = test_iv(0x74);

    // Register via valid init.
    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;
    let _ack = timeout(Duration::from_secs(5), read_smb_frame(&mut stream)).await??;
    assert!(registry.get(agent_id).await.is_some());

    let ctr_before = registry.ctr_offset(agent_id).await?;

    // Send desync callback on a new connection.
    let mut stream2 = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream2, agent_id, &ctr_desync_callback_packet(agent_id)).await?;

    sleep(Duration::from_millis(100)).await;

    // CTR offset must be unchanged.
    let ctr_after = registry.ctr_offset(agent_id).await?;
    assert_eq!(ctr_before, ctr_after, "CTR offset must not advance on failed SMB callback");

    // Agent must still be registered.
    assert!(registry.get(agent_id).await.is_some());

    manager.stop("smb-ctr-desync").await?;
    Ok(())
}

/// Oversized length-prefixed field inside init metadata sent via SMB.
#[cfg(unix)]
#[tokio::test]
async fn smb_rejects_oversized_inner_field() -> Result<(), Box<dyn std::error::Error>> {
    let (pipe_name, registry, manager) =
        setup_smb_listener("smb-oversized-field", "oversized").await?;
    let agent_id = 0xEE00_7777;

    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, &oversized_inner_field_init_packet(agent_id)).await?;

    sleep(Duration::from_millis(100)).await;
    assert!(registry.get(agent_id).await.is_none());

    manager.stop("smb-oversized-field").await?;
    Ok(())
}
