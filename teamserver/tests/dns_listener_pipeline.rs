//! DNS listener integration tests.
//!
//! These tests spin up a real DNS C2 listener through the [`ListenerManager`] API,
//! send mock Demon agent packets as UDP DNS queries, and verify the full flow:
//! agent init → registration → callback → response.  They follow the same pattern
//! as `http_listener_pipeline.rs` and `smb_listener.rs`.

mod common;

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use red_cell_common::{DnsListenerConfig, ListenerConfig};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Base32hex alphabet (RFC 4648 §7).
const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encode `data` using base32hex (unpadded, uppercase).
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

/// Build a DNS upload qname for the C2 protocol.
fn dns_upload_qname(agent_id: u32, seq: u16, total: u16, chunk: &[u8], domain: &str) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Build a DNS download qname for the C2 protocol.
fn dns_download_qname(agent_id: u32, seq: u16, domain: &str) -> String {
    format!("{seq:x}-{agent_id:08x}.dn.{domain}")
}

/// Build a minimal DNS query packet for `qname` with the given `qtype`.
fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100_u16.to_be_bytes()); // flags: QR=0, RD=1
    buf.extend_from_slice(&1_u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // arcount
    for label in qname.split('.') {
        buf.push(u8::try_from(label.len()).expect("label too long"));
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // zero terminator
    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN
    buf
}

/// Build a DNS TXT query.
fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, 16) // DNS_TYPE_TXT = 16
}

/// DNS wire-format header length.
const DNS_HEADER_LEN: usize = 12;

/// Parse the TXT answer from a DNS response packet.
fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    // Skip the question section.
    let mut pos = DNS_HEADER_LEN;
    while pos < packet.len() {
        let len = usize::from(packet[pos]);
        pos += 1;
        if len == 0 {
            break;
        }
        pos = pos.checked_add(len)?;
    }
    // Skip QTYPE(2) + QCLASS(2).
    pos = pos.checked_add(4)?;
    // Answer: skip NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
    pos = pos.checked_add(2 + 2 + 2 + 4 + 2)?;
    let txt_len = usize::from(*packet.get(pos)?);
    let start = pos.checked_add(1)?;
    let end = start.checked_add(txt_len)?;
    std::str::from_utf8(packet.get(start..end)?).ok().map(str::to_owned)
}

/// Find a free UDP port on 127.0.0.1.
fn free_udp_port() -> u16 {
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

/// Build a DNS listener config.
fn dns_listener(name: &str, port: u16, domain: &str) -> ListenerConfig {
    ListenerConfig::from(DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    })
}

/// Send a full Demon packet to the DNS listener by chunking it into upload queries.
///
/// Returns the TXT answer from the final chunk's response (e.g. "ack", "err").
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

/// Poll DNS download queries until all chunks are received and return the
/// reassembled base32hex-decoded response payload.
async fn dns_download_response(
    client: &UdpSocket,
    agent_id: u32,
    domain: &str,
    query_id_base: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut chunks: Vec<String> = Vec::new();
    let mut expected_total: Option<usize> = None;
    let mut seq: u16 = 0;

    loop {
        let qname = dns_download_qname(agent_id, seq, domain);
        let packet = build_dns_txt_query(query_id_base.wrapping_add(seq), &qname);
        client.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse download TXT answer")?;

        if txt == "wait" {
            // No response queued yet — retry after a short delay.
            sleep(Duration::from_millis(50)).await;
            continue;
        }
        if txt == "done" {
            break;
        }

        // Format: "<TOTAL> <B32HEX>"
        let (total_str, b32_chunk) =
            txt.split_once(' ').ok_or_else(|| format!("unexpected download response: {txt}"))?;
        let total: usize = total_str.parse()?;
        if let Some(et) = expected_total {
            assert_eq!(et, total, "inconsistent total across download chunks");
        } else {
            expected_total = Some(total);
        }
        chunks.push(b32_chunk.to_owned());
        seq += 1;

        if chunks.len() >= total {
            // Request one more to trigger "done" and cleanup.
            let done_qname = dns_download_qname(agent_id, seq, domain);
            let done_packet = build_dns_txt_query(query_id_base.wrapping_add(seq), &done_qname);
            client.send(&done_packet).await?;
            let mut done_buf = vec![0u8; 4096];
            let done_len = timeout(Duration::from_secs(5), client.recv(&mut done_buf)).await??;
            done_buf.truncate(done_len);
            let done_txt = parse_dns_txt_answer(&done_buf);
            assert_eq!(done_txt.as_deref(), Some("done"), "expected 'done' after last chunk");
            break;
        }
    }

    // Reassemble: decode each base32hex chunk and concatenate.
    let mut assembled = Vec::new();
    for chunk in &chunks {
        assembled.extend_from_slice(&base32hex_decode(chunk)?);
    }
    Ok(assembled)
}

/// Decode base32hex (unpadded, case-insensitive) into bytes.
fn base32hex_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result = Vec::with_capacity(input.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for ch in input.chars() {
        let val = match ch {
            '0'..='9' => (ch as u8) - b'0',
            'A'..='V' => (ch as u8) - b'A' + 10,
            'a'..='v' => (ch as u8) - b'a' + 10,
            '=' => continue, // padding
            _ => return Err(format!("invalid base32hex character: {ch}").into()),
        };
        buf = (buf << 5) | u32::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }
    Ok(result)
}

/// Wait for the DNS listener to start responding.
async fn wait_for_dns_listener(port: u16) -> Result<UdpSocket, Box<dyn std::error::Error>> {
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{port}")).await?;

    // Send a dummy query and wait for any response.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full DNS C2 pipeline: agent init → registration → download ACK → callback → event.
#[tokio::test]
async fn dns_listener_pipeline_registers_agent_and_broadcasts_checkin()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let agent_id = 0x1234_5678_u32;

    manager.create(dns_listener("dns-pipeline", port, domain)).await?;
    manager.start("dns-pipeline").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Upload a DEMON_INIT packet via chunked DNS queries.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0x1000).await?;
    assert_eq!(init_result, "ack", "DEMON_INIT upload must be acknowledged");

    // 2. Verify the agent is registered in the registry.
    let stored = registry.get(agent_id).await.ok_or("agent should be registered after DNS init")?;
    assert_eq!(stored.hostname, "wkstn-01");

    // 3. Verify AgentNew event was broadcast.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected AgentNew event, got {event:?}");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "dns-pipeline");

    // 4. Download the init ACK response (encrypted agent_id).
    let ack_payload = dns_download_response(&client, agent_id, domain, 0x2000).await?;
    // The init ACK is AES-encrypted. Verify it's non-empty (the actual decryption
    // is tested in http_listener_pipeline; here we verify the DNS transport delivers it).
    assert!(!ack_payload.is_empty(), "init ACK response must be non-empty");

    // Decrypt and verify the ACK contains the agent_id.
    let decrypted = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK must contain agent_id as LE bytes"
    );

    // Track the CTR offset after the ACK for subsequent callbacks.
    let ctr_offset = red_cell_common::crypto::ctr_blocks_for_len(ack_payload.len());

    // 5. Send a COMMAND_CHECKIN callback via DNS upload.
    let before_checkin = stored.last_call_in.clone();
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        ctr_offset,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0x3000).await?;
    assert_eq!(callback_result, "ack", "COMMAND_CHECKIN callback must be acknowledged");

    // 6. Verify AgentUpdate event was broadcast.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentUpdate(message)) = event else {
        panic!("expected AgentUpdate event, got {event:?}");
    };
    assert_eq!(message.info.agent_id, "12345678");
    assert_eq!(message.info.marked, "Alive");

    // 7. Verify last_call_in advanced.
    let updated =
        registry.get(agent_id).await.ok_or("agent should remain registered after checkin")?;
    assert_ne!(updated.last_call_in, before_checkin, "last_call_in must advance after checkin");

    manager.stop("dns-pipeline").await?;
    Ok(())
}

/// A DNS upload for an unregistered agent's callback must be rejected.
#[tokio::test]
async fn dns_listener_pipeline_rejects_callbacks_from_unregistered_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None);

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let agent_id = 0xCAFE_BABE_u32;

    manager.create(dns_listener("dns-unknown-cb", port, domain)).await?;
    manager.start("dns-unknown-cb").await?;
    let client = wait_for_dns_listener(port).await?;

    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    let result = dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0x5000).await?;

    // The DNS transport processes the upload and may return "ack" even for unknown
    // callbacks (unlike HTTP which returns 404).  The important invariant is that no
    // agent state is created in the registry.
    assert!(
        result == "ack" || result == "err",
        "callback from unregistered agent must return 'ack' or 'err', got '{result}'"
    );
    assert!(
        registry.get(agent_id).await.is_none(),
        "unregistered callback must not create agent state"
    );

    manager.stop("dns-unknown-cb").await?;
    Ok(())
}

/// A duplicate DEMON_INIT via DNS must not overwrite the original AES key.
#[tokio::test]
async fn dns_listener_pipeline_rejects_duplicate_init_preserves_original_key()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let agent_id = 0xDEAD_C0DE_u32;
    let original_key = [0x41_u8; AGENT_KEY_LENGTH];
    let original_iv = [0x24_u8; AGENT_IV_LENGTH];
    let hijack_key = [0xBB_u8; AGENT_KEY_LENGTH];
    let hijack_iv = [0xCC_u8; AGENT_IV_LENGTH];

    manager.create(dns_listener("dns-dup-init", port, domain)).await?;
    manager.start("dns-dup-init").await?;
    let client = wait_for_dns_listener(port).await?;

    // First init — must succeed.
    let init_body = common::valid_demon_init_body(agent_id, original_key, original_iv);
    let result = dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0x6000).await?;
    assert_eq!(result, "ack", "first DEMON_INIT must succeed");

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &original_key);

    // Drain AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // Second init with hijack key — must be rejected.
    let hijack_body = common::valid_demon_init_body(agent_id, hijack_key, hijack_iv);
    let hijack_result =
        dns_upload_demon_packet(&client, agent_id, &hijack_body, domain, 0x7000).await?;
    assert_eq!(hijack_result, "err", "duplicate DEMON_INIT must be rejected");

    // Original key must still be intact.
    let stored_after = registry.get(agent_id).await.ok_or("agent should remain registered")?;
    assert_eq!(
        stored_after.encryption.aes_key.as_slice(),
        &original_key,
        "original AES key must not be overwritten by duplicate init"
    );
    assert_eq!(
        stored_after.encryption.aes_iv.as_slice(),
        &original_iv,
        "original AES IV must not be overwritten by duplicate init"
    );

    // Only one agent in the registry.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 1, "duplicate init must not create a second agent entry");

    manager.stop("dns-dup-init").await?;
    Ok(())
}

/// Download queries for an unregistered agent must return "wait".
#[tokio::test]
async fn dns_listener_pipeline_download_returns_wait_for_unknown_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);

    let port = free_udp_port();
    let domain = "c2.example.com";
    let agent_id = 0xAAAA_BBBB_u32;

    manager.create(dns_listener("dns-dl-unknown", port, domain)).await?;
    manager.start("dns-dl-unknown").await?;
    let client = wait_for_dns_listener(port).await?;

    // Download for an unregistered agent.
    let qname = dns_download_qname(agent_id, 0, domain);
    let packet = build_dns_txt_query(0x9000, &qname);
    client.send(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    assert_eq!(txt, "wait", "download for unknown agent must return 'wait'");

    manager.stop("dns-dl-unknown").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Malformed / truncated query rejection tests
// ---------------------------------------------------------------------------

/// Helper: set up a DNS listener and return (manager, registry, client, domain).
async fn setup_dns_test(
    name: &str,
) -> Result<
    (ListenerManager, AgentRegistry, UdpSocket, u16, &'static str),
    Box<dyn std::error::Error>,
> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);

    let port = free_udp_port();
    let domain = "c2.example.com";
    manager.create(dns_listener(name, port, domain)).await?;
    manager.start(name).await?;
    let client = wait_for_dns_listener(port).await?;

    Ok((manager, registry, client, port, domain))
}

/// Send a valid DNS probe and assert the listener responds (is still alive).
async fn assert_listener_alive(client: &UdpSocket, domain: &str) {
    let probe = build_dns_txt_query(0xFFFE, &format!("probe.other.{domain}"));
    client.send(&probe).await.expect("probe send failed");
    let mut buf = vec![0u8; 512];
    let result = timeout(Duration::from_secs(5), client.recv(&mut buf)).await;
    assert!(result.is_ok(), "listener must still respond after receiving malformed packet");
}

/// Truncated DNS packets (< 12 byte header) must not crash the listener.
#[tokio::test]
async fn dns_listener_survives_truncated_packet() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, registry, client, _port, domain) = setup_dns_test("dns-truncated").await?;

    // Send various truncated packets: 0, 1, 5, 11 bytes — all under the 12-byte header.
    for &size in &[0usize, 1, 5, 11] {
        let truncated = vec![0u8; size];
        client.send(&truncated).await?;

        // The listener silently drops packets it cannot parse.  Give it a moment,
        // then confirm it is still alive with a valid probe.
        sleep(Duration::from_millis(50)).await;
        assert_listener_alive(&client, domain).await;
    }

    // No agent state should have been created.
    assert!(
        registry.list_active().await.is_empty(),
        "truncated packets must not create agent state"
    );

    manager.stop("dns-truncated").await?;
    Ok(())
}

/// A DNS packet with qdcount = 0 (no question section) must be silently dropped.
#[tokio::test]
async fn dns_listener_survives_zero_qdcount() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, registry, client, _port, domain) = setup_dns_test("dns-zero-qd").await?;

    // Build a valid-looking DNS header with qdcount = 0.
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x1234_u16.to_be_bytes()); // id
    packet.extend_from_slice(&0x0100_u16.to_be_bytes()); // flags: QR=0, RD=1
    packet.extend_from_slice(&0_u16.to_be_bytes()); // qdcount = 0
    packet.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    packet.extend_from_slice(&0_u16.to_be_bytes()); // arcount

    client.send(&packet).await?;
    sleep(Duration::from_millis(50)).await;
    assert_listener_alive(&client, domain).await;

    assert!(
        registry.list_active().await.is_empty(),
        "zero-qdcount packet must not create agent state"
    );

    manager.stop("dns-zero-qd").await?;
    Ok(())
}

/// A DNS query with a label exceeding 63 bytes (RFC 1035 limit) must not crash
/// the listener.
#[tokio::test]
async fn dns_listener_survives_oversized_label() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, registry, client, _port, domain) = setup_dns_test("dns-big-label").await?;

    // Manually build a DNS packet with a 70-byte label (exceeds the 63-byte RFC limit).
    let mut packet = Vec::new();
    packet.extend_from_slice(&0xAAAA_u16.to_be_bytes()); // id
    packet.extend_from_slice(&0x0100_u16.to_be_bytes()); // flags
    packet.extend_from_slice(&1_u16.to_be_bytes()); // qdcount = 1
    packet.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    packet.extend_from_slice(&0_u16.to_be_bytes()); // arcount

    // Oversized label: length byte = 70, followed by 70 'A' bytes.
    packet.push(70);
    packet.extend_from_slice(&[b'A'; 70]);
    // Terminate qname.
    packet.push(0);
    // QTYPE = TXT, QCLASS = IN.
    packet.extend_from_slice(&16_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());

    client.send(&packet).await?;
    sleep(Duration::from_millis(50)).await;
    assert_listener_alive(&client, domain).await;

    assert!(
        registry.list_active().await.is_empty(),
        "oversized-label packet must not create agent state"
    );

    manager.stop("dns-big-label").await?;
    Ok(())
}

/// An upload query with invalid base32hex characters in the data label must be
/// rejected without crashing.
#[tokio::test]
async fn dns_listener_survives_invalid_base32hex_upload() -> Result<(), Box<dyn std::error::Error>>
{
    let (manager, registry, client, _port, domain) = setup_dns_test("dns-bad-b32").await?;

    let agent_id = 0xBAAD_F00D_u32;

    // Build an upload qname with invalid base32hex chars ('Z', '!', '~' are not
    // in the base32hex alphabet 0-9 A-V).
    let bad_b32 = "ZZ!!~~XX";
    let qname = format!("{bad_b32}.0-1-{agent_id:08x}.up.{domain}");
    let packet = build_dns_txt_query(0xBBBB, &qname);
    client.send(&packet).await?;

    // The server should respond (REFUSED or similar) without crashing.
    let mut buf = vec![0u8; 4096];
    let recv_result = timeout(Duration::from_secs(5), client.recv(&mut buf)).await;
    assert!(recv_result.is_ok(), "listener must respond to invalid base32hex upload (not crash)");

    // Confirm still alive.
    assert_listener_alive(&client, domain).await;

    assert!(
        registry.list_active().await.is_empty(),
        "invalid base32hex upload must not create agent state"
    );

    manager.stop("dns-bad-b32").await?;
    Ok(())
}

/// An upload with seq > total (out-of-bounds chunk index) must be rejected.
#[tokio::test]
async fn dns_listener_survives_seq_exceeding_total() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, registry, client, _port, domain) = setup_dns_test("dns-seq-oob").await?;

    let agent_id = 0xDEAD_0001_u32;

    // seq=5, total=2 — seq >= total is out of bounds.
    let chunk_data = base32hex_encode(&[0x41, 0x42, 0x43]);
    let qname = format!("{chunk_data}.5-2-{agent_id:08x}.up.{domain}");
    let packet = build_dns_txt_query(0xCCCC, &qname);
    client.send(&packet).await?;

    // The server should respond with "err" (rejected by try_assemble_upload).
    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    assert_eq!(txt, "err", "upload with seq > total must be rejected");

    // Confirm still alive.
    assert_listener_alive(&client, domain).await;

    assert!(
        registry.list_active().await.is_empty(),
        "out-of-bounds seq upload must not create agent state"
    );

    manager.stop("dns-seq-oob").await?;
    Ok(())
}

/// Send all malformation types in sequence to a single listener to verify
/// cumulative resilience — the listener must survive the entire barrage.
#[tokio::test]
async fn dns_listener_survives_malformation_barrage() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, registry, client, _port, domain) = setup_dns_test("dns-barrage").await?;

    // 1. Truncated packet (3 bytes).
    client.send(&[0xDE, 0xAD, 0x00]).await?;
    sleep(Duration::from_millis(20)).await;

    // 2. Zero qdcount.
    let mut zero_qd = Vec::new();
    zero_qd.extend_from_slice(&0x1111_u16.to_be_bytes());
    zero_qd.extend_from_slice(&0x0100_u16.to_be_bytes());
    zero_qd.extend_from_slice(&0_u16.to_be_bytes()); // qdcount = 0
    zero_qd.extend_from_slice(&0_u16.to_be_bytes());
    zero_qd.extend_from_slice(&0_u16.to_be_bytes());
    zero_qd.extend_from_slice(&0_u16.to_be_bytes());
    client.send(&zero_qd).await?;
    sleep(Duration::from_millis(20)).await;

    // 3. Oversized label (100 bytes).
    let mut big_label = Vec::new();
    big_label.extend_from_slice(&0x2222_u16.to_be_bytes());
    big_label.extend_from_slice(&0x0100_u16.to_be_bytes());
    big_label.extend_from_slice(&1_u16.to_be_bytes());
    big_label.extend_from_slice(&0_u16.to_be_bytes());
    big_label.extend_from_slice(&0_u16.to_be_bytes());
    big_label.extend_from_slice(&0_u16.to_be_bytes());
    big_label.push(100);
    big_label.extend_from_slice(&[b'X'; 100]);
    big_label.push(0);
    big_label.extend_from_slice(&16_u16.to_be_bytes());
    big_label.extend_from_slice(&1_u16.to_be_bytes());
    client.send(&big_label).await?;
    sleep(Duration::from_millis(20)).await;

    // 4. Invalid base32hex in upload.
    let bad_qname = format!("!!!ZZZ.0-1-deadbeef.up.{domain}");
    let bad_b32_packet = build_dns_txt_query(0x3333, &bad_qname);
    client.send(&bad_b32_packet).await?;
    // Drain the response (REFUSED expected for invalid b32).
    let mut buf = vec![0u8; 4096];
    let _ = timeout(Duration::from_secs(2), client.recv(&mut buf)).await;

    // 5. seq > total upload.
    let chunk = base32hex_encode(&[0xFF]);
    let oob_qname = format!("{chunk}.a-2-cafebabe.up.{domain}");
    let oob_packet = build_dns_txt_query(0x4444, &oob_qname);
    client.send(&oob_packet).await?;
    let mut buf2 = vec![0u8; 4096];
    let _ = timeout(Duration::from_secs(2), client.recv(&mut buf2)).await;

    // Final liveness check.
    assert_listener_alive(&client, domain).await;

    assert!(
        registry.list_active().await.is_empty(),
        "no agent state should be created from malformed packets"
    );

    manager.stop("dns-barrage").await?;
    Ok(())
}

/// Two agents communicating concurrently through the same DNS listener must not
/// have their upload chunk buffers or download response queues mixed up.
#[tokio::test]
async fn dns_listener_concurrent_multi_agent_sessions_are_isolated()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";

    // Agent A parameters.
    let agent_id_a = 0xAAAA_0001_u32;
    let key_a = [0x11; AGENT_KEY_LENGTH];
    let iv_a = [0x22; AGENT_IV_LENGTH];

    // Agent B parameters — distinct key/iv so cross-contamination is detectable.
    let agent_id_b = 0xBBBB_0002_u32;
    let key_b = [0x33; AGENT_KEY_LENGTH];
    let iv_b = [0x44; AGENT_IV_LENGTH];

    manager.create(dns_listener("dns-concurrent", port, domain)).await?;
    manager.start("dns-concurrent").await?;

    // Each agent needs its own UDP socket so their packets interleave naturally.
    let client_a = {
        let s = UdpSocket::bind("127.0.0.1:0").await?;
        s.connect(format!("127.0.0.1:{port}")).await?;
        s
    };
    let client_b = {
        let s = UdpSocket::bind("127.0.0.1:0").await?;
        s.connect(format!("127.0.0.1:{port}")).await?;
        s
    };

    // Wait for the listener to be ready using a throwaway probe.
    let _probe_client = wait_for_dns_listener(port).await?;

    // 1. Upload DEMON_INIT for both agents concurrently.
    let init_body_a = common::valid_demon_init_body(agent_id_a, key_a, iv_a);
    let init_body_b = common::valid_demon_init_body(agent_id_b, key_b, iv_b);

    let (init_result_a, init_result_b) = tokio::join!(
        dns_upload_demon_packet(&client_a, agent_id_a, &init_body_a, domain, 0x1000),
        dns_upload_demon_packet(&client_b, agent_id_b, &init_body_b, domain, 0x2000),
    );

    assert_eq!(init_result_a?, "ack", "agent A DEMON_INIT must be acknowledged");
    assert_eq!(init_result_b?, "ack", "agent B DEMON_INIT must be acknowledged");

    // 2. Verify both agents are registered with correct, distinct keys.
    let stored_a =
        registry.get(agent_id_a).await.ok_or("agent A should be registered after init")?;
    let stored_b =
        registry.get(agent_id_b).await.ok_or("agent B should be registered after init")?;

    assert_eq!(
        stored_a.encryption.aes_key.as_slice(),
        &key_a,
        "agent A must have its own AES key (no cross-contamination)"
    );
    assert_eq!(stored_a.encryption.aes_iv.as_slice(), &iv_a, "agent A must have its own AES IV");
    assert_eq!(
        stored_b.encryption.aes_key.as_slice(),
        &key_b,
        "agent B must have its own AES key (no cross-contamination)"
    );
    assert_eq!(stored_b.encryption.aes_iv.as_slice(), &iv_b, "agent B must have its own AES IV");

    // 3. Drain the two AgentNew events (order is non-deterministic).
    let mut new_agent_ids = Vec::new();
    for _ in 0..2 {
        let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
        let Some(OperatorMessage::AgentNew(msg)) = event else {
            panic!("expected AgentNew event, got {event:?}");
        };
        new_agent_ids.push(msg.info.name_id.clone());
    }
    new_agent_ids.sort();
    let mut expected_ids = vec![format!("{agent_id_a:08X}"), format!("{agent_id_b:08X}")];
    expected_ids.sort();
    assert_eq!(new_agent_ids, expected_ids, "both AgentNew events must fire");

    // 4. Download init ACK for each agent and verify decryption with the correct key.
    let (ack_a, ack_b) = tokio::join!(
        dns_download_response(&client_a, agent_id_a, domain, 0x3000),
        dns_download_response(&client_b, agent_id_b, domain, 0x4000),
    );

    let ack_payload_a = ack_a?;
    let ack_payload_b = ack_b?;

    let decrypted_a = red_cell_common::crypto::decrypt_agent_data(&key_a, &iv_a, &ack_payload_a)?;
    assert_eq!(
        decrypted_a.as_slice(),
        &agent_id_a.to_le_bytes(),
        "agent A's init ACK must contain agent A's id"
    );

    let decrypted_b = red_cell_common::crypto::decrypt_agent_data(&key_b, &iv_b, &ack_payload_b)?;
    assert_eq!(
        decrypted_b.as_slice(),
        &agent_id_b.to_le_bytes(),
        "agent B's init ACK must contain agent B's id"
    );

    // Cross-check: decrypting A's ACK with B's key must NOT produce A's agent_id.
    let cross_decrypt = red_cell_common::crypto::decrypt_agent_data(&key_b, &iv_b, &ack_payload_a);
    if let Ok(cross) = cross_decrypt {
        assert_ne!(
            cross.as_slice(),
            &agent_id_a.to_le_bytes(),
            "decrypting agent A's ACK with agent B's key must not produce a valid agent_id"
        );
    }

    let ctr_offset_a = red_cell_common::crypto::ctr_blocks_for_len(ack_payload_a.len());
    let ctr_offset_b = red_cell_common::crypto::ctr_blocks_for_len(ack_payload_b.len());

    // 5. Send COMMAND_CHECKIN callbacks from both agents concurrently.
    let callback_body_a = common::valid_demon_callback_body(
        agent_id_a,
        key_a,
        iv_a,
        ctr_offset_a,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    let callback_body_b = common::valid_demon_callback_body(
        agent_id_b,
        key_b,
        iv_b,
        ctr_offset_b,
        u32::from(DemonCommand::CommandCheckin),
        7,
        &[],
    );

    let (cb_result_a, cb_result_b) = tokio::join!(
        dns_upload_demon_packet(&client_a, agent_id_a, &callback_body_a, domain, 0x5000),
        dns_upload_demon_packet(&client_b, agent_id_b, &callback_body_b, domain, 0x6000),
    );

    assert_eq!(cb_result_a?, "ack", "agent A COMMAND_CHECKIN must be acknowledged");
    assert_eq!(cb_result_b?, "ack", "agent B COMMAND_CHECKIN must be acknowledged");

    // 6. Drain the two AgentUpdate events and verify both agents are marked Alive.
    let mut update_agent_ids = Vec::new();
    for _ in 0..2 {
        let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
        let Some(OperatorMessage::AgentUpdate(msg)) = event else {
            panic!("expected AgentUpdate event, got {event:?}");
        };
        assert_eq!(msg.info.marked, "Alive", "checkin must mark agent as Alive");
        update_agent_ids.push(msg.info.agent_id.clone());
    }
    update_agent_ids.sort();
    assert_eq!(update_agent_ids, expected_ids, "both agents must receive AgentUpdate events");

    // 7. Verify both agents still exist in the registry with correct metadata.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 2, "registry must contain exactly two agents");

    manager.stop("dns-concurrent").await?;
    Ok(())
}
