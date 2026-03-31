//! DNS listener integration tests.
//!
//! These tests spin up a real DNS C2 listener through the [`ListenerManager`] API,
//! send mock Demon agent packets as UDP DNS queries, and verify the full flow:
//! agent init → registration → callback → response.  They follow the same pattern
//! as `http_listener_pipeline.rs` and `smb_listener.rs`.

mod common;

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
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

/// Send a full Demon packet to the DNS listener with chunks delivered in the
/// order specified by `send_order`.  Each entry in `send_order` is a chunk
/// index (0-based) into the natural chunk sequence.  Entries may repeat
/// (to simulate retransmission) or appear out of order.
///
/// Returns a `Vec` of `(seq_index, txt_answer)` pairs — one per query sent.
async fn dns_upload_demon_packet_ordered(
    client: &UdpSocket,
    agent_id: u32,
    payload: &[u8],
    domain: &str,
    query_id_base: u16,
    send_order: &[usize],
) -> Result<Vec<(usize, String)>, Box<dyn std::error::Error>> {
    let chunks: Vec<&[u8]> = payload.chunks(39).collect();
    let total = u16::try_from(chunks.len())?;
    let mut results = Vec::new();

    for (i, &idx) in send_order.iter().enumerate() {
        let seq_u16 = u16::try_from(idx)?;
        let qname = dns_upload_qname(agent_id, seq_u16, total, chunks[idx], domain);
        let packet = build_dns_txt_query(query_id_base.wrapping_add(u16::try_from(i)?), &qname);
        client.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
        results.push((idx, txt));
    }

    Ok(results)
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
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
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

    // DEMON_INIT registers agents in legacy CTR mode — every packet starts at block 0.
    let ctr_offset = 0;

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
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
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

/// A second DEMON_INIT via DNS for an already-registered `agent_id` is treated as a
/// re-registration (agent restart after crash or kill-date reset).  The session key is
/// replaced and the DNS listener returns "ack".
///
/// NOTE: the teamserver does not currently verify that the re-init key material matches the
/// original.  Operators who require key-rotation protection should track agent restarts via
/// the `AgentNew` event and alert on unexpected re-registrations from unknown IPs.
#[tokio::test]
async fn dns_listener_pipeline_reinit_updates_key_material()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let agent_id = 0xDEAD_C0DE_u32;
    let original_key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let original_iv: [u8; AGENT_IV_LENGTH] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];
    let new_key: [u8; AGENT_KEY_LENGTH] = [
        0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD,
        0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE,
        0xDD, 0xCC,
    ];
    let new_iv: [u8; AGENT_IV_LENGTH] = [
        0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE,
        0xDD,
    ];

    manager.create(dns_listener("dns-reinit", port, domain)).await?;
    manager.start("dns-reinit").await?;
    let client = wait_for_dns_listener(port).await?;

    // First init — must succeed and register the original key.
    let init_body = common::valid_demon_init_body(agent_id, original_key, original_iv);
    let result = dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0x6000).await?;
    assert_eq!(result, "ack", "first DEMON_INIT must succeed");

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &original_key);

    // Drain first AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // Second init (same agent_id, new key) — treated as re-registration, must succeed.
    let reinit_body = common::valid_demon_init_body(agent_id, new_key, new_iv);
    let reinit_result =
        dns_upload_demon_packet(&client, agent_id, &reinit_body, domain, 0x7000).await?;
    assert_eq!(reinit_result, "ack", "re-registration DEMON_INIT must be accepted");

    // Key must be updated to the new material.
    let stored_after = registry.get(agent_id).await.ok_or("agent should remain registered")?;
    assert_eq!(
        stored_after.encryption.aes_key.as_slice(),
        &new_key,
        "re-init must update the session key to the new material"
    );
    assert_eq!(
        stored_after.encryption.aes_iv.as_slice(),
        &new_iv,
        "re-init must update the session IV to the new material"
    );

    // Still exactly one active entry.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 1, "re-init must not create a second agent entry");

    manager.stop("dns-reinit").await?;
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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

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
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";

    // Agent A parameters.
    let agent_id_a = 0xAAAA_0001_u32;
    let key_a: [u8; AGENT_KEY_LENGTH] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80,
    ];
    let iv_a: [u8; AGENT_IV_LENGTH] = [
        0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
        0x19,
    ];

    // Agent B parameters — distinct key/iv so cross-contamination is detectable.
    let agent_id_b = 0xBBBB_0002_u32;
    let key_b: [u8; AGENT_KEY_LENGTH] = [
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E,
        0x9F, 0xA0,
    ];
    let iv_b: [u8; AGENT_IV_LENGTH] = [
        0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19,
        0x2A,
    ];

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

    // DEMON_INIT registers agents in legacy CTR mode — every packet starts at block 0.
    let ctr_offset_a = 0;
    let ctr_offset_b = 0;

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

// ---------------------------------------------------------------------------
// Registered-agent empty-task-queue tests
// ---------------------------------------------------------------------------

/// A registered agent with no pending tasks must receive "wait" when polling
/// the download endpoint — not garbage data or an error.
#[tokio::test]
async fn dns_listener_pipeline_download_returns_wait_for_registered_agent_with_no_tasks()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE,
        0xEF, 0xF0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00,
    ];
    let agent_id = 0xFEED_0001_u32;

    manager.create(dns_listener("dns-idle-dl", port, domain)).await?;
    manager.start("dns-idle-dl").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register the agent via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xA000).await?;
    assert_eq!(init_result, "ack", "DEMON_INIT upload must be acknowledged");

    // Verify registration.
    assert!(registry.get(agent_id).await.is_some(), "agent must be registered after init");

    // Drain the AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Download the init ACK (consuming the pending response).
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xA100).await?;
    assert!(!ack_payload.is_empty(), "init ACK response must be non-empty");

    // 3. Poll download again — no tasks have been queued, so response must be "wait".
    let qname = dns_download_qname(agent_id, 0, domain);
    let packet = build_dns_txt_query(0xA200, &qname);
    client.send(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    assert_eq!(
        txt, "wait",
        "download for registered agent with no tasks must return 'wait', got '{txt}'"
    );

    manager.stop("dns-idle-dl").await?;
    Ok(())
}

/// After a registered agent consumes its init ACK and then a task is enqueued,
/// the next checkin callback must deliver the task via the download channel.
#[tokio::test]
async fn dns_listener_pipeline_registered_agent_downloads_task_after_enqueue()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
        0xDF, 0xE0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0,
    ];
    let agent_id = 0xFEED_0002_u32;

    manager.create(dns_listener("dns-task-dl", port, domain)).await?;
    manager.start("dns-task-dl").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xB000).await?;
    assert_eq!(init_result, "ack");

    assert!(registry.get(agent_id).await.is_some());

    // Drain AgentNew.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Download and consume the init ACK.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xB100).await?;
    assert!(!ack_payload.is_empty());

    // 3. Verify "wait" before enqueuing any task.
    let qname = dns_download_qname(agent_id, 0, domain);
    let packet = build_dns_txt_query(0xB200, &qname);
    client.send(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    assert_eq!(txt, "wait", "no tasks queued yet — download must return 'wait'");

    // 4. Enqueue a job for the agent.
    use red_cell::Job;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 100,
                payload: vec![0xDE, 0xAD],
                command_line: "test-task".to_owned(),
                task_id: "task-001".to_owned(),
                created_at: String::new(),
                operator: String::new(),
            },
        )
        .await?;

    // 5. Send a COMMAND_GET_JOB callback — this triggers the dispatcher to
    //    dequeue jobs and build an encrypted response for the agent.
    //    Legacy Demon agents reset AES-CTR to block 0 for every packet, so the
    //    callback must be encrypted at offset 0 regardless of prior traffic.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        8,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0xB300).await?;
    assert_eq!(callback_result, "ack", "COMMAND_GET_JOB callback must be acknowledged");

    // 6. Download the task response — must NOT be "wait" since a job was queued.
    let task_payload = dns_download_response(&client, agent_id, domain, 0xB400).await?;
    assert!(
        !task_payload.is_empty(),
        "download after task enqueue must return actual data, not empty/wait"
    );

    manager.stop("dns-task-dl").await?;
    Ok(())
}

/// Happy path: agent registers → operator queues task → agent downloads via DNS
/// → decrypted DemonMessage contains the correct command_id and request_id.
#[tokio::test]
async fn dns_task_delivery_happy_path_decrypts_correctly() -> Result<(), Box<dyn std::error::Error>>
{
    use red_cell::Job;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD1, 0xE4, 0xF7, 0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB,
        0xEE,
    ];
    let agent_id = 0xFEED_1001_u32;

    manager.create(dns_listener("dns-happy", port, domain)).await?;
    manager.start("dns-happy").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xC000).await?;
    assert_eq!(init_result, "ack");
    assert!(registry.get(agent_id).await.is_some());

    // Drain AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Consume the init ACK.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xC100).await?;
    assert!(!ack_payload.is_empty());

    // 3. Enqueue a task for the agent.
    let task_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 0x3A,
                payload: task_payload.clone(),
                command_line: "checkin".to_owned(),
                task_id: "task-happy-1".to_owned(),
                created_at: String::new(),
                operator: String::new(),
            },
        )
        .await?;

    // 4. Agent sends CommandGetJob to trigger task dispatch.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        9,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0xC200).await?;
    assert_eq!(callback_result, "ack");

    // 5. Download the task response.
    let response_bytes = dns_download_response(&client, agent_id, domain, 0xC300).await?;
    assert!(!response_bytes.is_empty(), "task response must not be empty");

    // 6. Parse DemonMessage and verify structure.
    let msg = DemonMessage::from_bytes(&response_bytes)?;
    assert_eq!(msg.packages.len(), 1, "exactly one task package expected");
    assert_eq!(
        msg.packages[0].command_id,
        u32::from(DemonCommand::CommandCheckin),
        "task command must match queued CommandCheckin"
    );
    assert_eq!(msg.packages[0].request_id, 0x3A, "request_id must match queued value");

    // 7. Decrypt the payload and verify it matches the original task data.
    //    Legacy CTR mode: server encrypts at offset 0.
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &msg.packages[0].payload)?;
    assert_eq!(decrypted, task_payload, "decrypted task payload must match original");

    manager.stop("dns-happy").await?;
    Ok(())
}

/// Multi-chunk delivery: queue a task large enough to require more than one DNS
/// TXT chunk and verify reassembly + decryption are correct.
#[tokio::test]
async fn dns_task_delivery_multi_chunk() -> Result<(), Box<dyn std::error::Error>> {
    use red_cell::Job;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80,
    ];
    let agent_id = 0xFEED_2002_u32;

    manager.create(dns_listener("dns-multichunk", port, domain)).await?;
    manager.start("dns-multichunk").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xD000).await?;
    assert_eq!(init_result, "ack");
    assert!(registry.get(agent_id).await.is_some());

    // Drain AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Consume the init ACK.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xD100).await?;
    assert!(!ack_payload.is_empty());

    // 3. Build a large task payload that will require multiple DNS TXT chunks.
    //    DNS TXT records have a ~255 byte limit; base32hex encoding expands data
    //    by 8/5, so a 500-byte payload will definitely span multiple chunks.
    let large_payload: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 0x7B,
                payload: large_payload.clone(),
                command_line: "large-task".to_owned(),
                task_id: "task-multi-1".to_owned(),
                created_at: String::new(),
                operator: String::new(),
            },
        )
        .await?;

    // 4. Agent sends CommandGetJob.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        10,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0xD200).await?;
    assert_eq!(callback_result, "ack");

    // 5. Download the multi-chunk response.
    let response_bytes = dns_download_response(&client, agent_id, domain, 0xD300).await?;
    assert!(!response_bytes.is_empty(), "multi-chunk task response must not be empty");

    // 6. Parse and verify DemonMessage structure.
    let msg = DemonMessage::from_bytes(&response_bytes)?;
    assert_eq!(msg.packages.len(), 1);
    assert_eq!(msg.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(msg.packages[0].request_id, 0x7B);

    // 7. Decrypt and verify the payload matches byte-for-byte.
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &msg.packages[0].payload)?;
    assert_eq!(
        decrypted,
        large_payload,
        "multi-chunk decrypted payload must match original ({} bytes)",
        large_payload.len()
    );

    manager.stop("dns-multichunk").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Out-of-order and duplicate chunk upload tests
// ---------------------------------------------------------------------------

/// Uploading a multi-chunk DEMON_INIT with chunks arriving out of order must
/// reassemble the original packet correctly and register the agent.
#[tokio::test]
async fn dns_listener_out_of_order_upload_reassembles_correctly()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x01,
    ];
    let agent_id = 0x000D_0001_u32;

    manager.create(dns_listener("dns-ooo-upload", port, domain)).await?;
    manager.start("dns-ooo-upload").await?;
    let client = wait_for_dns_listener(port).await?;

    // Build the DEMON_INIT payload and determine natural chunk count.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let num_chunks = init_body.chunks(39).count();
    assert!(
        num_chunks >= 3,
        "test requires at least 3 chunks to exercise out-of-order delivery, got {num_chunks}"
    );

    // Reverse the chunk order: last chunk first, first chunk last.
    let reversed_order: Vec<usize> = (0..num_chunks).rev().collect();

    let results = dns_upload_demon_packet_ordered(
        &client,
        agent_id,
        &init_body,
        domain,
        0xE000,
        &reversed_order,
    )
    .await?;

    // Intermediate chunks must return "ok"; the final chunk that completes
    // the set must return "ack".
    let last_txt = &results.last().expect("must have at least one result").1;
    assert_eq!(
        last_txt, "ack",
        "last chunk completing the out-of-order upload must return 'ack', got '{last_txt}'"
    );

    // The agent must be fully registered with the correct key.
    let stored = registry
        .get(agent_id)
        .await
        .ok_or("agent should be registered after out-of-order DEMON_INIT upload")?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &iv);
    assert_eq!(stored.hostname, "wkstn-01");

    // AgentNew event must have fired.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(
        matches!(event, Some(OperatorMessage::AgentNew(_))),
        "expected AgentNew after out-of-order init, got {event:?}"
    );

    // Download the init ACK and verify decryption to confirm no data corruption.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xE100).await?;
    let decrypted = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK after out-of-order upload must decrypt to the correct agent_id"
    );

    manager.stop("dns-ooo-upload").await?;
    Ok(())
}

/// Retransmitting an already-received chunk during a multi-chunk upload must
/// not corrupt reassembly or create duplicate agent state.
#[tokio::test]
async fn dns_listener_duplicate_chunk_retransmission_is_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
        0xBE, 0xBF,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF,
    ];
    let agent_id = 0xDDDD_0002_u32;

    manager.create(dns_listener("dns-dup-chunk", port, domain)).await?;
    manager.start("dns-dup-chunk").await?;
    let client = wait_for_dns_listener(port).await?;

    // Build the DEMON_INIT payload.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let num_chunks = init_body.chunks(39).count();
    assert!(
        num_chunks >= 3,
        "test requires at least 3 chunks to exercise duplicate retransmission, got {num_chunks}"
    );

    // Send chunks in order but retransmit chunk 0 and chunk 1 after their
    // initial delivery: [0, 1, 0, 1, 2, 3, ..., N-1].
    let mut send_order: Vec<usize> = Vec::new();
    send_order.push(0);
    send_order.push(1);
    send_order.push(0); // retransmit chunk 0
    send_order.push(1); // retransmit chunk 1
    for i in 2..num_chunks {
        send_order.push(i);
    }

    let results =
        dns_upload_demon_packet_ordered(&client, agent_id, &init_body, domain, 0xF000, &send_order)
            .await?;

    // The final response must be "ack" — the duplicate chunks must not have
    // confused the reassembly logic.
    let last_txt = &results.last().expect("must have at least one result").1;
    assert_eq!(
        last_txt, "ack",
        "final chunk after duplicate retransmission must return 'ack', got '{last_txt}'"
    );

    // Agent must be registered with correct key material.
    let stored = registry
        .get(agent_id)
        .await
        .ok_or("agent should be registered after upload with duplicate chunks")?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &iv);
    assert_eq!(stored.hostname, "wkstn-01");

    // Exactly one agent should exist — no duplicates from retransmission.
    let active = registry.list_active().await;
    assert_eq!(
        active.len(),
        1,
        "duplicate chunk retransmission must not create extra agent entries"
    );

    // AgentNew must have fired exactly once.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(
        matches!(event, Some(OperatorMessage::AgentNew(_))),
        "expected AgentNew after upload with duplicates, got {event:?}"
    );

    // Download init ACK and verify correctness.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xF100).await?;
    let decrypted = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK after duplicate-chunk upload must decrypt to the correct agent_id"
    );

    // A subsequent in-order upload for a *different* agent must succeed,
    // proving the retransmission did not poison shared state.
    let agent_id_2 = 0xDDDD_0003_u32;
    let key_2: [u8; AGENT_KEY_LENGTH] = [
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30,
    ];
    let iv_2: [u8; AGENT_IV_LENGTH] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40,
    ];
    let init_body_2 = common::valid_demon_init_body(agent_id_2, key_2, iv_2);
    let result_2 =
        dns_upload_demon_packet(&client, agent_id_2, &init_body_2, domain, 0xF200).await?;
    assert_eq!(
        result_2, "ack",
        "subsequent normal upload after duplicate-chunk session must succeed"
    );
    assert!(
        registry.get(agent_id_2).await.is_some(),
        "second agent must be registered, proving no state poisoning"
    );

    manager.stop("dns-dup-chunk").await?;
    Ok(())
}
