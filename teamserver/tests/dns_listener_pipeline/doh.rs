//! Specter/Archon DoH grammar tests (RFC 4648 base32 uplink, NXDOMAIN ack, TXT downlink).

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use tokio::time::{sleep, timeout};

use super::common;
use super::helpers::{
    DOH_CHUNK_BYTES, build_dns_txt_query, dns_listener, dns_rcode, doh_chunk_qname, doh_decode_b32,
    doh_encode_b32, doh_ready_qname, doh_upload_qname, free_udp_port, parse_dns_txt_answer,
    wait_for_dns_listener,
};

/// DoH uplink chunks must be acknowledged with NXDOMAIN (rcode 3) while the upload is
/// still in progress (pending reassembly — no Demon packet is processed yet).
#[tokio::test]
async fn dns_listener_doh_uplink_returns_nxdomain() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let port = free_udp_port();
    let domain = "c2.example.com";
    let session = "0123456789abcdef";

    manager.create(dns_listener("dns-doh-nx", port, domain)).await?;
    manager.start("dns-doh-nx").await?;
    let client = wait_for_dns_listener(port).await?;

    // Two chunks required — send only the first so the server stays in Pending (NXDOMAIN)
    // and never runs Demon validation (which would REFUSED on garbage).
    let payload = [0x42u8; DOH_CHUNK_BYTES * 2];
    let chunks: Vec<&[u8]> = payload.chunks(DOH_CHUNK_BYTES).collect();
    let total = u16::try_from(chunks.len())?;

    let chunk = chunks.first().expect("two chunks");
    let qname = doh_upload_qname(&doh_encode_b32(chunk), 0, total, session, domain);
    let packet = build_dns_txt_query(0x7000, &qname);
    client.send(&packet).await?;
    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    assert_eq!(dns_rcode(&buf), Some(3), "DoH uplink chunk must be acknowledged with NXDOMAIN");

    manager.stop("dns-doh-nx").await?;
    Ok(())
}

/// Full pipeline: DoH uplink DEMON_INIT → ready TXT (hex total) → chunk TXT (base32) → decrypt ACK.
#[tokio::test]
async fn dns_listener_doh_grammar_registers_and_delivers_init_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let port = free_udp_port();
    let domain = "c2.example.com";
    let session = "fedcba9876543210";
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

    manager.create(dns_listener("dns-doh-full", port, domain)).await?;
    manager.start("dns-doh-full").await?;
    let client = wait_for_dns_listener(port).await?;

    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let raw_chunks: Vec<&[u8]> = init_body.chunks(DOH_CHUNK_BYTES).collect();
    let total = u16::try_from(raw_chunks.len())?;

    for (seq, chunk) in raw_chunks.iter().enumerate() {
        let seq_u16 = u16::try_from(seq)?;
        let qname = doh_upload_qname(&doh_encode_b32(chunk), seq_u16, total, session, domain);
        let packet = build_dns_txt_query(0x8000 + seq_u16, &qname);
        client.send(&packet).await?;
        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        assert_eq!(dns_rcode(&buf), Some(3), "DoH uplink must use NXDOMAIN");
    }

    assert!(registry.get(agent_id).await.is_some(), "DEMON_INIT via DoH must register the agent");

    // Ready poll: NXDOMAIN until processed, then TXT with lowercase hex total.
    let mut total_chunks: Option<usize> = None;
    for _ in 0..200 {
        let qname = doh_ready_qname(session, domain);
        let packet = build_dns_txt_query(0x9000, &qname);
        client.send(&packet).await?;
        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(2), client.recv(&mut buf)).await??;
        buf.truncate(len);
        if dns_rcode(&buf) == Some(3) {
            sleep(Duration::from_millis(20)).await;
            continue;
        }
        let txt = parse_dns_txt_answer(&buf).ok_or("ready: expected TXT")?;
        total_chunks = Some(usize::from_str_radix(txt.trim(), 16)?);
        break;
    }
    let chunk_count = total_chunks.ok_or("timed out waiting for DoH ready TXT")?;

    let mut assembled = Vec::new();
    for seq in 0..chunk_count {
        let qname = doh_chunk_qname(u16::try_from(seq)?, session, domain);
        let packet = build_dns_txt_query(0xA000 + u16::try_from(seq)?, &qname);
        client.send(&packet).await?;
        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        let txt = parse_dns_txt_answer(&buf).ok_or("chunk: missing TXT")?;
        assembled.extend_from_slice(&doh_decode_b32(txt.trim_matches('"').trim())?);
    }

    let decrypted = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &assembled)?;
    assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());

    manager.stop("dns-doh-full").await?;
    Ok(())
}
