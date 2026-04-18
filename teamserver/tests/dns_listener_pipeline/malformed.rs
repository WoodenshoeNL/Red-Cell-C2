//! Malformed and truncated DNS packet rejection tests.

use std::time::Duration;

use tokio::time::{sleep, timeout};

use super::helpers::{
    assert_listener_alive, base32hex_encode, build_dns_txt_query, parse_dns_txt_answer,
    setup_dns_test,
};

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
