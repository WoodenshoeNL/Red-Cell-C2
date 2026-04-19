//! Shared helpers for DNS listener integration tests.

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::{DnsListenerConfig, ListenerConfig};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

/// Base32hex alphabet (RFC 4648 §7).
pub(super) const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// DNS wire-format header length.
pub(super) const DNS_HEADER_LEN: usize = 12;

/// Specter/Archon DoH chunk byte length.
pub(super) const DOH_CHUNK_BYTES: usize = 37;

/// Encode `data` using base32hex (unpadded, uppercase).
pub(super) fn base32hex_encode(data: &[u8]) -> String {
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

/// Decode base32hex (unpadded, case-insensitive) into bytes.
pub(super) fn base32hex_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
            buf &= (1 << bits) - 1;
        }
    }
    Ok(result)
}

/// Build a DNS upload qname for the C2 protocol.
pub(super) fn dns_upload_qname(
    agent_id: u32,
    seq: u16,
    total: u16,
    chunk: &[u8],
    domain: &str,
) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Build a DNS download qname for the C2 protocol.
pub(super) fn dns_download_qname(agent_id: u32, seq: u16, domain: &str) -> String {
    format!("{seq:x}-{agent_id:08x}.dn.{domain}")
}

/// Build a minimal DNS query packet for `qname` with the given `qtype`.
pub(super) fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
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
pub(super) fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, 16) // DNS_TYPE_TXT = 16
}

/// Parse the TXT answer from a DNS response packet.
pub(super) fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
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
pub(super) fn free_udp_port() -> u16 {
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

/// Build a DNS listener config.
pub(super) fn dns_listener(name: &str, port: u16, domain: &str) -> ListenerConfig {
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

/// Send a full Demon packet to the DNS listener with chunks delivered in the
/// order specified by `send_order`.  Each entry in `send_order` is a chunk
/// index (0-based) into the natural chunk sequence.  Entries may repeat
/// (to simulate retransmission) or appear out of order.
///
/// Returns a `Vec` of `(seq_index, txt_answer)` pairs — one per query sent.
pub(super) async fn dns_upload_demon_packet_ordered(
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
pub(super) async fn dns_upload_demon_packet(
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
pub(super) async fn dns_download_response(
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

/// Wait for the DNS listener to start responding.
pub(super) async fn wait_for_dns_listener(
    port: u16,
) -> Result<UdpSocket, Box<dyn std::error::Error>> {
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

/// Set up a DNS listener and return (manager, registry, client, port, domain).
pub(super) async fn setup_dns_test(
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
pub(super) async fn assert_listener_alive(client: &UdpSocket, domain: &str) {
    let probe = build_dns_txt_query(0xFFFE, &format!("probe.other.{domain}"));
    client.send(&probe).await.expect("probe send failed");
    let mut buf = vec![0u8; 512];
    let result = timeout(Duration::from_secs(5), client.recv(&mut buf)).await;
    assert!(result.is_ok(), "listener must still respond after receiving malformed packet");
}

/// Extract the RCODE from a DNS response packet.
pub(super) fn dns_rcode(buf: &[u8]) -> Option<u8> {
    buf.get(3).map(|b| b & 0x0F)
}

/// RFC 4648 base32 (lowercase), matches `agent/specter` `encode_b32`.
pub(super) fn doh_encode_b32(data: &[u8]) -> String {
    const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    if data.is_empty() {
        return String::new();
    }
    let out_len = (data.len() * 8).div_ceil(5);
    let mut out = Vec::with_capacity(out_len);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 0x1F) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 0x1F) as usize]);
    }
    String::from_utf8(out).expect("b32 alphabet is ascii")
}

pub(super) fn doh_decode_b32(s: &str) -> Result<Vec<u8>, String> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.chars() {
        let val = match ch {
            'a'..='z' => u64::from(ch as u8 - b'a'),
            '2'..='7' => u64::from(ch as u8 - b'2' + 26),
            _ => return Err(format!("invalid b32 {ch:?}")),
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u64 << bits).saturating_sub(1);
        }
    }
    Ok(out)
}

pub(super) fn doh_upload_qname(
    chunk_b32: &str,
    seq: u16,
    total: u16,
    session: &str,
    domain: &str,
) -> String {
    let seqtotal = format!("{seq:04x}{total:04x}");
    format!("{chunk_b32}.{seqtotal}.{session}.u.{domain}")
}

pub(super) fn doh_ready_qname(session: &str, domain: &str) -> String {
    format!("rdy.{session}.d.{domain}")
}

pub(super) fn doh_chunk_qname(seq: u16, session: &str, domain: &str) -> String {
    format!("{seq:04x}.{session}.d.{domain}")
}
