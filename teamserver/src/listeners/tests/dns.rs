use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use super::super::MAX_DEMON_INIT_ATTEMPTS_PER_IP;
use super::*;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::super::dns::{
    DNS_DOH_RESPONSE_CHUNK_BYTES, DNS_HEADER_LEN, DNS_MAX_DOWNLOAD_CHUNKS,
    DNS_MAX_PENDING_RESPONSE_BYTES, DNS_MAX_PENDING_RESPONSES, DNS_MAX_PENDING_UPLOADS,
    DNS_MAX_UPLOAD_CHUNKS, DNS_MAX_UPLOADS_PER_IP, DNS_QTYPE_ANY, DNS_QTYPE_AXFR,
    DNS_RESPONSE_CHUNK_BYTES, DNS_TYPE_A, DNS_TYPE_CNAME, DNS_TYPE_TXT, DNS_UPLOAD_TIMEOUT_SECS,
    DnsC2Query, DnsListenerState, DnsPendingResponse, DnsPendingUpload, DnsUploadAssembly,
    base32_rfc4648_decode, base32_rfc4648_encode, base32hex_decode, base32hex_encode,
    build_dns_c2_response, build_dns_nxdomain_response, chunk_response_to_b32hex,
    chunk_response_to_doh_b32, dns_allowed_query_types, dns_wire_domain_from_ascii_payload,
    parse_dns_c2_query, parse_dns_query, spawn_dns_listener_runtime,
};
use super::super::{DNS_RECON_WINDOW_DURATION, DnsReconBlockLimiter, MAX_DNS_RECON_QUERIES_PER_IP};

fn dns_upload_qname(agent_id: u32, seq: u16, total: u16, chunk: &[u8], domain: &str) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Return the TYPE field of the first answer RR (after a single question).
///
/// `qname_raw_len` is the length of the wire-format QNAME in the echoed question
/// (including the root label's zero octet).
fn dns_answer_rr_type(packet: &[u8], qname_raw_len: usize) -> Option<u16> {
    let ans_start = DNS_HEADER_LEN.checked_add(qname_raw_len)?.checked_add(4)?;
    let type_off = ans_start.checked_add(2)?;
    let t = packet.get(type_off..type_off + 2)?;
    Some(u16::from_be_bytes([t[0], t[1]]))
}

/// RDATA octets of the first answer RR (single question, compressed NAME pointer).
fn dns_answer_rdata(packet: &[u8], qname_raw_len: usize) -> Option<Vec<u8>> {
    let ans_start = DNS_HEADER_LEN.checked_add(qname_raw_len)?.checked_add(4)?;
    let rdlen_off = ans_start.checked_add(2 + 2 + 2 + 4)?;
    let rdlen = u16::from_be_bytes([*packet.get(rdlen_off)?, *packet.get(rdlen_off + 1)?]) as usize;
    let rdata_start = rdlen_off.checked_add(2)?;
    let end = rdata_start.checked_add(rdlen)?;
    Some(packet.get(rdata_start..end)?.to_vec())
}

fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
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

async fn dns_state(name: &str) -> DnsListenerState {
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let config = red_cell_common::DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: 0,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };

    DnsListenerState::new(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        DnsReconBlockLimiter::new(),
        ShutdownController::new(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
}

async fn spawn_test_dns_listener(
    config: red_cell_common::DnsListenerConfig,
) -> (JoinHandle<()>, AgentRegistry) {
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = spawn_dns_listener_runtime(
        &config,
        registry.clone(),
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        ShutdownController::new(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
    .await
    .expect("dns runtime should start");
    let handle = tokio::spawn(async move {
        let _ = runtime.await;
    });

    (handle, registry)
}

/// Build a minimal DNS query packet for `qname`.
fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: QR=0, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // QNAME
    for label in qname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // zero terminator
    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    buf
}

fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, DNS_TYPE_TXT)
}

fn build_dns_cname_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, DNS_TYPE_CNAME)
}

#[test]
fn base32hex_encode_and_decode_round_trip() {
    let cases: &[&[u8]] =
        &[b"hello", b"", b"\x00\xff\xaa", b"The quick brown fox jumps over the lazy dog"];
    for &data in cases {
        let encoded = base32hex_encode(data);
        let decoded = base32hex_decode(&encoded).expect("decode failed");
        assert_eq!(decoded, data, "round trip failed for {data:?}");
    }
}

#[test]
fn base32hex_decode_is_case_insensitive() {
    let lower = base32hex_decode("c9gq6u").expect("lower decode failed");
    let upper = base32hex_decode("C9GQ6U").expect("upper decode failed");
    assert_eq!(lower, upper);
}

#[test]
fn base32hex_decode_rejects_invalid_characters() {
    assert!(base32hex_decode("XY!").is_none());
    assert!(base32hex_decode("ZZZZ").is_none()); // Z is not in base32hex
}

#[test]
fn parse_dns_query_extracts_labels_and_type() {
    let qname = "data.0-1-deadbeef.up.c2.example.com";
    let packet = build_dns_txt_query(0x1234, qname);
    let parsed = parse_dns_query(&packet).expect("parse failed");
    assert_eq!(parsed.id, 0x1234);
    assert_eq!(parsed.qtype, DNS_TYPE_TXT);
    assert_eq!(parsed.labels, &["data", "0-1-deadbeef", "up", "c2", "example", "com"]);
    // qname_raw includes zero terminator
    assert_eq!(*parsed.qname_raw.last().expect("DNS qname should end with a zero-length label"), 0);
}

#[test]
fn parse_dns_query_rejects_short_packets() {
    assert!(parse_dns_query(&[0u8; 3]).is_none());
}

#[test]
fn parse_dns_query_rejects_multiple_questions() {
    let mut packet = build_dns_txt_query(1, "foo.bar");
    // Set qdcount = 2
    packet[4] = 0;
    packet[5] = 2;
    assert!(parse_dns_query(&packet).is_none());
}

#[test]
fn parse_dns_query_rejects_response_packets() {
    let mut packet = build_dns_txt_query(0x1234, "foo.bar");
    packet[2] |= 0x80;
    assert!(parse_dns_query(&packet).is_none());
}

#[test]
fn parse_dns_c2_query_recognises_upload_query() {
    let data = b"hello";
    let b32 = base32hex_encode(data);
    let labels: Vec<String> = [b32.as_str(), "0-1-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::Upload { agent_id, seq, total, data: decoded }) = result else {
        panic!("expected Upload variant");
    };
    assert_eq!(agent_id, 0xDEAD_BEEF);
    assert_eq!(seq, 0);
    assert_eq!(total, 1);
    assert_eq!(decoded, b"hello");
}

#[test]
fn parse_dns_c2_query_recognises_download_query() {
    let labels: Vec<String> =
        ["3-cafebabe", "dn", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::Download { agent_id, seq }) = result else {
        panic!("expected Download variant");
    };
    assert_eq!(agent_id, 0xCAFE_BABE);
    assert_eq!(seq, 3);
}

#[test]
fn parse_dns_c2_query_rejects_wrong_domain() {
    let labels: Vec<String> = ["data", "0-1-deadbeef", "up", "other", "domain", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_ctrl_too_few_parts() {
    // Only 2 dash-separated parts instead of 3 → None
    let labels: Vec<String> = ["CPNMU", "0-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_ctrl_too_many_parts() {
    // 4 dash-separated parts instead of 3 → None
    let labels: Vec<String> =
        ["CPNMU", "0-1-2-3", "up", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_non_hex_seq() {
    // "zzz" is not valid hex → from_str_radix fails → None
    let labels: Vec<String> = ["CPNMU", "zzz-1-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_non_hex_agent_id() {
    let labels: Vec<String> = ["CPNMU", "0-1-GGGGGGGG", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_invalid_base32hex() {
    // 'Z' is outside the base32hex alphabet (0-9, A-V) → None
    let labels: Vec<String> = ["ZZZZ", "0-1-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_download_ctrl_no_dash() {
    // Single part with no dash → parts.len() == 1 → None
    let labels: Vec<String> =
        ["deadbeef", "dn", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_unknown_direction() {
    // "fwd" is neither "up" nor "dn" → falls through to _ => None
    let labels: Vec<String> = ["CPNMU", "0-1-deadbeef", "fwd", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_recognises_doh_upload() {
    let payload = b"hello";
    let b32 = base32_rfc4648_encode(payload);
    let seqtotal = format!("{:04x}{:04x}", 0u16, 1u16);
    let session = "0123456789abcdef";
    let labels: Vec<String> = [b32.as_str(), &seqtotal, session, "u", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::DohUpload { session: s, seq, total, data }) = result else {
        panic!("expected DohUpload variant, got {result:?}");
    };
    assert_eq!(s, session);
    assert_eq!(seq, 0);
    assert_eq!(total, 1);
    assert_eq!(data, payload);
}

#[test]
fn parse_dns_c2_query_recognises_doh_ready() {
    let session = "0123456789abcdef";
    let labels: Vec<String> =
        ["rdy", session, "d", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::DohReady { session: s }) = result else {
        panic!("expected DohReady variant");
    };
    assert_eq!(s, session);
}

#[test]
fn parse_dns_c2_query_recognises_doh_chunk_download() {
    let session = "fedcba9876543210";
    let labels: Vec<String> =
        ["0003", session, "d", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::DohDownload { session: s, seq }) = result else {
        panic!("expected DohDownload variant");
    };
    assert_eq!(s, session);
    assert_eq!(seq, 3);
}

/// End-to-end interop: query names built with the same `format!` patterns as
/// `agent/specter/src/doh_transport.rs` and `agent/archon/src/core/TransportDoH.c`
/// must parse through `parse_dns_query` → `parse_dns_c2_query` (the DNS listener path).
#[test]
fn doh_interop_specter_archon_wire_names_parse_from_udp_packet() {
    const C2_DOMAIN: &str = "c2.example.com";
    let payload = b"demon-packet-bytes";
    let chunk = base32_rfc4648_encode(payload);
    let seq = 7u16;
    let total = 99u16;
    let session_mixed = "0123456789ABCDEF";
    let session_lower = "0123456789abcdef";

    // Uplink — one label for `<seq:04x><total:04x>` (not two labels).
    let uplink_name = format!("{chunk}.{seq:04x}{total:04x}.{session_mixed}.u.{C2_DOMAIN}");
    let pkt = build_dns_txt_query(0xACE, &uplink_name);
    let parsed = parse_dns_query(&pkt).expect("wire parse");
    let q = parse_dns_c2_query(&parsed.labels, C2_DOMAIN).expect("c2 parse uplink");
    let DnsC2Query::DohUpload { session, seq: got_seq, total: got_total, data } = q else {
        panic!("expected DohUpload, got {q:?}");
    };
    assert_eq!(session, session_lower);
    assert_eq!(got_seq, seq);
    assert_eq!(got_total, total);
    assert_eq!(data.as_slice(), payload);

    // Ready poll — `rdy.<session>.d.<domain>`
    let ready_name = format!("rdy.{session_mixed}.d.{C2_DOMAIN}");
    let pkt = build_dns_txt_query(0xBEE, &ready_name);
    let parsed = parse_dns_query(&pkt).expect("wire parse");
    let q = parse_dns_c2_query(&parsed.labels, C2_DOMAIN).expect("c2 parse ready");
    let DnsC2Query::DohReady { session } = q else {
        panic!("expected DohReady, got {q:?}");
    };
    assert_eq!(session, session_lower);

    // Chunk fetch — `<seq:04x>.<session>.d.<domain>`
    let fetch_seq = 12u16;
    let fetch_name = format!("{fetch_seq:04x}.{session_mixed}.d.{C2_DOMAIN}");
    let pkt = build_dns_txt_query(0xC0D, &fetch_name);
    let parsed = parse_dns_query(&pkt).expect("wire parse");
    let q = parse_dns_c2_query(&parsed.labels, C2_DOMAIN).expect("c2 parse fetch");
    let DnsC2Query::DohDownload { session, seq } = q else {
        panic!("expected DohDownload, got {q:?}");
    };
    assert_eq!(session, session_lower);
    assert_eq!(seq, fetch_seq);
}

#[test]
fn build_dns_nxdomain_response_sets_rcode_3() {
    let packet = build_dns_txt_query(0x4242, "rdy.testsession.d.c2.example.com");
    let parsed = parse_dns_query(&packet).expect("parse failed");
    let resp = build_dns_nxdomain_response(parsed.id, &parsed.qname_raw, parsed.qtype);
    assert_eq!(resp[3] & 0x0F, 3u8);
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
}

#[test]
fn chunk_response_to_doh_b32_round_trip() {
    let payload = vec![0xABu8; 80];
    let chunks = chunk_response_to_doh_b32(&payload);
    assert_eq!(chunks.len(), 3); // ceil(80/37) = 3
    let mut out = Vec::new();
    for c in &chunks {
        out.extend_from_slice(&base32_rfc4648_decode(c).expect("decode"));
    }
    assert_eq!(out, payload);
}

#[test]
fn dns_doh_chunk_size_matches_specter() {
    assert_eq!(DNS_DOH_RESPONSE_CHUNK_BYTES, 37);
}

#[test]
fn build_dns_c2_response_answer_rr_matches_txt_a_cname_queries() {
    let payload = b"ok";
    for (qtype, expected_type) in
        [(DNS_TYPE_TXT, DNS_TYPE_TXT), (DNS_TYPE_A, DNS_TYPE_A), (DNS_TYPE_CNAME, DNS_TYPE_CNAME)]
    {
        let packet = build_dns_query(0xABCD, "test.c2.example.com", qtype);
        let parsed = parse_dns_query(&packet).expect("parse failed");
        let response = build_dns_c2_response(parsed.id, &parsed.qname_raw, parsed.qtype, payload)
            .expect("response should encode");

        assert!(response.len() >= DNS_HEADER_LEN);
        assert!(response[2] & 0x80 != 0, "QR bit not set");
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);

        let question_qtype_offset = DNS_HEADER_LEN + parsed.qname_raw.len();
        let echoed_qtype = u16::from_be_bytes([
            response[question_qtype_offset],
            response[question_qtype_offset + 1],
        ]);
        assert_eq!(echoed_qtype, qtype);

        assert_eq!(
            dns_answer_rr_type(&response, parsed.qname_raw.len()),
            Some(expected_type),
            "answer RR TYPE must match query type {qtype}"
        );
    }

    let packet_a = build_dns_query(0xABCD, "test.c2.example.com", DNS_TYPE_A);
    let parsed_a = parse_dns_query(&packet_a).expect("parse failed");
    let response_a = build_dns_c2_response(parsed_a.id, &parsed_a.qname_raw, parsed_a.qtype, b"ok")
        .expect("a response");
    assert_eq!(
        dns_answer_rdata(&response_a, parsed_a.qname_raw.len()),
        Some(vec![b'o', b'k', 0, 0])
    );
}

#[test]
fn build_dns_c2_response_returns_none_when_a_payload_exceeds_four_octets() {
    let packet = build_dns_query(0xABCD, "test.c2.example.com", DNS_TYPE_A);
    let parsed = parse_dns_query(&packet).expect("parse failed");
    assert!(build_dns_c2_response(parsed.id, &parsed.qname_raw, parsed.qtype, b"hello").is_none());
}

#[test]
fn dns_wire_domain_splits_long_payload_into_labels() {
    let s = "a".repeat(130);
    let wire = dns_wire_domain_from_ascii_payload(&s).expect("wire");
    assert!(wire.len() <= 255);
    assert_eq!(wire[0], 63);
    assert_eq!(wire[64], 63);
    assert_eq!(wire[128], 4);
    assert_eq!(wire[133], 0);
}

#[test]
fn dns_allowed_query_types_defaults_to_txt_and_supports_cname() {
    assert_eq!(dns_allowed_query_types(&[]), Some(vec![DNS_TYPE_TXT]));
    assert_eq!(
        dns_allowed_query_types(&["txt".to_owned(), "CNAME".to_owned(), "A".to_owned()]),
        Some(vec![DNS_TYPE_TXT, DNS_TYPE_CNAME, DNS_TYPE_A])
    );
    assert!(dns_allowed_query_types(&["MX".to_owned()]).is_none());
}

#[test]
fn chunk_response_splits_payload_into_base32hex_chunks() {
    let payload = vec![0xABu8; 300]; // 300 bytes > 1 chunk (125 bytes each)
    let chunks = chunk_response_to_b32hex(&payload);
    assert_eq!(chunks.len(), 3); // ceil(300/125) = 3
    // Each chunk decodes back to the expected slice
    let mut reassembled = Vec::new();
    for chunk in &chunks {
        let decoded = base32hex_decode(chunk).expect("chunk decode failed");
        reassembled.extend_from_slice(&decoded);
    }
    assert_eq!(reassembled, payload);
}

#[test]
fn dns_max_download_chunks_matches_u16_max() {
    // Verify the constant is exactly u16::MAX so the seq field can address
    // every chunk without overflow.
    assert_eq!(DNS_MAX_DOWNLOAD_CHUNKS, u16::MAX as usize);
    assert_eq!(DNS_MAX_DOWNLOAD_CHUNKS, 65_535);
}

#[test]
fn chunk_response_at_u16_boundary_is_within_limit() {
    // Exactly u16::MAX chunks — should be accepted.
    let payload_size = DNS_MAX_DOWNLOAD_CHUNKS * DNS_RESPONSE_CHUNK_BYTES;
    let chunks = chunk_response_to_b32hex(&vec![0xBB; payload_size]);
    assert_eq!(chunks.len(), DNS_MAX_DOWNLOAD_CHUNKS);
}

#[test]
fn chunk_response_exceeding_u16_limit_produces_too_many_chunks() {
    // One byte over the limit produces chunk count > u16::MAX.
    let payload_size = DNS_MAX_DOWNLOAD_CHUNKS * DNS_RESPONSE_CHUNK_BYTES + 1;
    let chunks = chunk_response_to_b32hex(&vec![0xCC; payload_size]);
    assert!(
        chunks.len() > DNS_MAX_DOWNLOAD_CHUNKS,
        "expected more than {} chunks, got {}",
        DNS_MAX_DOWNLOAD_CHUNKS,
        chunks.len()
    );
}

#[tokio::test]
async fn dns_listener_starts_and_responds_to_unknown_queries_with_refused() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-test".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    // Brief delay for the listener to bind
    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    // Send a query for an unrecognised C2 domain — expect REFUSED
    let packet = build_dns_txt_query(0x1111, "something.other.domain.com");
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    // RCODE should be 5 (REFUSED)
    let rcode = buf[3] & 0x0F;
    assert_eq!(rcode, 5, "expected REFUSED RCODE");
    handle.abort();
}

#[tokio::test]
async fn dns_listener_runtime_exits_when_shutdown_started_before_first_poll() {
    let shutdown = ShutdownController::new();
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-shutdown-prepoll".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = spawn_dns_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        shutdown.clone(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
    .await
    .expect("dns runtime should start");

    shutdown.initiate();

    let result = timeout(Duration::from_millis(200), runtime)
        .await
        .expect("dns runtime should observe pre-existing shutdown");
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn dns_listener_download_poll_returns_wait_when_no_response_queued() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-wait".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    // Download poll for agent 0xDEADBEEF, seq 0
    let qname = "0-deadbeef.dn.c2.example.com";
    let packet = build_dns_txt_query(0x2222, qname);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    // NOERROR (RCODE=0)
    let rcode = buf[3] & 0x0F;
    assert_eq!(rcode, 0, "expected NOERROR");

    // ANCOUNT = 1
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    assert_eq!(ancount, 1);
    let parsed = parse_dns_query(&packet).expect("query should parse");
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_TXT),
        "answer RR must be TXT when the query is TXT"
    );
    handle.abort();
}

#[tokio::test]
async fn dns_listener_a_query_returns_ipv4_rdata_when_payload_fits() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-a-rdata".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["A".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_query(0x7777, "0-deadbeef.dn.c2.example.com", DNS_TYPE_A);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR");
    let parsed = parse_dns_query(&packet).expect("query should parse");
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_A),
        "answer RR must be A when the query is A"
    );
    assert_eq!(dns_answer_rdata(&buf, parsed.qname_raw.len()), Some(vec![b'w', b'a', b'i', b't']));
    handle.abort();
}

#[tokio::test]
async fn dns_listener_rate_limits_demon_init_per_source_ip() {
    let port = free_udp_port();
    let domain = "c2.example.com".to_owned();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-init-limit".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.clone(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, registry) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    for attempt in 0..=MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0x3000_0000 + attempt;
        let payload = valid_demon_init_body(agent_id, test_key(0x41), test_iv(0x24));
        let chunks: Vec<&[u8]> = payload.chunks(39).collect();
        let total = u16::try_from(chunks.len()).expect("chunk count should fit in u16");
        let expected_txt = if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP { "ack" } else { "err" };

        for (seq, chunk) in chunks.iter().enumerate() {
            let qname = dns_upload_qname(
                agent_id,
                u16::try_from(seq).expect("chunk index should fit in u16"),
                total,
                chunk,
                &domain,
            );
            let packet = build_dns_txt_query(0x4000 + seq as u16, &qname);
            client.send(&packet).await.expect("send failed");

            let mut buf = vec![0u8; 1024];
            tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
                .await
                .expect("no response received")
                .expect("recv failed");

            let txt = parse_dns_txt_answer(&buf).expect("TXT answer should parse");
            let is_last = seq + 1 == chunks.len();
            if is_last {
                assert_eq!(txt, expected_txt);
            } else {
                assert_eq!(txt, "ok");
            }
        }

        if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            assert!(registry.get(agent_id).await.is_some());
        } else {
            assert!(registry.get(agent_id).await.is_none());
        }
    }
    handle.abort();
}

#[tokio::test]
async fn dns_listener_refuses_query_types_not_enabled_by_config() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-txt-only".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_query(0x3333, "0-deadbeef.dn.c2.example.com", DNS_TYPE_A);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
    handle.abort();
}

#[tokio::test]
async fn dns_listener_responds_to_a_burst_of_udp_queries() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-burst".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    for id in 0x5000..0x5010 {
        let packet = build_dns_txt_query(id, "burst.other.domain.com");
        client.send(&packet).await.expect("send failed");
    }

    let mut buf = vec![0u8; 512];
    let mut seen_ids = HashSet::new();
    for _ in 0x5000..0x5010 {
        let received = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");
        assert!(received >= DNS_HEADER_LEN, "response too short");
        seen_ids.insert(u16::from_be_bytes([buf[0], buf[1]]));
        assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
    }
    assert_eq!(seen_ids.len(), 16, "every burst query should receive a response");

    handle.abort();
}

#[tokio::test]
async fn dns_listener_accepts_cname_queries_when_enabled() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-cname".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["CNAME".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_cname_query(0x4444, "0-deadbeef.dn.c2.example.com");
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR");
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    assert_eq!(ancount, 1);
    let parsed = parse_dns_query(&packet).expect("query should parse");
    let question_qtype_offset = DNS_HEADER_LEN + parsed.qname_raw.len();
    let echoed_qtype =
        u16::from_be_bytes([buf[question_qtype_offset], buf[question_qtype_offset + 1]]);
    assert_eq!(echoed_qtype, DNS_TYPE_CNAME);
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_CNAME),
        "answer RR must be CNAME when the query is CNAME"
    );
    let expected_rdata =
        dns_wire_domain_from_ascii_payload("wait").expect("wait encodes as CNAME RDATA");
    assert_eq!(dns_answer_rdata(&buf, parsed.qname_raw.len()), Some(expected_rdata));
    handle.abort();
}

/// When multiple record types are enabled, each successful C2 poll must answer with an RR
/// whose TYPE matches the question QTYPE (not always TXT).
#[tokio::test]
async fn dns_listener_multi_record_types_each_answer_rr_matches_query_qtype() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-multi-qtype".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned(), "A".to_owned(), "CNAME".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let qname = "0-deadbeef.dn.c2.example.com";
    for (id, qtype) in [(0x6001u16, DNS_TYPE_TXT), (0x6002, DNS_TYPE_A), (0x6003, DNS_TYPE_CNAME)] {
        let packet = build_dns_query(id, qname, qtype);
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR for qtype {qtype}");
        let parsed = parse_dns_query(&packet).expect("query should parse");
        assert_eq!(
            dns_answer_rr_type(&buf, parsed.qname_raw.len()),
            Some(qtype),
            "answer RR TYPE must match QTYPE {qtype}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn dns_listener_start_rejects_unsupported_record_types() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-invalid-type".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["MX".to_owned()],
        kill_date: None,
        working_hours: None,
    };

    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let error = match spawn_dns_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        ShutdownController::new(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        false,
    )
    .await
    {
        Ok(_) => panic!("start should fail"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("unsupported DNS record type configuration"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn dns_listener_download_done_removes_pending_response() {
    let state = dns_state("dns-cleanup").await;
    let agent_id = 0xDEAD_BEEF;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(agent_id, key, iv)).await.expect("insert agent");

    state.responses.lock().await.insert(
        agent_id,
        DnsPendingResponse {
            chunks: vec!["AAA".to_owned(), "BBB".to_owned()],
            received_at: Instant::now(),
        },
    );

    assert_eq!(state.handle_download(agent_id, 0).await, "2 AAA");
    assert!(state.responses.lock().await.contains_key(&agent_id));

    assert_eq!(state.handle_download(agent_id, 2).await, "done");
    assert!(!state.responses.lock().await.contains_key(&agent_id));
    assert_eq!(state.handle_download(agent_id, 0).await, "wait");
}

#[tokio::test]
async fn dns_listener_download_rejects_unknown_agent_id() {
    let state = dns_state("dns-auth-reject").await;
    let agent_id = 0xDEAD_BEEF;
    let unknown_id = 0xCAFE_BABE;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(agent_id, key, iv)).await.expect("insert agent");

    // Insert a queued response for the known agent using the unknown_id as the key
    // to simulate an attacker injecting under an unregistered agent ID.
    state.responses.lock().await.insert(
        unknown_id,
        DnsPendingResponse { chunks: vec!["SECRET".to_owned()], received_at: Instant::now() },
    );

    // Unknown agent should be rejected with "wait" and the queue entry must survive.
    assert_eq!(state.handle_download(unknown_id, 0).await, "wait");
    assert!(
        state.responses.lock().await.contains_key(&unknown_id),
        "queued response must not be consumed for unregistered agent"
    );
}

/// Regression test for red-cell-c2-59m7: DNS download must succeed even
/// when the resolver IP changes between upload and download.  Recursive
/// resolver pools legitimately rotate source IPs, so binding to the
/// upload peer_ip strands real agents.
#[tokio::test]
async fn dns_download_succeeds_from_different_resolver_ip() {
    let state = dns_state("dns-resolver-rotate").await;
    let agent_id = 0xDEAD_BEEF;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(agent_id, key, iv)).await.expect("insert agent");

    // Simulate response queued from upload via resolver A.
    state.responses.lock().await.insert(
        agent_id,
        DnsPendingResponse {
            chunks: vec!["AAA".to_owned(), "BBB".to_owned()],
            received_at: Instant::now(),
        },
    );

    // Download arrives via resolver B (different IP) — must still work.
    assert_eq!(state.handle_download(agent_id, 0).await, "2 AAA");
    assert!(state.responses.lock().await.contains_key(&agent_id));
    assert_eq!(state.handle_download(agent_id, 1).await, "2 BBB");
    assert!(state.responses.lock().await.contains_key(&agent_id));
    assert_eq!(state.handle_download(agent_id, 2).await, "done");
    assert!(!state.responses.lock().await.contains_key(&agent_id));
}

/// An unregistered agent must not be able to download responses, even
/// though the IP check was removed.  The registry check is the gate.
#[tokio::test]
async fn dns_download_rejects_unregistered_agent_regardless_of_ip() {
    let state = dns_state("dns-unregistered-dl").await;
    let registered_id = 0xDEAD_BEEF;
    let unregistered_id = 0xCAFE_BABE;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(registered_id, key, iv)).await.expect("insert");

    // Plant a response under the unregistered agent ID.
    state.responses.lock().await.insert(
        unregistered_id,
        DnsPendingResponse { chunks: vec!["SECRET".to_owned()], received_at: Instant::now() },
    );

    // Must be rejected because the agent is not in the registry.
    assert_eq!(state.handle_download(unregistered_id, 0).await, "wait");
    assert!(
        state.responses.lock().await.contains_key(&unregistered_id),
        "queued response must not be consumed for unregistered agent"
    );
}

#[tokio::test]
async fn dns_upload_rejects_total_over_limit() {
    let state = dns_state("dns-total-cap").await;

    let result = state
        .try_assemble_upload(
            0xDEAD_BEEF,
            0,
            DNS_MAX_UPLOAD_CHUNKS + 1,
            vec![0x41],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .await;

    assert_eq!(result, DnsUploadAssembly::Rejected);
    assert!(state.uploads.lock().await.is_empty());
}

#[tokio::test]
async fn dns_upload_rejects_inconsistent_total_and_clears_session() {
    let state = dns_state("dns-total-mismatch").await;
    let agent_id = 0xDEAD_BEEF;

    let first = state
        .try_assemble_upload(agent_id, 0, 2, vec![0x41], IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await;
    assert_eq!(first, DnsUploadAssembly::Pending);

    let second = state
        .try_assemble_upload(agent_id, 1, 3, vec![0x42], IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await;
    assert_eq!(second, DnsUploadAssembly::Rejected);
    assert!(!state.uploads.lock().await.contains_key(&agent_id));
}

/// A third-party host that knows a valid agent_id must not be able to clear the legitimate
/// agent's in-progress upload session by sending a chunk with a mismatched total.
#[tokio::test]
async fn dns_upload_spoof_does_not_clear_legitimate_session() {
    let state = dns_state("dns-spoof-dos").await;
    let agent_id = 0xDEAD_BEEF;
    let legit_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let attacker_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    // Legitimate agent opens a 3-chunk upload session.
    let first = state.try_assemble_upload(agent_id, 0, 3, vec![0x41], legit_ip).await;
    assert_eq!(first, DnsUploadAssembly::Pending);

    // Attacker sends a chunk for the same agent_id with a different total to trigger
    // the inconsistent-total branch — this must be rejected without clearing the session.
    let spoof = state.try_assemble_upload(agent_id, 0, 99, vec![0xFF], attacker_ip).await;
    assert_eq!(spoof, DnsUploadAssembly::Rejected);

    // The legitimate session must still be intact.
    {
        let uploads = state.uploads.lock().await;
        let session = uploads.get(&agent_id).expect("session must still exist after spoof");
        assert_eq!(session.total, 3, "session total must not have been overwritten");
        assert_eq!(session.peer_ip, legit_ip, "session peer_ip must not have changed");
    }

    // Attacker sends matching total but is still rejected due to IP mismatch.
    let spoof_matching_total =
        state.try_assemble_upload(agent_id, 1, 3, vec![0xAA], attacker_ip).await;
    assert_eq!(spoof_matching_total, DnsUploadAssembly::Rejected);

    // Session must remain unchanged — only legit_ip's chunk (seq 0) is present.
    {
        let uploads = state.uploads.lock().await;
        let session = uploads.get(&agent_id).expect("session must still exist");
        assert_eq!(session.chunks.len(), 1);
        assert!(session.chunks.contains_key(&0));
    }

    // Legitimate agent completes the upload normally.
    let second = state.try_assemble_upload(agent_id, 1, 3, vec![0x42], legit_ip).await;
    assert_eq!(second, DnsUploadAssembly::Pending);
    let third = state.try_assemble_upload(agent_id, 2, 3, vec![0x43], legit_ip).await;
    assert_eq!(third, DnsUploadAssembly::Complete(vec![0x41, 0x42, 0x43]));
}

#[tokio::test]
async fn dns_upload_rejects_new_session_when_capacity_reached() {
    let state = dns_state("dns-capacity").await;

    {
        let mut uploads = state.uploads.lock().await;
        for agent_id in 0..DNS_MAX_PENDING_UPLOADS {
            uploads.insert(
                agent_id as u32,
                DnsPendingUpload {
                    chunks: HashMap::new(),
                    total: 1,
                    received_at: Instant::now(),
                    // Use a distinct IP per slot so per-IP limits don't interfere.
                    peer_ip: IpAddr::V4(Ipv4Addr::new(
                        10,
                        ((agent_id >> 16) & 0xFF) as u8,
                        ((agent_id >> 8) & 0xFF) as u8,
                        (agent_id & 0xFF) as u8,
                    )),
                },
            );
        }
    }

    let result = state
        .try_assemble_upload(
            0xDEAD_BEEF,
            0,
            1,
            vec![0x41],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        )
        .await;

    assert_eq!(result, DnsUploadAssembly::Rejected);
    assert_eq!(state.uploads.lock().await.len(), DNS_MAX_PENDING_UPLOADS);
}

#[tokio::test]
async fn dns_upload_rejects_new_session_when_per_ip_limit_reached() {
    let state = dns_state("dns-per-ip-cap").await;
    let attacker_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let other_ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

    // Fill up DNS_MAX_UPLOADS_PER_IP sessions from the attacker IP.
    for i in 0..DNS_MAX_UPLOADS_PER_IP {
        let result = state.try_assemble_upload(i as u32, 0, 2, vec![0x41], attacker_ip).await;
        assert_eq!(result, DnsUploadAssembly::Pending, "session {i} should be accepted");
    }

    // Next session from the same IP must be rejected.
    let result = state
        .try_assemble_upload(DNS_MAX_UPLOADS_PER_IP as u32, 0, 1, vec![0x41], attacker_ip)
        .await;
    assert_eq!(result, DnsUploadAssembly::Rejected);

    // A different IP must still be accepted.
    let result = state.try_assemble_upload(0xFFFF_0001, 0, 1, vec![0x41], other_ip).await;
    assert_eq!(result, DnsUploadAssembly::Complete(vec![0x41]));
}

#[tokio::test]
async fn dns_upload_cleanup_removes_expired_sessions() {
    let state = dns_state("dns-expiry").await;
    let stale_age = Duration::from_secs(DNS_UPLOAD_TIMEOUT_SECS + 1);

    {
        let mut uploads = state.uploads.lock().await;
        uploads.insert(
            1,
            DnsPendingUpload {
                chunks: HashMap::new(),
                total: 1,
                received_at: Instant::now() - stale_age,
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
        );
        uploads.insert(
            2,
            DnsPendingUpload {
                chunks: HashMap::new(),
                total: 1,
                received_at: Instant::now(),
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            },
        );
    }
    {
        let mut responses = state.responses.lock().await;
        responses.insert(
            3,
            DnsPendingResponse {
                chunks: vec!["AAA".to_owned()],
                received_at: Instant::now() - stale_age,
            },
        );
        responses.insert(
            4,
            DnsPendingResponse { chunks: vec!["BBB".to_owned()], received_at: Instant::now() },
        );
    }

    state.cleanup_expired_uploads().await;

    let uploads = state.uploads.lock().await;
    assert!(!uploads.contains_key(&1));
    assert!(uploads.contains_key(&2));
    drop(uploads);

    let responses = state.responses.lock().await;
    assert!(!responses.contains_key(&3));
    assert!(responses.contains_key(&4));
}

#[tokio::test]
async fn dns_response_cap_evicts_oldest_when_count_exceeded() {
    let state = dns_state("dns-resp-count-cap").await;

    {
        let mut responses = state.responses.lock().await;
        for i in 0..DNS_MAX_PENDING_RESPONSES {
            responses.insert(
                i as u32,
                DnsPendingResponse {
                    chunks: vec!["A".to_owned()],
                    // Stagger timestamps so eviction order is deterministic.
                    received_at: Instant::now()
                        - Duration::from_secs((DNS_MAX_PENDING_RESPONSES - i) as u64),
                },
            );
        }
        assert_eq!(responses.len(), DNS_MAX_PENDING_RESPONSES);
    }

    // Insert one more via enforce_response_caps — should evict agent 0 (oldest).
    let new_chunks = vec!["NEW".to_owned()];
    {
        let mut responses = state.responses.lock().await;
        let accepted = DnsListenerState::enforce_response_caps(
            &mut responses,
            0xFFFF_FFFF,
            &new_chunks,
            "test",
        );
        assert!(accepted, "small response should be accepted");
        responses.insert(
            0xFFFF_FFFF,
            DnsPendingResponse { chunks: new_chunks, received_at: Instant::now() },
        );

        assert_eq!(responses.len(), DNS_MAX_PENDING_RESPONSES);
        assert!(!responses.contains_key(&0), "oldest entry (agent 0) should have been evicted");
        assert!(responses.contains_key(&0xFFFF_FFFF), "new entry should be present");
    }
}

#[tokio::test]
async fn dns_response_cap_evicts_oldest_when_byte_limit_exceeded() {
    let state = dns_state("dns-resp-byte-cap").await;

    // Each chunk is 1 MB of data — insert 7 entries (7 MB total, under 8 MB cap).
    let big_chunk = "X".repeat(1024 * 1024);
    {
        let mut responses = state.responses.lock().await;
        for i in 0..7u32 {
            responses.insert(
                i,
                DnsPendingResponse {
                    chunks: vec![big_chunk.clone()],
                    received_at: Instant::now() - Duration::from_secs((7 - i) as u64),
                },
            );
        }
        assert_eq!(responses.len(), 7);
    }

    // Inserting a 2 MB response should push total to 9 MB, evicting the oldest.
    let new_chunks = vec![big_chunk.clone(), big_chunk.clone()];
    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 100, &new_chunks, "test");
        assert!(accepted, "response fitting within cap should be accepted");
        responses
            .insert(100, DnsPendingResponse { chunks: new_chunks, received_at: Instant::now() });

        // Agent 0 (oldest, 1 MB) evicted → 6 old + 1 new = 7 entries, 8 MB total.
        assert!(!responses.contains_key(&0), "oldest entry should have been evicted");
        assert!(responses.contains_key(&100), "new entry should be present");
        let total = DnsListenerState::pending_response_bytes(&responses);
        assert!(
            total <= DNS_MAX_PENDING_RESPONSE_BYTES,
            "total bytes {total} exceeds cap {DNS_MAX_PENDING_RESPONSE_BYTES}"
        );
    }
}

#[tokio::test]
async fn dns_response_cap_replacement_does_not_evict() {
    let state = dns_state("dns-resp-replace").await;

    {
        let mut responses = state.responses.lock().await;
        for i in 0..DNS_MAX_PENDING_RESPONSES {
            responses.insert(
                i as u32,
                DnsPendingResponse { chunks: vec!["OLD".to_owned()], received_at: Instant::now() },
            );
        }
    }

    // Replacing agent 0's response (same agent_id) should not evict any other entry.
    let new_chunks = vec!["REPLACED".to_owned()];
    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 0, &new_chunks, "test");
        assert!(accepted, "replacement response should be accepted");
        responses.insert(0, DnsPendingResponse { chunks: new_chunks, received_at: Instant::now() });

        assert_eq!(responses.len(), DNS_MAX_PENDING_RESPONSES);
        assert_eq!(responses.get(&0).expect("agent 0").chunks[0], "REPLACED");
        // All other entries still present.
        for i in 1..DNS_MAX_PENDING_RESPONSES {
            assert!(responses.contains_key(&(i as u32)), "agent {i} must still exist");
        }
    }
}

#[tokio::test]
async fn dns_response_cap_rejects_oversized_single_response() {
    let state = dns_state("dns-resp-oversize").await;

    // Build a single response that exceeds DNS_MAX_PENDING_RESPONSE_BYTES (8 MiB).
    // Use (8 MiB + 1) bytes spread across two chunks.
    let half = DNS_MAX_PENDING_RESPONSE_BYTES / 2;
    let oversized_chunks = vec!["X".repeat(half), "X".repeat(half + 1)];
    let total: usize = oversized_chunks.iter().map(|c| c.len()).sum();
    assert!(total > DNS_MAX_PENDING_RESPONSE_BYTES);

    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 42, &oversized_chunks, "test");
        assert!(!accepted, "oversized single response must be rejected");
        assert!(responses.is_empty(), "map should remain empty after rejection");
    }
}

#[tokio::test]
async fn dns_response_cap_rejects_oversized_and_restores_replaced() {
    let state = dns_state("dns-resp-oversize-replace").await;

    // Pre-populate an entry for agent 42.
    let original_chunks = vec!["ORIGINAL".to_owned()];
    {
        let mut responses = state.responses.lock().await;
        responses.insert(
            42,
            DnsPendingResponse { chunks: original_chunks, received_at: Instant::now() },
        );
    }

    // Try to replace agent 42's entry with an oversized response.
    let half = DNS_MAX_PENDING_RESPONSE_BYTES / 2;
    let oversized_chunks = vec!["X".repeat(half), "X".repeat(half + 1)];

    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 42, &oversized_chunks, "test");
        assert!(!accepted, "oversized replacement must be rejected");
        // The original entry should be restored.
        assert!(responses.contains_key(&42), "original entry must be restored");
        assert_eq!(
            responses.get(&42).expect("agent 42").chunks[0],
            "ORIGINAL",
            "restored entry must have original data"
        );
    }
}

#[test]
fn dns_pending_response_bytes_computes_correctly() {
    let mut map = HashMap::new();
    map.insert(
        1,
        DnsPendingResponse {
            chunks: vec!["ABC".to_owned(), "DE".to_owned()],
            received_at: Instant::now(),
        },
    );
    map.insert(
        2,
        DnsPendingResponse { chunks: vec!["FGHIJ".to_owned()], received_at: Instant::now() },
    );
    // "ABC" (3) + "DE" (2) + "FGHIJ" (5) = 10
    assert_eq!(DnsListenerState::pending_response_bytes(&map), 10);
}

#[tokio::test]
async fn dns_listener_refuses_axfr_query() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-axfr-refused".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;
    sleep(Duration::from_millis(50)).await;
    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");
    let packet = build_dns_query(0xAF01, "c2.example.com", DNS_QTYPE_AXFR);
    client.send(&packet).await.expect("send failed");
    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");
    assert_eq!(buf[3] & 0x0F, 5, "AXFR must receive REFUSED RCODE");
    handle.abort();
}

/// An ANY query (qtype=255) must receive REFUSED without attempting C2 parsing.
#[tokio::test]
async fn dns_listener_refuses_any_query() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-any-refused".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;
    sleep(Duration::from_millis(50)).await;
    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");
    let packet = build_dns_query(0xAF02, "c2.example.com", DNS_QTYPE_ANY);
    client.send(&packet).await.expect("send failed");
    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");
    assert_eq!(buf[3] & 0x0F, 5, "ANY must receive REFUSED RCODE");
    handle.abort();
}

/// After MAX_DNS_RECON_QUERIES_PER_IP AXFR/ANY queries the limiter must
/// stop allowing further queries from that IP (returns false).
#[tokio::test]
async fn dns_recon_block_limiter_stops_responding_after_threshold() {
    let peer_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let limiter = DnsReconBlockLimiter::new();
    for i in 0..MAX_DNS_RECON_QUERIES_PER_IP {
        assert!(limiter.allow(peer_ip).await, "query {i} should be allowed (below threshold)");
    }
    assert!(!limiter.allow(peer_ip).await, "query beyond threshold should be blocked");
    let other_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    assert!(limiter.allow(other_ip).await, "different IP should still be allowed");
}

/// After the window expires the IP counter resets and the IP is allowed again.
#[tokio::test]
async fn dns_recon_block_limiter_resets_after_window_expires() {
    let peer_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let limiter = DnsReconBlockLimiter::new();
    for _ in 0..=MAX_DNS_RECON_QUERIES_PER_IP {
        limiter.allow(peer_ip).await;
    }
    assert!(!limiter.allow(peer_ip).await, "should be blocked before window resets");
    {
        let mut windows = limiter.windows.lock().await;
        if let Some(w) = windows.get_mut(&peer_ip) {
            w.window_start = Instant::now()
                .checked_sub(DNS_RECON_WINDOW_DURATION + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }
    assert!(limiter.allow(peer_ip).await, "IP should be allowed again after recon window expires");
}

/// The limiter tracks distinct IPs correctly.
#[tokio::test]
async fn dns_recon_block_limiter_tracks_ip_count() {
    let limiter = DnsReconBlockLimiter::new();
    assert_eq!(limiter.tracked_ip_count().await, 0);
    let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    limiter.allow(ip1).await;
    assert_eq!(limiter.tracked_ip_count().await, 1);
    limiter.allow(ip2).await;
    assert_eq!(limiter.tracked_ip_count().await, 2);
    limiter.allow(ip1).await;
    assert_eq!(limiter.tracked_ip_count().await, 2);
}

/// Once the threshold is exceeded handle_dns_packet must return None
/// (drop without response) rather than returning a REFUSED packet.
#[tokio::test]
async fn dns_state_drops_axfr_from_repeat_offender_without_response() {
    let state = dns_state("dns-recon-drop").await;
    let peer_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    for _ in 0..MAX_DNS_RECON_QUERIES_PER_IP {
        let packet = build_dns_query(0x1000, "c2.example.com", DNS_QTYPE_AXFR);
        let resp = state.handle_dns_packet(&packet, peer_ip).await;
        assert!(resp.is_some(), "within-threshold AXFR should receive REFUSED");
        assert_eq!(resp.unwrap()[3] & 0x0F, 5, "within-threshold AXFR RCODE must be REFUSED");
    }
    let packet = build_dns_query(0x1001, "c2.example.com", DNS_QTYPE_AXFR);
    let resp = state.handle_dns_packet(&packet, peer_ip).await;
    assert!(resp.is_none(), "repeat offender AXFR must be dropped without response");
}
