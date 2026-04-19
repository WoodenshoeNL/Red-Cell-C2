use super::super::*;
use tokio::task::JoinHandle;

use super::super::super::DnsReconBlockLimiter;
use super::super::super::dns::{
    DNS_DOH_RESPONSE_CHUNK_BYTES, DNS_HEADER_LEN, DNS_MAX_DOWNLOAD_CHUNKS,
    DNS_RESPONSE_CHUNK_BYTES, DNS_TYPE_A, DNS_TYPE_CNAME, DNS_TYPE_TXT, DnsC2Query,
    DnsListenerState, base32_rfc4648_decode, base32_rfc4648_encode, base32hex_decode,
    base32hex_encode, build_dns_c2_response, build_dns_nxdomain_response, chunk_response_to_b32hex,
    chunk_response_to_doh_b32, dns_allowed_query_types, dns_wire_domain_from_ascii_payload,
    parse_dns_c2_query, parse_dns_query, spawn_dns_listener_runtime,
};

pub(super) fn dns_upload_qname(
    agent_id: u32,
    seq: u16,
    total: u16,
    chunk: &[u8],
    domain: &str,
) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Return the TYPE field of the first answer RR (after a single question).
///
/// `qname_raw_len` is the length of the wire-format QNAME in the echoed question
/// (including the root label's zero octet).
pub(super) fn dns_answer_rr_type(packet: &[u8], qname_raw_len: usize) -> Option<u16> {
    let ans_start = DNS_HEADER_LEN.checked_add(qname_raw_len)?.checked_add(4)?;
    let type_off = ans_start.checked_add(2)?;
    let t = packet.get(type_off..type_off + 2)?;
    Some(u16::from_be_bytes([t[0], t[1]]))
}

/// RDATA octets of the first answer RR (single question, compressed NAME pointer).
pub(super) fn dns_answer_rdata(packet: &[u8], qname_raw_len: usize) -> Option<Vec<u8>> {
    let ans_start = DNS_HEADER_LEN.checked_add(qname_raw_len)?.checked_add(4)?;
    let rdlen_off = ans_start.checked_add(2 + 2 + 2 + 4)?;
    let rdlen = u16::from_be_bytes([*packet.get(rdlen_off)?, *packet.get(rdlen_off + 1)?]) as usize;
    let rdata_start = rdlen_off.checked_add(2)?;
    let end = rdata_start.checked_add(rdlen)?;
    Some(packet.get(rdata_start..end)?.to_vec())
}

pub(super) fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
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

pub(super) async fn dns_state(name: &str) -> DnsListenerState {
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
        suppress_opsec_warnings: true,
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

pub(super) async fn spawn_test_dns_listener(
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
pub(super) fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
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

pub(super) fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, DNS_TYPE_TXT)
}

pub(super) fn build_dns_cname_query(id: u16, qname: &str) -> Vec<u8> {
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
