//! DNS wire-format parsing, encoding, and response-building helpers.

use super::{
    BASE32_RFC4648_ALPHABET, BASE32HEX_ALPHABET, DNS_CLASS_IN, DNS_DOH_RESPONSE_CHUNK_BYTES,
    DNS_DOH_SESSION_HEX_LEN, DNS_FLAG_AA, DNS_FLAG_QR, DNS_HEADER_LEN, DNS_MAX_DOMAIN_WIRE_LEN,
    DNS_MAX_LABEL_LEN, DNS_RCODE_NOERROR, DNS_RCODE_NXDOMAIN, DNS_RCODE_REFUSED,
    DNS_RESPONSE_CHUNK_BYTES, DNS_TYPE_A, DNS_TYPE_CNAME, DNS_TYPE_TXT,
};

/// A parsed DNS C2 query from a Demon agent.
#[derive(Debug)]
pub(crate) enum DnsC2Query {
    /// Upload chunk: `<b32hex-data>.<seq>-<total>-<agentid>.up.<domain>`
    Upload { agent_id: u32, seq: u16, total: u16, data: Vec<u8> },
    /// Download request: `<seq>-<agentid>.dn.<domain>`
    Download { agent_id: u32, seq: u16 },
    /// DoH uplink chunk (RFC4648 base32): `<b32>.<seq:04x><total:04x>.<session>.u.<domain>`
    DohUpload { session: String, seq: u16, total: u16, data: Vec<u8> },
    /// DoH ready poll: `rdy.<session>.d.<domain>`
    DohReady { session: String },
    /// DoH chunk fetch: `<seq:04x>.<session>.d.<domain>`
    DohDownload { session: String, seq: u16 },
}

/// A minimally parsed DNS query sufficient for C2 processing.
pub(crate) struct ParsedDnsQuery {
    pub(crate) id: u16,
    /// Raw wire-format QNAME bytes (including final zero label).
    pub(crate) qname_raw: Vec<u8>,
    /// Lowercase parsed labels.
    pub(crate) labels: Vec<String>,
    pub(crate) qtype: u16,
}

pub(crate) fn dns_allowed_query_types(record_types: &[String]) -> Option<Vec<u16>> {
    let configured =
        if record_types.is_empty() { vec!["TXT".to_owned()] } else { record_types.to_vec() };

    let mut allowed = Vec::new();
    for record_type in configured {
        let qtype = match record_type.trim().to_ascii_uppercase().as_str() {
            "A" => DNS_TYPE_A,
            "TXT" => DNS_TYPE_TXT,
            "CNAME" => DNS_TYPE_CNAME,
            _ => return None,
        };

        if !allowed.contains(&qtype) {
            allowed.push(qtype);
        }
    }

    Some(allowed)
}

/// Parse the first question from a raw DNS UDP payload.
///
/// Returns `None` if the packet is malformed or has ≠ 1 question.
pub(crate) fn parse_dns_query(buf: &[u8]) -> Option<ParsedDnsQuery> {
    if buf.len() < DNS_HEADER_LEN {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & DNS_FLAG_QR != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    if qdcount != 1 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let qname_start = pos;
    let mut labels = Vec::new();

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = usize::from(buf[pos]);
        if len == 0 {
            pos += 1;
            break;
        }
        // Reject DNS pointer compression in queries (not expected in client queries)
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos..pos + len]).ok()?.to_ascii_lowercase();
        labels.push(label);
        pos += len;
    }

    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qname_raw = buf[qname_start..pos].to_vec();

    Some(ParsedDnsQuery { id, qname_raw, labels, qtype })
}

/// Parse DNS labels into a [`DnsC2Query`] if they match the expected C2 format.
///
/// Expected formats (labels listed from leftmost to rightmost, domain stripped):
/// * Legacy upload: `["<b32hex>", "<seq>-<total>-<aid>", "up"]`
/// * Legacy download: `["<seq>-<aid>", "dn"]`
/// * DoH upload: `["<b32>", "<seq:04x><total:04x>", "<session_hex16>", "u"]`
/// * DoH ready: `["rdy", "<session_hex16>", "d"]`
/// * DoH chunk: `["<seq:04x>", "<session_hex16>", "d"]`
///
/// DoH session labels are **16 hex digits** (ASCII); case is normalized to lowercase when
/// matching Specter/Archon (`agent/specter/src/doh_transport.rs`, `TransportDoH.c`).
pub(crate) fn parse_dns_c2_query(labels: &[String], domain: &str) -> Option<DnsC2Query> {
    let domain_labels: Vec<&str> = domain.split('.').collect();
    let domain_label_count = domain_labels.len();

    if labels.len() <= domain_label_count {
        return None;
    }

    let suffix = &labels[labels.len() - domain_label_count..];
    if suffix.iter().zip(domain_labels.iter()).any(|(a, b)| a != b) {
        return None;
    }

    let c2_labels = &labels[..labels.len() - domain_label_count];

    match c2_labels.len() {
        4 => {
            let b32data = c2_labels.first()?;
            let seqtotal = c2_labels.get(1)?;
            let session = c2_labels.get(2)?;
            let u = c2_labels.get(3)?;
            if u != "u" || seqtotal.len() != 8 {
                return None;
            }
            let seq = u16::from_str_radix(&seqtotal[..4], 16).ok()?;
            let total = u16::from_str_radix(&seqtotal[4..], 16).ok()?;
            let data = base32_rfc4648_decode(b32data)?;
            let session = normalize_session_hex16(session)?;
            Some(DnsC2Query::DohUpload { session, seq, total, data })
        }
        3 => {
            let a = c2_labels.first()?;
            let b = c2_labels.get(1)?;
            let c = c2_labels.get(2)?;
            if a == "rdy" && c == "d" {
                let session = normalize_session_hex16(b)?;
                return Some(DnsC2Query::DohReady { session });
            }
            if c == "up" {
                let parts: Vec<&str> = b.splitn(3, '-').collect();
                if parts.len() != 3 {
                    return None;
                }
                let seq = u16::from_str_radix(parts[0], 16).ok()?;
                let total = u16::from_str_radix(parts[1], 16).ok()?;
                let agent_id = u32::from_str_radix(parts[2], 16).ok()?;
                let data = base32hex_decode(a)?;
                return Some(DnsC2Query::Upload { agent_id, seq, total, data });
            }
            if c == "d" && a.len() == 4 {
                let session = normalize_session_hex16(b)?;
                let seq = u16::from_str_radix(a, 16).ok()?;
                return Some(DnsC2Query::DohDownload { session, seq });
            }
            None
        }
        2 => {
            let ctrl = c2_labels.first()?;
            let dn = c2_labels.get(1)?;
            if dn != "dn" {
                return None;
            }
            let parts: Vec<&str> = ctrl.splitn(2, '-').collect();
            if parts.len() != 2 {
                return None;
            }
            let seq = u16::from_str_radix(parts[0], 16).ok()?;
            let agent_id = u32::from_str_radix(parts[1], 16).ok()?;
            Some(DnsC2Query::Download { agent_id, seq })
        }
        _ => None,
    }
}

/// Normalize a 16-character session id (8 bytes as hex) to lowercase.
///
/// Specter and Archon emit lowercase hex, but DNS labels are case-insensitive; callers may
/// observe uppercase `A`–`F`.  Pending DoH state is keyed by session — canonicalize so lookups
/// match regardless of wire casing.
pub(crate) fn normalize_session_hex16(s: &str) -> Option<String> {
    if s.len() != DNS_DOH_SESSION_HEX_LEN {
        return None;
    }
    let mut out = String::with_capacity(DNS_DOH_SESSION_HEX_LEN);
    for c in s.chars() {
        if !c.is_ascii_hexdigit() {
            return None;
        }
        out.push(c.to_ascii_lowercase());
    }
    Some(out)
}

/// Encode bytes as lowercase RFC 4648 base32 (no padding).
pub(crate) fn base32_rfc4648_encode(data: &[u8]) -> String {
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
            out.push(BASE32_RFC4648_ALPHABET[((buf >> bits) & 0x1F) as usize]);
        }
    }
    if bits > 0 {
        out.push(BASE32_RFC4648_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]);
    }
    // SAFETY: alphabet is ASCII.
    String::from_utf8(out).unwrap_or_default()
}

/// Decode lowercase RFC 4648 base32 (no padding). Rejects invalid characters.
pub(crate) fn base32_rfc4648_decode(s: &str) -> Option<Vec<u8>> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.chars() {
        let val = match ch {
            'a'..='z' => u64::from(ch as u8 - b'a'),
            '2'..='7' => u64::from(ch as u8 - b'2' + 26),
            _ => return None,
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u64 << bits).saturating_sub(1);
        }
    }
    Some(out)
}

/// Split a Demon response payload into RFC4648 base32 chunks for DoH DNS delivery.
pub(crate) fn chunk_response_to_doh_b32(payload: &[u8]) -> Vec<String> {
    payload.chunks(DNS_DOH_RESPONSE_CHUNK_BYTES).map(base32_rfc4648_encode).collect()
}

/// Encode `data` as uppercase base32hex (RFC 4648 §7) with no padding.
pub(crate) fn base32hex_encode(data: &[u8]) -> String {
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
        result.push(char::from(BASE32HEX_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]));
    }

    result
}

/// Decode a base32hex string (case-insensitive, no padding) into bytes.
///
/// Returns `None` if any character is outside the base32hex alphabet.
pub(crate) fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for ch in s.bytes() {
        let val = match ch {
            b'0'..=b'9' => u32::from(ch - b'0'),
            b'a'..=b'v' => u32::from(ch - b'a' + 10),
            b'A'..=b'V' => u32::from(ch - b'A' + 10),
            _ => return None,
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }

    Some(result)
}

/// Split a Demon response payload into base32hex-encoded chunks for DNS delivery.
pub(crate) fn chunk_response_to_b32hex(payload: &[u8]) -> Vec<String> {
    payload.chunks(DNS_RESPONSE_CHUNK_BYTES).map(base32hex_encode).collect()
}

/// Encode `payload` as a DNS wire-format domain name (length-prefixed labels, root terminator).
///
/// The payload is split into labels of at most [`DNS_MAX_LABEL_LEN`] octets. Used for CNAME
/// RDATA so arbitrary C2 strings (base32hex chunks, status tokens) fit in a single RR.
pub(crate) fn dns_wire_domain_from_ascii_payload(payload: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if payload.is_empty() {
        out.push(1);
        out.push(b'0');
        out.push(0);
        return Some(out);
    }
    for chunk in payload.as_bytes().chunks(DNS_MAX_LABEL_LEN) {
        let len = chunk.len();
        let len_u8 = u8::try_from(len).ok()?;
        out.push(len_u8);
        out.extend_from_slice(chunk);
        if out.len() > DNS_MAX_DOMAIN_WIRE_LEN {
            return None;
        }
    }
    if out.len() + 1 > DNS_MAX_DOMAIN_WIRE_LEN {
        return None;
    }
    out.push(0);
    Some(out)
}

/// Build a DNS response for `query_id` carrying C2 `payload` in an answer RR matching `qtype`.
///
/// The question section is reconstructed from `qname_raw` (which already includes the
/// zero-label terminator). The answer uses a NAME pointer to offset 12 (start of the question
/// QNAME).
///
/// Returns `None` when the payload cannot be represented for the requested type (for example,
/// more than four octets for `A`).
pub(crate) fn build_dns_c2_response(
    query_id: u16,
    qname_raw: &[u8],
    qtype: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let (answer_type, rdata): (u16, Vec<u8>) = match qtype {
        DNS_TYPE_TXT => {
            // Clamp TXT data to 255 bytes (single TXT string limit per RFC 1035).
            let txt_data = &payload[..payload.len().min(255)];
            let mut rdata = Vec::with_capacity(1 + txt_data.len());
            rdata.push(txt_data.len() as u8);
            rdata.extend_from_slice(txt_data);
            (DNS_TYPE_TXT, rdata)
        }
        DNS_TYPE_A => {
            if payload.len() > 4 {
                return None;
            }
            let mut rdata = [0u8; 4];
            rdata[..payload.len()].copy_from_slice(payload);
            (DNS_TYPE_A, rdata.to_vec())
        }
        DNS_TYPE_CNAME => {
            let s = std::str::from_utf8(payload).ok()?;
            let rdata = dns_wire_domain_from_ascii_payload(s)?;
            (DNS_TYPE_CNAME, rdata)
        }
        _ => return None,
    };

    let rdlength = u16::try_from(rdata.len()).ok()?;

    let mut response =
        Vec::with_capacity(DNS_HEADER_LEN + qname_raw.len() + 4 + 2 + 2 + 2 + 4 + 2 + rdata.len());

    // Header (12 bytes)
    response.extend_from_slice(&query_id.to_be_bytes());
    let flags: u16 = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NOERROR;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // qdcount = 1
    response.extend_from_slice(&1u16.to_be_bytes()); // ancount = 1
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount = 0
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount = 0

    // Question section: QNAME + QTYPE + QCLASS
    response.extend_from_slice(qname_raw);
    response.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // QCLASS

    // Answer RR
    // NAME: pointer to offset 12 (start of QNAME in question), encoded as 0xC00C
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&answer_type.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0 (no caching)
    response.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
    response.extend_from_slice(&rdata);

    Some(response)
}

/// Build a DNS NXDOMAIN response echoing the question (no answer records).
///
/// Used for Specter/Archon DoH uplink acknowledgements and ready-poll "not yet" probes.
pub(crate) fn build_dns_nxdomain_response(query_id: u16, qname_raw: &[u8], qtype: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(DNS_HEADER_LEN + qname_raw.len() + 4);
    response.extend_from_slice(&query_id.to_be_bytes());
    let flags: u16 = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NXDOMAIN;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    response.extend_from_slice(&0u16.to_be_bytes()); // ancount
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount
    response.extend_from_slice(qname_raw);
    response.extend_from_slice(&qtype.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response
}

/// Build a DNS REFUSED response for `query_id`.
pub(crate) fn build_dns_refused_response(query_id: u16) -> Vec<u8> {
    let mut response = vec![0u8; DNS_HEADER_LEN];
    response[0] = (query_id >> 8) as u8;
    response[1] = query_id as u8;
    let flags: u16 = DNS_FLAG_QR | DNS_RCODE_REFUSED;
    response[2] = (flags >> 8) as u8;
    response[3] = flags as u8;
    response
}
