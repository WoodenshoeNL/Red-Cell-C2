//! Demon body buffering, magic pre-check, and transport classification.

use std::net::IpAddr;

use axum::body::{Body, Bytes};
use red_cell_common::demon::{
    ArchonEnvelope, ArchonHeader, DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonHeader,
};
use tracing::warn;

use crate::listeners::{
    DEMON_INIT_WINDOW_DURATION, DemonInitRateLimiter, MAX_DEMON_INIT_ATTEMPTS_PER_IP,
};

pub(crate) const MINIMUM_DEMON_CALLBACK_BYTES: usize = DemonHeader::SERIALIZED_LEN + 8;

/// Minimum bytes buffered before the non-legacy shape precheck fires.
///
/// Equals the full Archon header length (size | agent_id | magic = 12 bytes).
/// For **`legacy_mode = false`**, once these bytes are available the declared
/// Archon frame length (`4 + size` with `size` from the first four bytes) is
/// used as a streaming cap whenever it is at least this many bytes, so garbage
/// that claims a short frame cannot drive buffering up to the global agent
/// message cap (`crate::MAX_AGENT_MESSAGE_LEN`).
pub(crate) const NONLEGACY_PRECHECK_HEADER_LEN: usize = ArchonHeader::SERIALIZED_LEN; // 12

/// Buffers an HTTP request body while performing an early pre-screen on the
/// Demon transport magic value.
///
/// The `legacy_mode` flag controls how the magic check is applied:
///
/// - **`legacy_mode = true`** (Demon listeners): bytes 4–7 of the Demon wire
///   format carry the fixed magic `0xDEADBEEF`.  The body is accepted only if
///   those bytes match; anything else is rejected immediately after the first
///   8 bytes have been buffered, limiting per-connection allocation to a single
///   network chunk (~16 KiB).
///
/// - **`legacy_mode = false`** (new-protocol listeners): bytes 4–7 are the
///   Archon `agent_id` (not fixed) and bytes 8–11 are the per-build magic, so
///   there is no fixed prefix to compare against like legacy Demon.  After
///   [`NONLEGACY_PRECHECK_HEADER_LEN`] bytes, the Archon `size` field is
///   interpreted as an **exclusive** total byte count (`4 + size`, matching
///   [`ArchonEnvelope::from_bytes`]): further buffering is capped to that value
///   (and never beyond `max_len`).  If `4 + size` is below 12, the prefix cannot
///   be Archon-framed (it is treated as ECDH key material or noise), and the
///   stream keeps using the caller's `max_len` cap only.  This closes a
///   pre-auth memory DoS where a client matched the listener but sent a huge
///   body whose header claimed a small packet.  Legitimate Archon payloads and
///   ECDH registration/session packets retain prior behaviour.
///
/// Returns `None` if the body exceeds `max_len`, contains a read error, or
/// fails the appropriate magic check.
pub(crate) async fn collect_body_with_magic_precheck(
    body: Body,
    max_len: usize,
    legacy_mode: bool,
) -> Option<Bytes> {
    use http_body_util::BodyExt as _;

    // Precheck fires after this many bytes: 8 for legacy (bytes 4–7),
    // 12 for non-legacy (full Archon header).
    let precheck_threshold = if legacy_mode { 8 } else { NONLEGACY_PRECHECK_HEADER_LEN };

    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    let mut magic_checked = false;
    let mut effective_max = max_len;

    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        let Ok(data) = frame.into_data() else {
            // Trailers and other non-data frames are skipped.
            continue;
        };
        let data = data.as_ref();
        let next_len = buf.len().checked_add(data.len())?;

        if magic_checked {
            if next_len > effective_max || next_len > max_len {
                return None;
            }
            buf.extend_from_slice(data);
            continue;
        }

        if next_len < precheck_threshold {
            if next_len > max_len {
                return None;
            }
            buf.extend_from_slice(data);
            continue;
        }

        if buf.len() < precheck_threshold {
            // First frame that crosses the threshold: peek the fixed header
            // and apply the non-legacy Archon declared-length cap **before**
            // accepting bodies larger than the claimed frame (or rejecting
            // invalid legacy magic) without buffering the overrun in `buf`.
            let mut hdr = [0_u8; NONLEGACY_PRECHECK_HEADER_LEN];
            hdr[..buf.len()].copy_from_slice(&buf);
            let from_data = precheck_threshold - buf.len();
            let hdr_tail = hdr.get_mut(buf.len()..precheck_threshold)?;
            hdr_tail.copy_from_slice(data.get(..from_data)?);

            if legacy_mode {
                if hdr[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
                    return None;
                }
            } else {
                let declared = u32::from_be_bytes(hdr[0..4].try_into().ok()?);
                let archon_claim = 4usize.checked_add(declared as usize)?;
                if archon_claim > max_len {
                    return None;
                }
                effective_max = if archon_claim < NONLEGACY_PRECHECK_HEADER_LEN {
                    max_len
                } else {
                    archon_claim
                };
            }

            if next_len > effective_max || next_len > max_len {
                return None;
            }
            buf.extend_from_slice(data);
            magic_checked = true;
            continue;
        }

        // Unreachable unless `precheck_threshold == 0` (it is not).
        return None;
    }

    // Bodies shorter than 8 (legacy) or 12 (non-legacy) bytes cannot carry
    // a valid header.
    if !magic_checked {
        return None;
    }

    Some(Bytes::from(buf))
}

/// Validate a legacy Demon callback body (header layout: size | magic=0xDEADBEEF | agent_id).
pub(crate) fn is_valid_demon_callback_request(body: &[u8]) -> bool {
    if body.len() < MINIMUM_DEMON_CALLBACK_BYTES {
        return false;
    }

    if body[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
        return false;
    }

    DemonHeader::from_bytes(body).is_ok()
}

/// Validate an Archon callback body (header layout: size | agent_id | magic=random).
///
/// For Archon packets, bytes 4–7 are the agent_id (not magic), and bytes 8–11 are the
/// per-build random magic.  We can only check minimum length and that the magic is not
/// `0xDEADBEEF` (which would indicate a mis-routed Demon packet).  Per-agent magic
/// validation happens later in [`DemonPacketParser`] before AES decryption.
pub(crate) fn is_valid_archon_callback_request(body: &[u8]) -> bool {
    if body.len() < MINIMUM_DEMON_CALLBACK_BYTES {
        return false;
    }
    // Reject any packet with the Demon fingerprint at the magic position (bytes 8-11).
    body[8..12] != DEMON_MAGIC_VALUE.to_be_bytes()
}

/// Validate a callback body using the appropriate check for the listener mode.
pub(crate) fn is_valid_callback_request(body: &[u8], legacy_mode: bool) -> bool {
    if legacy_mode {
        is_valid_demon_callback_request(body)
    } else {
        is_valid_archon_callback_request(body)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemonTransportKind {
    Init,
    Reconnect,
    Callback,
}

pub(crate) fn classify_demon_transport(
    body: &[u8],
    legacy_mode: bool,
) -> Option<DemonTransportKind> {
    let payload = if legacy_mode {
        DemonEnvelope::from_bytes(body).ok()?.payload
    } else {
        ArchonEnvelope::from_bytes(body).ok()?.payload
    };

    if payload.len() < 8 {
        return None;
    }

    let command_id = u32::from_be_bytes(payload[0..4].try_into().ok()?);
    if command_id != u32::from(DemonCommand::DemonInit) {
        return Some(DemonTransportKind::Callback);
    }

    let remaining = &payload[8..];
    if remaining.is_empty() {
        Some(DemonTransportKind::Reconnect)
    } else {
        Some(DemonTransportKind::Init)
    }
}

pub(crate) async fn allow_demon_init_for_ip(
    listener_name: &str,
    rate_limiter: &DemonInitRateLimiter,
    client_ip: IpAddr,
    body: &[u8],
    legacy_mode: bool,
) -> bool {
    if classify_demon_transport(body, legacy_mode) != Some(DemonTransportKind::Init) {
        return true;
    }

    if rate_limiter.allow(client_ip).await {
        return true;
    }

    warn!(
        listener = listener_name,
        client_ip = %client_ip,
        max_attempts = MAX_DEMON_INIT_ATTEMPTS_PER_IP,
        window_seconds = DEMON_INIT_WINDOW_DURATION.as_secs(),
        "rejecting DEMON_INIT because the per-IP rate limit was exceeded"
    );
    false
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use red_cell_common::demon::{ArchonEnvelope, DemonCommand, DemonEnvelope};

    use super::*;
    use crate::listeners::{DemonInitRateLimiter, MAX_DEMON_INIT_ATTEMPTS_PER_IP};

    /// Build a minimal DEMON_INIT payload (command_id + request_id + 1 extra byte).
    fn demon_init_payload() -> Vec<u8> {
        let command_id: u32 = u32::from(DemonCommand::DemonInit);
        let mut p = Vec::with_capacity(9);
        p.extend_from_slice(&command_id.to_be_bytes());
        p.extend_from_slice(&0_u32.to_be_bytes()); // request_id
        p.push(0xFF); // non-empty → Init (not Reconnect)
        p
    }

    fn make_legacy_init_packet() -> Vec<u8> {
        DemonEnvelope::new(1, demon_init_payload()).unwrap().to_bytes()
    }

    fn make_archon_init_packet(magic: u32) -> Vec<u8> {
        ArchonEnvelope::new(1, magic, demon_init_payload()).unwrap().to_bytes()
    }

    // ── classify_demon_transport ────────────────────────────────────────────

    #[test]
    fn classify_legacy_init_legacy_mode() {
        let pkt = make_legacy_init_packet();
        assert_eq!(classify_demon_transport(&pkt, true), Some(DemonTransportKind::Init));
    }

    #[test]
    fn classify_archon_init_rejects_legacy_parser() {
        // An Archon packet must return None when parsed in legacy mode because
        // bytes 4-7 are agent_id (not 0xDEADBEEF), which DemonEnvelope::from_bytes rejects.
        let pkt = make_archon_init_packet(0xCAFEBABE);
        assert_eq!(classify_demon_transport(&pkt, true), None);
    }

    #[test]
    fn classify_archon_init_non_legacy_mode() {
        let pkt = make_archon_init_packet(0xCAFEBABE);
        assert_eq!(classify_demon_transport(&pkt, false), Some(DemonTransportKind::Init));
    }

    // ── allow_demon_init_for_ip (Archon rate-limiter regression) ───────────

    #[tokio::test]
    async fn archon_init_hits_rate_limiter_on_non_legacy_listener() {
        let rl = DemonInitRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let magic = 0xCAFEBABE;
        let pkt = make_archon_init_packet(magic);

        // Exhaust the per-IP budget.
        for _ in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            let allowed = allow_demon_init_for_ip("test-listener", &rl, ip, &pkt, false).await;
            assert!(allowed, "should be allowed while under budget");
        }

        // The next attempt must be blocked.
        let blocked = allow_demon_init_for_ip("test-listener", &rl, ip, &pkt, false).await;
        assert!(!blocked, "Archon DEMON_INIT must be blocked after budget is exhausted");
    }

    #[tokio::test]
    async fn archon_init_bypassed_limiter_when_misclassified_as_legacy() {
        // This test documents the bug: if we incorrectly called the legacy classifier
        // for an Archon packet, classify_demon_transport would return None and
        // allow_demon_init_for_ip would return true (bypass) even after budget exhaustion.
        // With the fix, non-legacy mode uses the Archon parser and the limiter fires.
        let rl = DemonInitRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let pkt = make_archon_init_packet(0xABCDABCD);

        // Exhaust budget using the corrected non-legacy classifier.
        for _ in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            allow_demon_init_for_ip("test-listener", &rl, ip, &pkt, false).await;
        }

        // Verify legacy_mode=true would have classified the same packet as None
        // (bypass path), while the fixed non-legacy path correctly blocks.
        assert_eq!(
            classify_demon_transport(&pkt, true),
            None,
            "legacy parser must reject Archon packet"
        );
        let blocked = allow_demon_init_for_ip("test-listener", &rl, ip, &pkt, false).await;
        assert!(!blocked, "non-legacy classifier must block after budget exhaustion");
    }

    #[tokio::test]
    async fn non_init_archon_packet_not_rate_limited() {
        let rl = DemonInitRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        // Build an Archon callback packet (command_id != DemonInit).
        let mut callback_payload = Vec::with_capacity(8);
        callback_payload.extend_from_slice(&0_u32.to_be_bytes()); // command_id = 0
        callback_payload.extend_from_slice(&0_u32.to_be_bytes());
        let pkt = ArchonEnvelope::new(1, 0xCAFEBABE, callback_payload).unwrap().to_bytes();

        // Non-init packets should always pass regardless of how many times they hit.
        for _ in 0..(MAX_DEMON_INIT_ATTEMPTS_PER_IP + 5) {
            let allowed = allow_demon_init_for_ip("test-listener", &rl, ip, &pkt, false).await;
            assert!(allowed, "non-init Archon packets must never be rate-limited");
        }
    }

    // ── collect_body_with_magic_precheck — DEADBEEF collision regression ───

    fn make_body(bytes: Vec<u8>) -> Body {
        Body::from(Bytes::from(bytes))
    }

    /// Archon packet whose agent_id == 0xDEADBEEF must NOT be rejected by a
    /// non-legacy listener's precheck (regression for the bug fixed in hxg94).
    #[tokio::test]
    async fn archon_agent_id_deadbeef_passes_non_legacy_precheck() {
        let envelope = ArchonEnvelope::new(0xDEAD_BEEF, 0xCAFE_BABE, demon_init_payload()).unwrap();
        let raw = envelope.to_bytes();
        assert_eq!(&raw[4..8], &0xDEAD_BEEFu32.to_be_bytes());

        let result = collect_body_with_magic_precheck(make_body(raw), usize::MAX, false).await;
        assert!(
            result.is_some(),
            "Archon packet with agent_id=0xDEADBEEF must pass the non-legacy precheck"
        );
    }

    /// Legacy listener must still reject an Archon packet (bytes 4-7 != 0xDEADBEEF).
    #[tokio::test]
    async fn archon_packet_rejected_by_legacy_precheck() {
        let envelope = ArchonEnvelope::new(0x0000_0001, 0xCAFE_BABE, demon_init_payload()).unwrap();
        let raw = envelope.to_bytes();
        let result = collect_body_with_magic_precheck(make_body(raw), usize::MAX, true).await;
        assert!(result.is_none(), "legacy precheck must reject Archon packets");
    }

    /// ECDH packet whose connection_id bytes equal 0xDEADBEEF must pass the
    /// non-legacy precheck — those bytes are random key/id material, not magic.
    #[tokio::test]
    async fn ecdh_packet_deadbeef_collision_passes_non_legacy_precheck() {
        // bytes 4-7 == 0xDEADBEEF (was never caught, but verify it still passes)
        let mut raw = vec![0u8; 32];
        raw[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let result = collect_body_with_magic_precheck(make_body(raw), usize::MAX, false).await;
        assert!(
            result.is_some(),
            "ECDH packet with connection_id[4..8]=0xDEADBEEF must pass the non-legacy precheck"
        );

        // bytes 8-11 == 0xDEADBEEF (the actual regression from red-cell-c2-5rd8q)
        let mut raw2 = vec![0u8; 32];
        raw2[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let result2 = collect_body_with_magic_precheck(make_body(raw2), usize::MAX, false).await;
        assert!(
            result2.is_some(),
            "ECDH packet with connection_id[8..12]=0xDEADBEEF must pass the non-legacy precheck"
        );
    }

    /// A real legacy Demon packet must still be accepted by the legacy precheck.
    #[tokio::test]
    async fn legacy_demon_packet_accepted_by_legacy_precheck() {
        let raw = make_legacy_init_packet();
        let result = collect_body_with_magic_precheck(make_body(raw), usize::MAX, true).await;
        assert!(result.is_some(), "legacy Demon packet must pass the legacy precheck");
    }

    /// A body shorter than 8 bytes must be rejected regardless of mode.
    #[tokio::test]
    async fn short_body_rejected() {
        for legacy_mode in [true, false] {
            let result =
                collect_body_with_magic_precheck(make_body(vec![0u8; 7]), usize::MAX, legacy_mode)
                    .await;
            assert!(
                result.is_none(),
                "body < 8 bytes must be rejected (legacy_mode={legacy_mode})"
            );
        }
    }

    // ── non-legacy early precheck — minimum-length gate ──

    /// Bodies of 8–11 bytes must be rejected in non-legacy mode because the
    /// non-legacy precheck fires at NONLEGACY_PRECHECK_HEADER_LEN (12) bytes.
    #[tokio::test]
    async fn nonlegacy_body_8_to_11_bytes_rejected() {
        for len in 8..=11 {
            let result =
                collect_body_with_magic_precheck(make_body(vec![0u8; len]), usize::MAX, false)
                    .await;
            assert!(result.is_none(), "non-legacy body of {len} bytes must be rejected");
        }
    }

    /// A non-legacy body whose bytes 8–11 equal DEMON_MAGIC_VALUE must be
    /// accepted by the precheck — the precheck does not inspect magic for
    /// non-legacy packets; downstream parsers classify by packet type.
    #[tokio::test]
    async fn nonlegacy_deadbeef_at_archon_magic_position_passes_precheck() {
        let mut raw = vec![0u8; 1024];
        raw[8..12].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());

        let result = collect_body_with_magic_precheck(make_body(raw), usize::MAX, false).await;
        assert!(
            result.is_some(),
            "non-legacy precheck must not reject on bytes 8–11; downstream handles classification"
        );
    }

    /// A body that passes the legacy precheck (bytes 4–7 = 0xDEADBEEF) must
    /// also pass the non-legacy precheck — non-legacy has no magic gate.
    #[tokio::test]
    async fn legacy_magic_body_passes_nonlegacy_precheck() {
        let mut raw = vec![0u8; 32];
        raw[4..8].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());
        raw[8..12].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());

        // Legacy precheck: bytes 4–7 = 0xDEADBEEF → passes.
        let legacy_result =
            collect_body_with_magic_precheck(make_body(raw.clone()), usize::MAX, true).await;
        assert!(legacy_result.is_some(), "body with DEADBEEF at bytes 4–7 must pass legacy check");

        // Non-legacy precheck: no magic gate → also passes.
        let nonlegacy_result =
            collect_body_with_magic_precheck(make_body(raw), usize::MAX, false).await;
        assert!(
            nonlegacy_result.is_some(),
            "non-legacy precheck must not gate on bytes 8–11 (ECDH/Archon magic position)"
        );
    }

    /// max_len is the only early-termination mechanism for non-legacy bodies;
    /// a body exceeding it must be rejected regardless of magic bytes.
    #[tokio::test]
    async fn nonlegacy_body_exceeding_max_len_rejected() {
        use axum::body::Body;
        use futures_util::stream;

        let stream = stream::iter([
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![
                0u8;
                NONLEGACY_PRECHECK_HEADER_LEN
            ])),
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![0xABu8; 4096])),
        ]);
        let body = Body::from_stream(stream);

        // max_len = 12 (exactly the first frame) — second frame pushes past it.
        let result =
            collect_body_with_magic_precheck(body, NONLEGACY_PRECHECK_HEADER_LEN, false).await;
        assert!(result.is_none(), "non-legacy body exceeding max_len must be rejected");
    }

    /// Regression (red-cell-c2-8mp6v): declared Archon frame length is smaller than
    /// the bytes the client sends — reject without buffering to `max_len`.
    #[tokio::test]
    async fn nonlegacy_rejects_oversize_stream_against_archon_declared_total() {
        use axum::body::Body;
        use futures_util::stream;

        // `4 + u32_be(size_field) == 100` → size field = 96.
        let mut hdr = vec![0u8; 12];
        hdr[0..4].copy_from_slice(&96u32.to_be_bytes());
        let stream = stream::iter([
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(hdr)),
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![0xABu8; 500])),
        ]);
        let result =
            collect_body_with_magic_precheck(Body::from_stream(stream), usize::MAX, false).await;
        assert!(result.is_none());
    }
}
