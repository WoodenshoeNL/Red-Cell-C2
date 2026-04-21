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
/// This is the unauthenticated buffering ceiling for non-legacy listeners:
/// bodies that fail the precheck are rejected after at most this many bytes
/// instead of after the full `MAX_AGENT_MESSAGE_LEN` cap.
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
///   Archon `agent_id` (not fixed) and bytes 0–15 are a random ECDH
///   `connection_id`, so the legacy bytes-4–7 check cannot be applied.
///   Instead, the Archon magic field at **bytes 8–11** is checked: it must
///   never equal `0xDEADBEEF` for any valid non-legacy packet (this is also
///   enforced downstream by `is_valid_archon_callback_request`, but checking
///   it here limits unauthenticated buffering to [`NONLEGACY_PRECHECK_HEADER_LEN`]
///   bytes for bodies that would be rejected anyway).  Packets where an ECDH
///   `connection_id[4..8]` or `connection_id[8..12]` coincidentally equals
///   `0xDEADBEEF` are also rejected here — consistent with the downstream
///   validator's behaviour.
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
    // 12 for non-legacy (bytes 8–11 = Archon magic field).
    let precheck_threshold = if legacy_mode { 8 } else { NONLEGACY_PRECHECK_HEADER_LEN };

    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    let mut magic_checked = false;

    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        let Ok(data) = frame.into_data() else {
            // Trailers and other non-data frames are skipped.
            continue;
        };
        if buf.len() + data.len() > max_len {
            return None;
        }
        buf.extend_from_slice(&data);

        if !magic_checked && buf.len() >= precheck_threshold {
            if legacy_mode {
                // Legacy: bytes 4–7 must be 0xDEADBEEF.
                if buf[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
                    return None;
                }
            } else {
                // Non-legacy: bytes 8–11 (Archon magic field) must NOT be
                // 0xDEADBEEF.  Firing here rather than in the downstream
                // validator limits unauthenticated memory use to
                // NONLEGACY_PRECHECK_HEADER_LEN bytes for these bodies.
                if buf[8..12] == DEMON_MAGIC_VALUE.to_be_bytes() {
                    return None;
                }
            }
            magic_checked = true;
        }
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

    /// ECDH packet whose connection_id[4..8] == 0xDEADBEEF must pass the
    /// non-legacy precheck (regression for the bug fixed in hxg94).
    #[tokio::test]
    async fn ecdh_packet_deadbeef_collision_passes_non_legacy_precheck() {
        // Craft a synthetic ECDH-shaped body: 16-byte connection_id with
        // bytes 4-7 == 0xDEADBEEF, followed by enough padding to exceed 8 bytes.
        let mut raw = vec![0u8; 32];
        raw[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let result = collect_body_with_magic_precheck(make_body(raw), usize::MAX, false).await;
        assert!(
            result.is_some(),
            "ECDH packet with connection_id[4..8]=0xDEADBEEF must pass the non-legacy precheck"
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

    // ── non-legacy early precheck — regression tests for the DEADBEEF-at-magic-position fix ──

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
    /// rejected immediately — this is an impossible Archon shape (the Archon
    /// magic field must never be 0xDEADBEEF) and is also rejected by the
    /// downstream is_valid_archon_callback_request validator, but the early
    /// precheck fires at NONLEGACY_PRECHECK_HEADER_LEN bytes rather than
    /// after buffering up to MAX_AGENT_MESSAGE_LEN.
    #[tokio::test]
    async fn nonlegacy_deadbeef_at_archon_magic_position_rejected() {
        // 1 KiB body that would pass the max_len check but carries 0xDEADBEEF
        // at the Archon magic field position (bytes 8–11).
        let mut raw = vec![0u8; 1024];
        raw[8..12].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());

        let result = collect_body_with_magic_precheck(make_body(raw), usize::MAX, false).await;
        assert!(
            result.is_none(),
            "non-legacy body with 0xDEADBEEF at Archon magic position must be rejected"
        );
    }

    /// The same body accepted by legacy precheck must be rejected by the non-legacy
    /// precheck because the Archon magic field (bytes 8–11 = 0xDEADBEEF) is invalid.
    #[tokio::test]
    async fn legacy_magic_body_rejected_by_nonlegacy_precheck() {
        // Build a synthetic body that passes legacy precheck (bytes 4–7 = 0xDEADBEEF)
        // but must be rejected by non-legacy (bytes 8–11 = 0xDEADBEEF).
        let mut raw = vec![0u8; 32];
        raw[4..8].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());
        raw[8..12].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());

        // Legacy precheck fires at bytes 4–7 = 0xDEADBEEF → passes.
        let legacy_result =
            collect_body_with_magic_precheck(make_body(raw.clone()), usize::MAX, true).await;
        assert!(legacy_result.is_some(), "body with DEADBEEF at bytes 4–7 must pass legacy check");

        // Non-legacy precheck fires at bytes 8–11 = 0xDEADBEEF → rejected.
        let nonlegacy_result =
            collect_body_with_magic_precheck(make_body(raw), usize::MAX, false).await;
        assert!(
            nonlegacy_result.is_none(),
            "body with DEADBEEF at Archon magic position must be rejected by non-legacy precheck"
        );
    }

    /// A junk body whose bytes 8–11 equal DEMON_MAGIC_VALUE is rejected after
    /// buffering only NONLEGACY_PRECHECK_HEADER_LEN bytes, not after the full
    /// body.  This test proves the early-rejection property using a streaming
    /// body that would exhaust MAX_AGENT_MESSAGE_LEN if the precheck were
    /// absent.
    #[tokio::test]
    async fn nonlegacy_junk_rejected_before_full_body_accumulation() {
        use axum::body::Body;
        use futures_util::stream;

        // Two-frame body: first frame has the magic at [8..12], second is large junk.
        // Without the early precheck the collector would buffer both frames.
        // With the fix it returns None after the first frame (12+ bytes read).
        let mut header_bytes = vec![0u8; NONLEGACY_PRECHECK_HEADER_LEN];
        header_bytes[8..12].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());

        let stream = stream::iter([
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(header_bytes)),
            // A second frame with valid-looking (non-DEADBEEF) bytes that would
            // normally push the buffer past any reasonable pre-auth ceiling.
            Ok::<Bytes, std::convert::Infallible>(Bytes::from(vec![0xABu8; 4096])),
        ]);
        let body = Body::from_stream(stream);

        let result = collect_body_with_magic_precheck(body, usize::MAX, false).await;
        assert!(
            result.is_none(),
            "non-legacy precheck must reject junk before the second (large) frame is consumed"
        );
    }
}
