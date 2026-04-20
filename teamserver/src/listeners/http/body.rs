//! Demon body buffering, magic pre-check, and transport classification.

use std::net::IpAddr;

use axum::body::{Body, Bytes};
use red_cell_common::demon::{
    ArchonEnvelope, DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonHeader,
};
use tracing::warn;

use crate::listeners::{
    DEMON_INIT_WINDOW_DURATION, DemonInitRateLimiter, MAX_DEMON_INIT_ATTEMPTS_PER_IP,
};

pub(crate) const MINIMUM_DEMON_CALLBACK_BYTES: usize = DemonHeader::SERIALIZED_LEN + 8;

/// Buffers an HTTP request body while performing an early pre-screen on the
/// Demon transport magic value.
///
/// The Demon magic value (`0xDEADBEEF`) occupies bytes 4–7 of every valid
/// Demon packet.  The `legacy_mode` flag controls how the magic is treated:
///
/// - **`legacy_mode = true`** (Demon listeners): the body is accepted only if
///   bytes 4–7 equal `0xDEADBEEF`.  Any other value causes immediate rejection
///   after the first 8 bytes have been buffered, limiting per-connection
///   allocation to a single network chunk (~16 KiB).
///
/// - **`legacy_mode = false`** (new-protocol listeners): the body is accepted
///   only if bytes 4–7 do **not** equal `0xDEADBEEF`.  Packets that carry the
///   plaintext Havoc fingerprint are rejected at this pre-filter stage, before
///   any DB look-up, so that non-legacy listeners carry no detectable Demon
///   fingerprint.
///
/// Returns `None` if the body exceeds `max_len`, contains a read error, or
/// fails the mode-appropriate magic check.
pub(crate) async fn collect_body_with_magic_precheck(
    body: Body,
    max_len: usize,
    legacy_mode: bool,
) -> Option<Bytes> {
    use http_body_util::BodyExt as _;

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
        // As soon as we have the 8 bytes that cover the magic field (bytes 4–7),
        // apply the mode-appropriate check.
        if !magic_checked && buf.len() >= 8 {
            let has_demon_magic = buf[4..8] == DEMON_MAGIC_VALUE.to_be_bytes();
            if legacy_mode && !has_demon_magic {
                // Legacy listener: require 0xDEADBEEF — reject anything else.
                return None;
            }
            if !legacy_mode && has_demon_magic {
                // Non-legacy listener: reject 0xDEADBEEF before DB look-up.
                return None;
            }
            magic_checked = true;
        }
    }

    // Bodies shorter than 8 bytes cannot pass the magic check.
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
            let allowed =
                allow_demon_init_for_ip("test-listener", &rl, ip, &pkt, false).await;
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
        assert_eq!(classify_demon_transport(&pkt, true), None, "legacy parser must reject Archon packet");
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
}
