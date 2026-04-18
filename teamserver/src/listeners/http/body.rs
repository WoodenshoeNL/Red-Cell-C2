//! Demon body buffering, magic pre-check, and transport classification.

use std::net::IpAddr;

use axum::body::{Body, Bytes};
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonHeader};
use tracing::warn;

use crate::listeners::{
    DEMON_INIT_WINDOW_DURATION, DemonInitRateLimiter, MAX_DEMON_INIT_ATTEMPTS_PER_IP,
};

pub(crate) const MINIMUM_DEMON_CALLBACK_BYTES: usize = DemonHeader::SERIALIZED_LEN + 8;

/// Buffers an HTTP request body while performing an early pre-screen on the
/// Demon transport magic value.
///
/// The Demon magic value (`0xDEADBEEF`) occupies bytes 4–7 of every valid
/// Demon packet. Buffering the full body before checking the magic allows
/// an adversary to force the server to allocate up to `MAX_AGENT_MESSAGE_LEN`
/// (30 MiB) per connection before rejection. This function rejects bodies
/// that fail the magic check as soon as 8 bytes have been accumulated, which
/// limits per-connection allocation to a single network chunk (~16 KiB in
/// practice) for obviously non-Demon traffic.
///
/// Returns `None` if the body exceeds `max_len`, contains a read error, or
/// does not carry the correct Demon magic value.
pub(crate) async fn collect_body_with_magic_precheck(body: Body, max_len: usize) -> Option<Bytes> {
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
        // validate the magic and drop the connection immediately on mismatch.
        if !magic_checked && buf.len() >= 8 {
            if buf[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
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

pub(crate) fn is_valid_demon_callback_request(body: &[u8]) -> bool {
    if body.len() < MINIMUM_DEMON_CALLBACK_BYTES {
        return false;
    }

    if body[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
        return false;
    }

    DemonHeader::from_bytes(body).is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemonTransportKind {
    Init,
    Reconnect,
    Callback,
}

pub(crate) fn classify_demon_transport(body: &[u8]) -> Option<DemonTransportKind> {
    let envelope = DemonEnvelope::from_bytes(body).ok()?;
    if envelope.payload.len() < 8 {
        return None;
    }

    let command_id = u32::from_be_bytes(envelope.payload[0..4].try_into().ok()?);
    if command_id != u32::from(DemonCommand::DemonInit) {
        return Some(DemonTransportKind::Callback);
    }

    let remaining = &envelope.payload[8..];
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
) -> bool {
    if classify_demon_transport(body) != Some(DemonTransportKind::Init) {
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
