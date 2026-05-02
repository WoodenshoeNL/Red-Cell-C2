//! Shared ECDH dispatch types.

/// Replay-protection window: registration packets older or newer than this are rejected.
pub(crate) const ECDH_REPLAY_WINDOW_SECS: u64 = 300;

/// Result of processing an ECDH packet.
#[derive(Debug)]
pub(crate) struct EcdhResponse {
    pub(crate) payload: Vec<u8>,
    /// Agent ID resolved during ECDH handling, needed for corpus capture.
    pub(crate) agent_id: u32,
    /// ECDH session key; the registry stores zeros for ECDH agents, so we
    /// carry the real key here for corpus `session.keys.json` sidecars.
    pub(crate) session_key: [u8; 32],
    /// Listener X25519 private key used during registration.  Stored in
    /// corpus `session.keys.json` so replay tests can call
    /// `open_registration_packet` with the exact same keypair.
    /// `None` for session packets (no registration occurred).
    pub(crate) listener_secret_bytes: Option<[u8; 32]>,
}

/// Outcome of an ECDH packet dispatch attempt.
///
/// Distinguishes "successfully handled" from "not an ECDH packet, try Archon"
/// from "registration rejected by the per-IP limiter".  The rate-limited case
/// is a routine runtime event rather than a listener error, so it lives on the
/// `Ok` side and is emitted without reusing `ListenerManagerError::InvalidConfig`
/// (which would misleadingly read as a configuration problem in logs).
#[derive(Debug)]
pub(crate) enum EcdhOutcome {
    /// Packet was handled end-to-end; `payload` is the body to return.
    Handled(EcdhResponse),
    /// Body is not an ECDH packet — caller should fall through to the Archon
    /// handler.
    NotEcdh,
    /// Registration-shaped body was rejected by the per-IP rate limiter.
    /// The helper has already emitted a structured WARN; the caller should
    /// return a fake 404 without a second log line.
    RateLimited,
}
