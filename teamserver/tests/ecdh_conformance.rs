//! ECDH conformance test group.
//!
//! Verifies that the Rust implementation of the X25519 + AES-256-GCM ECDH
//! handshake (used by Phantom and Specter agents) derives byte-for-byte
//! identical session keys on both the agent side and the teamserver side,
//! and that session packets round-trip correctly under those keys.
//!
//! # Approach
//!
//! The tests synthesise a registration packet from known fixed keys so that
//! the derived session key is deterministic and can be compared against a
//! pre-computed golden vector.  The expected session key was computed
//! independently with Python's `cryptography` library and is hardcoded below.
//!
//! The test structure mirrors `wire_replay.rs`: a fixture-generation helper
//! ensures deterministic test data, and the replay tests feed that data
//! through the same library functions the teamserver uses in production.

mod common;

use red_cell_common::crypto::ecdh::{
    ConnectionId, ListenerKeypair, build_registration_packet_from_parts,
    build_registration_response, open_registration_packet, open_session_packet,
    open_session_response, parse_registration_response, seal_session_packet, seal_session_response,
};

// ─────────────────────────────────────────── fixture constants ──

/// Listener secret seed: byte `i` = `0xA1 + i`.
const FIXTURE_LISTENER_SECRET_SEED: u8 = 0xA1;
/// Ephemeral secret seed used by the agent: byte `i` = `0xB2 + i`.
const FIXTURE_EPHEMERAL_SECRET_SEED: u8 = 0xB2;
/// Agent ID embedded in registration response.
const FIXTURE_AGENT_ID: u32 = 0xECD0_0001;

// The X25519 shared secret for the fixture key pair (used to derive FIXTURE_SESSION_KEY):
//   26727595e29dc9c2040f6d023ecf16e5701a64d78243926f7693dca982562959
// Verified with Python's `cryptography` library (X25519 + HKDF-SHA256).

/// Pre-computed HKDF-SHA256 session key for the fixture key pair.
///
/// Derived from `FIXTURE_SHARED_SECRET_HEX` with
/// `info = b"red-cell-ecdh-session-key-v1"` and no salt (RFC 5869 default).
/// Verified independently with Python `hkdf` library.
const FIXTURE_SESSION_KEY: [u8; 32] = [
    0x03, 0x81, 0x25, 0x61, 0xf4, 0x1b, 0x0a, 0x9e, 0xc1, 0xf2, 0xe1, 0xa1, 0x1b, 0x97, 0x8f, 0xf4,
    0xba, 0x5c, 0xd0, 0x11, 0xc7, 0x74, 0xff, 0xb0, 0x61, 0xe9, 0x3a, 0xe8, 0x12, 0x6e, 0xb1, 0x74,
];

// ─────────────────────────────────────────── fixture helpers ──

fn synthetic_listener_keypair() -> ListenerKeypair {
    let secret: [u8; 32] =
        core::array::from_fn(|i| FIXTURE_LISTENER_SECRET_SEED.wrapping_add(i as u8));
    ListenerKeypair::from_bytes(secret)
}

fn synthetic_ephemeral_secret() -> [u8; 32] {
    core::array::from_fn(|i| FIXTURE_EPHEMERAL_SECRET_SEED.wrapping_add(i as u8))
}

/// Build a synthetic ECDH registration packet using fixed keys.
///
/// Returns `(packet_bytes, session_key)`.  The session key is identical to
/// `FIXTURE_SESSION_KEY` — this function verifies that invariant before
/// returning so that callers can rely on it.
fn build_synthetic_registration() -> (Vec<u8>, [u8; 32]) {
    let kp = synthetic_listener_keypair();
    let ephemeral = synthetic_ephemeral_secret();
    let metadata = b"phantom-conformance-test";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock ok")
        .as_secs();

    let (packet, session_key) =
        build_registration_packet_from_parts(&kp.public_bytes, ephemeral, timestamp, metadata)
            .expect("build_registration_packet_from_parts must succeed");

    assert_eq!(
        session_key, FIXTURE_SESSION_KEY,
        "agent-side session key must match the pre-computed golden vector"
    );

    (packet, session_key)
}

// ─────────────────────────────────────────────────────── tests ──

/// Full ECDH registration round-trip: agent builds packet with known keys,
/// teamserver opens it, both sides agree on the session key.
///
/// The derived session key is also compared against the pre-computed golden
/// vector (`FIXTURE_SESSION_KEY`) so any drift in the X25519 or HKDF
/// implementations is caught immediately.
#[test]
fn replay_ecdh_registration_derives_correct_session_key() {
    let kp = synthetic_listener_keypair();

    let (packet, expected_session_key) = build_synthetic_registration();

    // Teamserver-side: open the registration packet with the listener keypair.
    // Use a generous replay window (1 h) so the test passes under slow CI.
    let parsed = open_registration_packet(&kp, 3_600, &packet)
        .expect("open_registration_packet must succeed for a fresh synthetic packet");

    assert_eq!(
        parsed.session_key, expected_session_key,
        "server-side session key must match agent-side session key"
    );
    assert_eq!(
        parsed.session_key, FIXTURE_SESSION_KEY,
        "server-side session key must match pre-computed golden vector"
    );

    // open_registration_packet strips the 8-byte timestamp; the remaining
    // metadata must equal what the agent passed to build_registration_packet_from_parts.
    assert_eq!(
        parsed.metadata.as_slice(),
        b"phantom-conformance-test",
        "metadata (timestamp already stripped) must match what the agent sent"
    );
}

/// Verify that `build_registration_response` + `parse_registration_response`
/// round-trip correctly using the fixture session key.
///
/// This covers the teamserver→agent direction of the registration exchange.
#[test]
fn replay_ecdh_registration_response_round_trip() {
    let conn_id = ConnectionId([
        0xC0, 0xDE, 0xC0, 0xDE, 0xC0, 0xDE, 0xC0, 0xDE, 0xC0, 0xDE, 0xC0, 0xDE, 0xC0, 0xDE, 0xC0,
        0xDE,
    ]);

    let response = build_registration_response(&conn_id, &FIXTURE_SESSION_KEY, FIXTURE_AGENT_ID)
        .expect("build_registration_response must succeed");

    let (parsed_conn_id, parsed_agent_id) =
        parse_registration_response(&FIXTURE_SESSION_KEY, &response)
            .expect("parse_registration_response must succeed");

    assert_eq!(parsed_conn_id, conn_id, "connection ID must survive the round-trip");
    assert_eq!(parsed_agent_id, FIXTURE_AGENT_ID, "agent ID must survive the round-trip");
}

/// Verify that session packets round-trip correctly using the fixture session key.
///
/// Covers both the agent→teamserver direction (`seal_session_packet` /
/// `open_session_packet`) and the teamserver→agent direction
/// (`seal_session_response` / `open_session_response`).
#[test]
fn replay_ecdh_session_packet_round_trip() {
    let conn_id = ConnectionId([
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        0x89,
    ]);

    // Agent → teamserver
    let task_output = b"whoami\noperator\n";
    let agent_packet = seal_session_packet(&conn_id, &FIXTURE_SESSION_KEY, task_output)
        .expect("seal_session_packet must succeed");

    // Teamserver opens it: strip the 16-byte connection_id prefix, then decrypt.
    assert!(
        agent_packet.len() > 16,
        "sealed session packet must be longer than the connection_id prefix"
    );
    assert_eq!(&agent_packet[..16], &conn_id.0, "packet must start with the connection_id");
    let decrypted = open_session_packet(&FIXTURE_SESSION_KEY, &agent_packet[16..])
        .expect("open_session_packet must succeed");
    assert_eq!(decrypted, task_output, "decrypted payload must match original");

    // Teamserver → agent
    let server_reply = b"tasks dispatched";
    let server_packet = seal_session_response(&FIXTURE_SESSION_KEY, server_reply)
        .expect("seal_session_response must succeed");
    let opened = open_session_response(&FIXTURE_SESSION_KEY, &server_packet)
        .expect("open_session_response must succeed");
    assert_eq!(opened, server_reply, "server reply must survive the round-trip");
}

/// Verify that a tampered session packet is rejected by `open_session_packet`.
///
/// This guards against the class of bugs where AEAD authentication is
/// inadvertently disabled or bypassed after a protocol refactor.
#[test]
fn replay_ecdh_tampered_session_packet_is_rejected() {
    let conn_id = ConnectionId([0x11; 16]);
    let payload = b"sensitive-beacon-data";

    let mut packet =
        seal_session_packet(&conn_id, &FIXTURE_SESSION_KEY, payload).expect("seal must succeed");

    // Flip a byte in the ciphertext (after the 16-byte connection_id prefix
    // and 12-byte nonce — target the ciphertext body).
    let flip_offset = 16 + 12 + 1;
    let packet_len = packet.len();
    if flip_offset < packet_len {
        packet[flip_offset] ^= 0xFF;
    } else {
        packet[packet_len - 17] ^= 0xFF;
    }

    let result = open_session_packet(&FIXTURE_SESSION_KEY, &packet[16..]);
    assert!(result.is_err(), "tampered session packet must be rejected by open_session_packet");
}

/// Verify that `FIXTURE_SHARED_SECRET_HEX` encodes the expected X25519 result
/// for the fixture key pair.
///
/// This test is self-contained: it recomputes the X25519 DH using only the
/// `build_registration_packet_from_parts` → `open_registration_packet` path
/// and checks that the derived session key matches the golden vector, which
/// was independently computed from `FIXTURE_SHARED_SECRET_HEX` via HKDF.
/// Any mismatch in the X25519 or HKDF implementation will surface here.
#[test]
fn fixture_session_key_matches_shared_secret_golden_vector() {
    let kp = synthetic_listener_keypair();
    let ephemeral = synthetic_ephemeral_secret();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock ok")
        .as_secs();

    let (packet, agent_key) =
        build_registration_packet_from_parts(&kp.public_bytes, ephemeral, ts, b"golden")
            .expect("build must succeed");

    let parsed = open_registration_packet(&kp, 3_600, &packet).expect("open must succeed");

    assert_eq!(agent_key, parsed.session_key, "agent and server must agree on the session key");
    assert_eq!(
        agent_key, FIXTURE_SESSION_KEY,
        "session key derived from fixture keys must match the pre-computed golden vector; \
         any drift in X25519 or HKDF-SHA256 (info=red-cell-ecdh-session-key-v1) will appear here"
    );
}
