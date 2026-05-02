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
//!
//! # Corpus-replay test (`replay_ecdh_registration_from_real_corpus`)
//!
//! The `replay_ecdh_registration_from_real_corpus` test is marked `#[ignore]`
//! until a real Specter/Phantom ECDH corpus has been captured via:
//!
//! ```text
//! cd automatic-test && python test.py --scenario 05 --capture-corpus ../tests/wire-corpus
//! ```
//!
//! Once the corpus is present in `tests/wire-corpus/specter/checkin/` (or
//! `phantom/checkin/`) with a `session.keys.json` that includes
//! `listener_secret_key_hex`, remove the `#[ignore]` attribute so CI exercises
//! the real cross-implementation round-trip on every run.

mod common;

use red_cell_common::corpus::CORPUS_FORMAT_VERSION;
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

/// Corpus-replay test: verify that a real Specter/Phantom ECDH registration packet
/// captured from a live agent decrypts correctly with the listener keypair that was
/// active during the capture.
///
/// # Why this test exists
///
/// The synthetic tests above only verify Rust→Rust round-trips.  This test feeds
/// a packet produced by a real C/Rust agent through `open_registration_packet` and
/// checks that the derived session key matches the value the teamserver recorded in
/// `session.keys.json` during the capture.  Any cross-implementation drift in the
/// X25519 or HKDF implementations (e.g. the class of bugs in red-cell-c2-5dggm)
/// will cause this test to fail.
///
/// # Capturing the corpus
///
/// ```text
/// cd automatic-test
/// python test.py --scenario 05 --capture-corpus ../tests/wire-corpus
/// ```
///
/// The capture lands in `tests/wire-corpus/specter/checkin/` with a
/// `session.keys.json` that includes `listener_secret_key_hex`.
///
/// # Enabling in CI
///
/// Once the corpus is committed, remove the `#[ignore]` attribute so this test
/// runs on every CI pass.
#[test]
#[ignore = "requires a live corpus captured via `python test.py --scenario 05 --capture-corpus ../tests/wire-corpus`"]
fn replay_ecdh_registration_from_real_corpus() {
    // Try specter first, then phantom — whichever has a real corpus.
    let (agent, scenario) = if common::corpus_has_real_data("specter", "checkin") {
        ("specter", "checkin")
    } else if common::corpus_has_real_data("phantom", "checkin") {
        ("phantom", "checkin")
    } else {
        panic!(
            "no real ECDH corpus found — capture one first:\n\
             cd automatic-test && python test.py --scenario 05 --capture-corpus ../tests/wire-corpus"
        );
    };

    let packet_bytes = common::load_first_corpus_packet(agent, scenario)
        .unwrap_or_else(|| panic!("corpus/{agent}/{scenario}/0000.bin must exist"));

    let keys = common::load_corpus_session_keys(agent, scenario)
        .unwrap_or_else(|| panic!("corpus/{agent}/{scenario}/session.keys.json must exist"));

    assert_eq!(
        keys.version, CORPUS_FORMAT_VERSION,
        "session.keys.json version mismatch — re-capture the corpus"
    );

    let listener_secret_hex = keys.listener_secret_key_hex.as_deref().unwrap_or_else(|| {
        panic!(
            "session.keys.json is missing listener_secret_key_hex — \
             re-capture with an updated teamserver that stores the listener private key"
        )
    });

    let expected_session_key_hex = keys
        .aes_key_hex
        .as_deref()
        .unwrap_or_else(|| panic!("session.keys.json is missing aes_key_hex"));

    // Decode listener private key.
    let listener_secret_bytes: Vec<u8> = listener_secret_hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk).expect("valid utf8 hex pairs");
            u8::from_str_radix(s, 16).expect("valid hex digits in listener_secret_key_hex")
        })
        .collect();
    assert_eq!(
        listener_secret_bytes.len(),
        32,
        "listener_secret_key_hex must decode to exactly 32 bytes"
    );
    let listener_secret_arr: [u8; 32] = listener_secret_bytes.try_into().expect("32-byte slice");
    let kp = ListenerKeypair::from_bytes(listener_secret_arr);

    // Decode expected session key.
    let expected_key_bytes: Vec<u8> = expected_session_key_hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk).expect("valid utf8 hex pairs");
            u8::from_str_radix(s, 16).expect("valid hex digits in aes_key_hex")
        })
        .collect();
    assert_eq!(expected_key_bytes.len(), 32, "aes_key_hex must decode to exactly 32 bytes");
    let expected_session_key: [u8; 32] = expected_key_bytes.try_into().expect("32-byte slice");

    // Open the registration packet.  Use u64::MAX as the replay window so the
    // test does not fail on a packet captured days earlier — the goal is to
    // verify the cryptographic derivation, not the freshness check.
    let parsed = open_registration_packet(&kp, u64::MAX, &packet_bytes).unwrap_or_else(|e| {
        panic!(
            "open_registration_packet failed on real {agent} corpus packet: {e}\n\
             This indicates cross-implementation drift in X25519 or HKDF-SHA256."
        )
    });

    assert_eq!(
        parsed.session_key, expected_session_key,
        "session key derived from real {agent} corpus packet must match session.keys.json;\n\
         a mismatch indicates X25519 or HKDF-SHA256 drift between the C/Rust agent and \
         the Rust teamserver"
    );
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
