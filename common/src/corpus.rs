//! Wire-corpus capture format for protocol conformance testing.
//!
//! A **corpus** is a set of captured network packets between the teamserver
//! and an agent, saved to disk so that replay tests can verify protocol
//! correctness without a live agent.
//!
//! # On-disk layout
//!
//! ```text
//! tests/wire-corpus/
//!   <agent>/          e.g. "demon", "archon", "phantom", "specter"
//!     <scenario>/     e.g. "checkin", "task-output", "file-transfer"
//!       0000.bin      raw encrypted packet bytes (TX from agent to teamserver)
//!       0000.meta.json  metadata sidecar (see CorpusPacketMeta)
//!       0001.bin      raw packet bytes (RX from teamserver to agent)
//!       0001.meta.json
//!       ...
//!       session.keys.json  CorpusSessionKeys for the entire scenario
//! ```
//!
//! # Format versioning
//!
//! [`CORPUS_FORMAT_VERSION`] is embedded in every [`CorpusPacketMeta`] and
//! [`CorpusSessionKeys`] sidecar.  Replay test harnesses must reject corpus
//! files whose version does not match the version they were written for.
//!
//! # Binary file format
//!
//! The `.bin` files contain the raw, **on-the-wire bytes** with no framing
//! beyond what the protocol itself adds.  For HTTP-transported Demon/Archon
//! traffic this is the HTTP request/response body (the 20-byte Demon envelope
//! header + encrypted payload).  For DNS traffic it is the DNS query/response
//! payload.
//!
//! The bytes are written at the first meaningful protocol layer — i.e. after
//! HTTP chunked-transfer encoding is stripped but before any Demon-layer
//! decryption.  This preserves the cryptographic envelope so that replay
//! tests can exercise the full decryption pipeline.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Format version embedded in all corpus sidecar files.
///
/// Increment this constant whenever the sidecar JSON schema changes in a
/// backward-incompatible way.  Replay test harnesses must reject corpus
/// files with a mismatched version.
pub const CORPUS_FORMAT_VERSION: u32 = 1;

/// Packet direction relative to the teamserver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CorpusPacketDir {
    /// Packet originated from the agent and is received by the teamserver.
    Rx,
    /// Packet originated from the teamserver and sent to the agent.
    Tx,
}

/// Agent type that produced or consumed the captured packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CorpusAgentType {
    /// The original Havoc Demon C/ASM agent (frozen wire format, legacy CTR).
    Demon,
    /// Archon: wire-compatible Demon fork with monotonic CTR and Rust agents.
    Archon,
    /// Phantom: Rust agent for Linux.
    Phantom,
    /// Specter: Rust agent for Windows.
    Specter,
}

/// Metadata sidecar for a single captured packet.
///
/// Written as a UTF-8 JSON file at `<seq>.meta.json` alongside the raw
/// binary `<seq>.bin` file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorpusPacketMeta {
    /// Format version; must equal [`CORPUS_FORMAT_VERSION`].
    pub version: u32,

    /// Zero-based packet sequence number within this scenario.
    pub seq: u64,

    /// Direction of this packet.
    pub direction: CorpusPacketDir,

    /// Agent type associated with this scenario.
    pub agent_type: CorpusAgentType,

    /// Human-readable scenario identifier (e.g. `"checkin"`, `"task-output"`).
    pub scenario: String,

    /// Unix timestamp (seconds) when the packet was captured.
    pub captured_at_unix: i64,

    /// SHA-256 hex digest of the raw packet bytes in the companion `.bin` file.
    ///
    /// Used to detect file corruption or mismatched sidecar/binary pairs.
    pub bytes_sha256: String,

    /// Number of raw bytes in the companion `.bin` file.
    pub byte_len: usize,

    /// Expected teamserver handler or protocol phase for this packet.
    ///
    /// Used by replay tests to assert the correct parser branch was exercised.
    /// Examples: `"DEMON_INIT"`, `"DEMON_CHECKIN"`, `"COMMAND_TASK_OUTPUT"`.
    pub expected_handler: Option<String>,
}

impl CorpusPacketMeta {
    /// Construct a [`CorpusPacketMeta`] with the current format version.
    pub fn new(
        seq: u64,
        direction: CorpusPacketDir,
        agent_type: CorpusAgentType,
        scenario: String,
        captured_at_unix: i64,
        bytes_sha256: String,
        byte_len: usize,
        expected_handler: Option<String>,
    ) -> Self {
        Self {
            version: CORPUS_FORMAT_VERSION,
            seq,
            direction,
            agent_type,
            scenario,
            captured_at_unix,
            bytes_sha256,
            byte_len,
            expected_handler,
        }
    }
}

/// Session key material for an entire captured scenario.
///
/// Written as a UTF-8 JSON file at `session.keys.json` within a scenario
/// directory.  Contains the AES-256 key and IV assigned to the agent session
/// so that replay tests can decrypt corpus packets.
///
/// # Security note
///
/// This file contains raw key material in plaintext.  It must never be
/// committed to a public repository.  The `.gitignore` pattern
/// `tests/wire-corpus/**/*.keys.json` prevents accidental commits.
/// Only hand-crafted golden fixtures (with **test-only, non-secret** key
/// material) are safe to commit.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct CorpusSessionKeys {
    /// Format version; must equal [`CORPUS_FORMAT_VERSION`].
    pub version: u32,

    /// AES-256 session key as a lowercase hex string (64 hex chars = 32 bytes).
    /// `None` in stub files written before key material is available.
    #[serde(default)]
    pub aes_key_hex: Option<String>,

    /// AES-CTR IV as a lowercase hex string (32 hex chars = 16 bytes).
    /// `None` for AES-256-GCM sessions (nonce is per-packet, not stored here).
    /// `None` in stub files written before key material is available.
    #[serde(default)]
    pub aes_iv_hex: Option<String>,

    /// Whether this session uses monotonic CTR (Archon/Phantom/Specter) or
    /// legacy per-packet reset CTR (Demon).
    /// `None` for AES-256-GCM sessions (concept does not apply).
    /// `None` in stub files written before key material is available.
    #[serde(default)]
    pub monotonic_ctr: Option<bool>,

    /// CTR block offset at the start of the captured scenario (usually 0).
    /// `None` for AES-256-GCM sessions (concept does not apply).
    /// `None` in stub files written before key material is available.
    #[serde(default)]
    pub initial_ctr_block_offset: Option<u64>,

    /// Agent ID assigned during INIT handshake, as a hex string (e.g. `"0x12345678"`).
    /// `None` in stub files written before key material is available.
    #[serde(default)]
    pub agent_id_hex: Option<String>,

    /// Encryption scheme used by this session: `"aes-256-ctr"` or `"aes-256-gcm"`.
    /// `None` in legacy stub files that predate this field.
    #[serde(default)]
    pub encryption_scheme: Option<String>,

    /// Listener X25519 private key (32 bytes) as a lowercase hex string (64 hex chars).
    ///
    /// Present only for ECDH sessions (`encryption_scheme = "aes-256-gcm"`).  Stored
    /// alongside the session key so that corpus-replay tests can call
    /// `open_registration_packet` with the same keypair the teamserver used during
    /// capture, enabling full round-trip verification.
    ///
    /// `None` for AES-256-CTR sessions and in stub files that predate this field.
    #[serde(default)]
    pub listener_secret_key_hex: Option<String>,
}

impl CorpusSessionKeys {
    /// Construct a [`CorpusSessionKeys`] for an AES-256-CTR session with real key material.
    pub fn new(
        aes_key_hex: String,
        aes_iv_hex: String,
        monotonic_ctr: bool,
        initial_ctr_block_offset: u64,
        agent_id_hex: String,
    ) -> Self {
        Self {
            version: CORPUS_FORMAT_VERSION,
            aes_key_hex: Some(aes_key_hex),
            aes_iv_hex: Some(aes_iv_hex),
            monotonic_ctr: Some(monotonic_ctr),
            initial_ctr_block_offset: Some(initial_ctr_block_offset),
            agent_id_hex: Some(agent_id_hex),
            encryption_scheme: Some("aes-256-ctr".to_string()),
            listener_secret_key_hex: None,
        }
    }

    /// Construct a [`CorpusSessionKeys`] for an AES-256-GCM (ECDH) session.
    ///
    /// GCM uses a per-packet random 12-byte nonce embedded in each ciphertext,
    /// so `aes_iv_hex`, `monotonic_ctr`, and `initial_ctr_block_offset` are `None`.
    ///
    /// `listener_secret_key_hex` should be provided when the listener's private key
    /// is available, enabling corpus-replay tests to call `open_registration_packet`.
    pub fn new_gcm(
        aes_key_hex: String,
        agent_id_hex: String,
        listener_secret_key_hex: Option<String>,
    ) -> Self {
        Self {
            version: CORPUS_FORMAT_VERSION,
            aes_key_hex: Some(aes_key_hex),
            aes_iv_hex: None,
            monotonic_ctr: None,
            initial_ctr_block_offset: None,
            agent_id_hex: Some(agent_id_hex),
            encryption_scheme: Some("aes-256-gcm".to_string()),
            listener_secret_key_hex,
        }
    }
}

/// Compute the SHA-256 hex digest of `data`.
///
/// Used to populate [`CorpusPacketMeta::bytes_sha256`] when capturing packets.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_packet_meta_round_trips_json() {
        let meta = CorpusPacketMeta::new(
            0,
            CorpusPacketDir::Rx,
            CorpusAgentType::Demon,
            "checkin".to_string(),
            1_746_000_000,
            "a".repeat(64),
            256,
            Some("DEMON_INIT".to_string()),
        );
        let json = serde_json::to_string(&meta).expect("serialize");
        let decoded: CorpusPacketMeta = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.version, CORPUS_FORMAT_VERSION);
        assert_eq!(decoded.seq, 0);
        assert_eq!(decoded.direction, CorpusPacketDir::Rx);
        assert_eq!(decoded.agent_type, CorpusAgentType::Demon);
        assert_eq!(decoded.scenario, "checkin");
        assert_eq!(decoded.expected_handler.as_deref(), Some("DEMON_INIT"));
    }

    #[test]
    fn corpus_session_keys_round_trips_json() {
        let keys = CorpusSessionKeys::new(
            "a".repeat(64),
            "b".repeat(32),
            false,
            0,
            "0x12345678".to_string(),
        );
        let json = serde_json::to_string(&keys).expect("serialize");
        let decoded: CorpusSessionKeys = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.version, CORPUS_FORMAT_VERSION);
        assert_eq!(decoded.monotonic_ctr, Some(false));
        assert_eq!(decoded.initial_ctr_block_offset, Some(0));
        assert_eq!(decoded.agent_id_hex.as_deref(), Some("0x12345678"));
        assert_eq!(decoded.encryption_scheme.as_deref(), Some("aes-256-ctr"));
    }

    #[test]
    fn corpus_session_keys_gcm_has_null_ctr_fields() {
        let keys = CorpusSessionKeys::new_gcm("c".repeat(64), "0xDEADBEEF".to_string(), None);
        assert!(keys.aes_iv_hex.is_none(), "GCM keys must have null aes_iv_hex");
        assert!(keys.monotonic_ctr.is_none(), "GCM keys must have null monotonic_ctr");
        assert!(
            keys.initial_ctr_block_offset.is_none(),
            "GCM keys must have null initial_ctr_block_offset"
        );
        assert_eq!(keys.encryption_scheme.as_deref(), Some("aes-256-gcm"));

        let json = serde_json::to_string(&keys).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(parsed["aes_iv_hex"].is_null());
        assert!(parsed["monotonic_ctr"].is_null());
        assert!(parsed["initial_ctr_block_offset"].is_null());
        assert_eq!(parsed["encryption_scheme"].as_str(), Some("aes-256-gcm"));
    }

    #[test]
    fn corpus_session_keys_null_stub_round_trips_json() {
        let stub = r#"{"version":1,"aes_key_hex":null,"aes_iv_hex":null,"monotonic_ctr":null,"initial_ctr_block_offset":null,"agent_id_hex":null}"#;
        let decoded: CorpusSessionKeys = serde_json::from_str(stub).expect("deserialize stub");
        assert_eq!(decoded.version, CORPUS_FORMAT_VERSION);
        assert!(decoded.aes_key_hex.is_none());
        assert!(decoded.aes_iv_hex.is_none());
        assert!(decoded.monotonic_ctr.is_none());
        assert!(decoded.initial_ctr_block_offset.is_none());
        assert!(decoded.agent_id_hex.is_none());
    }

    #[test]
    fn corpus_packet_dir_serializes_to_lowercase() {
        let rx_json = serde_json::to_string(&CorpusPacketDir::Rx).expect("serialize rx");
        let tx_json = serde_json::to_string(&CorpusPacketDir::Tx).expect("serialize tx");
        assert_eq!(rx_json, r#""rx""#);
        assert_eq!(tx_json, r#""tx""#);
    }

    #[test]
    fn corpus_agent_type_serializes_to_lowercase() {
        let demon = serde_json::to_string(&CorpusAgentType::Demon).expect("serialize");
        let phantom = serde_json::to_string(&CorpusAgentType::Phantom).expect("serialize");
        assert_eq!(demon, r#""demon""#);
        assert_eq!(phantom, r#""phantom""#);
    }

    #[test]
    fn sha256_hex_produces_64_char_lowercase_hex() {
        let digest = sha256_hex(b"hello, corpus");
        assert_eq!(digest.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn sha256_hex_empty_input_known_digest() {
        // SHA-256 of the empty string is a well-known constant.
        let digest = sha256_hex(b"");
        assert_eq!(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let data = b"deterministic payload";
        assert_eq!(sha256_hex(data), sha256_hex(data));
    }

    #[test]
    fn corpus_format_version_is_one() {
        assert_eq!(CORPUS_FORMAT_VERSION, 1);
    }

    #[test]
    fn corpus_packet_meta_version_matches_constant() {
        let meta = CorpusPacketMeta::new(
            1,
            CorpusPacketDir::Tx,
            CorpusAgentType::Archon,
            "task-output".to_string(),
            0,
            "c".repeat(64),
            128,
            None,
        );
        assert_eq!(meta.version, CORPUS_FORMAT_VERSION);
    }

    #[test]
    fn corpus_session_keys_monotonic_ctr_true() {
        let keys = CorpusSessionKeys::new(
            "d".repeat(64),
            "e".repeat(32),
            true,
            42,
            "0xDEADBEEF".to_string(),
        );
        assert_eq!(keys.monotonic_ctr, Some(true));
        assert_eq!(keys.initial_ctr_block_offset, Some(42));
    }

    #[test]
    fn corpus_session_keys_gcm_with_listener_secret_round_trips() {
        let secret_hex = "f".repeat(64);
        let keys = CorpusSessionKeys::new_gcm(
            "c".repeat(64),
            "0x00112233".to_string(),
            Some(secret_hex.clone()),
        );
        assert_eq!(keys.listener_secret_key_hex.as_deref(), Some(secret_hex.as_str()));
        let json = serde_json::to_string(&keys).expect("serialize");
        let decoded: CorpusSessionKeys = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.listener_secret_key_hex.as_deref(), Some(secret_hex.as_str()));
    }

    #[test]
    fn corpus_session_keys_gcm_without_listener_secret_has_null_field() {
        let keys = CorpusSessionKeys::new_gcm("c".repeat(64), "0xDEADBEEF".to_string(), None);
        assert!(keys.listener_secret_key_hex.is_none());
        let json = serde_json::to_string(&keys).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(parsed["listener_secret_key_hex"].is_null());
    }

    #[test]
    fn corpus_session_keys_ctr_has_null_listener_secret() {
        let keys = CorpusSessionKeys::new(
            "a".repeat(64),
            "b".repeat(32),
            false,
            0,
            "0x12345678".to_string(),
        );
        assert!(keys.listener_secret_key_hex.is_none(), "CTR keys must not carry listener secret");
    }
}
