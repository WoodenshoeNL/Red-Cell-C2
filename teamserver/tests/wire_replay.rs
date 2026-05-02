//! Wire-replay integration test harness.
//!
//! Loads corpus fixtures from `tests/wire-corpus/<agent>/<scenario>/`,
//! feeds the raw bytes directly into the teamserver's Demon protocol parser
//! (no OS sockets, no live listener), and asserts correct handler dispatch,
//! callback emission, and database state.
//!
//! # Synthetic fixtures
//!
//! The corpus directory ships with a hand-crafted synthetic Demon INIT fixture
//! under `tests/wire-corpus/demon/checkin/`.  If the `.bin` or `session.keys.json`
//! files are absent (both are gitignored), `ensure_synthetic_demon_checkin_fixture()`
//! regenerates them deterministically from the known-good test key/IV constants
//! defined below.  The `.meta.json` sidecar IS tracked in git and will be used
//! to verify the regenerated binary's SHA-256 digest.

mod common;

use std::path::{Path, PathBuf};

use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
use red_cell::demon::{DemonPacketParser, ParsedDemonPacket};
use red_cell::{AgentRegistry, Database};
use red_cell_common::corpus::{
    CORPUS_FORMAT_VERSION, CorpusAgentType, CorpusPacketDir, CorpusPacketMeta, CorpusSessionKeys,
    sha256_hex,
};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

// ──────────────────────────────────────────────────────── error type ──

#[derive(Debug, thiserror::Error)]
enum ReplayError {
    #[error("corpus directory not found: {0}")]
    CorpusNotFound(PathBuf),

    #[error("session key field '{0}' is not set (None) — capture not yet run or stub file")]
    KeyFieldMissing(&'static str),

    #[error("all session key fields are None — stub file, capture has not been run yet")]
    KeysNotYetAvailable,

    #[error("format version mismatch in {path}: expected {expected}, got {actual}")]
    FormatVersionMismatch { path: PathBuf, expected: u32, actual: u32 },

    #[error("SHA-256 mismatch for {path}: expected {expected}, got {actual}")]
    DigestMismatch { path: PathBuf, expected: String, actual: String },

    #[error("byte-length mismatch for {path}: meta says {expected} bytes, file has {actual}")]
    SizeMismatch { path: PathBuf, expected: usize, actual: usize },

    #[error("invalid hex in field '{field}': {inner}")]
    InvalidHex { field: &'static str, inner: String },

    #[error("I/O error reading {path}: {inner}")]
    Io { path: PathBuf, inner: std::io::Error },

    #[error("JSON parse error in {path}: {inner}")]
    Json { path: PathBuf, inner: serde_json::Error },

    #[error("protocol parse error at phase '{phase}': {inner}")]
    ParseError { phase: String, inner: String },

    #[error(
        "handler mismatch at seq {seq}: expected handler '{expected}', \
         but parser produced packet kind '{actual}'"
    )]
    HandlerMismatch { seq: u64, expected: String, actual: String },
}

// ──────────────────────────────────────────────────── corpus loader ──

/// One entry from a loaded corpus scenario.
#[derive(Debug)]
struct CorpusEntry {
    dir: CorpusPacketDir,
    bytes: Vec<u8>,
    meta: CorpusPacketMeta,
}

/// Resolve the on-disk path for a corpus scenario.
///
/// `CARGO_MANIFEST_DIR` points to `teamserver/` at compile time; the corpus
/// lives one level up at `<workspace-root>/tests/wire-corpus/`.
fn corpus_dir(agent: &str, scenario: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("wire-corpus")
        .join(agent)
        .join(scenario)
}

/// Load all corpus entries for an `(agent, scenario)` pair.
///
/// Entries are returned sorted by sequence number (filename order).  Each
/// entry's SHA-256 digest and byte length are verified against the companion
/// `.meta.json` sidecar, so a corrupted or mismatched file is detected before
/// the replay begins rather than producing a confusing parse failure.
fn load_corpus(agent: &str, scenario: &str) -> Result<Vec<CorpusEntry>, ReplayError> {
    let dir = corpus_dir(agent, scenario);
    load_corpus_from_dir(&dir)
}

/// Load session key material from `<corpus_dir>/session.keys.json`.
///
/// Returns a typed [`ReplayError`] instead of panicking when any key field
/// is `None` (stub file written before a real capture run).
///
/// On success, **all five fields** (`aes_key_hex`, `aes_iv_hex`, `monotonic_ctr`,
/// `initial_ctr_block_offset`, `agent_id_hex`) are guaranteed to be `Some`.
/// Callers may safely call `.expect()` on any field of the returned value.
fn load_session_keys(corpus_dir: &Path) -> Result<CorpusSessionKeys, ReplayError> {
    let keys_path = corpus_dir.join("session.keys.json");
    let json = std::fs::read_to_string(&keys_path)
        .map_err(|e| ReplayError::Io { path: keys_path.clone(), inner: e })?;
    let keys: CorpusSessionKeys = serde_json::from_str(&json)
        .map_err(|e| ReplayError::Json { path: keys_path.clone(), inner: e })?;

    if keys.version != CORPUS_FORMAT_VERSION {
        return Err(ReplayError::FormatVersionMismatch {
            path: keys_path,
            expected: CORPUS_FORMAT_VERSION,
            actual: keys.version,
        });
    }

    // If every field is None the file is a stub — fail with a clear error.
    if keys.aes_key_hex.is_none()
        && keys.aes_iv_hex.is_none()
        && keys.monotonic_ctr.is_none()
        && keys.initial_ctr_block_offset.is_none()
        && keys.agent_id_hex.is_none()
    {
        return Err(ReplayError::KeysNotYetAvailable);
    }

    // Fail on individual missing fields with a field-specific error.
    if keys.aes_key_hex.is_none() {
        return Err(ReplayError::KeyFieldMissing("aes_key_hex"));
    }
    if keys.aes_iv_hex.is_none() {
        return Err(ReplayError::KeyFieldMissing("aes_iv_hex"));
    }
    if keys.monotonic_ctr.is_none() {
        return Err(ReplayError::KeyFieldMissing("monotonic_ctr"));
    }
    if keys.initial_ctr_block_offset.is_none() {
        return Err(ReplayError::KeyFieldMissing("initial_ctr_block_offset"));
    }
    if keys.agent_id_hex.is_none() {
        return Err(ReplayError::KeyFieldMissing("agent_id_hex"));
    }

    Ok(keys)
}

/// Decode a lowercase hex string into bytes.
fn hex_decode(field: &'static str, hex: &str) -> Result<Vec<u8>, ReplayError> {
    if hex.len() % 2 != 0 {
        return Err(ReplayError::InvalidHex {
            field,
            inner: format!("odd hex length {}", hex.len()),
        });
    }
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk).unwrap_or("??");
            u8::from_str_radix(pair, 16)
                .map_err(|e| ReplayError::InvalidHex { field, inner: e.to_string() })
        })
        .collect()
}

/// Encode bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ────────────────────────────────────────── synthetic fixture setup ──

/// AES-256 key seed for the synthetic Demon INIT fixture.
const FIXTURE_KEY_SEED: u8 = 0xA1;
/// AES-CTR IV seed for the synthetic Demon INIT fixture.
const FIXTURE_IV_SEED: u8 = 0xB0;
/// Agent ID embedded in the synthetic INIT packet.
const FIXTURE_AGENT_ID: u32 = 0xDEAD_C0DE;
/// Capture timestamp embedded in sidecar metadata (2026-05-01 00:00:00 UTC).
const FIXTURE_CAPTURED_AT: i64 = 1_746_057_600;

fn synthetic_key() -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| FIXTURE_KEY_SEED.wrapping_add(i as u8))
}

fn synthetic_iv() -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| FIXTURE_IV_SEED.wrapping_add(i as u8))
}

/// Ensure the synthetic Demon checkin fixture files exist on disk.
///
/// The `.bin` and `session.keys.json` files are gitignored; this function
/// regenerates them deterministically whenever they are absent.  The
/// `.meta.json` sidecar is committed to git and will also be created here
/// when absent (e.g. on the very first run that bootstraps the fixture).
///
/// If `.meta.json` already exists its SHA-256 is used to verify the
/// regenerated binary, catching any unexpected divergence between the
/// committed sidecar and the packet builder.
fn ensure_synthetic_demon_checkin_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let dir = corpus_dir("demon", "checkin");
    std::fs::create_dir_all(&dir)?;

    let bin_path = dir.join("0000.bin");
    let meta_path = dir.join("0000.meta.json");
    let keys_path = dir.join("session.keys.json");

    // If all three already exist, nothing to do.
    if bin_path.exists() && meta_path.exists() && keys_path.exists() {
        return Ok(());
    }

    let key = synthetic_key();
    let iv = synthetic_iv();

    // Build the INIT packet using the shared integration-test helper.
    // INIT_EXT_MONOTONIC_CTR is set so the parser accepts the packet
    // without AllowLegacyCtr = true.
    let init_bytes = common::valid_demon_init_body_with_ext_flags(
        FIXTURE_AGENT_ID,
        key,
        iv,
        INIT_EXT_MONOTONIC_CTR,
    );

    let digest = sha256_hex(&init_bytes);
    let byte_len = init_bytes.len();

    // If a committed meta.json exists, validate the digest before writing
    // so we detect if the packet builder drifted since the sidecar was committed.
    if meta_path.exists() {
        let existing_meta_json = std::fs::read_to_string(&meta_path)?;
        let existing_meta: CorpusPacketMeta = serde_json::from_str(&existing_meta_json)?;
        if existing_meta.bytes_sha256 != digest {
            return Err(format!(
                "synthetic fixture digest mismatch: committed meta.json expects SHA-256 {}, \
                 but packet builder produced {}. The packet builder may have changed since \
                 the fixture was committed — regenerate with: rm {} && cargo test wire_replay",
                existing_meta.bytes_sha256,
                digest,
                meta_path.display(),
            )
            .into());
        }
    }

    // Write (or overwrite) the gitignored binary.
    std::fs::write(&bin_path, &init_bytes)?;

    // Write (or overwrite) the meta sidecar.
    let meta = CorpusPacketMeta::new(
        0,
        CorpusPacketDir::Rx,
        CorpusAgentType::Demon,
        "checkin".to_string(),
        FIXTURE_CAPTURED_AT,
        digest,
        byte_len,
        Some("DEMON_INIT".to_string()),
    );
    let meta_json = serde_json::to_string_pretty(&meta)?;
    std::fs::write(&meta_path, meta_json + "\n")?;

    // Write (or overwrite) the gitignored session keys.
    let agent_id_hex = format!("0x{FIXTURE_AGENT_ID:08X}");
    let keys = CorpusSessionKeys::new(
        hex_encode(&key),
        hex_encode(&iv),
        true, // monotonic_ctr — INIT_EXT_MONOTONIC_CTR was set
        0,    // initial_ctr_block_offset
        agent_id_hex,
    );
    let keys_json = serde_json::to_string_pretty(&keys)?;
    std::fs::write(&keys_path, keys_json + "\n")?;

    Ok(())
}

// ────────────────────────────────────────────────── replay helpers ──

/// Human-readable label for a [`ParsedDemonPacket`] variant, used in
/// [`ReplayError::HandlerMismatch`] messages so failures name the phase.
fn packet_kind_label(packet: &ParsedDemonPacket) -> &'static str {
    match packet {
        ParsedDemonPacket::Init(_) => "DEMON_INIT",
        ParsedDemonPacket::ReInit(_) => "DEMON_REINIT",
        ParsedDemonPacket::Reconnect { .. } => "DEMON_RECONNECT",
        ParsedDemonPacket::Callback { .. } => "DEMON_CALLBACK",
    }
}

/// Feed a single corpus entry into `parser` and return the parsed packet.
///
/// If `entry.meta.expected_handler` is set, the returned packet variant is
/// checked against it and a [`ReplayError::HandlerMismatch`] is returned when
/// the phase label does not match — so test failures name the protocol phase
/// rather than producing a generic "unexpected value" panic.
async fn replay_entry(
    parser: &DemonPacketParser,
    entry: &CorpusEntry,
    external_ip: &str,
    listener_name: &str,
) -> Result<ParsedDemonPacket, ReplayError> {
    let phase = entry.meta.expected_handler.as_deref().unwrap_or("unknown").to_owned();

    let packet = parser
        .parse_for_listener(&entry.bytes, external_ip, listener_name)
        .await
        .map_err(|e| ReplayError::ParseError { phase: phase.clone(), inner: e.to_string() })?;

    if let Some(expected) = &entry.meta.expected_handler {
        let actual = packet_kind_label(&packet);
        if actual != expected {
            return Err(ReplayError::HandlerMismatch {
                seq: entry.meta.seq,
                expected: expected.clone(),
                actual: actual.to_owned(),
            });
        }
    }

    Ok(packet)
}

// ─────────────────────────────────────────────────────────── tests ──

/// Replay the synthetic Demon INIT corpus fixture through the teamserver
/// protocol parser and assert the agent is registered with the expected fields.
///
/// This test drives the parser directly — no OS listener socket is opened.
#[tokio::test]
async fn replay_demon_init_from_corpus() -> Result<(), Box<dyn std::error::Error>> {
    ensure_synthetic_demon_checkin_fixture()?;

    // Load corpus entries.
    let entries = load_corpus("demon", "checkin")?;
    assert_eq!(entries.len(), 1, "synthetic checkin fixture must contain exactly one packet");

    let entry = &entries[0];
    assert_eq!(entry.dir, CorpusPacketDir::Rx, "DEMON_INIT is an agent→teamserver (Rx) packet");
    assert_eq!(
        entry.meta.expected_handler.as_deref(),
        Some("DEMON_INIT"),
        "meta.json must advertise the DEMON_INIT phase"
    );

    // Load and validate session keys — returns a typed error if any field is None.
    let dir = corpus_dir("demon", "checkin");
    let session_keys = load_session_keys(&dir)?;

    // All fields guaranteed Some by load_session_keys — it returns Err for any None field.
    let aes_key_hex =
        session_keys.aes_key_hex.expect("aes_key_hex guaranteed Some by load_session_keys");
    let aes_iv_hex =
        session_keys.aes_iv_hex.expect("aes_iv_hex guaranteed Some by load_session_keys");
    let agent_id_hex =
        session_keys.agent_id_hex.expect("agent_id_hex guaranteed Some by load_session_keys");
    let expected_monotonic_ctr =
        session_keys.monotonic_ctr.expect("monotonic_ctr guaranteed Some by load_session_keys");
    let expected_ctr_block_offset = session_keys
        .initial_ctr_block_offset
        .expect("initial_ctr_block_offset guaranteed Some by load_session_keys");

    let expected_key = hex_decode("aes_key_hex", &aes_key_hex)?;
    let expected_iv = hex_decode("aes_iv_hex", &aes_iv_hex)?;

    // Verify key lengths before converting (clear error instead of a bounds panic).
    assert_eq!(
        expected_key.len(),
        AGENT_KEY_LENGTH,
        "session.keys.json aes_key_hex must decode to {AGENT_KEY_LENGTH} bytes"
    );
    assert_eq!(
        expected_iv.len(),
        AGENT_IV_LENGTH,
        "session.keys.json aes_iv_hex must decode to {AGENT_IV_LENGTH} bytes"
    );

    // Parse agent_id_hex (accepts "0x..." or plain hex).
    let agent_id_str = agent_id_hex.trim_start_matches("0x");
    let expected_agent_id = u32::from_str_radix(agent_id_str, 16)
        .map_err(|e| ReplayError::InvalidHex { field: "agent_id_hex", inner: e.to_string() })?;

    // Build in-memory registry + parser — no OS listener socket.
    // Clone the database handle so we can query persisted state after INIT without
    // going through the registry's (intentionally limited) public API.
    let database = Database::connect_in_memory().await?;
    let db_handle = database.clone();
    let registry = AgentRegistry::new(database);
    let parser = DemonPacketParser::new(registry.clone());

    // Feed the INIT packet through the parser.
    let packet = replay_entry(&parser, entry, "127.0.0.1", "replay-test").await?;

    // Assert the correct handler was dispatched.
    let ParsedDemonPacket::Init(init) = packet else {
        return Err(format!("expected DEMON_INIT packet from replay, got: {packet:?}").into());
    };

    // Assert agent fields match the fixture.
    assert_eq!(
        init.agent.agent_id, expected_agent_id,
        "parsed agent_id must match session.keys.json agent_id_hex"
    );
    assert_eq!(init.agent.hostname, "wkstn-01", "hostname must match fixture metadata");
    assert_eq!(init.agent.username, "operator", "username must match fixture metadata");
    assert_eq!(init.agent.domain_name, "REDCELL", "domain must match fixture metadata");
    assert_eq!(init.agent.external_ip, "127.0.0.1", "external_ip must come from the replay call");

    // Assert cryptographic material is stored correctly.
    assert_eq!(
        init.agent.encryption.aes_key.as_slice(),
        &expected_key,
        "stored AES key must match session.keys.json"
    );
    assert_eq!(
        init.agent.encryption.aes_iv.as_slice(),
        &expected_iv,
        "stored AES IV must match session.keys.json"
    );
    assert_eq!(
        init.agent.encryption.monotonic_ctr, expected_monotonic_ctr,
        "monotonic_ctr must match corpus session.keys.json"
    );

    // Assert the agent record is present in the registry.
    let registered = registry
        .get(expected_agent_id)
        .await
        .expect("agent must be inserted into registry after DEMON_INIT replay");
    assert_eq!(registered.agent_id, expected_agent_id);

    // Assert that the persisted ctr_block_offset matches the corpus fixture value.
    // This catches regressions where initial_ctr_block_offset is recorded incorrectly
    // (e.g. null instead of 0) at the value level, not just the field-presence level.
    let persisted = db_handle
        .agents()
        .get_persisted(expected_agent_id)
        .await
        .map_err(|e| format!("database error querying persisted agent: {e}"))?
        .ok_or_else(|| {
            format!("persisted agent {expected_agent_id:#010x} not found in database after INIT")
        })?;
    assert_eq!(
        persisted.ctr_block_offset, expected_ctr_block_offset,
        "persisted ctr_block_offset must match session.keys.json initial_ctr_block_offset"
    );

    Ok(())
}

/// Verify that `load_session_keys` returns `ReplayError::KeysNotYetAvailable`
/// for a stub file where all fields are JSON `null`.
#[test]
fn load_session_keys_returns_typed_error_for_stub_file() {
    let tmp = tempfile::tempdir().expect("tempdir should be created");
    let keys_path = tmp.path().join("session.keys.json");

    let stub = r#"{
  "version": 1,
  "aes_key_hex": null,
  "aes_iv_hex": null,
  "monotonic_ctr": null,
  "initial_ctr_block_offset": null,
  "agent_id_hex": null
}"#;
    std::fs::write(&keys_path, stub).expect("write stub");

    let result = load_session_keys(tmp.path());
    assert!(
        matches!(result, Err(ReplayError::KeysNotYetAvailable)),
        "stub session.keys.json must return ReplayError::KeysNotYetAvailable, got: {result:?}"
    );
}

/// Verify that `load_session_keys` returns `ReplayError::KeyFieldMissing` when
/// some (but not all) fields are `null`.
#[test]
fn load_session_keys_returns_key_field_missing_for_partial_stub() {
    let tmp = tempfile::tempdir().expect("tempdir should be created");
    let keys_path = tmp.path().join("session.keys.json");

    // aes_key_hex is present, aes_iv_hex is null.
    let partial = r#"{
  "version": 1,
  "aes_key_hex": "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
  "aes_iv_hex": null,
  "monotonic_ctr": true,
  "initial_ctr_block_offset": 0,
  "agent_id_hex": "0xDEADC0DE"
}"#;
    std::fs::write(&keys_path, partial).expect("write partial stub");

    let result = load_session_keys(tmp.path());
    assert!(
        matches!(result, Err(ReplayError::KeyFieldMissing("aes_iv_hex"))),
        "partial stub must return ReplayError::KeyFieldMissing(\"aes_iv_hex\"), got: {result:?}"
    );
}

/// Verify that `load_corpus` returns a digest-mismatch error when the `.bin`
/// file has been corrupted (bytes differ from the SHA-256 in the sidecar).
#[test]
fn load_corpus_detects_digest_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir should be created");
    let dir = tmp.path();

    // Write a known payload.
    let good_bytes: Vec<u8> = (0u8..=15).collect();
    let good_digest = sha256_hex(&good_bytes);

    // Write the meta.json with the correct digest but then write different bytes
    // to the bin file to simulate corruption.
    let meta = CorpusPacketMeta::new(
        0,
        CorpusPacketDir::Rx,
        CorpusAgentType::Demon,
        "test".to_string(),
        0,
        good_digest,
        good_bytes.len(),
        None,
    );
    std::fs::write(
        dir.join("0000.meta.json"),
        serde_json::to_string_pretty(&meta).expect("serialize"),
    )
    .expect("write meta");

    // Write corrupted bytes (one bit flipped).
    let bad_bytes: Vec<u8> = (0u8..=15).map(|b| b ^ 0xFF).collect();
    std::fs::write(dir.join("0000.bin"), &bad_bytes).expect("write corrupted bin");

    // Fake corpus dir by constructing a temporary sub-path structure.
    // We call load_corpus via a helper that reads the temp directory.
    let result = load_corpus_from_dir(dir);
    assert!(
        matches!(result, Err(ReplayError::DigestMismatch { .. })),
        "corrupted bin must return ReplayError::DigestMismatch, got: {result:?}"
    );
}

/// Verify that `replay_entry` returns `ReplayError::HandlerMismatch` when
/// `meta.expected_handler` names a phase that does not match the packet kind
/// the parser actually produced.
///
/// The synthetic DEMON_INIT fixture bytes are fed through the parser normally;
/// the mismatch is injected by setting `expected_handler = "DEMON_REINIT"` on
/// a manually constructed [`CorpusEntry`] — the parser returns
/// `ParsedDemonPacket::Init`, which does not match that label.
#[tokio::test]
async fn replay_entry_returns_handler_mismatch_for_wrong_expected_handler()
-> Result<(), Box<dyn std::error::Error>> {
    ensure_synthetic_demon_checkin_fixture()?;

    // Load the synthetic INIT bytes.
    let entries = load_corpus("demon", "checkin")?;
    assert_eq!(entries.len(), 1, "synthetic checkin fixture must contain exactly one packet");
    let entry = &entries[0];

    // Build an in-memory registry and parser (same as the happy-path test).
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    let parser = DemonPacketParser::new(registry);

    // Construct a CorpusEntry with the same DEMON_INIT bytes but with
    // expected_handler pointing at the wrong phase.
    let mismatched = CorpusEntry {
        dir: entry.dir,
        bytes: entry.bytes.clone(),
        meta: CorpusPacketMeta::new(
            entry.meta.seq,
            entry.meta.direction,
            entry.meta.agent_type,
            entry.meta.scenario.clone(),
            entry.meta.captured_at_unix,
            entry.meta.bytes_sha256.clone(),
            entry.meta.byte_len,
            Some("DEMON_REINIT".to_string()),
        ),
    };

    let result = replay_entry(&parser, &mismatched, "127.0.0.1", "replay-test").await;

    assert!(
        matches!(result, Err(ReplayError::HandlerMismatch { .. })),
        "expected ReplayError::HandlerMismatch, got: {result:?}"
    );

    // The error message must name both the expected and actual phases so a
    // failing replay reports which handler was expected vs. which fired.
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("DEMON_REINIT"),
        "error message must contain the expected phase label 'DEMON_REINIT': {err_msg}"
    );
    assert!(
        err_msg.contains("DEMON_INIT"),
        "error message must contain the actual phase label 'DEMON_INIT': {err_msg}"
    );

    Ok(())
}

/// Lower-level corpus loader that reads directly from an arbitrary directory
/// (used by tests that construct synthetic directories).
fn load_corpus_from_dir(dir: &Path) -> Result<Vec<CorpusEntry>, ReplayError> {
    if !dir.exists() {
        return Err(ReplayError::CorpusNotFound(dir.to_owned()));
    }

    let mut bin_files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| ReplayError::Io { path: dir.to_owned(), inner: e })?
        .filter_map(|entry| entry.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("bin"))
        .collect();
    bin_files.sort();

    let mut entries = Vec::new();
    for bin_path in bin_files {
        let meta_path = bin_path.with_extension("meta.json");

        let bin_bytes = std::fs::read(&bin_path)
            .map_err(|e| ReplayError::Io { path: bin_path.clone(), inner: e })?;
        let meta_json = std::fs::read_to_string(&meta_path)
            .map_err(|e| ReplayError::Io { path: meta_path.clone(), inner: e })?;
        let meta: CorpusPacketMeta = serde_json::from_str(&meta_json)
            .map_err(|e| ReplayError::Json { path: meta_path.clone(), inner: e })?;

        if meta.version != CORPUS_FORMAT_VERSION {
            return Err(ReplayError::FormatVersionMismatch {
                path: meta_path,
                expected: CORPUS_FORMAT_VERSION,
                actual: meta.version,
            });
        }

        if bin_bytes.len() != meta.byte_len {
            return Err(ReplayError::SizeMismatch {
                path: bin_path,
                expected: meta.byte_len,
                actual: bin_bytes.len(),
            });
        }

        let actual_digest = sha256_hex(&bin_bytes);
        if actual_digest != meta.bytes_sha256 {
            return Err(ReplayError::DigestMismatch {
                path: bin_path,
                expected: meta.bytes_sha256.clone(),
                actual: actual_digest,
            });
        }

        entries.push(CorpusEntry { dir: meta.direction, bytes: bin_bytes, meta });
    }

    Ok(entries)
}
