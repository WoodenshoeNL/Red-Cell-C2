//! Corpus capture middleware for the HTTP listener.
//!
//! When the teamserver is started with `--capture-corpus <dir>`, this module
//! writes on-wire packet bytes and AES session keys to disk in the
//! [`CorpusPacketMeta`] / [`CorpusSessionKeys`] format defined in
//! `common/src/corpus.rs`.
//!
//! # Directory layout
//!
//! ```text
//! <corpus_dir>/
//!   <agent_type>/     e.g. "demon", "archon"
//!     <agent_id_hex>/ e.g. "deadbeef"
//!       0000.bin        encrypted request bytes (RX: agent → teamserver)
//!       0000.meta.json
//!       0001.bin        encrypted response bytes (TX: teamserver → agent)
//!       0001.meta.json
//!       ...
//!       session.keys.json
//! ```
//!
//! The layout uses the numeric agent ID as the "scenario" identifier, since
//! the teamserver does not know the test scenario number at runtime.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use red_cell_common::corpus::{
    CorpusAgentType, CorpusPacketDir, CorpusPacketMeta, CorpusSessionKeys, sha256_hex,
};
use tokio::sync::Mutex;
use tracing::warn;

/// Corpus writer for a single HTTP listener.
///
/// Internally reference-counted, so `clone()` is cheap.
#[derive(Clone, Debug)]
pub struct CorpusCapture {
    inner: Arc<CaptureInner>,
}

#[derive(Debug)]
struct CaptureInner {
    base_dir: PathBuf,
    agent_type: CorpusAgentType,
    /// Per-agent packet sequence counter.
    seq: Mutex<HashMap<u32, u64>>,
    /// Agents for which `session.keys.json` has already been written.
    keys_written: Mutex<HashSet<u32>>,
}

impl CorpusCapture {
    /// Create a new `CorpusCapture` that writes to `base_dir`.
    ///
    /// `agent_type` should reflect the kind of agent served by the owning
    /// HTTP listener (e.g. [`CorpusAgentType::Demon`] for legacy-mode listeners).
    pub fn new(base_dir: PathBuf, agent_type: CorpusAgentType) -> Self {
        Self {
            inner: Arc::new(CaptureInner {
                base_dir,
                agent_type,
                seq: Mutex::new(HashMap::new()),
                keys_written: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// Path to the per-agent scenario directory.
    fn agent_dir(&self, agent_id: u32) -> PathBuf {
        let type_str = agent_type_str(self.inner.agent_type);
        self.inner.base_dir.join(type_str).join(format!("{agent_id:08x}"))
    }

    /// Allocate the next zero-based sequence number for `agent_id`.
    async fn next_seq(&self, agent_id: u32) -> u64 {
        let mut map = self.inner.seq.lock().await;
        let entry = map.entry(agent_id).or_insert(0);
        let seq = *entry;
        *entry += 1;
        seq
    }

    /// Record a raw packet (encrypted on-wire bytes) to the corpus directory.
    ///
    /// Writes `<seq:04d>.bin` and `<seq:04d>.meta.json` for the given agent.
    /// Silently logs a warning on I/O failure — capture errors must never
    /// affect normal agent traffic processing.
    pub async fn record_packet(
        &self,
        agent_id: u32,
        direction: CorpusPacketDir,
        raw_bytes: &[u8],
        expected_handler: Option<&str>,
    ) {
        let dir = self.agent_dir(agent_id);
        let seq = self.next_seq(agent_id).await;
        if let Err(e) =
            write_packet_files(&dir, seq, direction, self.inner.agent_type, agent_id, raw_bytes, expected_handler).await
        {
            warn!(
                agent_id = format_args!("{agent_id:08x}"),
                seq,
                %e,
                "corpus: failed to write packet"
            );
        }
    }

    /// Write `session.keys.json` for `agent_id`, skipping if already written.
    ///
    /// Only the first call per agent actually writes to disk; subsequent calls
    /// for the same `agent_id` are no-ops.  This preserves `initial_ctr_block_offset = 0`
    /// from the INIT handshake even if callbacks advance the counter later.
    pub async fn write_session_keys_once(&self, agent_id: u32, keys: CorpusSessionKeys) {
        let should_write = {
            let mut written = self.inner.keys_written.lock().await;
            if written.contains(&agent_id) {
                false
            } else {
                written.insert(agent_id);
                true
            }
        };

        if !should_write {
            return;
        }

        let dir = self.agent_dir(agent_id);
        if let Err(e) = write_keys_file(&dir, &keys).await {
            // Remove from the set so we retry on the next packet.
            self.inner.keys_written.lock().await.remove(&agent_id);
            warn!(
                agent_id = format_args!("{agent_id:08x}"),
                %e,
                "corpus: failed to write session.keys.json"
            );
        }
    }
}

// ── File-writing helpers ──────────────────────────────────────────────────────

async fn write_packet_files(
    dir: &Path,
    seq: u64,
    direction: CorpusPacketDir,
    agent_type: CorpusAgentType,
    agent_id: u32,
    raw_bytes: &[u8],
    expected_handler: Option<&str>,
) -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(dir).await?;

    let bin_path = dir.join(format!("{seq:04}.bin"));
    tokio::fs::write(&bin_path, raw_bytes).await?;

    let sha = sha256_hex(raw_bytes);
    let captured_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let meta = CorpusPacketMeta::new(
        seq,
        direction,
        agent_type,
        format!("{agent_id:08x}"),
        captured_at,
        sha,
        raw_bytes.len(),
        expected_handler.map(str::to_owned),
    );
    let meta_json =
        serde_json::to_string_pretty(&meta).map_err(|e| std::io::Error::other(e.to_string()))?;
    let meta_path = dir.join(format!("{seq:04}.meta.json"));
    tokio::fs::write(&meta_path, meta_json.as_bytes()).await
}

async fn write_keys_file(dir: &Path, keys: &CorpusSessionKeys) -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(dir).await?;
    let json =
        serde_json::to_string_pretty(keys).map_err(|e| std::io::Error::other(e.to_string()))?;
    tokio::fs::write(dir.join("session.keys.json"), json.as_bytes()).await
}

fn agent_type_str(t: CorpusAgentType) -> &'static str {
    match t {
        CorpusAgentType::Demon => "demon",
        CorpusAgentType::Archon => "archon",
        CorpusAgentType::Phantom => "phantom",
        CorpusAgentType::Specter => "specter",
    }
}

/// Encode `bytes` as a lowercase hexadecimal string.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::corpus::CorpusSessionKeys;
    use tempfile::TempDir;

    fn make_capture(dir: &TempDir) -> CorpusCapture {
        CorpusCapture::new(dir.path().to_path_buf(), CorpusAgentType::Demon)
    }

    #[tokio::test]
    async fn record_packet_creates_bin_and_meta() {
        use red_cell_common::corpus::CORPUS_FORMAT_VERSION;

        let tmp = TempDir::new().expect("tempdir");
        let cap = make_capture(&tmp);
        let body = b"hello corpus";

        cap.record_packet(0x1234_5678, CorpusPacketDir::Rx, body, Some("DEMON_INIT")).await;

        let dir = tmp.path().join("demon").join("12345678");
        assert!(dir.join("0000.bin").exists(), "bin file should exist");
        assert!(dir.join("0000.meta.json").exists(), "meta file should exist");

        let bin = std::fs::read(dir.join("0000.bin")).expect("read bin");
        assert_eq!(bin, body);

        let meta_raw = std::fs::read_to_string(dir.join("0000.meta.json")).expect("read meta");
        let meta: serde_json::Value = serde_json::from_str(&meta_raw).expect("parse meta");
        assert_eq!(meta["seq"], 0);
        assert_eq!(meta["direction"], "rx");
        assert_eq!(meta["agent_type"], "demon");
        assert_eq!(meta["expected_handler"], "DEMON_INIT");
        assert_eq!(meta["version"], CORPUS_FORMAT_VERSION);
    }

    #[tokio::test]
    async fn sequence_increments_per_agent() {
        let tmp = TempDir::new().expect("tempdir");
        let cap = make_capture(&tmp);

        cap.record_packet(0xABCD_EF01, CorpusPacketDir::Rx, b"rx", None).await;
        cap.record_packet(0xABCD_EF01, CorpusPacketDir::Tx, b"tx", None).await;

        let dir = tmp.path().join("demon").join("abcdef01");
        assert!(dir.join("0000.bin").exists());
        assert!(dir.join("0001.bin").exists());

        let meta0: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("0000.meta.json")).expect("read"))
                .expect("parse");
        let meta1: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("0001.meta.json")).expect("read"))
                .expect("parse");

        assert_eq!(meta0["seq"], 0);
        assert_eq!(meta0["direction"], "rx");
        assert_eq!(meta1["seq"], 1);
        assert_eq!(meta1["direction"], "tx");
    }

    #[tokio::test]
    async fn different_agents_have_independent_sequences() {
        let tmp = TempDir::new().expect("tempdir");
        let cap = make_capture(&tmp);

        cap.record_packet(0x0000_0001, CorpusPacketDir::Rx, b"agent1", None).await;
        cap.record_packet(0x0000_0002, CorpusPacketDir::Rx, b"agent2", None).await;
        cap.record_packet(0x0000_0001, CorpusPacketDir::Tx, b"agent1-r", None).await;

        let dir1 = tmp.path().join("demon").join("00000001");
        let dir2 = tmp.path().join("demon").join("00000002");

        let m = |p: &std::path::Path| -> u64 {
            let s = std::fs::read_to_string(p).expect("read");
            let v: serde_json::Value = serde_json::from_str(&s).expect("parse");
            v["seq"].as_u64().expect("seq")
        };

        assert_eq!(m(&dir1.join("0000.meta.json")), 0);
        assert_eq!(m(&dir1.join("0001.meta.json")), 1);
        assert_eq!(m(&dir2.join("0000.meta.json")), 0);
    }

    #[tokio::test]
    async fn write_session_keys_once_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        let cap = make_capture(&tmp);
        let agent_id = 0xDEAD_BEEF;

        let keys1 = CorpusSessionKeys::new(
            "a".repeat(64),
            "b".repeat(32),
            false,
            0,
            format!("0x{agent_id:08x}"),
        );
        let keys2 = CorpusSessionKeys::new(
            "c".repeat(64),
            "d".repeat(32),
            true,
            99,
            format!("0x{agent_id:08x}"),
        );

        cap.write_session_keys_once(agent_id, keys1).await;
        cap.write_session_keys_once(agent_id, keys2).await; // should not overwrite

        let dir = tmp.path().join("demon").join("deadbeef");
        let raw = std::fs::read_to_string(dir.join("session.keys.json")).expect("read keys");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse");

        // keys1 should have been written; keys2 must not overwrite
        assert_eq!(parsed["aes_key_hex"], "a".repeat(64));
        assert_eq!(parsed["monotonic_ctr"], false);
        assert_eq!(parsed["initial_ctr_block_offset"], 0);
    }

    #[tokio::test]
    async fn write_session_keys_includes_version() {
        use red_cell_common::corpus::CORPUS_FORMAT_VERSION;

        let tmp = TempDir::new().expect("tempdir");
        let cap = make_capture(&tmp);
        let agent_id = 0x1111_2222;

        let keys = CorpusSessionKeys::new(
            "e".repeat(64),
            "f".repeat(32),
            true,
            0,
            format!("0x{agent_id:08x}"),
        );
        cap.write_session_keys_once(agent_id, keys).await;

        let dir = tmp.path().join("demon").join("11112222");
        let raw = std::fs::read_to_string(dir.join("session.keys.json")).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse");

        assert_eq!(parsed["version"], CORPUS_FORMAT_VERSION);
    }

    #[test]
    fn bytes_to_hex_encodes_correctly() {
        assert_eq!(bytes_to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[]), "");
        let key = [0xABu8; 32];
        assert_eq!(bytes_to_hex(&key).len(), 64);
        assert!(bytes_to_hex(&key).chars().all(|c| "0123456789abcdef".contains(c)));
    }

    #[test]
    fn agent_type_str_returns_expected_strings() {
        assert_eq!(agent_type_str(CorpusAgentType::Demon), "demon");
        assert_eq!(agent_type_str(CorpusAgentType::Archon), "archon");
        assert_eq!(agent_type_str(CorpusAgentType::Phantom), "phantom");
        assert_eq!(agent_type_str(CorpusAgentType::Specter), "specter");
    }
}
