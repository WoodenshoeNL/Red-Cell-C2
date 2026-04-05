//! SSH-style trust-on-first-use (TOFU) known-servers store.
//!
//! Persists trusted teamserver certificate fingerprints keyed by `host:port`,
//! similar to SSH's `known_hosts` file. The store is loaded from and saved to
//! `~/.config/red-cell-client/known_servers.toml`.
//!
//! Security note: the file is created with mode `0600` on Unix, but the pinned
//! fingerprints remain plaintext on disk. Treat the file as sensitive operator
//! trust material: protect operator workstations with full-disk encryption and
//! verify first-use fingerprints over a separate trusted channel before calling
//! [`KnownServersStore::trust`]. See `client/OPERATOR_SECURITY.md` for the
//! operator-facing setup guidance and current TOFU limitations.

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Errors that can occur when persisting the known-servers store.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    /// Failed to create the parent config directory.
    #[error("failed to create config directory '{path}': {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Failed to serialize the store to TOML.
    #[error("failed to serialize known-servers store: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// Failed to write the store file.
    #[error("failed to write known-servers file '{path}': {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

const KNOWN_SERVERS_FILE: &str = "known_servers.toml";
const APP_DIR_NAME: &str = "red-cell-client";

/// A single trusted server entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownServer {
    /// SHA-256 certificate fingerprint (64 lowercase hex chars).
    pub fingerprint: String,
    /// ISO-8601 timestamp of when the certificate was first trusted.
    pub first_seen: String,
    /// ISO-8601 timestamp of when an operator explicitly re-confirmed the fingerprint
    /// via the verify-fingerprint workflow.  `None` means it was only TOFU-accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
    /// Optional operator-provided alias or comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Result of verifying a server's certificate against the known-servers store.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TofuVerification {
    /// The server is known and the fingerprint matches.
    Trusted,
    /// The server has never been seen before.
    NewServer,
    /// The server is known but the certificate fingerprint has changed.
    CertificateChanged {
        /// The previously trusted fingerprint.
        stored_fingerprint: String,
    },
}

/// Persistent store mapping `host:port` → [`KnownServer`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownServersStore {
    #[serde(flatten)]
    servers: BTreeMap<String, KnownServer>,
}

impl KnownServersStore {
    /// Load the known-servers store from the platform config directory.
    ///
    /// Returns an empty store if the file does not exist or cannot be parsed.
    pub fn load() -> Self {
        Self::load_with_path(store_file_path())
    }

    /// Load the known-servers store from a specific path.
    ///
    /// Returns an empty store if the file does not exist or cannot be parsed.
    pub fn load_from(path: &std::path::Path) -> Self {
        match fs::read_to_string(path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(store) => store,
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "failed to parse known-servers file; starting with empty store",
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Persist the store to the platform config directory.
    ///
    /// Returns an error if the config directory cannot be created or the file
    /// cannot be written. Callers should surface this to the operator so that
    /// a TOFU decision that cannot be persisted is not silently lost.
    pub fn save(&self) -> Result<(), SaveError> {
        self.save_with_path(store_file_path())
    }

    /// Persist the store to a specific path.
    ///
    /// Creates parent directories as needed. Returns an error if the directory
    /// cannot be created, serialization fails, or the file write fails.
    /// On Unix the file is created with mode 0600 (owner-only read/write).
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), SaveError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|source| SaveError::CreateDir { path: parent.to_owned(), source })?;
        }
        let contents = toml::to_string_pretty(self)?;
        write_store_file(path, contents.as_bytes())
            .map_err(|source| SaveError::Write { path: path.to_owned(), source })?;
        Ok(())
    }

    /// Look up a server by `host:port`.
    pub fn lookup(&self, host_port: &str) -> Option<&KnownServer> {
        self.servers.get(host_port)
    }

    /// Verify a server's certificate fingerprint against the store.
    #[allow(dead_code)]
    pub fn verify(&self, host_port: &str, fingerprint: &str) -> TofuVerification {
        match self.servers.get(host_port) {
            None => TofuVerification::NewServer,
            Some(entry) if entry.fingerprint == fingerprint => TofuVerification::Trusted,
            Some(entry) => TofuVerification::CertificateChanged {
                stored_fingerprint: entry.fingerprint.clone(),
            },
        }
    }

    /// Trust a server by storing its certificate fingerprint.
    ///
    /// If the server was already known, the entry is replaced.
    pub fn trust(&mut self, host_port: &str, fingerprint: &str, comment: Option<&str>) {
        let now = current_timestamp();
        self.servers.insert(
            host_port.to_owned(),
            KnownServer {
                fingerprint: fingerprint.to_owned(),
                first_seen: now,
                confirmed_at: None,
                comment: comment.map(str::to_owned),
            },
        );
    }

    /// Record that an operator explicitly confirmed the stored fingerprint for `host_port`.
    ///
    /// Sets `confirmed_at` to the current timestamp. Does nothing if the server is not
    /// in the store. Returns `true` if the entry existed and was updated.
    pub fn confirm(&mut self, host_port: &str) -> bool {
        if let Some(entry) = self.servers.get_mut(host_port) {
            entry.confirmed_at = Some(current_timestamp());
            true
        } else {
            false
        }
    }

    /// Iterate over all known servers in `host:port` order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &KnownServer)> {
        self.servers.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Remove a server from the store. Returns `true` if it was present.
    pub fn remove(&mut self, host_port: &str) -> bool {
        self.servers.remove(host_port).is_some()
    }

    /// Returns the number of known servers.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Returns `true` if the store is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    fn load_with_path(path: Option<PathBuf>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        Self::load_from(&path)
    }

    fn save_with_path(&self, path: Option<PathBuf>) -> Result<(), SaveError> {
        let Some(path) = path else {
            return Ok(());
        };
        self.save_to(&path)
    }
}

/// Extract `host:port` from a WebSocket URL string.
///
/// Returns `None` if the URL cannot be parsed or has no host.
pub fn host_port_from_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let default_port = match parsed.scheme() {
        "wss" | "https" => 443,
        "ws" | "http" => 80,
        _ => return None,
    };
    let port = parsed.port().unwrap_or(default_port);
    Some(format!("{host}:{port}"))
}

/// Write `data` to `path` with mode 0600 on Unix (owner-only read/write).
fn write_store_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    let mut file =
        fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;

    #[cfg(not(unix))]
    let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)?;

    file.write_all(data)?;

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;

    Ok(())
}

fn store_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join(APP_DIR_NAME).join(KNOWN_SERVERS_FILE))
}

fn current_timestamp() -> String {
    // Use a simple UTC timestamp without pulling in chrono.
    // Format: seconds since epoch (portable, monotonic, parseable).
    let duration =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    // Produce a human-readable approximation: YYYY-MM-DDThh:mm:ssZ
    // Using integer arithmetic to avoid external dependencies.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch → year/month/day (simplified Gregorian).
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's civil_from_days.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_has_no_servers() {
        let store = KnownServersStore::default();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn trust_and_lookup_round_trips() {
        let mut store = KnownServersStore::default();
        let fp = "a".repeat(64);
        store.trust("10.0.0.1:40056", &fp, Some("dev server"));

        let entry = store.lookup("10.0.0.1:40056");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.fingerprint, fp);
        assert_eq!(entry.comment.as_deref(), Some("dev server"));
        assert!(!entry.first_seen.is_empty());
    }

    #[test]
    fn verify_returns_new_server_for_unknown() {
        let store = KnownServersStore::default();
        assert_eq!(store.verify("10.0.0.1:40056", &"a".repeat(64)), TofuVerification::NewServer);
    }

    #[test]
    fn verify_returns_trusted_when_fingerprint_matches() {
        let mut store = KnownServersStore::default();
        let fp = "b".repeat(64);
        store.trust("10.0.0.1:40056", &fp, None);
        assert_eq!(store.verify("10.0.0.1:40056", &fp), TofuVerification::Trusted);
    }

    #[test]
    fn verify_returns_changed_when_fingerprint_differs() {
        let mut store = KnownServersStore::default();
        let old_fp = "c".repeat(64);
        let new_fp = "d".repeat(64);
        store.trust("10.0.0.1:40056", &old_fp, None);
        assert_eq!(
            store.verify("10.0.0.1:40056", &new_fp),
            TofuVerification::CertificateChanged { stored_fingerprint: old_fp }
        );
    }

    #[test]
    fn remove_returns_true_when_present() {
        let mut store = KnownServersStore::default();
        store.trust("10.0.0.1:40056", &"e".repeat(64), None);
        assert!(store.remove("10.0.0.1:40056"));
        assert!(store.is_empty());
    }

    #[test]
    fn remove_returns_false_when_absent() {
        let mut store = KnownServersStore::default();
        assert!(!store.remove("10.0.0.1:40056"));
    }

    #[test]
    fn trust_replaces_existing_entry() {
        let mut store = KnownServersStore::default();
        let fp1 = "f".repeat(64);
        let fp2 = "0".repeat(64);
        store.trust("10.0.0.1:40056", &fp1, None);
        store.trust("10.0.0.1:40056", &fp2, Some("renewed cert"));

        let entry = store.lookup("10.0.0.1:40056").unwrap();
        assert_eq!(entry.fingerprint, fp2);
        assert_eq!(entry.comment.as_deref(), Some("renewed cert"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn save_and_load_round_trip_via_tempdir() {
        let dir =
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir creation should succeed: {e}"));
        let path = dir.path().join("known_servers.toml");

        let mut store = KnownServersStore::default();
        store.trust("10.0.0.1:40056", &"a".repeat(64), Some("test"));
        store.trust("192.168.1.1:9999", &"b".repeat(64), None);

        store.save_to(&path).unwrap_or_else(|e| panic!("save should succeed: {e}"));
        let loaded = KnownServersStore::load_from(&path);

        assert_eq!(loaded, store);
    }

    #[test]
    fn load_from_returns_empty_for_nonexistent_path() {
        let path = std::path::Path::new("/tmp/red-cell-nonexistent/known_servers.toml");
        assert_eq!(KnownServersStore::load_from(path), KnownServersStore::default());
    }

    #[test]
    fn load_from_returns_empty_for_invalid_toml() {
        let dir =
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir creation should succeed: {e}"));
        let path = dir.path().join("known_servers.toml");
        fs::write(&path, "invalid = [").unwrap_or_else(|e| panic!("write should succeed: {e}"));
        assert_eq!(KnownServersStore::load_from(&path), KnownServersStore::default());
    }

    #[test]
    fn load_from_returns_empty_for_empty_file() {
        let dir =
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir creation should succeed: {e}"));
        let path = dir.path().join("known_servers.toml");
        fs::write(&path, "").unwrap_or_else(|e| panic!("write should succeed: {e}"));
        let store = KnownServersStore::load_from(&path);
        assert!(store.is_empty());
    }

    #[test]
    fn host_port_from_url_extracts_correctly() {
        assert_eq!(
            host_port_from_url("wss://10.0.0.1:40056/havoc/"),
            Some("10.0.0.1:40056".to_owned())
        );
        assert_eq!(
            host_port_from_url("wss://example.com/havoc/"),
            Some("example.com:443".to_owned())
        );
        assert_eq!(
            host_port_from_url("ws://localhost:8080/test"),
            Some("localhost:8080".to_owned())
        );
    }

    #[test]
    fn host_port_from_url_returns_none_for_invalid() {
        assert_eq!(host_port_from_url("not-a-url"), None);
        assert_eq!(host_port_from_url(""), None);
    }

    #[test]
    fn days_to_ymd_known_dates() {
        // 1970-01-01 = day 0
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 2000-01-01 = day 10957
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
        // 2026-03-21 = day 20533
        assert_eq!(days_to_ymd(20533), (2026, 3, 21));
    }

    #[test]
    fn days_to_ymd_leap_year_2000_feb29() {
        // 2000 is a 400-year leap year: Feb 29 exists.
        // day 11016 = 2000-02-29, day 11017 = 2000-03-01.
        assert_eq!(days_to_ymd(11016), (2000, 2, 29));
        assert_eq!(days_to_ymd(11017), (2000, 3, 1));
    }

    #[test]
    fn days_to_ymd_leap_year_2024_feb29() {
        // 2024 is a 4-year leap year: Feb 29 exists.
        // day 19782 = 2024-02-29, day 19783 = 2024-03-01.
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
        assert_eq!(days_to_ymd(19783), (2024, 3, 1));
    }

    #[test]
    fn days_to_ymd_dec31_to_jan1_boundary() {
        // 2024-12-31 = day 20088, 2025-01-01 = day 20089.
        assert_eq!(days_to_ymd(20088), (2024, 12, 31));
        assert_eq!(days_to_ymd(20089), (2025, 1, 1));
    }

    #[test]
    fn current_timestamp_looks_like_iso8601() {
        let ts = current_timestamp();
        assert!(ts.ends_with('Z'), "timestamp should end with Z: {ts}");
        assert!(ts.contains('T'), "timestamp should contain T separator: {ts}");
        assert_eq!(ts.len(), 20, "timestamp should be 20 chars: {ts}");
    }

    #[cfg(unix)]
    #[test]
    fn save_to_creates_file_with_restrictive_permissions() {
        let dir =
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir creation should succeed: {e}"));
        let path = dir.path().join("known_servers.toml");

        let mut store = KnownServersStore::default();
        store.trust("10.0.0.1:40056", &"a".repeat(64), None);
        store.save_to(&path).unwrap_or_else(|e| panic!("save should succeed: {e}"));

        let mode = fs::metadata(&path)
            .unwrap_or_else(|e| panic!("metadata should succeed: {e}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "known_servers file should be 0600, got {mode:#o}");
    }

    #[test]
    fn serialization_produces_readable_toml() {
        let mut store = KnownServersStore::default();
        store.trust("10.0.0.1:40056", &"ab".repeat(32), Some("dev"));

        let toml_str = toml::to_string_pretty(&store).unwrap_or_else(|e| panic!("serialize: {e}"));
        assert!(toml_str.contains("[\"10.0.0.1:40056\"]") || toml_str.contains("[10.0.0.1:40056]"));
        assert!(toml_str.contains("fingerprint"));
        assert!(toml_str.contains("first_seen"));
    }

    #[cfg(unix)]
    #[test]
    fn save_to_returns_error_when_parent_dir_is_unwritable() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir creation should succeed: {e}"));

        // Make the directory unwritable so create_dir_all / open will fail.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555))
            .unwrap_or_else(|e| panic!("chmod should succeed: {e}"));

        let path = dir.path().join("subdir").join("known_servers.toml");
        let store = KnownServersStore::default();
        let result = store.save_to(&path);

        // Restore permissions so tempdir cleanup can remove the directory.
        let _ = fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755));

        assert!(result.is_err(), "expected Err for unwritable parent, got Ok");
    }

    #[test]
    fn save_to_returns_ok_on_success() {
        let dir =
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir creation should succeed: {e}"));
        let path = dir.path().join("known_servers.toml");

        let mut store = KnownServersStore::default();
        store.trust("127.0.0.1:40056", &"cc".repeat(32), None);

        assert!(store.save_to(&path).is_ok(), "save_to should succeed");
    }

    #[test]
    fn trust_sets_confirmed_at_to_none() {
        let mut store = KnownServersStore::default();
        store.trust("10.0.0.1:40056", &"a".repeat(64), None);
        let entry = store.lookup("10.0.0.1:40056").unwrap();
        assert!(entry.confirmed_at.is_none(), "trust() must not pre-confirm the entry");
    }

    #[test]
    fn confirm_sets_confirmed_at_timestamp() {
        let mut store = KnownServersStore::default();
        store.trust("10.0.0.1:40056", &"a".repeat(64), None);
        let updated = store.confirm("10.0.0.1:40056");
        assert!(updated, "confirm() should return true for a known server");
        let entry = store.lookup("10.0.0.1:40056").unwrap();
        assert!(entry.confirmed_at.is_some(), "confirmed_at should be set after confirm()");
        let ts = entry.confirmed_at.as_deref().unwrap();
        assert!(ts.ends_with('Z') && ts.contains('T'), "timestamp should be ISO-8601: {ts}");
    }

    #[test]
    fn confirm_returns_false_for_unknown_server() {
        let mut store = KnownServersStore::default();
        assert!(!store.confirm("10.0.0.1:40056"), "confirm() should return false for unknown host");
    }

    #[test]
    fn iter_returns_all_entries_in_order() {
        let mut store = KnownServersStore::default();
        store.trust("b.example:9000", &"b".repeat(64), None);
        store.trust("a.example:9000", &"a".repeat(64), None);
        let keys: Vec<&str> = store.iter().map(|(k, _)| k).collect();
        // BTreeMap → alphabetical order.
        assert_eq!(keys, vec!["a.example:9000", "b.example:9000"]);
    }

    #[test]
    fn confirmed_at_round_trips_through_toml() {
        let dir =
            tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir creation should succeed: {e}"));
        let path = dir.path().join("known_servers.toml");

        let mut store = KnownServersStore::default();
        store.trust("10.0.0.1:40056", &"a".repeat(64), None);
        store.confirm("10.0.0.1:40056");

        store.save_to(&path).unwrap_or_else(|e| panic!("save: {e}"));
        let loaded = KnownServersStore::load_from(&path);
        let entry = loaded.lookup("10.0.0.1:40056").unwrap();
        assert!(entry.confirmed_at.is_some(), "confirmed_at should survive TOML round-trip");
    }
}
