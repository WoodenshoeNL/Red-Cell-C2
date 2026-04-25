//! Payload build manifest — metadata embedded in compiled agent binaries.
//!
//! The teamserver appends a manifest to every built payload so that
//! `red-cell-cli payload inspect <file>` can extract build parameters
//! without needing a server connection.

use serde::{Deserialize, Serialize};

/// Sentinel line that precedes the JSON manifest blob inside a payload binary.
pub const MANIFEST_MARKER: &str = "RED_CELL_MANIFEST_V1";

/// Build metadata embedded in a compiled agent payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadManifest {
    /// Agent type: `"Demon"`, `"Archon"`, `"Phantom"`, or `"Specter"`.
    pub agent_type: String,
    /// Target CPU architecture (e.g. `"x64"`, `"x86"`).
    pub arch: String,
    /// Output format (e.g. `"exe"`, `"dll"`, `"bin"`).
    pub format: String,
    /// Callback host(s) baked into the payload.
    pub hosts: Vec<String>,
    /// Callback port.
    pub port: Option<u16>,
    /// Whether TLS is enabled for the callback connection.
    pub secure: bool,
    /// Full callback URL (for Rust agents that use a single URL).
    pub callback_url: Option<String>,
    /// Agent sleep interval in milliseconds.
    pub sleep_ms: Option<u64>,
    /// Jitter percentage (0–100).
    pub jitter: Option<u32>,
    /// SHA-256 hash of the init secret (hex, truncated to 16 chars).
    /// The actual secret is never exposed.
    pub init_secret_hash: Option<String>,
    /// Kill date as RFC 3339 string, if configured.
    pub kill_date: Option<String>,
    /// Working hours bitmask, if configured.
    pub working_hours_mask: Option<u32>,
    /// Name of the listener this payload connects to.
    pub listener_name: String,
    /// For Archon DLL builds: the randomized export function name.
    pub export_name: Option<String>,
    /// RFC 3339 build timestamp.
    pub built_at: String,
}

/// Extract a [`PayloadManifest`] from a payload binary.
///
/// Scans the file contents for [`MANIFEST_MARKER`] followed by a newline and
/// a JSON object. Returns `None` if no manifest is found or if the JSON is
/// malformed.
pub fn extract_manifest(data: &[u8]) -> Option<PayloadManifest> {
    let marker_bytes = MANIFEST_MARKER.as_bytes();

    // Search backwards — the manifest is appended at the end.
    let data_len = data.len();
    if data_len < marker_bytes.len() + 3 {
        return None;
    }

    let marker_pos = find_last_occurrence(data, marker_bytes)?;

    // The JSON starts after the marker + newline.
    let json_start = marker_pos + marker_bytes.len();
    // Skip the newline after the marker.
    let json_start = if json_start < data_len && data[json_start] == b'\n' {
        json_start + 1
    } else {
        json_start
    };

    if json_start >= data_len {
        return None;
    }

    // The JSON extends to the end of the file (possibly with a trailing newline).
    let json_slice = &data[json_start..];
    let json_str = std::str::from_utf8(json_slice).ok()?;
    let json_str = json_str.trim();

    serde_json::from_str(json_str).ok()
}

/// Serialize a manifest and return the bytes to append to a payload binary.
///
/// Format: `\n{MANIFEST_MARKER}\n{json}\n`
pub fn encode_manifest(manifest: &PayloadManifest) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_string(manifest)?;
    Ok(format!("\n{MANIFEST_MARKER}\n{json}\n").into_bytes())
}

/// Hash an init secret for safe inclusion in the manifest.
///
/// Returns the first 16 hex characters of the SHA-256 digest.
pub fn hash_init_secret(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(secret.as_bytes());
    format!("{:x}", digest)[..16].to_owned()
}

/// Find the last occurrence of `needle` in `haystack`.
fn find_last_occurrence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=(haystack.len() - needle.len()))
        .rev()
        .find(|&i| haystack[i..i + needle.len()] == *needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> PayloadManifest {
        PayloadManifest {
            agent_type: "Demon".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            hosts: vec!["192.168.1.100".to_owned()],
            port: Some(443),
            secure: true,
            callback_url: None,
            sleep_ms: Some(5000),
            jitter: Some(20),
            init_secret_hash: Some("abc123def4567890".to_owned()),
            kill_date: None,
            working_hours_mask: None,
            listener_name: "http1".to_owned(),
            export_name: None,
            built_at: "2026-04-25T12:00:00Z".to_owned(),
        }
    }

    #[test]
    fn round_trip_encode_extract() {
        let manifest = sample_manifest();
        let mut payload = vec![0xDE, 0xAD, 0xBE, 0xEF]; // fake binary prefix
        payload.extend_from_slice(b"\x00".repeat(100).as_slice());
        let trailer = encode_manifest(&manifest).expect("encode");
        payload.extend_from_slice(&trailer);

        let extracted = extract_manifest(&payload).expect("extract");
        assert_eq!(extracted, manifest);
    }

    #[test]
    fn extract_returns_none_for_no_marker() {
        let data = b"just some random binary data without a manifest";
        assert!(extract_manifest(data).is_none());
    }

    #[test]
    fn extract_returns_none_for_truncated_json() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\nRED_CELL_MANIFEST_V1\n{invalid");
        assert!(extract_manifest(&data).is_none());
    }

    #[test]
    fn extract_returns_none_for_empty_input() {
        assert!(extract_manifest(b"").is_none());
    }

    #[test]
    fn extract_returns_none_for_tiny_input() {
        assert!(extract_manifest(b"R").is_none());
    }

    #[test]
    fn hash_init_secret_deterministic() {
        let h1 = hash_init_secret("my-secret-key");
        let h2 = hash_init_secret("my-secret-key");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn hash_init_secret_differs_for_different_inputs() {
        let h1 = hash_init_secret("secret-a");
        let h2 = hash_init_secret("secret-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn round_trip_with_all_optional_fields() {
        let manifest = PayloadManifest {
            agent_type: "Phantom".to_owned(),
            arch: "x64".to_owned(),
            format: "elf".to_owned(),
            hosts: vec!["10.0.0.1".to_owned(), "10.0.0.2".to_owned()],
            port: Some(8443),
            secure: true,
            callback_url: Some("https://10.0.0.1:8443/".to_owned()),
            sleep_ms: Some(10000),
            jitter: Some(50),
            init_secret_hash: Some("0123456789abcdef".to_owned()),
            kill_date: Some("2027-01-01T00:00:00Z".to_owned()),
            working_hours_mask: Some(0x00FF_FF00),
            listener_name: "https-main".to_owned(),
            export_name: None,
            built_at: "2026-04-25T12:00:00Z".to_owned(),
        };

        let mut binary = vec![0u8; 500];
        binary.extend_from_slice(&encode_manifest(&manifest).expect("encode"));

        let extracted = extract_manifest(&binary).expect("extract");
        assert_eq!(extracted, manifest);
    }

    #[test]
    fn round_trip_archon_with_export_name() {
        let manifest = PayloadManifest {
            agent_type: "Archon".to_owned(),
            arch: "x64".to_owned(),
            format: "dll".to_owned(),
            hosts: vec!["c2.example.com".to_owned()],
            port: Some(443),
            secure: true,
            callback_url: None,
            sleep_ms: Some(2000),
            jitter: Some(10),
            init_secret_hash: None,
            kill_date: None,
            working_hours_mask: None,
            listener_name: "https-c2".to_owned(),
            export_name: Some("Arc3f8b1a2c4d5e6f7".to_owned()),
            built_at: "2026-04-25T14:30:00Z".to_owned(),
        };

        let mut binary = vec![0x4D, 0x5A]; // PE header start
        binary.extend_from_slice(&vec![0u8; 200]);
        binary.extend_from_slice(&encode_manifest(&manifest).expect("encode"));

        let extracted = extract_manifest(&binary).expect("extract");
        assert_eq!(extracted, manifest);
        assert_eq!(extracted.export_name.as_deref(), Some("Arc3f8b1a2c4d5e6f7"));
    }

    #[test]
    fn find_last_occurrence_basic() {
        let data = b"hello world hello";
        let pos = find_last_occurrence(data, b"hello");
        assert_eq!(pos, Some(12));
    }

    #[test]
    fn find_last_occurrence_not_found() {
        let data = b"hello world";
        assert!(find_last_occurrence(data, b"xyz").is_none());
    }
}
