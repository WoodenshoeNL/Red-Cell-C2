use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const APP_DIR_NAME: &str = "red-cell-client";
const CONFIG_FILE_NAME: &str = "client.toml";
const SCRIPTS_DIR_NAME: &str = "scripts";

/// Persisted client preferences loaded between sessions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LocalConfig {
    /// Last-used teamserver WebSocket URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// Last-used operator username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Directory containing client-side Python scripts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scripts_dir: Option<PathBuf>,
    /// Path to a custom CA certificate PEM file for teamserver verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<PathBuf>,
    /// SHA-256 fingerprint (hex) of the pinned teamserver certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,
}

impl LocalConfig {
    /// Load the local config from the platform config directory.
    ///
    /// Returns the default config if the file does not exist or cannot be parsed.
    pub fn load() -> Self {
        Self::load_with_path(config_file_path())
    }

    /// Load the local config from a specific path.
    ///
    /// Returns the default config if the file does not exist or cannot be parsed.
    pub(crate) fn load_from(path: &std::path::Path) -> Self {
        match fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist the local config to the platform config directory.
    ///
    /// Silently ignores write failures (non-critical persistence).
    pub fn save(&self) {
        self.save_with_path(config_file_path());
    }

    /// Persist the local config to a specific path.
    ///
    /// Creates parent directories as needed. Silently ignores write failures.
    pub(crate) fn save_to(&self, path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(contents) = toml::to_string_pretty(self) {
            let _ = fs::write(path, contents);
        }
    }

    /// Resolve the configured scripts directory, falling back to the default location.
    pub fn resolved_scripts_dir(&self) -> Option<PathBuf> {
        self.scripts_dir.clone().or_else(default_scripts_dir)
    }

    fn load_with_path(path: Option<PathBuf>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        Self::load_from(&path)
    }

    fn save_with_path(&self, path: Option<PathBuf>) {
        let Some(path) = path else {
            return;
        };
        self.save_to(&path);
    }
}

fn config_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join(APP_DIR_NAME).join(CONFIG_FILE_NAME))
}

pub(crate) fn default_scripts_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join(APP_DIR_NAME).join(SCRIPTS_DIR_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_no_values() {
        let config = LocalConfig::default();
        assert_eq!(config.server_url, None);
        assert_eq!(config.username, None);
        assert_eq!(config.scripts_dir, None);
        assert_eq!(config.ca_cert, None);
        assert_eq!(config.cert_fingerprint, None);
    }

    #[test]
    fn config_round_trips_through_toml() {
        let config = LocalConfig {
            server_url: Some("wss://10.0.0.1:40056/havoc/".to_owned()),
            username: Some("operator".to_owned()),
            scripts_dir: Some(PathBuf::from("/tmp/red-cell-client/scripts")),
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some("abcdef0123456789".to_owned()),
        };

        let serialized = toml::to_string_pretty(&config)
            .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));
        let deserialized: LocalConfig = toml::from_str(&serialized)
            .unwrap_or_else(|error| panic!("deserialization should succeed: {error}"));

        assert_eq!(deserialized, config);
    }

    #[test]
    fn config_deserializes_partial_toml() {
        let toml_str = r#"server_url = "wss://example.com/havoc/""#;
        let config: LocalConfig = toml::from_str(toml_str)
            .unwrap_or_else(|error| panic!("partial deserialization should succeed: {error}"));

        assert_eq!(config.server_url.as_deref(), Some("wss://example.com/havoc/"));
        assert_eq!(config.username, None);
        assert_eq!(config.scripts_dir, None);
    }

    #[test]
    fn config_deserializes_empty_toml() {
        let config: LocalConfig =
            toml::from_str("").unwrap_or_else(|error| panic!("empty toml should parse: {error}"));

        assert_eq!(config, LocalConfig::default());
    }

    #[test]
    fn save_and_load_round_trip_via_tempdir() {
        let dir = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("tempdir creation should succeed: {error}"));
        let path = dir.path().join("client.toml");

        let config = LocalConfig {
            server_url: Some("wss://10.0.0.5:9999/havoc/".to_owned()),
            username: Some("admin".to_owned()),
            scripts_dir: Some(dir.path().join("scripts")),
            ca_cert: None,
            cert_fingerprint: None,
        };

        config.save_to(&path);
        let loaded = LocalConfig::load_from(&path);

        assert_eq!(loaded, config);
    }

    #[test]
    fn load_from_returns_default_for_invalid_toml() {
        let dir = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("tempdir creation should succeed: {error}"));
        let path = dir.path().join("client.toml");

        fs::write(&path, "server_url = [")
            .unwrap_or_else(|error| panic!("write should succeed: {error}"));

        assert_eq!(LocalConfig::load_from(&path), LocalConfig::default());
    }

    #[test]
    fn load_with_missing_config_dir_returns_default() {
        assert_eq!(LocalConfig::load_with_path(None), LocalConfig::default());
    }

    #[test]
    fn save_with_missing_config_dir_is_noop() {
        let config = LocalConfig {
            server_url: Some("wss://10.0.0.5:9999/havoc/".to_owned()),
            username: Some("admin".to_owned()),
            scripts_dir: Some(PathBuf::from("/tmp/red-cell-client/scripts")),
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some("abcdef0123456789".to_owned()),
        };

        config.save_with_path(None);
    }

    #[test]
    fn resolved_scripts_dir_prefers_explicit_value() {
        let config = LocalConfig {
            scripts_dir: Some(PathBuf::from("/tmp/client-scripts")),
            ..LocalConfig::default()
        };

        assert_eq!(config.resolved_scripts_dir(), Some(PathBuf::from("/tmp/client-scripts")));
    }
}
