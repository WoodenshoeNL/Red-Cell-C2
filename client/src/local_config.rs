use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const APP_DIR_NAME: &str = "red-cell-client";
const CONFIG_FILE_NAME: &str = "client.toml";
const SCRIPTS_DIR_NAME: &str = "scripts";

/// Persisted client preferences loaded between sessions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalConfig {
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
    pub fn load_from(path: &std::path::Path) -> Self {
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
    pub fn save_to(&self, path: &std::path::Path) {
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

    #[test]
    fn resolved_scripts_dir_falls_back_to_default_location_when_unset() {
        let config = LocalConfig::default();

        assert_eq!(config.resolved_scripts_dir(), default_scripts_dir());
    }

    #[test]
    fn resolved_scripts_dir_returns_none_when_default_location_is_unavailable() {
        let config = LocalConfig::default();

        if default_scripts_dir().is_some() {
            return;
        }

        assert_eq!(config.resolved_scripts_dir(), None);
    }

    // Mutex to serialize tests that share the platform config file.  These
    // tests write to (and restore) the real config path, so they must not run
    // concurrently with each other.
    static CONFIG_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Returns the resolved config file path used by the public API, replicating
    /// the private `config_file_path()` logic so tests can set up/tear down the
    /// file without going through the production helpers.
    fn resolved_config_path() -> Option<std::path::PathBuf> {
        dirs::config_dir().map(|d| d.join(APP_DIR_NAME).join(CONFIG_FILE_NAME))
    }

    /// Exercise the full public `save()` → `load()` chain using the platform
    /// config path.  Skips on platforms where no config directory is resolvable.
    #[test]
    fn public_save_and_load_round_trip() {
        let _guard = CONFIG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let Some(config_path) = resolved_config_path() else {
            // No config directory on this platform — skip rather than fail.
            return;
        };

        // Back up whatever is already at this path so we leave the system clean.
        let backup = fs::read(&config_path).ok();

        let config = LocalConfig {
            server_url: Some("wss://10.0.0.1:40056/havoc/".to_owned()),
            username: Some("operator".to_owned()),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
        };

        config.save();
        let loaded = LocalConfig::load();

        // Restore: put the original file back (or remove the one we created).
        match backup {
            Some(data) => {
                let _ = fs::write(&config_path, data);
            }
            None => {
                let _ = fs::remove_file(&config_path);
            }
        }

        assert_eq!(loaded, config);
    }

    /// When the resolved config file contains invalid TOML, `load()` must
    /// return `LocalConfig::default()` rather than panicking.
    #[test]
    fn public_load_returns_default_for_invalid_toml() {
        let _guard = CONFIG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let Some(config_path) = resolved_config_path() else {
            // No config directory on this platform — skip rather than fail.
            return;
        };

        // Back up whatever is already at this path.
        let backup = fs::read(&config_path).ok();

        // Create parent dirs then write malformed TOML.
        if let Some(parent) = config_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&config_path, "server_url = [")
            .unwrap_or_else(|e| panic!("should write invalid toml: {e}"));

        let loaded = LocalConfig::load();

        // Restore.
        match backup {
            Some(data) => {
                let _ = fs::write(&config_path, data);
            }
            None => {
                let _ = fs::remove_file(&config_path);
            }
        }

        assert_eq!(loaded, LocalConfig::default());
    }

    /// `save()` must complete without panicking regardless of whether a config
    /// directory is available.  When `dirs::config_dir()` returns `None` the
    /// call is a documented silent no-op; when it returns `Some` it must also
    /// not panic on success.  Either path is exercised here depending on the
    /// host environment.
    #[test]
    fn public_save_does_not_panic() {
        let _guard = CONFIG_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let config_path = resolved_config_path();
        let backup = config_path.as_deref().and_then(|p| fs::read(p).ok());

        let config = LocalConfig {
            server_url: Some("wss://10.0.0.1:40056/havoc/".to_owned()),
            ..LocalConfig::default()
        };
        config.save(); // must not panic regardless of whether a config dir exists

        // Restore if we wrote anything.
        if let Some(path) = &config_path {
            match backup {
                Some(data) => {
                    let _ = fs::write(path, data);
                }
                None => {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
}
