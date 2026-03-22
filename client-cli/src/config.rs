//! Auth and configuration resolution for `red-cell-cli`.
//!
//! Resolution order (first wins):
//! 1. `--server` / `--token` CLI flags
//! 2. `RC_SERVER` / `RC_TOKEN` environment variables (handled by clap)
//! 3. `.red-cell-cli.toml` walked up from the current working directory
//! 4. `~/.config/red-cell-cli/config.toml`

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// Raw values loaded from a TOML config file.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileConfig {
    /// Teamserver base URL (e.g. `https://teamserver:40056`).
    pub server: Option<String>,
    /// API authentication token.
    pub token: Option<String>,
    /// Request timeout in seconds.
    pub timeout: Option<u64>,
}

/// Final resolved configuration ready for use by command handlers.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Teamserver base URL (scheme + host + port, no trailing slash).
    pub server: String,
    /// API authentication token.
    pub token: String,
    /// Request timeout in seconds.
    pub timeout: u64,
}

/// Errors that can occur during configuration resolution.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No server URL was found in any source.
    #[error(
        "missing server URL — provide --server, set RC_SERVER, or add `server` to a config file"
    )]
    MissingServer,

    /// No auth token was found in any source.
    #[error("missing auth token — provide --token, set RC_TOKEN, or add `token` to a config file")]
    MissingToken,

    /// A config file existed but could not be read.
    #[error("failed to read config file {path}: {source}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A config file existed but contained invalid TOML.
    #[error("failed to parse config file {path}: {source}")]
    ParseError {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Walk up the directory tree from `start`, returning the first
/// `.red-cell-cli.toml` that exists.
///
/// Returns `None` when the filesystem root is reached without finding one.
pub fn find_config_file(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join(".red-cell-cli.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Return the path to the user-global config file:
/// `~/.config/red-cell-cli/config.toml`.
///
/// Returns `None` if the home/config directory cannot be determined.
pub fn global_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("red-cell-cli").join("config.toml"))
}

/// Load and parse a TOML config file from `path`.
///
/// Missing files are silently treated as empty configs rather than errors;
/// only files that exist but are malformed return an error.
pub fn load_config_file(path: &Path) -> Result<FileConfig, ConfigError> {
    if !path.is_file() {
        return Ok(FileConfig::default());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::ReadError { path: path.to_path_buf(), source: e })?;
    toml::from_str(&content)
        .map_err(|e| ConfigError::ParseError { path: path.to_path_buf(), source: e })
}

/// Resolve the final configuration from all sources.
///
/// `cli_server` and `cli_token` already incorporate both CLI flags and
/// environment variables because clap handles both via `#[arg(env = "…")]`.
///
/// `cli_timeout` is the value from `--timeout` (or its default of 30).
///
/// Config files are only consulted when the CLI/env did not provide all
/// required values.
pub fn resolve(
    cli_server: Option<String>,
    cli_token: Option<String>,
    cli_timeout: u64,
) -> Result<ResolvedConfig, ConfigError> {
    // Only pay the I/O cost of loading files when something is missing.
    let need_file = cli_server.is_none() || cli_token.is_none();

    let file_config: Option<FileConfig> = if need_file {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let path = find_config_file(&cwd).or_else(global_config_path);
        match path {
            Some(p) => Some(load_config_file(&p)?),
            None => None,
        }
    } else {
        None
    };

    let server = cli_server
        .or_else(|| file_config.as_ref().and_then(|c| c.server.clone()))
        .ok_or(ConfigError::MissingServer)?;

    let token = cli_token
        .or_else(|| file_config.as_ref().and_then(|c| c.token.clone()))
        .ok_or(ConfigError::MissingToken)?;

    // Timeout: file value overrides the default (30 s) but the CLI flag wins
    // over everything.  Because clap always gives us a value (default = 30)
    // we cannot distinguish "user passed --timeout" from "default applied", so
    // we use the file value only when cli_timeout is still at the default (30).
    let timeout = if cli_timeout != 30 {
        cli_timeout
    } else {
        file_config.as_ref().and_then(|c| c.timeout).unwrap_or(cli_timeout)
    };

    Ok(ResolvedConfig { server: server.trim_end_matches('/').to_owned(), token, timeout })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex;

    use tempfile::TempDir;

    use super::*;

    /// Serialises tests that mutate the process-wide CWD.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    fn write_config(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join(".red-cell-cli.toml");
        fs::write(&path, content).expect("write test config");
        path
    }

    // ── find_config_file ────────────────────────────────────────────────────

    #[test]
    fn find_config_finds_file_in_start_dir() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "");
        let result = find_config_file(tmp.path());
        assert_eq!(result, Some(tmp.path().join(".red-cell-cli.toml")));
    }

    #[test]
    fn find_config_walks_up_to_parent() {
        let tmp = TempDir::new().unwrap();
        let child = tmp.path().join("a").join("b");
        fs::create_dir_all(&child).unwrap();
        write_config(tmp.path(), "");
        let result = find_config_file(&child);
        assert_eq!(result, Some(tmp.path().join(".red-cell-cli.toml")));
    }

    #[test]
    fn find_config_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        let result = find_config_file(tmp.path());
        assert!(result.is_none());
    }

    // ── load_config_file ────────────────────────────────────────────────────

    #[test]
    fn load_config_parses_all_fields() {
        let tmp = TempDir::new().unwrap();
        let path = write_config(
            tmp.path(),
            r#"
server  = "https://ts:40056"
token   = "tok123"
timeout = 60
"#,
        );
        let cfg = load_config_file(&path).unwrap();
        assert_eq!(cfg.server.as_deref(), Some("https://ts:40056"));
        assert_eq!(cfg.token.as_deref(), Some("tok123"));
        assert_eq!(cfg.timeout, Some(60));
    }

    #[test]
    fn load_config_returns_default_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.toml");
        let cfg = load_config_file(&path).unwrap();
        assert!(cfg.server.is_none());
        assert!(cfg.token.is_none());
    }

    #[test]
    fn load_config_returns_error_for_invalid_toml() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(".red-cell-cli.toml");
        fs::write(&path, "not = [valid toml @@@@").unwrap();
        let err = load_config_file(&path).unwrap_err();
        assert!(matches!(err, ConfigError::ParseError { .. }));
    }

    // ── resolve ─────────────────────────────────────────────────────────────

    #[test]
    fn resolve_uses_cli_values_directly() {
        let cfg = resolve(Some("https://ts:40056".to_owned()), Some("tok".to_owned()), 30).unwrap();
        assert_eq!(cfg.server, "https://ts:40056");
        assert_eq!(cfg.token, "tok");
        assert_eq!(cfg.timeout, 30);
    }

    #[test]
    fn resolve_strips_trailing_slash_from_server() {
        let cfg =
            resolve(Some("https://ts:40056/".to_owned()), Some("tok".to_owned()), 30).unwrap();
        assert_eq!(cfg.server, "https://ts:40056");
    }

    #[test]
    fn resolve_returns_missing_server_error() {
        let tmp = TempDir::new().unwrap();
        let original = std::env::current_dir().unwrap();
        let _guard = CWD_LOCK.lock().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let err = resolve(None, Some("tok".to_owned()), 30);
        std::env::set_current_dir(&original).unwrap();
        assert!(matches!(err, Err(ConfigError::MissingServer)));
    }

    #[test]
    fn resolve_returns_missing_token_error() {
        let tmp = TempDir::new().unwrap();
        let original = std::env::current_dir().unwrap();
        let _guard = CWD_LOCK.lock().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let err = resolve(Some("https://ts:40056".to_owned()), None, 30);
        std::env::set_current_dir(&original).unwrap();
        assert!(matches!(err, Err(ConfigError::MissingToken)));
    }

    #[test]
    fn resolve_uses_explicit_timeout_over_file() {
        let cfg = resolve(Some("https://ts:40056".to_owned()), Some("tok".to_owned()), 45).unwrap();
        assert_eq!(cfg.timeout, 45);
    }

    // ── resolve: file-based fallback ─────────────────────────────────────────

    /// All three values absent from CLI/env — all must come from the config file.
    /// Also verifies that a file-supplied `timeout` overrides the default of 30.
    #[test]
    fn resolve_reads_server_token_and_timeout_from_config_file() {
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            r#"
server  = "https://file-ts:40056"
token   = "file-tok"
timeout = 90
"#,
        );

        let original = std::env::current_dir().unwrap();
        let _guard = CWD_LOCK.lock().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = resolve(None, None, 30);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed with file config");
        assert_eq!(cfg.server, "https://file-ts:40056");
        assert_eq!(cfg.token, "file-tok");
        assert_eq!(cfg.timeout, 90, "file timeout should override default 30");
    }

    /// CLI provides `server`; file provides `token` — partial override.
    /// The CLI value must win for `server`; the file value must fill `token`.
    #[test]
    fn resolve_cli_server_overrides_file_server_file_token_used() {
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            r#"
server = "https://file-ts:40056"
token  = "file-tok"
"#,
        );

        let original = std::env::current_dir().unwrap();
        let _guard = CWD_LOCK.lock().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = resolve(Some("https://cli-ts:9999".to_owned()), None, 30);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed with partial override");
        assert_eq!(cfg.server, "https://cli-ts:9999", "CLI server must win");
        assert_eq!(cfg.token, "file-tok", "token must come from file");
    }
}
