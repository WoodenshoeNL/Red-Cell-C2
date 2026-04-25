//! Auth and configuration resolution for `red-cell-cli`.
//!
//! Resolution order (first wins):
//! 1. `--server` / `--token` / `--cert-fingerprint` CLI flags
//! 2. `RC_SERVER` / `RC_TOKEN` / `RC_CERT_FINGERPRINT` environment variables (handled by clap)
//! 3. `.red-cell-cli.toml` walked up from the current working directory
//! 4. `~/.config/red-cell-cli/config.toml`

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// Which certificate in the TLS handshake to match when using fingerprint pinning.
///
/// **Leaf** pinning binds to the server's end-entity certificate: it is the
/// strictest check, but you must update the pin whenever that certificate is
/// renewed. **Chain** pinning matches the fingerprint against any certificate
/// the server presents (leaf plus intermediates); use it to pin an
/// intermediate CA so leaf rotation does not require a new pin. Chain pinning
/// is weaker in the sense that any presented cert in the chain with that
/// fingerprint satisfies the check—prefer leaf pinning when you can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintPinMode {
    /// Match only the end-entity (leaf) certificate (default).
    #[default]
    Leaf,
    /// Match the fingerprint against any certificate in the presented chain.
    Chain,
}

/// TLS fingerprint pinning parameters (`--cert-fingerprint` / `--pin-intermediate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintTls {
    /// SHA-256 fingerprint of the certificate to pin (lowercase hex, 64 chars).
    pub sha256_hex: String,
    /// Whether to require a match on the leaf only or anywhere in the chain.
    pub pin_mode: FingerprintPinMode,
}

/// Controls how the CLI verifies the teamserver's TLS certificate.
#[derive(Debug, Clone, Default)]
pub enum TlsMode {
    /// Verify against the system/webpki root CAs (default, secure).
    #[default]
    SystemRoots,
    /// Verify against a single custom CA certificate loaded from a PEM file.
    /// Built-in root CAs are disabled so only this CA is trusted.
    CustomCa(PathBuf),
    /// Pin against a SHA-256 certificate fingerprint. Overrides `--ca-cert`
    /// when both are supplied.
    Fingerprint(FingerprintTls),
}

/// Raw values loaded from a TOML config file.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FileConfig {
    /// Teamserver base URL (e.g. `https://teamserver:40056`).
    pub server: Option<String>,
    /// API authentication token.
    pub token: Option<String>,
    /// Request timeout in seconds.
    pub timeout: Option<u64>,
    /// SHA-256 certificate fingerprint for TLS pinning (lowercase hex, 64 chars).
    pub cert_fingerprint: Option<String>,
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
    /// How the HTTP client should verify the teamserver's TLS certificate.
    pub tls_mode: TlsMode,
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

    /// `--pin-intermediate` was set without `--cert-fingerprint`.
    #[error("--pin-intermediate requires --cert-fingerprint")]
    PinIntermediateWithoutFingerprint,

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

    /// A config file could not be written.
    #[error("failed to write config file {path}: {source}")]
    #[allow(dead_code)] // Public API for future config-writing commands.
    WriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
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
///
/// On Unix, if the file exists with permissions looser than 0o600, they are
/// tightened to owner-only read/write and a warning is printed to stderr.
/// This guards against accidental exposure of API tokens on shared systems.
pub fn load_config_file(path: &Path) -> Result<FileConfig, ConfigError> {
    if !path.is_file() {
        return Ok(FileConfig::default());
    }

    // Tighten permissions on existing files that may have been created
    // without restrictive mode (e.g. by a text editor or manual `echo`).
    #[cfg(unix)]
    tighten_permissions(path);

    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::ReadError { path: path.to_path_buf(), source: e })?;
    toml::from_str(&content)
        .map_err(|e| ConfigError::ParseError { path: path.to_path_buf(), source: e })
}

/// Write `data` to `path` with mode 0o600 on Unix (owner-only read/write).
///
/// On non-Unix platforms this uses default permissions.
///
/// Parent directories are **not** created automatically — the caller must
/// ensure they exist.
#[allow(dead_code)] // Public API for future config-writing commands.
pub fn write_config_file(path: &Path, config: &FileConfig) -> Result<(), ConfigError> {
    let content = toml::to_string_pretty(config).map_err(|e| ConfigError::WriteError {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;

    write_bytes(path, content.as_bytes())
        .map_err(|e| ConfigError::WriteError { path: path.to_path_buf(), source: e })
}

/// Write raw bytes to `path` with 0o600 on Unix.
#[allow(dead_code)] // Called by write_config_file.
fn write_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };

    #[cfg(not(unix))]
    let mut file =
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)?;

    file.write_all(data)?;

    // On Unix, .mode() only applies at creation time. If the file already
    // existed with looser permissions, explicitly tighten them.
    #[cfg(unix)]
    tighten_permissions(path);

    Ok(())
}

/// If `mode & 0o777` is not already `0o600`, returns the stderr warning text
/// (including a trailing newline). Used by [`tighten_permissions`] and unit-tested.
#[cfg(unix)]
fn config_permission_tightening_warning(mode: u32) -> Option<String> {
    let mode = mode & 0o777;
    if mode == 0o600 {
        None
    } else {
        Some(format!(
            "warning: config file has insecure permissions ({mode:04o}); tightening to 0600.\n\
If this is unexpected, your config file may have been modified by another process.\n"
        ))
    }
}

/// Best-effort tighten file permissions to 0o600 on Unix.
///
/// Before tightening, prints a warning to stderr if the mode was not already
/// `0o600`. Silently ignores errors (e.g. file owned by another user) so callers
/// never fail due to a permission-hardening attempt.
#[cfg(unix)]
fn tighten_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mode = match std::fs::metadata(path) {
        Ok(m) => m.permissions().mode(),
        Err(_) => return,
    };
    if let Some(msg) = config_permission_tightening_warning(mode) {
        eprint!("{msg}");
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Resolve the final configuration from all sources.
///
/// `cli_server` and `cli_token` already incorporate both CLI flags and
/// environment variables because clap handles both via `#[arg(env = "…")]`.
///
/// `cli_timeout` is `Some(secs)` when the user explicitly passed `--timeout`,
/// or `None` when the flag was omitted.  An explicit value always wins over the
/// config file; when absent the config file's `timeout` is used, falling back
/// to the built-in default of 30 seconds.
///
/// `ca_cert` comes from `--ca-cert` (CLI-only).
/// `cert_fingerprint` comes from `--cert-fingerprint` / `RC_CERT_FINGERPRINT`
/// env var (handled by clap) and falls back to the config file's
/// `cert_fingerprint` field.  When both `ca_cert` and `cert_fingerprint` are
/// supplied, `cert_fingerprint` wins.
///
/// `pin_intermediate` maps to [`FingerprintPinMode::Chain`] when
/// `cert_fingerprint` is set; it is an error without a fingerprint.
pub fn resolve(
    cli_server: Option<String>,
    cli_token: Option<String>,
    cli_timeout: Option<u64>,
    ca_cert: Option<PathBuf>,
    cert_fingerprint: Option<String>,
    pin_intermediate: bool,
) -> Result<ResolvedConfig, ConfigError> {
    // Pay the I/O cost of loading files when any value that can come from the
    // config file is absent from the CLI/env.  Timeout and cert_fingerprint are
    // included so that `--server X --token Y` (no `--timeout`) still picks up
    // `timeout` / `cert_fingerprint` from the config file instead of silently
    // falling back to defaults.
    let need_file = cli_server.is_none()
        || cli_token.is_none()
        || cli_timeout.is_none()
        || cert_fingerprint.is_none();

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

    // Timeout: explicit CLI flag always wins; when absent, fall back to the
    // config file value, then to the built-in default of 30 seconds.
    let timeout =
        cli_timeout.or_else(|| file_config.as_ref().and_then(|c| c.timeout)).unwrap_or(30);

    let cert_fingerprint =
        cert_fingerprint.or_else(|| file_config.as_ref().and_then(|c| c.cert_fingerprint.clone()));

    if pin_intermediate && cert_fingerprint.is_none() {
        return Err(ConfigError::PinIntermediateWithoutFingerprint);
    }

    // TLS mode: fingerprint wins over CA cert.
    let tls_mode = match (ca_cert, cert_fingerprint) {
        (_, Some(fp)) => TlsMode::Fingerprint(FingerprintTls {
            sha256_hex: fp,
            pin_mode: if pin_intermediate {
                FingerprintPinMode::Chain
            } else {
                FingerprintPinMode::Leaf
            },
        }),
        (Some(path), None) => TlsMode::CustomCa(path),
        (None, None) => TlsMode::SystemRoots,
    };

    Ok(ResolvedConfig { server: server.trim_end_matches('/').to_owned(), token, timeout, tls_mode })
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
            &format!(
                r#"
server           = "https://ts:40056"
token            = "tok123"
timeout          = 60
cert_fingerprint = "{}"
"#,
                "ab".repeat(32)
            ),
        );
        let cfg = load_config_file(&path).unwrap();
        assert_eq!(cfg.server.as_deref(), Some("https://ts:40056"));
        assert_eq!(cfg.token.as_deref(), Some("tok123"));
        assert_eq!(cfg.timeout, Some(60));
        assert_eq!(cfg.cert_fingerprint.as_deref(), Some("ab".repeat(32).as_str()));
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
        // Pass explicit `Some(30)` for timeout so `need_file` is false and no config file is
        // loaded — otherwise `cli_timeout = None` loads ~/.config/... and makes this test
        // depend on the developer machine (see `resolve_cli_server_and_token_file_timeout_used_when_flag_omitted`).
        let cfg = resolve(
            Some("https://ts:40056".to_owned()),
            Some("tok".to_owned()),
            Some(30),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(cfg.server, "https://ts:40056");
        assert_eq!(cfg.token, "tok");
        assert_eq!(cfg.timeout, 30);
    }

    #[test]
    fn resolve_strips_trailing_slash_from_server() {
        let cfg = resolve(
            Some("https://ts:40056/".to_owned()),
            Some("tok".to_owned()),
            Some(30),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(cfg.server, "https://ts:40056");
    }

    #[test]
    fn resolve_returns_missing_server_error() {
        let tmp = TempDir::new().unwrap();
        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let err = resolve(None, Some("tok".to_owned()), None, None, None, false);
        std::env::set_current_dir(&original).unwrap();
        assert!(matches!(err, Err(ConfigError::MissingServer)));
    }

    #[test]
    fn resolve_returns_missing_token_error() {
        let tmp = TempDir::new().unwrap();
        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let err = resolve(Some("https://ts:40056".to_owned()), None, None, None, None, false);
        std::env::set_current_dir(&original).unwrap();
        assert!(matches!(err, Err(ConfigError::MissingToken)));
    }

    #[test]
    fn resolve_uses_explicit_timeout_over_file() {
        let cfg = resolve(
            Some("https://ts:40056".to_owned()),
            Some("tok".to_owned()),
            Some(45),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(cfg.timeout, 45);
    }

    #[test]
    fn resolve_pin_intermediate_without_fingerprint_errors() {
        let err = resolve(
            Some("https://ts:40056".to_owned()),
            Some("tok".to_owned()),
            Some(30),
            None,
            None,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::PinIntermediateWithoutFingerprint));
    }

    #[test]
    fn resolve_cert_fingerprint_with_pin_intermediate_sets_chain_mode() {
        let cfg = resolve(
            Some("https://ts:40056".to_owned()),
            Some("tok".to_owned()),
            Some(30),
            None,
            Some("ab".repeat(32)),
            true,
        )
        .unwrap();
        match &cfg.tls_mode {
            TlsMode::Fingerprint(fp) => {
                assert_eq!(fp.pin_mode, FingerprintPinMode::Chain);
                assert_eq!(fp.sha256_hex.len(), 64);
            }
            _ => panic!("expected Fingerprint tls mode"),
        }
    }

    #[test]
    fn resolve_cert_fingerprint_defaults_to_leaf_pin_mode() {
        let cfg = resolve(
            Some("https://ts:40056".to_owned()),
            Some("tok".to_owned()),
            Some(30),
            None,
            Some("ab".repeat(32)),
            false,
        )
        .unwrap();
        match &cfg.tls_mode {
            TlsMode::Fingerprint(fp) => assert_eq!(fp.pin_mode, FingerprintPinMode::Leaf),
            _ => panic!("expected Fingerprint tls mode"),
        }
    }

    // ── resolve: cert_fingerprint from config file ───────────────────────────

    #[test]
    fn resolve_cert_fingerprint_falls_back_to_config_file() {
        let fp = "ab".repeat(32);
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            &format!(
                r#"
server           = "https://ts:40056"
token            = "tok"
cert_fingerprint = "{fp}"
"#,
            ),
        );

        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = resolve(None, None, Some(30), None, None, false);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed");
        match &cfg.tls_mode {
            TlsMode::Fingerprint(f) => {
                assert_eq!(f.sha256_hex, fp);
                assert_eq!(f.pin_mode, FingerprintPinMode::Leaf);
            }
            _ => panic!("expected Fingerprint tls mode from config file fallback"),
        }
    }

    #[test]
    fn resolve_cli_cert_fingerprint_wins_over_config_file() {
        let cli_fp = "cd".repeat(32);
        let file_fp = "ab".repeat(32);
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            &format!(
                r#"
server           = "https://ts:40056"
token            = "tok"
cert_fingerprint = "{file_fp}"
"#,
            ),
        );

        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = resolve(None, None, Some(30), None, Some(cli_fp.clone()), false);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed");
        match &cfg.tls_mode {
            TlsMode::Fingerprint(f) => {
                assert_eq!(f.sha256_hex, cli_fp, "CLI fingerprint must win over file");
            }
            _ => panic!("expected Fingerprint tls mode"),
        }
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

        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = resolve(None, None, None, None, None, false);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed with file config");
        assert_eq!(cfg.server, "https://file-ts:40056");
        assert_eq!(cfg.token, "file-tok");
        assert_eq!(cfg.timeout, 90, "file timeout should override default 30");
    }

    /// When `--timeout` is omitted (`None`), the config file's `timeout` wins
    /// over the built-in default.
    #[test]
    fn resolve_file_timeout_wins_when_timeout_flag_omitted() {
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            r#"
server  = "https://file-ts:40056"
timeout = 60
"#,
        );

        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        // token provided on CLI; server absent → file is loaded.
        // cli_timeout = None (flag omitted), so the file's 60 wins.
        let result = resolve(None, Some("tok".to_owned()), None, None, None, false);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed");
        assert_eq!(cfg.timeout, 60, "file timeout (60) must win when --timeout is omitted");
    }

    /// Explicit `--timeout 30` must win over a config file that specifies a
    /// different timeout — this was the bug that the sentinel approach could not
    /// distinguish.
    #[test]
    fn resolve_explicit_timeout_30_wins_over_file_timeout() {
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            r#"
server  = "https://file-ts:40056"
timeout = 60
"#,
        );

        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        // Explicit --timeout 30 must beat file's 60.
        let result = resolve(None, Some("tok".to_owned()), Some(30), None, None, false);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed");
        assert_eq!(cfg.timeout, 30, "explicit --timeout 30 must win over file timeout (60)");
    }

    /// Regression test: `--server` and `--token` both provided via CLI but
    /// `--timeout` omitted.  The config file's `timeout` must still be used
    /// rather than the built-in 30-second default.
    #[test]
    fn resolve_cli_server_and_token_file_timeout_used_when_flag_omitted() {
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            r#"
timeout = 120
"#,
        );

        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        // Both auth values come from the CLI — historically this prevented the
        // config file from being loaded, causing timeout to always be 30.
        let result = resolve(
            Some("https://cli-ts:9999".to_owned()),
            Some("cli-tok".to_owned()),
            None, // --timeout omitted
            None,
            None,
            false,
        );
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed");
        assert_eq!(cfg.server, "https://cli-ts:9999");
        assert_eq!(cfg.token, "cli-tok");
        assert_eq!(
            cfg.timeout, 120,
            "file timeout (120) must win when --timeout is omitted, even when --server and --token are both supplied"
        );
    }

    // ── permission tightening warning ──────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn config_permission_tightening_warning_none_when_already_0600() {
        assert_eq!(config_permission_tightening_warning(0o600), None);
    }

    #[cfg(unix)]
    #[test]
    fn config_permission_tightening_warning_describes_insecure_mode() {
        let msg = config_permission_tightening_warning(0o644).expect("expected warning");
        assert!(msg.contains("(0644)"), "msg={msg:?}");
        assert!(msg.contains("tightening to 0600"), "msg={msg:?}");
        assert!(msg.contains("another process"), "msg={msg:?}");
    }

    // ── write_config_file ──────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn write_config_creates_file_with_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test-config.toml");
        let config = FileConfig {
            server: Some("https://ts:40056".to_owned()),
            token: Some("secret-tok".to_owned()),
            timeout: None,
            cert_fingerprint: None,
        };
        write_config_file(&path, &config).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config file should be owner-only (0600), got {mode:#o}");

        // Verify content round-trips.
        let loaded = load_config_file(&path).unwrap();
        assert_eq!(loaded.server.as_deref(), Some("https://ts:40056"));
        assert_eq!(loaded.token.as_deref(), Some("secret-tok"));
    }

    #[cfg(unix)]
    #[test]
    fn write_config_tightens_permissions_on_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("loose.toml");

        // Create an initial file with permissive (0o644) permissions.
        fs::write(&path, "server = \"old\"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let config = FileConfig {
            server: Some("https://new:40056".to_owned()),
            token: None,
            timeout: None,
            cert_fingerprint: None,
        };
        write_config_file(&path, &config).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions should be tightened to 0600, got {mode:#o}");
    }

    #[cfg(unix)]
    #[test]
    fn load_config_tightens_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(".red-cell-cli.toml");
        fs::write(&path, "server = \"https://ts:1\"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let _ = load_config_file(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "load_config_file should tighten loose permissions to 0600, got {mode:#o}"
        );
    }

    // ── resolve: partial override ──────────────────────────────────────────

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

        let _guard = CWD_LOCK.lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let result = resolve(Some("https://cli-ts:9999".to_owned()), None, None, None, None, false);
        std::env::set_current_dir(&original).unwrap();

        let cfg = result.expect("resolve should succeed with partial override");
        assert_eq!(cfg.server, "https://cli-ts:9999", "CLI server must win");
        assert_eq!(cfg.token, "file-tok", "token must come from file");
    }
}
