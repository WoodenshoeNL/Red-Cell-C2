use std::fs;
use std::path::Path;
use std::sync::Mutex;

use tempfile::TempDir;

use super::discovery::no_config_on_disk;
use super::file::{load_config_file, write_config_file};
use super::find_config_file;
#[cfg(unix)]
use super::permissions::config_permission_tightening_warning;
use super::resolve::{resolve, resolve_with_global};
use super::types::{ConfigError, FileConfig, FingerprintPinMode, TlsMode};

/// Serialises tests that mutate the process-wide CWD.
static CWD_LOCK: Mutex<()> = Mutex::new(());

fn write_config(dir: &Path, content: &str) -> std::path::PathBuf {
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
    let err = resolve_with_global(None, Some("tok".to_owned()), None, None, None, false, None);
    std::env::set_current_dir(&original).unwrap();
    assert!(matches!(err, Err(ConfigError::MissingServer)));
}

#[test]
fn resolve_returns_missing_token_error() {
    let tmp = TempDir::new().unwrap();
    let _guard = CWD_LOCK.lock().unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();
    let err = resolve_with_global(
        Some("https://ts:40056".to_owned()),
        None,
        None,
        None,
        None,
        false,
        None,
    );
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
    let err = resolve_with_global(
        Some("https://ts:40056".to_owned()),
        Some("tok".to_owned()),
        Some(30),
        None,
        None,
        true,
        None,
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

// ── no_config_on_disk (is_unconfigured helper) ────────────────────────

#[test]
fn no_config_on_disk_true_in_empty_dir() {
    let tmp = TempDir::new().unwrap();
    assert!(no_config_on_disk(tmp.path(), None));
}

#[test]
fn no_config_on_disk_false_when_local_config_exists() {
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path(), "server = \"https://ts:40056\"\ntoken = \"t\"");
    assert!(!no_config_on_disk(tmp.path(), None));
}

#[test]
fn no_config_on_disk_false_when_parent_config_exists() {
    let tmp = TempDir::new().unwrap();
    write_config(tmp.path(), "server = \"https://ts:40056\"");
    let child = tmp.path().join("sub");
    fs::create_dir_all(&child).unwrap();
    assert!(!no_config_on_disk(&child, None));
}

#[test]
fn no_config_on_disk_false_when_global_config_exists() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global-config.toml");
    fs::write(&global, "server = \"https://ts:40056\"").unwrap();
    let empty = TempDir::new().unwrap();
    assert!(!no_config_on_disk(empty.path(), Some(global.as_path())));
}

#[test]
fn load_config_ignores_unknown_enable_local_shell_key() {
    let tmp = TempDir::new().unwrap();
    let path = write_config(
        tmp.path(),
        "server = \"https://ts:40056\"\ntoken = \"t\"\nenable_local_shell = true",
    );
    let cfg = load_config_file(&path).unwrap();
    assert_eq!(cfg.server.as_deref(), Some("https://ts:40056"));
    assert_eq!(cfg.token.as_deref(), Some("t"));
}
