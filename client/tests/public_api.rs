//! Smoke tests for the `red_cell_client` crate-root public API exports.
//!
//! These tests exercise the crate as a downstream consumer would, importing
//! types through the public module re-exports in `lib.rs`.  Any accidental
//! visibility change will cause a compile-time or assertion failure here.

use red_cell_client::local_config::LocalConfig;
use red_cell_client::login::LoginState;

// ── Happy-path construction ────────────────────────────────────────────────

#[test]
fn local_config_default_round_trips() {
    let cfg = LocalConfig::default();
    assert_eq!(cfg.server_url, None);
    assert_eq!(cfg.username, None);
    assert_eq!(cfg.scripts_dir, None);
    assert_eq!(cfg.ca_cert, None);
    assert_eq!(cfg.cert_fingerprint, None);
    assert_eq!(cfg.log_dir, None);
    assert_eq!(cfg.log_level, None);
}

#[test]
fn login_state_new_uses_cli_default_when_config_empty() {
    let cfg = LocalConfig::default();
    let state = LoginState::new("wss://127.0.0.1:40056", &cfg);

    assert_eq!(state.server_url, "wss://127.0.0.1:40056");
    assert!(state.username.is_empty());
    assert!(state.password.is_empty());
    assert!(!state.connecting);
    assert!(state.error_message.is_none());
    assert!(state.tls_failure.is_none());
}

#[test]
fn login_state_prefers_config_url_over_cli() {
    let cfg = LocalConfig {
        server_url: Some("wss://saved:9999".into()),
        username: Some("operator".into()),
        ..Default::default()
    };
    let state = LoginState::new("wss://cli-default:40056", &cfg);

    assert_eq!(state.server_url, "wss://saved:9999");
    assert_eq!(state.username, "operator");
}

// ── API contract ───────────────────────────────────────────────────────────

#[test]
fn crate_reexports_local_config_module() {
    // Ensures the `local_config` module is reachable from the crate root.
    // A compile-time check — the assertion is secondary.
    let _cfg: LocalConfig = Default::default();
}

#[test]
fn crate_reexports_login_module() {
    // Ensures the `login` module is reachable from the crate root.
    let cfg = LocalConfig::default();
    let _state = LoginState::new("wss://localhost:40056", &cfg);
}

// ── Regression guards ──────────────────────────────────────────────────────

#[test]
fn login_state_can_submit_requires_non_empty_fields() {
    let cfg = LocalConfig::default();
    let mut state = LoginState::new("wss://localhost:40056", &cfg);

    // Empty username + empty password → cannot submit
    assert!(!state.can_submit());

    state.username = "op".into();
    *state.password = "pass".into();
    assert!(state.can_submit());

    // Connecting flag blocks submission
    state.connecting = true;
    assert!(!state.can_submit());
}
