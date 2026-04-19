use std::fs;
use std::path::PathBuf;

use red_cell_client::local_config::LocalConfig;
use red_cell_client::login::LoginState;
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{EventCode, OperatorMessage};

fn login_message_for(
    config: &LocalConfig,
    cli_server: &str,
    password: &str,
) -> (LoginState, OperatorMessage) {
    let mut state = LoginState::new(cli_server, config);
    *state.password = password.to_owned();
    let message = state.build_login_message();
    (state, message)
}

#[test]
fn persisted_config_populates_login_state_and_message() {
    let tempdir = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("tempdir creation should succeed: {error}"));
    let config_path = tempdir.path().join("client.toml");
    let persisted = LocalConfig {
        server_url: Some("wss://saved.example:40056/havoc/".to_owned()),
        username: Some("operator".to_owned()),
        scripts_dir: Some(tempdir.path().join("scripts")),
        ca_cert: Some(tempdir.path().join("ca.pem")),
        cert_fingerprint: Some("0123456789abcdef".to_owned()),
        python_script_timeout_secs: None,
        log_dir: None,
        log_level: None,
        api_key: None,
    };

    persisted.save_to(&config_path).unwrap_or_else(|e| panic!("save_to should succeed: {e}"));
    let loaded = LocalConfig::load_from(&config_path);
    let (state, message) = login_message_for(&loaded, "wss://cli.example/havoc/", "secret");

    assert_eq!(state.server_url, "wss://saved.example:40056/havoc/");
    assert_eq!(state.username, "operator");
    assert_eq!(loaded.ca_cert, Some(tempdir.path().join("ca.pem")));
    assert_eq!(loaded.cert_fingerprint.as_deref(), Some("0123456789abcdef"));

    let OperatorMessage::Login(message) = message else {
        panic!("expected login message");
    };
    assert_eq!(message.head.event, EventCode::InitConnection);
    assert_eq!(message.head.user, "operator");
    assert_eq!(message.info.user, "operator");
    assert_eq!(message.info.password, hash_password_sha3("secret"));
}

#[test]
fn malformed_persisted_config_falls_back_to_defaults() {
    let tempdir = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("tempdir creation should succeed: {error}"));
    let config_path = tempdir.path().join("client.toml");
    fs::write(&config_path, "server_url = [")
        .unwrap_or_else(|error| panic!("invalid config write should succeed: {error}"));

    let loaded = LocalConfig::load_from(&config_path);
    let (state, message) = login_message_for(&loaded, "wss://cli.example/havoc/", "fallback");

    assert_eq!(loaded, LocalConfig::default());
    assert_eq!(state.server_url, "wss://cli.example/havoc/");
    assert!(state.username.is_empty());

    let OperatorMessage::Login(message) = message else {
        panic!("expected login message");
    };
    assert_eq!(message.head.event, EventCode::InitConnection);
    assert_eq!(message.head.user, "");
    assert_eq!(message.info.user, "");
    assert_eq!(message.info.password, hash_password_sha3("fallback"));
}

#[test]
fn optional_tls_fields_remain_unset_in_persisted_flow() {
    let tempdir = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("tempdir creation should succeed: {error}"));
    let config_path = tempdir.path().join("client.toml");
    let persisted = LocalConfig {
        server_url: Some("wss://saved.example:40056/havoc/".to_owned()),
        username: Some("operator".to_owned()),
        scripts_dir: Some(PathBuf::from("/tmp/scripts")),
        ca_cert: None,
        cert_fingerprint: None,
        python_script_timeout_secs: None,
        log_dir: None,
        log_level: None,
        api_key: None,
    };

    persisted.save_to(&config_path).unwrap_or_else(|e| panic!("save_to should succeed: {e}"));
    let serialized = fs::read_to_string(&config_path)
        .unwrap_or_else(|error| panic!("saved config should be readable: {error}"));
    let loaded = LocalConfig::load_from(&config_path);
    let (_, message) = login_message_for(&loaded, "wss://cli.example/havoc/", "secret");

    assert!(!serialized.contains("ca_cert"));
    assert!(!serialized.contains("cert_fingerprint"));
    assert_eq!(loaded.ca_cert, None);
    assert_eq!(loaded.cert_fingerprint, None);

    let OperatorMessage::Login(message) = message else {
        panic!("expected login message");
    };
    assert_eq!(message.head.user, "operator");
    assert_eq!(message.info.user, "operator");
}

#[test]
fn nonexistent_config_file_falls_back_to_defaults() {
    let tempdir = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("tempdir creation should succeed: {error}"));
    let config_path = tempdir.path().join("never_written.toml");

    let loaded = LocalConfig::load_from(&config_path);
    let (state, message) = login_message_for(&loaded, "wss://cli.example/havoc/", "firstrun");

    assert_eq!(loaded, LocalConfig::default());
    assert_eq!(state.server_url, "wss://cli.example/havoc/");
    assert!(state.username.is_empty());

    let OperatorMessage::Login(message) = message else {
        panic!("expected login message");
    };
    assert_eq!(message.head.event, EventCode::InitConnection);
    assert_eq!(message.head.user, "");
    assert_eq!(message.info.user, "");
    assert_eq!(message.info.password, hash_password_sha3("firstrun"));
}
