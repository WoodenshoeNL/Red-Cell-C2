use super::*;

#[test]
fn client_app_state_initializes_placeholder_state() {
    let app_state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    assert_eq!(app_state.server_url, "wss://127.0.0.1:40056/havoc/");
    assert_eq!(app_state.connection_status, ConnectionStatus::Disconnected);
    assert!(app_state.operator_info.is_none());
    assert!(app_state.agents.is_empty());
    assert!(app_state.agent_consoles.is_empty());
    assert!(app_state.process_lists.is_empty());
    assert!(app_state.listeners.is_empty());
    assert!(app_state.loot.is_empty());
    assert!(app_state.event_log.entries.is_empty());
    assert!(app_state.online_operators.is_empty());
}

#[test]
fn client_app_starts_in_login_phase() {
    let cli = Cli {
        server: DEFAULT_SERVER_URL.to_owned(),
        scripts_dir: None,
        ca_cert: None,
        cert_fingerprint: None,
        accept_invalid_certs: false,
        purge_known_server: None,
    };
    let app = ClientApp::new(cli).unwrap();
    assert!(matches!(app.phase, AppPhase::Login(_)));
}

#[test]
fn client_app_login_state_uses_cli_default() {
    let cli = Cli {
        server: "wss://custom:1234/havoc/".to_owned(),
        scripts_dir: None,
        ca_cert: None,
        cert_fingerprint: None,
        accept_invalid_certs: false,
        purge_known_server: None,
    };
    let app = ClientApp::new(cli).unwrap();
    match &app.phase {
        AppPhase::Login(state) => {
            if app.local_config.server_url.is_none() {
                assert_eq!(state.server_url, "wss://custom:1234/havoc/");
            }
        }
        _ => panic!("expected Login phase"),
    }
}
