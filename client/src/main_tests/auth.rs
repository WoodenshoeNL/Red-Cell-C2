use super::*;

/// Build a `ClientApp` in the `Authenticating` phase with the given shared state.
fn app_in_authenticating_phase(app_state: SharedAppState) -> ClientApp {
    let login_state = LoginState::new(DEFAULT_SERVER_URL, &LocalConfig::default());
    ClientApp {
        phase: AppPhase::Authenticating {
            app_state,
            transport: ClientTransport::dummy(),
            login_state,
        },
        local_config: LocalConfig::default(),
        known_servers: KnownServersStore::default(),
        cli_server_url: DEFAULT_SERVER_URL.to_owned(),
        scripts_dir: None,
        tls_verification: TlsVerification::CertificateAuthority,
        session_panel: SessionPanelState::default(),
        outgoing_tx: None,
        python_runtime: None,
        show_known_servers: false,
        retained_app_state: None,
    }
}

#[test]
fn check_auth_response_retrying_without_auth_error_transitions_to_login() {
    let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let app_state: SharedAppState = Arc::new(Mutex::new(state));
    {
        let mut s = app_state.lock().unwrap();
        s.connection_status = ConnectionStatus::Retrying("Connection closed by server".to_owned());
        // last_auth_error is None — server closed without sending an explicit error
    }

    let mut app = app_in_authenticating_phase(app_state);
    app.check_auth_response();

    match &app.phase {
        AppPhase::Login(login_state) => {
            assert!(
                login_state.error_message.is_some(),
                "expected an error message on the login state"
            );
            assert!(
                login_state.error_message.as_deref().unwrap().contains("Connection closed"),
                "error should contain the disconnect reason"
            );
        }
        _ => panic!("expected Login phase after Retrying during auth without last_auth_error"),
    }
}

#[test]
fn check_auth_response_retrying_with_auth_error_uses_auth_error() {
    let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let app_state: SharedAppState = Arc::new(Mutex::new(state));
    {
        let mut s = app_state.lock().unwrap();
        s.connection_status = ConnectionStatus::Retrying("WebSocket closed".to_owned());
        s.last_auth_error = Some("Invalid credentials".to_owned());
    }

    let mut app = app_in_authenticating_phase(app_state);
    app.check_auth_response();

    match &app.phase {
        AppPhase::Login(login_state) => {
            assert_eq!(
                login_state.error_message.as_deref(),
                Some("Invalid credentials"),
                "should prefer last_auth_error over retry reason"
            );
        }
        _ => panic!("expected Login phase"),
    }
}

#[test]
fn check_auth_response_error_transitions_to_login() {
    let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let app_state: SharedAppState = Arc::new(Mutex::new(state));
    {
        let mut s = app_state.lock().unwrap();
        s.connection_status = ConnectionStatus::Error("Authentication failed".to_owned());
    }

    let mut app = app_in_authenticating_phase(app_state);
    app.check_auth_response();

    match &app.phase {
        AppPhase::Login(login_state) => {
            assert_eq!(login_state.error_message.as_deref(), Some("Authentication failed"));
        }
        _ => panic!("expected Login phase after Error during auth"),
    }
}

#[test]
fn check_auth_response_connecting_stays_authenticating() {
    let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let app_state: SharedAppState = Arc::new(Mutex::new(state));
    // Default status is Disconnected but let's set Connecting to test the _ => None arm
    {
        let mut s = app_state.lock().unwrap();
        s.connection_status = ConnectionStatus::Connected;
    }

    let mut app = app_in_authenticating_phase(app_state);
    app.check_auth_response();

    assert!(
        matches!(app.phase, AppPhase::Authenticating { .. }),
        "should remain in Authenticating when status is Connected but no operator_info"
    );
}

#[test]
fn check_auth_response_success_transitions_to_connected() {
    use red_cell_common::OperatorInfo;

    let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let app_state: SharedAppState = Arc::new(Mutex::new(state));
    {
        let mut s = app_state.lock().unwrap();
        s.operator_info = Some(OperatorInfo {
            username: "operator".to_owned(),
            password_hash: None,
            role: None,
            online: true,
            last_seen: None,
        });
    }

    let mut app = app_in_authenticating_phase(app_state);
    app.check_auth_response();

    assert!(
        matches!(app.phase, AppPhase::Connected { .. }),
        "expected Connected after operator_info is populated"
    );
}
