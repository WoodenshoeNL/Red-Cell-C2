use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{EventCode, LoginInfo, Message, MessageHead, OperatorMessage};
use zeroize::Zeroizing;

use crate::local_config::LocalConfig;

use super::types::TlsFailure;

const MIN_USERNAME_LENGTH: usize = 1;
const MIN_PASSWORD_LENGTH: usize = 1;

/// Tracks which field should receive initial focus on the next frame.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum FocusRequest {
    ServerUrl,
    Username,
    Password,
    None,
}

/// Mutable state for the login dialog.
#[derive(Clone, Debug)]
pub struct LoginState {
    pub server_url: String,
    pub username: String,
    /// Login password, wrapped in [`Zeroizing`] so that heap memory is wiped on drop.
    pub password: Zeroizing<String>,
    pub error_message: Option<String>,
    pub connecting: bool,
    focus_request: FocusRequest,
    /// Set when the last connection failed due to a TLS certificate error.
    pub tls_failure: Option<TlsFailure>,
}

impl LoginState {
    /// Create login state pre-populated from local config and CLI defaults.
    pub fn new(cli_server_url: &str, config: &LocalConfig) -> Self {
        let server_url = config.server_url.as_deref().unwrap_or(cli_server_url).to_owned();
        let username = config.username.clone().unwrap_or_default();

        let focus_request =
            if username.is_empty() { FocusRequest::Username } else { FocusRequest::Password };

        Self {
            server_url,
            username,
            password: Zeroizing::new(String::new()),
            error_message: None,
            connecting: false,
            focus_request,
            tls_failure: None,
        }
    }

    /// Returns true when the form fields pass basic validation.
    pub fn can_submit(&self) -> bool {
        !self.connecting
            && !self.server_url.trim().is_empty()
            && self.username.trim().len() >= MIN_USERNAME_LENGTH
            && self.password.len() >= MIN_PASSWORD_LENGTH
    }

    /// Build the `OperatorMessage::Login` message from the current form state.
    pub fn build_login_message(&self) -> OperatorMessage {
        OperatorMessage::Login(Message {
            head: MessageHead {
                event: EventCode::InitConnection,
                user: self.username.trim().to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: LoginInfo {
                user: self.username.trim().to_owned(),
                password: hash_password_sha3(&self.password),
            },
        })
    }

    /// Record an authentication error to display on the login dialog.
    pub fn set_error(&mut self, message: String) {
        self.error_message = Some(message);
        self.connecting = false;
        self.focus_request = FocusRequest::Password;
    }

    /// Record a TLS failure with optional certificate fingerprint for the UI prompt.
    pub fn set_tls_failure(&mut self, failure: TlsFailure) {
        self.tls_failure = Some(failure);
    }

    /// Mark the login as in-progress (disables the form).
    pub fn set_connecting(&mut self) {
        self.connecting = true;
        self.error_message = None;
        self.tls_failure = None;
    }

    /// Zeroizes the password buffer and replaces it with an empty string.
    ///
    /// Call this as soon as authentication succeeds so the plaintext password is not retained
    /// for the rest of the session. Re-authentication (session expiry, reconnect) must collect
    /// the password from the user again; [`LoginState::new`](Self::new) starts with an empty
    /// password field.
    pub fn clear_password(&mut self) {
        self.password = Zeroizing::new(String::new());
    }

    /// If the server URL field is pending focus, consume the request and return `true`.
    pub fn take_server_url_focus(&mut self) -> bool {
        if self.focus_request == FocusRequest::ServerUrl {
            self.focus_request = FocusRequest::None;
            true
        } else {
            false
        }
    }

    /// If the username field is pending focus, consume the request and return `true`.
    pub fn take_username_focus(&mut self) -> bool {
        if self.focus_request == FocusRequest::Username {
            self.focus_request = FocusRequest::None;
            true
        } else {
            false
        }
    }

    /// If the password field is pending focus, consume the request and return `true`.
    pub fn take_password_focus(&mut self) -> bool {
        if self.focus_request == FocusRequest::Password {
            self.focus_request = FocusRequest::None;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_config::LocalConfig;
    use red_cell_common::crypto::hash_password_sha3;
    use red_cell_common::operator::{EventCode, OperatorMessage};
    use zeroize::Zeroizing;

    use crate::login::types::{TlsFailure, TlsFailureKind};

    fn default_login_state() -> LoginState {
        LoginState::new("wss://127.0.0.1:40056/havoc/", &LocalConfig::default())
    }

    #[test]
    fn login_state_uses_cli_default_when_config_empty() {
        let state = default_login_state();
        assert_eq!(state.server_url, "wss://127.0.0.1:40056/havoc/");
        assert!(state.username.is_empty());
        assert!(state.password.is_empty());
        assert!(!state.connecting);
        assert!(state.error_message.is_none());
    }

    #[test]
    fn login_state_prefers_config_values() {
        let config = LocalConfig {
            server_url: Some("wss://saved.example:9999/havoc/".to_owned()),
            username: Some("saved-user".to_owned()),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            python_script_timeout_secs: None,
            log_dir: None,
            log_level: None,
            api_key: None,
        };
        let state = LoginState::new("wss://cli-default/havoc/", &config);

        assert_eq!(state.server_url, "wss://saved.example:9999/havoc/");
        assert_eq!(state.username, "saved-user");
    }

    #[test]
    fn can_submit_requires_all_fields() {
        let mut state = default_login_state();
        assert!(!state.can_submit());

        state.username = "user".to_owned();
        assert!(!state.can_submit());

        *state.password = "pass".to_owned();
        assert!(state.can_submit());
    }

    #[test]
    fn can_submit_false_when_connecting() {
        let mut state = default_login_state();
        state.username = "user".to_owned();
        *state.password = "pass".to_owned();
        state.set_connecting();
        assert!(!state.can_submit());
    }

    #[test]
    fn can_submit_rejects_whitespace_only_fields() {
        let mut state = default_login_state();
        state.username = "   ".to_owned();
        *state.password = "pass".to_owned();
        assert!(!state.can_submit());

        state.server_url = "  ".to_owned();
        state.username = "user".to_owned();
        assert!(!state.can_submit());
    }

    #[test]
    fn build_login_message_hashes_password() {
        let mut state = default_login_state();
        state.username = "operator".to_owned();
        *state.password = "secret".to_owned();

        let message = state.build_login_message();
        match message {
            OperatorMessage::Login(msg) => {
                assert_eq!(msg.info.user, "operator");
                assert_eq!(msg.info.password, hash_password_sha3("secret"));
                assert_eq!(msg.info.password.len(), 64);
                assert_eq!(msg.head.event, EventCode::InitConnection);
            }
            other => panic!("expected Login variant, got {other:?}"),
        }
    }

    #[test]
    fn build_login_message_trims_username() {
        let mut state = default_login_state();
        state.username = "  operator  ".to_owned();
        *state.password = "pass".to_owned();

        let message = state.build_login_message();
        match message {
            OperatorMessage::Login(msg) => {
                assert_eq!(msg.info.user, "operator");
                assert_eq!(msg.head.user, "operator");
            }
            other => panic!("expected Login variant, got {other:?}"),
        }
    }

    /// Passwords are intentionally NOT trimmed before the length check — a password of spaces
    /// is valid (the server will reject it during authentication). This test documents that
    /// contract so that adding `trim()` to the password check in the future is a conscious,
    /// breaking decision rather than an accidental refactor.
    #[test]
    fn can_submit_accepts_whitespace_only_password() {
        let mut state = default_login_state();
        state.username = "user".to_owned();
        *state.password = "   ".to_owned(); // three spaces — meets MIN_PASSWORD_LENGTH
        assert!(state.can_submit());
    }

    /// `build_login_message` hashes the raw password without trimming. A password with
    /// surrounding spaces must be hashed as-is so that the server can verify it against
    /// the same raw value. This test documents that contract explicitly.
    #[test]
    fn build_login_message_does_not_trim_password() {
        let mut state = default_login_state();
        state.username = "operator".to_owned();
        *state.password = " secret".to_owned(); // leading space is intentional

        let message = state.build_login_message();
        match message {
            OperatorMessage::Login(msg) => {
                assert_eq!(msg.info.password, hash_password_sha3(" secret"));
                assert_ne!(msg.info.password, hash_password_sha3("secret"));
            }
            other => panic!("expected Login variant, got {other:?}"),
        }
    }

    /// The password field must be `Zeroizing<String>` so that heap memory is wiped on drop.
    /// This test is a compile-time contract: if the field type is changed to a bare `String`,
    /// the `Zeroizing::clone` call below will fail to compile.
    #[test]
    fn password_field_is_zeroizing() {
        let mut state = default_login_state();
        *state.password = "hunter2".to_owned();
        // Confirm we hold a Zeroizing<String> — the explicit type annotation is the assertion.
        let _z: Zeroizing<String> = state.password.clone();
        assert_eq!(*_z, "hunter2");
    }

    #[test]
    fn clear_password_removes_secret_and_requires_re_entry_to_submit() {
        let mut state = default_login_state();
        state.username = "u".to_owned();
        *state.password = "secret".to_owned();
        assert!(state.can_submit());

        state.clear_password();
        assert!(state.password.is_empty());
        assert!(!state.can_submit());

        *state.password = "again".to_owned();
        assert!(state.can_submit());
    }

    #[test]
    fn set_error_clears_connecting_flag() {
        let mut state = default_login_state();
        state.set_connecting();
        assert!(state.connecting);

        state.set_error("invalid credentials".to_owned());
        assert!(!state.connecting);
        assert_eq!(state.error_message.as_deref(), Some("invalid credentials"));
    }

    /// After an authentication error the cursor should land on the password field so the
    /// user can retype immediately without reaching for the mouse.
    #[test]
    fn set_error_requests_password_focus() {
        let mut state = default_login_state();
        // Start from a neutral focus state.
        state.focus_request = FocusRequest::None;

        state.set_error("wrong password".to_owned());
        assert_eq!(state.focus_request, FocusRequest::Password);
    }

    #[test]
    fn set_connecting_clears_error() {
        let mut state = default_login_state();
        state.set_error("previous error".to_owned());
        assert!(state.error_message.is_some());

        state.set_connecting();
        assert!(state.connecting);
        assert!(state.error_message.is_none());
    }

    fn make_tls_failure(msg: &str, fp: Option<&str>) -> TlsFailure {
        TlsFailure {
            message: msg.to_owned(),
            cert_fingerprint: fp.map(str::to_owned),
            kind: TlsFailureKind::CertificateError,
        }
    }

    fn make_changed_certificate_failure(
        msg: &str,
        stored_fingerprint: &str,
        new_fingerprint: Option<&str>,
    ) -> TlsFailure {
        TlsFailure {
            message: msg.to_owned(),
            cert_fingerprint: new_fingerprint.map(str::to_owned),
            kind: TlsFailureKind::CertificateChanged {
                stored_fingerprint: stored_fingerprint.to_owned(),
            },
        }
    }

    #[test]
    fn set_tls_failure_stores_failure() {
        let mut state = default_login_state();
        let failure = make_tls_failure("certificate not trusted", Some("aabbcc"));
        state.set_tls_failure(failure.clone());
        assert_eq!(state.tls_failure, Some(failure));
    }

    #[test]
    fn set_connecting_clears_tls_failure() {
        let mut state = default_login_state();
        state.set_tls_failure(make_tls_failure("cert error", None));
        assert!(state.tls_failure.is_some());

        state.set_connecting();
        assert!(state.tls_failure.is_none());
    }

    #[test]
    fn set_error_does_not_clear_tls_failure() {
        let mut state = default_login_state();
        let failure = make_tls_failure("cert error", Some("deadbeef"));
        state.set_tls_failure(failure.clone());
        state.set_error("auth failed".to_owned());
        assert_eq!(state.tls_failure, Some(failure));
    }

    #[test]
    fn new_focuses_username_when_no_saved_username() {
        let state = default_login_state();
        assert_eq!(state.focus_request, FocusRequest::Username);
    }

    #[test]
    fn new_focuses_password_when_username_saved() {
        let config = LocalConfig {
            server_url: None,
            username: Some("saved-user".to_owned()),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            python_script_timeout_secs: None,
            log_dir: None,
            log_level: None,
            api_key: None,
        };
        let state = LoginState::new("wss://localhost/havoc/", &config);
        assert_eq!(state.focus_request, FocusRequest::Password);
    }

    #[test]
    fn take_username_focus_consumes_request_once() {
        let mut state = default_login_state(); // starts with FocusRequest::Username
        assert!(state.take_username_focus());
        assert!(!state.take_username_focus()); // consumed
    }

    #[test]
    fn take_password_focus_returns_true_only_for_matching_field() {
        let mut state = default_login_state(); // starts with FocusRequest::Username
        assert!(!state.take_password_focus());
        assert!(!state.take_server_url_focus());
    }
}
