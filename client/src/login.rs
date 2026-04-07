use eframe::egui::{self, Align, Color32, Key, Layout, RichText, TextEdit, Vec2};
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{EventCode, LoginInfo, Message, MessageHead, OperatorMessage};
use zeroize::Zeroizing;

use crate::local_config::LocalConfig;

const MIN_USERNAME_LENGTH: usize = 1;
const MIN_PASSWORD_LENGTH: usize = 1;
#[allow(dead_code)]
const LOGIN_PANEL_WIDTH: f32 = 400.0;
#[allow(dead_code)]
const CONNECTING_COLOR: Color32 = Color32::from_rgb(232, 182, 83);

/// Classifies the kind of TLS failure for UI rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFailureKind {
    /// Regular TLS error (expired, hostname mismatch, etc.)
    CertificateError,
    /// First connection to an unknown server — show TOFU accept prompt.
    UnknownServer,
    /// Server certificate has changed since first trust — show SSH-style warning.
    CertificateChanged {
        /// The previously trusted fingerprint.
        stored_fingerprint: String,
    },
}

/// Details about a TLS connection failure, surfaced to the UI for actionable messaging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFailure {
    /// Actionable, human-readable description of what went wrong.
    pub message: String,
    /// SHA-256 fingerprint (64 lowercase hex chars) of the server's certificate, if captured.
    pub cert_fingerprint: Option<String>,
    /// What kind of failure this is (determines UI rendering).
    pub kind: TlsFailureKind,
}

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
}

/// Outcome of a single login dialog render pass.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum LoginAction {
    /// User has not yet submitted.
    Waiting,
    /// User submitted the login form.
    Submit,
    /// User chose to trust a new server's certificate by its fingerprint.
    TrustCertificate(String),
    /// User explicitly accepted a changed certificate (overrides the SSH-style warning).
    AcceptChangedCertificate(String),
}

/// Render the login dialog into the given egui context. Returns the action taken.
#[allow(dead_code)]
pub(crate) fn render_login_dialog(ctx: &egui::Context, state: &mut LoginState) -> LoginAction {
    let mut action = LoginAction::Waiting;

    egui::CentralPanel::default().show(ctx, |ui| {
        ui.with_layout(Layout::top_down(Align::Center), |ui| {
            ui.add_space(ui.available_height() * 0.2);

            egui::Frame::NONE
                .inner_margin(24.0)
                .corner_radius(8.0)
                .fill(Color32::from_rgb(30, 30, 36))
                .show(ui, |ui| {
                    ui.set_max_width(LOGIN_PANEL_WIDTH);

                    ui.vertical_centered(|ui| {
                        ui.heading(RichText::new("Red Cell C2").strong().size(22.0));
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("Connect to teamserver")
                                .color(Color32::from_rgb(160, 160, 170)),
                        );
                        ui.add_space(16.0);
                    });

                    ui.label("Server URL");
                    let server_response = ui.add_sized(
                        Vec2::new(LOGIN_PANEL_WIDTH, 28.0),
                        TextEdit::singleline(&mut state.server_url)
                            .hint_text("wss://host:port/havoc/"),
                    );
                    if state.focus_request == FocusRequest::ServerUrl {
                        server_response.request_focus();
                        state.focus_request = FocusRequest::None;
                    }
                    ui.add_space(8.0);

                    ui.label("Username");
                    let username_response = ui.add_sized(
                        Vec2::new(LOGIN_PANEL_WIDTH, 28.0),
                        TextEdit::singleline(&mut state.username).hint_text("operator"),
                    );
                    if state.focus_request == FocusRequest::Username {
                        username_response.request_focus();
                        state.focus_request = FocusRequest::None;
                    }
                    ui.add_space(8.0);

                    ui.label("Password");
                    let password_response = ui.add_sized(
                        Vec2::new(LOGIN_PANEL_WIDTH, 28.0),
                        TextEdit::singleline(&mut *state.password)
                            .password(true)
                            .hint_text("password"),
                    );
                    if state.focus_request == FocusRequest::Password {
                        password_response.request_focus();
                        state.focus_request = FocusRequest::None;
                    }
                    ui.add_space(12.0);

                    if let Some(error) = &state.error_message {
                        ui.colored_label(Color32::from_rgb(215, 83, 83), error);
                        ui.add_space(8.0);
                    }

                    if let Some(failure) = &state.tls_failure.clone() {
                        if let Some(tls_action) = render_tls_failure_panel(ui, failure) {
                            action = tls_action;
                        }
                        ui.add_space(8.0);
                    }

                    let enter_pressed = ui.input(|input| input.key_pressed(Key::Enter));
                    let submit_requested = enter_pressed && state.can_submit();

                    ui.with_layout(Layout::top_down(Align::Center), |ui| {
                        if state.connecting {
                            ui.colored_label(CONNECTING_COLOR, "Connecting...");
                        } else {
                            let button = ui.add_enabled(
                                state.can_submit(),
                                egui::Button::new(RichText::new("  Connect  ").strong().size(15.0))
                                    .min_size(Vec2::new(120.0, 32.0)),
                            );
                            if button.clicked() || submit_requested {
                                action = LoginAction::Submit;
                            }
                        }
                    });
                });
        });
    });

    action
}

/// Render the TLS failure panel, varying appearance by [`TlsFailureKind`].
///
/// Returns `Some(LoginAction)` if the user clicked a trust/accept button.
#[allow(dead_code)]
fn render_tls_failure_panel(ui: &mut egui::Ui, failure: &TlsFailure) -> Option<LoginAction> {
    let mut action = None;
    match &failure.kind {
        TlsFailureKind::CertificateChanged { stored_fingerprint } => {
            // SSH-style "HOST IDENTIFICATION HAS CHANGED" warning.
            egui::Frame::NONE
                .inner_margin(10.0)
                .corner_radius(4.0)
                .fill(Color32::from_rgb(80, 20, 20))
                .show(ui, |ui| {
                    ui.set_min_width(LOGIN_PANEL_WIDTH);
                    ui.colored_label(
                        Color32::from_rgb(255, 80, 80),
                        RichText::new("⚠  WARNING: SERVER CERTIFICATE HAS CHANGED!  ⚠")
                            .strong()
                            .size(14.0),
                    );
                    ui.add_space(6.0);
                    ui.colored_label(
                        Color32::from_rgb(220, 160, 160),
                        "Someone could be eavesdropping on you right now \
                         (man-in-the-middle attack). It is also possible that the \
                         server's certificate was legitimately renewed.",
                    );
                    ui.add_space(6.0);
                    ui.label(RichText::new("Previously trusted fingerprint:").small());
                    ui.add(
                        TextEdit::singleline(&mut stored_fingerprint.clone())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                    if let Some(fp) = &failure.cert_fingerprint {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Current server fingerprint:").small());
                        ui.add(
                            TextEdit::singleline(&mut fp.clone())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        );
                        ui.add_space(8.0);
                        ui.colored_label(
                            Color32::from_rgb(220, 160, 160),
                            "If you expected this change, you may accept the new certificate. \
                             Otherwise, DO NOT connect.",
                        );
                        ui.add_space(6.0);
                        if ui
                            .button(
                                RichText::new("Accept new certificate")
                                    .strong()
                                    .color(Color32::from_rgb(255, 120, 120)),
                            )
                            .on_hover_text(
                                "Replace the stored fingerprint with the new one and reconnect. \
                                 Only do this if you trust the server.",
                            )
                            .clicked()
                        {
                            action = Some(LoginAction::AcceptChangedCertificate(fp.clone()));
                        }
                    }
                });
        }
        TlsFailureKind::UnknownServer => {
            // TOFU prompt for first connection to a new server.
            egui::Frame::NONE
                .inner_margin(10.0)
                .corner_radius(4.0)
                .fill(Color32::from_rgb(40, 40, 20))
                .show(ui, |ui| {
                    ui.set_min_width(LOGIN_PANEL_WIDTH);
                    ui.colored_label(
                        Color32::from_rgb(232, 182, 83),
                        RichText::new("Unknown Server Certificate").strong(),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        "This is the first time connecting to this server. \
                         Verify the certificate fingerprint with your administrator.",
                    );
                    if let Some(fp) = &failure.cert_fingerprint {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Server certificate fingerprint:").small());
                        ui.add(
                            TextEdit::singleline(&mut fp.clone())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        );
                        ui.add_space(6.0);
                        if ui
                            .button(RichText::new("Trust this certificate").strong())
                            .on_hover_text(
                                "Store this certificate fingerprint and reconnect. \
                                 Only do this if you recognise this certificate.",
                            )
                            .clicked()
                        {
                            action = Some(LoginAction::TrustCertificate(fp.clone()));
                        }
                    }
                });
        }
        TlsFailureKind::CertificateError => {
            // Generic TLS certificate error (expired, hostname mismatch, etc.)
            egui::Frame::NONE
                .inner_margin(10.0)
                .corner_radius(4.0)
                .fill(Color32::from_rgb(50, 30, 30))
                .show(ui, |ui| {
                    ui.set_min_width(LOGIN_PANEL_WIDTH);
                    ui.colored_label(Color32::from_rgb(215, 83, 83), "TLS Certificate Error");
                    ui.add_space(4.0);
                    ui.label(&failure.message);
                    if let Some(fp) = &failure.cert_fingerprint {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Server certificate fingerprint:").small());
                        ui.add(
                            TextEdit::singleline(&mut fp.clone())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        );
                        ui.add_space(6.0);
                        if ui
                            .button(RichText::new("Trust this certificate").strong())
                            .on_hover_text(
                                "Pin this certificate fingerprint and reconnect. \
                                 Only do this if you recognise this certificate.",
                            )
                            .clicked()
                        {
                            action = Some(LoginAction::TrustCertificate(fp.clone()));
                        }
                    }
                });
        }
    }
    action
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- egui widget interaction tests ---

    use egui::{Event, Modifiers, Pos2, Rect};

    /// Helper: create a `RawInput` with a reasonable screen rect so widgets get laid out.
    fn base_raw_input() -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 600.0))),
            ..Default::default()
        }
    }

    /// Helper: prepare a `LoginState` with valid credentials ready to submit.
    fn submittable_login_state() -> LoginState {
        let mut state = default_login_state();
        state.username = "operator".to_owned();
        *state.password = "secret".to_owned();
        state
    }

    /// Run `render_login_dialog` inside a headless egui frame and return the `LoginAction`.
    fn run_dialog(
        ctx: &egui::Context,
        input: egui::RawInput,
        state: &mut LoginState,
    ) -> LoginAction {
        run_dialog_with_output(ctx, input, state).0
    }

    fn run_dialog_with_output(
        ctx: &egui::Context,
        input: egui::RawInput,
        state: &mut LoginState,
    ) -> (LoginAction, egui::FullOutput) {
        let mut action = LoginAction::Waiting;
        let output = ctx.run(input, |ctx| {
            action = render_login_dialog(ctx, state);
        });
        (action, output)
    }

    /// Build a `RawInput` that injects an Enter key press.
    fn input_with_enter() -> egui::RawInput {
        let mut input = base_raw_input();
        input.events.push(Event::Key {
            key: Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Modifiers::NONE,
        });
        input
    }

    /// Build a `RawInput` that simulates a pointer click at `pos`.
    fn input_with_click(pos: Pos2) -> egui::RawInput {
        let mut input = base_raw_input();
        input.events.push(Event::PointerMoved(pos));
        input.events.push(Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: Modifiers::NONE,
        });
        input.events.push(Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: Modifiers::NONE,
        });
        input
    }

    fn collect_shape_text(shape: &egui::epaint::Shape, text: &mut String) {
        match shape {
            egui::epaint::Shape::Text(text_shape) => {
                text.push_str(&text_shape.galley.job.text);
                text.push('\n');
            }
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect_shape_text(shape, text);
                }
            }
            _ => {}
        }
    }

    fn find_text_rect_in_shape(shape: &egui::epaint::Shape, needle: &str) -> Option<Rect> {
        match shape {
            egui::epaint::Shape::Text(text_shape) => text_shape
                .galley
                .job
                .text
                .contains(needle)
                .then(|| text_shape.visual_bounding_rect()),
            egui::epaint::Shape::Vec(shapes) => {
                shapes.iter().find_map(|shape| find_text_rect_in_shape(shape, needle))
            }
            _ => None,
        }
    }

    fn rendered_text(output: &egui::FullOutput) -> String {
        let mut text = String::new();
        for clipped_shape in &output.shapes {
            collect_shape_text(&clipped_shape.shape, &mut text);
        }
        text
    }

    fn find_rendered_text_rect(output: &egui::FullOutput, needle: &str) -> Option<Rect> {
        output
            .shapes
            .iter()
            .find_map(|clipped_shape| find_text_rect_in_shape(&clipped_shape.shape, needle))
    }

    #[test]
    fn render_enter_key_submits_when_form_valid() {
        let ctx = egui::Context::default();
        let mut state = submittable_login_state();

        // First frame: lay out widgets.
        run_dialog(&ctx, base_raw_input(), &mut state);

        // Second frame: inject Enter key press.
        let action = run_dialog(&ctx, input_with_enter(), &mut state);
        assert_eq!(action, LoginAction::Submit);
    }

    #[test]
    fn render_enter_key_does_not_submit_while_connecting() {
        let ctx = egui::Context::default();
        let mut state = submittable_login_state();
        state.set_connecting();

        // First frame: lay out.
        run_dialog(&ctx, base_raw_input(), &mut state);

        // Second frame: inject Enter key — should not submit.
        let action = run_dialog(&ctx, input_with_enter(), &mut state);
        assert_eq!(action, LoginAction::Waiting);
    }

    #[test]
    fn render_trust_certificate_button_returns_fingerprint() {
        let ctx = egui::Context::default();
        let fingerprint = "aabbccdd11223344";
        let mut state = submittable_login_state();
        state.set_tls_failure(make_tls_failure("cert error", Some(fingerprint)));

        // First frame: lay out widgets.
        run_dialog(&ctx, base_raw_input(), &mut state);

        // Scan the central panel area for a click that produces
        // `TrustCertificate`. The dialog is centred in 800x600 with a
        // 400px panel, so widgets sit within roughly x 150–650, y 50–550.
        let mut found = false;
        'outer: for y in (50..550).step_by(10) {
            for x in (150..650).step_by(10) {
                let pos = Pos2::new(x as f32, y as f32);
                state.tls_failure = Some(make_tls_failure("cert error", Some(fingerprint)));
                let action = run_dialog(&ctx, input_with_click(pos), &mut state);
                if action == LoginAction::TrustCertificate(fingerprint.to_owned()) {
                    found = true;
                    break 'outer;
                }
            }
        }
        assert!(found, "should find and click 'Trust this certificate' button");
    }

    #[test]
    fn render_tls_failure_without_fingerprint_has_no_trust_button() {
        let ctx = egui::Context::default();
        let mut state = submittable_login_state();
        state.set_tls_failure(make_tls_failure("cert error", None));

        // First frame: lay out.
        run_dialog(&ctx, base_raw_input(), &mut state);

        // Scan the entire interactive area — no click should produce
        // TrustCertificate when the fingerprint is absent.
        for y in (50..550).step_by(10) {
            for x in (150..650).step_by(10) {
                let pos = Pos2::new(x as f32, y as f32);
                state.tls_failure = Some(make_tls_failure("cert error", None));
                let action = run_dialog(&ctx, input_with_click(pos), &mut state);
                assert!(
                    !matches!(action, LoginAction::TrustCertificate(_)),
                    "TrustCertificate should not be possible without a fingerprint"
                );
            }
        }
    }

    #[test]
    fn render_accept_changed_certificate_button_returns_new_fingerprint() {
        let ctx = egui::Context::default();
        let stored_fingerprint = "stored001122334455";
        let new_fingerprint = "newaabbccddeeff00";
        let mut state = submittable_login_state();
        state.set_tls_failure(make_changed_certificate_failure(
            "certificate changed",
            stored_fingerprint,
            Some(new_fingerprint),
        ));

        let (_, output) = run_dialog_with_output(&ctx, base_raw_input(), &mut state);
        let button_rect = find_rendered_text_rect(&output, "Accept new certificate")
            .expect("should render 'Accept new certificate' button text");

        state.tls_failure = Some(make_changed_certificate_failure(
            "certificate changed",
            stored_fingerprint,
            Some(new_fingerprint),
        ));
        let action = run_dialog(&ctx, input_with_click(button_rect.center()), &mut state);

        assert_eq!(action, LoginAction::AcceptChangedCertificate(new_fingerprint.to_owned()));
    }

    #[test]
    fn render_changed_certificate_panel_shows_stored_and_current_fingerprints() {
        let ctx = egui::Context::default();
        let stored_fingerprint = "stored001122334455";
        let new_fingerprint = "newaabbccddeeff00";
        let mut state = submittable_login_state();
        state.set_tls_failure(make_changed_certificate_failure(
            "certificate changed",
            stored_fingerprint,
            Some(new_fingerprint),
        ));

        let (_, output) = run_dialog_with_output(&ctx, base_raw_input(), &mut state);
        let rendered = rendered_text(&output);

        assert!(
            rendered.contains("Previously trusted fingerprint:"),
            "warning panel should label the stored fingerprint"
        );
        assert!(
            rendered.contains(stored_fingerprint),
            "warning panel should show the stored fingerprint"
        );
        assert!(
            rendered.contains("Current server fingerprint:"),
            "warning panel should label the current fingerprint"
        );
        assert!(
            rendered.contains(new_fingerprint),
            "warning panel should show the new fingerprint"
        );
        assert!(
            rendered.contains("Accept new certificate"),
            "warning panel should render the acceptance button"
        );
    }
}
