use eframe::egui::{self, Align, Color32, Key, Layout, RichText, TextEdit, Vec2};
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{EventCode, LoginInfo, Message, MessageHead, OperatorMessage};

use crate::local_config::LocalConfig;
use crate::transport::ConnectionStatus;

const MIN_USERNAME_LENGTH: usize = 1;
const MIN_PASSWORD_LENGTH: usize = 1;
const LOGIN_PANEL_WIDTH: f32 = 400.0;

/// Tracks which field should receive initial focus on the next frame.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FocusRequest {
    ServerUrl,
    Username,
    Password,
    None,
}

/// Mutable state for the login dialog.
#[derive(Clone, Debug)]
pub(crate) struct LoginState {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub error_message: Option<String>,
    pub connecting: bool,
    focus_request: FocusRequest,
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
            password: String::new(),
            error_message: None,
            connecting: false,
            focus_request,
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

    /// Mark the login as in-progress (disables the form).
    pub fn set_connecting(&mut self) {
        self.connecting = true;
        self.error_message = None;
    }
}

/// Outcome of a single login dialog render pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LoginAction {
    /// User has not yet submitted.
    Waiting,
    /// User submitted the login form.
    Submit,
}

/// Render the login dialog into the given egui context. Returns the action taken.
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
                        TextEdit::singleline(&mut state.password)
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

                    let enter_pressed = ui.input(|input| input.key_pressed(Key::Enter));
                    let submit_requested = enter_pressed && state.can_submit();

                    ui.with_layout(Layout::top_down(Align::Center), |ui| {
                        if state.connecting {
                            ui.colored_label(ConnectionStatus::Connecting.color(), "Connecting...");
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

        state.password = "pass".to_owned();
        assert!(state.can_submit());
    }

    #[test]
    fn can_submit_false_when_connecting() {
        let mut state = default_login_state();
        state.username = "user".to_owned();
        state.password = "pass".to_owned();
        state.set_connecting();
        assert!(!state.can_submit());
    }

    #[test]
    fn can_submit_rejects_whitespace_only_fields() {
        let mut state = default_login_state();
        state.username = "   ".to_owned();
        state.password = "pass".to_owned();
        assert!(!state.can_submit());

        state.server_url = "  ".to_owned();
        state.username = "user".to_owned();
        assert!(!state.can_submit());
    }

    #[test]
    fn build_login_message_hashes_password() {
        let mut state = default_login_state();
        state.username = "operator".to_owned();
        state.password = "secret".to_owned();

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
        state.password = "pass".to_owned();

        let message = state.build_login_message();
        match message {
            OperatorMessage::Login(msg) => {
                assert_eq!(msg.info.user, "operator");
                assert_eq!(msg.head.user, "operator");
            }
            other => panic!("expected Login variant, got {other:?}"),
        }
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

    #[test]
    fn set_connecting_clears_error() {
        let mut state = default_login_state();
        state.set_error("previous error".to_owned());
        assert!(state.error_message.is_some());

        state.set_connecting();
        assert!(state.connecting);
        assert!(state.error_message.is_none());
    }
}
