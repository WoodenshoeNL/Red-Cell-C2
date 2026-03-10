mod local_config;
mod login;
mod transport;

use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use clap::Parser;
use eframe::egui::{self, Align, Layout, RichText};
use local_config::LocalConfig;
use login::{LoginAction, LoginState, render_login_dialog};
use transport::{AppState, ClientTransport, ConnectionStatus, SharedAppState};

const WINDOW_TITLE: &str = "Red Cell Client";
const DEFAULT_SERVER_URL: &str = "wss://127.0.0.1:40056/havoc/";
const INITIAL_WINDOW_SIZE: [f32; 2] = [1600.0, 900.0];
const MINIMUM_WINDOW_SIZE: [f32; 2] = [1280.0, 720.0];

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
#[command(name = "red-cell-client", about = "Red Cell operator client")]
struct Cli {
    /// Teamserver WebSocket URL.
    #[arg(long, default_value = DEFAULT_SERVER_URL)]
    server: String,
}

/// Application lifecycle phase.
enum AppPhase {
    /// Showing the login dialog, no active transport.
    Login(LoginState),
    /// Transport is active and login message has been sent.
    Authenticating {
        app_state: SharedAppState,
        transport: ClientTransport,
        login_state: LoginState,
    },
    /// Authenticated and showing the main operator UI.
    Connected {
        app_state: SharedAppState,
        #[allow(dead_code)]
        transport: ClientTransport,
    },
}

struct ClientApp {
    phase: AppPhase,
    local_config: LocalConfig,
    cli_server_url: String,
}

impl ClientApp {
    fn new(cli: Cli) -> Self {
        let local_config = LocalConfig::load();
        let login_state = LoginState::new(&cli.server, &local_config);

        Self { phase: AppPhase::Login(login_state), local_config, cli_server_url: cli.server }
    }

    fn snapshot(app_state: &SharedAppState) -> AppState {
        match app_state.lock() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn handle_login_submit(&mut self, ctx: &egui::Context) {
        let AppPhase::Login(login_state) = &mut self.phase else {
            return;
        };

        login_state.set_connecting();

        let server_url = login_state.server_url.trim().to_owned();
        let app_state = Arc::new(Mutex::new(AppState::new(server_url.clone())));

        match ClientTransport::spawn(server_url.clone(), app_state.clone(), ctx.clone()) {
            Ok(transport) => {
                let login_message = login_state.build_login_message();
                if let Err(error) = transport.queue_message(login_message) {
                    login_state.set_error(format!("Failed to send login: {error}"));
                    return;
                }

                self.local_config.server_url = Some(server_url);
                self.local_config.username = Some(login_state.username.trim().to_owned());
                self.local_config.save();

                let login_state_clone = login_state.clone();
                self.phase = AppPhase::Authenticating {
                    app_state,
                    transport,
                    login_state: login_state_clone,
                };
            }
            Err(error) => {
                login_state.set_error(format!("Connection failed: {error}"));
            }
        }
    }

    fn check_auth_response(&mut self) {
        let (snapshot, error_message) = match &self.phase {
            AppPhase::Authenticating { app_state, .. } => {
                let snap = Self::snapshot(app_state);
                let error = match &snap.connection_status {
                    ConnectionStatus::Error(msg) => Some(msg.clone()),
                    _ => None,
                };
                (snap, error)
            }
            _ => return,
        };

        if snapshot.operator_info.is_some() {
            let placeholder =
                AppPhase::Login(LoginState::new(&self.cli_server_url, &self.local_config));
            let old_phase = std::mem::replace(&mut self.phase, placeholder);
            if let AppPhase::Authenticating { app_state, transport, .. } = old_phase {
                self.phase = AppPhase::Connected { app_state, transport };
            }
            return;
        }

        if let Some(error_msg) = error_message {
            let placeholder =
                AppPhase::Login(LoginState::new(&self.cli_server_url, &self.local_config));
            let old_phase = std::mem::replace(&mut self.phase, placeholder);
            if let AppPhase::Authenticating { mut login_state, .. } = old_phase {
                login_state.set_error(error_msg);
                self.phase = AppPhase::Login(login_state);
            }
        }
    }

    fn render_connection_bar(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal_wrapped(|ui| {
            ui.heading(WINDOW_TITLE);
            ui.separator();
            ui.label("Teamserver");
            ui.monospace(&state.server_url);
            ui.separator();
            ui.colored_label(state.connection_status.color(), state.connection_status.label());

            if let Some(message) = state.connection_status.detail() {
                ui.separator();
                ui.colored_label(state.connection_status.color(), message);
            }
        });
    }

    fn render_operator_panel(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Operator");
        ui.separator();

        if let Some(operator) = &state.operator_info {
            ui.label(format!("Username: {}", operator.username));
            ui.label(format!("Online: {}", yes_no(operator.online)));
            ui.label(format!("Role: {}", operator.role.as_deref().unwrap_or("unassigned")));
            ui.label(format!(
                "Last seen: {}",
                operator.last_seen.as_deref().unwrap_or("not available")
            ));
        } else {
            ui.label("No operator session is active.");
        }
    }

    fn render_agents_panel(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Agents");
        ui.separator();

        if state.agents.is_empty() {
            ui.label("No agents are registered yet.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for agent in &state.agents {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.monospace(&agent.name_id);
                        ui.label(format!("[{}]", agent.status));
                        ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                    });
                    ui.label(format!("Host: {}", agent.hostname));
                    ui.label(format!("Process: {} ({})", agent.process_name, agent.process_pid));
                    ui.label(format!("Last check-in: {}", agent.last_call_in));
                });
            }
        });
    }

    fn render_listeners_panel(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Listeners");
        ui.separator();

        if state.listeners.is_empty() {
            ui.label("No listeners are configured yet.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for listener in &state.listeners {
                ui.group(|ui| {
                    ui.label(RichText::new(&listener.name).strong());
                    ui.label(format!("Protocol: {}", listener.protocol));
                    ui.label(format!("Status: {}", listener.status));
                });
            }
        });
    }

    fn render_loot_panel(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Loot");
        ui.separator();

        if state.loot.is_empty() {
            ui.label("No loot has been collected yet.");
            return;
        }

        egui::Grid::new("loot-grid").striped(true).show(ui, |ui| {
            ui.strong("Item");
            ui.strong("Source");
            ui.strong("Collected");
            ui.end_row();

            for item in &state.loot {
                ui.label(&item.name);
                ui.label(&item.source);
                ui.label(&item.collected_at);
                ui.end_row();
            }
        });
    }

    fn render_chat_panel(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Team Chat");
        ui.separator();

        if state.chat_messages.is_empty() {
            ui.label("No chat messages yet.");
            return;
        }

        egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for message in &state.chat_messages {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.strong(&message.author);
                        ui.label(RichText::new(&message.sent_at).weak());
                    });
                    ui.label(&message.message);
                });
            }
        });
    }

    fn render_overview_panel(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Overview");
        ui.separator();
        ui.label("Connected to teamserver. Live WebSocket transport is active.");
        ui.add_space(8.0);

        egui::Grid::new("overview-stats").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
            ui.label("Connection");
            ui.colored_label(state.connection_status.color(), state.connection_status.label());
            ui.end_row();

            ui.label("Operator");
            ui.label(
                state.operator_info.as_ref().map_or("Not authenticated", |op| op.username.as_str()),
            );
            ui.end_row();

            ui.label("Agents");
            ui.label(state.agents.len().to_string());
            ui.end_row();

            ui.label("Listeners");
            ui.label(state.listeners.len().to_string());
            ui.end_row();

            ui.label("Loot items");
            ui.label(state.loot.len().to_string());
            ui.end_row();

            ui.label("Chat messages");
            ui.label(state.chat_messages.len().to_string());
            ui.end_row();
        });

        ui.add_space(12.0);
        ui.label(RichText::new("Connection states").strong());
        ui.horizontal_wrapped(|ui| {
            for status in ConnectionStatus::placeholders() {
                ui.colored_label(status.color(), status.label());
            }
        });
    }

    fn render_current_phase(
        &mut self,
        ctx: &egui::Context,
        fallback_app_state: Option<SharedAppState>,
    ) {
        match &mut self.phase {
            AppPhase::Login(login_state) => {
                let action = render_login_dialog(ctx, login_state);
                if action == LoginAction::Submit {
                    self.handle_login_submit(ctx);
                }
            }
            AppPhase::Authenticating { .. } => {
                if let Some(app_state_ref) = fallback_app_state {
                    let snapshot = Self::snapshot(&app_state_ref);
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.with_layout(Layout::top_down(Align::Center), |ui| {
                            ui.add_space(ui.available_height() * 0.35);
                            ui.heading("Authenticating...");
                            ui.add_space(8.0);
                            ui.colored_label(
                                snapshot.connection_status.color(),
                                snapshot.connection_status.label(),
                            );
                        });
                    });
                }
            }
            AppPhase::Connected { app_state, .. } => {
                let app_state_ref = app_state.clone();
                self.render_main_ui(ctx, &app_state_ref);
            }
        }
    }

    fn render_main_ui(&self, ctx: &egui::Context, app_state: &SharedAppState) {
        let snapshot = Self::snapshot(app_state);

        egui::TopBottomPanel::top("connection_bar").show(ctx, |ui| {
            self.render_connection_bar(ui, &snapshot);
        });

        egui::SidePanel::left("navigation_left").resizable(true).default_width(320.0).show(
            ctx,
            |ui| {
                self.render_operator_panel(ui, &snapshot);
                ui.add_space(12.0);
                self.render_agents_panel(ui, &snapshot);
            },
        );

        egui::SidePanel::right("navigation_right").resizable(true).default_width(320.0).show(
            ctx,
            |ui| {
                self.render_listeners_panel(ui, &snapshot);
                ui.add_space(12.0);
                self.render_loot_panel(ui, &snapshot);
            },
        );

        egui::TopBottomPanel::bottom("chat_panel").resizable(true).default_height(220.0).show(
            ctx,
            |ui| {
                self.render_chat_panel(ui, &snapshot);
            },
        );

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                self.render_overview_panel(ui, &snapshot);
            });
        });
    }
}

impl eframe::App for ClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match &self.phase {
            AppPhase::Login(_) => {
                let AppPhase::Login(login_state) = &mut self.phase else {
                    return;
                };
                let action = render_login_dialog(ctx, login_state);
                if action == LoginAction::Submit {
                    self.handle_login_submit(ctx);
                }
            }
            AppPhase::Authenticating { app_state, .. } => {
                let app_state_ref = app_state.clone();
                self.check_auth_response();
                self.render_current_phase(ctx, Some(app_state_ref));
            }
            AppPhase::Connected { app_state, .. } => {
                let app_state_ref = app_state.clone();
                self.render_main_ui(ctx, &app_state_ref);
            }
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    launch_client(cli)
}

fn launch_client(cli: Cli) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(INITIAL_WINDOW_SIZE)
            .with_min_inner_size(MINIMUM_WINDOW_SIZE),
        ..Default::default()
    };

    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(move |creation_context| {
            creation_context.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(ClientApp::new(cli)) as Box<dyn eframe::App>)
        }),
    )
    .map_err(|error| anyhow!("failed to start egui application: {error}"))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_uses_default_server_url() {
        let cli = Cli::parse_from(["red-cell-client"]);
        assert_eq!(cli.server, DEFAULT_SERVER_URL);
    }

    #[test]
    fn cli_accepts_custom_server_url() {
        let cli = Cli::parse_from([
            "red-cell-client",
            "--server",
            "wss://teamserver.example.test/havoc/",
        ]);
        assert_eq!(cli.server, "wss://teamserver.example.test/havoc/");
    }

    #[test]
    fn client_app_state_initializes_placeholder_state() {
        let app_state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

        assert_eq!(app_state.server_url, "wss://127.0.0.1:40056/havoc/");
        assert_eq!(app_state.connection_status, ConnectionStatus::Disconnected);
        assert!(app_state.operator_info.is_none());
        assert!(app_state.agents.is_empty());
        assert!(app_state.agent_consoles.is_empty());
        assert!(app_state.listeners.is_empty());
        assert!(app_state.loot.is_empty());
        assert!(app_state.chat_messages.is_empty());
    }

    #[test]
    fn client_app_starts_in_login_phase() {
        let cli = Cli { server: DEFAULT_SERVER_URL.to_owned() };
        let app = ClientApp::new(cli);
        assert!(matches!(app.phase, AppPhase::Login(_)));
    }

    #[test]
    fn client_app_login_state_uses_cli_default() {
        let cli = Cli { server: "wss://custom:1234/havoc/".to_owned() };
        let app = ClientApp::new(cli);
        match &app.phase {
            AppPhase::Login(state) => {
                if app.local_config.server_url.is_none() {
                    assert_eq!(state.server_url, "wss://custom:1234/havoc/");
                }
            }
            _ => panic!("expected Login phase"),
        }
    }
}
