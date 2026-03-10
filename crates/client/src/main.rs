mod transport;

use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use clap::Parser;
use eframe::egui::{self, Align, Layout, RichText};
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

#[derive(Debug)]
struct ClientApp {
    app_state: SharedAppState,
    transport: ClientTransport,
}

impl ClientApp {
    fn new(server_url: String, repaint: egui::Context) -> Result<Self, transport::TransportError> {
        let app_state = Arc::new(Mutex::new(AppState::new(server_url.clone())));
        let transport = ClientTransport::spawn(server_url, app_state.clone(), repaint)?;

        Ok(Self { app_state, transport })
    }

    fn snapshot(&self) -> AppState {
        match self.app_state.lock() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
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
        ui.label(
            "This client skeleton now maintains a live WebSocket transport and shared connection state.",
        );
        ui.add_space(8.0);

        egui::Grid::new("overview-stats").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
            ui.label("Connection");
            ui.colored_label(state.connection_status.color(), state.connection_status.label());
            ui.end_row();

            ui.label("Operator");
            ui.label(
                state
                    .operator_info
                    .as_ref()
                    .map_or("Not authenticated", |operator| operator.username.as_str()),
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
}

impl eframe::App for ClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let _ = &self.transport;
        let snapshot = self.snapshot();

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

            ClientApp::new(cli.server.clone(), creation_context.egui_ctx.clone())
                .map(|app| Box::new(app) as Box<dyn eframe::App>)
                .map_err(|error| {
                    Box::new(std::io::Error::other(format!(
                        "failed to initialize client transport: {error}"
                    ))) as Box<dyn std::error::Error + Send + Sync>
                })
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
        assert!(app_state.listeners.is_empty());
        assert!(app_state.loot.is_empty());
        assert!(app_state.chat_messages.is_empty());
    }
}
