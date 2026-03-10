use anyhow::{Result, anyhow};
use clap::Parser;
use eframe::egui::{self, Align, Color32, Layout, RichText};
use red_cell_common::{AgentInfo, ListenerConfig, OperatorInfo};

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl ConnectionStatus {
    fn placeholders() -> [Self; 4] {
        [
            Self::Disconnected,
            Self::Connecting,
            Self::Connected,
            Self::Error("Awaiting transport initialization".to_owned()),
        ]
    }

    fn label(&self) -> &str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Error(_) => "Connection Error",
        }
    }

    fn color(&self) -> Color32 {
        match self {
            Self::Disconnected => Color32::from_rgb(130, 138, 145),
            Self::Connecting => Color32::from_rgb(232, 182, 83),
            Self::Connected => Color32::from_rgb(110, 199, 141),
            Self::Error(_) => Color32::from_rgb(215, 83, 83),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LootItem {
    name: String,
    source: String,
    collected_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChatMessage {
    author: String,
    sent_at: String,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientApp {
    server_url: String,
    connection_status: ConnectionStatus,
    operator_info: Option<OperatorInfo>,
    agents: Vec<AgentInfo>,
    listeners: Vec<ListenerConfig>,
    loot: Vec<LootItem>,
    chat_messages: Vec<ChatMessage>,
}

impl ClientApp {
    fn new(server_url: String) -> Self {
        Self {
            server_url,
            connection_status: ConnectionStatus::Disconnected,
            operator_info: None,
            agents: Vec::new(),
            listeners: Vec::new(),
            loot: Vec::new(),
            chat_messages: Vec::new(),
        }
    }

    fn render_connection_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading(WINDOW_TITLE);
            ui.separator();
            ui.label("Teamserver");
            ui.monospace(&self.server_url);
            ui.separator();
            ui.colored_label(self.connection_status.color(), self.connection_status.label());

            if let ConnectionStatus::Error(message) = &self.connection_status {
                ui.separator();
                ui.colored_label(self.connection_status.color(), message);
            }
        });
    }

    fn render_operator_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Operator");
        ui.separator();

        if let Some(operator) = &self.operator_info {
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

    fn render_agents_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Agents");
        ui.separator();

        if self.agents.is_empty() {
            ui.label("No agents are registered yet.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for agent in &self.agents {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.monospace(agent.name_id());
                        ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                    });
                    ui.label(format!("Host: {}", agent.hostname));
                    ui.label(format!("Process: {} ({})", agent.process_name, agent.process_pid));
                    ui.label(format!("Last check-in: {}", agent.last_call_in));
                });
            }
        });
    }

    fn render_listeners_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Listeners");
        ui.separator();

        if self.listeners.is_empty() {
            ui.label("No listeners are configured yet.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for listener in &self.listeners {
                ui.group(|ui| {
                    ui.label(RichText::new(listener.name()).strong());
                    ui.label(format!("Protocol: {}", listener.protocol()));
                });
            }
        });
    }

    fn render_loot_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Loot");
        ui.separator();

        if self.loot.is_empty() {
            ui.label("No loot has been collected yet.");
            return;
        }

        egui::Grid::new("loot-grid").striped(true).show(ui, |ui| {
            ui.strong("Item");
            ui.strong("Source");
            ui.strong("Collected");
            ui.end_row();

            for item in &self.loot {
                ui.label(&item.name);
                ui.label(&item.source);
                ui.label(&item.collected_at);
                ui.end_row();
            }
        });
    }

    fn render_chat_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Team Chat");
        ui.separator();

        if self.chat_messages.is_empty() {
            ui.label("No chat messages yet.");
            return;
        }

        egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            for message in &self.chat_messages {
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

    fn render_overview_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Overview");
        ui.separator();
        ui.label(
            "This client skeleton provides placeholder panels for upcoming operator workflows.",
        );
        ui.add_space(8.0);

        egui::Grid::new("overview-stats").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
            ui.label("Connection");
            ui.colored_label(self.connection_status.color(), self.connection_status.label());
            ui.end_row();

            ui.label("Operator");
            ui.label(
                self.operator_info
                    .as_ref()
                    .map_or("Not authenticated", |operator| operator.username.as_str()),
            );
            ui.end_row();

            ui.label("Agents");
            ui.label(self.agents.len().to_string());
            ui.end_row();

            ui.label("Listeners");
            ui.label(self.listeners.len().to_string());
            ui.end_row();

            ui.label("Loot items");
            ui.label(self.loot.len().to_string());
            ui.end_row();

            ui.label("Chat messages");
            ui.label(self.chat_messages.len().to_string());
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
        egui::TopBottomPanel::top("connection_bar").show(ctx, |ui| {
            self.render_connection_bar(ui);
        });

        egui::SidePanel::left("navigation_left").resizable(true).default_width(320.0).show(
            ctx,
            |ui| {
                self.render_operator_panel(ui);
                ui.add_space(12.0);
                self.render_agents_panel(ui);
            },
        );

        egui::SidePanel::right("navigation_right").resizable(true).default_width(320.0).show(
            ctx,
            |ui| {
                self.render_listeners_panel(ui);
                ui.add_space(12.0);
                self.render_loot_panel(ui);
            },
        );

        egui::TopBottomPanel::bottom("chat_panel").resizable(true).default_height(220.0).show(
            ctx,
            |ui| {
                self.render_chat_panel(ui);
            },
        );

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                self.render_overview_panel(ui);
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
        Box::new(|creation_context| {
            creation_context.egui_ctx.set_visuals(egui::Visuals::dark());

            Ok(Box::new(ClientApp::new(cli.server.clone())))
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
    fn client_app_initializes_placeholder_state() {
        let app = ClientApp::new("wss://127.0.0.1:40056/havoc/".to_owned());

        assert_eq!(app.server_url, "wss://127.0.0.1:40056/havoc/");
        assert_eq!(app.connection_status, ConnectionStatus::Disconnected);
        assert!(app.operator_info.is_none());
        assert!(app.agents.is_empty());
        assert!(app.listeners.is_empty());
        assert!(app.loot.is_empty());
        assert!(app.chat_messages.is_empty());
    }
}
