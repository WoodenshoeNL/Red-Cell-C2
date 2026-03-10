mod local_config;
mod login;
mod transport;

use base64::Engine;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use clap::Parser;
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Stroke};
use local_config::LocalConfig;
use login::{LoginAction, LoginState, render_login_dialog};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentTaskInfo, EventCode, FlatInfo, Message, MessageHead, OperatorMessage,
};
use transport::{AppState, ClientTransport, ConnectionStatus, LootItem, LootKind, SharedAppState};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentSortColumn {
    Id,
    Hostname,
    Username,
    Domain,
    Ip,
    Pid,
    Process,
    Arch,
    Elevated,
    Os,
    SleepJitter,
    LastCheckin,
}

impl AgentSortColumn {
    const ALL: [(Self, &'static str); 12] = [
        (Self::Id, "ID"),
        (Self::Hostname, "Hostname"),
        (Self::Username, "Username"),
        (Self::Domain, "Domain"),
        (Self::Ip, "IP"),
        (Self::Pid, "PID"),
        (Self::Process, "Process"),
        (Self::Arch, "Arch"),
        (Self::Elevated, "Elevated"),
        (Self::Os, "OS"),
        (Self::SleepJitter, "Sleep/Jitter"),
        (Self::LastCheckin, "Last Checkin"),
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NoteEditorState {
    agent_id: String,
    note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum LootTypeFilter {
    #[default]
    All,
    Credentials,
    Files,
    Screenshots,
}

impl LootTypeFilter {
    const ALL: [(Self, &'static str); 4] = [
        (Self::All, "All"),
        (Self::Credentials, "Credentials"),
        (Self::Files, "Files"),
        (Self::Screenshots, "Screenshots"),
    ];
}

#[derive(Debug, Default)]
struct SessionPanelState {
    filter: String,
    sort_column: Option<AgentSortColumn>,
    descending: bool,
    open_consoles: Vec<String>,
    note_editor: Option<NoteEditorState>,
    pending_messages: Vec<OperatorMessage>,
    status_message: Option<String>,
    loot_type_filter: LootTypeFilter,
    loot_agent_filter: String,
    loot_time_filter: String,
    loot_text_filter: String,
    loot_status_message: Option<String>,
    chat_input: String,
}

impl SessionPanelState {
    fn toggle_sort(&mut self, column: AgentSortColumn) {
        if self.sort_column == Some(column) {
            self.descending = !self.descending;
        } else {
            self.sort_column = Some(column);
            self.descending = false;
        }
    }

    fn ensure_console_open(&mut self, agent_id: &str) {
        if !self.open_consoles.iter().any(|open_id| open_id == agent_id) {
            self.open_consoles.push(agent_id.to_owned());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionAction {
    OpenConsole(String),
    RequestKill(String),
    EditNote { agent_id: String, current_note: String },
}

struct ClientApp {
    phase: AppPhase,
    local_config: LocalConfig,
    cli_server_url: String,
    session_panel: SessionPanelState,
    outgoing_tx: Option<tokio::sync::mpsc::UnboundedSender<OperatorMessage>>,
}

impl ClientApp {
    fn new(cli: Cli) -> Self {
        let local_config = LocalConfig::load();
        let login_state = LoginState::new(&cli.server, &local_config);

        Self {
            phase: AppPhase::Login(login_state),
            local_config,
            cli_server_url: cli.server,
            session_panel: SessionPanelState {
                sort_column: Some(AgentSortColumn::LastCheckin),
                descending: true,
                ..SessionPanelState::default()
            },
            outgoing_tx: None,
        }
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
                self.outgoing_tx = Some(transport.outgoing_sender());

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
                self.outgoing_tx = None;
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

    fn render_agents_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Sessions");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Filter");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.filter)
                    .hint_text("Search ID, host, user, process, note"),
            );
            if response.changed() {
                ui.ctx().request_repaint();
            }
        });
        ui.add_space(6.0);

        if state.agents.is_empty() {
            ui.label("No agents are registered yet.");
            return;
        }

        let agents = self.filtered_and_sorted_agents(&state.agents);
        if agents.is_empty() {
            ui.label("No agents match the current filter.");
            return;
        }

        if let Some(message) = &self.session_panel.status_message {
            ui.label(RichText::new(message).weak());
            ui.add_space(6.0);
        }

        self.render_session_table_header(ui);
        egui::ScrollArea::vertical().show(ui, |ui| {
            for agent in &agents {
                let fill = if agent.elevated {
                    Color32::from_rgba_unmultiplied(120, 28, 28, 110)
                } else {
                    Color32::from_rgba_unmultiplied(255, 255, 255, 8)
                };
                let frame = egui::Frame::default()
                    .fill(fill)
                    .stroke(Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 18)))
                    .inner_margin(egui::Margin::symmetric(8, 6));
                let inner = frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        self.render_session_row_cell(ui, 86.0, &agent.name_id, true);
                        self.render_session_row_cell(ui, 116.0, &agent.hostname, false);
                        self.render_session_row_cell(ui, 108.0, &agent.username, false);
                        self.render_session_row_cell(ui, 86.0, &agent.domain_name, false);
                        self.render_session_row_cell(ui, 108.0, &agent_ip(agent), false);
                        self.render_session_row_cell(ui, 72.0, &agent.process_pid, false);
                        self.render_session_row_cell(ui, 132.0, &agent.process_name, false);
                        self.render_session_row_cell(ui, 72.0, &agent_arch(agent), false);
                        self.render_session_row_cell(
                            ui,
                            82.0,
                            if agent.elevated { "Yes" } else { "No" },
                            false,
                        );
                        self.render_session_row_cell(ui, 170.0, &agent_os(agent), false);
                        self.render_session_row_cell(ui, 110.0, &agent_sleep_jitter(agent), false);
                        self.render_session_row_cell(ui, 136.0, &agent.last_call_in, false);
                    });
                });

                let row_response = ui.interact(
                    inner.response.rect,
                    ui.make_persistent_id(("agent-row", &agent.name_id)),
                    Sense::click(),
                );

                if row_response.double_clicked() {
                    self.session_panel.ensure_console_open(&agent.name_id);
                }

                row_response.context_menu(|ui| {
                    if ui.button("Interact").clicked() {
                        self.handle_session_action(
                            SessionAction::OpenConsole(agent.name_id.clone()),
                            state.operator_info.as_ref().map(|operator| operator.username.as_str()),
                        );
                        ui.close();
                    }
                    if ui.button("Kill").clicked() {
                        self.handle_session_action(
                            SessionAction::RequestKill(agent.name_id.clone()),
                            state.operator_info.as_ref().map(|operator| operator.username.as_str()),
                        );
                        ui.close();
                    }
                    if ui.button("Add note").clicked() {
                        self.handle_session_action(
                            SessionAction::EditNote {
                                agent_id: agent.name_id.clone(),
                                current_note: agent.note.clone(),
                            },
                            state.operator_info.as_ref().map(|operator| operator.username.as_str()),
                        );
                        ui.close();
                    }
                });

                ui.add_space(4.0);
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

    fn render_loot_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Loot");
        ui.separator();

        ui.horizontal_wrapped(|ui| {
            ui.label("Type");
            egui::ComboBox::from_id_salt("loot-type-filter")
                .selected_text(match self.session_panel.loot_type_filter {
                    LootTypeFilter::All => "All",
                    LootTypeFilter::Credentials => "Credentials",
                    LootTypeFilter::Files => "Files",
                    LootTypeFilter::Screenshots => "Screenshots",
                })
                .show_ui(ui, |ui| {
                    for (value, label) in LootTypeFilter::ALL {
                        ui.selectable_value(&mut self.session_panel.loot_type_filter, value, label);
                    }
                });
            ui.label("Agent");
            ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.loot_agent_filter)
                    .desired_width(84.0)
                    .hint_text("ABCD1234"),
            );
            ui.label("Time");
            ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.loot_time_filter)
                    .desired_width(100.0)
                    .hint_text("2026-03-10"),
            );
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.session_panel.loot_text_filter)
                .hint_text("Search name, path, source, preview"),
        );
        if let Some(message) = &self.session_panel.loot_status_message {
            ui.add_space(6.0);
            ui.label(RichText::new(message).weak());
        }
        ui.add_space(6.0);

        let filtered_loot: Vec<_> = state
            .loot
            .iter()
            .filter(|item| {
                loot_matches_filters(
                    item,
                    self.session_panel.loot_type_filter,
                    &self.session_panel.loot_agent_filter,
                    &self.session_panel.loot_time_filter,
                    &self.session_panel.loot_text_filter,
                )
            })
            .collect();

        if filtered_loot.is_empty() {
            ui.label(if state.loot.is_empty() {
                "No loot has been collected yet."
            } else {
                "No loot matches the current filters."
            });
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for item in filtered_loot {
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(item.kind.label()).strong());
                        ui.separator();
                        ui.label(RichText::new(&item.name).strong());
                        if !item.agent_id.is_empty() {
                            ui.separator();
                            ui.monospace(&item.agent_id);
                        }
                    });
                    ui.label(format!("Source: {}", item.source));
                    ui.label(format!(
                        "Collected: {}",
                        blank_if_empty(&item.collected_at, "unknown")
                    ));
                    if let Some(path) = &item.file_path {
                        ui.label(format!("Path: {path}"));
                    }
                    if let Some(size) = item.size_bytes {
                        ui.label(format!("Size: {}", human_size(size)));
                    }
                    if let Some(preview) = &item.preview {
                        ui.add_space(4.0);
                        ui.label(RichText::new(preview).monospace());
                    }
                    if loot_is_downloadable(item) {
                        ui.add_space(6.0);
                        if ui.button("Download").clicked() {
                            self.session_panel.loot_status_message =
                                Some(download_loot_item(item).unwrap_or_else(|error| error));
                        }
                    }
                });
                ui.add_space(6.0);
            }
        });
    }

    fn render_chat_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Team Chat");
        ui.separator();

        let online_users = if state.online_operators.is_empty() {
            "No presence data".to_owned()
        } else {
            state.online_operators.iter().cloned().collect::<Vec<_>>().join(", ")
        };
        ui.label(format!("Online: {online_users}"));
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            let input = ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.chat_input)
                    .desired_width(f32::INFINITY)
                    .hint_text("Send a message to all operators"),
            );
            let send_requested =
                input.lost_focus() && ui.input(|state| state.key_pressed(egui::Key::Enter));
            if ui.button("Send").clicked() || send_requested {
                if let Some(message) = build_chat_message(
                    state.operator_info.as_ref().map(|operator| operator.username.as_str()),
                    &self.session_panel.chat_input,
                ) {
                    self.session_panel.pending_messages.push(message);
                    self.session_panel.chat_input.clear();
                }
            }
        });
        ui.add_space(8.0);

        if state.chat_messages.is_empty() {
            ui.label("No chat messages yet.");
        } else {
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

    fn render_main_ui(&mut self, ctx: &egui::Context, app_state: &SharedAppState) {
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

        self.render_agent_consoles(ctx, &snapshot);
        self.render_note_editor(ctx, app_state);
        self.flush_pending_messages();
    }

    fn render_session_table_header(&mut self, ui: &mut egui::Ui) {
        let widths = [
            (AgentSortColumn::Id, 86.0),
            (AgentSortColumn::Hostname, 116.0),
            (AgentSortColumn::Username, 108.0),
            (AgentSortColumn::Domain, 86.0),
            (AgentSortColumn::Ip, 108.0),
            (AgentSortColumn::Pid, 72.0),
            (AgentSortColumn::Process, 132.0),
            (AgentSortColumn::Arch, 72.0),
            (AgentSortColumn::Elevated, 82.0),
            (AgentSortColumn::Os, 170.0),
            (AgentSortColumn::SleepJitter, 110.0),
            (AgentSortColumn::LastCheckin, 136.0),
        ];
        ui.horizontal(|ui| {
            for (column, width) in widths {
                let label = sort_button_label(
                    self.session_panel.sort_column,
                    self.session_panel.descending,
                    column,
                );
                let button =
                    egui::Button::new(label).frame(false).wrap_mode(egui::TextWrapMode::Truncate);
                if ui.add_sized([width, 24.0], button).clicked() {
                    self.session_panel.toggle_sort(column);
                }
            }
        });
        ui.separator();
    }

    fn render_session_row_cell(&self, ui: &mut egui::Ui, width: f32, value: &str, monospace: bool) {
        let text = ellipsize(value, 24);
        if monospace {
            ui.add_sized([width, 20.0], egui::Label::new(RichText::new(text).monospace()));
        } else {
            ui.add_sized([width, 20.0], egui::Label::new(text));
        }
    }

    fn filtered_and_sorted_agents(
        &self,
        agents: &[transport::AgentSummary],
    ) -> Vec<transport::AgentSummary> {
        let mut filtered: Vec<_> = agents
            .iter()
            .filter(|agent| agent_matches_filter(agent, &self.session_panel.filter))
            .cloned()
            .collect();
        sort_agents(
            &mut filtered,
            self.session_panel.sort_column.unwrap_or(AgentSortColumn::LastCheckin),
            self.session_panel.descending,
        );
        filtered
    }

    fn handle_session_action(&mut self, action: SessionAction, operator: Option<&str>) {
        match action {
            SessionAction::OpenConsole(agent_id) => {
                self.session_panel.ensure_console_open(&agent_id);
            }
            SessionAction::RequestKill(agent_id) => {
                self.session_panel
                    .pending_messages
                    .push(build_kill_task(&agent_id, operator.unwrap_or("")));
                self.session_panel.status_message =
                    Some(format!("Queued kill task for {agent_id}."));
            }
            SessionAction::EditNote { agent_id, current_note } => {
                self.session_panel.note_editor =
                    Some(NoteEditorState { agent_id, note: current_note });
            }
        }
    }

    fn render_agent_consoles(&mut self, ctx: &egui::Context, state: &AppState) {
        let mut still_open = Vec::new();
        for agent_id in self.session_panel.open_consoles.clone() {
            let mut open = true;
            egui::Window::new(format!("Console {agent_id}"))
                .id(egui::Id::new(("agent-console", &agent_id)))
                .open(&mut open)
                .resizable(true)
                .default_size([720.0, 420.0])
                .show(ctx, |ui| {
                    if let Some(agent) = state.agents.iter().find(|agent| agent.name_id == agent_id)
                    {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(&agent.hostname).strong());
                            ui.separator();
                            ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                            ui.separator();
                            ui.label(format!(
                                "Process: {} ({})",
                                agent.process_name, agent.process_pid
                            ));
                            ui.separator();
                            ui.label(format!("Status: {}", agent.status));
                        });
                        if !agent.note.trim().is_empty() {
                            ui.add_space(6.0);
                            ui.label(RichText::new(format!("Note: {}", agent.note)).weak());
                        }
                    }

                    ui.separator();

                    match state.agent_consoles.get(&agent_id) {
                        Some(entries) if !entries.is_empty() => {
                            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                                for entry in entries {
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.monospace(&entry.command_id);
                                            ui.label(RichText::new(&entry.received_at).weak());
                                        });
                                        ui.monospace(&entry.output);
                                    });
                                }
                            });
                        }
                        _ => {
                            ui.label("No console output for this session yet.");
                        }
                    }
                });

            if open {
                still_open.push(agent_id);
            }
        }
        self.session_panel.open_consoles = still_open;
    }

    fn render_note_editor(&mut self, ctx: &egui::Context, app_state: &SharedAppState) {
        let Some(editor) = &mut self.session_panel.note_editor else {
            return;
        };

        let mut keep_open = true;
        let mut save_note = false;
        let mut cancel_note = false;
        let title = format!("Agent Note {}", editor.agent_id);
        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_size([420.0, 220.0])
            .open(&mut keep_open)
            .show(ctx, |ui| {
                ui.label("Operator note");
                ui.add(
                    egui::TextEdit::multiline(&mut editor.note)
                        .desired_rows(8)
                        .hint_text("Add operator context for this agent"),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save_note = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel_note = true;
                    }
                });
            });

        if save_note {
            let agent_id = editor.agent_id.clone();
            let note = editor.note.trim().to_owned();
            match app_state.lock() {
                Ok(mut state) => state.update_agent_note(&agent_id, note.clone()),
                Err(poisoned) => poisoned.into_inner().update_agent_note(&agent_id, note.clone()),
            }
            self.session_panel.pending_messages.push(build_note_task(&agent_id, &note, ""));
            self.session_panel.status_message = Some(format!("Updated note for {agent_id}."));
            self.session_panel.note_editor = None;
            ctx.request_repaint();
        } else if cancel_note || !keep_open {
            self.session_panel.note_editor = None;
        }
    }

    fn flush_pending_messages(&mut self) {
        if self.session_panel.pending_messages.is_empty() {
            return;
        }

        let Some(outgoing_tx) = &self.outgoing_tx else {
            self.session_panel.status_message = Some(
                "Session action could not be sent because the transport is unavailable.".to_owned(),
            );
            self.session_panel.pending_messages.clear();
            return;
        };

        for message in self.session_panel.pending_messages.drain(..) {
            if outgoing_tx.send(message).is_err() {
                self.session_panel.status_message =
                    Some("Session action could not be queued for delivery.".to_owned());
                break;
            }
        }
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

fn build_kill_task(agent_id: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command_line: "kill".to_owned(),
            command: Some("kill".to_owned()),
            ..AgentTaskInfo::default()
        },
    )
}

fn build_note_task(agent_id: &str, note: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: "Teamserver".to_owned(),
            command_line: "note".to_owned(),
            command: Some("note".to_owned()),
            arguments: Some(note.to_owned()),
            ..AgentTaskInfo::default()
        },
    )
}

fn build_chat_message(operator: Option<&str>, message: &str) -> Option<OperatorMessage> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(OperatorMessage::ChatMessage(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: operator.unwrap_or_default().to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo {
            fields: std::collections::BTreeMap::from([
                (
                    "User".to_owned(),
                    serde_json::Value::String(operator.unwrap_or_default().to_owned()),
                ),
                ("Message".to_owned(), serde_json::Value::String(trimmed.to_owned())),
            ]),
        },
    }))
}

fn build_agent_task(operator: &str, info: AgentTaskInfo) -> OperatorMessage {
    OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: red_cell_common::operator::EventCode::Session,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

fn next_task_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};

    static TASK_COUNTER: AtomicU32 = AtomicU32::new(1);
    TASK_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn agent_ip(agent: &transport::AgentSummary) -> String {
    if agent.internal_ip.trim().is_empty() {
        agent.external_ip.clone()
    } else {
        agent.internal_ip.clone()
    }
}

fn agent_arch(agent: &transport::AgentSummary) -> String {
    if agent.process_arch.trim().is_empty() {
        agent.os_arch.clone()
    } else {
        agent.process_arch.clone()
    }
}

fn agent_os(agent: &transport::AgentSummary) -> String {
    if agent.os_build.trim().is_empty() {
        agent.os_version.clone()
    } else {
        format!("{} ({})", agent.os_version, agent.os_build)
    }
}

fn agent_sleep_jitter(agent: &transport::AgentSummary) -> String {
    match (agent.sleep_delay.trim(), agent.sleep_jitter.trim()) {
        ("", "") => String::new(),
        (delay, "") => delay.to_owned(),
        ("", jitter) => format!("j{jitter}%"),
        (delay, jitter) => format!("{delay}s / {jitter}%"),
    }
}

fn agent_matches_filter(agent: &transport::AgentSummary, filter: &str) -> bool {
    let filter = filter.trim();
    if filter.is_empty() {
        return true;
    }

    let needle = filter.to_ascii_lowercase();
    [
        agent.name_id.as_str(),
        agent.hostname.as_str(),
        agent.username.as_str(),
        agent.domain_name.as_str(),
        agent.internal_ip.as_str(),
        agent.external_ip.as_str(),
        agent.process_pid.as_str(),
        agent.process_name.as_str(),
        agent.process_arch.as_str(),
        agent.os_version.as_str(),
        agent.os_build.as_str(),
        agent.note.as_str(),
    ]
    .into_iter()
    .any(|field| field.to_ascii_lowercase().contains(&needle))
}

fn sort_agents(agents: &mut [transport::AgentSummary], column: AgentSortColumn, descending: bool) {
    agents.sort_by(|left, right| {
        let ordering = match column {
            AgentSortColumn::Id => left.name_id.cmp(&right.name_id),
            AgentSortColumn::Hostname => left.hostname.cmp(&right.hostname),
            AgentSortColumn::Username => left.username.cmp(&right.username),
            AgentSortColumn::Domain => left.domain_name.cmp(&right.domain_name),
            AgentSortColumn::Ip => agent_ip(left).cmp(&agent_ip(right)),
            AgentSortColumn::Pid => left.process_pid.cmp(&right.process_pid),
            AgentSortColumn::Process => left.process_name.cmp(&right.process_name),
            AgentSortColumn::Arch => agent_arch(left).cmp(&agent_arch(right)),
            AgentSortColumn::Elevated => left.elevated.cmp(&right.elevated),
            AgentSortColumn::Os => agent_os(left).cmp(&agent_os(right)),
            AgentSortColumn::SleepJitter => {
                agent_sleep_jitter(left).cmp(&agent_sleep_jitter(right))
            }
            AgentSortColumn::LastCheckin => left.last_call_in.cmp(&right.last_call_in),
        };
        let normalized = if ordering == std::cmp::Ordering::Equal {
            left.name_id.cmp(&right.name_id)
        } else {
            ordering
        };
        if descending { normalized.reverse() } else { normalized }
    });
}

fn sort_button_label(
    current_column: Option<AgentSortColumn>,
    descending: bool,
    button_column: AgentSortColumn,
) -> String {
    let name = AgentSortColumn::ALL
        .iter()
        .find_map(|(column, label)| (*column == button_column).then_some(*label))
        .unwrap_or("Column");
    if current_column == Some(button_column) {
        let arrow = if descending { "v" } else { "^" };
        format!("{name} {arrow}")
    } else {
        name.to_owned()
    }
}

fn ellipsize(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }

    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index + 1 >= max_chars {
            break;
        }
        output.push(ch);
    }
    output.push_str("...");
    output
}

fn loot_matches_filters(
    item: &LootItem,
    type_filter: LootTypeFilter,
    agent_filter: &str,
    time_filter: &str,
    text_filter: &str,
) -> bool {
    if !matches_loot_type_filter(item, type_filter) {
        return false;
    }

    contains_ascii_case_insensitive(&item.agent_id, agent_filter)
        && contains_ascii_case_insensitive(&item.collected_at, time_filter)
        && [
            item.name.as_str(),
            item.source.as_str(),
            item.agent_id.as_str(),
            item.file_path.as_deref().unwrap_or_default(),
            item.preview.as_deref().unwrap_or_default(),
        ]
        .into_iter()
        .any(|field| contains_ascii_case_insensitive(field, text_filter))
}

fn matches_loot_type_filter(item: &LootItem, type_filter: LootTypeFilter) -> bool {
    match type_filter {
        LootTypeFilter::All => true,
        LootTypeFilter::Credentials => matches!(item.kind, LootKind::Credential),
        LootTypeFilter::Files => matches!(item.kind, LootKind::File),
        LootTypeFilter::Screenshots => matches!(item.kind, LootKind::Screenshot),
    }
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let trimmed = needle.trim();
    trimmed.is_empty() || haystack.to_ascii_lowercase().contains(&trimmed.to_ascii_lowercase())
}

fn loot_is_downloadable(item: &LootItem) -> bool {
    matches!(item.kind, LootKind::File | LootKind::Screenshot) && item.content_base64.is_some()
}

fn download_loot_item(item: &LootItem) -> std::result::Result<String, String> {
    let Some(encoded) = &item.content_base64 else {
        return Err("This loot item does not include downloadable content.".to_owned());
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("Failed to decode loot payload: {error}"))?;
    let file_name = derive_download_file_name(item);
    let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    let output_path = next_available_path(&output_dir.join(file_name));
    std::fs::write(&output_path, bytes)
        .map_err(|error| format!("Failed to save loot file: {error}"))?;
    Ok(format!("Saved {}", output_path.display()))
}

fn derive_download_file_name(item: &LootItem) -> String {
    let candidate = item
        .file_path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|value| value.to_str())
        .unwrap_or(item.name.as_str());
    sanitize_file_name(candidate)
}

fn sanitize_file_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect();
    if sanitized.trim().is_empty() { "loot.bin".to_owned() } else { sanitized }
}

fn next_available_path(path: &std::path::Path) -> std::path::PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let stem = path.file_stem().and_then(|value| value.to_str()).unwrap_or("loot");
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
    for index in 1..1000 {
        let candidate = if extension.is_empty() {
            path.with_file_name(format!("{stem}-{index}"))
        } else {
            path.with_file_name(format!("{stem}-{index}.{extension}"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }

    path.to_path_buf()
}

fn blank_if_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() { fallback } else { value }
}

fn human_size(size_bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

    let mut size = size_bytes as f64;
    let mut unit = 0_usize;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{size_bytes} {}", UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use transport::{AgentSummary, LootItem};

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
        assert!(app_state.online_operators.is_empty());
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

    fn sample_agent(
        name_id: &str,
        hostname: &str,
        username: &str,
        elevated: bool,
        last_call_in: &str,
    ) -> AgentSummary {
        AgentSummary {
            name_id: name_id.to_owned(),
            status: "Alive".to_owned(),
            domain_name: "LAB".to_owned(),
            username: username.to_owned(),
            internal_ip: "10.0.0.10".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            hostname: hostname.to_owned(),
            process_arch: "x64".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_pid: "1234".to_owned(),
            elevated,
            os_version: "Windows 11".to_owned(),
            os_build: "22631".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: "5".to_owned(),
            sleep_jitter: "10".to_owned(),
            last_call_in: last_call_in.to_owned(),
            note: "primary workstation".to_owned(),
        }
    }

    #[test]
    fn agent_filter_matches_multiple_columns() {
        let agent = sample_agent("ABCD1234", "wkstn-1", "operator", true, "10/03/2026 12:00:00");
        assert!(agent_matches_filter(&agent, "wkstn"));
        assert!(agent_matches_filter(&agent, "primary"));
        assert!(agent_matches_filter(&agent, "10.0.0.10"));
        assert!(!agent_matches_filter(&agent, "sqlservr"));
    }

    #[test]
    fn sort_agents_orders_by_last_checkin_descending() {
        let mut agents = vec![
            sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 11:00:00"),
            sample_agent("BBBB0002", "wkstn-2", "bob", true, "10/03/2026 12:00:00"),
        ];

        sort_agents(&mut agents, AgentSortColumn::LastCheckin, true);

        assert_eq!(agents[0].name_id, "BBBB0002");
        assert_eq!(agents[1].name_id, "AAAA0001");
    }

    #[test]
    fn sort_button_label_marks_active_column() {
        assert_eq!(
            sort_button_label(Some(AgentSortColumn::Hostname), false, AgentSortColumn::Hostname),
            "Hostname ^"
        );
        assert_eq!(
            sort_button_label(Some(AgentSortColumn::Hostname), true, AgentSortColumn::Id),
            "ID"
        );
    }

    #[test]
    fn build_kill_task_uses_exit_command_shape() {
        let OperatorMessage::AgentTask(message) = build_kill_task("ABCD1234", "operator") else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.demon_id, "ABCD1234");
        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandExit).to_string());
        assert_eq!(message.info.command.as_deref(), Some("kill"));
    }

    #[test]
    fn build_note_task_uses_teamserver_note_shape() {
        let OperatorMessage::AgentTask(message) =
            build_note_task("ABCD1234", "triaged", "operator")
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.demon_id, "ABCD1234");
        assert_eq!(message.info.command_id, "Teamserver");
        assert_eq!(message.info.command.as_deref(), Some("note"));
        assert_eq!(message.info.arguments.as_deref(), Some("triaged"));
    }

    #[test]
    fn build_chat_message_uses_chat_wire_shape() {
        let Some(OperatorMessage::ChatMessage(message)) =
            build_chat_message(Some("operator"), " hello team ")
        else {
            panic!("expected chat message");
        };

        assert_eq!(message.head.event, EventCode::Chat);
        assert_eq!(
            message.info.fields.get("Message"),
            Some(&serde_json::Value::String("hello team".to_owned()))
        );
    }

    #[test]
    fn loot_filter_matches_type_agent_and_text() {
        let item = LootItem {
            kind: LootKind::Screenshot,
            name: "desktop.png".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("C:/Temp/desktop.png".to_owned()),
            size_bytes: Some(1024),
            content_base64: None,
            preview: Some("primary desktop".to_owned()),
        };

        assert!(loot_matches_filters(
            &item,
            LootTypeFilter::Screenshots,
            "abcd",
            "2026-03-10",
            "desktop"
        ));
        assert!(!loot_matches_filters(&item, LootTypeFilter::Credentials, "", "", ""));
    }

    #[test]
    fn sanitize_file_name_replaces_invalid_characters() {
        assert_eq!(sanitize_file_name("C:\\Temp\\report?.txt"), "C__Temp_report_.txt");
    }
}
