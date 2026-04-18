//! Agent-panel state types: sort columns, loot browser, per-agent sub-panels,
//! session graph, process injection, dock tabs, and action enums.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use eframe::egui::{self, Color32, Pos2, TextureHandle};

use crate::transport::AppState;

// ── Agent table ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentSortColumn {
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
    pub(crate) const ALL: [(Self, &'static str); 12] = [
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

// ── Note editor ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoteEditorState {
    pub(crate) agent_id: String,
    pub(crate) note: String,
}

// ── Loot panel types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LootTypeFilter {
    #[default]
    All,
    Credentials,
    Files,
    Screenshots,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CredentialSubFilter {
    #[default]
    All,
    NtlmHash,
    Plaintext,
    KerberosTicket,
    Certificate,
}

impl CredentialSubFilter {
    pub(crate) const ALL: [(Self, &'static str); 5] = [
        (Self::All, "All"),
        (Self::NtlmHash, "NTLM Hash"),
        (Self::Plaintext, "Plaintext Password"),
        (Self::KerberosTicket, "Kerberos Ticket"),
        (Self::Certificate, "Certificate"),
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FileSubFilter {
    #[default]
    All,
    Document,
    Archive,
    Binary,
}

impl FileSubFilter {
    pub(crate) const ALL: [(Self, &'static str); 4] = [
        (Self::All, "All"),
        (Self::Document, "Document"),
        (Self::Archive, "Archive"),
        (Self::Binary, "Binary"),
    ];
}

/// Active sub-tab inside the Loot dock panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LootTab {
    #[default]
    Credentials,
    Screenshots,
    Files,
}

/// Columns available for sorting in the credential table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CredentialSortColumn {
    #[default]
    Name,
    Agent,
    Category,
    Source,
    Time,
}

/// Persistent UI state for the Loot panel.
#[derive(Debug)]
pub(crate) struct LootPanelState {
    /// Currently active sub-tab.
    pub(crate) active_tab: LootTab,
    /// Selected screenshot index (into the filtered screenshot list) for detail view.
    pub(crate) selected_screenshot: Option<usize>,
    /// Column used for sorting the credential table.
    pub(crate) cred_sort_column: CredentialSortColumn,
    /// Whether the credential sort is descending.
    pub(crate) cred_sort_desc: bool,
    /// Cached indices into `AppState::loot` matching the current filter state.
    pub(crate) filtered_loot: Vec<usize>,
    /// Set whenever filters change so the cached index list can be rebuilt lazily.
    pub(crate) filter_dirty: bool,
    /// Loot revision used to populate `filtered_loot`.
    pub(crate) cached_loot_revision: u64,
}

impl LootPanelState {
    pub(crate) fn mark_filter_dirty(&mut self) {
        self.filter_dirty = true;
    }

    pub(crate) fn refresh_filtered_loot(
        &mut self,
        state: &AppState,
        cred_filter: CredentialSubFilter,
        file_filter: FileSubFilter,
        agent_filter: &str,
        since_filter: &str,
        until_filter: &str,
        text_filter: &str,
    ) {
        if !self.filter_dirty && self.cached_loot_revision == state.loot_revision {
            return;
        }

        let type_filter = match self.active_tab {
            LootTab::Credentials => LootTypeFilter::Credentials,
            LootTab::Screenshots => LootTypeFilter::Screenshots,
            LootTab::Files => LootTypeFilter::Files,
        };

        self.filtered_loot = crate::build_filtered_loot_indices(
            &state.loot,
            type_filter,
            cred_filter,
            file_filter,
            agent_filter,
            since_filter,
            until_filter,
            text_filter,
        );
        self.cached_loot_revision = state.loot_revision;
        self.filter_dirty = false;
    }
}

impl Default for LootPanelState {
    fn default() -> Self {
        Self {
            active_tab: LootTab::default(),
            selected_screenshot: None,
            cred_sort_column: CredentialSortColumn::default(),
            cred_sort_desc: false,
            filtered_loot: Vec::new(),
            filter_dirty: true,
            cached_loot_revision: 0,
        }
    }
}

// ── Per-agent sub-panel state ─────────────────────────────────────────────────

#[derive(Debug, Default)]
pub(crate) struct AgentConsoleState {
    pub(crate) input: String,
    pub(crate) history: Vec<String>,
    pub(crate) history_index: Option<usize>,
    pub(crate) completion_index: usize,
    pub(crate) completion_seed: Option<String>,
    pub(crate) status_message: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct AgentFileBrowserUiState {
    pub(crate) selected_path: Option<String>,
    pub(crate) pending_dirs: BTreeSet<String>,
    pub(crate) status_message: Option<String>,
    /// File IDs of completed downloads that have been saved or dismissed by the operator.
    /// Entries here are hidden from the "completed downloads" list.
    pub(crate) dismissed_downloads: BTreeSet<String>,
}

/// Auto-refresh interval for the process list panel (standalone tab and console sub-panel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ProcessListAutoRefresh {
    #[default]
    Off,
    Secs10,
    Secs30,
    Secs60,
}

impl ProcessListAutoRefresh {
    /// Returns `None` when off, otherwise the interval in seconds.
    pub(crate) fn interval_secs(self) -> Option<u64> {
        match self {
            Self::Off => None,
            Self::Secs10 => Some(10),
            Self::Secs30 => Some(30),
            Self::Secs60 => Some(60),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Secs10 => "10s",
            Self::Secs30 => "30s",
            Self::Secs60 => "60s",
        }
    }
}

#[cfg(test)]
mod process_list_auto_refresh_tests {
    use super::ProcessListAutoRefresh;

    #[test]
    fn interval_secs_matches_variant() {
        assert_eq!(ProcessListAutoRefresh::Off.interval_secs(), None);
        assert_eq!(ProcessListAutoRefresh::Secs10.interval_secs(), Some(10));
        assert_eq!(ProcessListAutoRefresh::Secs30.interval_secs(), Some(30));
        assert_eq!(ProcessListAutoRefresh::Secs60.interval_secs(), Some(60));
    }
}

#[derive(Debug)]
pub(crate) struct AgentProcessPanelState {
    pub(crate) filter: String,
    pub(crate) status_message: Option<String>,
    pub(crate) refresh_in_flight: bool,
    pub(crate) pending_refresh_generation: Option<u64>,
    pub(crate) refresh_started_at: Option<std::time::Instant>,
    /// Local wall-clock label, e.g. `Last refreshed: 14:32:05`.
    pub(crate) last_refreshed_display: Option<String>,
    pub(crate) auto_refresh: ProcessListAutoRefresh,
    pub(crate) next_auto_refresh_at: Option<std::time::Instant>,
}

impl Default for AgentProcessPanelState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            status_message: None,
            refresh_in_flight: false,
            pending_refresh_generation: None,
            refresh_started_at: None,
            last_refreshed_display: None,
            auto_refresh: ProcessListAutoRefresh::Off,
            next_auto_refresh_at: None,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ScriptManagerState {
    pub(crate) selected_script: Option<String>,
    pub(crate) selected_tab: Option<String>,
    pub(crate) status_message: Option<String>,
}

// ── Session graph state ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SessionGraphState {
    pub(crate) pan: egui::Vec2,
    pub(crate) zoom: f32,
}

impl Default for SessionGraphState {
    fn default() -> Self {
        Self { pan: egui::Vec2::ZERO, zoom: 1.0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionGraphNodeKind {
    Teamserver,
    Agent,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SessionGraphNode {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) subtitle: String,
    pub(crate) status: String,
    pub(crate) position: Pos2,
    pub(crate) size: egui::Vec2,
    pub(crate) kind: SessionGraphNodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionGraphEdge {
    pub(crate) from: String,
    pub(crate) to: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SessionGraphLayout {
    pub(crate) nodes: Vec<SessionGraphNode>,
    pub(crate) edges: Vec<SessionGraphEdge>,
}

// ── Process injection state ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum InjectionTargetAction {
    #[default]
    Inject,
    Migrate,
}

impl InjectionTargetAction {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Inject => "Inject",
            Self::Migrate => "Migrate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum InjectionTechnique {
    #[default]
    Default,
    CreateRemoteThread,
    NtCreateThreadEx,
    NtQueueApcThread,
}

impl InjectionTechnique {
    pub(crate) const ALL: [(Self, &'static str); 4] = [
        (Self::Default, "Default"),
        (Self::CreateRemoteThread, "CreateRemoteThread"),
        (Self::NtCreateThreadEx, "NtCreateThreadEx"),
        (Self::NtQueueApcThread, "NtQueueApcThread"),
    ];

    pub(crate) fn as_wire_value(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::CreateRemoteThread => "createremotethread",
            Self::NtCreateThreadEx => "ntcreatethreadex",
            Self::NtQueueApcThread => "ntqueueapcthread",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessInjectionDialogState {
    pub(crate) agent_id: String,
    pub(crate) pid: u32,
    pub(crate) process_name: String,
    pub(crate) arch: String,
    pub(crate) action: InjectionTargetAction,
    pub(crate) technique: InjectionTechnique,
    pub(crate) shellcode_path: String,
    pub(crate) arguments: String,
    pub(crate) status_message: Option<String>,
}

// ── Dock panel ───────────────────────────────────────────────────────────────

/// Identifies a tab in the bottom dock panel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum DockTab {
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
    /// Python-script-registered custom tab (title is the normalized tab name).
    CustomTab(String),
}

impl DockTab {
    /// Display label for the tab.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::TeamserverChat => "Teamserver Chat".to_owned(),
            Self::Listeners => "Listeners".to_owned(),
            Self::SessionGraph => "Session Graph".to_owned(),
            Self::Scripts => "Scripts".to_owned(),
            Self::Loot => "Loot".to_owned(),
            Self::AgentConsole(id) => format!("[{id}]"),
            Self::FileBrowser(id) => format!("[{id}] File Explorer"),
            Self::ProcessList(id) => format!("Process: [{id}]"),
            Self::CustomTab(title) => title.clone(),
        }
    }

    /// Accent color for the tab's left border (Havoc-style).
    pub(crate) fn accent_color(&self) -> Color32 {
        match self {
            Self::TeamserverChat => Color32::from_rgb(200, 80, 200), // magenta
            Self::Listeners => Color32::from_rgb(80, 180, 220),      // cyan
            Self::SessionGraph => Color32::from_rgb(110, 199, 141),  // green
            Self::Scripts => Color32::from_rgb(232, 182, 83),        // yellow
            Self::Loot => Color32::from_rgb(220, 130, 60),           // orange
            Self::AgentConsole(_) => Color32::from_rgb(140, 120, 220), // purple
            Self::FileBrowser(_) => Color32::from_rgb(80, 180, 140), // teal
            Self::ProcessList(_) => Color32::from_rgb(255, 85, 85),  // red/salmon
            Self::CustomTab(_) => Color32::from_rgb(100, 200, 120),  // green (plugin)
        }
    }

    /// Whether this tab can be closed by the user.
    pub(crate) fn closeable(&self) -> bool {
        !matches!(self, Self::TeamserverChat)
    }
}

/// Dock panel state — tracks which tabs are open, which is selected, and the top/bottom split.
#[derive(Debug)]
pub(crate) struct DockState {
    /// Ordered list of open dock tabs.
    pub(crate) open_tabs: Vec<DockTab>,
    /// Currently selected/visible dock tab.
    pub(crate) selected: Option<DockTab>,
    /// Fractional height of the top zone (0.0–1.0, default 0.35).
    #[allow(dead_code)]
    pub(crate) top_fraction: f32,
    /// Whether the event viewer panel (top-right) is visible.
    pub(crate) event_viewer_open: bool,
    /// Fractional width of the session table vs event viewer (0.0–1.0, default 0.6).
    pub(crate) top_split_fraction: f32,
}

impl Default for DockState {
    fn default() -> Self {
        Self {
            open_tabs: vec![DockTab::TeamserverChat],
            selected: Some(DockTab::TeamserverChat),
            top_fraction: 0.35,
            event_viewer_open: false,
            top_split_fraction: 0.6,
        }
    }
}

impl DockState {
    pub(crate) fn open_tab(&mut self, tab: DockTab) {
        if !self.open_tabs.contains(&tab) {
            self.open_tabs.push(tab.clone());
        }
        self.selected = Some(tab);
    }

    pub(crate) fn close_tab(&mut self, tab: &DockTab) {
        self.open_tabs.retain(|t| t != tab);
        if self.selected.as_ref() == Some(tab) {
            self.selected = self.open_tabs.first().cloned();
        }
    }

    pub(crate) fn ensure_selected(&mut self) {
        if self.selected.as_ref().is_some_and(|s| self.open_tabs.contains(s)) {
            return;
        }
        self.selected = self.open_tabs.first().cloned();
    }
}

// ── Screenshot texture cache ─────────────────────────────────────────────────

/// Cache for decoded screenshot textures.  `TextureHandle` does not implement `Debug`,
/// so we provide a manual impl to keep `SessionPanelState` debuggable.
#[derive(Default)]
pub(crate) struct ScreenshotTextureCache {
    pub(crate) inner: HashMap<i64, TextureHandle>,
}

impl std::fmt::Debug for ScreenshotTextureCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreenshotTextureCache").field("count", &self.inner.len()).finish()
    }
}

// ── Action enums ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionAction {
    OpenConsole(String),
    OpenFileBrowser(String),
    OpenProcessList(String),
    RequestKill(String),
    EditNote { agent_id: String, current_note: String },
}

#[derive(Debug, Clone)]
pub(crate) enum ScriptManagerAction {
    Load(PathBuf),
    Reload(String),
    Unload(String),
}
