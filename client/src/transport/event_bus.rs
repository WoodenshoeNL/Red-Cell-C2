use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui;
use red_cell_common::OperatorInfo;
use red_cell_common::demon::DemonCommand;

use crate::login::TlsFailure;

/// Default maximum number of events kept in the notification log.
pub(crate) const DEFAULT_EVENT_LOG_MAX: usize = 500;
pub(super) const MAX_OPERATOR_ACTIVITY: usize = 20;

pub(super) const MAX_LOOT_NAME_CHARS: usize = 512;
pub(super) const MAX_LOOT_AGENT_ID_CHARS: usize = 64;
pub(super) const MAX_LOOT_SOURCE_CHARS: usize = 256;
pub(super) const MAX_LOOT_TIMESTAMP_CHARS: usize = 128;
pub(super) const MAX_LOOT_PATH_CHARS: usize = 512;
pub(super) const MAX_LOOT_PREVIEW_CHARS: usize = 1024;

/// A single command dispatched by an operator, recorded for the activity feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperatorActivityEntry {
    /// Timestamp of the command dispatch.
    pub(crate) timestamp: String,
    /// Target agent ID (normalised to uppercase eight-char hex).
    pub(crate) agent_id: String,
    /// Full command line as typed by the operator.
    pub(crate) command_line: String,
}

/// Presence, role, and recent activity state for a connected operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectedOperatorState {
    /// Optional RBAC role name (e.g. `"Admin"`, `"Operator"`, `"ReadOnly"`).
    pub(crate) role: Option<String>,
    /// Whether the operator is currently online.
    pub(crate) online: bool,
    /// Timestamp of the operator's most recent activity or connect event.
    pub(crate) last_seen: Option<String>,
    /// Most recent commands dispatched by this operator, newest first.
    pub(crate) recent_commands: VecDeque<OperatorActivityEntry>,
}

pub(crate) type SharedAppState = Arc<Mutex<AppState>>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppEvent {
    AgentCheckin(String),
    AgentTaskResult {
        task_id: String,
        agent_id: String,
        output: String,
    },
    /// Fires whenever any non-empty agent command output arrives.
    CommandResponse {
        agent_id: String,
        task_id: String,
        output: String,
    },
    /// Fires when a loot item (credential, file, screenshot, etc.) is captured.
    LootCaptured(LootItem),
    /// Fires when a listener is started, stopped, or edited.
    ListenerChanged {
        name: String,
        action: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Retrying(String),
    Error(String),
}

impl ConnectionStatus {
    #[allow(dead_code)]
    pub(crate) fn placeholders() -> [Self; 5] {
        [
            Self::Disconnected,
            Self::Connecting,
            Self::Connected,
            Self::Retrying("Retrying after a dropped connection".to_owned()),
            Self::Error("Awaiting transport initialization".to_owned()),
        ]
    }

    pub(crate) fn label(&self) -> &str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Retrying(_) => "Retrying",
            Self::Error(_) => "Connection Error",
        }
    }

    pub(crate) fn color(&self) -> egui::Color32 {
        match self {
            Self::Disconnected => egui::Color32::from_rgb(130, 138, 145),
            Self::Connecting | Self::Retrying(_) => egui::Color32::from_rgb(232, 182, 83),
            Self::Connected => egui::Color32::from_rgb(110, 199, 141),
            Self::Error(_) => egui::Color32::from_rgb(215, 83, 83),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn detail(&self) -> Option<&str> {
        match self {
            Self::Retrying(message) | Self::Error(message) => Some(message.as_str()),
            Self::Disconnected | Self::Connecting | Self::Connected => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LootKind {
    Credential,
    File,
    Screenshot,
    Other,
}

impl LootKind {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Credential => "Credential",
            Self::File => "File",
            Self::Screenshot => "Screenshot",
            Self::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LootItem {
    pub(crate) id: Option<i64>,
    pub(crate) kind: LootKind,
    pub(crate) name: String,
    pub(crate) agent_id: String,
    pub(crate) source: String,
    pub(crate) collected_at: String,
    pub(crate) file_path: Option<String>,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) content_base64: Option<String>,
    pub(crate) preview: Option<String>,
}

/// Classifies an event stored in the notification log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventKind {
    /// Events directly related to agent check-ins and task output.
    Agent,
    /// Chat messages sent by human operators.
    Operator,
    /// Teamserver, builder, and connection lifecycle messages.
    System,
}

impl EventKind {
    /// Human-readable label used in filter buttons.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Agent => "Agent",
            Self::Operator => "Operator",
            Self::System => "System",
        }
    }
}

/// A single entry in the persistent notification / chat log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NotificationEntry {
    pub(crate) kind: EventKind,
    pub(crate) author: String,
    pub(crate) sent_at: String,
    pub(crate) message: String,
    pub(crate) read: bool,
}

/// Bounded event log stored in the client, backed by a `VecDeque`.
///
/// Oldest entries are evicted when `max_size` is exceeded. An `unread_count`
/// is maintained so callers can display a badge without scanning all entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventLog {
    pub(crate) entries: VecDeque<NotificationEntry>,
    pub(crate) max_size: usize,
    pub(crate) unread_count: usize,
}

impl EventLog {
    /// Create a new empty log with the given capacity limit.
    pub(crate) fn new(max_size: usize) -> Self {
        Self { entries: VecDeque::new(), max_size, unread_count: 0 }
    }

    /// Push a new event; evicts the oldest entry when at capacity.
    pub(crate) fn push(
        &mut self,
        kind: EventKind,
        author: impl Into<String>,
        sent_at: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.entries.len() >= self.max_size {
            if let Some(front) = self.entries.pop_front() {
                if !front.read {
                    self.unread_count = self.unread_count.saturating_sub(1);
                }
            }
        }
        self.entries.push_back(NotificationEntry {
            kind,
            author: author.into(),
            sent_at: sent_at.into(),
            message: message.into(),
            read: false,
        });
        self.unread_count += 1;
    }

    /// Mark every entry as read, resetting `unread_count` to zero.
    pub(crate) fn mark_all_read(&mut self) {
        for entry in &mut self.entries {
            entry.read = true;
        }
        self.unread_count = 0;
    }

    /// Number of unread entries with a given kind.
    pub(crate) fn unread_by_kind(&self, kind: EventKind) -> usize {
        self.entries.iter().filter(|e| !e.read && e.kind == kind).count()
    }

    /// Total number of entries (read and unread).
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentConsoleEntryKind {
    Output,
    Error,
}

impl AgentConsoleEntryKind {
    pub(crate) fn from_command_id(command_id: &str) -> Self {
        match command_id.trim().parse::<u32>() {
            Ok(id) if id == u32::from(DemonCommand::CommandError) => Self::Error,
            _ => Self::Output,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentConsoleEntry {
    pub(crate) command_id: String,
    /// Task ID assigned when the command was dispatched; empty for local/injected entries.
    pub(crate) task_id: String,
    pub(crate) received_at: String,
    pub(crate) command_line: Option<String>,
    pub(crate) kind: AgentConsoleEntryKind,
    pub(crate) output: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileBrowserEntry {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) is_dir: bool,
    pub(crate) size_label: String,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) modified_at: String,
    pub(crate) permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessEntry {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) name: String,
    pub(crate) arch: String,
    pub(crate) user: String,
    pub(crate) session: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct AgentProcessListState {
    pub(crate) rows: Vec<ProcessEntry>,
    pub(crate) status_message: Option<String>,
    pub(crate) updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DownloadProgress {
    pub(crate) file_id: String,
    pub(crate) remote_path: String,
    pub(crate) current_size: u64,
    pub(crate) expected_size: u64,
    pub(crate) state: String,
}

/// Holds the content of a completed agent file download, ready to be saved to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompletedDownload {
    /// Remote path the file was downloaded from.
    pub(crate) remote_path: String,
    /// Raw file bytes.
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct AgentFileBrowserState {
    pub(crate) current_dir: Option<String>,
    pub(crate) directories: BTreeMap<String, Vec<FileBrowserEntry>>,
    pub(crate) downloads: BTreeMap<String, DownloadProgress>,
    pub(crate) status_message: Option<String>,
    /// Completed downloads awaiting a save-to-disk dialog, keyed by file_id.
    pub(crate) completed_downloads: BTreeMap<String, CompletedDownload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentSummary {
    pub(crate) name_id: String,
    pub(crate) status: String,
    pub(crate) domain_name: String,
    pub(crate) username: String,
    pub(crate) internal_ip: String,
    pub(crate) external_ip: String,
    pub(crate) hostname: String,
    pub(crate) process_arch: String,
    pub(crate) process_name: String,
    pub(crate) process_pid: String,
    pub(crate) elevated: bool,
    pub(crate) os_version: String,
    pub(crate) os_build: String,
    pub(crate) os_arch: String,
    pub(crate) sleep_delay: String,
    pub(crate) sleep_jitter: String,
    pub(crate) last_call_in: String,
    pub(crate) note: String,
    pub(crate) pivot_parent: Option<String>,
    pub(crate) pivot_links: Vec<String>,
}

/// A single line of build-console output received from the teamserver during
/// payload generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildConsoleEntry {
    /// Severity tag sent by the builder (e.g. "Info", "Good", "Error").
    pub(crate) message_type: String,
    /// Human-readable message text.
    pub(crate) message: String,
}

/// Holds the result of a successful payload build so the operator can save it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayloadBuildResult {
    /// Raw payload bytes (decoded from base64).
    pub(crate) payload_bytes: Vec<u8>,
    /// Output format string (e.g. "Windows Exe").
    pub(crate) format: String,
    /// Suggested filename (e.g. "demon.exe").
    pub(crate) file_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListenerSummary {
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) port_bind: String,
    pub(crate) port_conn: String,
    pub(crate) status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppState {
    pub(crate) server_url: String,
    pub(crate) connection_status: ConnectionStatus,
    pub(crate) operator_info: Option<OperatorInfo>,
    /// Arc-wrapped to allow O(1) snapshot clones at read sites (e.g. Python bindings).
    /// Mutate via `Arc::make_mut(&mut self.agents)` for copy-on-write semantics.
    pub(crate) agents: Arc<Vec<AgentSummary>>,
    pub(crate) agent_consoles: BTreeMap<String, Vec<AgentConsoleEntry>>,
    pub(crate) file_browsers: BTreeMap<String, AgentFileBrowserState>,
    pub(crate) process_lists: BTreeMap<String, AgentProcessListState>,
    /// Arc-wrapped for O(1) snapshot clones; mutate via `Arc::make_mut`.
    pub(crate) listeners: Arc<Vec<ListenerSummary>>,
    /// Arc-wrapped for O(1) snapshot clones; mutate via `Arc::make_mut`.
    pub(crate) loot: Arc<Vec<LootItem>>,
    pub(crate) loot_revision: u64,
    /// Persistent notification / chat log with per-entry read tracking.
    pub(crate) event_log: EventLog,
    /// Usernames of operators currently seen online (used by the chat panel).
    pub(crate) online_operators: BTreeSet<String>,
    /// Per-operator presence, role, and activity state, keyed by username.
    pub(crate) connected_operators: BTreeMap<String, ConnectedOperatorState>,
    /// Set when the last connection attempt failed due to a TLS certificate error.
    pub(crate) tls_failure: Option<TlsFailure>,
    /// Stores the most recent authentication error message so it remains accessible
    /// even after the connection status transitions from `Error` to `Retrying`.
    pub(crate) last_auth_error: Option<String>,
    /// Build console messages received during payload generation (displayed in the
    /// Payload dialog's "Building Console" area).
    /// Arc-wrapped for O(1) snapshot clones; mutate via `Arc::make_mut`.
    pub(crate) build_console_messages: Arc<Vec<BuildConsoleEntry>>,
    /// The most recent payload build response, if any.  The dialog reads this to
    /// offer the operator a file-save action.
    pub(crate) last_payload_response: Option<PayloadBuildResult>,
    /// Wall-clock time when the session was established (used for client-side TTL tracking).
    pub(crate) session_start: Option<Instant>,
}

impl AppState {
    pub(crate) fn new(server_url: String) -> Self {
        Self {
            server_url,
            connection_status: ConnectionStatus::Disconnected,
            operator_info: None,
            agents: Arc::new(Vec::new()),
            agent_consoles: BTreeMap::new(),
            file_browsers: BTreeMap::new(),
            process_lists: BTreeMap::new(),
            listeners: Arc::new(Vec::new()),
            loot: Arc::new(Vec::new()),
            loot_revision: 0,
            event_log: EventLog::new(DEFAULT_EVENT_LOG_MAX),
            online_operators: BTreeSet::new(),
            connected_operators: BTreeMap::new(),
            tls_failure: None,
            last_auth_error: None,
            build_console_messages: Arc::new(Vec::new()),
            last_payload_response: None,
            session_start: None,
        }
    }
}
