//! Top-level session panel state: operator presence, agent table, chat, and dialogs.

use std::collections::BTreeMap;

use red_cell_common::operator::OperatorMessage;

use crate::transport::EventKind;

use super::agent::{
    AgentConsoleState, AgentFileBrowserUiState, AgentProcessPanelState, AgentSortColumn,
    CredentialSubFilter, DockState, DockTab, FileSubFilter, LootPanelState, NoteEditorState,
    ProcessInjectionDialogState, ScreenshotTextureCache, ScriptManagerState, SessionGraphState,
};
use super::listener::{ListenerDialogState, PayloadDialogState};

// ── Audit log panel state ─────────────────────────────────────────────────────

/// A single row fetched from `GET /api/v1/audit`.
#[derive(Debug, Clone)]
pub(crate) struct AuditRow {
    /// Server-assigned primary key — used as a stable egui widget ID.
    pub(crate) id: i64,
    pub(crate) occurred_at: String,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) target_kind: String,
    pub(crate) target_id: Option<String>,
    pub(crate) agent_id: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) result_status: String,
}

/// Fetch status for the audit log panel.
#[derive(Debug, Default)]
pub(crate) enum AuditFetchStatus {
    #[default]
    Idle,
    Fetching,
    Error(String),
}

/// Transient UI state for the audit log viewer panel.
#[derive(Debug)]
pub(crate) struct AuditLogPanelState {
    /// Rows returned from the last successful fetch, newest first.
    pub(crate) rows: Vec<AuditRow>,
    /// Total matching rows reported by the server for the current filter.
    pub(crate) total: usize,
    /// Current page offset.
    pub(crate) offset: usize,
    /// Page size (rows per request).
    pub(crate) limit: usize,
    /// Whether a fetch is in progress.
    pub(crate) fetch_status: AuditFetchStatus,
    /// Filter: operator/actor name substring.
    pub(crate) filter_actor: String,
    /// Filter: action label substring.
    pub(crate) filter_action: String,
    /// Filter: agent ID hex substring.
    pub(crate) filter_agent_id: String,
    /// API key input field (editable in the panel when not in LocalConfig).
    pub(crate) api_key_input: String,
    /// Whether the API key input field should be shown.
    pub(crate) show_api_key_input: bool,
    /// Result channel: the background fetch task writes here when done.
    pub(crate) result_rx: Option<tokio::sync::oneshot::Receiver<FetchResult>>,
    /// Shared HTTP client — reused across page fetches to keep the connection pool alive.
    pub(crate) http_client: reqwest::Client,
}

impl Default for AuditLogPanelState {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            total: 0,
            offset: 0,
            limit: 0,
            fetch_status: AuditFetchStatus::default(),
            filter_actor: String::new(),
            filter_action: String::new(),
            filter_agent_id: String::new(),
            api_key_input: String::new(),
            show_api_key_input: false,
            result_rx: None,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }
}

/// Result type for an audit log fetch task.
pub(crate) type FetchResult = Result<AuditFetchPayload, String>;

/// Successful audit log fetch payload.
#[derive(Debug)]
pub(crate) struct AuditFetchPayload {
    pub(crate) rows: Vec<AuditRow>,
    pub(crate) total: usize,
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}

impl AuditLogPanelState {
    pub(crate) const DEFAULT_LIMIT: usize = 50;
}

// ── Operator management panel state ──────────────────────────────────────────

/// Transient UI state for the operator management panel.
#[derive(Debug, Default)]
pub(crate) struct OperatorPanelState {
    /// Whether the "Create Operator" dialog is open.
    pub(crate) create_dialog_open: bool,
    /// Username field in the Create Operator dialog.
    pub(crate) create_username: String,
    /// Password field in the Create Operator dialog.
    pub(crate) create_password: String,
    /// Role selection index in the Create Operator dialog (0=Admin, 1=Operator, 2=Analyst).
    pub(crate) create_role_index: usize,
    /// Username pending deletion confirmation (Some = confirmation modal open).
    pub(crate) delete_pending: Option<String>,
    /// Last status message (success or error feedback to the operator).
    pub(crate) status_message: Option<String>,
}

// ── Top-level session panel state ────────────────────────────────────────────

#[derive(Debug, Default)]
pub(crate) struct SessionPanelState {
    pub(crate) filter: String,
    pub(crate) sort_column: Option<AgentSortColumn>,
    pub(crate) descending: bool,
    pub(crate) open_consoles: Vec<String>,
    pub(crate) selected_console: Option<String>,
    pub(crate) console_state: BTreeMap<String, AgentConsoleState>,
    pub(crate) file_browser_state: BTreeMap<String, AgentFileBrowserUiState>,
    pub(crate) process_state: BTreeMap<String, AgentProcessPanelState>,
    pub(crate) note_editor: Option<NoteEditorState>,
    pub(crate) process_injection: Option<ProcessInjectionDialogState>,
    pub(crate) script_manager: ScriptManagerState,
    pub(crate) graph_state: SessionGraphState,
    pub(crate) pending_messages: Vec<OperatorMessage>,
    pub(crate) status_message: Option<String>,
    pub(crate) loot_cred_filter: CredentialSubFilter,
    pub(crate) loot_file_filter: FileSubFilter,
    pub(crate) loot_agent_filter: String,
    pub(crate) loot_since_filter: String,
    pub(crate) loot_until_filter: String,
    pub(crate) loot_text_filter: String,
    pub(crate) loot_status_message: Option<String>,
    pub(crate) loot_panel: LootPanelState,
    /// Cache of decoded screenshot textures keyed by loot item id.
    pub(crate) screenshot_textures: ScreenshotTextureCache,
    pub(crate) chat_input: String,
    /// Which event kinds are shown in the notification panel (None = all).
    pub(crate) event_kind_filter: Option<EventKind>,
    /// Selected listener name in the listeners table.
    pub(crate) selected_listener: Option<String>,
    /// Open Create/Edit Listener dialog state (None = dialog closed).
    pub(crate) listener_dialog: Option<ListenerDialogState>,
    /// Open Payload generation dialog state (None = dialog closed).
    pub(crate) payload_dialog: Option<PayloadDialogState>,
    /// Operator management panel state.
    pub(crate) operators_panel: OperatorPanelState,
    /// Audit log viewer panel state.
    pub(crate) audit_log_panel: AuditLogPanelState,
    /// Set to true when the "Mark all read" button is pressed; consumed in `render_main_ui`.
    pub(crate) pending_mark_all_read: bool,
    /// Bottom dock panel state.
    pub(crate) dock: DockState,
}

impl SessionPanelState {
    pub(crate) fn toggle_sort(&mut self, column: AgentSortColumn) {
        if self.sort_column == Some(column) {
            self.descending = !self.descending;
        } else {
            self.sort_column = Some(column);
            self.descending = false;
        }
    }

    pub(crate) fn ensure_console_open(&mut self, agent_id: &str) {
        if !self.open_consoles.iter().any(|open_id| open_id == agent_id) {
            self.open_consoles.push(agent_id.to_owned());
        }
        self.selected_console = Some(agent_id.to_owned());
        self.dock.open_tab(DockTab::AgentConsole(agent_id.to_owned()));
    }

    pub(crate) fn ensure_file_browser_open(&mut self, agent_id: &str) {
        self.dock.open_tab(DockTab::FileBrowser(agent_id.to_owned()));
    }

    pub(crate) fn ensure_process_list_open(&mut self, agent_id: &str) {
        self.dock.open_tab(DockTab::ProcessList(agent_id.to_owned()));
    }

    #[allow(dead_code)]
    pub(crate) fn ensure_selected_console(&mut self) {
        if self
            .selected_console
            .as_ref()
            .is_some_and(|selected| self.open_consoles.iter().any(|open_id| open_id == selected))
        {
            return;
        }

        self.selected_console = self.open_consoles.first().cloned();
    }

    pub(crate) fn close_console(&mut self, agent_id: &str) {
        self.open_consoles.retain(|open_id| open_id != agent_id);
        self.console_state.remove(agent_id);
        self.file_browser_state.remove(agent_id);
        self.dock.close_tab(&DockTab::AgentConsole(agent_id.to_owned()));
        if self.selected_console.as_deref() == Some(agent_id) {
            self.selected_console = self.open_consoles.first().cloned();
        }
    }

    pub(crate) fn console_state_mut(&mut self, agent_id: &str) -> &mut AgentConsoleState {
        self.console_state.entry(agent_id.to_owned()).or_default()
    }

    pub(crate) fn file_browser_state_mut(
        &mut self,
        agent_id: &str,
    ) -> &mut AgentFileBrowserUiState {
        self.file_browser_state.entry(agent_id.to_owned()).or_default()
    }

    pub(crate) fn process_state_mut(&mut self, agent_id: &str) -> &mut AgentProcessPanelState {
        self.process_state.entry(agent_id.to_owned()).or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_sort_first_click_selects_column_ascending() {
        let mut s = SessionPanelState::default();
        s.toggle_sort(AgentSortColumn::Hostname);
        assert_eq!(s.sort_column, Some(AgentSortColumn::Hostname));
        assert!(!s.descending);
    }

    #[test]
    fn toggle_sort_second_click_on_same_column_flips_descending() {
        let mut s = SessionPanelState::default();
        s.toggle_sort(AgentSortColumn::Pid);
        s.toggle_sort(AgentSortColumn::Pid);
        assert_eq!(s.sort_column, Some(AgentSortColumn::Pid));
        assert!(s.descending);
    }

    #[test]
    fn toggle_sort_switching_column_resets_to_ascending() {
        let mut s = SessionPanelState::default();
        s.toggle_sort(AgentSortColumn::Hostname);
        s.toggle_sort(AgentSortColumn::Hostname);
        assert!(s.descending);
        s.toggle_sort(AgentSortColumn::Pid);
        assert_eq!(s.sort_column, Some(AgentSortColumn::Pid));
        assert!(!s.descending);
    }

    #[test]
    fn listener_dialog_open_close() {
        let mut s = SessionPanelState::default();
        assert!(s.listener_dialog.is_none());
        s.listener_dialog = Some(ListenerDialogState::new_create());
        assert!(s.listener_dialog.is_some());
        s.listener_dialog = None;
        assert!(s.listener_dialog.is_none());
    }

    #[test]
    fn listener_dialog_cancel_discards_edits_next_open_is_fresh() {
        let mut s = SessionPanelState::default();
        s.listener_dialog = Some(ListenerDialogState::new_create());
        if let Some(d) = &mut s.listener_dialog {
            d.name = "dirty".to_owned();
        }
        s.listener_dialog = None;
        let fresh = ListenerDialogState::new_create();
        assert!(fresh.name.is_empty());
        s.listener_dialog = Some(fresh);
        assert_eq!(s.listener_dialog.as_ref().unwrap().name, "");
    }

    #[test]
    fn payload_dialog_open_close() {
        let mut s = SessionPanelState::default();
        assert!(s.payload_dialog.is_none());
        s.payload_dialog = Some(PayloadDialogState::new());
        assert!(s.payload_dialog.is_some());
        s.payload_dialog = None;
        assert!(s.payload_dialog.is_none());
    }
}
