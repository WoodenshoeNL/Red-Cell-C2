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
