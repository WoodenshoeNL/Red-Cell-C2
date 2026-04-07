//! Process-list refresh, process kill, and shellcode injection for `ClientApp`.

use crate::ClientApp;
use crate::tasks::{
    build_process_injection_task, build_process_kill_task, build_process_list_task,
};

impl ClientApp {
    pub(crate) fn queue_process_refresh(&mut self, agent_id: &str) {
        let message = build_process_list_task(agent_id, &self.current_operator_username());
        self.session_panel.process_state_mut(agent_id).status_message =
            Some("Queued `ps`.".to_owned());
        self.session_panel.pending_messages.push(message);
    }

    pub(crate) fn queue_process_kill(&mut self, agent_id: &str, pid: u32) {
        let message = build_process_kill_task(agent_id, pid, &self.current_operator_username());
        self.session_panel.process_state_mut(agent_id).status_message =
            Some(format!("Queued process kill for PID {pid}."));
        self.session_panel.pending_messages.push(message);
    }

    pub(crate) fn submit_process_injection(&mut self) {
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
}
