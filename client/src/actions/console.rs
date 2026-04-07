//! Console command submission and console-entry injection for `ClientApp`.

use crate::tasks::{
    agent_task_id, build_console_task, handle_local_command, push_history_entry, short_task_id,
};
use crate::transport::{AgentConsoleEntry, AgentConsoleEntryKind};
use crate::{AppPhase, ClientApp};

impl ClientApp {
    pub(crate) fn submit_console_command(&mut self, agent_id: &str) {
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
                let task_id = agent_task_id(&message).unwrap_or_default();
                push_history_entry(console, &command_line);
                console.input.clear();
                console.status_message = None;
                // Show the outgoing task ID immediately so operators can correlate output.
                let submitted_output =
                    format!("→ [t:{}] {}", short_task_id(&task_id), command_line);
                self.inject_console_entry_with_task(
                    agent_id,
                    &command_line,
                    &submitted_output,
                    &task_id,
                );
                self.session_panel.pending_messages.push(message);
            }
            Err(error) => {
                self.session_panel.console_state_mut(agent_id).status_message = Some(error);
            }
        }
    }

    /// Inserts a locally-generated console entry into the shared app state.
    fn inject_console_entry(&self, agent_id: &str, command_line: &str, output: &str) {
        self.inject_console_entry_with_task(agent_id, command_line, output, "");
    }

    fn inject_console_entry_with_task(
        &self,
        agent_id: &str,
        command_line: &str,
        output: &str,
        task_id: &str,
    ) {
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
            task_id: task_id.to_owned(),
            received_at: String::new(),
            command_line: Some(command_line.to_owned()),
            output: output.to_owned(),
        });
    }
}
