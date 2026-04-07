//! Process-list refresh, process kill, and shellcode injection for `ClientApp`.

use std::time::{Duration, Instant};

use eframe::egui;

use crate::AppPhase;
use crate::ClientApp;
use crate::tasks::{
    build_process_injection_task, build_process_kill_task, build_process_list_task,
};
use crate::transport::AppState;

impl ClientApp {
    /// Current process-list refresh generation for `agent_id` (0 if none stored yet).
    pub(crate) fn current_process_list_generation(&self, agent_id: &str) -> u64 {
        let app_state = match &self.phase {
            AppPhase::Connected { app_state, .. } | AppPhase::Authenticating { app_state, .. } => {
                app_state
            }
            AppPhase::Login(_) => {
                return 0;
            }
        };
        match app_state.lock() {
            Ok(s) => s.process_lists.get(agent_id).map(|p| p.refresh_generation).unwrap_or(0),
            Err(poisoned) => poisoned
                .into_inner()
                .process_lists
                .get(agent_id)
                .map(|p| p.refresh_generation)
                .unwrap_or(0),
        }
    }

    /// Clears [`crate::state::AgentProcessPanelState::refresh_in_flight`] when a matching
    /// process-list response arrives, or after a timeout if the agent never answers.
    pub(crate) fn sync_process_refresh_completion(&mut self, agent_id: &str, state: &AppState) {
        let panel = self.session_panel.process_state_mut(agent_id);
        if !panel.refresh_in_flight {
            return;
        }
        let Some(expected) = panel.pending_refresh_generation else {
            return;
        };
        let current_gen =
            state.process_lists.get(agent_id).map(|p| p.refresh_generation).unwrap_or(0);
        if current_gen >= expected {
            panel.refresh_in_flight = false;
            panel.pending_refresh_generation = None;
            panel.refresh_started_at = None;
            panel.last_refreshed_display =
                Some(format!("Last refreshed: {}", chrono::Local::now().format("%H:%M:%S")));
            if let Some(secs) = panel.auto_refresh.interval_secs() {
                panel.next_auto_refresh_at = Some(Instant::now() + Duration::from_secs(secs));
            }
            return;
        }
        if let Some(started) = panel.refresh_started_at {
            if started.elapsed() > Duration::from_secs(90) {
                panel.refresh_in_flight = false;
                panel.pending_refresh_generation = None;
                panel.refresh_started_at = None;
            }
        }
    }

    /// Dispatches another process-list task when the auto-refresh deadline is reached.
    pub(crate) fn maybe_process_list_auto_refresh(&mut self, agent_id: &str, ctx: &egui::Context) {
        let (should_fire, wait_hint) = {
            let panel = match self.session_panel.process_state.get(agent_id) {
                Some(p) => p,
                None => return,
            };
            if panel.refresh_in_flight {
                return;
            }
            if panel.auto_refresh.interval_secs().is_none() {
                return;
            }
            let Some(deadline) = panel.next_auto_refresh_at else {
                return;
            };
            let now = Instant::now();
            if now < deadline {
                let wait = deadline.duration_since(now);
                (false, Some(wait.min(Duration::from_secs(1))))
            } else {
                (true, None)
            }
        };
        if let Some(w) = wait_hint {
            ctx.request_repaint_after(w);
        }
        if should_fire {
            self.queue_process_refresh(agent_id);
        }
    }

    /// Queues a process-list (`ps`) task for the agent and marks the panel as awaiting a response.
    pub(crate) fn queue_process_refresh(&mut self, agent_id: &str) {
        if self.session_panel.process_state.get(agent_id).is_some_and(|p| p.refresh_in_flight) {
            return;
        }
        let current_gen = self.current_process_list_generation(agent_id);
        let message = build_process_list_task(agent_id, &self.current_operator_username());
        let panel = self.session_panel.process_state_mut(agent_id);
        panel.refresh_in_flight = true;
        panel.pending_refresh_generation = Some(current_gen.saturating_add(1));
        panel.refresh_started_at = Some(Instant::now());
        panel.next_auto_refresh_at = None;
        panel.status_message = Some("Queued `ps`.".to_owned());
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
