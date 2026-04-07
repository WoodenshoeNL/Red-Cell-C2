use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use rfd::FileDialog;

use crate::transport::{AppState, ProcessEntry};
use crate::{
    ClientApp, InjectionTargetAction, InjectionTechnique, ProcessInjectionDialogState,
    ProcessListAutoRefresh, blank_if_empty, filtered_process_rows,
};

impl ClientApp {
    /// Search, refresh, last-refreshed time, and optional auto-refresh interval.
    pub(crate) fn render_process_list_toolbar(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        state: &AppState,
        filter_width: f32,
        filter_hint: &'static str,
    ) {
        self.sync_process_refresh_completion(agent_id, state);
        self.maybe_process_list_auto_refresh(agent_id, ui.ctx());

        let current_pid = state
            .agents
            .iter()
            .find(|a| a.name_id == agent_id)
            .and_then(|entry| entry.process_pid.trim().parse::<u32>().ok());

        let in_flight =
            self.session_panel.process_state.get(agent_id).is_some_and(|p| p.refresh_in_flight);
        let prev_auto = self
            .session_panel
            .process_state
            .get(agent_id)
            .map(|p| p.auto_refresh)
            .unwrap_or(ProcessListAutoRefresh::Off);
        let last_refreshed = self
            .session_panel
            .process_state
            .get(agent_id)
            .and_then(|p| p.last_refreshed_display.clone());

        let mut next_auto = prev_auto;
        let mut queue_refresh = false;

        ui.horizontal_wrapped(|ui| {
            ui.label("Filter");
            let filter = &mut self.session_panel.process_state_mut(agent_id).filter;
            ui.add(
                egui::TextEdit::singleline(filter)
                    .desired_width(filter_width)
                    .hint_text(filter_hint),
            );

            if in_flight {
                ui.add(egui::Spinner::new());
            }

            let refresh = ui.add_enabled(!in_flight, egui::Button::new("Refresh"));
            if refresh.clicked() {
                queue_refresh = true;
            }

            if let Some(ref last) = last_refreshed {
                ui.separator();
                ui.label(RichText::new(last).weak());
            }

            ui.separator();
            egui::ComboBox::from_id_salt(("process-auto-refresh", agent_id))
                .selected_text(format!("Auto: {}", prev_auto.label()))
                .show_ui(ui, |ui| {
                    for option in [
                        ProcessListAutoRefresh::Off,
                        ProcessListAutoRefresh::Secs10,
                        ProcessListAutoRefresh::Secs30,
                        ProcessListAutoRefresh::Secs60,
                    ] {
                        ui.selectable_value(
                            &mut next_auto,
                            option,
                            format!("Auto: {}", option.label()),
                        );
                    }
                });

            if let Some(pid) = current_pid {
                ui.separator();
                ui.label(RichText::new(format!("Agent PID {pid}")).weak());
            }
        });

        if queue_refresh {
            self.queue_process_refresh(agent_id);
        }

        if next_auto != prev_auto {
            let panel = self.session_panel.process_state_mut(agent_id);
            panel.auto_refresh = next_auto;
            if let Some(secs) = next_auto.interval_secs() {
                panel.next_auto_refresh_at =
                    Some(std::time::Instant::now() + Duration::from_secs(secs));
            } else {
                panel.next_auto_refresh_at = None;
            }
        }
    }

    pub(crate) fn render_process_panel(
        &mut self,
        ui: &mut egui::Ui,
        agent: Option<&crate::transport::AgentSummary>,
        agent_id: &str,
        state: &AppState,
    ) {
        let process_list = state.process_lists.get(agent_id);
        ui.heading("Process List");
        ui.separator();

        let current_pid = agent.and_then(|entry| entry.process_pid.trim().parse::<u32>().ok());
        let process_status = self
            .session_panel
            .process_state
            .get(agent_id)
            .and_then(|state| state.status_message.clone())
            .or_else(|| process_list.and_then(|state| state.status_message.clone()));

        self.render_process_list_toolbar(ui, agent_id, state, 180.0, "Search name or PID");

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
    pub(crate) fn render_process_list_tab(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        agent_id: &str,
    ) {
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

            // ── Toolbar: search + refresh + last refreshed + auto ─
            let process_status = self
                .session_panel
                .process_state
                .get(agent_id)
                .and_then(|s| s.status_message.clone())
                .or_else(|| process_list.and_then(|s| s.status_message.clone()));

            self.render_process_list_toolbar(
                ui,
                agent_id,
                state,
                220.0,
                "Search name, PID, or user",
            );

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
                                RichText::new(format!("{} (PID {})", row.name, row.pid)).strong(),
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

    pub(crate) fn open_process_injection_dialog(
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

    pub(crate) fn render_process_injection_dialog(&mut self, ctx: &egui::Context) {
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
}
