use eframe::egui::{self, Align, Color32, Layout, RichText, Sense};

use crate::transport::{self, AppState, EventKind};
use crate::{AgentSortColumn, ClientApp, NoteEditorState, SessionAction, build_kill_task};

impl ClientApp {
    pub(crate) fn render_top_zone(&mut self, ui: &mut egui::Ui, state: &AppState) {
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
    pub(crate) fn render_session_table_zone(&mut self, ui: &mut egui::Ui, state: &AppState) {
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
    pub(crate) fn render_event_viewer(&mut self, ui: &mut egui::Ui, state: &AppState) {
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

    pub(crate) fn render_session_table_header(&mut self, ui: &mut egui::Ui) {
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

    pub(crate) fn render_session_row_cell(
        &self,
        ui: &mut egui::Ui,
        width: f32,
        value: &str,
        monospace: bool,
    ) {
        let text = ellipsize(value, 24);
        if monospace {
            ui.add_sized([width, 20.0], egui::Label::new(RichText::new(text).monospace()));
        } else {
            ui.add_sized([width, 20.0], egui::Label::new(text));
        }
    }

    pub(crate) fn filtered_and_sorted_agents(
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

    pub(crate) fn handle_session_action(&mut self, action: SessionAction, operator: Option<&str>) {
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
}

// ─── Agent helpers ────────────────────────────────────────────────────────────

pub(crate) fn agent_ip(agent: &transport::AgentSummary) -> String {
    if agent.internal_ip.trim().is_empty() {
        agent.external_ip.clone()
    } else {
        agent.internal_ip.clone()
    }
}

pub(crate) fn agent_arch(agent: &transport::AgentSummary) -> String {
    if agent.process_arch.trim().is_empty() {
        agent.os_arch.clone()
    } else {
        agent.process_arch.clone()
    }
}

pub(crate) fn agent_os(agent: &transport::AgentSummary) -> String {
    if agent.os_build.trim().is_empty() {
        agent.os_version.clone()
    } else {
        format!("{} ({})", agent.os_version, agent.os_build)
    }
}

pub(crate) fn agent_sleep_jitter(agent: &transport::AgentSummary) -> String {
    match (agent.sleep_delay.trim(), agent.sleep_jitter.trim()) {
        ("", "") => String::new(),
        (delay, "") => delay.to_owned(),
        ("", jitter) => format!("j{jitter}%"),
        (delay, jitter) => format!("{delay}s / {jitter}%"),
    }
}

pub(crate) fn agent_matches_filter(agent: &transport::AgentSummary, filter: &str) -> bool {
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

pub(crate) fn sort_agents(
    agents: &mut [transport::AgentSummary],
    column: AgentSortColumn,
    descending: bool,
) {
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

pub(crate) fn sort_button_label(
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

pub(crate) fn ellipsize(value: &str, max_chars: usize) -> String {
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
