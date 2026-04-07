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
            .filter(|e| event_matches_kind_filter(active_filter, e.kind))
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

/// Returns whether an event log entry should be shown for the current session filter
/// (`None` means all kinds are visible).
pub(crate) fn event_matches_kind_filter(filter: Option<EventKind>, entry_kind: EventKind) -> bool {
    filter.is_none_or(|k| entry_kind == k)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentSortColumn;

    fn minimal_agent(name_id: &str) -> transport::AgentSummary {
        transport::AgentSummary {
            name_id: name_id.to_owned(),
            status: String::new(),
            domain_name: String::new(),
            username: String::new(),
            internal_ip: String::new(),
            external_ip: String::new(),
            hostname: String::new(),
            process_arch: String::new(),
            process_name: String::new(),
            process_pid: String::new(),
            elevated: false,
            os_version: String::new(),
            os_build: String::new(),
            os_arch: String::new(),
            sleep_delay: String::new(),
            sleep_jitter: String::new(),
            last_call_in: String::new(),
            note: String::new(),
            pivot_parent: None,
            pivot_links: Vec::new(),
        }
    }

    #[test]
    fn event_matches_kind_filter_shows_all_when_none() {
        assert!(event_matches_kind_filter(None, EventKind::Agent));
        assert!(event_matches_kind_filter(None, EventKind::Operator));
        assert!(event_matches_kind_filter(None, EventKind::System));
    }

    #[test]
    fn event_matches_kind_filter_partitions_by_kind() {
        assert!(event_matches_kind_filter(Some(EventKind::Agent), EventKind::Agent));
        assert!(!event_matches_kind_filter(Some(EventKind::Agent), EventKind::System));
        assert!(event_matches_kind_filter(Some(EventKind::Operator), EventKind::Operator));
        assert!(!event_matches_kind_filter(Some(EventKind::Operator), EventKind::Agent));
    }

    #[test]
    fn sort_button_label_marks_all_twelve_columns_when_active() {
        for (column, label) in AgentSortColumn::ALL {
            let asc = sort_button_label(Some(column), false, column);
            assert!(
                asc.starts_with(label) && asc.contains('^'),
                "unexpected asc label for {column:?}: {asc}"
            );
            let desc = sort_button_label(Some(column), true, column);
            assert!(
                desc.starts_with(label) && desc.contains('v'),
                "unexpected desc label for {column:?}: {desc}"
            );
        }
    }

    #[test]
    fn sort_orders_by_id() {
        let mut hi = minimal_agent("zzz");
        let mut lo = minimal_agent("aaa");
        hi.hostname = "z".to_owned();
        lo.hostname = "a".to_owned();
        let mut agents = vec![hi, lo];
        sort_agents(&mut agents, AgentSortColumn::Id, false);
        assert_eq!(agents[0].name_id, "aaa");
        assert_eq!(agents[1].name_id, "zzz");
        sort_agents(&mut agents, AgentSortColumn::Id, true);
        assert_eq!(agents[0].name_id, "zzz");
    }

    #[test]
    fn sort_orders_by_hostname() {
        let mut a = minimal_agent("x");
        a.hostname = "host-b".to_owned();
        let mut b = minimal_agent("y");
        b.hostname = "host-a".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Hostname, false);
        assert_eq!(agents[0].hostname, "host-a");
        sort_agents(&mut agents, AgentSortColumn::Hostname, true);
        assert_eq!(agents[0].hostname, "host-b");
    }

    #[test]
    fn sort_orders_by_username() {
        let mut a = minimal_agent("x");
        a.username = "zebra".to_owned();
        let mut b = minimal_agent("y");
        b.username = "alice".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Username, false);
        assert_eq!(agents[0].username, "alice");
    }

    #[test]
    fn sort_orders_by_domain() {
        let mut a = minimal_agent("x");
        a.domain_name = "z.dom".to_owned();
        let mut b = minimal_agent("y");
        b.domain_name = "a.dom".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Domain, false);
        assert_eq!(agents[0].domain_name, "a.dom");
    }

    #[test]
    fn sort_orders_by_ip_using_agent_ip() {
        let mut a = minimal_agent("x");
        a.internal_ip = "10.0.0.2".to_owned();
        let mut b = minimal_agent("y");
        b.internal_ip = String::new();
        b.external_ip = "10.0.0.9".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Ip, false);
        assert_eq!(agent_ip(&agents[0]), "10.0.0.2");
        assert_eq!(agent_ip(&agents[1]), "10.0.0.9");
    }

    #[test]
    fn sort_orders_by_pid_lexicographically() {
        let mut a = minimal_agent("x");
        a.process_pid = "20".to_owned();
        let mut b = minimal_agent("y");
        b.process_pid = "3".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Pid, false);
        assert_eq!(agents[0].process_pid, "20");
        assert_eq!(agents[1].process_pid, "3");
    }

    #[test]
    fn sort_orders_by_process_name() {
        let mut a = minimal_agent("x");
        a.process_name = "zebra.exe".to_owned();
        let mut b = minimal_agent("y");
        b.process_name = "agent.exe".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Process, false);
        assert_eq!(agents[0].process_name, "agent.exe");
    }

    #[test]
    fn sort_orders_by_arch_prefers_process_arch_then_os_arch() {
        let mut a = minimal_agent("x");
        a.process_arch = "x86".to_owned();
        a.os_arch = "amd64".to_owned();
        let mut b = minimal_agent("y");
        b.process_arch = String::new();
        b.os_arch = "arm64".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Arch, false);
        assert_eq!(agent_arch(&agents[0]), "arm64");
        assert_eq!(agent_arch(&agents[1]), "x86");
    }

    #[test]
    fn sort_orders_by_elevated() {
        let mut a = minimal_agent("x");
        a.elevated = true;
        let mut b = minimal_agent("y");
        b.elevated = false;
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Elevated, false);
        assert!(!agents[0].elevated);
        sort_agents(&mut agents, AgentSortColumn::Elevated, true);
        assert!(agents[0].elevated);
    }

    #[test]
    fn sort_orders_by_os_version_and_build() {
        let mut a = minimal_agent("x");
        a.os_version = "10".to_owned();
        a.os_build = "2000".to_owned();
        let mut b = minimal_agent("y");
        b.os_version = "10".to_owned();
        b.os_build = String::new();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Os, false);
        assert_eq!(agent_os(&agents[0]), "10");
        assert_eq!(agent_os(&agents[1]), "10 (2000)");
    }

    #[test]
    fn sort_orders_by_sleep_jitter_string() {
        let mut a = minimal_agent("x");
        a.sleep_delay = "5".to_owned();
        a.sleep_jitter = "10".to_owned();
        let mut b = minimal_agent("y");
        b.sleep_delay = "1".to_owned();
        b.sleep_jitter = String::new();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::SleepJitter, false);
        assert_eq!(agent_sleep_jitter(&agents[0]), "1");
        assert_eq!(agent_sleep_jitter(&agents[1]), "5s / 10%");
    }

    #[test]
    fn sort_orders_by_last_checkin() {
        let mut a = minimal_agent("x");
        a.last_call_in = "2026-04-07T12:00:00".to_owned();
        let mut b = minimal_agent("y");
        b.last_call_in = "2026-04-06T12:00:00".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::LastCheckin, false);
        assert_eq!(agents[0].last_call_in, "2026-04-06T12:00:00");
    }

    #[test]
    fn sort_tie_breaks_using_name_id() {
        let mut a = minimal_agent("bbb");
        a.hostname = "same".to_owned();
        let mut b = minimal_agent("aaa");
        b.hostname = "same".to_owned();
        let mut agents = vec![a, b];
        sort_agents(&mut agents, AgentSortColumn::Hostname, false);
        assert_eq!(agents[0].name_id, "aaa");
        assert_eq!(agents[1].name_id, "bbb");
    }
}
