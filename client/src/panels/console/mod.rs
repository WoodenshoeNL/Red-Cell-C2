mod browser;
mod input;
mod output;

use eframe::egui::{self, Color32, RichText, Stroke};

use crate::transport::AppState;
use crate::{ClientApp, agent_arch, agent_os, blank_if_empty};

impl ClientApp {
    #[allow(dead_code)]
    pub(crate) fn render_console_tabs(&mut self, ui: &mut egui::Ui) {
        let mut close_agent = None;

        ui.horizontal_wrapped(|ui| {
            for agent_id in self.session_panel.open_consoles.clone() {
                let selected = self.session_panel.selected_console.as_deref() == Some(&agent_id);
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        if ui.selectable_label(selected, &agent_id).clicked() {
                            self.session_panel.selected_console = Some(agent_id.clone());
                        }
                        if ui.small_button("x").clicked() {
                            close_agent = Some(agent_id.clone());
                        }
                    });
                });
            }
        });

        if let Some(agent_id) = close_agent {
            self.session_panel.close_console(&agent_id);
        }
    }

    pub(crate) fn render_single_console(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        agent_id: &str,
    ) {
        let agent = state.agents.iter().find(|agent| agent.name_id == agent_id);
        let entries = state.agent_consoles.get(agent_id).map(Vec::as_slice).unwrap_or(&[]);
        let browser = state.file_browsers.get(agent_id);
        let status_message = self
            .session_panel
            .console_state
            .get(agent_id)
            .and_then(|console| console.status_message.clone());

        egui::Frame::default()
            .fill(Color32::from_rgba_unmultiplied(255, 255, 255, 6))
            .stroke(Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 18)))
            .inner_margin(egui::Margin::symmetric(10, 10))
            .show(ui, |ui| {
                if let Some(agent) = agent {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(&agent.name_id).strong().monospace());
                        ui.separator();
                        ui.label(RichText::new(&agent.hostname).strong());
                        ui.separator();
                        ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                        ui.separator();
                        ui.label(format!("PID {}", agent.process_pid));
                        ui.separator();
                        ui.label(&agent.process_name);
                        ui.separator();
                        ui.label(format!("Status: {}", agent.status));
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "{} | {} | {}",
                            blank_if_empty(&agent.internal_ip, &agent.external_ip),
                            agent_os(agent),
                            agent_arch(agent)
                        ))
                        .weak(),
                    );
                    if !agent.note.trim().is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new(format!("Note: {}", agent.note)).weak());
                    }
                } else {
                    ui.label(
                        RichText::new(format!("Agent {agent_id} is no longer present")).weak(),
                    );
                }

                if let Some(message) = &status_message {
                    ui.add_space(6.0);
                    ui.colored_label(Color32::from_rgb(232, 182, 83), message);
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                ui.columns(2, |columns| {
                    self.render_file_browser_panel(&mut columns[0], agent_id, browser);
                    self.render_console_output_panel(&mut columns[1], agent_id, entries);
                });

                ui.add_space(8.0);
                self.render_console_input(ui, agent_id);

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                self.render_process_panel(ui, agent, agent_id, state);
            });
    }
}
