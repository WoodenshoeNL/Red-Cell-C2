//! Agent note editor modal dialog for `ClientApp`.

use eframe::egui;

use crate::ClientApp;
use crate::tasks::build_note_task;
use crate::transport::SharedAppState;

impl ClientApp {
    pub(crate) fn render_note_editor(&mut self, ctx: &egui::Context, app_state: &SharedAppState) {
        let Some(editor) = &mut self.session_panel.note_editor else {
            return;
        };

        let mut keep_open = true;
        let mut save_note = false;
        let mut cancel_note = false;
        let title = format!("Agent Note {}", editor.agent_id);
        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_size([420.0, 220.0])
            .open(&mut keep_open)
            .show(ctx, |ui| {
                ui.label("Operator note");
                ui.add(
                    egui::TextEdit::multiline(&mut editor.note)
                        .desired_rows(8)
                        .hint_text("Add operator context for this agent"),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save_note = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel_note = true;
                    }
                });
            });

        if save_note {
            let agent_id = editor.agent_id.clone();
            let note = editor.note.trim().to_owned();
            let operator = match app_state.lock() {
                Ok(mut state) => {
                    state.update_agent_note(&agent_id, note.clone());
                    state
                        .operator_info
                        .as_ref()
                        .map(|operator| operator.username.clone())
                        .unwrap_or_default()
                }
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    state.update_agent_note(&agent_id, note.clone());
                    state
                        .operator_info
                        .as_ref()
                        .map(|operator| operator.username.clone())
                        .unwrap_or_default()
                }
            };
            self.session_panel.pending_messages.push(build_note_task(&agent_id, &note, &operator));
            self.session_panel.status_message = Some(format!("Updated note for {agent_id}."));
            self.session_panel.note_editor = None;
            ctx.request_repaint();
        } else if cancel_note || !keep_open {
            self.session_panel.note_editor = None;
        }
    }
}
