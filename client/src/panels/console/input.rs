use eframe::egui::{self, Key, RichText};

use crate::{
    ClientApp, HistoryDirection, apply_completion, apply_history_step, format_console_prompt,
};

impl ClientApp {
    pub(crate) fn render_console_input(&mut self, ui: &mut egui::Ui, agent_id: &str) {
        let mut run_command = false;

        let prompt = format_console_prompt(&self.current_operator_username(), agent_id);

        ui.horizontal(|ui| {
            ui.label(RichText::new(&prompt).strong().monospace());
            let response = {
                let console = self.session_panel.console_state_mut(agent_id);
                ui.add(
                    egui::TextEdit::singleline(&mut console.input)
                        .id_source(("console-input", agent_id))
                        .desired_width(f32::INFINITY)
                        .hint_text("Enter a Demon command (type 'help' for available commands)"),
                )
            };

            let send_requested =
                response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
            let tab_pressed = response.has_focus() && ui.input(|input| input.key_pressed(Key::Tab));
            let up_pressed =
                response.has_focus() && ui.input(|input| input.key_pressed(Key::ArrowUp));
            let down_pressed =
                response.has_focus() && ui.input(|input| input.key_pressed(Key::ArrowDown));

            if up_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_history_step(console, HistoryDirection::Older);
                response.request_focus();
            } else if down_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_history_step(console, HistoryDirection::Newer);
                response.request_focus();
            } else if tab_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_completion(console);
                response.request_focus();
            }

            if response.changed() {
                let console = self.session_panel.console_state_mut(agent_id);
                console.completion_index = 0;
                console.completion_seed = None;
            }

            run_command = ui.button("Run").clicked() || send_requested;
        });

        if run_command {
            self.submit_console_command(agent_id);
        }
    }
}
