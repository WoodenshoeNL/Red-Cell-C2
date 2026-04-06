use eframe::egui::{self, RichText};

use crate::transport::{AppState, EventKind};
use crate::{ClientApp, build_chat_message};

impl ClientApp {
    pub(crate) fn render_chat_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal(|ui| {
            ui.heading("Events & Chat");

            let unread = state.event_log.unread_count;
            if unread > 0 {
                ui.label(
                    RichText::new(format!("  {unread} unread"))
                        .color(egui::Color32::from_rgb(232, 182, 83))
                        .strong(),
                );
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Mark all read").clicked() {
                    self.session_panel.pending_mark_all_read = true;
                }
            });
        });
        ui.separator();

        // Filter buttons with per-kind unread counts.
        ui.horizontal(|ui| {
            let all_selected = self.session_panel.event_kind_filter.is_none();
            if ui.selectable_label(all_selected, "All").clicked() {
                self.session_panel.event_kind_filter = None;
            }
            for kind in [EventKind::Agent, EventKind::Operator, EventKind::System] {
                let selected = self.session_panel.event_kind_filter == Some(kind);
                let unread_for_kind = state.event_log.unread_by_kind(kind);
                let label = if unread_for_kind > 0 {
                    format!("{} ({})", kind.label(), unread_for_kind)
                } else {
                    kind.label().to_owned()
                };
                if ui.selectable_label(selected, label).clicked() {
                    self.session_panel.event_kind_filter = Some(kind);
                }
            }
        });
        ui.add_space(4.0);

        let online_users = if state.online_operators.is_empty() {
            "No presence data".to_owned()
        } else {
            state.online_operators.iter().cloned().collect::<Vec<_>>().join(", ")
        };
        ui.label(format!("Online: {online_users}"));
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let input = ui.add(
                egui::TextEdit::singleline(&mut self.session_panel.chat_input)
                    .desired_width(f32::INFINITY)
                    .hint_text("Send a message to all operators"),
            );
            let send_requested =
                input.lost_focus() && ui.input(|state| state.key_pressed(egui::Key::Enter));
            if ui.button("Send").clicked() || send_requested {
                if let Some(message) = build_chat_message(
                    state.operator_info.as_ref().map(|operator| operator.username.as_str()),
                    &self.session_panel.chat_input,
                ) {
                    self.session_panel.pending_messages.push(message);
                    self.session_panel.chat_input.clear();
                }
            }
        });
        ui.add_space(6.0);

        let active_filter = self.session_panel.event_kind_filter;
        let visible: Vec<_> = state
            .event_log
            .entries
            .iter()
            .filter(|e| active_filter.is_none_or(|k| e.kind == k))
            .collect();

        if visible.is_empty() {
            ui.label("No events yet.");
        } else {
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for entry in &visible {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            let kind_color = match entry.kind {
                                EventKind::Agent => egui::Color32::from_rgb(110, 199, 141),
                                EventKind::Operator => egui::Color32::from_rgb(100, 180, 240),
                                EventKind::System => egui::Color32::from_rgb(180, 180, 180),
                            };
                            ui.colored_label(kind_color, entry.kind.label());
                            ui.strong(&entry.author);
                            ui.label(RichText::new(&entry.sent_at).weak());
                            if !entry.read {
                                ui.label(
                                    RichText::new("●").color(egui::Color32::from_rgb(232, 182, 83)),
                                );
                            }
                        });
                        ui.label(&entry.message);
                    });
                }
            });
        }
    }
}
