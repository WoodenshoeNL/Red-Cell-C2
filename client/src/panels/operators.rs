//! Operator management panel — lists operators, shows online/role/last-seen, and
//! provides Create/Delete actions via the `OperatorManagement` WebSocket extension.

use eframe::egui::{self, Color32, RichText};

use red_cell_common::operator::{
    CreateOperatorInfo, EventCode, Message, MessageHead, OperatorMessage, RemoveOperatorInfo,
};

use crate::ClientApp;
use crate::transport::{AppState, ConnectedOperatorState};

// Role options shown in the Create dialog.
const ROLES: [&str; 3] = ["Admin", "Operator", "Analyst"];

// ── Column widths ─────────────────────────────────────────────────────────────

const COL_USER: f32 = 140.0;
const COL_ROLE: f32 = 90.0;
const COL_STATUS: f32 = 70.0;
const COL_LAST_SEEN: f32 = 160.0;
const COL_ACTIONS: f32 = 80.0;

impl ClientApp {
    /// Render the operator management dock tab.
    pub(crate) fn render_operators_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        let panel = &mut self.session_panel.operators_panel;

        // ── Toolbar ──────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Operators").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("+ Create").clicked() {
                    panel.create_dialog_open = true;
                    panel.create_username.clear();
                    panel.create_password.clear();
                    panel.create_role_index = 1; // default Operator
                    panel.status_message = None;
                }
            });
        });

        ui.add_space(4.0);

        if let Some(msg) = &panel.status_message.clone() {
            let color = if msg.starts_with("Error") {
                Color32::from_rgb(230, 80, 80)
            } else {
                Color32::from_rgb(110, 199, 141)
            };
            ui.label(RichText::new(msg).color(color).small());
            ui.add_space(2.0);
        }

        // ── Table header ─────────────────────────────────────────────
        ui.horizontal(|ui| {
            for (label, width) in [
                ("Username", COL_USER),
                ("Role", COL_ROLE),
                ("Status", COL_STATUS),
                ("Last Seen", COL_LAST_SEEN),
                ("", COL_ACTIONS),
            ] {
                ui.add_sized(
                    [width, 18.0],
                    egui::Label::new(
                        RichText::new(label).strong().color(Color32::from_rgb(180, 180, 200)),
                    ),
                );
            }
        });
        ui.separator();

        // ── Table body ───────────────────────────────────────────────
        let operators: Vec<(String, ConnectedOperatorState)> =
            state.connected_operators.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        if operators.is_empty() {
            egui::ScrollArea::vertical().id_salt("operators_scroll").show(ui, |ui| {
                ui.label(RichText::new("No operators recorded yet.").weak());
            });
        } else {
            egui::ScrollArea::vertical().id_salt("operators_scroll").show(ui, |ui| {
                let mut pending_delete: Option<String> = None;
                for (username, op_state) in &operators {
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [COL_USER, 16.0],
                            egui::Label::new(RichText::new(username).monospace()),
                        );
                        let role_text = op_state.role.as_deref().unwrap_or("—");
                        ui.add_sized([COL_ROLE, 16.0], egui::Label::new(RichText::new(role_text)));
                        let (status_label, status_color) = if op_state.online {
                            ("Online", Color32::from_rgb(110, 199, 141))
                        } else {
                            ("Offline", Color32::from_rgb(160, 160, 170))
                        };
                        ui.add_sized(
                            [COL_STATUS, 16.0],
                            egui::Label::new(RichText::new(status_label).color(status_color)),
                        );
                        let last_seen = op_state.last_seen.as_deref().unwrap_or("—");
                        ui.add_sized(
                            [COL_LAST_SEEN, 16.0],
                            egui::Label::new(RichText::new(last_seen).small()),
                        );
                        if ui
                            .add_sized(
                                [COL_ACTIONS, 16.0],
                                egui::Button::new(
                                    RichText::new("Delete").color(Color32::from_rgb(220, 80, 80)),
                                ),
                            )
                            .clicked()
                        {
                            pending_delete = Some(username.clone());
                        }
                    });
                }
                if let Some(name) = pending_delete {
                    self.session_panel.operators_panel.delete_pending = Some(name);
                }
            });
        }

        // ── Delete confirmation modal ─────────────────────────────────
        let delete_target = self.session_panel.operators_panel.delete_pending.clone();
        if let Some(target) = delete_target {
            let mut open = true;
            egui::Window::new("Confirm Delete")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ui.ctx(), |ui| {
                    ui.label(format!("Delete operator \"{target}\"?"));
                    ui.label(
                        RichText::new("This cannot be undone.")
                            .color(Color32::from_rgb(220, 80, 80)),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Delete").clicked() {
                            if let Some(msg) = build_operator_remove(&target, state) {
                                self.session_panel.pending_messages.push(msg);
                                self.session_panel.operators_panel.status_message =
                                    Some(format!("Delete request sent for \"{target}\"."));
                            }
                            self.session_panel.operators_panel.delete_pending = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.session_panel.operators_panel.delete_pending = None;
                        }
                    });
                });
            if !open {
                self.session_panel.operators_panel.delete_pending = None;
            }
        }

        // ── Create operator dialog ────────────────────────────────────
        let mut create_open = self.session_panel.operators_panel.create_dialog_open;
        if create_open {
            egui::Window::new("Create Operator")
                .collapsible(false)
                .resizable(false)
                .open(&mut create_open)
                .show(ui.ctx(), |ui| {
                    let panel = &mut self.session_panel.operators_panel;
                    egui::Grid::new("create_op_grid").num_columns(2).spacing([8.0, 4.0]).show(
                        ui,
                        |ui| {
                            ui.label("Username:");
                            ui.text_edit_singleline(&mut panel.create_username);
                            ui.end_row();
                            ui.label("Password:");
                            ui.add(
                                egui::TextEdit::singleline(&mut panel.create_password)
                                    .password(true),
                            );
                            ui.end_row();
                            ui.label("Role:");
                            egui::ComboBox::from_id_salt("create_op_role")
                                .selected_text(ROLES[panel.create_role_index])
                                .show_ui(ui, |ui| {
                                    for (i, role) in ROLES.iter().enumerate() {
                                        ui.selectable_value(&mut panel.create_role_index, i, *role);
                                    }
                                });
                            ui.end_row();
                        },
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let can_submit = !panel.create_username.trim().is_empty()
                            && !panel.create_password.is_empty();
                        if ui.add_enabled(can_submit, egui::Button::new("Create")).clicked() {
                            let username = panel.create_username.trim().to_owned();
                            let password = panel.create_password.clone();
                            let role = ROLES[panel.create_role_index].to_owned();
                            if let Some(msg) =
                                build_operator_create(&username, &password, &role, state)
                            {
                                self.session_panel.pending_messages.push(msg);
                                panel.status_message =
                                    Some(format!("Create request sent for \"{username}\"."));
                            }
                            panel.create_dialog_open = false;
                        }
                        if ui.button("Cancel").clicked() {
                            panel.create_dialog_open = false;
                        }
                    });
                });
            self.session_panel.operators_panel.create_dialog_open = create_open;
        }
    }
}

// ── Message builders ──────────────────────────────────────────────────────────

fn build_operator_create(
    username: &str,
    password: &str,
    role: &str,
    state: &AppState,
) -> Option<OperatorMessage> {
    let operator = state.operator_info.as_ref()?.username.clone();
    Some(OperatorMessage::OperatorCreate(Message {
        head: MessageHead {
            event: EventCode::OperatorManagement,
            user: operator,
            timestamp: chrono_now(),
            one_time: String::new(),
        },
        info: CreateOperatorInfo {
            username: username.to_owned(),
            password: password.to_owned(),
            role: Some(role.to_owned()),
        },
    }))
}

fn build_operator_remove(username: &str, state: &AppState) -> Option<OperatorMessage> {
    let operator = state.operator_info.as_ref()?.username.clone();
    Some(OperatorMessage::OperatorRemove(Message {
        head: MessageHead {
            event: EventCode::OperatorManagement,
            user: operator,
            timestamp: chrono_now(),
            one_time: String::new(),
        },
        info: RemoveOperatorInfo { username: username.to_owned() },
    }))
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (h, m, s) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    // Simple timestamp string matching Havoc wire format "MM/DD/YYYY HH:MM:SS"
    format!("01/01/1970 {:02}:{:02}:{:02}", h, m, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::session::OperatorPanelState;
    use crate::transport::AppState;
    use red_cell_common::OperatorInfo;

    fn state_with_operator(username: &str) -> AppState {
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        state.operator_info = Some(OperatorInfo {
            username: username.to_owned(),
            password_hash: None,
            role: None,
            online: true,
            last_seen: None,
        });
        state
    }

    #[test]
    fn build_operator_create_produces_correct_variant() {
        let state = state_with_operator("admin");
        let msg =
            build_operator_create("alice", "pw", "Operator", &state).expect("should build message");
        match msg {
            OperatorMessage::OperatorCreate(m) => {
                assert_eq!(m.info.username, "alice");
                assert_eq!(m.info.password, "pw");
                assert_eq!(m.info.role.as_deref(), Some("Operator"));
                assert_eq!(m.head.user, "admin");
            }
            other => panic!("expected OperatorCreate, got {other:?}"),
        }
    }

    #[test]
    fn build_operator_create_returns_none_when_not_logged_in() {
        let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let msg = build_operator_create("alice", "pw", "Operator", &state);
        assert!(msg.is_none());
    }

    #[test]
    fn build_operator_remove_produces_correct_variant() {
        let state = state_with_operator("admin");
        let msg = build_operator_remove("bob", &state).expect("should build message");
        match msg {
            OperatorMessage::OperatorRemove(m) => {
                assert_eq!(m.info.username, "bob");
                assert_eq!(m.head.user, "admin");
            }
            other => panic!("expected OperatorRemove, got {other:?}"),
        }
    }

    #[test]
    fn build_operator_remove_returns_none_when_not_logged_in() {
        let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let msg = build_operator_remove("bob", &state);
        assert!(msg.is_none());
    }

    #[test]
    fn operator_create_message_serializes_and_deserializes() {
        let state = state_with_operator("admin");
        let msg = build_operator_create("alice", "s3cr3t", "Admin", &state).unwrap();
        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: OperatorMessage = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            OperatorMessage::OperatorCreate(m) => {
                assert_eq!(m.info.username, "alice");
                assert_eq!(m.info.password, "s3cr3t");
                assert_eq!(m.info.role.as_deref(), Some("Admin"));
            }
            other => panic!("expected OperatorCreate, got {other:?}"),
        }
    }

    #[test]
    fn operator_remove_message_serializes_and_deserializes() {
        let state = state_with_operator("admin");
        let msg = build_operator_remove("charlie", &state).unwrap();
        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: OperatorMessage = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            OperatorMessage::OperatorRemove(m) => {
                assert_eq!(m.info.username, "charlie");
            }
            other => panic!("expected OperatorRemove, got {other:?}"),
        }
    }

    #[test]
    fn operator_panel_state_defaults_to_closed() {
        let state = OperatorPanelState::default();
        assert!(!state.create_dialog_open);
        assert!(state.create_username.is_empty());
        assert!(state.create_password.is_empty());
        assert_eq!(state.create_role_index, 0);
        assert!(state.delete_pending.is_none());
        assert!(state.status_message.is_none());
    }
}
