//! Menu bar, status bar, session-expiry banner, and known-servers window for `ClientApp`.

use eframe::egui::{self, Align, Align2, Color32, Layout, RichText};

use crate::known_servers::KnownServer;
use crate::state::{DockTab, PayloadDialogState};
use crate::transport::AppState;
use crate::{ClientApp, SESSION_TTL, SESSION_WARN_BEFORE};

impl ClientApp {
    /// Non-blocking warning banner shown 5 minutes before the session expires.
    pub(crate) fn render_session_expiry_banner(&self, ctx: &egui::Context, state: &AppState) {
        let Some(start) = state.session_start else {
            return;
        };
        let elapsed = start.elapsed();
        if elapsed < SESSION_TTL.saturating_sub(SESSION_WARN_BEFORE) {
            return;
        }
        if elapsed >= SESSION_TTL {
            return;
        }
        let remaining = SESSION_TTL - elapsed;
        let mins = remaining.as_secs() / 60;
        let secs = remaining.as_secs() % 60;

        egui::Window::new("session_expiry_banner")
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .anchor(Align2::CENTER_TOP, [0.0, 30.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        Color32::from_rgb(255, 165, 0),
                        format!(
                            "Session expires in {mins}:{secs:02} — save your work and re-authenticate."
                        ),
                    );
                });
            });
    }

    /// Havoc-style menu bar: Havoc, View, Attack, Scripts, Help.
    pub(crate) fn render_menu_bar(&mut self, ui: &mut egui::Ui, state: &AppState) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("Red Cell", |ui| {
                ui.label(format!(
                    "Operator: {}",
                    state.operator_info.as_ref().map_or("—", |op| op.username.as_str())
                ));
                ui.label(format!("Server: {}", state.server_url));
                ui.separator();
                let status_color = state.connection_status.color();
                ui.colored_label(status_color, state.connection_status.label());
                ui.separator();
                if ui.button("Disconnect").clicked() {
                    ui.close();
                }
                ui.separator();
                if ui.button("Known Servers…").clicked() {
                    self.show_known_servers = true;
                    ui.close();
                }
            });

            ui.menu_button("View", |ui| {
                if ui.button("Event Viewer").clicked() {
                    self.session_panel.dock.event_viewer_open =
                        !self.session_panel.dock.event_viewer_open;
                    ui.close();
                }
                ui.separator();
                if ui.button("Teamserver Chat").clicked() {
                    self.session_panel.dock.open_tab(DockTab::TeamserverChat);
                    ui.close();
                }
                if ui.button("Listeners").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Listeners);
                    ui.close();
                }
                if ui.button("Session Graph").clicked() {
                    self.session_panel.dock.open_tab(DockTab::SessionGraph);
                    ui.close();
                }
                if ui.button("Loot").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Loot);
                    ui.close();
                }
                if ui.button("Operators").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Operators);
                    ui.close();
                }
                if ui.button("Audit Log").clicked() {
                    self.session_panel.dock.open_tab(DockTab::AuditLog);
                    ui.close();
                }
            });

            ui.menu_button("Attack", |ui| {
                if ui.button("Payload").clicked() {
                    if self.session_panel.payload_dialog.is_none() {
                        self.session_panel.payload_dialog = Some(PayloadDialogState::new());
                    }
                    ui.close();
                }
            });

            ui.menu_button("Scripts", |ui| {
                if ui.button("Script Manager").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Scripts);
                    ui.close();
                }
            });

            ui.menu_button("Help", |ui| {
                ui.label("Red Cell C2 — Havoc rewrite in Rust");
                ui.label("https://github.com/…");
            });
        });
    }

    /// Bottom status bar showing operator name and remaining session time.
    pub(crate) fn render_status_bar(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal_centered(|ui| {
            let operator = state.operator_info.as_ref().map_or("—", |op| op.username.as_str());
            ui.label(RichText::new(operator).monospace().small());

            if let Some(start) = state.session_start {
                let elapsed = start.elapsed();
                if elapsed < SESSION_TTL {
                    let remaining = SESSION_TTL - elapsed;
                    let mins = remaining.as_secs() / 60;
                    let secs = remaining.as_secs() % 60;
                    let (label_text, color) = if remaining <= SESSION_WARN_BEFORE {
                        (
                            format!("  session expires in {mins}:{secs:02}"),
                            Color32::from_rgb(255, 165, 0), // orange
                        )
                    } else {
                        (format!("  session {mins}:{secs:02}"), Color32::from_rgb(120, 120, 120))
                    };
                    ui.label(RichText::new(label_text).monospace().small().color(color));
                }
            }
        });
    }

    /// Render the Known Servers verification window.
    ///
    /// Shows every pinned teamserver fingerprint with its trust timestamps and lets
    /// the operator mark entries as explicitly verified or remove them entirely.
    pub(crate) fn render_known_servers_window(&mut self, ctx: &egui::Context) {
        if !self.show_known_servers {
            return;
        }

        // Collect rows so we can mutate `known_servers` after the UI loop.
        let entries: Vec<(String, KnownServer)> =
            self.known_servers.iter().map(|(k, v)| (k.to_owned(), v.clone())).collect();

        let mut confirm_key: Option<String> = None;
        let mut remove_key: Option<String> = None;
        let mut open = true;

        egui::Window::new("Known Servers")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(720.0)
            .default_height(340.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(
                    "Review pinned teamserver certificate fingerprints. \
                     Verify each fingerprint over a trusted out-of-band channel \
                     before marking it as confirmed.",
                );
                ui.add_space(8.0);

                if entries.is_empty() {
                    ui.colored_label(
                        Color32::from_rgb(160, 160, 170),
                        "No servers are pinned yet. Connect to a teamserver to add one.",
                    );
                    return;
                }

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (host_port, entry) in &entries {
                        ui.group(|ui| {
                            ui.set_min_width(ui.available_width());

                            ui.horizontal(|ui| {
                                ui.label(RichText::new(host_port).strong().monospace());
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui
                                        .button(
                                            RichText::new("Remove")
                                                .color(Color32::from_rgb(215, 83, 83)),
                                        )
                                        .on_hover_text("Remove this server from the trusted list")
                                        .clicked()
                                    {
                                        remove_key = Some(host_port.clone());
                                    }
                                    let confirmed = entry.confirmed_at.is_some();
                                    if ui
                                        .add_enabled(
                                            !confirmed,
                                            egui::Button::new(if confirmed {
                                                "✓ Verified"
                                            } else {
                                                "Mark as verified"
                                            }),
                                        )
                                        .on_hover_text(if confirmed {
                                            "Fingerprint was explicitly confirmed by an operator"
                                        } else {
                                            "Record that you have verified this fingerprint \
                                             over a trusted out-of-band channel"
                                        })
                                        .clicked()
                                    {
                                        confirm_key = Some(host_port.clone());
                                    }
                                });
                            });

                            ui.add_space(4.0);
                            ui.label(RichText::new("Fingerprint:").small());
                            ui.add(
                                egui::TextEdit::singleline(&mut entry.fingerprint.clone())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .interactive(true),
                            );

                            ui.add_space(2.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("First trusted: {}", entry.first_seen))
                                        .small()
                                        .color(Color32::from_rgb(140, 140, 150)),
                                );
                                if let Some(confirmed_at) = &entry.confirmed_at {
                                    ui.separator();
                                    ui.label(
                                        RichText::new(format!("Confirmed: {confirmed_at}"))
                                            .small()
                                            .color(Color32::from_rgb(100, 200, 120)),
                                    );
                                }
                            });

                            if let Some(comment) = &entry.comment {
                                ui.label(
                                    RichText::new(comment)
                                        .small()
                                        .italics()
                                        .color(Color32::from_rgb(160, 160, 170)),
                                );
                            }
                        });
                        ui.add_space(4.0);
                    }
                });
            });

        if !open {
            self.show_known_servers = false;
        }
        if let Some(key) = confirm_key {
            if self.known_servers.confirm(&key) {
                let _ = self.known_servers.save();
            }
        }
        if let Some(key) = remove_key {
            self.known_servers.remove(&key);
            let _ = self.known_servers.save();
        }
    }
}
