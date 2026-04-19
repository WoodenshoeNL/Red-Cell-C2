use eframe::egui::{self, Align2, Color32, RichText, Sense};
use rfd::FileDialog;
use std::sync::Arc;

use crate::transport::{AppState, BuildConsoleEntry, PayloadBuildResult, SharedAppState};
use crate::{
    AllocMethod, ClientApp, ExecuteMethod, ListenerDialogMode, ListenerDialogState,
    ListenerProtocol, PayloadArch, PayloadFormat, SleepTechnique, build_console_message_color,
    build_console_message_prefix, build_listener_edit, build_listener_new, build_listener_remove,
    build_payload_request,
};
use red_cell_common::operator::ListenerInfo;

impl ClientApp {
    pub(crate) fn render_listeners_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        // ── Table ───────────────────────────────────────────────────
        let col_widths = [120.0_f32, 80.0, 120.0, 70.0, 70.0, 80.0];
        let headers = ["Name", "Protocol", "Host", "PortBind", "PortConn", "Status"];

        // Header row
        ui.horizontal(|ui| {
            for (header, &width) in headers.iter().zip(&col_widths) {
                ui.add_sized(
                    [width, 18.0],
                    egui::Label::new(
                        RichText::new(*header).strong().color(Color32::from_rgb(180, 180, 200)),
                    ),
                );
            }
        });
        ui.separator();

        // Body
        egui::ScrollArea::vertical().id_salt("listeners_table_scroll").show(ui, |ui| {
            if state.listeners.is_empty() {
                ui.label(RichText::new("No listeners configured.").weak());
            } else {
                for listener in state.listeners.iter() {
                    let is_selected =
                        self.session_panel.selected_listener.as_deref() == Some(&listener.name);

                    let row_bg = if is_selected {
                        Color32::from_rgb(50, 50, 80)
                    } else {
                        Color32::TRANSPARENT
                    };

                    let response = egui::Frame::default()
                        .fill(row_bg)
                        .inner_margin(egui::Margin::symmetric(0, 1))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [col_widths[0], 16.0],
                                    egui::Label::new(RichText::new(&listener.name)),
                                );
                                ui.add_sized(
                                    [col_widths[1], 16.0],
                                    egui::Label::new(RichText::new(&listener.protocol)),
                                );
                                ui.add_sized(
                                    [col_widths[2], 16.0],
                                    egui::Label::new(RichText::new(&listener.host)),
                                );
                                ui.add_sized(
                                    [col_widths[3], 16.0],
                                    egui::Label::new(RichText::new(&listener.port_bind)),
                                );
                                ui.add_sized(
                                    [col_widths[4], 16.0],
                                    egui::Label::new(RichText::new(&listener.port_conn)),
                                );
                                let status_color = if listener.status.contains("Online") {
                                    Color32::from_rgb(110, 199, 141) // green
                                } else {
                                    Color32::from_rgb(230, 80, 80) // red (offline/error)
                                };
                                ui.add_sized(
                                    [col_widths[5], 16.0],
                                    egui::Label::new(
                                        RichText::new(&listener.status).color(status_color),
                                    ),
                                );
                            });
                        })
                        .response;

                    if response.interact(Sense::click()).clicked() {
                        self.session_panel.selected_listener = Some(listener.name.clone());
                    }
                }
            }
        });

        ui.add_space(4.0);
        ui.separator();

        // ── Action buttons ──────────────────────────────────────────
        ui.horizontal(|ui| {
            if ui.button("Add").clicked() {
                self.session_panel.listener_dialog = Some(ListenerDialogState::new_create());
            }
            let has_selection = self.session_panel.selected_listener.is_some();
            if ui.add_enabled(has_selection, egui::Button::new("Remove")).clicked() {
                if let Some(name) = self.session_panel.selected_listener.take() {
                    let operator = state
                        .operator_info
                        .as_ref()
                        .map(|op| op.username.as_str())
                        .unwrap_or_default();
                    self.session_panel
                        .pending_messages
                        .push(build_listener_remove(&name, operator));
                }
            }
            if ui.add_enabled(has_selection, egui::Button::new("Edit")).clicked() {
                // For Edit we re-open the dialog pre-filled; since we only store
                // summary data locally, we populate from the summary and let the
                // operator change what the server allows.
                if let Some(name) = &self.session_panel.selected_listener {
                    if let Some(listener) = state.listeners.iter().find(|l| &l.name == name) {
                        let info = ListenerInfo {
                            host_bind: Some(listener.host.clone()),
                            port_bind: Some(listener.port_bind.clone()),
                            ..ListenerInfo::default()
                        };
                        self.session_panel.listener_dialog = Some(ListenerDialogState::new_edit(
                            &listener.name,
                            &listener.protocol,
                            &info,
                        ));
                    }
                }
            }
        });
    }

    /// Render the Create/Edit Listener dialog as an egui window overlay.
    pub(crate) fn render_listener_dialog(&mut self, ctx: &egui::Context, state: &AppState) {
        let Some(dialog) = &mut self.session_panel.listener_dialog else {
            return;
        };

        let title = match dialog.mode {
            ListenerDialogMode::Create => "Create Listener",
            ListenerDialogMode::Edit => "Edit Listener",
        };

        let mut close_requested = false;
        let mut save_clicked = false;

        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_width(480.0)
            .default_height(520.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::Grid::new("listener_dialog_grid").num_columns(2).spacing([8.0, 6.0]).show(
                    ui,
                    |ui| {
                        ui.label("Name:");
                        let name_editable = dialog.mode == ListenerDialogMode::Create;
                        ui.add_enabled(
                            name_editable,
                            egui::TextEdit::singleline(&mut dialog.name).desired_width(300.0),
                        );
                        ui.end_row();

                        ui.label("Payload:");
                        egui::ComboBox::from_id_salt("listener_protocol_combo")
                            .selected_text(dialog.protocol.label())
                            .width(300.0)
                            .show_ui(ui, |ui| {
                                for proto in ListenerProtocol::ALL {
                                    ui.selectable_value(&mut dialog.protocol, proto, proto.label());
                                }
                            });
                        ui.end_row();
                    },
                );

                ui.add_space(8.0);
                ui.heading("Config Options");
                ui.separator();

                match dialog.protocol {
                    ListenerProtocol::Http | ListenerProtocol::Https => {
                        Self::render_http_listener_fields(ui, dialog);
                    }
                    ListenerProtocol::Smb => {
                        egui::Grid::new("smb_fields").num_columns(2).spacing([8.0, 6.0]).show(
                            ui,
                            |ui| {
                                ui.label("Pipe Name:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.pipe_name)
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                            },
                        );
                    }
                    ListenerProtocol::Dns => {
                        egui::Grid::new("dns_fields").num_columns(2).spacing([8.0, 6.0]).show(
                            ui,
                            |ui| {
                                ui.label("Bind Address:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.host)
                                        .desired_width(300.0),
                                );
                                ui.end_row();

                                ui.label("Port:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.port)
                                        .desired_width(300.0),
                                );
                                ui.end_row();

                                ui.label("Domain:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.dns_domain)
                                        .desired_width(300.0),
                                );
                                ui.end_row();

                                ui.label("Record Types:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.dns_record_types)
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                            },
                        );
                    }
                    ListenerProtocol::External => {
                        egui::Grid::new("external_fields").num_columns(2).spacing([8.0, 6.0]).show(
                            ui,
                            |ui| {
                                ui.label("Endpoint:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut dialog.endpoint)
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                            },
                        );
                    }
                }

                ui.add_space(12.0);
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save_clicked = true;
                    }
                    if ui.button("Close").clicked() {
                        close_requested = true;
                    }
                });
            });

        if save_clicked {
            if let Some(dialog) = &self.session_panel.listener_dialog {
                let operator =
                    state.operator_info.as_ref().map(|op| op.username.as_str()).unwrap_or_default();
                let info = dialog.to_listener_info();
                let message = match dialog.mode {
                    ListenerDialogMode::Create => build_listener_new(info, operator),
                    ListenerDialogMode::Edit => build_listener_edit(info, operator),
                };
                self.session_panel.pending_messages.push(message);
            }
            self.session_panel.listener_dialog = None;
        } else if close_requested {
            self.session_panel.listener_dialog = None;
        }
    }

    /// Render the HTTP/HTTPS-specific config fields inside the listener dialog.
    pub(crate) fn render_http_listener_fields(ui: &mut egui::Ui, dialog: &mut ListenerDialogState) {
        egui::Grid::new("http_fields").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            ui.label("Host:");
            ui.add(egui::TextEdit::singleline(&mut dialog.host).desired_width(300.0));
            ui.end_row();

            ui.label("Port:");
            ui.add(egui::TextEdit::singleline(&mut dialog.port).desired_width(300.0));
            ui.end_row();

            ui.label("User Agent:");
            ui.add(egui::TextEdit::singleline(&mut dialog.user_agent).desired_width(300.0));
            ui.end_row();

            ui.label("Headers:");
            ui.add(
                egui::TextEdit::multiline(&mut dialog.headers).desired_width(300.0).desired_rows(3),
            );
            ui.end_row();

            ui.label("Uris:");
            ui.add(
                egui::TextEdit::multiline(&mut dialog.uris).desired_width(300.0).desired_rows(3),
            );
            ui.end_row();

            ui.label("Host Header:");
            ui.add(egui::TextEdit::singleline(&mut dialog.host_header).desired_width(300.0));
            ui.end_row();
        });

        ui.checkbox(&mut dialog.proxy_enabled, "Enable Proxy Connection");

        if dialog.proxy_enabled {
            egui::Frame::default()
                .fill(Color32::from_rgb(30, 30, 50))
                .inner_margin(egui::Margin::same(8))
                .corner_radius(4.0)
                .show(ui, |ui| {
                    egui::Grid::new("proxy_fields").num_columns(2).spacing([8.0, 6.0]).show(
                        ui,
                        |ui| {
                            ui.label("Proxy Type:");
                            egui::ComboBox::from_id_salt("proxy_type_combo")
                                .selected_text(&dialog.proxy_type)
                                .width(300.0)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut dialog.proxy_type,
                                        "http".to_owned(),
                                        "http",
                                    );
                                    ui.selectable_value(
                                        &mut dialog.proxy_type,
                                        "https".to_owned(),
                                        "https",
                                    );
                                });
                            ui.end_row();

                            ui.label("Proxy Host:");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.proxy_host)
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label("Proxy Port:");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.proxy_port)
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label("UserName:");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.proxy_username)
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label("Password:");
                            ui.add(
                                egui::TextEdit::singleline(&mut *dialog.proxy_password)
                                    .desired_width(300.0)
                                    .password(true),
                            );
                            ui.end_row();
                        },
                    );
                });
        }
    }

    /// Render the Payload generation dialog (Attack > Payload).
    pub(crate) fn render_payload_dialog(
        &mut self,
        ctx: &egui::Context,
        state: &AppState,
        app_state: &SharedAppState,
    ) {
        let Some(dialog) = &mut self.session_panel.payload_dialog else {
            return;
        };

        let mut close_requested = false;
        let mut generate_clicked = false;
        let mut save_result: Option<PayloadBuildResult> = None;

        // Snapshot build console + payload response from shared state.
        let build_messages: Arc<Vec<BuildConsoleEntry>> = Arc::clone(&state.build_console_messages);
        let payload_result: Option<PayloadBuildResult> = state.last_payload_response.clone();

        egui::Window::new("Payload")
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .default_height(640.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                // ── Agent type ──────────────────────────────────────
                egui::Grid::new("payload_agent_grid").num_columns(2).spacing([8.0, 6.0]).show(
                    ui,
                    |ui| {
                        ui.label("Agent:");
                        egui::ComboBox::from_id_salt("payload_agent_type")
                            .selected_text(&dialog.agent_type)
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut dialog.agent_type,
                                    "Demon".to_owned(),
                                    "Demon",
                                );
                                ui.selectable_value(
                                    &mut dialog.agent_type,
                                    "Archon".to_owned(),
                                    "Archon",
                                );
                            });
                        ui.end_row();
                    },
                );

                // ── Options section ─────────────────────────────────
                ui.add_space(4.0);
                ui.label(RichText::new("Options").strong());
                ui.separator();

                egui::Grid::new("payload_options_grid").num_columns(2).spacing([8.0, 6.0]).show(
                    ui,
                    |ui| {
                        ui.label("Listener:");
                        let listener_names: Vec<String> =
                            state.listeners.iter().map(|l| l.name.clone()).collect();
                        let selected = if dialog.listener.is_empty() {
                            listener_names.first().cloned().unwrap_or_default()
                        } else {
                            dialog.listener.clone()
                        };
                        egui::ComboBox::from_id_salt("payload_listener")
                            .selected_text(&selected)
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                for name in &listener_names {
                                    if ui.selectable_label(dialog.listener == *name, name).clicked()
                                    {
                                        dialog.listener = name.clone();
                                    }
                                }
                            });
                        ui.end_row();

                        ui.label("Arch:");
                        egui::ComboBox::from_id_salt("payload_arch")
                            .selected_text(dialog.arch.label())
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                for arch in PayloadArch::ALL {
                                    ui.selectable_value(&mut dialog.arch, arch, arch.label());
                                }
                            });
                        ui.end_row();

                        ui.label("Format:");
                        egui::ComboBox::from_id_salt("payload_format")
                            .selected_text(dialog.format.label())
                            .width(360.0)
                            .show_ui(ui, |ui| {
                                for fmt in PayloadFormat::ALL {
                                    ui.selectable_value(&mut dialog.format, fmt, fmt.label());
                                }
                            });
                        ui.end_row();
                    },
                );

                // ── Config table ────────────────────────────────────
                ui.add_space(4.0);
                egui::Grid::new("payload_config_header").num_columns(2).spacing([8.0, 0.0]).show(
                    ui,
                    |ui| {
                        ui.strong("Config");
                        ui.strong("Value");
                        ui.end_row();
                    },
                );
                ui.separator();

                egui::Grid::new("payload_config_grid").num_columns(2).spacing([8.0, 4.0]).show(
                    ui,
                    |ui| {
                        ui.label("    Sleep");
                        ui.add(egui::TextEdit::singleline(&mut dialog.sleep).desired_width(200.0));
                        ui.end_row();

                        ui.label("    Jitter");
                        ui.add(egui::TextEdit::singleline(&mut dialog.jitter).desired_width(200.0));
                        ui.end_row();

                        ui.label("    Indirect Syscall");
                        ui.checkbox(&mut dialog.indirect_syscall, "");
                        ui.end_row();

                        ui.label("    Sleep Technique");
                        egui::ComboBox::from_id_salt("payload_sleep_tech")
                            .selected_text(dialog.sleep_technique.label())
                            .width(200.0)
                            .show_ui(ui, |ui| {
                                for tech in SleepTechnique::ALL {
                                    ui.selectable_value(
                                        &mut dialog.sleep_technique,
                                        tech,
                                        tech.label(),
                                    );
                                }
                            });
                        ui.end_row();
                    },
                );

                // ── Injection section ───────────────────────────────
                ui.add_space(4.0);
                ui.collapsing("Injection", |ui| {
                    egui::Grid::new("payload_injection_grid")
                        .num_columns(2)
                        .spacing([8.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Alloc");
                            egui::ComboBox::from_id_salt("payload_alloc")
                                .selected_text(dialog.alloc.label())
                                .width(200.0)
                                .show_ui(ui, |ui| {
                                    for m in AllocMethod::ALL {
                                        ui.selectable_value(&mut dialog.alloc, m, m.label());
                                    }
                                });
                            ui.end_row();

                            ui.label("Execute");
                            egui::ComboBox::from_id_salt("payload_execute")
                                .selected_text(dialog.execute.label())
                                .width(200.0)
                                .show_ui(ui, |ui| {
                                    for m in ExecuteMethod::ALL {
                                        ui.selectable_value(&mut dialog.execute, m, m.label());
                                    }
                                });
                            ui.end_row();

                            ui.label("Spawn64");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.spawn64)
                                    .desired_width(280.0)
                                    .text_color(Color32::from_rgb(85, 255, 85)),
                            );
                            ui.end_row();

                            ui.label("Spawn32");
                            ui.add(
                                egui::TextEdit::singleline(&mut dialog.spawn32)
                                    .desired_width(280.0)
                                    .text_color(Color32::from_rgb(85, 255, 85)),
                            );
                            ui.end_row();
                        });
                });

                // ── Building Console ────────────────────────────────
                ui.add_space(8.0);
                ui.strong("Building Console");

                let console_height = 140.0;
                egui::Frame::NONE
                    .fill(Color32::from_rgb(20, 20, 30))
                    .inner_margin(6.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(console_height)
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                if build_messages.is_empty() {
                                    ui.colored_label(
                                        Color32::from_rgb(100, 100, 100),
                                        "No build output yet.",
                                    );
                                } else {
                                    for entry in build_messages.iter() {
                                        let color =
                                            build_console_message_color(&entry.message_type);
                                        let prefix =
                                            build_console_message_prefix(&entry.message_type);
                                        ui.colored_label(
                                            color,
                                            format!("{prefix} {}", entry.message),
                                        );
                                    }
                                }
                            });
                    });

                // ── Generate / Save / Close buttons ─────────────────
                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    let can_generate = !dialog.building;
                    if ui.add_enabled(can_generate, egui::Button::new("Generate")).clicked() {
                        generate_clicked = true;
                    }
                    if let Some(result) = &payload_result {
                        if ui.button(format!("Save ({})", result.file_name)).clicked() {
                            save_result = Some(result.clone());
                        }
                    }
                    if ui.button("Close").clicked() {
                        close_requested = true;
                    }
                });
            });

        // ── Post-frame actions ──────────────────────────────────────
        if generate_clicked {
            if let Some(dialog) = &mut self.session_panel.payload_dialog {
                dialog.building = true;
                // Clear previous build state.
                match app_state.lock() {
                    Ok(mut s) => {
                        Arc::make_mut(&mut s.build_console_messages).clear();
                        s.last_payload_response = None;
                    }
                    Err(poisoned) => {
                        let mut s = poisoned.into_inner();
                        Arc::make_mut(&mut s.build_console_messages).clear();
                        s.last_payload_response = None;
                    }
                }
                let operator =
                    state.operator_info.as_ref().map(|op| op.username.as_str()).unwrap_or_default();
                let message = build_payload_request(dialog, operator);
                self.session_panel.pending_messages.push(message);
            }
        }

        if let Some(result) = save_result {
            if let Some(path) = FileDialog::new().set_file_name(&result.file_name).save_file() {
                if let Err(e) = std::fs::write(&path, &result.payload_bytes) {
                    self.session_panel.status_message =
                        Some(format!("Failed to save payload: {e}"));
                } else {
                    self.session_panel.status_message =
                        Some(format!("Payload saved to {}", path.display()));
                }
            }
        }

        if close_requested {
            self.session_panel.payload_dialog = None;
            // Clear build state when closing the dialog.
            match app_state.lock() {
                Ok(mut s) => {
                    Arc::make_mut(&mut s.build_console_messages).clear();
                    s.last_payload_response = None;
                }
                Err(poisoned) => {
                    let mut s = poisoned.into_inner();
                    Arc::make_mut(&mut s.build_console_messages).clear();
                    s.last_payload_response = None;
                }
            }
        }

        // Mark building as done when we have a response or build is done.
        if payload_result.is_some() {
            if let Some(dialog) = &mut self.session_panel.payload_dialog {
                dialog.building = false;
            }
        }
    }
}
