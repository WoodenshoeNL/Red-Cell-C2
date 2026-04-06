use base64::Engine;
use eframe::egui::{self, Color32, RichText, Stroke};

use crate::transport::{AppState, LootItem};
use crate::{
    ClientApp, CredentialSortColumn, CredentialSubFilter, FileSubFilter, LootTab, blank_if_empty,
    download_loot_item, export_loot_csv, export_loot_json, loot_is_downloadable,
    loot_sub_category_label, loot_table_row_height, render_loot_credential_header,
    render_loot_credential_row, render_loot_file_row,
};

impl ClientApp {
    pub(crate) fn render_loot_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        // ── Header with sub-tabs ───────────────────────────────────────
        ui.horizontal(|ui| {
            ui.heading("Loot");
            ui.add_space(16.0);
            for (tab, label) in [
                (LootTab::Credentials, "Credentials"),
                (LootTab::Screenshots, "Screenshots"),
                (LootTab::Files, "Files"),
            ] {
                let active = self.session_panel.loot_panel.active_tab == tab;
                let text = if active {
                    RichText::new(label).strong().color(Color32::WHITE)
                } else {
                    RichText::new(label).color(Color32::from_rgb(160, 160, 170))
                };
                let frame = if active {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(40, 42, 54))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(220, 130, 60)))
                        .inner_margin(egui::Margin::symmetric(8, 3))
                } else {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(30, 30, 46))
                        .inner_margin(egui::Margin::symmetric(8, 3))
                };
                if frame.show(ui, |ui| ui.label(text)).response.clicked() {
                    self.session_panel.loot_panel.active_tab = tab;
                    self.session_panel.loot_panel.mark_filter_dirty();
                }
            }
        });
        ui.separator();

        // ── Common filter bar ──────────────────────────────────────────
        let mut filters_changed = false;
        ui.horizontal_wrapped(|ui| {
            // Show sub-filter only when relevant to the active tab.
            match self.session_panel.loot_panel.active_tab {
                LootTab::Credentials => {
                    ui.label("Category");
                    let response = egui::ComboBox::from_id_salt("loot-cred-filter")
                        .selected_text(match self.session_panel.loot_cred_filter {
                            CredentialSubFilter::All => "All",
                            CredentialSubFilter::NtlmHash => "NTLM Hash",
                            CredentialSubFilter::Plaintext => "Plaintext Password",
                            CredentialSubFilter::KerberosTicket => "Kerberos Ticket",
                            CredentialSubFilter::Certificate => "Certificate",
                        })
                        .show_ui(ui, |ui| {
                            for (value, label) in CredentialSubFilter::ALL {
                                ui.selectable_value(
                                    &mut self.session_panel.loot_cred_filter,
                                    value,
                                    label,
                                );
                            }
                        });
                    filters_changed |= response.response.changed();
                }
                LootTab::Files => {
                    ui.label("Category");
                    let response = egui::ComboBox::from_id_salt("loot-file-filter")
                        .selected_text(match self.session_panel.loot_file_filter {
                            FileSubFilter::All => "All",
                            FileSubFilter::Document => "Document",
                            FileSubFilter::Archive => "Archive",
                            FileSubFilter::Binary => "Binary",
                        })
                        .show_ui(ui, |ui| {
                            for (value, label) in FileSubFilter::ALL {
                                ui.selectable_value(
                                    &mut self.session_panel.loot_file_filter,
                                    value,
                                    label,
                                );
                            }
                        });
                    filters_changed |= response.response.changed();
                }
                LootTab::Screenshots => {}
            }

            ui.label("Agent");
            filters_changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut self.session_panel.loot_agent_filter)
                        .desired_width(84.0)
                        .hint_text("ABCD1234"),
                )
                .changed();
            ui.label("Since");
            filters_changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut self.session_panel.loot_since_filter)
                        .desired_width(100.0)
                        .hint_text("2026-03-01"),
                )
                .changed();
            ui.label("Until");
            filters_changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut self.session_panel.loot_until_filter)
                        .desired_width(100.0)
                        .hint_text("2026-03-31"),
                )
                .changed();
        });
        filters_changed |= ui
            .add(
                egui::TextEdit::singleline(&mut self.session_panel.loot_text_filter)
                    .hint_text("Search name, path, source, preview"),
            )
            .changed();

        if filters_changed {
            self.session_panel.loot_panel.mark_filter_dirty();
        }

        if let Some(message) = &self.session_panel.loot_status_message {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }
        ui.add_space(4.0);

        self.session_panel.loot_panel.refresh_filtered_loot(
            state,
            self.session_panel.loot_cred_filter,
            self.session_panel.loot_file_filter,
            &self.session_panel.loot_agent_filter,
            &self.session_panel.loot_since_filter,
            &self.session_panel.loot_until_filter,
            &self.session_panel.loot_text_filter,
        );

        // ── Export bar ─────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label(format!("{} item(s)", self.session_panel.loot_panel.filtered_loot.len()));
            if ui.button("Export CSV").clicked() {
                let filtered_loot = self.filtered_loot_items(state);
                self.session_panel.loot_status_message =
                    Some(export_loot_csv(&filtered_loot).unwrap_or_else(|e| e));
            }
            if ui.button("Export JSON").clicked() {
                let filtered_loot = self.filtered_loot_items(state);
                self.session_panel.loot_status_message =
                    Some(export_loot_json(&filtered_loot).unwrap_or_else(|e| e));
            }
        });
        ui.add_space(4.0);

        // ── Tab content ────────────────────────────────────────────────
        match self.session_panel.loot_panel.active_tab {
            LootTab::Credentials => self.render_loot_credentials(ui, state),
            LootTab::Screenshots => {
                let filtered_loot = self.filtered_loot_items(state);
                self.render_loot_screenshots(ui, &filtered_loot);
            }
            LootTab::Files => self.render_loot_files(ui, state),
        }
    }

    /// Render the credential table inside the Loot panel.
    pub(crate) fn render_loot_credentials(&mut self, ui: &mut egui::Ui, state: &AppState) {
        if self.session_panel.loot_panel.filtered_loot.is_empty() {
            ui.label("No credentials collected yet.");
            return;
        }

        // Sort items according to selected column.
        let mut sorted = self.session_panel.loot_panel.filtered_loot.clone();
        let desc = self.session_panel.loot_panel.cred_sort_desc;
        sorted.sort_by(|a, b| {
            let a = &state.loot[*a];
            let b = &state.loot[*b];
            let ordering = match self.session_panel.loot_panel.cred_sort_column {
                CredentialSortColumn::Name => a.name.cmp(&b.name),
                CredentialSortColumn::Agent => a.agent_id.cmp(&b.agent_id),
                CredentialSortColumn::Category => {
                    loot_sub_category_label(a).cmp(loot_sub_category_label(b))
                }
                CredentialSortColumn::Source => a.source.cmp(&b.source),
                CredentialSortColumn::Time => a.collected_at.cmp(&b.collected_at),
            };
            if desc { ordering.reverse() } else { ordering }
        });

        render_loot_credential_header(
            ui,
            &mut self.session_panel.loot_panel,
            Color32::from_rgb(180, 180, 190),
        );
        ui.separator();

        let row_height = loot_table_row_height(ui);
        egui::ScrollArea::vertical().show_rows(ui, row_height, sorted.len(), |ui, row_range| {
            egui::Grid::new("loot-cred-table-body")
                .num_columns(6)
                .striped(false)
                .min_col_width(60.0)
                .spacing([8.0, 2.0])
                .show(ui, |ui| {
                    for index in row_range {
                        let item = &state.loot[sorted[index]];
                        render_loot_credential_row(ui, item);
                    }
                });
        });
    }

    /// Render the screenshot gallery inside the Loot panel.
    pub(crate) fn render_loot_screenshots(&mut self, ui: &mut egui::Ui, items: &[&LootItem]) {
        if items.is_empty() {
            ui.label("No screenshots captured yet.");
            return;
        }

        // Clamp selected index.
        if let Some(sel) = self.session_panel.loot_panel.selected_screenshot {
            if sel >= items.len() {
                self.session_panel.loot_panel.selected_screenshot = None;
            }
        }

        // If a screenshot is selected, show detail view.
        if let Some(selected_idx) = self.session_panel.loot_panel.selected_screenshot {
            let item = items[selected_idx];
            ui.horizontal(|ui| {
                if ui.button("<< Back to gallery").clicked() {
                    self.session_panel.loot_panel.selected_screenshot = None;
                }
                ui.add_space(8.0);
                ui.label(RichText::new(&item.name).strong());
                if !item.agent_id.is_empty() {
                    ui.monospace(format!("[{}]", item.agent_id));
                }
                ui.label(format!("  {}", blank_if_empty(&item.collected_at, "unknown")));
                if loot_is_downloadable(item) && ui.button("Save").clicked() {
                    self.session_panel.loot_status_message =
                        Some(download_loot_item(item).unwrap_or_else(|e| e));
                }
            });
            ui.separator();

            // Render the screenshot image.
            egui::ScrollArea::both().show(ui, |ui| {
                if let Some(texture) = self.ensure_screenshot_texture(ui.ctx(), item) {
                    let size = texture.size_vec2();
                    let available = ui.available_size();
                    let scale = (available.x / size.x).min(available.y / size.y).min(1.0);
                    let scaled = size * scale;
                    ui.add(egui::Image::from_texture(&texture).fit_to_exact_size(scaled));
                } else {
                    ui.label(
                        RichText::new("Unable to decode screenshot image.")
                            .color(Color32::from_rgb(220, 80, 80)),
                    );
                }
            });
            return;
        }

        // Thumbnail grid view.
        let thumb_size = 200.0_f32;
        egui::ScrollArea::vertical().show(ui, |ui| {
            let available_width = ui.available_width();
            let cols = ((available_width / (thumb_size + 12.0)) as usize).max(1);
            egui::Grid::new("loot-screenshot-grid").num_columns(cols).spacing([8.0, 8.0]).show(
                ui,
                |ui| {
                    for (index, item) in items.iter().enumerate() {
                        let frame = egui::Frame::default()
                            .fill(Color32::from_rgb(30, 30, 46))
                            .stroke(Stroke::new(1.0, Color32::from_rgb(60, 60, 80)))
                            .inner_margin(egui::Margin::same(4));
                        let response = frame
                            .show(ui, |ui| {
                                ui.set_width(thumb_size);
                                if let Some(texture) =
                                    self.ensure_screenshot_texture(ui.ctx(), item)
                                {
                                    let img_size = texture.size_vec2();
                                    let scale =
                                        (thumb_size / img_size.x).min(thumb_size / img_size.y);
                                    let scaled = img_size * scale;
                                    ui.add(
                                        egui::Image::from_texture(&texture)
                                            .fit_to_exact_size(scaled),
                                    );
                                } else {
                                    ui.allocate_space(egui::vec2(thumb_size, thumb_size * 0.6));
                                    ui.label(
                                        RichText::new("[decode error]")
                                            .small()
                                            .color(Color32::from_rgb(180, 80, 80)),
                                    );
                                }
                                ui.label(RichText::new(&item.name).small().strong());
                                ui.label(
                                    RichText::new(format!(
                                        "{} | {}",
                                        blank_if_empty(&item.agent_id, "?"),
                                        blank_if_empty(&item.collected_at, "?"),
                                    ))
                                    .small()
                                    .color(Color32::GRAY),
                                );
                            })
                            .response;
                        if response.clicked() {
                            self.session_panel.loot_panel.selected_screenshot = Some(index);
                        }
                        if (index + 1) % cols == 0 {
                            ui.end_row();
                        }
                    }
                },
            );
        });
    }

    /// Render the file downloads table inside the Loot panel.
    pub(crate) fn render_loot_files(&mut self, ui: &mut egui::Ui, state: &AppState) {
        if self.session_panel.loot_panel.filtered_loot.is_empty() {
            ui.label("No files downloaded yet.");
            return;
        }

        egui::Grid::new("loot-files-table-header")
            .num_columns(7)
            .striped(false)
            .min_col_width(50.0)
            .spacing([8.0, 2.0])
            .show(ui, |ui| {
                for label in ["Name", "Category", "Agent", "Path", "Size", "Collected", ""] {
                    ui.label(RichText::new(label).strong().color(Color32::from_rgb(180, 180, 190)));
                }
                ui.end_row();
            });
        ui.separator();

        let filtered_indices = self.session_panel.loot_panel.filtered_loot.clone();
        let row_height = loot_table_row_height(ui);
        egui::ScrollArea::vertical().show_rows(
            ui,
            row_height,
            filtered_indices.len(),
            |ui, row_range| {
                egui::Grid::new("loot-files-table-body")
                    .num_columns(7)
                    .striped(false)
                    .min_col_width(50.0)
                    .spacing([8.0, 2.0])
                    .show(ui, |ui| {
                        for index in row_range {
                            let item = &state.loot[filtered_indices[index]];
                            render_loot_file_row(
                                ui,
                                item,
                                &mut self.session_panel.loot_status_message,
                            );
                        }
                    });
            },
        );
    }

    pub(crate) fn filtered_loot_items<'a>(&self, state: &'a AppState) -> Vec<&'a LootItem> {
        self.session_panel
            .loot_panel
            .filtered_loot
            .iter()
            .map(|index| &state.loot[*index])
            .collect()
    }

    /// Decode and cache a screenshot texture for the given loot item.
    ///
    /// Returns `None` if the item has no image content or decoding fails.
    pub(crate) fn ensure_screenshot_texture(
        &mut self,
        ctx: &egui::Context,
        item: &LootItem,
    ) -> Option<egui::TextureHandle> {
        let id = item.id.unwrap_or(-1);
        if let Some(handle) = self.session_panel.screenshot_textures.inner.get(&id) {
            return Some(handle.clone());
        }
        let encoded = item.content_base64.as_deref()?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
        let img = image::load_from_memory(&bytes).ok()?.to_rgba8();
        let (w, h) = img.dimensions();
        let color_image =
            egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], img.as_raw());
        let texture = ctx.load_texture(
            format!("loot-screenshot-{id}"),
            color_image,
            egui::TextureOptions::LINEAR,
        );
        self.session_panel.screenshot_textures.inner.insert(id, texture.clone());
        Some(texture)
    }
}

// Re-export loot helpers that are needed by main.rs tests (via use super::loot::*)
// These functions are defined in main.rs but called from here.
// (No re-exports needed - functions defined in main.rs are accessible from child modules.)
