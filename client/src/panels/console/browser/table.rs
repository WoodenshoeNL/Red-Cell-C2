//! Right-pane file list grid for the standalone file browser tab.

use eframe::egui::{self, Color32, RichText};

use crate::transport::AgentFileBrowserState;
use crate::{ClientApp, selected_remote_directory};

/// Right-pane file list table for the standalone file browser tab.
pub(crate) fn render_file_list_table(
    app: &mut ClientApp,
    ui: &mut egui::Ui,
    agent_id: &str,
    browser: Option<&AgentFileBrowserState>,
    current_dir: Option<&str>,
) {
    // Determine the directory to show in the file list — use the selected
    // path if it's a directory, otherwise fall back to the current working
    // directory.
    let selected_path =
        app.session_panel.file_browser_state.get(agent_id).and_then(|s| s.selected_path.clone());
    let display_dir = selected_remote_directory(browser, selected_path.as_deref())
        .or_else(|| current_dir.map(String::from));

    let entries =
        display_dir.as_deref().and_then(|dir| browser.and_then(|b| b.directories.get(dir)));

    egui::ScrollArea::both().id_salt(("fb-files", agent_id)).show(ui, |ui| {
        if let Some(entries) = entries {
            if entries.is_empty() {
                ui.label("Directory is empty.");
                return;
            }

            // Header row
            egui::Grid::new(("fb-file-grid", agent_id))
                .num_columns(4)
                .spacing([12.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.label(RichText::new("Name").strong());
                    ui.label(RichText::new("Size").strong());
                    ui.label(RichText::new("Modified").strong());
                    ui.label(RichText::new("Permissions").strong());
                    ui.end_row();

                    // Directories first, then files
                    let mut sorted: Vec<_> = entries.iter().collect();
                    sorted
                        .sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));

                    for entry in sorted {
                        let is_selected = app
                            .session_panel
                            .file_browser_state
                            .get(agent_id)
                            .and_then(|s| s.selected_path.as_deref())
                            == Some(entry.path.as_str());

                        let icon = if entry.is_dir { "\u{1F4C1}" } else { "\u{1F4C4}" };
                        let name_text = format!("{icon} {}", entry.name);
                        let label_text = if entry.is_dir {
                            RichText::new(&name_text)
                                .monospace()
                                .color(Color32::from_rgb(80, 180, 220))
                        } else {
                            RichText::new(&name_text).monospace()
                        };

                        let response = ui.selectable_label(is_selected, label_text);
                        if response.clicked() {
                            app.session_panel.file_browser_state_mut(agent_id).selected_path =
                                Some(entry.path.clone());
                        }
                        if response.double_clicked() && entry.is_dir {
                            app.queue_file_browser_cd(agent_id, &entry.path);
                            app.queue_file_browser_list(agent_id, &entry.path);
                        }

                        // Context menu on each entry
                        response.context_menu(|ui| {
                            if entry.is_dir {
                                if ui.button("Open").clicked() {
                                    app.queue_file_browser_cd(agent_id, &entry.path);
                                    app.queue_file_browser_list(agent_id, &entry.path);
                                    ui.close();
                                }
                            } else if ui.button("Download").clicked() {
                                app.queue_file_browser_download(agent_id, &entry.path);
                                ui.close();
                            }
                            if ui.button("Delete").clicked() {
                                app.queue_file_browser_delete(agent_id, &entry.path);
                                ui.close();
                            }
                        });

                        ui.label(RichText::new(&entry.size_label).monospace().weak());
                        ui.label(RichText::new(&entry.modified_at).monospace().weak());
                        ui.label(RichText::new(&entry.permissions).monospace().weak());
                        ui.end_row();
                    }
                });
        } else {
            ui.label("Select a directory to view its contents.");
        }
    });
}
