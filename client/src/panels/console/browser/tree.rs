//! Recursive directory tree for the file browser left pane.

use eframe::egui;

use crate::transport::AgentFileBrowserState;
use crate::{ClientApp, build_file_browser_list_task, directory_label, file_entry_label};

pub(crate) fn render_directory_tree(
    app: &mut ClientApp,
    ui: &mut egui::Ui,
    agent_id: &str,
    browser: &AgentFileBrowserState,
    path: &str,
    depth: usize,
) {
    let label = directory_label(path);
    let response = egui::CollapsingHeader::new(label)
        .id_salt(("file-browser-dir", agent_id, path))
        .default_open(depth == 0)
        .show(ui, |ui| {
            if let Some(entries) = browser.directories.get(path) {
                if entries.is_empty() {
                    ui.label("Directory is empty.");
                } else {
                    for entry in entries {
                        if entry.is_dir {
                            render_directory_tree(
                                app,
                                ui,
                                agent_id,
                                browser,
                                &entry.path,
                                depth + 1,
                            );
                        } else {
                            let selected = app
                                .session_panel
                                .file_browser_state
                                .get(agent_id)
                                .and_then(|state| state.selected_path.as_deref())
                                == Some(entry.path.as_str());
                            if ui.selectable_label(selected, file_entry_label(entry)).clicked() {
                                app.session_panel.file_browser_state_mut(agent_id).selected_path =
                                    Some(entry.path.clone());
                            }
                        }
                    }
                }
            } else {
                ui.label("Waiting for directory listing...");
            }
        });

    if response.header_response.clicked() {
        app.session_panel.file_browser_state_mut(agent_id).selected_path = Some(path.to_owned());
    }

    if response.fully_open() && !browser.directories.contains_key(path) {
        let operator = app.current_operator_username();
        let ui_state = app.session_panel.file_browser_state_mut(agent_id);
        if !ui_state.pending_dirs.contains(path) {
            let message = build_file_browser_list_task(agent_id, path, &operator);
            ui_state.pending_dirs.insert(path.to_owned());
            ui_state.status_message = Some(format!("Queued listing for {path}."));
            app.session_panel.pending_messages.push(message);
        }
    }
}
