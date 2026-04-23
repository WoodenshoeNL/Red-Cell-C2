//! Breadcrumb path bar, secondary path actions, and main file-browser toolbar.

use eframe::egui::{self, RichText};

use crate::transport::AgentFileBrowserState;
use crate::{
    ClientApp, breadcrumb_segments, build_file_browser_list_task, find_file_entry,
    parent_remote_path, selected_remote_directory, upload_destination,
};

/// Breadcrumb path bar for the file browser tab.
pub(crate) fn render_file_browser_breadcrumb(
    app: &mut ClientApp,
    ui: &mut egui::Ui,
    agent_id: &str,
    browser: Option<&AgentFileBrowserState>,
    current_dir: Option<&str>,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Path:").strong());

        if let Some(path) = current_dir {
            let segments = breadcrumb_segments(path);
            for (i, (label, full_path)) in segments.iter().enumerate() {
                if i > 0 {
                    ui.label(RichText::new(">").weak());
                }

                let segment_width =
                    (ui.available_width() / (segments.len() - i).max(1) as f32).clamp(72.0, 220.0);
                let button = egui::Button::new(RichText::new(label.as_str()).monospace())
                    .truncate()
                    .small()
                    .frame(false);
                let mut response =
                    ui.add_sized([segment_width, ui.spacing().interact_size.y], button);
                if response.intrinsic_size.is_some_and(|size| size.x > response.rect.width() + 0.5)
                {
                    response = response.on_hover_text(full_path.as_str());
                }
                if response.clicked() {
                    app.queue_file_browser_cd(agent_id, full_path);
                    app.queue_file_browser_list(agent_id, full_path);
                }
                let copied_path = full_path.clone();
                response.context_menu(|ui| {
                    if ui.button("Copy path").clicked() {
                        ui.ctx().copy_text(copied_path.clone());
                        ui.close();
                    }
                });
            }
        } else {
            let response =
                ui.add(egui::Label::new(RichText::new("unknown").monospace()).truncate());
            response.on_hover_text("Resolve cwd to populate the breadcrumb path.");
        }
    });

    ui.horizontal_wrapped(|ui| {
        if current_dir.is_none() {
            ui.add_enabled(false, egui::Button::new("Current path unavailable"));
        } else if let Some(path) = current_dir {
            let response =
                ui.add(egui::Label::new(RichText::new(path).monospace().weak()).truncate());
            if response.intrinsic_size.is_some_and(|size| size.x > response.rect.width() + 0.5) {
                response.on_hover_text(path);
            }
        }

        ui.separator();

        if ui.button("Resolve cwd").clicked() {
            app.queue_file_browser_pwd(agent_id);
        }
        if ui.button("Refresh").clicked() {
            if let Some(path) = current_dir {
                app.queue_file_browser_list(agent_id, path);
            }
        }
        if ui.button("Up").clicked() {
            if let Some(path) = current_dir.and_then(parent_remote_path) {
                app.queue_file_browser_cd(agent_id, &path);
                app.queue_file_browser_list(agent_id, &path);
            }
        }

        // Auto-request listing if the current directory is not yet loaded
        let loaded_paths = browser.map(|s| &s.directories);
        let operator = app.current_operator_username();
        {
            let ui_state = app.session_panel.file_browser_state_mut(agent_id);
            if let Some(browser) = browser {
                ui_state.pending_dirs.retain(|p| !browser.directories.contains_key(p));
            }
            if let Some(root) = current_dir {
                if loaded_paths.is_none_or(|paths| !paths.contains_key(root))
                    && !ui_state.pending_dirs.contains(root)
                {
                    let message = build_file_browser_list_task(agent_id, root, &operator);
                    ui_state.pending_dirs.insert(root.to_owned());
                    ui_state.status_message = Some(format!("Queued listing for {root}."));
                    app.session_panel.pending_messages.push(message);
                }
            }
        }
    });
}

/// Action toolbar for the file browser tab (Download, Upload, Delete, Set Working Dir).
pub(crate) fn render_file_browser_toolbar(
    app: &mut ClientApp,
    ui: &mut egui::Ui,
    agent_id: &str,
    browser: Option<&AgentFileBrowserState>,
) {
    ui.horizontal_wrapped(|ui| {
        let selected_path = app
            .session_panel
            .file_browser_state
            .get(agent_id)
            .and_then(|s| s.selected_path.clone());
        let selected_entry = browser.and_then(|state| {
            selected_path.as_deref().and_then(|path| find_file_entry(state, path))
        });
        let selected_directory = selected_remote_directory(browser, selected_path.as_deref());

        if ui
            .add_enabled(selected_directory.is_some(), egui::Button::new("Set Working Dir"))
            .clicked()
            && let Some(path) = selected_directory.as_deref()
        {
            app.queue_file_browser_cd(agent_id, path);
            app.queue_file_browser_list(agent_id, path);
        }

        if ui
            .add_enabled(
                selected_entry.is_some_and(|entry| !entry.is_dir),
                egui::Button::new("Download"),
            )
            .clicked()
        {
            if let Some(path) = selected_path.as_deref() {
                app.queue_file_browser_download(agent_id, path);
            }
        }

        if ui.button("Upload").clicked() {
            app.queue_file_browser_upload(
                agent_id,
                upload_destination(browser, selected_path.as_deref()),
            );
        }

        if ui.add_enabled(selected_path.is_some(), egui::Button::new("Delete")).clicked() {
            if let Some(path) = selected_path.as_deref() {
                app.queue_file_browser_delete(agent_id, path);
            }
        }

        if let Some(path) = &selected_path {
            ui.separator();
            ui.label(RichText::new(format!("Selected: {path}")).weak().monospace());
        }
    });
}
