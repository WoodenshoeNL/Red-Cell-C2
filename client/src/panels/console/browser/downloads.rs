//! In-progress and completed download rows for the file browser.

use eframe::egui::{self, RichText};

use crate::transport::AgentFileBrowserState;
use crate::{ClientApp, CompletedDownloadSaveOutcome, human_size, save_completed_download};

/// Renders the downloads-in-progress section of the file browser.
///
/// For each in-progress download:
/// - Shows a status icon (⏳ in progress, ❌ stopped).
/// - Shows a progress bar with bytes-received / total-bytes.
/// - Shows a "Cancel" button while the download is running.
///
/// For each completed download:
/// - Shows a ✅ icon with the file path and size.
/// - Shows a "Save" button that opens a native save-file dialog.
/// - Remembers which ones have been dismissed so they are not shown again.
pub(crate) fn render_download_progress_section(
    app: &mut ClientApp,
    ui: &mut egui::Ui,
    agent_id: &str,
    browser: &AgentFileBrowserState,
) {
    let has_active = !browser.downloads.is_empty();
    let has_completed = browser.completed_downloads.iter().any(|(file_id, _)| {
        !app.session_panel
            .file_browser_state
            .get(agent_id)
            .is_some_and(|s| s.dismissed_downloads.contains(file_id.as_str()))
    });

    if !has_active && !has_completed {
        return;
    }

    ui.add_space(8.0);
    ui.separator();
    ui.label(RichText::new("Downloads").strong());

    // ── In-progress downloads ──────────────────────────────────
    let mut cancel_file_ids: Vec<String> = Vec::new();

    for progress in browser.downloads.values() {
        let denominator = progress.expected_size.max(1) as f32;
        let fraction = (progress.current_size as f32 / denominator).clamp(0.0, 1.0);

        let is_running = progress.state.eq_ignore_ascii_case("InProgress")
            || progress.state.eq_ignore_ascii_case("Started")
            || progress.state.eq_ignore_ascii_case("Running");
        let is_stopped = progress.state.eq_ignore_ascii_case("Stopped");

        let icon = if is_stopped { "❌" } else { "⏳" };

        ui.horizontal(|ui| {
            ui.label(icon);
            ui.add(egui::ProgressBar::new(fraction).text(format!(
                "{} [{} / {}]",
                progress.remote_path,
                human_size(progress.current_size),
                human_size(progress.expected_size),
            )));
            if is_running
                && ui
                    .add(egui::Button::new("Cancel").small())
                    .on_hover_text("Stop this download")
                    .clicked()
            {
                cancel_file_ids.push(progress.file_id.clone());
            }
        });
    }

    // Send cancel messages outside the immutable borrow of `browser`.
    for file_id in cancel_file_ids {
        app.queue_file_browser_download_cancel(agent_id, &file_id);
    }

    // ── Completed downloads awaiting save ──────────────────────
    if has_completed {
        ui.add_space(4.0);
        ui.label(RichText::new("Completed — click Save to write to disk:").weak());
    }

    let mut to_dismiss: Vec<String> = Vec::new();
    for (file_id, c) in &browser.completed_downloads {
        if app
            .session_panel
            .file_browser_state
            .get(agent_id)
            .is_some_and(|s| s.dismissed_downloads.contains(file_id.as_str()))
        {
            continue;
        }
        ui.horizontal(|ui| {
            ui.label("✅");
            ui.label(
                RichText::new(format!("{} ({})", c.remote_path, human_size(c.data.len() as u64)))
                    .monospace(),
            );
            if ui.button("Save").clicked() {
                match save_completed_download(c.remote_path.as_str(), c.data.as_slice()) {
                    CompletedDownloadSaveOutcome::Cancelled => {}
                    CompletedDownloadSaveOutcome::Saved => {
                        to_dismiss.push(file_id.clone());
                    }
                    CompletedDownloadSaveOutcome::WriteFailed(message) => {
                        app.session_panel.file_browser_state_mut(agent_id).status_message =
                            Some(message);
                    }
                }
            }
            if ui
                .add(egui::Button::new("Dismiss").small())
                .on_hover_text("Remove from the list without saving")
                .clicked()
            {
                to_dismiss.push(file_id.clone());
            }
        });
    }

    // Mark dismissed entries so they are hidden on future renders.
    if !to_dismiss.is_empty() {
        let ui_state = app.session_panel.file_browser_state_mut(agent_id);
        for file_id in to_dismiss {
            ui_state.dismissed_downloads.insert(file_id);
        }
    }
}
