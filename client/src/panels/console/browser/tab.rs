//! Standalone file browser tab layout: agent header, breadcrumb, toolbar, dual-pane
//! explorer, and downloads footer.

use eframe::egui::{self, RichText};

use crate::ClientApp;
use crate::transport::AppState;

use super::{breadcrumb, downloads, table, tree};

/// Standalone file browser tab — dual-pane explorer with directory tree (left)
/// and file list (right), breadcrumb bar, and action toolbar.
pub(crate) fn render_file_browser_tab(
    app: &mut ClientApp,
    ui: &mut egui::Ui,
    state: &AppState,
    agent_id: &str,
) {
    let agent = state.agents.iter().find(|a| a.name_id == agent_id);
    let browser = state.file_browsers.get(agent_id);

    egui::Frame::default().inner_margin(egui::Margin::symmetric(10, 10)).show(ui, |ui| {
        // ── Agent header ──────────────────────────────────────
        if let Some(agent) = agent {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!("{} File Explorer", agent.name_id)).strong().monospace(),
                );
                ui.separator();
                ui.label(RichText::new(&agent.hostname).strong());
                ui.separator();
                ui.label(format!("{}\\{}", agent.domain_name, agent.username));
            });
        } else {
            ui.label(RichText::new(format!("Agent {agent_id} is no longer present")).weak());
        }

        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);

        // ── Breadcrumb / path bar ─────────────────────────────
        let current_dir = browser
            .and_then(|s| s.current_dir.clone())
            .or_else(|| browser.and_then(|s| s.directories.keys().next().cloned()));

        breadcrumb::render_file_browser_breadcrumb(
            app,
            ui,
            agent_id,
            browser,
            current_dir.as_deref(),
        );

        ui.add_space(4.0);

        // ── Action toolbar ────────────────────────────────────
        breadcrumb::render_file_browser_toolbar(app, ui, agent_id, browser);

        // ── Status messages ───────────────────────────────────
        let browser_status = browser.and_then(|s| s.status_message.as_deref());
        let ui_status = app
            .session_panel
            .file_browser_state
            .get(agent_id)
            .and_then(|s| s.status_message.as_deref());
        if let Some(message) = ui_status.or(browser_status) {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);

        // ── Dual-pane: directory tree (left) + file list (right) ─
        let available = ui.available_size();
        let left_width = (available.x * 0.35).max(180.0);
        ui.horizontal(|ui| {
            // Left pane — directory tree
            ui.allocate_ui(egui::vec2(left_width, available.y - 20.0), |ui| {
                ui.label(RichText::new("Directories").strong());
                ui.separator();
                egui::ScrollArea::both().id_salt(("fb-tree", agent_id)).show(ui, |ui| {
                    if let Some(browser) = browser {
                        if let Some(root) = current_dir.as_deref() {
                            tree::render_directory_tree(app, ui, agent_id, browser, root, 0);
                        } else {
                            ui.label("Resolve cwd to initialize.");
                        }
                    } else {
                        ui.label("No filesystem state yet.");
                    }
                });
            });

            ui.separator();

            // Right pane — file list table
            ui.vertical(|ui| {
                ui.label(RichText::new("Files").strong());
                ui.separator();
                table::render_file_list_table(app, ui, agent_id, browser, current_dir.as_deref());
            });
        });

        // ── Downloads progress ────────────────────────────────
        if let Some(browser) = browser {
            downloads::render_download_progress_section(app, ui, agent_id, browser);
        }
    });
}
