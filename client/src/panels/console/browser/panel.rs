//! Embedded file browser panel used inside the session console split view.

use eframe::egui::{self, RichText};

use crate::ClientApp;
use crate::transport::AgentFileBrowserState;

use super::{breadcrumb, downloads, tree};

pub(crate) fn render_file_browser_panel(
    app: &mut ClientApp,
    ui: &mut egui::Ui,
    agent_id: &str,
    browser: Option<&AgentFileBrowserState>,
) {
    ui.heading("File Browser");
    ui.separator();

    let current_dir = browser
        .and_then(|state| state.current_dir.clone())
        .or_else(|| browser.and_then(|state| state.directories.keys().next().cloned()));
    breadcrumb::render_file_browser_breadcrumb(app, ui, agent_id, browser, current_dir.as_deref());

    let browser_status = browser.and_then(|state| state.status_message.as_deref());
    let ui_status = app
        .session_panel
        .file_browser_state
        .get(agent_id)
        .and_then(|state| state.status_message.as_deref());
    if let Some(message) = ui_status.or(browser_status) {
        ui.add_space(4.0);
        ui.label(RichText::new(message).weak());
    }

    ui.add_space(6.0);
    breadcrumb::render_file_browser_toolbar(app, ui, agent_id, browser, false);

    ui.add_space(6.0);
    if let Some(browser) = browser {
        if let Some(root) = current_dir.as_deref() {
            tree::render_directory_tree(app, ui, agent_id, browser, root, 0);
        } else {
            ui.label("Request the current working directory to initialize the browser.");
        }

        downloads::render_download_progress_section(app, ui, agent_id, browser);
    } else {
        ui.label("No filesystem state has been received for this agent yet.");
    }
}
