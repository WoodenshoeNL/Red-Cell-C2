//! File browser UI: tab, breadcrumb/toolbar, file grid, embedded panel, downloads, tree.
//!
//! Split across submodules so each stays under the session-size guideline.

mod breadcrumb;
mod downloads;
mod panel;
mod tab;
mod table;
mod tree;

use crate::ClientApp;
use crate::transport::{AgentFileBrowserState, AppState};
use eframe::egui;

impl ClientApp {
    /// Standalone file browser tab — dual-pane explorer with directory tree (left)
    /// and file list (right), breadcrumb bar, and action toolbar.
    pub(crate) fn render_file_browser_tab(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        agent_id: &str,
    ) {
        tab::render_file_browser_tab(self, ui, state, agent_id);
    }

    pub(crate) fn render_file_browser_panel(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
    ) {
        panel::render_file_browser_panel(self, ui, agent_id, browser);
    }
}
