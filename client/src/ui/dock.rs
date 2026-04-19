//! Dock panel (tab bar + tab content) and Python custom-tab helpers for `ClientApp`.

use eframe::egui::{self, Color32, RichText, Stroke};

use crate::ClientApp;
use crate::state::DockTab;
use crate::transport::AppState;

impl ClientApp {
    /// Top zone: session table (left) + event viewer (right).
    pub(crate) fn render_dock_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
        self.sync_custom_dock_tabs();
        self.session_panel.dock.ensure_selected();

        // ── Tab bar ─────────────────────────────────────────────────
        let mut tab_to_close: Option<DockTab> = None;
        let mut tab_to_select: Option<DockTab> = None;

        ui.horizontal(|ui| {
            for tab in &self.session_panel.dock.open_tabs.clone() {
                let selected = self.session_panel.dock.selected.as_ref() == Some(tab);
                let accent = tab.accent_color();

                let frame = if selected {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(40, 42, 54))
                        .stroke(Stroke::new(2.0, accent))
                        .inner_margin(egui::Margin::symmetric(8, 4))
                } else {
                    egui::Frame::default()
                        .fill(Color32::from_rgb(30, 30, 46))
                        .inner_margin(egui::Margin::symmetric(8, 4))
                };

                let response = frame
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let label_text = if selected {
                                RichText::new(tab.label()).strong().color(Color32::WHITE)
                            } else {
                                RichText::new(tab.label()).color(Color32::from_rgb(160, 160, 170))
                            };
                            if ui.label(label_text).clicked() {
                                tab_to_select = Some(tab.clone());
                            }
                            if tab.closeable()
                                && ui
                                    .button(
                                        RichText::new("X")
                                            .small()
                                            .color(Color32::from_rgb(160, 160, 170)),
                                    )
                                    .clicked()
                            {
                                tab_to_close = Some(tab.clone());
                            }
                        });
                    })
                    .response;

                if response.clicked() {
                    tab_to_select = Some(tab.clone());
                }
            }
        });

        if let Some(tab) = tab_to_close {
            self.session_panel.dock.close_tab(&tab);
        }
        if let Some(tab) = tab_to_select {
            self.session_panel.dock.selected = Some(tab);
        }

        ui.separator();

        // ── Tab content ─────────────────────────────────────────────
        let selected = self.session_panel.dock.selected.clone();
        match selected {
            Some(DockTab::TeamserverChat) => {
                self.render_chat_panel(ui, state);
            }
            Some(DockTab::Listeners) => {
                self.render_listeners_panel(ui, state);
            }
            Some(DockTab::SessionGraph) => {
                self.render_session_graph_panel(ui, state);
            }
            Some(DockTab::Scripts) => {
                self.render_script_manager_panel(ui);
            }
            Some(DockTab::Loot) => {
                self.render_loot_panel(ui, state);
            }
            Some(DockTab::Operators) => {
                self.render_operators_panel(ui, state);
            }
            Some(DockTab::AuditLog) => {
                let local_config = self.local_config.clone();
                self.render_audit_log_panel(ui, state, &local_config);
            }
            Some(DockTab::AgentConsole(ref agent_id)) => {
                let agent_id = agent_id.clone();
                self.session_panel.selected_console = Some(agent_id.clone());
                self.render_single_console(ui, state, &agent_id);
            }
            Some(DockTab::FileBrowser(ref agent_id)) => {
                let agent_id = agent_id.clone();
                self.render_file_browser_tab(ui, state, &agent_id);
            }
            Some(DockTab::ProcessList(ref agent_id)) => {
                let agent_id = agent_id.clone();
                self.render_process_list_tab(ui, state, &agent_id);
            }
            Some(DockTab::CustomTab(ref title)) => {
                let title = title.clone();
                self.render_custom_tab_content(ui, &title);
            }
            None => {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("Open a tab from the View menu or interact with an agent")
                            .weak(),
                    );
                });
            }
        }
    }

    /// Synchronise the dock panel's `CustomTab` entries with currently registered script tabs.
    ///
    /// Opens a `CustomTab` for each newly registered script tab and closes any `CustomTab`
    /// whose backing script tab has been removed (e.g. after a script unload).
    fn sync_custom_dock_tabs(&mut self) {
        let Some(runtime) = self.python_runtime.clone() else {
            // Remove any stale custom tabs that remained after the runtime was torn down.
            let stale: Vec<DockTab> = self
                .session_panel
                .dock
                .open_tabs
                .iter()
                .filter(|t| matches!(t, DockTab::CustomTab(_)))
                .cloned()
                .collect();
            for tab in stale {
                self.session_panel.dock.close_tab(&tab);
            }
            return;
        };

        let registered: Vec<String> = runtime.script_tabs().into_iter().map(|d| d.title).collect();

        // Close tabs that are no longer registered.
        let to_close: Vec<DockTab> = self
            .session_panel
            .dock
            .open_tabs
            .iter()
            .filter(|t| {
                if let DockTab::CustomTab(title) = t { !registered.contains(title) } else { false }
            })
            .cloned()
            .collect();
        for tab in to_close {
            self.session_panel.dock.close_tab(&tab);
        }

        // Open tabs that are newly registered, preserving the current selection.
        let current_selected = self.session_panel.dock.selected.clone();
        for title in &registered {
            let tab = DockTab::CustomTab(title.clone());
            if !self.session_panel.dock.open_tabs.contains(&tab) {
                self.session_panel.dock.open_tabs.push(tab);
            }
        }
        // Restore selection so opening new tabs doesn't hijack the view.
        if current_selected.is_some() {
            self.session_panel.dock.selected = current_selected;
        }
    }

    /// Render the content area for a Python-script-registered custom dock tab.
    fn render_custom_tab_content(&mut self, ui: &mut egui::Ui, title: &str) {
        let Some(runtime) = self.python_runtime.clone() else {
            ui.label("Python runtime is not available.");
            return;
        };

        let tabs = runtime.script_tabs();
        let Some(tab) = tabs.iter().find(|t| t.title == title) else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("This script tab is no longer available.").weak());
            });
            return;
        };

        ui.horizontal_wrapped(|ui| {
            ui.monospace(&tab.script_name);
            if tab.has_callback && ui.button("Refresh").clicked() {
                let result = runtime.activate_tab(title);
                self.session_panel.script_manager.status_message = Some(match result {
                    Ok(()) => format!("Refreshed tab {title}."),
                    Err(e) => format!("Failed to refresh tab {title}: {e}"),
                });
            }
        });
        ui.add_space(4.0);

        egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt(("custom-dock-tab-layout", title)).show(
                ui,
                |ui| {
                    if tab.layout.trim().is_empty() {
                        ui.label("This tab has not published any layout yet.");
                    } else {
                        ui.label(RichText::new(&tab.layout).monospace());
                    }
                },
            );
        });
    }
}
