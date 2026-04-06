use eframe::egui::{self, Color32, RichText, Stroke};
use rfd::FileDialog;

use crate::python::{
    PythonRuntime, ScriptDescriptor, ScriptLoadStatus, ScriptOutputEntry, ScriptTabDescriptor,
};
use crate::{
    ClientApp, ScriptManagerAction, script_name_for_display, script_output_color,
    script_output_label, script_status_color, script_status_label,
};

impl ClientApp {
    pub(crate) fn render_script_manager_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Python Scripts");
        ui.separator();

        let Some(runtime) = self.python_runtime.clone() else {
            ui.label("Client Python runtime is not initialized.");
            return;
        };

        let scripts = runtime.script_descriptors();
        let output = runtime.script_output();
        let tabs = runtime.script_tabs();
        self.prune_selected_script(&scripts);
        self.prune_selected_tab(&tabs);

        let loaded_count =
            scripts.iter().filter(|script| script.status == ScriptLoadStatus::Loaded).count();
        let error_count =
            scripts.iter().filter(|script| script.status == ScriptLoadStatus::Error).count();
        let command_count =
            scripts.iter().map(|script| script.registered_command_count).sum::<usize>();
        let tab_count = tabs.len();

        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Loaded: {loaded_count}"));
            ui.separator();
            ui.label(format!("Errors: {error_count}"));
            ui.separator();
            ui.label(format!("Commands: {command_count}"));
            ui.separator();
            ui.label(format!("Tabs: {tab_count}"));
            if let Some(path) =
                self.scripts_dir.clone().or_else(|| self.local_config.resolved_scripts_dir())
            {
                ui.separator();
                ui.monospace(path.display().to_string());
            }
        });
        ui.add_space(6.0);

        ui.horizontal_wrapped(|ui| {
            if ui.button("Load Script").clicked()
                && let Some(path) = FileDialog::new().add_filter("Python", &["py"]).pick_file()
            {
                match runtime.load_script(path.clone()) {
                    Ok(()) => {
                        if let Some(script_name) = script_name_for_display(&path) {
                            self.session_panel.script_manager.selected_script = Some(script_name);
                        }
                        self.session_panel.script_manager.status_message =
                            Some(format!("Loaded {}.", path.display()));
                    }
                    Err(error) => {
                        self.session_panel.script_manager.status_message =
                            Some(format!("Failed to load {}: {error}", path.display()));
                    }
                }
            }

            let selected_script = self.session_panel.script_manager.selected_script.clone();
            if ui
                .add_enabled(selected_script.is_some(), egui::Button::new("Reload Selected"))
                .clicked()
                && let Some(script_name) = selected_script.as_deref()
            {
                self.apply_script_action(
                    &runtime,
                    ScriptManagerAction::Reload(script_name.to_owned()),
                );
            }

            if ui
                .add_enabled(selected_script.is_some(), egui::Button::new("Unload Selected"))
                .clicked()
                && let Some(script_name) = selected_script.as_deref()
            {
                self.apply_script_action(
                    &runtime,
                    ScriptManagerAction::Unload(script_name.to_owned()),
                );
            }
        });

        if let Some(message) = &self.session_panel.script_manager.status_message {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }

        ui.add_space(8.0);
        ui.columns(2, |columns| {
            self.render_script_list_panel(&mut columns[0], &runtime, &scripts);
            self.render_script_output_panel(&mut columns[1], &output);
        });

        if !tabs.is_empty() {
            ui.add_space(8.0);
            self.render_script_tabs_panel(ui, &runtime, &tabs);
        }
    }

    pub(crate) fn render_script_list_panel(
        &mut self,
        ui: &mut egui::Ui,
        runtime: &PythonRuntime,
        scripts: &[ScriptDescriptor],
    ) {
        ui.heading("Loaded Scripts");
        ui.separator();

        if scripts.is_empty() {
            ui.label("No Python scripts are loaded yet.");
            return;
        }

        egui::ScrollArea::vertical().id_salt("python-script-list").max_height(300.0).show(
            ui,
            |ui| {
                for script in scripts {
                    let selected = self.session_panel.script_manager.selected_script.as_deref()
                        == Some(script.name.as_str());
                    egui::Frame::default()
                        .fill(if selected {
                            Color32::from_rgba_unmultiplied(110, 199, 141, 28)
                        } else {
                            Color32::from_rgba_unmultiplied(255, 255, 255, 6)
                        })
                        .stroke(Stroke::new(
                            1.0,
                            Color32::from_rgba_unmultiplied(255, 255, 255, 18),
                        ))
                        .inner_margin(egui::Margin::symmetric(8, 8))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                if ui.selectable_label(selected, &script.name).clicked() {
                                    self.session_panel.script_manager.selected_script =
                                        Some(script.name.clone());
                                }
                                ui.separator();
                                ui.colored_label(
                                    script_status_color(script.status),
                                    script_status_label(script.status),
                                );
                                ui.separator();
                                ui.label(format!("{} cmds", script.registered_command_count));
                            });
                            ui.add_space(2.0);
                            ui.monospace(script.path.display().to_string());
                            if !script.registered_commands.is_empty() {
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(script.registered_commands.join(", "))
                                        .monospace()
                                        .weak(),
                                );
                            }
                            if let Some(error) = &script.error {
                                ui.add_space(4.0);
                                ui.colored_label(Color32::from_rgb(215, 83, 83), error);
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        script.status != ScriptLoadStatus::Loaded,
                                        egui::Button::new("Load"),
                                    )
                                    .clicked()
                                {
                                    self.apply_script_action(
                                        runtime,
                                        ScriptManagerAction::Load(script.path.clone()),
                                    );
                                }
                                if ui.small_button("Reload").clicked() {
                                    self.apply_script_action(
                                        runtime,
                                        ScriptManagerAction::Reload(script.name.clone()),
                                    );
                                }
                                if ui
                                    .add_enabled(
                                        script.status != ScriptLoadStatus::Unloaded,
                                        egui::Button::new("Unload"),
                                    )
                                    .clicked()
                                {
                                    self.apply_script_action(
                                        runtime,
                                        ScriptManagerAction::Unload(script.name.clone()),
                                    );
                                }
                            });
                        });
                    ui.add_space(6.0);
                }
            },
        );
    }

    pub(crate) fn render_script_output_panel(
        &self,
        ui: &mut egui::Ui,
        output: &[ScriptOutputEntry],
    ) {
        ui.heading("Script Output");
        ui.separator();

        egui::ScrollArea::vertical()
            .id_salt("python-script-output")
            .stick_to_bottom(true)
            .max_height(300.0)
            .show(ui, |ui| {
                if output.is_empty() {
                    ui.label("No script output captured yet.");
                    return;
                }

                for entry in output {
                    ui.group(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.monospace(&entry.script_name);
                            ui.separator();
                            ui.colored_label(
                                script_output_color(entry.stream),
                                RichText::new(script_output_label(entry.stream)).monospace(),
                            );
                        });
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(entry.text.trim_end_matches('\n'))
                                .monospace()
                                .color(script_output_color(entry.stream)),
                        );
                    });
                    ui.add_space(4.0);
                }
            });
    }

    pub(crate) fn render_script_tabs_panel(
        &mut self,
        ui: &mut egui::Ui,
        runtime: &PythonRuntime,
        tabs: &[ScriptTabDescriptor],
    ) {
        ui.heading("Script Tabs");
        ui.separator();

        ui.horizontal_wrapped(|ui| {
            for tab in tabs {
                let selected = self.session_panel.script_manager.selected_tab.as_deref()
                    == Some(tab.title.as_str());
                if ui.selectable_label(selected, &tab.title).clicked() {
                    self.session_panel.script_manager.selected_tab = Some(tab.title.clone());
                    if tab.has_callback {
                        self.session_panel.script_manager.status_message =
                            Some(match runtime.activate_tab(&tab.title) {
                                Ok(()) => format!("Activated tab {}.", tab.title),
                                Err(error) => {
                                    format!("Failed to activate tab {}: {error}", tab.title)
                                }
                            });
                    }
                }
            }
        });
        ui.add_space(6.0);

        let selected_title = self
            .session_panel
            .script_manager
            .selected_tab
            .clone()
            .or_else(|| tabs.first().map(|tab| tab.title.clone()));
        let Some(selected_title) = selected_title else {
            ui.label("No script tabs are active.");
            return;
        };
        self.session_panel.script_manager.selected_tab = Some(selected_title.clone());

        let Some(selected_tab) = tabs.iter().find(|tab| tab.title == selected_title) else {
            ui.label("Selected script tab is no longer available.");
            return;
        };

        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&selected_tab.title).strong());
            ui.separator();
            ui.monospace(&selected_tab.script_name);
            if selected_tab.has_callback && ui.button("Refresh").clicked() {
                self.session_panel.script_manager.status_message =
                    Some(match runtime.activate_tab(&selected_tab.title) {
                        Ok(()) => format!("Refreshed tab {}.", selected_tab.title),
                        Err(error) => {
                            format!("Failed to refresh tab {}: {error}", selected_tab.title)
                        }
                    });
            }
        });
        ui.add_space(4.0);

        egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt(("python-script-tab-layout", selected_tab.title.as_str()))
                .max_height(220.0)
                .show(ui, |ui| {
                    if selected_tab.layout.trim().is_empty() {
                        ui.label("This tab has not published any layout yet.");
                    } else {
                        ui.label(RichText::new(&selected_tab.layout).monospace());
                    }
                });
        });
    }

    pub(crate) fn apply_script_action(
        &mut self,
        runtime: &PythonRuntime,
        action: ScriptManagerAction,
    ) {
        let result = match &action {
            ScriptManagerAction::Load(path) => runtime.load_script(path.clone()),
            ScriptManagerAction::Reload(script_name) => runtime.reload_script(script_name),
            ScriptManagerAction::Unload(script_name) => runtime.unload_script(script_name),
        };

        self.session_panel.script_manager.status_message = Some(match result {
            Ok(()) => match action {
                ScriptManagerAction::Load(path) => {
                    if let Some(script_name) = script_name_for_display(&path) {
                        self.session_panel.script_manager.selected_script = Some(script_name);
                    }
                    format!("Loaded {}.", path.display())
                }
                ScriptManagerAction::Reload(script_name) => {
                    self.session_panel.script_manager.selected_script = Some(script_name.clone());
                    format!("Reloaded {script_name}.")
                }
                ScriptManagerAction::Unload(script_name) => {
                    self.session_panel.script_manager.selected_script = Some(script_name.clone());
                    format!("Unloaded {script_name}.")
                }
            },
            Err(error) => match action {
                ScriptManagerAction::Load(path) => {
                    format!("Failed to load {}: {error}", path.display())
                }
                ScriptManagerAction::Reload(script_name) => {
                    format!("Failed to reload {script_name}: {error}")
                }
                ScriptManagerAction::Unload(script_name) => {
                    format!("Failed to unload {script_name}: {error}")
                }
            },
        });
    }

    pub(crate) fn prune_selected_script(&mut self, scripts: &[ScriptDescriptor]) {
        if self
            .session_panel
            .script_manager
            .selected_script
            .as_ref()
            .is_some_and(|selected| scripts.iter().any(|script| &script.name == selected))
        {
            return;
        }

        self.session_panel.script_manager.selected_script =
            scripts.first().map(|script| script.name.clone());
    }

    pub(crate) fn prune_selected_tab(&mut self, tabs: &[ScriptTabDescriptor]) {
        if self
            .session_panel
            .script_manager
            .selected_tab
            .as_ref()
            .is_some_and(|selected| tabs.iter().any(|tab| &tab.title == selected))
        {
            return;
        }

        self.session_panel.script_manager.selected_tab = tabs.first().map(|tab| tab.title.clone());
    }
}
