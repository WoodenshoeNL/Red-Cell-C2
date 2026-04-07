use eframe::egui::{self, Color32, Key, RichText, Stroke};

use crate::transport::{AgentConsoleEntry, AgentConsoleEntryKind, AgentFileBrowserState, AppState};
use crate::{
    ClientApp, CompletedDownloadSaveOutcome, HistoryDirection, agent_arch, agent_os,
    apply_completion, apply_history_step, blank_if_empty, breadcrumb_segments,
    build_file_browser_list_task, directory_label, file_entry_label, find_file_entry,
    format_console_prompt, human_size, parent_remote_path, save_completed_download,
    selected_remote_directory, short_task_id, upload_destination,
};

impl ClientApp {
    #[allow(dead_code)]
    pub(crate) fn render_console_tabs(&mut self, ui: &mut egui::Ui) {
        let mut close_agent = None;

        ui.horizontal_wrapped(|ui| {
            for agent_id in self.session_panel.open_consoles.clone() {
                let selected = self.session_panel.selected_console.as_deref() == Some(&agent_id);
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        if ui.selectable_label(selected, &agent_id).clicked() {
                            self.session_panel.selected_console = Some(agent_id.clone());
                        }
                        if ui.small_button("x").clicked() {
                            close_agent = Some(agent_id.clone());
                        }
                    });
                });
            }
        });

        if let Some(agent_id) = close_agent {
            self.session_panel.close_console(&agent_id);
        }
    }

    pub(crate) fn render_single_console(
        &mut self,
        ui: &mut egui::Ui,
        state: &AppState,
        agent_id: &str,
    ) {
        let agent = state.agents.iter().find(|agent| agent.name_id == agent_id);
        let entries = state.agent_consoles.get(agent_id).map(Vec::as_slice).unwrap_or(&[]);
        let browser = state.file_browsers.get(agent_id);
        let status_message = self
            .session_panel
            .console_state
            .get(agent_id)
            .and_then(|console| console.status_message.clone());

        egui::Frame::default()
            .fill(Color32::from_rgba_unmultiplied(255, 255, 255, 6))
            .stroke(Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 18)))
            .inner_margin(egui::Margin::symmetric(10, 10))
            .show(ui, |ui| {
                if let Some(agent) = agent {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(&agent.name_id).strong().monospace());
                        ui.separator();
                        ui.label(RichText::new(&agent.hostname).strong());
                        ui.separator();
                        ui.label(format!("{}\\{}", agent.domain_name, agent.username));
                        ui.separator();
                        ui.label(format!("PID {}", agent.process_pid));
                        ui.separator();
                        ui.label(&agent.process_name);
                        ui.separator();
                        ui.label(format!("Status: {}", agent.status));
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "{} | {} | {}",
                            blank_if_empty(&agent.internal_ip, &agent.external_ip),
                            agent_os(agent),
                            agent_arch(agent)
                        ))
                        .weak(),
                    );
                    if !agent.note.trim().is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new(format!("Note: {}", agent.note)).weak());
                    }
                } else {
                    ui.label(
                        RichText::new(format!("Agent {agent_id} is no longer present")).weak(),
                    );
                }

                if let Some(message) = &status_message {
                    ui.add_space(6.0);
                    ui.colored_label(Color32::from_rgb(232, 182, 83), message);
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                ui.columns(2, |columns| {
                    self.render_file_browser_panel(&mut columns[0], agent_id, browser);
                    self.render_console_output_panel(&mut columns[1], agent_id, entries);
                });

                ui.add_space(8.0);
                self.render_console_input(ui, agent_id);

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                self.render_process_panel(ui, agent, agent_id, state);
            });
    }

    /// Standalone file browser tab — dual-pane explorer with directory tree (left)
    /// and file list (right), breadcrumb bar, and action toolbar.
    pub(crate) fn render_file_browser_tab(
        &mut self,
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
                        RichText::new(format!("{} File Explorer", agent.name_id))
                            .strong()
                            .monospace(),
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

            self.render_file_browser_breadcrumb(ui, agent_id, browser, current_dir.as_deref());

            ui.add_space(4.0);

            // ── Action toolbar ────────────────────────────────────
            self.render_file_browser_toolbar(ui, agent_id, browser);

            // ── Status messages ───────────────────────────────────
            let browser_status = browser.and_then(|s| s.status_message.as_deref());
            let ui_status = self
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
                                self.render_directory_tree(ui, agent_id, browser, root, 0);
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
                    self.render_file_list_table(ui, agent_id, browser, current_dir.as_deref());
                });
            });

            // ── Downloads progress ────────────────────────────────
            if let Some(browser) = browser {
                self.render_download_progress_section(ui, agent_id, browser);
            }
        });
    }

    /// Breadcrumb path bar for the file browser tab.
    pub(crate) fn render_file_browser_breadcrumb(
        &mut self,
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

                    let segment_width = (ui.available_width() / (segments.len() - i).max(1) as f32)
                        .clamp(72.0, 220.0);
                    let button = egui::Button::new(RichText::new(label.as_str()).monospace())
                        .truncate()
                        .small()
                        .frame(false);
                    let mut response =
                        ui.add_sized([segment_width, ui.spacing().interact_size.y], button);
                    if response
                        .intrinsic_size
                        .is_some_and(|size| size.x > response.rect.width() + 0.5)
                    {
                        response = response.on_hover_text(full_path.as_str());
                    }
                    if response.clicked() {
                        self.queue_file_browser_cd(agent_id, full_path);
                        self.queue_file_browser_list(agent_id, full_path);
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
                if response.intrinsic_size.is_some_and(|size| size.x > response.rect.width() + 0.5)
                {
                    response.on_hover_text(path);
                }
            }

            ui.separator();

            if ui.button("Resolve cwd").clicked() {
                self.queue_file_browser_pwd(agent_id);
            }
            if ui.button("Refresh").clicked() {
                if let Some(path) = current_dir {
                    self.queue_file_browser_list(agent_id, path);
                }
            }
            if ui.button("Up").clicked() {
                if let Some(path) = current_dir.and_then(parent_remote_path) {
                    self.queue_file_browser_cd(agent_id, &path);
                    self.queue_file_browser_list(agent_id, &path);
                }
            }

            // Auto-request listing if the current directory is not yet loaded
            let loaded_paths = browser.map(|s| &s.directories);
            let operator = self.current_operator_username();
            {
                let ui_state = self.session_panel.file_browser_state_mut(agent_id);
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
                        self.session_panel.pending_messages.push(message);
                    }
                }
            }
        });
    }

    /// Action toolbar for the file browser tab (Download, Upload, Delete, Set Working Dir).
    pub(crate) fn render_file_browser_toolbar(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
    ) {
        ui.horizontal_wrapped(|ui| {
            let selected_path = self
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
                self.queue_file_browser_cd(agent_id, path);
                self.queue_file_browser_list(agent_id, path);
            }

            if ui
                .add_enabled(
                    selected_entry.is_some_and(|entry| !entry.is_dir),
                    egui::Button::new("Download"),
                )
                .clicked()
            {
                if let Some(path) = selected_path.as_deref() {
                    self.queue_file_browser_download(agent_id, path);
                }
            }

            if ui.button("Upload").clicked() {
                self.queue_file_browser_upload(
                    agent_id,
                    upload_destination(browser, selected_path.as_deref()),
                );
            }

            if ui.add_enabled(selected_path.is_some(), egui::Button::new("Delete")).clicked() {
                if let Some(path) = selected_path.as_deref() {
                    self.queue_file_browser_delete(agent_id, path);
                }
            }

            if let Some(path) = &selected_path {
                ui.separator();
                ui.label(RichText::new(format!("Selected: {path}")).weak().monospace());
            }
        });
    }

    /// Right-pane file list table for the standalone file browser tab.
    pub(crate) fn render_file_list_table(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
        current_dir: Option<&str>,
    ) {
        // Determine the directory to show in the file list — use the selected
        // path if it's a directory, otherwise fall back to the current working
        // directory.
        let selected_path = self
            .session_panel
            .file_browser_state
            .get(agent_id)
            .and_then(|s| s.selected_path.clone());
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
                        sorted.sort_by(|a, b| {
                            b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name))
                        });

                        for entry in sorted {
                            let is_selected = self
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
                                self.session_panel.file_browser_state_mut(agent_id).selected_path =
                                    Some(entry.path.clone());
                            }
                            if response.double_clicked() && entry.is_dir {
                                self.queue_file_browser_cd(agent_id, &entry.path);
                                self.queue_file_browser_list(agent_id, &entry.path);
                            }

                            // Context menu on each entry
                            response.context_menu(|ui| {
                                if entry.is_dir {
                                    if ui.button("Open").clicked() {
                                        self.queue_file_browser_cd(agent_id, &entry.path);
                                        self.queue_file_browser_list(agent_id, &entry.path);
                                        ui.close();
                                    }
                                } else if ui.button("Download").clicked() {
                                    self.queue_file_browser_download(agent_id, &entry.path);
                                    ui.close();
                                }
                                if ui.button("Delete").clicked() {
                                    self.queue_file_browser_delete(agent_id, &entry.path);
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

    pub(crate) fn render_console_output_panel(
        &self,
        ui: &mut egui::Ui,
        agent_id: &str,
        entries: &[AgentConsoleEntry],
    ) {
        ui.heading("Console Output");
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt(("console-output", agent_id))
            .stick_to_bottom(true)
            .max_height(360.0)
            .show(ui, |ui| {
                if entries.is_empty() {
                    ui.label("No console output for this session yet.");
                } else {
                    for entry in entries {
                        self.render_console_entry(ui, entry);
                        ui.add_space(4.0);
                    }
                }
            });
    }

    pub(crate) fn render_file_browser_panel(
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: Option<&AgentFileBrowserState>,
    ) {
        ui.heading("File Browser");
        ui.separator();

        let current_dir = browser
            .and_then(|state| state.current_dir.clone())
            .or_else(|| browser.and_then(|state| state.directories.keys().next().cloned()));
        self.render_file_browser_breadcrumb(ui, agent_id, browser, current_dir.as_deref());

        let browser_status = browser.and_then(|state| state.status_message.as_deref());
        let ui_status = self
            .session_panel
            .file_browser_state
            .get(agent_id)
            .and_then(|state| state.status_message.as_deref());
        if let Some(message) = ui_status.or(browser_status) {
            ui.add_space(4.0);
            ui.label(RichText::new(message).weak());
        }

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let selected_path = self
                .session_panel
                .file_browser_state
                .get(agent_id)
                .and_then(|state| state.selected_path.clone());
            let selected_entry = browser.and_then(|state| {
                selected_path.as_deref().and_then(|path| find_file_entry(state, path))
            });
            let selected_directory = selected_remote_directory(browser, selected_path.as_deref());

            if ui
                .add_enabled(selected_directory.is_some(), egui::Button::new("Set Working Dir"))
                .clicked()
                && let Some(path) = selected_directory.as_deref()
            {
                self.queue_file_browser_cd(agent_id, path);
                self.queue_file_browser_list(agent_id, path);
            }

            if ui
                .add_enabled(
                    selected_entry.is_some_and(|entry| !entry.is_dir),
                    egui::Button::new("Download"),
                )
                .clicked()
            {
                if let Some(path) = selected_path.as_deref() {
                    self.queue_file_browser_download(agent_id, path);
                }
            }

            if ui.button("Upload").clicked() {
                self.queue_file_browser_upload(
                    agent_id,
                    upload_destination(browser, selected_path.as_deref()),
                );
            }

            if ui.add_enabled(selected_path.is_some(), egui::Button::new("Delete")).clicked() {
                if let Some(path) = selected_path.as_deref() {
                    self.queue_file_browser_delete(agent_id, path);
                }
            }
        });

        ui.add_space(6.0);
        if let Some(browser) = browser {
            if let Some(root) = current_dir.as_deref() {
                self.render_directory_tree(ui, agent_id, browser, root, 0);
            } else {
                ui.label("Request the current working directory to initialize the browser.");
            }

            self.render_download_progress_section(ui, agent_id, browser);
        } else {
            ui.label("No filesystem state has been received for this agent yet.");
        }
    }

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
        &mut self,
        ui: &mut egui::Ui,
        agent_id: &str,
        browser: &AgentFileBrowserState,
    ) {
        // Compute the set of non-dismissed completed downloads before borrowing self mutably.
        let pending_completed: Vec<(String, String, Vec<u8>)> = browser
            .completed_downloads
            .iter()
            .filter(|(file_id, _)| {
                !self
                    .session_panel
                    .file_browser_state
                    .get(agent_id)
                    .is_some_and(|s| s.dismissed_downloads.contains(file_id.as_str()))
            })
            .map(|(id, c)| (id.clone(), c.remote_path.clone(), c.data.clone()))
            .collect();

        let has_active = !browser.downloads.is_empty();
        let has_completed = !pending_completed.is_empty();

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
            self.queue_file_browser_download_cancel(agent_id, &file_id);
        }

        // ── Completed downloads awaiting save ──────────────────────
        if !pending_completed.is_empty() {
            ui.add_space(4.0);
            ui.label(RichText::new("Completed — click Save to write to disk:").weak());
        }

        let mut to_dismiss: Vec<String> = Vec::new();
        for (file_id, remote_path, data) in &pending_completed {
            ui.horizontal(|ui| {
                ui.label("✅");
                ui.label(
                    RichText::new(format!("{} ({})", remote_path, human_size(data.len() as u64)))
                        .monospace(),
                );
                if ui.button("Save").clicked() {
                    match save_completed_download(remote_path, data) {
                        CompletedDownloadSaveOutcome::Cancelled => {}
                        CompletedDownloadSaveOutcome::Saved => {
                            to_dismiss.push(file_id.clone());
                        }
                        CompletedDownloadSaveOutcome::WriteFailed(message) => {
                            self.session_panel.file_browser_state_mut(agent_id).status_message =
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
            let ui_state = self.session_panel.file_browser_state_mut(agent_id);
            for file_id in to_dismiss {
                ui_state.dismissed_downloads.insert(file_id);
            }
        }
    }

    pub(crate) fn render_directory_tree(
        &mut self,
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
                                self.render_directory_tree(
                                    ui,
                                    agent_id,
                                    browser,
                                    &entry.path,
                                    depth + 1,
                                );
                            } else {
                                let selected = self
                                    .session_panel
                                    .file_browser_state
                                    .get(agent_id)
                                    .and_then(|state| state.selected_path.as_deref())
                                    == Some(entry.path.as_str());
                                if ui.selectable_label(selected, file_entry_label(entry)).clicked()
                                {
                                    self.session_panel
                                        .file_browser_state_mut(agent_id)
                                        .selected_path = Some(entry.path.clone());
                                }
                            }
                        }
                    }
                } else {
                    ui.label("Waiting for directory listing...");
                }
            });

        if response.header_response.clicked() {
            self.session_panel.file_browser_state_mut(agent_id).selected_path =
                Some(path.to_owned());
        }

        if response.fully_open() && !browser.directories.contains_key(path) {
            let operator = self.current_operator_username();
            let ui_state = self.session_panel.file_browser_state_mut(agent_id);
            if !ui_state.pending_dirs.contains(path) {
                let message = build_file_browser_list_task(agent_id, path, &operator);
                ui_state.pending_dirs.insert(path.to_owned());
                ui_state.status_message = Some(format!("Queued listing for {path}."));
                self.session_panel.pending_messages.push(message);
            }
        }
    }

    pub(crate) fn render_console_entry(&self, ui: &mut egui::Ui, entry: &AgentConsoleEntry) {
        let accent = match entry.kind {
            AgentConsoleEntryKind::Output => Color32::from_rgb(110, 199, 141),
            AgentConsoleEntryKind::Error => Color32::from_rgb(215, 83, 83),
        };

        let task_color = task_id_color(&entry.task_id);

        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                let timestamp = blank_if_empty(&entry.received_at, "pending");
                ui.label(RichText::new(timestamp).weak().monospace());
                ui.separator();
                ui.colored_label(accent, RichText::new(&entry.command_id).monospace());
                if !entry.task_id.is_empty() {
                    ui.separator();
                    let tag = format!("[t:{}]", short_task_id(&entry.task_id));
                    ui.colored_label(task_color, RichText::new(tag).monospace().strong());
                }
                if let Some(command_line) = &entry.command_line {
                    if !command_line.trim().is_empty() {
                        ui.separator();
                        ui.label(RichText::new(command_line).monospace().weak());
                    }
                }
            });
            ui.add_space(2.0);
            ui.label(RichText::new(&entry.output).monospace().color(accent));
        });
    }

    pub(crate) fn render_console_input(&mut self, ui: &mut egui::Ui, agent_id: &str) {
        let mut run_command = false;

        let prompt = format_console_prompt(&self.current_operator_username(), agent_id);

        ui.horizontal(|ui| {
            ui.label(RichText::new(&prompt).strong().monospace());
            let response = {
                let console = self.session_panel.console_state_mut(agent_id);
                ui.add(
                    egui::TextEdit::singleline(&mut console.input)
                        .id_source(("console-input", agent_id))
                        .desired_width(f32::INFINITY)
                        .hint_text("Enter a Demon command (type 'help' for available commands)"),
                )
            };

            let send_requested =
                response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
            let tab_pressed = response.has_focus() && ui.input(|input| input.key_pressed(Key::Tab));
            let up_pressed =
                response.has_focus() && ui.input(|input| input.key_pressed(Key::ArrowUp));
            let down_pressed =
                response.has_focus() && ui.input(|input| input.key_pressed(Key::ArrowDown));

            if up_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_history_step(console, HistoryDirection::Older);
                response.request_focus();
            } else if down_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_history_step(console, HistoryDirection::Newer);
                response.request_focus();
            } else if tab_pressed {
                let console = self.session_panel.console_state_mut(agent_id);
                apply_completion(console);
                response.request_focus();
            }

            if response.changed() {
                let console = self.session_panel.console_state_mut(agent_id);
                console.completion_index = 0;
                console.completion_seed = None;
            }

            run_command = ui.button("Run").clicked() || send_requested;
        });

        if run_command {
            self.submit_console_command(agent_id);
        }
    }
}

/// Deterministically maps a task ID to a display color from a fixed palette.
///
/// The same task ID always produces the same color within a session, making it
/// easy to visually correlate interleaved output chunks.
fn task_id_color(task_id: &str) -> Color32 {
    const PALETTE: &[Color32] = &[
        Color32::from_rgb(100, 180, 255), // sky blue
        Color32::from_rgb(255, 180, 80),  // amber
        Color32::from_rgb(200, 130, 255), // lavender
        Color32::from_rgb(80, 220, 200),  // teal
        Color32::from_rgb(255, 120, 150), // rose
        Color32::from_rgb(160, 230, 80),  // lime
        Color32::from_rgb(255, 220, 60),  // yellow
        Color32::from_rgb(120, 200, 180), // sage
    ];

    if task_id.is_empty() {
        return Color32::from_rgb(160, 160, 160);
    }

    // Hash the task ID to a palette index using a simple FNV-1a fold.
    let hash = task_id
        .bytes()
        .fold(2_166_136_261_u32, |acc, b| acc.wrapping_mul(16_777_619) ^ u32::from(b));
    PALETTE[(hash as usize) % PALETTE.len()]
}
