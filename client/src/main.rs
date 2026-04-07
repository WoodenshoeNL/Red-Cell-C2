mod helpers;
mod known_servers;
mod local_config;
mod login;
mod panels;
mod python;
mod state;
mod tasks;
mod transport;

pub(crate) use helpers::*;
pub(crate) use state::*;
pub(crate) use tasks::*;

// Re-export agent helpers defined in the agents panel so that the inline test
// module (which uses `use super::*`) can find them without modification.
#[cfg(test)]
pub(crate) use panels::agents::{
    agent_ip, agent_matches_filter, agent_sleep_jitter, sort_agents, sort_button_label,
};

// Additional imports used only in the test module via `use super::*`.
#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use python::{ScriptLoadStatus, ScriptOutputStream};
#[cfg(test)]
use red_cell_common::operator::ListenerInfo;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use transport::{LootKind, ProcessEntry};
#[cfg(test)]
use zeroize::Zeroizing;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::Parser;
use eframe::egui::{self, Align, Align2, Color32, Layout, RichText, Stroke};
use known_servers::{KnownServersStore, host_port_from_url};
use local_config::LocalConfig;
use login::{LoginAction, LoginState, render_login_dialog};
use python::PythonRuntime;
use red_cell_common::operator::OperatorMessage;
use rfd::FileDialog;
use transport::{
    AgentConsoleEntry, AgentConsoleEntryKind, AppState, ClientTransport, ConnectionStatus,
    SharedAppState, TlsVerification,
};

const WINDOW_TITLE: &str = "Red Cell Client";
const DEFAULT_SERVER_URL: &str = "wss://127.0.0.1:40056/havoc";
const INITIAL_WINDOW_SIZE: [f32; 2] = [1600.0, 900.0];
const MINIMUM_WINDOW_SIZE: [f32; 2] = [1280.0, 720.0];
const SESSION_GRAPH_HEIGHT: f32 = 280.0;
const SESSION_GRAPH_MIN_ZOOM: f32 = 0.35;
const SESSION_GRAPH_MAX_ZOOM: f32 = 2.5;
const SESSION_GRAPH_ROOT_ID: &str = "__teamserver__";
/// Server-side session TTL (teamserver expires tokens after 1 hour).
const SESSION_TTL: Duration = Duration::from_secs(3600);
/// How far before expiry to show the warning banner.
const SESSION_WARN_BEFORE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
#[command(name = "red-cell-client", about = "Red Cell operator client")]
struct Cli {
    /// Teamserver WebSocket URL.
    #[arg(long, default_value = DEFAULT_SERVER_URL)]
    server: String,
    /// Directory containing client-side Python scripts.
    #[arg(long)]
    scripts_dir: Option<PathBuf>,
    /// Path to a PEM-encoded CA certificate for teamserver verification.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// SHA-256 fingerprint (hex) of the pinned teamserver certificate.
    #[arg(long)]
    cert_fingerprint: Option<String>,
    /// Disable TLS certificate verification entirely. DANGEROUS: makes connections
    /// vulnerable to man-in-the-middle attacks. Prefer --ca-cert or --cert-fingerprint.
    /// Deprecated: TOFU is now the default — this flag will be removed in a future release.
    #[arg(long, default_value_t = false, hide = true)]
    accept_invalid_certs: bool,
    /// Remove a previously trusted server from the known-servers store and exit.
    /// Specify the host:port (e.g. "10.0.0.1:40056") to purge.
    #[arg(long)]
    purge_known_server: Option<String>,
}

/// Application lifecycle phase.
enum AppPhase {
    /// Showing the login dialog, no active transport.
    Login(LoginState),
    /// Transport is active and login message has been sent.
    Authenticating {
        app_state: SharedAppState,
        transport: ClientTransport,
        login_state: LoginState,
    },
    /// Authenticated and showing the main operator UI.
    Connected {
        app_state: SharedAppState,
        #[allow(dead_code)]
        transport: ClientTransport,
    },
}

struct ClientApp {
    phase: AppPhase,
    local_config: LocalConfig,
    known_servers: KnownServersStore,
    cli_server_url: String,
    scripts_dir: Option<PathBuf>,
    tls_verification: TlsVerification,
    session_panel: SessionPanelState,
    outgoing_tx: Option<tokio::sync::mpsc::UnboundedSender<OperatorMessage>>,
    python_runtime: Option<PythonRuntime>,
    /// Whether the Known Servers verification window is open.
    show_known_servers: bool,
    /// Preserved agent/loot state from the most recent session.  Set when a session
    /// expires so the operator can still see their data while re-authenticating.
    retained_app_state: Option<SharedAppState>,
}

impl ClientApp {
    fn new(cli: Cli) -> Result<Self> {
        let local_config = LocalConfig::load();
        let known_servers = KnownServersStore::load();
        let login_state = LoginState::new(&cli.server, &local_config);
        let tls_verification =
            resolve_tls_verification(&cli, &local_config, &known_servers, &cli.server)?;

        Ok(Self {
            phase: AppPhase::Login(login_state),
            local_config,
            known_servers,
            cli_server_url: cli.server,
            scripts_dir: cli.scripts_dir,
            tls_verification,
            session_panel: SessionPanelState {
                sort_column: Some(AgentSortColumn::LastCheckin),
                descending: true,
                ..SessionPanelState::default()
            },
            outgoing_tx: None,
            python_runtime: None,
            show_known_servers: false,
            retained_app_state: None,
        })
    }

    fn snapshot(app_state: &SharedAppState) -> AppState {
        match app_state.lock() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn handle_login_submit(&mut self, ctx: &egui::Context) {
        let AppPhase::Login(login_state) = &mut self.phase else {
            return;
        };

        login_state.set_connecting();

        let server_url = login_state.server_url.trim().to_owned();

        // Re-resolve TLS verification for the actual server URL the user typed,
        // in case it differs from the CLI default (TOFU is per host:port).
        if let Some(host_port) = host_port_from_url(&server_url) {
            if let Some(entry) = self.known_servers.lookup(&host_port) {
                self.tls_verification = TlsVerification::Fingerprint(entry.fingerprint.clone());
            }
        }
        // If a previous session expired while still connected, reuse its app state
        // so that agents, loot, and consoles remain visible during re-authentication.
        let app_state = if let Some(retained) = self.retained_app_state.take() {
            {
                let mut state = match retained.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                state.session_start = None;
                state.operator_info = None;
                state.connection_status = ConnectionStatus::Connecting;
                state.last_auth_error = None;
                state.tls_failure = None;
            }
            retained
        } else {
            Arc::new(Mutex::new(AppState::new(server_url.clone())))
        };
        let scripts_dir =
            self.scripts_dir.clone().or_else(|| self.local_config.resolved_scripts_dir());
        let python_runtime = scripts_dir.as_ref().and_then(|path| match PythonRuntime::initialize(
            app_state.clone(),
            path.clone(),
        ) {
            Ok(runtime) => {
                if let Some(secs) = self.local_config.python_script_timeout_secs {
                    runtime.set_script_timeout(secs);
                }
                Some(runtime)
            }
            Err(error) => {
                tracing::warn!(error = %error, "failed to initialize client python runtime");
                None
            }
        });

        match ClientTransport::spawn(
            server_url.clone(),
            app_state.clone(),
            ctx.clone(),
            python_runtime.clone(),
            self.tls_verification.clone(),
        ) {
            Ok(transport) => {
                let login_message = login_state.build_login_message();
                if let Err(error) = transport.queue_message(login_message) {
                    login_state.set_error(format!("Failed to send login: {error}"));
                    return;
                }
                let outgoing_tx = transport.outgoing_sender();
                if let Some(runtime) = python_runtime.as_ref() {
                    runtime.set_outgoing_sender(outgoing_tx.clone());
                }
                self.outgoing_tx = Some(outgoing_tx);

                self.local_config.server_url = Some(server_url);
                self.local_config.username = Some(login_state.username.trim().to_owned());
                if self.local_config.scripts_dir.is_none() {
                    self.local_config.scripts_dir = scripts_dir.clone();
                }
                if let Err(error) = self.local_config.save() {
                    tracing::warn!(
                        %error,
                        "failed to persist local config — \
                         server URL and username will be lost on next launch",
                    );
                }
                self.python_runtime = python_runtime;

                let login_state_clone = login_state.clone();
                self.phase = AppPhase::Authenticating {
                    app_state,
                    transport,
                    login_state: login_state_clone,
                };
            }
            Err(error) => {
                login_state.set_error(format!("Connection failed: {error}"));
            }
        }
    }

    /// Handle the user trusting (or re-trusting) a server certificate.
    ///
    /// Stores the fingerprint in the known-servers file keyed by host:port,
    /// updates the TLS verification mode to pin against that fingerprint, and
    /// also persists the fingerprint in the legacy per-client config for
    /// backwards compatibility.
    fn handle_trust_certificate(&mut self, fingerprint: String) {
        let server_url = match &self.phase {
            AppPhase::Login(login_state) => login_state.server_url.trim().to_owned(),
            _ => self.cli_server_url.clone(),
        };
        if let Some(host_port) = host_port_from_url(&server_url) {
            self.known_servers.trust(&host_port, &fingerprint, None);
            if let Err(error) = self.known_servers.save() {
                tracing::warn!(
                    %error,
                    "failed to persist certificate trust — \
                     TOFU decision will be lost on next launch",
                );
            }
        }
        // Also keep the legacy global fingerprint for backwards compat.
        self.local_config.cert_fingerprint = Some(fingerprint.clone());
        self.tls_verification = TlsVerification::Fingerprint(fingerprint);
        if let Err(error) = self.local_config.save() {
            tracing::warn!(
                %error,
                "failed to persist pinned certificate fingerprint — \
                 TLS trust decision will be lost on next launch",
            );
        }
    }

    fn check_auth_response(&mut self) {
        let (snapshot, error_message) = match &self.phase {
            AppPhase::Authenticating { app_state, .. } => {
                let snap = Self::snapshot(app_state);
                let error = match &snap.connection_status {
                    ConnectionStatus::Error(msg) => Some(msg.clone()),
                    // The transport may overwrite an Error state with Retrying before the
                    // UI gets a chance to observe Error. Fall back to the stored auth error
                    // so the login dialog shows the actual failure reason.
                    // If the server closed without sending an explicit auth error (e.g.
                    // rejected credentials via WebSocket close), use the disconnect reason.
                    ConnectionStatus::Retrying(reason) => {
                        snap.last_auth_error.clone().or_else(|| Some(reason.clone()))
                    }
                    ConnectionStatus::Disconnected => snap.last_auth_error.clone(),
                    _ => None,
                };
                (snap, error)
            }
            _ => return,
        };

        if snapshot.operator_info.is_some() {
            let placeholder =
                AppPhase::Login(LoginState::new(&self.cli_server_url, &self.local_config));
            let old_phase = std::mem::replace(&mut self.phase, placeholder);
            if let AppPhase::Authenticating { app_state, transport, .. } = old_phase {
                self.phase = AppPhase::Connected { app_state, transport };
            }
            return;
        }

        if let Some(error_msg) = error_message {
            let tls_failure = snapshot.tls_failure.clone();
            let placeholder =
                AppPhase::Login(LoginState::new(&self.cli_server_url, &self.local_config));
            let old_phase = std::mem::replace(&mut self.phase, placeholder);
            if let AppPhase::Authenticating { mut login_state, .. } = old_phase {
                login_state.set_error(error_msg);
                if let Some(failure) = tls_failure {
                    login_state.set_tls_failure(failure);
                }
                self.outgoing_tx = None;
                self.phase = AppPhase::Login(login_state);
            }
        }
    }

    /// Check whether the active session has passed the server-side TTL.
    ///
    /// If expired, transitions from `Connected` back to `Login`, stashing the current
    /// `AppState` in `retained_app_state` so agents and loot remain visible while the
    /// operator re-enters their credentials.
    fn check_session_expiry(&mut self) {
        let AppPhase::Connected { app_state, .. } = &self.phase else {
            return;
        };
        let session_start = match app_state.lock() {
            Ok(guard) => guard.session_start,
            Err(poisoned) => poisoned.into_inner().session_start,
        };
        let Some(start) = session_start else {
            return;
        };
        if start.elapsed() < SESSION_TTL {
            return;
        }

        let placeholder =
            AppPhase::Login(LoginState::new(&self.cli_server_url, &self.local_config));
        let old_phase = std::mem::replace(&mut self.phase, placeholder);
        if let AppPhase::Connected { app_state, .. } = old_phase {
            self.outgoing_tx = None;
            self.retained_app_state = Some(app_state);
        }
    }

    fn render_current_phase(
        &mut self,
        ctx: &egui::Context,
        fallback_app_state: Option<SharedAppState>,
    ) {
        match &mut self.phase {
            AppPhase::Login(login_state) => {
                let action = render_login_dialog(ctx, login_state);
                match action {
                    LoginAction::Submit => {
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::TrustCertificate(fingerprint)
                    | LoginAction::AcceptChangedCertificate(fingerprint) => {
                        self.handle_trust_certificate(fingerprint);
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::Waiting => {}
                }
            }
            AppPhase::Authenticating { .. } => {
                if let Some(app_state_ref) = fallback_app_state {
                    let snapshot = Self::snapshot(&app_state_ref);
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.with_layout(Layout::top_down(Align::Center), |ui| {
                            ui.add_space(ui.available_height() * 0.35);
                            ui.heading("Authenticating...");
                            ui.add_space(8.0);
                            ui.colored_label(
                                snapshot.connection_status.color(),
                                snapshot.connection_status.label(),
                            );
                        });
                    });
                }
            }
            AppPhase::Connected { app_state, .. } => {
                let app_state_ref = app_state.clone();
                self.render_main_ui(ctx, &app_state_ref);
            }
        }
    }

    fn render_main_ui(&mut self, ctx: &egui::Context, app_state: &SharedAppState) {
        let snapshot = Self::snapshot(app_state);

        // ── Menu bar (top) ──────────────────────────────────────────
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.render_menu_bar(ui, &snapshot);
        });

        // ── Status bar (bottom) ─────────────────────────────────────
        egui::TopBottomPanel::bottom("status_bar").exact_height(22.0).show(ctx, |ui| {
            self.render_status_bar(ui, &snapshot);
        });

        // ── Bottom dock panel (tabbed) ──────────────────────────────
        egui::TopBottomPanel::bottom("dock_panel")
            .resizable(true)
            .default_height(350.0)
            .min_height(120.0)
            .show(ctx, |ui| {
                self.render_dock_panel(ui, &snapshot);
            });

        // ── Central panel: top half with session table + event viewer
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_top_zone(ui, &snapshot);
        });

        // ── Modal dialogs ───────────────────────────────────────────
        self.render_note_editor(ctx, app_state);
        self.render_process_injection_dialog(ctx);
        self.render_listener_dialog(ctx, &snapshot);
        self.render_payload_dialog(ctx, &snapshot, app_state);
        self.render_known_servers_window(ctx);

        if self.session_panel.pending_mark_all_read {
            self.session_panel.pending_mark_all_read = false;
            match app_state.lock() {
                Ok(mut state) => state.event_log.mark_all_read(),
                Err(poisoned) => poisoned.into_inner().event_log.mark_all_read(),
            }
        }

        self.flush_pending_messages();
        self.render_session_expiry_banner(ctx, &snapshot);
    }

    /// Non-blocking warning banner shown 5 minutes before the session expires.
    fn render_session_expiry_banner(&self, ctx: &egui::Context, state: &AppState) {
        let Some(start) = state.session_start else {
            return;
        };
        let elapsed = start.elapsed();
        if elapsed < SESSION_TTL.saturating_sub(SESSION_WARN_BEFORE) {
            return;
        }
        if elapsed >= SESSION_TTL {
            return;
        }
        let remaining = SESSION_TTL - elapsed;
        let mins = remaining.as_secs() / 60;
        let secs = remaining.as_secs() % 60;

        egui::Window::new("session_expiry_banner")
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .anchor(Align2::CENTER_TOP, [0.0, 30.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        Color32::from_rgb(255, 165, 0),
                        format!(
                            "Session expires in {mins}:{secs:02} — save your work and re-authenticate."
                        ),
                    );
                });
            });
    }

    /// Havoc-style menu bar: Havoc, View, Attack, Scripts, Help.
    fn render_menu_bar(&mut self, ui: &mut egui::Ui, state: &AppState) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("Red Cell", |ui| {
                ui.label(format!(
                    "Operator: {}",
                    state.operator_info.as_ref().map_or("—", |op| op.username.as_str())
                ));
                ui.label(format!("Server: {}", state.server_url));
                ui.separator();
                let status_color = state.connection_status.color();
                ui.colored_label(status_color, state.connection_status.label());
                ui.separator();
                if ui.button("Disconnect").clicked() {
                    ui.close();
                }
                ui.separator();
                if ui.button("Known Servers…").clicked() {
                    self.show_known_servers = true;
                    ui.close();
                }
            });

            ui.menu_button("View", |ui| {
                if ui.button("Event Viewer").clicked() {
                    self.session_panel.dock.event_viewer_open =
                        !self.session_panel.dock.event_viewer_open;
                    ui.close();
                }
                ui.separator();
                if ui.button("Teamserver Chat").clicked() {
                    self.session_panel.dock.open_tab(DockTab::TeamserverChat);
                    ui.close();
                }
                if ui.button("Listeners").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Listeners);
                    ui.close();
                }
                if ui.button("Session Graph").clicked() {
                    self.session_panel.dock.open_tab(DockTab::SessionGraph);
                    ui.close();
                }
                if ui.button("Loot").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Loot);
                    ui.close();
                }
            });

            ui.menu_button("Attack", |ui| {
                if ui.button("Payload").clicked() {
                    if self.session_panel.payload_dialog.is_none() {
                        self.session_panel.payload_dialog = Some(PayloadDialogState::new());
                    }
                    ui.close();
                }
            });

            ui.menu_button("Scripts", |ui| {
                if ui.button("Script Manager").clicked() {
                    self.session_panel.dock.open_tab(DockTab::Scripts);
                    ui.close();
                }
            });

            ui.menu_button("Help", |ui| {
                ui.label("Red Cell C2 — Havoc rewrite in Rust");
                ui.label("https://github.com/…");
            });
        });
    }

    /// Bottom status bar showing operator name and remaining session time.
    fn render_status_bar(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal_centered(|ui| {
            let operator = state.operator_info.as_ref().map_or("—", |op| op.username.as_str());
            ui.label(RichText::new(operator).monospace().small());

            if let Some(start) = state.session_start {
                let elapsed = start.elapsed();
                if elapsed < SESSION_TTL {
                    let remaining = SESSION_TTL - elapsed;
                    let mins = remaining.as_secs() / 60;
                    let secs = remaining.as_secs() % 60;
                    let (label_text, color) = if remaining <= SESSION_WARN_BEFORE {
                        (
                            format!("  session expires in {mins}:{secs:02}"),
                            Color32::from_rgb(255, 165, 0), // orange
                        )
                    } else {
                        (format!("  session {mins}:{secs:02}"), Color32::from_rgb(120, 120, 120))
                    };
                    ui.label(RichText::new(label_text).monospace().small().color(color));
                }
            }
        });
    }

    /// Top zone: session table (left) + event viewer (right).
    fn render_dock_panel(&mut self, ui: &mut egui::Ui, state: &AppState) {
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

    fn render_note_editor(&mut self, ctx: &egui::Context, app_state: &SharedAppState) {
        let Some(editor) = &mut self.session_panel.note_editor else {
            return;
        };

        let mut keep_open = true;
        let mut save_note = false;
        let mut cancel_note = false;
        let title = format!("Agent Note {}", editor.agent_id);
        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_size([420.0, 220.0])
            .open(&mut keep_open)
            .show(ctx, |ui| {
                ui.label("Operator note");
                ui.add(
                    egui::TextEdit::multiline(&mut editor.note)
                        .desired_rows(8)
                        .hint_text("Add operator context for this agent"),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save_note = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel_note = true;
                    }
                });
            });

        if save_note {
            let agent_id = editor.agent_id.clone();
            let note = editor.note.trim().to_owned();
            let operator = match app_state.lock() {
                Ok(mut state) => {
                    state.update_agent_note(&agent_id, note.clone());
                    state
                        .operator_info
                        .as_ref()
                        .map(|operator| operator.username.clone())
                        .unwrap_or_default()
                }
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    state.update_agent_note(&agent_id, note.clone());
                    state
                        .operator_info
                        .as_ref()
                        .map(|operator| operator.username.clone())
                        .unwrap_or_default()
                }
            };
            self.session_panel.pending_messages.push(build_note_task(&agent_id, &note, &operator));
            self.session_panel.status_message = Some(format!("Updated note for {agent_id}."));
            self.session_panel.note_editor = None;
            ctx.request_repaint();
        } else if cancel_note || !keep_open {
            self.session_panel.note_editor = None;
        }
    }

    fn submit_console_command(&mut self, agent_id: &str) {
        let operator = self.current_operator_username();
        let python_runtime = self.python_runtime.clone();

        let console = self.session_panel.console_state_mut(agent_id);
        let command_line = console.input.trim().to_owned();
        if command_line.is_empty() {
            return;
        }

        // Handle local client-side commands first.
        if let Some(output) = handle_local_command(&command_line) {
            push_history_entry(console, &command_line);
            console.input.clear();
            self.inject_console_entry(agent_id, &command_line, &output);
            return;
        }

        if let Some(runtime) = python_runtime {
            match runtime.execute_registered_command(agent_id, &command_line) {
                Ok(true) => {
                    push_history_entry(console, &command_line);
                    console.input.clear();
                    console.status_message =
                        Some(format!("Executed script command `{command_line}`."));
                    return;
                }
                Ok(false) => {}
                Err(error) => {
                    console.status_message =
                        Some(format!("Script command `{command_line}` failed: {error}"));
                    return;
                }
            }
        }

        match build_console_task(agent_id, &command_line, &operator) {
            Ok(message) => {
                let task_id = agent_task_id(&message).unwrap_or_default();
                push_history_entry(console, &command_line);
                console.input.clear();
                console.status_message = None;
                // Show the outgoing task ID immediately so operators can correlate output.
                let submitted_output =
                    format!("→ [t:{}] {}", short_task_id(&task_id), command_line);
                self.inject_console_entry_with_task(
                    agent_id,
                    &command_line,
                    &submitted_output,
                    &task_id,
                );
                self.session_panel.pending_messages.push(message);
            }
            Err(error) => {
                console.status_message = Some(error);
            }
        }
    }

    /// Inserts a locally-generated console entry into the shared app state.
    fn inject_console_entry(&self, agent_id: &str, command_line: &str, output: &str) {
        self.inject_console_entry_with_task(agent_id, command_line, output, "");
    }

    fn inject_console_entry_with_task(
        &self,
        agent_id: &str,
        command_line: &str,
        output: &str,
        task_id: &str,
    ) {
        let app_state = match &self.phase {
            AppPhase::Connected { app_state, .. } | AppPhase::Authenticating { app_state, .. } => {
                app_state
            }
            AppPhase::Login(_) => return,
        };
        let mut state = match app_state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.agent_consoles.entry(agent_id.to_owned()).or_default().push(AgentConsoleEntry {
            kind: AgentConsoleEntryKind::Output,
            command_id: "local".to_owned(),
            task_id: task_id.to_owned(),
            received_at: String::new(),
            command_line: Some(command_line.to_owned()),
            output: output.to_owned(),
        });
    }

    fn current_operator_username(&self) -> String {
        match &self.phase {
            AppPhase::Connected { app_state, .. } | AppPhase::Authenticating { app_state, .. } => {
                let snapshot = Self::snapshot(app_state);
                snapshot.operator_info.map(|info| info.username).unwrap_or_default()
            }
            AppPhase::Login(_) => String::new(),
        }
    }

    fn build_file_browser_list_message(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Option<OperatorMessage> {
        Some(build_file_browser_list_task(agent_id, path, &self.current_operator_username()))
    }

    fn queue_process_refresh(&mut self, agent_id: &str) {
        let message = build_process_list_task(agent_id, &self.current_operator_username());
        self.session_panel.process_state_mut(agent_id).status_message =
            Some("Queued `ps`.".to_owned());
        self.session_panel.pending_messages.push(message);
    }

    fn queue_process_kill(&mut self, agent_id: &str, pid: u32) {
        let message = build_process_kill_task(agent_id, pid, &self.current_operator_username());
        self.session_panel.process_state_mut(agent_id).status_message =
            Some(format!("Queued process kill for PID {pid}."));
        self.session_panel.pending_messages.push(message);
    }

    fn submit_process_injection(&mut self) {
        let Some(dialog) = self.session_panel.process_injection.clone() else {
            return;
        };

        let shellcode_path = dialog.shellcode_path.trim();
        if shellcode_path.is_empty() {
            if let Some(dialog_state) = self.session_panel.process_injection.as_mut() {
                dialog_state.status_message = Some("Select a shellcode file first.".to_owned());
            }
            return;
        }

        match std::fs::read(shellcode_path) {
            Ok(binary) => {
                let operator = self.current_operator_username();
                let message = build_process_injection_task(
                    &dialog.agent_id,
                    dialog.pid,
                    &dialog.arch,
                    dialog.technique,
                    &binary,
                    &dialog.arguments,
                    dialog.action,
                    &operator,
                );
                self.session_panel.process_state_mut(&dialog.agent_id).status_message =
                    Some(format!(
                        "Queued {} for PID {}.",
                        dialog.action.label().to_ascii_lowercase(),
                        dialog.pid
                    ));
                self.session_panel.pending_messages.push(message);
                self.session_panel.process_injection = None;
            }
            Err(error) => {
                if let Some(dialog_state) = self.session_panel.process_injection.as_mut() {
                    dialog_state.status_message =
                        Some(format!("Failed to read shellcode file: {error}"));
                }
            }
        }
    }

    fn queue_file_browser_pwd(&mut self, agent_id: &str) {
        let message = build_file_browser_pwd_task(agent_id, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some("Queued `pwd`.".to_owned());
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_list(&mut self, agent_id: &str, path: &str) {
        if let Some(message) = self.build_file_browser_list_message(agent_id, path) {
            let ui_state = self.session_panel.file_browser_state_mut(agent_id);
            ui_state.pending_dirs.insert(path.to_owned());
            ui_state.status_message = Some(format!("Queued listing for {path}."));
            self.session_panel.pending_messages.push(message);
        }
    }

    fn queue_file_browser_cd(&mut self, agent_id: &str, path: &str) {
        let message = build_file_browser_cd_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued directory change to {path}."));
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_download(&mut self, agent_id: &str, path: &str) {
        let message =
            build_file_browser_download_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued download for {path}."));
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_delete(&mut self, agent_id: &str, path: &str) {
        let message =
            build_file_browser_delete_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued delete for {path}."));
        self.session_panel.pending_messages.push(message);
    }

    fn queue_file_browser_upload(&mut self, agent_id: &str, destination_dir: Option<String>) {
        let Some(destination_dir) = destination_dir else {
            self.session_panel.file_browser_state_mut(agent_id).status_message = Some(
                "Select a directory or resolve the current working directory first.".to_owned(),
            );
            return;
        };

        let Some(local_path) = FileDialog::new().pick_file() else {
            return;
        };

        match std::fs::read(&local_path) {
            Ok(bytes) => {
                let file_name =
                    local_path.file_name().and_then(|value| value.to_str()).unwrap_or("upload.bin");
                let remote_path = join_remote_path(&destination_dir, file_name);
                let message = build_file_browser_upload_task(
                    agent_id,
                    &remote_path,
                    &bytes,
                    &self.current_operator_username(),
                );
                self.session_panel.file_browser_state_mut(agent_id).status_message =
                    Some(format!("Queued upload to {remote_path}."));
                self.session_panel.pending_messages.push(message);
            }
            Err(error) => {
                self.session_panel.file_browser_state_mut(agent_id).status_message =
                    Some(format!("Failed to read local file: {error}"));
            }
        }
    }

    fn queue_file_browser_download_cancel(&mut self, agent_id: &str, file_id: &str) {
        let operator = self.current_operator_username();
        if let Some(message) = build_transfer_stop_task(agent_id, file_id, &operator) {
            self.session_panel.file_browser_state_mut(agent_id).status_message =
                Some(format!("Queued cancel for download {file_id}."));
            self.session_panel.pending_messages.push(message);
        } else {
            self.session_panel.file_browser_state_mut(agent_id).status_message =
                Some(format!("Could not build cancel message: invalid file ID {file_id}."));
        }
    }

    fn flush_pending_messages(&mut self) {
        if self.session_panel.pending_messages.is_empty() {
            return;
        }

        let Some(outgoing_tx) = &self.outgoing_tx else {
            self.session_panel.status_message = Some(
                "Session action could not be sent because the transport is unavailable.".to_owned(),
            );
            self.session_panel.pending_messages.clear();
            return;
        };

        for message in self.session_panel.pending_messages.drain(..) {
            if outgoing_tx.send(message).is_err() {
                self.session_panel.status_message =
                    Some("Session action could not be queued for delivery.".to_owned());
                break;
            }
        }
    }

    /// Render the Known Servers verification window.
    ///
    /// Shows every pinned teamserver fingerprint with its trust timestamps and lets
    /// the operator mark entries as explicitly verified or remove them entirely.
    fn render_known_servers_window(&mut self, ctx: &egui::Context) {
        if !self.show_known_servers {
            return;
        }

        // Collect rows so we can mutate `known_servers` after the UI loop.
        let entries: Vec<(String, known_servers::KnownServer)> =
            self.known_servers.iter().map(|(k, v)| (k.to_owned(), v.clone())).collect();

        let mut confirm_key: Option<String> = None;
        let mut remove_key: Option<String> = None;
        let mut open = true;

        egui::Window::new("Known Servers")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(720.0)
            .default_height(340.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(
                    "Review pinned teamserver certificate fingerprints. \
                     Verify each fingerprint over a trusted out-of-band channel \
                     before marking it as confirmed.",
                );
                ui.add_space(8.0);

                if entries.is_empty() {
                    ui.colored_label(
                        Color32::from_rgb(160, 160, 170),
                        "No servers are pinned yet. Connect to a teamserver to add one.",
                    );
                    return;
                }

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (host_port, entry) in &entries {
                        ui.group(|ui| {
                            ui.set_min_width(ui.available_width());

                            ui.horizontal(|ui| {
                                ui.label(RichText::new(host_port).strong().monospace());
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui
                                        .button(
                                            RichText::new("Remove")
                                                .color(Color32::from_rgb(215, 83, 83)),
                                        )
                                        .on_hover_text("Remove this server from the trusted list")
                                        .clicked()
                                    {
                                        remove_key = Some(host_port.clone());
                                    }
                                    let confirmed = entry.confirmed_at.is_some();
                                    if ui
                                        .add_enabled(
                                            !confirmed,
                                            egui::Button::new(if confirmed {
                                                "✓ Verified"
                                            } else {
                                                "Mark as verified"
                                            }),
                                        )
                                        .on_hover_text(if confirmed {
                                            "Fingerprint was explicitly confirmed by an operator"
                                        } else {
                                            "Record that you have verified this fingerprint \
                                             over a trusted out-of-band channel"
                                        })
                                        .clicked()
                                    {
                                        confirm_key = Some(host_port.clone());
                                    }
                                });
                            });

                            ui.add_space(4.0);
                            ui.label(RichText::new("Fingerprint:").small());
                            ui.add(
                                egui::TextEdit::singleline(&mut entry.fingerprint.clone())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .interactive(true),
                            );

                            ui.add_space(2.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("First trusted: {}", entry.first_seen))
                                        .small()
                                        .color(Color32::from_rgb(140, 140, 150)),
                                );
                                if let Some(confirmed_at) = &entry.confirmed_at {
                                    ui.separator();
                                    ui.label(
                                        RichText::new(format!("Confirmed: {confirmed_at}"))
                                            .small()
                                            .color(Color32::from_rgb(100, 200, 120)),
                                    );
                                }
                            });

                            if let Some(comment) = &entry.comment {
                                ui.label(
                                    RichText::new(comment)
                                        .small()
                                        .italics()
                                        .color(Color32::from_rgb(160, 160, 170)),
                                );
                            }
                        });
                        ui.add_space(4.0);
                    }
                });
            });

        if !open {
            self.show_known_servers = false;
        }
        if let Some(key) = confirm_key {
            if self.known_servers.confirm(&key) {
                let _ = self.known_servers.save();
            }
        }
        if let Some(key) = remove_key {
            self.known_servers.remove(&key);
            let _ = self.known_servers.save();
        }
    }
}

impl eframe::App for ClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match &self.phase {
            AppPhase::Login(_) => {
                let AppPhase::Login(login_state) = &mut self.phase else {
                    return;
                };
                let action = render_login_dialog(ctx, login_state);
                match action {
                    LoginAction::Submit => {
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::TrustCertificate(fingerprint)
                    | LoginAction::AcceptChangedCertificate(fingerprint) => {
                        self.handle_trust_certificate(fingerprint);
                        self.handle_login_submit(ctx);
                    }
                    LoginAction::Waiting => {}
                }
            }
            AppPhase::Authenticating { app_state, .. } => {
                let app_state_ref = app_state.clone();
                self.check_auth_response();
                self.render_current_phase(ctx, Some(app_state_ref));
            }
            AppPhase::Connected { app_state, .. } => {
                let app_state_ref = app_state.clone();
                self.check_session_expiry();
                // Still Connected after expiry check?
                if matches!(self.phase, AppPhase::Connected { .. }) {
                    self.render_main_ui(ctx, &app_state_ref);
                    // Drive the session countdown even when no server events arrive.
                    ctx.request_repaint_after(Duration::from_secs(10));
                }
            }
        }
    }
}

/// Validate that a certificate fingerprint is a well-formed SHA-256 hex digest.
///
/// Returns the fingerprint unchanged if valid, or an error describing why it is malformed.
fn validate_fingerprint(fingerprint: &str, source: &str) -> Result<String> {
    if fingerprint.len() != 64 {
        return Err(anyhow!(
            "invalid certificate fingerprint from {source}: expected 64 hex characters \
             (SHA-256 digest), got {} characters",
            fingerprint.len()
        ));
    }
    if !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid certificate fingerprint from {source}: contains non-hex characters"
        ));
    }
    Ok(fingerprint.to_owned())
}

/// Determine the TLS verification mode from CLI flags, falling back to known-servers
/// TOFU store, then local config.
///
/// Precedence: CLI `--accept-invalid-certs` > CLI `--cert-fingerprint` > CLI `--ca-cert`
///           > known-servers TOFU store > config `cert_fingerprint` > config `ca_cert`
///           > system root CAs (with fingerprint capture for TOFU prompts).
///
/// Returns an error if a provided fingerprint is not a valid SHA-256 hex digest.
fn resolve_tls_verification(
    cli: &Cli,
    config: &LocalConfig,
    known_servers: &KnownServersStore,
    server_url: &str,
) -> Result<TlsVerification> {
    if cli.accept_invalid_certs {
        tracing::warn!("--accept-invalid-certs is deprecated; TOFU is now the default TLS mode");
        return Ok(TlsVerification::DangerousSkipVerify);
    }
    if let Some(fingerprint) = &cli.cert_fingerprint {
        let validated = validate_fingerprint(fingerprint, "--cert-fingerprint")?;
        return Ok(TlsVerification::Fingerprint(validated));
    }
    if let Some(ca_path) = &cli.ca_cert {
        return Ok(TlsVerification::CustomCa(ca_path.clone()));
    }
    // TOFU: check the known-servers store for a previously trusted fingerprint.
    if let Some(host_port) = host_port_from_url(server_url) {
        if let Some(entry) = known_servers.lookup(&host_port) {
            return Ok(TlsVerification::Fingerprint(entry.fingerprint.clone()));
        }
    }
    if let Some(fingerprint) = &config.cert_fingerprint {
        let validated = validate_fingerprint(fingerprint, "config file")?;
        return Ok(TlsVerification::Fingerprint(validated));
    }
    if let Some(ca_path) = &config.ca_cert {
        return Ok(TlsVerification::CustomCa(ca_path.clone()));
    }
    // Default: standard CA verification with fingerprint capture.
    // For self-signed teamservers this will fail with UnknownIssuer,
    // triggering the TOFU prompt in the login UI.
    Ok(TlsVerification::CertificateAuthority)
}

/// Build an egui `Visuals` matching Havoc C2's dark navy theme.
fn havoc_dark_theme() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();

    // Havoc background: dark navy (~#1a1a2e / #16162a)
    let bg_dark = Color32::from_rgb(22, 22, 42);
    let bg_panel = Color32::from_rgb(26, 26, 46);
    let bg_widget = Color32::from_rgb(36, 36, 60);
    let bg_widget_hover = Color32::from_rgb(46, 46, 76);
    let bg_widget_active = Color32::from_rgb(56, 56, 90);
    let accent = Color32::from_rgb(140, 80, 200); // purple accent
    let text_primary = Color32::from_rgb(220, 220, 230);
    let text_secondary = Color32::from_rgb(160, 160, 180);

    visuals.panel_fill = bg_panel;
    visuals.window_fill = bg_dark;
    visuals.extreme_bg_color = bg_dark;
    visuals.faint_bg_color = Color32::from_rgb(30, 30, 50);

    // Widget styles
    visuals.widgets.noninteractive.bg_fill = bg_panel;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, text_secondary);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(50, 50, 70));

    visuals.widgets.inactive.bg_fill = bg_widget;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, text_primary);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(60, 60, 80));

    visuals.widgets.hovered.bg_fill = bg_widget_hover;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, accent);

    visuals.widgets.active.bg_fill = bg_widget_active;
    visuals.widgets.active.fg_stroke = Stroke::new(2.0, Color32::WHITE);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, accent);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(140, 80, 200, 80);
    visuals.selection.stroke = Stroke::new(1.0, accent);

    // Window shadow + separator
    visuals.window_shadow =
        egui::Shadow { offset: [0, 2], blur: 8, spread: 0, color: Color32::from_black_alpha(120) };
    visuals.popup_shadow = visuals.window_shadow;

    visuals.override_text_color = Some(text_primary);

    visuals
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle --purge-known-server: remove the entry and exit.
    if let Some(host_port) = &cli.purge_known_server {
        let mut store = KnownServersStore::load();
        if store.remove(host_port) {
            store.save().map_err(|e| anyhow::anyhow!("failed to save known-servers: {e}"))?;
            println!("Removed {host_port} from known servers.");
        } else {
            println!("No entry found for {host_port} in known servers.");
        }
        return Ok(());
    }

    launch_client(cli)
}

fn launch_client(cli: Cli) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(INITIAL_WINDOW_SIZE)
            .with_min_inner_size(MINIMUM_WINDOW_SIZE),
        ..Default::default()
    };

    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(move |creation_context| {
            creation_context.egui_ctx.set_visuals(havoc_dark_theme());
            let app = ClientApp::new(cli)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(Box::new(app) as Box<dyn eframe::App>)
        }),
    )
    .map_err(|error| anyhow!("failed to start egui application: {error}"))
}

/// Returns the display colour for an operator role badge.

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use panels::session_graph::{
        agent_is_active_status, build_session_graph, session_graph_status_color,
    };
    use red_cell_common::demon::DemonCommand;
    use red_cell_common::operator::{AgentTaskInfo, EventCode, MessageHead};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};
    use transport::{AgentFileBrowserState, AgentSummary, FileBrowserEntry, LootItem};

    static EXPORT_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn lock_export_test() -> MutexGuard<'static, ()> {
        EXPORT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn cli_uses_default_server_url() {
        let cli = Cli::parse_from(["red-cell-client"]);
        assert_eq!(cli.server, DEFAULT_SERVER_URL);
    }

    #[test]
    fn cli_accepts_custom_server_url() {
        let cli = Cli::parse_from([
            "red-cell-client",
            "--server",
            "wss://teamserver.example.test/havoc/",
        ]);
        assert_eq!(cli.server, "wss://teamserver.example.test/havoc/");
    }

    #[test]
    fn cli_accepts_scripts_dir() {
        let cli =
            Cli::parse_from(["red-cell-client", "--scripts-dir", "/tmp/red-cell-client-scripts"]);
        assert_eq!(cli.scripts_dir, Some(PathBuf::from("/tmp/red-cell-client-scripts")));
    }

    #[test]
    fn cli_accepts_tls_flags() {
        let cli = Cli::parse_from([
            "red-cell-client",
            "--ca-cert",
            "/tmp/ca.pem",
            "--cert-fingerprint",
            "abcd1234",
        ]);
        assert_eq!(cli.ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
        assert_eq!(cli.cert_fingerprint.as_deref(), Some("abcd1234"));
        assert!(!cli.accept_invalid_certs);
    }

    #[test]
    fn cli_optional_fields_default_to_none() {
        let cli = Cli::parse_from(["red-cell-client"]);
        assert!(cli.scripts_dir.is_none());
        assert!(cli.ca_cert.is_none());
        assert!(cli.cert_fingerprint.is_none());
    }

    #[test]
    fn cli_accept_invalid_certs_defaults_to_false() {
        let cli = Cli::parse_from(["red-cell-client"]);
        assert!(!cli.accept_invalid_certs);
    }

    #[test]
    fn cli_accept_invalid_certs_flag_sets_true() {
        let cli = Cli::parse_from(["red-cell-client", "--accept-invalid-certs"]);
        assert!(cli.accept_invalid_certs);
    }

    #[test]
    fn cli_rejects_unknown_args() {
        let result = Cli::try_parse_from(["red-cell-client", "--nonexistent-flag"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_unknown_positional_args() {
        let result = Cli::try_parse_from(["red-cell-client", "unexpected-positional"]);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_tls_prefers_cli_accept_invalid_certs() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some("abcd".to_owned()),
            accept_invalid_certs: true,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::DangerousSkipVerify
        ));
    }

    #[test]
    fn resolve_tls_prefers_cli_fingerprint_over_ca() {
        let valid_fp = "a".repeat(64);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some(valid_fp.clone()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref fp) if fp == &valid_fp
        ));
    }

    #[test]
    fn resolve_tls_falls_back_to_config_fingerprint() {
        let valid_fp = "b".repeat(64);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config =
            LocalConfig { cert_fingerprint: Some(valid_fp.clone()), ..LocalConfig::default() };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref fp) if fp == &valid_fp
        ));
    }

    #[test]
    fn resolve_tls_uses_custom_ca_when_cli_ca_cert_is_set() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/cli-ca.pem")),
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/cli-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_prefers_cli_custom_ca_over_config_custom_ca() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/cli-ca.pem")),
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig {
            ca_cert: Some(PathBuf::from("/tmp/config-ca.pem")),
            ..LocalConfig::default()
        };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/cli-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_falls_back_to_config_custom_ca() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig {
            ca_cert: Some(PathBuf::from("/tmp/config-ca.pem")),
            ..LocalConfig::default()
        };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/config-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_defaults_to_certificate_authority() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::CertificateAuthority
        ));
    }

    #[test]
    fn validate_fingerprint_accepts_valid_sha256_hex() {
        let valid_lower = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(validate_fingerprint(valid_lower, "test").is_ok());

        let valid_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(validate_fingerprint(valid_upper, "test").is_ok());

        let valid_mixed = "AbCdEf0123456789abcDEF0123456789ABCDEF0123456789abcdef0123456789";
        assert!(validate_fingerprint(valid_mixed, "test").is_ok());
    }

    #[test]
    fn validate_fingerprint_rejects_wrong_length() {
        let too_short = "abcdef";
        let err = validate_fingerprint(too_short, "test").unwrap_err();
        assert!(err.to_string().contains("6 characters"), "error: {err}");

        let too_long = "a".repeat(65);
        let err = validate_fingerprint(&too_long, "test").unwrap_err();
        assert!(err.to_string().contains("65 characters"), "error: {err}");

        let empty = "";
        let err = validate_fingerprint(empty, "test").unwrap_err();
        assert!(err.to_string().contains("0 characters"), "error: {err}");
    }

    #[test]
    fn validate_fingerprint_rejects_non_hex_chars() {
        // 64 chars but contains spaces (non-hex)
        let with_spaces = format!("{}    ", "a".repeat(60));
        assert_eq!(with_spaces.len(), 64);
        let err = validate_fingerprint(&with_spaces, "test").unwrap_err();
        assert!(err.to_string().contains("non-hex"), "error: {err}");

        // 64 chars but contains 'g'
        let with_invalid = "g".repeat(64);
        let err = validate_fingerprint(&with_invalid, "test").unwrap_err();
        assert!(err.to_string().contains("non-hex"), "error: {err}");
    }

    #[test]
    fn resolve_tls_rejects_malformed_cli_fingerprint() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some("not-a-valid-fingerprint".to_owned()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        let err =
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap_err();
        assert!(err.to_string().contains("--cert-fingerprint"), "error: {err}");
    }

    #[test]
    fn resolve_tls_rejects_malformed_config_fingerprint() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config =
            LocalConfig { cert_fingerprint: Some("zzzz".to_owned()), ..LocalConfig::default() };
        let err =
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap_err();
        assert!(err.to_string().contains("config file"), "error: {err}");
    }

    #[test]
    fn resolve_tls_accept_invalid_certs_skips_fingerprint_validation() {
        // Even with an invalid fingerprint, --accept-invalid-certs takes precedence
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some("bad".to_owned()),
            accept_invalid_certs: true,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::DangerousSkipVerify
        ));
    }

    #[test]
    fn resolve_tls_uses_known_servers_fingerprint() {
        let fp = "c".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &fp
        ));
    }

    #[test]
    fn resolve_tls_cli_fingerprint_overrides_known_servers() {
        let known_fp = "d".repeat(64);
        let cli_fp = "e".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &known_fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some(cli_fp.clone()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &cli_fp
        ));
    }

    #[test]
    fn resolve_tls_known_servers_overrides_config_fingerprint() {
        let known_fp = "f".repeat(64);
        let config_fp = "0".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &known_fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig { cert_fingerprint: Some(config_fp), ..LocalConfig::default() };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &known_fp
        ));
    }

    #[test]
    fn client_app_state_initializes_placeholder_state() {
        let app_state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

        assert_eq!(app_state.server_url, "wss://127.0.0.1:40056/havoc/");
        assert_eq!(app_state.connection_status, ConnectionStatus::Disconnected);
        assert!(app_state.operator_info.is_none());
        assert!(app_state.agents.is_empty());
        assert!(app_state.agent_consoles.is_empty());
        assert!(app_state.process_lists.is_empty());
        assert!(app_state.listeners.is_empty());
        assert!(app_state.loot.is_empty());
        assert!(app_state.event_log.entries.is_empty());
        assert!(app_state.online_operators.is_empty());
    }

    #[test]
    fn client_app_starts_in_login_phase() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let app = ClientApp::new(cli).unwrap();
        assert!(matches!(app.phase, AppPhase::Login(_)));
    }

    #[test]
    fn client_app_login_state_uses_cli_default() {
        let cli = Cli {
            server: "wss://custom:1234/havoc/".to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let app = ClientApp::new(cli).unwrap();
        match &app.phase {
            AppPhase::Login(state) => {
                if app.local_config.server_url.is_none() {
                    assert_eq!(state.server_url, "wss://custom:1234/havoc/");
                }
            }
            _ => panic!("expected Login phase"),
        }
    }

    fn sample_agent(
        name_id: &str,
        hostname: &str,
        username: &str,
        elevated: bool,
        last_call_in: &str,
    ) -> AgentSummary {
        AgentSummary {
            name_id: name_id.to_owned(),
            status: "Alive".to_owned(),
            domain_name: "LAB".to_owned(),
            username: username.to_owned(),
            internal_ip: "10.0.0.10".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            hostname: hostname.to_owned(),
            process_arch: "x64".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_pid: "1234".to_owned(),
            elevated,
            os_version: "Windows 11".to_owned(),
            os_build: "22631".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: "5".to_owned(),
            sleep_jitter: "10".to_owned(),
            last_call_in: last_call_in.to_owned(),
            note: "primary workstation".to_owned(),
            pivot_parent: None,
            pivot_links: Vec::new(),
        }
    }

    #[test]
    fn agent_filter_matches_multiple_columns() {
        let agent = sample_agent("ABCD1234", "wkstn-1", "operator", true, "10/03/2026 12:00:00");
        assert!(agent_matches_filter(&agent, "wkstn"));
        assert!(agent_matches_filter(&agent, "primary"));
        assert!(agent_matches_filter(&agent, "10.0.0.10"));
        assert!(!agent_matches_filter(&agent, "sqlservr"));
    }

    #[test]
    fn sort_agents_orders_by_last_checkin_descending() {
        let mut agents = vec![
            sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 11:00:00"),
            sample_agent("BBBB0002", "wkstn-2", "bob", true, "10/03/2026 12:00:00"),
        ];

        sort_agents(&mut agents, AgentSortColumn::LastCheckin, true);

        assert_eq!(agents[0].name_id, "BBBB0002");
        assert_eq!(agents[1].name_id, "AAAA0001");
    }

    #[test]
    fn sort_button_label_marks_active_column() {
        assert_eq!(
            sort_button_label(Some(AgentSortColumn::Hostname), false, AgentSortColumn::Hostname),
            "Hostname ^"
        );
        assert_eq!(
            sort_button_label(Some(AgentSortColumn::Hostname), true, AgentSortColumn::Id),
            "ID"
        );
    }

    #[test]
    fn build_kill_task_uses_exit_command_shape() {
        let OperatorMessage::AgentTask(message) = build_kill_task("ABCD1234", "operator") else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.demon_id, "ABCD1234");
        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandExit).to_string());
        assert_eq!(message.info.command.as_deref(), Some("kill"));
    }

    #[test]
    fn build_process_list_task_marks_process_manager_origin() {
        let OperatorMessage::AgentTask(message) = build_process_list_task("ABCD1234", "operator")
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandProcList).to_string());
        assert_eq!(
            message.info.extra.get("FromProcessManager"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn build_process_injection_task_encodes_shellcode_payload() {
        let OperatorMessage::AgentTask(message) = build_process_injection_task(
            "ABCD1234",
            4444,
            "x64",
            InjectionTechnique::NtCreateThreadEx,
            &[0x90, 0x90, 0xCC],
            "--flag",
            InjectionTargetAction::Inject,
            "operator",
        ) else {
            panic!("expected agent task");
        };

        assert_eq!(
            message.info.command_id,
            u32::from(DemonCommand::CommandInjectShellcode).to_string()
        );
        assert_eq!(
            message.info.extra.get("Technique"),
            Some(&serde_json::Value::String("ntcreatethreadex".to_owned()))
        );
        assert_eq!(
            message.info.extra.get("Binary"),
            Some(&serde_json::Value::String("kJDM".to_owned()))
        );
        assert_eq!(
            message.info.extra.get("Arguments"),
            Some(&serde_json::Value::String("LS1mbGFn".to_owned()))
        );
    }

    #[test]
    fn build_note_task_uses_teamserver_note_shape() {
        let OperatorMessage::AgentTask(message) =
            build_note_task("ABCD1234", "triaged", "operator")
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.head.user, "operator");
        assert_eq!(message.info.demon_id, "ABCD1234");
        assert_eq!(message.info.command_id, "Teamserver");
        assert_eq!(message.info.command.as_deref(), Some("note"));
        assert_eq!(message.info.arguments.as_deref(), Some("triaged"));
    }

    #[test]
    fn build_chat_message_uses_chat_wire_shape() {
        let Some(OperatorMessage::ChatMessage(message)) =
            build_chat_message(Some("operator"), " hello team ")
        else {
            panic!("expected chat message");
        };

        assert_eq!(message.head.event, EventCode::Chat);
        assert_eq!(
            message.info.fields.get("Message"),
            Some(&serde_json::Value::String("hello team".to_owned()))
        );
    }

    #[test]
    fn build_console_task_encodes_filesystem_download() {
        let OperatorMessage::AgentTask(message) =
            build_console_task("ABCD1234", "download C:\\Temp\\report.txt", "operator")
                .unwrap_or_else(|error| panic!("console task should build: {error}"))
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(message.info.sub_command.as_deref(), Some("download"));
        assert_eq!(message.info.arguments.as_deref(), Some("QzpcVGVtcFxyZXBvcnQudHh0"));
    }

    #[test]
    fn file_browser_list_task_uses_explorer_arguments() {
        let OperatorMessage::AgentTask(message) =
            build_file_browser_list_task("ABCD1234", "C:\\Temp", "operator")
        else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(message.info.sub_command.as_deref(), Some("dir"));
        assert_eq!(message.info.arguments.as_deref(), Some("C:\\Temp;true;false;false;false;;;"));
    }

    #[test]
    fn file_browser_upload_task_encodes_remote_path_and_content() {
        let OperatorMessage::AgentTask(message) = build_file_browser_upload_task(
            "ABCD1234",
            "C:\\Temp\\report.txt",
            b"hello",
            "operator",
        ) else {
            panic!("expected agent task");
        };

        assert_eq!(message.info.sub_command.as_deref(), Some("upload"));
        assert_eq!(message.info.arguments.as_deref(), Some("QzpcVGVtcFxyZXBvcnQudHh0;aGVsbG8="));
    }

    #[test]
    fn build_console_task_rejects_missing_process_kill_pid() {
        let error = build_console_task("ABCD1234", "proc kill", "operator")
            .expect_err("missing pid should fail");
        assert_eq!(error, "Usage: proc kill <pid>");
    }

    #[test]
    fn filtered_process_rows_matches_name_and_pid() {
        let rows = vec![
            ProcessEntry {
                pid: 1010,
                ppid: 4,
                name: "explorer.exe".to_owned(),
                arch: "x64".to_owned(),
                user: "LAB\\operator".to_owned(),
                session: 1,
            },
            ProcessEntry {
                pid: 2020,
                ppid: 4,
                name: "svchost.exe".to_owned(),
                arch: "x64".to_owned(),
                user: "SYSTEM".to_owned(),
                session: 0,
            },
        ];

        assert_eq!(filtered_process_rows(&rows, "explorer").len(), 1);
        assert_eq!(filtered_process_rows(&rows, "2020").len(), 1);
        assert_eq!(filtered_process_rows(&rows, "missing").len(), 0);
    }

    #[test]
    fn normalized_process_arch_maps_unknown_values_to_x64() {
        assert_eq!(normalized_process_arch("x86"), "x86");
        assert_eq!(normalized_process_arch("WOW64"), "x64");
    }

    #[test]
    fn history_navigation_walks_commands_and_resets() {
        let mut console = AgentConsoleState::default();
        push_history_entry(&mut console, "ps");
        push_history_entry(&mut console, "pwd");

        apply_history_step(&mut console, HistoryDirection::Older);
        assert_eq!(console.input, "pwd");

        apply_history_step(&mut console, HistoryDirection::Older);
        assert_eq!(console.input, "ps");

        apply_history_step(&mut console, HistoryDirection::Newer);
        assert_eq!(console.input, "pwd");

        apply_history_step(&mut console, HistoryDirection::Newer);
        assert!(console.input.is_empty());
    }

    #[test]
    fn completion_cycles_supported_commands() {
        let mut console =
            AgentConsoleState { input: "p".to_owned(), ..AgentConsoleState::default() };

        apply_completion(&mut console);
        assert_eq!(console.input, "ps");

        apply_completion(&mut console);
        assert_eq!(console.input, "pwd");

        apply_completion(&mut console);
        assert_eq!(console.input, "proc");
    }

    #[test]
    fn split_console_selection_prefers_selected_agent() {
        let open = vec!["A".to_owned(), "B".to_owned(), "C".to_owned()];
        let visible = split_console_selection(&open, Some("C"));
        assert_eq!(visible, vec!["C", "A"]);
    }

    #[test]
    fn build_session_graph_uses_explicit_pivot_parent() {
        let mut child = sample_agent("BBBB0002", "wkstn-2", "bob", false, "10/03/2026 12:01:00");
        child.pivot_parent = Some("AAAA0001".to_owned());
        let agents =
            vec![sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 12:00:00"), child];

        let graph = build_session_graph(&agents);

        assert!(graph.edges.iter().any(|edge| edge.from == "AAAA0001" && edge.to == "BBBB0002"));
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.from == SESSION_GRAPH_ROOT_ID && edge.to == "AAAA0001")
        );
    }

    #[test]
    fn build_session_graph_falls_back_to_pivot_links() {
        let mut parent = sample_agent("AAAA0001", "wkstn-1", "alice", false, "10/03/2026 12:00:00");
        parent.pivot_links.push("BBBB0002".to_owned());
        let child = sample_agent("BBBB0002", "wkstn-2", "bob", false, "10/03/2026 12:01:00");

        let graph = build_session_graph(&[parent, child]);

        assert!(graph.edges.iter().any(|edge| edge.from == "AAAA0001" && edge.to == "BBBB0002"));
    }

    #[test]
    fn agent_is_active_status_matches_expected_markers() {
        assert!(agent_is_active_status("Alive"));
        assert!(agent_is_active_status("true"));
        assert!(!agent_is_active_status("Dead"));
        assert!(!agent_is_active_status("Offline"));
    }

    #[test]
    fn loot_filter_matches_type_agent_and_text() {
        let item = LootItem {
            id: None,
            kind: LootKind::Screenshot,
            name: "desktop.png".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("C:/Temp/desktop.png".to_owned()),
            size_bytes: Some(1024),
            content_base64: None,
            preview: Some("primary desktop".to_owned()),
        };

        assert!(loot_matches_filters(
            &item,
            LootTypeFilter::Screenshots,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "abcd",
            "",
            "",
            "desktop"
        ));
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "",
            "",
            ""
        ));
    }

    #[test]
    fn download_loot_item_rejects_missing_content() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "report.txt".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("C:\\Temp\\report.txt".to_owned()),
            size_bytes: Some(12),
            content_base64: None,
            preview: None,
        };

        let error = download_loot_item(&item)
            .expect_err("download_loot_item should reject missing content");
        assert_eq!(error, "This loot item does not include downloadable content.");
    }

    #[test]
    fn download_loot_item_reports_decode_failures() {
        let item = LootItem {
            id: None,
            kind: LootKind::Screenshot,
            name: "desktop.png".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: None,
            size_bytes: Some(12),
            content_base64: Some("%%% definitely-not-base64 %%%".to_owned()),
            preview: None,
        };

        let error =
            download_loot_item(&item).expect_err("download_loot_item should reject invalid base64");
        assert!(error.starts_with("Failed to decode loot payload: "));
    }

    #[test]
    fn download_loot_item_saves_bytes_with_sanitized_file_name() {
        let _guard = lock_export_test();
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock should be after unix epoch: {error}"))
            .as_nanos();
        let file_stub = format!("report-{unique_id}");
        let expected_bytes = b"loot-bytes-\x00\xFF";
        let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
        let item = LootItem {
            id: Some(9),
            kind: LootKind::File,
            name: "fallback-name.bin".to_owned(),
            agent_id: "ABCD1234".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some(format!("C:\\Temp\\{file_stub}:Q1?.zip")),
            size_bytes: Some(expected_bytes.len() as u64),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(expected_bytes)),
            preview: None,
        };

        let message = download_loot_item(&item)
            .unwrap_or_else(|error| panic!("download_loot_item should succeed: {error}"));
        let saved_path = PathBuf::from(
            message
                .strip_prefix("Saved ")
                .unwrap_or_else(|| panic!("save message missing path: {message}")),
        );
        assert_eq!(saved_path.parent(), Some(output_dir.as_path()));
        let saved_file_name = saved_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_else(|| panic!("saved path missing file name: {}", saved_path.display()));
        assert!(saved_file_name.starts_with("C__Temp_report-"));
        assert!(saved_file_name.contains(&file_stub));
        assert!(saved_file_name.ends_with("_Q1_.zip"));
        let saved_bytes = std::fs::read(&saved_path).unwrap_or_else(|error| {
            panic!("failed to read saved file {}: {error}", saved_path.display())
        });
        assert_eq!(saved_bytes, expected_bytes);
        std::fs::remove_file(&saved_path).unwrap_or_else(|error| {
            panic!("failed to remove saved file {}: {error}", saved_path.display())
        });
    }

    fn make_loot_item(kind: LootKind, name: &str, agent_id: &str, collected_at: &str) -> LootItem {
        LootItem {
            id: None,
            kind,
            name: name.to_owned(),
            agent_id: agent_id.to_owned(),
            source: "test".to_owned(),
            collected_at: collected_at.to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        }
    }

    fn exported_path(message: &str) -> PathBuf {
        let Some((_, path)) = message.split_once(" to ") else {
            panic!("export message missing output path: {message}");
        };
        PathBuf::from(path)
    }

    fn read_exported_file(message: &str) -> String {
        let path = exported_path(message);
        let contents = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("failed to read exported file {}: {error}", path.display())
        });
        std::fs::remove_file(&path).unwrap_or_else(|error| {
            panic!("failed to remove exported file {}: {error}", path.display())
        });
        contents
    }

    #[test]
    fn loot_time_range_filter_since_excludes_older_items() {
        let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-05T10:00:00Z");
        // since=2026-03-10 should exclude an item collected on 2026-03-05
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::All,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "2026-03-10",
            "",
            ""
        ));
    }

    #[test]
    fn loot_time_range_filter_until_excludes_newer_items() {
        let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-20T10:00:00Z");
        // until=2026-03-15 should exclude an item collected on 2026-03-20
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::All,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "",
            "2026-03-15",
            ""
        ));
    }

    #[test]
    fn loot_time_range_filter_passes_item_in_range() {
        let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-12T10:00:00Z");
        assert!(loot_matches_filters(
            &item,
            LootTypeFilter::All,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "",
            "2026-03-10",
            "2026-03-15",
            ""
        ));
    }

    #[test]
    fn detect_credential_category_ntlm() {
        // Name contains "ntlm" keyword
        let item = make_loot_item(LootKind::Credential, "NTLM hash", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::NtlmHash);

        // Source labelled "ntlm" — e.g. from a mimikatz sekurlsa::msv dump
        let mut item2 = make_loot_item(LootKind::Credential, "Administrator", "AA", "");
        item2.source = "ntlm".to_owned();
        assert_eq!(detect_credential_category(&item2), CredentialSubFilter::NtlmHash);
    }

    #[test]
    fn detect_credential_category_kerberos() {
        let item = make_loot_item(LootKind::Credential, "TGT ticket.kirbi", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::KerberosTicket);
    }

    #[test]
    fn detect_credential_category_certificate() {
        let item = make_loot_item(LootKind::Credential, "user.pfx", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::Certificate);
    }

    #[test]
    fn detect_credential_category_plaintext() {
        let item = make_loot_item(LootKind::Credential, "plaintext password", "AA", "");
        assert_eq!(detect_credential_category(&item), CredentialSubFilter::Plaintext);
    }

    #[test]
    fn detect_file_category_document() {
        let mut item = make_loot_item(LootKind::File, "report.pdf", "AA", "");
        item.file_path = Some("C:\\Users\\alice\\report.pdf".to_owned());
        assert_eq!(detect_file_category(&item), FileSubFilter::Document);
    }

    #[test]
    fn detect_file_category_archive() {
        let mut item = make_loot_item(LootKind::File, "backup.zip", "AA", "");
        item.file_path = Some("C:\\Temp\\backup.zip".to_owned());
        assert_eq!(detect_file_category(&item), FileSubFilter::Archive);
    }

    #[test]
    fn loot_cred_sub_filter_ntlm_excludes_plaintext() {
        let mut item = make_loot_item(LootKind::Credential, "plaintext password", "AA", "");
        item.preview = Some("P@ssw0rd".to_owned());
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::NtlmHash,
            FileSubFilter::All,
            "",
            "",
            "",
            ""
        ));
    }

    #[test]
    fn loot_file_sub_filter_document_excludes_archives() {
        let mut item = make_loot_item(LootKind::File, "data.zip", "AA", "");
        item.file_path = Some("C:\\Temp\\data.zip".to_owned());
        assert!(!loot_matches_filters(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::Document,
            "",
            "",
            "",
            ""
        ));
    }

    #[test]
    fn export_loot_csv_writes_file_and_returns_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let items: Vec<&LootItem> = vec![];
        // exporting zero items should still succeed and report 0 items
        let result = export_loot_csv_to(&items, dir.path());
        assert!(result.is_ok(), "export_loot_csv failed: {:?}", result.err());
        assert!(result.unwrap().contains("0 item(s)"));
    }

    #[test]
    fn export_loot_json_writes_file_and_returns_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let items: Vec<&LootItem> = vec![];
        let result = export_loot_json_to(&items, dir.path());
        assert!(result.is_ok(), "export_loot_json failed: {:?}", result.err());
        assert!(result.unwrap().contains("0 item(s)"));
    }

    #[test]
    fn export_loot_csv_serializes_non_empty_rows_and_escapes_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let credential = LootItem {
            id: Some(7),
            kind: LootKind::Credential,
            name: "admin".to_owned(),
            agent_id: "operator,local".to_owned(),
            source: "ntlm sekurlsa \"logonpasswords\"".to_owned(),
            collected_at: "2026-03-18T09:10:11Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: Some("hash,user\nline2".to_owned()),
        };
        let file = LootItem {
            id: Some(42),
            kind: LootKind::File,
            name: "report, \"Q1\".zip".to_owned(),
            agent_id: "BEEFCAFE".to_owned(),
            source: "browser download".to_owned(),
            collected_at: "2026-03-18T10:11:12Z".to_owned(),
            file_path: Some("C:\\Loot\\report, \"Q1\".zip".to_owned()),
            size_bytes: Some(2048),
            content_base64: None,
            preview: None,
        };
        let items = vec![&credential, &file];

        let result = export_loot_csv_to(&items, dir.path())
            .unwrap_or_else(|error| panic!("CSV export failed: {error}"));
        assert!(result.contains("2 item(s)"));

        let contents = read_exported_file(&result);
        assert!(contents.starts_with(
            "id,kind,sub_category,name,agent_id,source,collected_at,file_path,size_bytes,preview\n"
        ));
        assert!(contents.contains(
            "7,Credential,NTLM Hash,admin,\"operator,local\",\"ntlm sekurlsa \"\"logonpasswords\"\"\",2026-03-18T09:10:11Z,,,\"hash,user\nline2\"\n"
        ));
        assert!(contents.contains(
            "42,File,Archive,\"report, \"\"Q1\"\".zip\",BEEFCAFE,browser download,2026-03-18T10:11:12Z,\"C:\\Loot\\report, \"\"Q1\"\".zip\",2048,\n"
        ));
    }

    #[test]
    fn export_loot_json_serializes_non_empty_rows_and_preserves_nulls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let credential = LootItem {
            id: Some(7),
            kind: LootKind::Credential,
            name: "admin".to_owned(),
            agent_id: "operator,local".to_owned(),
            source: "ntlm sekurlsa \"logonpasswords\"".to_owned(),
            collected_at: "2026-03-18T09:10:11Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: Some("hash,user\nline2".to_owned()),
        };
        let file = LootItem {
            id: Some(42),
            kind: LootKind::File,
            name: "report, \"Q1\".zip".to_owned(),
            agent_id: "BEEFCAFE".to_owned(),
            source: "browser download".to_owned(),
            collected_at: "2026-03-18T10:11:12Z".to_owned(),
            file_path: Some("C:\\Loot\\report, \"Q1\".zip".to_owned()),
            size_bytes: Some(2048),
            content_base64: None,
            preview: None,
        };
        let items = vec![&credential, &file];

        let result = export_loot_json_to(&items, dir.path())
            .unwrap_or_else(|error| panic!("JSON export failed: {error}"));
        assert!(result.contains("2 item(s)"));

        let contents = read_exported_file(&result);
        assert!(contents.contains("ntlm sekurlsa \\\"logonpasswords\\\""));
        assert!(contents.contains("hash,user\\nline2"));

        let exported: serde_json::Value = serde_json::from_str(&contents)
            .unwrap_or_else(|error| panic!("failed to parse exported JSON: {error}"));
        let entries = exported.as_array().expect("loot export should be a JSON array");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0]["id"], serde_json::Value::from(7));
        assert_eq!(entries[0]["kind"], serde_json::Value::from("Credential"));
        assert_eq!(entries[0]["sub_category"], serde_json::Value::from("NTLM Hash"));
        assert_eq!(entries[0]["agent_id"], serde_json::Value::from("operator,local"));
        assert_eq!(
            entries[0]["source"],
            serde_json::Value::from("ntlm sekurlsa \"logonpasswords\"")
        );
        assert_eq!(entries[0]["collected_at"], serde_json::Value::from("2026-03-18T09:10:11Z"));
        assert_eq!(entries[0]["file_path"], serde_json::Value::Null);
        assert_eq!(entries[0]["size_bytes"], serde_json::Value::Null);
        assert_eq!(entries[0]["preview"], serde_json::Value::from("hash,user\nline2"));

        assert_eq!(entries[1]["id"], serde_json::Value::from(42));
        assert_eq!(entries[1]["kind"], serde_json::Value::from("File"));
        assert_eq!(entries[1]["sub_category"], serde_json::Value::from("Archive"));
        assert_eq!(entries[1]["name"], serde_json::Value::from("report, \"Q1\".zip"));
        assert_eq!(
            entries[1]["file_path"],
            serde_json::Value::from("C:\\Loot\\report, \"Q1\".zip")
        );
        assert_eq!(entries[1]["size_bytes"], serde_json::Value::from(2048_u64));
        assert_eq!(entries[1]["preview"], serde_json::Value::Null);
    }

    #[test]
    fn csv_field_escapes_commas_and_quotes() {
        assert_eq!(csv_field("hello, world"), "\"hello, world\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("bare\rreturn"), "\"bare\rreturn\"");
        assert_eq!(csv_field("line\nfeed"), "\"line\nfeed\"");
    }

    #[test]
    fn csv_field_sanitizes_formula_injection() {
        // Plain formula triggers get a leading single-quote (no quoting needed).
        assert_eq!(csv_field("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(csv_field("+SUM(A1)"), "'+SUM(A1)");
        assert_eq!(csv_field("-1+2"), "'-1+2");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        // Leading whitespace: the first *non-whitespace* character determines injection risk.
        assert_eq!(csv_field("  =foo"), "'  =foo");
        // Formula trigger + embedded double-quote → prefix applied, then CSV-quoted.
        assert_eq!(csv_field("=EXEC(\"x\")"), "\"'=EXEC(\"\"x\"\")\"");
        // Values that do not start with a trigger must not be modified.
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("hello, world"), "\"hello, world\"");
        // A bare minus sign (e.g. used as an empty sentinel) must also be neutralised.
        assert_eq!(csv_field("-"), "'-");
    }

    #[test]
    fn sanitize_file_name_replaces_invalid_characters() {
        assert_eq!(sanitize_file_name("C:\\Temp\\report?.txt"), "C__Temp_report_.txt");
    }

    #[test]
    fn sanitize_file_name_returns_fallback_for_empty_input() {
        assert_eq!(sanitize_file_name(""), "loot.bin");
    }

    #[test]
    fn sanitize_file_name_returns_fallback_for_whitespace_only() {
        assert_eq!(sanitize_file_name("   "), "loot.bin");
    }

    #[test]
    fn sanitize_file_name_preserves_safe_names() {
        assert_eq!(sanitize_file_name("screenshot.png"), "screenshot.png");
    }

    // ---- derive_download_file_name tests ----

    #[test]
    fn derive_download_file_name_uses_file_path_basename() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "fallback-name.bin".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("/home/user/Documents/secrets.docx".to_owned()),
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "secrets.docx");
    }

    #[test]
    fn derive_download_file_name_falls_back_to_name_when_no_file_path() {
        let item = LootItem {
            id: None,
            kind: LootKind::Screenshot,
            name: "desktop.png".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "screenshot".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "desktop.png");
    }

    #[test]
    fn derive_download_file_name_sanitizes_dangerous_characters() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "fallback.bin".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("/tmp/report<v2>.txt".to_owned()),
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "report_v2_.txt");
    }

    #[test]
    fn derive_download_file_name_falls_back_to_name_when_file_path_has_no_basename() {
        let item = LootItem {
            id: None,
            kind: LootKind::File,
            name: "my-report.txt".to_owned(),
            agent_id: "AGENT01".to_owned(),
            source: "download".to_owned(),
            collected_at: "2026-03-10T12:00:00Z".to_owned(),
            file_path: Some("/".to_owned()),
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(derive_download_file_name(&item), "my-report.txt");
    }

    // ---- next_available_path tests ----

    #[test]
    fn next_available_path_returns_original_when_no_collision() {
        let dir = std::env::temp_dir().join("rc2-test-navail-nocoll");
        let _ = std::fs::create_dir_all(&dir);
        let candidate = dir.join("unique-file.txt");
        // Ensure it does not exist
        let _ = std::fs::remove_file(&candidate);
        assert_eq!(next_available_path(&candidate), candidate);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_available_path_appends_suffix_on_collision() {
        let dir = std::env::temp_dir().join("rc2-test-navail-coll1");
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("report.txt");
        std::fs::write(&base, b"existing").unwrap_or_else(|e| panic!("write failed: {e}"));

        let result = next_available_path(&base);
        assert_eq!(result, dir.join("report-1.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_available_path_skips_multiple_collisions() {
        let dir = std::env::temp_dir().join("rc2-test-navail-multi");
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("data.csv");
        std::fs::write(&base, b"v0").unwrap_or_else(|e| panic!("write failed: {e}"));
        std::fs::write(dir.join("data-1.csv"), b"v1")
            .unwrap_or_else(|e| panic!("write failed: {e}"));
        std::fs::write(dir.join("data-2.csv"), b"v2")
            .unwrap_or_else(|e| panic!("write failed: {e}"));

        let result = next_available_path(&base);
        assert_eq!(result, dir.join("data-3.csv"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_available_path_handles_no_extension() {
        let dir = std::env::temp_dir().join("rc2-test-navail-noext");
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("README");
        std::fs::write(&base, b"exists").unwrap_or_else(|e| panic!("write failed: {e}"));

        let result = next_available_path(&base);
        assert_eq!(result, dir.join("README-1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_remote_path_returns_windows_parent() {
        assert_eq!(parent_remote_path("C:\\Temp\\report.txt").as_deref(), Some("C:\\Temp\\"));
    }

    #[test]
    fn upload_destination_prefers_selected_directory() {
        let browser = AgentFileBrowserState {
            current_dir: Some("C:\\Temp".to_owned()),
            directories: BTreeMap::from([(
                "C:\\Temp".to_owned(),
                vec![FileBrowserEntry {
                    name: "Logs".to_owned(),
                    path: "C:\\Temp\\Logs".to_owned(),
                    is_dir: true,
                    size_label: String::new(),
                    size_bytes: None,
                    modified_at: String::new(),
                    permissions: String::new(),
                }],
            )]),
            ..AgentFileBrowserState::default()
        };

        assert_eq!(
            upload_destination(Some(&browser), Some("C:\\Temp\\Logs")).as_deref(),
            Some("C:\\Temp\\Logs")
        );
    }

    #[test]
    fn selected_remote_directory_uses_parent_for_selected_file() {
        let browser = AgentFileBrowserState {
            current_dir: Some("C:\\Temp".to_owned()),
            directories: BTreeMap::from([(
                "C:\\Temp".to_owned(),
                vec![FileBrowserEntry {
                    name: "report.txt".to_owned(),
                    path: "C:\\Temp\\report.txt".to_owned(),
                    is_dir: false,
                    size_label: "5 B".to_owned(),
                    size_bytes: Some(5),
                    modified_at: String::new(),
                    permissions: String::new(),
                }],
            )]),
            ..AgentFileBrowserState::default()
        };

        assert_eq!(
            selected_remote_directory(Some(&browser), Some("C:\\Temp\\report.txt")).as_deref(),
            Some("C:\\Temp\\")
        );
    }

    #[test]
    fn selected_remote_directory_returns_none_without_matching_entry() {
        let browser = AgentFileBrowserState::default();
        assert!(selected_remote_directory(Some(&browser), Some("C:\\Missing")).is_none());
    }

    /// Build a `ClientApp` in the `Authenticating` phase with the given shared state.
    fn app_in_authenticating_phase(app_state: SharedAppState) -> ClientApp {
        let login_state = LoginState::new(DEFAULT_SERVER_URL, &LocalConfig::default());
        ClientApp {
            phase: AppPhase::Authenticating {
                app_state,
                transport: ClientTransport::dummy(),
                login_state,
            },
            local_config: LocalConfig::default(),
            known_servers: KnownServersStore::default(),
            cli_server_url: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            tls_verification: TlsVerification::CertificateAuthority,
            session_panel: SessionPanelState::default(),
            outgoing_tx: None,
            python_runtime: None,
            show_known_servers: false,
            retained_app_state: None,
        }
    }

    #[test]
    fn check_auth_response_retrying_without_auth_error_transitions_to_login() {
        let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let app_state: SharedAppState = Arc::new(Mutex::new(state));
        {
            let mut s = app_state.lock().unwrap();
            s.connection_status =
                ConnectionStatus::Retrying("Connection closed by server".to_owned());
            // last_auth_error is None — server closed without sending an explicit error
        }

        let mut app = app_in_authenticating_phase(app_state);
        app.check_auth_response();

        match &app.phase {
            AppPhase::Login(login_state) => {
                assert!(
                    login_state.error_message.is_some(),
                    "expected an error message on the login state"
                );
                assert!(
                    login_state.error_message.as_deref().unwrap().contains("Connection closed"),
                    "error should contain the disconnect reason"
                );
            }
            _ => panic!("expected Login phase after Retrying during auth without last_auth_error"),
        }
    }

    #[test]
    fn check_auth_response_retrying_with_auth_error_uses_auth_error() {
        let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let app_state: SharedAppState = Arc::new(Mutex::new(state));
        {
            let mut s = app_state.lock().unwrap();
            s.connection_status = ConnectionStatus::Retrying("WebSocket closed".to_owned());
            s.last_auth_error = Some("Invalid credentials".to_owned());
        }

        let mut app = app_in_authenticating_phase(app_state);
        app.check_auth_response();

        match &app.phase {
            AppPhase::Login(login_state) => {
                assert_eq!(
                    login_state.error_message.as_deref(),
                    Some("Invalid credentials"),
                    "should prefer last_auth_error over retry reason"
                );
            }
            _ => panic!("expected Login phase"),
        }
    }

    #[test]
    fn check_auth_response_error_transitions_to_login() {
        let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let app_state: SharedAppState = Arc::new(Mutex::new(state));
        {
            let mut s = app_state.lock().unwrap();
            s.connection_status = ConnectionStatus::Error("Authentication failed".to_owned());
        }

        let mut app = app_in_authenticating_phase(app_state);
        app.check_auth_response();

        match &app.phase {
            AppPhase::Login(login_state) => {
                assert_eq!(login_state.error_message.as_deref(), Some("Authentication failed"));
            }
            _ => panic!("expected Login phase after Error during auth"),
        }
    }

    #[test]
    fn check_auth_response_connecting_stays_authenticating() {
        let state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        let app_state: SharedAppState = Arc::new(Mutex::new(state));
        // Default status is Disconnected but let's set Connecting to test the _ => None arm
        {
            let mut s = app_state.lock().unwrap();
            s.connection_status = ConnectionStatus::Connected;
        }

        let mut app = app_in_authenticating_phase(app_state);
        app.check_auth_response();

        assert!(
            matches!(app.phase, AppPhase::Authenticating { .. }),
            "should remain in Authenticating when status is Connected but no operator_info"
        );
    }

    // ── join_remote_path ──────────────────────────────────────────────

    #[test]
    fn join_remote_path_windows_backslash_base() {
        assert_eq!(
            join_remote_path("C:\\Users\\admin", "Documents"),
            "C:\\Users\\admin\\Documents"
        );
    }

    #[test]
    fn join_remote_path_unix_slash_base() {
        assert_eq!(join_remote_path("/home/user", "file.txt"), "/home/user/file.txt");
    }

    #[test]
    fn join_remote_path_trailing_backslash() {
        assert_eq!(join_remote_path("C:\\Users\\", "admin"), "C:\\Users\\admin");
    }

    #[test]
    fn join_remote_path_trailing_slash() {
        assert_eq!(join_remote_path("/home/user/", "file.txt"), "/home/user/file.txt");
    }

    #[test]
    fn join_remote_path_empty_base() {
        assert_eq!(join_remote_path("", "file.txt"), "file.txt");
    }

    #[test]
    fn join_remote_path_root_unix() {
        assert_eq!(join_remote_path("/", "etc"), "/etc");
    }

    // ── DockTab::FileBrowser ────────────────────────────────────────

    #[test]
    fn dock_tab_file_browser_label() {
        let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
        assert_eq!(tab.label(), "[DEADBEEF] File Explorer");
    }

    #[test]
    fn dock_tab_file_browser_is_closeable() {
        let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
        assert!(tab.closeable());
    }

    #[test]
    fn dock_tab_file_browser_accent_is_teal() {
        let tab = DockTab::FileBrowser("DEADBEEF".to_owned());
        assert_eq!(tab.accent_color(), Color32::from_rgb(80, 180, 140));
    }

    #[test]
    fn dock_state_open_file_browser_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::FileBrowser("AGENT1".to_owned()));
        assert!(dock.open_tabs.contains(&DockTab::FileBrowser("AGENT1".to_owned())));
        assert_eq!(dock.selected, Some(DockTab::FileBrowser("AGENT1".to_owned())));
    }

    #[test]
    fn dock_state_close_file_browser_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::FileBrowser("AGENT1".to_owned()));
        dock.close_tab(&DockTab::FileBrowser("AGENT1".to_owned()));
        assert!(!dock.open_tabs.contains(&DockTab::FileBrowser("AGENT1".to_owned())));
    }

    // ── DockTab::ProcessList ──────────────────────────────────────────

    #[test]
    fn dock_tab_process_list_label() {
        let tab = DockTab::ProcessList("DEADBEEF".to_owned());
        assert_eq!(tab.label(), "Process: [DEADBEEF]");
    }

    #[test]
    fn dock_tab_process_list_is_closeable() {
        let tab = DockTab::ProcessList("DEADBEEF".to_owned());
        assert!(tab.closeable());
    }

    #[test]
    fn dock_tab_process_list_accent_is_red() {
        let tab = DockTab::ProcessList("DEADBEEF".to_owned());
        assert_eq!(tab.accent_color(), Color32::from_rgb(255, 85, 85));
    }

    #[test]
    fn dock_state_open_process_list_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::ProcessList("AGENT1".to_owned()));
        assert!(dock.open_tabs.contains(&DockTab::ProcessList("AGENT1".to_owned())));
        assert_eq!(dock.selected, Some(DockTab::ProcessList("AGENT1".to_owned())));
    }

    #[test]
    fn dock_state_close_process_list_tab() {
        let mut dock = DockState::default();
        dock.open_tab(DockTab::ProcessList("AGENT1".to_owned()));
        dock.close_tab(&DockTab::ProcessList("AGENT1".to_owned()));
        assert!(!dock.open_tabs.contains(&DockTab::ProcessList("AGENT1".to_owned())));
    }

    #[test]
    fn ensure_process_list_open_creates_tab() {
        let mut panel = SessionPanelState::default();
        panel.ensure_process_list_open("ABCD1234");
        assert!(panel.dock.open_tabs.contains(&DockTab::ProcessList("ABCD1234".to_owned())));
        assert_eq!(panel.dock.selected, Some(DockTab::ProcessList("ABCD1234".to_owned())));
    }

    #[test]
    fn ensure_process_list_open_idempotent() {
        let mut panel = SessionPanelState::default();
        panel.ensure_process_list_open("ABCD1234");
        panel.ensure_process_list_open("ABCD1234");
        let count = panel
            .dock
            .open_tabs
            .iter()
            .filter(|t| **t == DockTab::ProcessList("ABCD1234".to_owned()))
            .count();
        assert_eq!(count, 1);
    }

    // ── breadcrumb_segments ──────────────────────────────────────────

    #[test]
    fn breadcrumb_segments_windows_path() {
        let segments = breadcrumb_segments("C:\\Users\\admin\\Documents");
        assert_eq!(
            segments,
            vec![
                ("C:\\".to_owned(), "C:\\".to_owned()),
                ("Users".to_owned(), "C:\\Users\\".to_owned()),
                ("admin".to_owned(), "C:\\Users\\admin\\".to_owned()),
                ("Documents".to_owned(), "C:\\Users\\admin\\Documents\\".to_owned()),
            ]
        );
    }

    #[test]
    fn breadcrumb_segments_unix_path() {
        let segments = breadcrumb_segments("/home/user/docs");
        assert_eq!(
            segments,
            vec![
                ("/".to_owned(), "/".to_owned()),
                ("home".to_owned(), "/home/".to_owned()),
                ("user".to_owned(), "/home/user/".to_owned()),
                ("docs".to_owned(), "/home/user/docs/".to_owned()),
            ]
        );
    }

    #[test]
    fn breadcrumb_segments_root_only() {
        let segments = breadcrumb_segments("/");
        assert_eq!(segments, vec![("/".to_owned(), "/".to_owned())]);
    }

    #[test]
    fn breadcrumb_segments_windows_drive_root() {
        let segments = breadcrumb_segments("C:\\");
        assert_eq!(segments, vec![("C:\\".to_owned(), "C:\\".to_owned())]);
    }

    #[test]
    fn breadcrumb_segments_relative_path() {
        let segments = breadcrumb_segments("Documents/Stuff");
        assert_eq!(
            segments,
            vec![
                ("Documents".to_owned(), "Documents/".to_owned()),
                ("Stuff".to_owned(), "Documents/Stuff/".to_owned()),
            ]
        );
    }

    // ── directory_label ───────────────────────────────────────────────

    #[test]
    fn directory_label_extracts_leaf() {
        assert_eq!(directory_label("/home/user/Documents"), "Documents");
    }

    #[test]
    fn directory_label_windows_leaf() {
        // On Linux, std::path::Path does not split on backslashes, so the full
        // string is returned as the "file_name". This matches the current
        // implementation which delegates to Path::file_name().
        let result = directory_label("C:\\Users\\admin\\Desktop");
        assert!(
            result == "Desktop" || result == "C:\\Users\\admin\\Desktop",
            "unexpected result: {result}"
        );
    }

    #[test]
    fn directory_label_trailing_separator() {
        assert_eq!(directory_label("/home/user/Downloads/"), "Downloads");
    }

    #[test]
    fn directory_label_drive_root_backslash() {
        assert_eq!(directory_label("C:\\"), "C:\\");
    }

    #[test]
    fn directory_label_drive_root_slash() {
        assert_eq!(directory_label("C:/"), "C:/");
    }

    #[test]
    fn directory_label_drive_letter_colon() {
        assert_eq!(directory_label("C:"), "C:");
    }

    // ── file_entry_label ──────────────────────────────────────────────

    fn make_file_browser_entry(
        name: &str,
        size_label: &str,
        modified: &str,
        perms: &str,
    ) -> FileBrowserEntry {
        FileBrowserEntry {
            name: name.to_owned(),
            path: String::new(),
            is_dir: false,
            size_label: size_label.to_owned(),
            size_bytes: None,
            modified_at: modified.to_owned(),
            permissions: perms.to_owned(),
        }
    }

    #[test]
    fn file_entry_label_all_fields() {
        let entry = make_file_browser_entry("readme.txt", "1.5 KB", "2026-01-15", "rwxr-xr-x");
        assert_eq!(file_entry_label(&entry), "readme.txt  [1.5 KB | 2026-01-15 | rwxr-xr-x]");
    }

    #[test]
    fn file_entry_label_empty_size() {
        let entry = make_file_browser_entry("dir", "", "2026-01-15", "drwxr-xr-x");
        assert_eq!(file_entry_label(&entry), "dir  [- | 2026-01-15 | drwxr-xr-x]");
    }

    #[test]
    fn file_entry_label_all_empty_metadata() {
        let entry = make_file_browser_entry("file.bin", " ", "", "");
        assert_eq!(file_entry_label(&entry), "file.bin  [- | - | -]");
    }

    // ── human_size ────────────────────────────────────────────────────

    #[test]
    fn human_size_zero_bytes() {
        assert_eq!(human_size(0), "0 B");
    }

    #[test]
    fn human_size_below_kb() {
        assert_eq!(human_size(1023), "1023 B");
    }

    #[test]
    fn human_size_exactly_1kb() {
        assert_eq!(human_size(1024), "1.0 KB");
    }

    #[test]
    fn human_size_megabyte_range() {
        assert_eq!(human_size(1_048_576), "1.0 MB");
    }

    #[test]
    fn human_size_gigabyte_range() {
        assert_eq!(human_size(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn human_size_large_gb_value() {
        assert_eq!(human_size(5_905_580_032), "5.5 GB");
    }

    #[test]
    fn human_size_one_byte() {
        assert_eq!(human_size(1), "1 B");
    }

    // ── find_file_entry ───────────────────────────────────────────────

    fn browser_with_entries(entries: Vec<FileBrowserEntry>) -> AgentFileBrowserState {
        let mut dirs = std::collections::BTreeMap::new();
        dirs.insert("/home".to_owned(), entries);
        AgentFileBrowserState {
            current_dir: Some("/home".to_owned()),
            directories: dirs,
            ..AgentFileBrowserState::default()
        }
    }

    #[test]
    fn find_file_entry_found() {
        let entry = FileBrowserEntry {
            name: "test.txt".to_owned(),
            path: "/home/test.txt".to_owned(),
            is_dir: false,
            size_label: "100 B".to_owned(),
            size_bytes: Some(100),
            modified_at: String::new(),
            permissions: String::new(),
        };
        let browser = browser_with_entries(vec![entry]);
        let found = find_file_entry(&browser, "/home/test.txt");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "test.txt");
    }

    #[test]
    fn find_file_entry_not_found() {
        let browser = browser_with_entries(vec![]);
        assert!(find_file_entry(&browser, "/nonexistent").is_none());
    }

    // ── parent_remote_path ────────────────────────────────────────────

    #[test]
    fn parent_remote_path_unix() {
        assert_eq!(parent_remote_path("/home/user/file.txt"), Some("/home/user/".to_owned()));
    }

    #[test]
    fn parent_remote_path_windows() {
        assert_eq!(
            parent_remote_path("C:\\Users\\admin\\file.txt"),
            Some("C:\\Users\\admin\\".to_owned())
        );
    }

    #[test]
    fn parent_remote_path_trailing_slash() {
        assert_eq!(parent_remote_path("/home/user/"), Some("/home/".to_owned()));
    }

    #[test]
    fn parent_remote_path_root() {
        assert_eq!(parent_remote_path("/"), None);
    }

    #[test]
    fn parent_remote_path_empty() {
        assert_eq!(parent_remote_path(""), None);
    }

    #[test]
    fn parent_remote_path_no_separator() {
        assert_eq!(parent_remote_path("file.txt"), None);
    }

    // ── json_str ─────────────────────────────────────────────────────────

    #[test]
    fn json_str_plain_string() {
        assert_eq!(json_str("hello"), "\"hello\"");
    }

    #[test]
    fn json_str_embedded_quotes() {
        assert_eq!(json_str(r#"say "hi""#), r#""say \"hi\"""#);
    }

    #[test]
    fn json_str_backslashes() {
        assert_eq!(json_str(r"C:\Users\admin"), r#""C:\\Users\\admin""#);
    }

    #[test]
    fn json_str_newlines_and_tabs() {
        assert_eq!(json_str("line1\nline2\ttab"), r#""line1\nline2\ttab""#);
    }

    #[test]
    fn json_str_carriage_return() {
        assert_eq!(json_str("a\rb"), r#""a\rb""#);
    }

    #[test]
    fn json_str_empty_string() {
        assert_eq!(json_str(""), "\"\"");
    }

    #[test]
    fn json_str_combined_escapes() {
        assert_eq!(json_str("\\\"\n\r\t"), r#""\\\"\n\r\t""#);
    }

    #[test]
    fn json_str_null_bytes_passed_through() {
        // Null bytes are not escaped by json_str — they pass through as-is.
        let result = json_str("a\0b");
        assert!(result.starts_with('"') && result.ends_with('"'));
        assert!(result.contains('\0'));
    }

    // ── contains_ascii_case_insensitive ──────────────────────────────────

    #[test]
    fn case_insensitive_match() {
        assert!(contains_ascii_case_insensitive("Hello World", "hello"));
    }

    #[test]
    fn case_insensitive_no_match() {
        assert!(!contains_ascii_case_insensitive("Hello World", "goodbye"));
    }

    #[test]
    fn case_insensitive_empty_needle_matches_all() {
        assert!(contains_ascii_case_insensitive("anything", ""));
        assert!(contains_ascii_case_insensitive("", ""));
    }

    #[test]
    fn case_insensitive_whitespace_only_needle_matches_all() {
        assert!(contains_ascii_case_insensitive("anything", "   "));
    }

    #[test]
    fn case_insensitive_mixed_case() {
        assert!(contains_ascii_case_insensitive("NtLmHash", "ntlm"));
    }

    #[test]
    fn case_insensitive_needle_with_surrounding_whitespace() {
        assert!(contains_ascii_case_insensitive("foobar", "  bar  "));
    }

    // ── loot_is_downloadable ─────────────────────────────────────────────

    fn make_loot(kind: LootKind) -> LootItem {
        LootItem {
            id: Some(1),
            kind,
            name: "test".to_owned(),
            agent_id: "agent-1".to_owned(),
            source: "source".to_owned(),
            collected_at: "2026-03-18T12:00:00Z".to_owned(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        }
    }

    #[test]
    fn loot_is_downloadable_file_with_content() {
        let mut item = make_loot(LootKind::File);
        item.content_base64 = Some("dGVzdA==".to_owned());
        assert!(loot_is_downloadable(&item));
    }

    #[test]
    fn loot_is_downloadable_screenshot_with_content() {
        let mut item = make_loot(LootKind::Screenshot);
        item.content_base64 = Some("dGVzdA==".to_owned());
        assert!(loot_is_downloadable(&item));
    }

    #[test]
    fn loot_not_downloadable_file_without_content() {
        let item = make_loot(LootKind::File);
        assert!(!loot_is_downloadable(&item));
    }

    #[test]
    fn loot_not_downloadable_credential() {
        let mut item = make_loot(LootKind::Credential);
        item.content_base64 = Some("dGVzdA==".to_owned());
        assert!(!loot_is_downloadable(&item));
    }

    #[test]
    fn loot_not_downloadable_other() {
        let item = make_loot(LootKind::Other);
        assert!(!loot_is_downloadable(&item));
    }

    // ── matches_loot_type_filter ─────────────────────────────────────────

    #[test]
    fn type_filter_all_matches_everything() {
        for kind in [LootKind::Credential, LootKind::File, LootKind::Screenshot, LootKind::Other] {
            let item = make_loot(kind);
            assert!(matches_loot_type_filter(
                &item,
                LootTypeFilter::All,
                CredentialSubFilter::All,
                FileSubFilter::All,
            ));
        }
    }

    #[test]
    fn type_filter_credentials_matches_credential() {
        let item = make_loot(LootKind::Credential);
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_credentials_rejects_file() {
        let item = make_loot(LootKind::File);
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_files_matches_file() {
        let item = make_loot(LootKind::File);
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_files_rejects_credential() {
        let item = make_loot(LootKind::Credential);
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_screenshots_matches_screenshot() {
        let item = make_loot(LootKind::Screenshot);
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Screenshots,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_screenshots_rejects_other() {
        let item = make_loot(LootKind::Other);
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Screenshots,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }

    // ── matches_credential_sub_filter ────────────────────────────────────

    #[test]
    fn credential_sub_filter_all_passes_everything() {
        let item = make_loot(LootKind::Credential);
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::All));
    }

    #[test]
    fn credential_sub_filter_ntlm_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM hash dump".to_owned();
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::NtlmHash));
    }

    #[test]
    fn credential_sub_filter_ntlm_rejects_plaintext() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "plaintext password".to_owned();
        assert!(!matches_credential_sub_filter(&item, CredentialSubFilter::NtlmHash));
    }

    #[test]
    fn credential_sub_filter_kerberos_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.source = "kerberos ticket".to_owned();
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::KerberosTicket));
    }

    #[test]
    fn credential_sub_filter_certificate_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "client.pfx".to_owned();
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::Certificate));
    }

    #[test]
    fn credential_sub_filter_plaintext_matches() {
        let mut item = make_loot(LootKind::Credential);
        item.preview = Some("plaintext creds".to_owned());
        assert!(matches_credential_sub_filter(&item, CredentialSubFilter::Plaintext));
    }

    // ── matches_file_sub_filter ──────────────────────────────────────────

    #[test]
    fn file_sub_filter_all_passes_everything() {
        let item = make_loot(LootKind::File);
        assert!(matches_file_sub_filter(&item, FileSubFilter::All));
    }

    #[test]
    fn file_sub_filter_document_matches_pdf() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("/docs/report.pdf".to_owned());
        assert!(matches_file_sub_filter(&item, FileSubFilter::Document));
    }

    #[test]
    fn file_sub_filter_archive_matches_zip() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("/tmp/backup.zip".to_owned());
        assert!(matches_file_sub_filter(&item, FileSubFilter::Archive));
    }

    #[test]
    fn file_sub_filter_binary_matches_exe() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("C:\\tools\\beacon.exe".to_owned());
        assert!(matches_file_sub_filter(&item, FileSubFilter::Binary));
    }

    #[test]
    fn file_sub_filter_document_rejects_exe() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("/usr/bin/agent.exe".to_owned());
        assert!(!matches_file_sub_filter(&item, FileSubFilter::Document));
    }

    #[test]
    fn file_sub_filter_uses_name_when_no_file_path() {
        let mut item = make_loot(LootKind::File);
        item.file_path = None;
        item.name = "secrets.tar.gz".to_owned();
        assert!(matches_file_sub_filter(&item, FileSubFilter::Archive));
    }

    // ── loot_sub_category_label ──────────────────────────────────────────

    #[test]
    fn sub_category_label_credential_ntlm() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM dump".to_owned();
        assert_eq!(loot_sub_category_label(&item), "NTLM Hash");
    }

    #[test]
    fn sub_category_label_credential_plaintext() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "password file".to_owned();
        assert_eq!(loot_sub_category_label(&item), "Plaintext");
    }

    #[test]
    fn sub_category_label_credential_kerberos() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "kirbi ticket".to_owned();
        assert_eq!(loot_sub_category_label(&item), "Kerberos");
    }

    #[test]
    fn sub_category_label_credential_certificate() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "client.crt".to_owned();
        assert_eq!(loot_sub_category_label(&item), "Certificate");
    }

    #[test]
    fn sub_category_label_credential_unknown() {
        let item = make_loot(LootKind::Credential);
        assert_eq!(loot_sub_category_label(&item), "");
    }

    #[test]
    fn sub_category_label_file_document() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("report.docx".to_owned());
        assert_eq!(loot_sub_category_label(&item), "Document");
    }

    #[test]
    fn sub_category_label_file_archive() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("data.7z".to_owned());
        assert_eq!(loot_sub_category_label(&item), "Archive");
    }

    #[test]
    fn sub_category_label_file_binary() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("agent.dll".to_owned());
        assert_eq!(loot_sub_category_label(&item), "Binary");
    }

    #[test]
    fn sub_category_label_screenshot_empty() {
        let item = make_loot(LootKind::Screenshot);
        assert_eq!(loot_sub_category_label(&item), "");
    }

    #[test]
    fn sub_category_label_other_empty() {
        let item = make_loot(LootKind::Other);
        assert_eq!(loot_sub_category_label(&item), "");
    }

    // ── type filter with credential sub-filter integration ───────────────

    #[test]
    fn type_filter_credentials_with_ntlm_sub_filter() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM hash dump".to_owned();
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::NtlmHash,
            FileSubFilter::All,
        ));
    }

    #[test]
    fn type_filter_credentials_with_wrong_sub_filter() {
        let mut item = make_loot(LootKind::Credential);
        item.name = "NTLM hash dump".to_owned();
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Credentials,
            CredentialSubFilter::Plaintext,
            FileSubFilter::All,
        ));
    }

    // ── type filter with file sub-filter integration ─────────────────────

    #[test]
    fn type_filter_files_with_document_sub_filter() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("report.pdf".to_owned());
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::Document,
        ));
    }

    #[test]
    fn type_filter_files_with_wrong_sub_filter() {
        let mut item = make_loot(LootKind::File);
        item.file_path = Some("report.pdf".to_owned());
        assert!(!matches_loot_type_filter(
            &item,
            LootTypeFilter::Files,
            CredentialSubFilter::All,
            FileSubFilter::Archive,
        ));
    }

    // ── process_task tests ──────────────────────────────────────────────

    #[test]
    fn process_task_valid_kill() {
        let info = process_task("DEAD0001", "proc kill 1234").unwrap();
        assert_eq!(info.demon_id, "DEAD0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandProc).to_string());
        assert_eq!(info.command.as_deref(), Some("proc"));
        assert_eq!(info.sub_command.as_deref(), Some("kill"));
        assert_eq!(info.arguments.as_deref(), Some("1234"));
        assert_eq!(info.command_line, "proc kill 1234");
        assert_eq!(info.extra.get("Args"), Some(&serde_json::Value::String("1234".to_owned())));
    }

    #[test]
    fn process_task_missing_subcommand() {
        let err = process_task("DEAD0001", "proc").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_missing_pid() {
        let err = process_task("DEAD0001", "proc kill").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_non_numeric_pid() {
        let err = process_task("DEAD0001", "proc kill abc").unwrap_err();
        assert!(err.contains("Invalid PID"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_extra_trailing_args() {
        let err = process_task("DEAD0001", "proc kill 1234 extra").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_unknown_subcommand() {
        let err = process_task("DEAD0001", "proc list").unwrap_err();
        assert!(err.contains("Usage"), "unexpected error: {err}");
    }

    #[test]
    fn process_task_kill_case_insensitive() {
        let info = process_task("DEAD0001", "proc KILL 42").unwrap();
        assert_eq!(info.sub_command.as_deref(), Some("kill"));
        assert_eq!(info.arguments.as_deref(), Some("42"));
    }

    // ── rest_after_word tests ───────────────────────────────────────────

    #[test]
    fn rest_after_word_two_words() {
        assert_eq!(rest_after_word("cmd argument").unwrap(), "argument");
    }

    #[test]
    fn rest_after_word_multiple_words() {
        assert_eq!(rest_after_word("shell whoami /all").unwrap(), "whoami /all");
    }

    #[test]
    fn rest_after_word_single_word_errors() {
        let err = rest_after_word("cmd").unwrap_err();
        assert!(err.contains("requires an argument"), "unexpected error: {err}");
    }

    #[test]
    fn rest_after_word_leading_trailing_whitespace() {
        assert_eq!(rest_after_word("  cmd   argument  ").unwrap(), "argument");
    }

    #[test]
    fn rest_after_word_empty_string_errors() {
        assert!(rest_after_word("").is_err());
    }

    #[test]
    fn rest_after_word_only_whitespace_errors() {
        assert!(rest_after_word("   ").is_err());
    }

    // ── file browser task builder tests ──────────────────────────────────

    /// Helper to extract the `AgentTaskInfo` from an `OperatorMessage::AgentTask`.
    fn unwrap_agent_task(msg: OperatorMessage) -> (MessageHead, AgentTaskInfo) {
        match msg {
            OperatorMessage::AgentTask(m) => (m.head, m.info),
            other => panic!("expected AgentTask, got {other:?}"),
        }
    }

    // -- filesystem_task helper --

    #[test]
    fn filesystem_task_sets_command_fs_and_sub_command() {
        let info = filesystem_task("DEAD0001", "pwd", "pwd", None);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.command.as_deref(), Some("fs"));
        assert_eq!(info.sub_command.as_deref(), Some("pwd"));
        assert_eq!(info.demon_id, "DEAD0001");
        assert_eq!(info.command_line, "pwd");
        assert!(info.arguments.is_none());
    }

    #[test]
    fn filesystem_task_with_arguments_passes_them_through() {
        let info = filesystem_task("DEAD0002", "cd /tmp", "cd", Some("/tmp".to_owned()));
        assert_eq!(info.arguments.as_deref(), Some("/tmp"));
        assert_eq!(info.command_line, "cd /tmp");
    }

    #[test]
    fn filesystem_task_generates_eight_hex_digit_task_id() {
        let info = filesystem_task("DEAD0003", "pwd", "pwd", None);
        assert_eq!(info.task_id.len(), 8);
        assert!(
            u32::from_str_radix(&info.task_id, 16).is_ok(),
            "task_id should be valid hex: {}",
            info.task_id
        );
    }

    // -- filesystem_transfer_task helper --

    #[test]
    fn filesystem_transfer_task_base64_encodes_path() {
        let info =
            filesystem_transfer_task("DEAD0004", "download /etc/passwd", "download", "/etc/passwd");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.command.as_deref(), Some("fs"));
        assert_eq!(info.sub_command.as_deref(), Some("download"));
        let expected = base64::engine::general_purpose::STANDARD.encode(b"/etc/passwd");
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn filesystem_transfer_task_encodes_windows_path() {
        let path = r"C:\Users\admin\Desktop\secrets.txt";
        let info =
            filesystem_transfer_task("DEAD0005", &format!("download {path}"), "download", path);
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn filesystem_transfer_task_encodes_unicode_path() {
        let path = "/home/用户/文件.txt";
        let info = filesystem_transfer_task("DEAD0006", &format!("cat {path}"), "cat", path);
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    // -- build_transfer_stop_task --

    #[test]
    fn build_transfer_stop_task_encodes_correct_payload() {
        let msg = build_transfer_stop_task("DEAD0007", "0000002A", "operator")
            .expect("should build for valid hex");
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(
            info.command_id,
            u32::from(red_cell_common::demon::DemonCommand::CommandTransfer).to_string()
        );
        assert_eq!(info.command_line, "transfer stop 0000002A");

        // Verify the binary payload: [1u32_le, 0x2Au32_le]
        let b64 = info
            .extra
            .get("PayloadBase64")
            .and_then(|v| v.as_str())
            .expect("PayloadBase64 must be present");
        let payload = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(payload.len(), 8);
        assert_eq!(&payload[..4], &1u32.to_le_bytes()); // stop subcommand
        assert_eq!(&payload[4..], &0x0000_002Au32.to_le_bytes()); // file_id
    }

    #[test]
    fn build_transfer_stop_task_rejects_invalid_hex() {
        assert!(build_transfer_stop_task("DEAD0008", "not_hex", "operator").is_none());
    }

    #[test]
    fn build_transfer_stop_task_handles_8digit_hex() {
        let msg = build_transfer_stop_task("DEAD0009", "DEADBEEF", "operator")
            .expect("should parse 8-digit hex");
        let (_, info) = unwrap_agent_task(msg);
        let b64 = info.extra["PayloadBase64"].as_str().unwrap();
        let payload = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(&payload[4..], &0xDEADBEEFu32.to_le_bytes());
    }

    // -- build_file_browser_pwd_task --

    #[test]
    fn build_file_browser_pwd_task_produces_correct_shape() {
        let (head, info) = unwrap_agent_task(build_file_browser_pwd_task("BEEF0001", "alice"));
        assert_eq!(head.user, "alice");
        assert_eq!(info.demon_id, "BEEF0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.command.as_deref(), Some("fs"));
        assert_eq!(info.sub_command.as_deref(), Some("pwd"));
        assert_eq!(info.command_line, "pwd");
        assert!(info.arguments.is_none());
    }

    // -- build_file_browser_cd_task --

    #[test]
    fn build_file_browser_cd_task_produces_correct_shape() {
        let (head, info) =
            unwrap_agent_task(build_file_browser_cd_task("BEEF0002", "/var/log", "bob"));
        assert_eq!(head.user, "bob");
        assert_eq!(info.demon_id, "BEEF0002");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("cd"));
        assert_eq!(info.command_line, "cd /var/log");
        assert_eq!(info.arguments.as_deref(), Some("/var/log"));
    }

    #[test]
    fn build_file_browser_cd_task_handles_path_with_spaces() {
        let (_, info) = unwrap_agent_task(build_file_browser_cd_task(
            "BEEF0003",
            "C:\\Program Files\\App",
            "op",
        ));
        assert_eq!(info.arguments.as_deref(), Some("C:\\Program Files\\App"));
        assert_eq!(info.command_line, "cd C:\\Program Files\\App");
    }

    #[test]
    fn build_file_browser_cd_task_handles_unicode_path() {
        let (_, info) =
            unwrap_agent_task(build_file_browser_cd_task("BEEF0004", "/home/用户", "op"));
        assert_eq!(info.arguments.as_deref(), Some("/home/用户"));
    }

    // -- build_file_browser_download_task --

    #[test]
    fn build_file_browser_download_task_produces_correct_shape() {
        let (head, info) = unwrap_agent_task(build_file_browser_download_task(
            "CAFE0001",
            "/tmp/data.bin",
            "charlie",
        ));
        assert_eq!(head.user, "charlie");
        assert_eq!(info.demon_id, "CAFE0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("download"));
        assert_eq!(info.command_line, "download /tmp/data.bin");
        let expected = base64::engine::general_purpose::STANDARD.encode(b"/tmp/data.bin");
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn build_file_browser_download_task_encodes_windows_backslash_path() {
        let path = r"C:\Users\admin\Documents\report.docx";
        let (_, info) = unwrap_agent_task(build_file_browser_download_task("CAFE0002", path, "op"));
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn build_file_browser_download_task_encodes_unicode_path() {
        let path = "/données/résumé.pdf";
        let (_, info) = unwrap_agent_task(build_file_browser_download_task("CAFE0003", path, "op"));
        let expected = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
        assert_eq!(info.arguments.as_deref(), Some(expected.as_str()));
    }

    // -- build_file_browser_delete_task --

    #[test]
    fn build_file_browser_delete_task_produces_correct_shape() {
        let (head, info) =
            unwrap_agent_task(build_file_browser_delete_task("F00D0001", "/tmp/junk.log", "dave"));
        assert_eq!(head.user, "dave");
        assert_eq!(info.demon_id, "F00D0001");
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("remove"));
        assert_eq!(info.command_line, "rm /tmp/junk.log");
        assert_eq!(info.arguments.as_deref(), Some("/tmp/junk.log"));
    }

    #[test]
    fn build_file_browser_delete_task_handles_path_with_spaces() {
        let path = "C:\\Program Files\\Old App\\config.ini";
        let (_, info) = unwrap_agent_task(build_file_browser_delete_task("F00D0002", path, "op"));
        assert_eq!(info.arguments.as_deref(), Some(path));
        assert_eq!(info.command_line, format!("rm {path}"));
    }

    #[test]
    fn build_file_browser_delete_task_handles_unicode_path() {
        let path = "/home/用户/临时文件.tmp";
        let (_, info) = unwrap_agent_task(build_file_browser_delete_task("F00D0003", path, "op"));
        assert_eq!(info.arguments.as_deref(), Some(path));
    }

    // -- cross-builder structural checks --

    #[test]
    fn all_file_browser_builders_set_session_event_code() {
        let builders: Vec<OperatorMessage> = vec![
            build_file_browser_pwd_task("A0000001", "op"),
            build_file_browser_cd_task("A0000002", "/tmp", "op"),
            build_file_browser_download_task("A0000003", "/tmp/f", "op"),
            build_file_browser_delete_task("A0000004", "/tmp/f", "op"),
        ];
        for msg in builders {
            let (head, _) = unwrap_agent_task(msg);
            assert_eq!(
                head.event,
                EventCode::Session,
                "file browser tasks must use Session event code"
            );
        }
    }

    #[test]
    fn all_file_browser_builders_produce_unique_task_ids() {
        let msgs: Vec<OperatorMessage> = vec![
            build_file_browser_pwd_task("B0000001", "op"),
            build_file_browser_cd_task("B0000002", "/a", "op"),
            build_file_browser_download_task("B0000003", "/b", "op"),
            build_file_browser_delete_task("B0000004", "/c", "op"),
        ];
        let mut ids: Vec<String> = msgs
            .into_iter()
            .map(|m| {
                let (_, info) = unwrap_agent_task(m);
                info.task_id
            })
            .collect();
        let count_before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count_before, "task IDs should all be unique");
    }

    // ---- agent metadata extractor tests ----

    fn make_agent(overrides: impl FnOnce(&mut transport::AgentSummary)) -> transport::AgentSummary {
        let mut agent = transport::AgentSummary {
            name_id: "DEAD0001".into(),
            status: "alive".into(),
            domain_name: "CORP".into(),
            username: "admin".into(),
            internal_ip: "10.0.0.5".into(),
            external_ip: "203.0.113.1".into(),
            hostname: "WS01".into(),
            process_arch: "x64".into(),
            process_name: "svchost.exe".into(),
            process_pid: "1234".into(),
            elevated: false,
            os_version: "Windows 10".into(),
            os_build: "19045".into(),
            os_arch: "x86_64".into(),
            sleep_delay: "5".into(),
            sleep_jitter: "20".into(),
            last_call_in: "2s".into(),
            note: String::new(),
            pivot_parent: None,
            pivot_links: Vec::new(),
        };
        overrides(&mut agent);
        agent
    }

    #[test]
    fn agent_ip_prefers_internal() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_ip(&agent), "10.0.0.5");
    }

    #[test]
    fn agent_ip_falls_back_to_external_when_internal_empty() {
        let agent = make_agent(|a| a.internal_ip = String::new());
        assert_eq!(agent_ip(&agent), "203.0.113.1");
    }

    #[test]
    fn agent_ip_falls_back_to_external_when_internal_whitespace() {
        let agent = make_agent(|a| a.internal_ip = "   ".into());
        assert_eq!(agent_ip(&agent), "203.0.113.1");
    }

    #[test]
    fn agent_arch_prefers_process_arch() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_arch(&agent), "x64");
    }

    #[test]
    fn agent_arch_falls_back_to_os_arch_when_process_arch_empty() {
        let agent = make_agent(|a| a.process_arch = String::new());
        assert_eq!(agent_arch(&agent), "x86_64");
    }

    #[test]
    fn agent_arch_falls_back_to_os_arch_when_process_arch_whitespace() {
        let agent = make_agent(|a| a.process_arch = "  ".into());
        assert_eq!(agent_arch(&agent), "x86_64");
    }

    #[test]
    fn agent_os_includes_build_when_present() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_os(&agent), "Windows 10 (19045)");
    }

    #[test]
    fn agent_os_returns_version_only_when_build_empty() {
        let agent = make_agent(|a| a.os_build = String::new());
        assert_eq!(agent_os(&agent), "Windows 10");
    }

    #[test]
    fn agent_os_returns_version_only_when_build_whitespace() {
        let agent = make_agent(|a| a.os_build = "   ".into());
        assert_eq!(agent_os(&agent), "Windows 10");
    }

    #[test]
    fn agent_sleep_jitter_both_present() {
        let agent = make_agent(|_| {});
        assert_eq!(agent_sleep_jitter(&agent), "5s / 20%");
    }

    #[test]
    fn agent_sleep_jitter_delay_only() {
        let agent = make_agent(|a| a.sleep_jitter = String::new());
        assert_eq!(agent_sleep_jitter(&agent), "5");
    }

    #[test]
    fn agent_sleep_jitter_jitter_only() {
        let agent = make_agent(|a| a.sleep_delay = String::new());
        assert_eq!(agent_sleep_jitter(&agent), "j20%");
    }

    #[test]
    fn agent_sleep_jitter_both_empty() {
        let agent = make_agent(|a| {
            a.sleep_delay = String::new();
            a.sleep_jitter = String::new();
        });
        assert_eq!(agent_sleep_jitter(&agent), "");
    }

    #[test]
    fn agent_sleep_jitter_whitespace_treated_as_empty() {
        let agent = make_agent(|a| {
            a.sleep_delay = "  ".into();
            a.sleep_jitter = "  ".into();
        });
        assert_eq!(agent_sleep_jitter(&agent), "");
    }

    #[test]
    fn agent_metadata_all_empty() {
        let agent = make_agent(|a| {
            a.internal_ip = String::new();
            a.external_ip = String::new();
            a.process_arch = String::new();
            a.os_arch = String::new();
            a.os_version = String::new();
            a.os_build = String::new();
            a.sleep_delay = String::new();
            a.sleep_jitter = String::new();
        });
        assert_eq!(agent_ip(&agent), "");
        assert_eq!(agent_arch(&agent), "");
        assert_eq!(agent_os(&agent), "");
        assert_eq!(agent_sleep_jitter(&agent), "");
    }

    // ---- ellipsize tests ----

    #[test]
    fn ellipsize_shorter_than_max() {
        assert_eq!(ellipsize("hello", 10), "hello");
    }

    #[test]
    fn ellipsize_exactly_at_max() {
        assert_eq!(ellipsize("hello", 5), "hello");
    }

    #[test]
    fn ellipsize_longer_than_max() {
        assert_eq!(ellipsize("hello world", 5), "hell...");
    }

    #[test]
    fn ellipsize_max_one() {
        // max_chars=1 means we break at index 0, so empty prefix + "..."
        assert_eq!(ellipsize("hello", 1), "...");
    }

    #[test]
    fn ellipsize_max_zero() {
        assert_eq!(ellipsize("hello", 0), "...");
    }

    #[test]
    fn ellipsize_empty_string() {
        assert_eq!(ellipsize("", 5), "");
    }

    #[test]
    fn ellipsize_multibyte_chars() {
        // "héllo" is 5 chars; max_chars=3 should keep 2 chars + "..."
        assert_eq!(ellipsize("héllo", 3), "hé...");
    }

    // ---- blank_if_empty tests ----

    #[test]
    fn blank_if_empty_returns_value_when_non_empty() {
        assert_eq!(blank_if_empty("hello", "fallback"), "hello");
    }

    #[test]
    fn blank_if_empty_returns_fallback_for_empty_string() {
        assert_eq!(blank_if_empty("", "fallback"), "fallback");
    }

    #[test]
    fn blank_if_empty_returns_fallback_for_whitespace() {
        assert_eq!(blank_if_empty("   ", "fallback"), "fallback");
    }

    #[test]
    fn blank_if_empty_returns_fallback_for_tab_and_newline() {
        assert_eq!(blank_if_empty("\t\n", "fallback"), "fallback");
    }

    // ---- console_completion_candidates tests ----

    #[test]
    fn completion_empty_prefix_returns_all_commands() {
        let all = console_completion_candidates("");
        assert_eq!(all.len(), CONSOLE_COMMANDS.len());
        for spec in &CONSOLE_COMMANDS {
            assert!(all.contains(&spec.name), "missing command: {}", spec.name);
        }
    }

    #[test]
    fn completion_prefix_matches_command_names() {
        let matches = console_completion_candidates("sc");
        assert_eq!(matches, vec!["screenshot"]);
    }

    #[test]
    fn completion_prefix_matches_via_alias() {
        // "exit" is an alias for "kill"
        let matches = console_completion_candidates("ex");
        assert!(matches.contains(&"kill"), "expected 'kill' via alias 'exit'");
    }

    #[test]
    fn completion_no_match_returns_empty() {
        let matches = console_completion_candidates("zzz");
        assert!(matches.is_empty());
    }

    #[test]
    fn completion_case_insensitive() {
        let matches = console_completion_candidates("SC");
        assert_eq!(matches, vec!["screenshot"]);
    }

    #[test]
    fn completion_whitespace_only_prefix_returns_all() {
        let all = console_completion_candidates("   ");
        assert_eq!(all.len(), CONSOLE_COMMANDS.len());
    }

    // ---- closest_command_usage tests ----

    #[test]
    fn closest_usage_known_command() {
        assert_eq!(closest_command_usage("kill"), Some("kill [process]"));
    }

    #[test]
    fn closest_usage_via_alias() {
        // "exit" is an alias for "kill", should return kill's usage
        assert_eq!(closest_command_usage("exit"), Some("kill [process]"));
    }

    #[test]
    fn closest_usage_unknown_returns_none() {
        assert_eq!(closest_command_usage("nonexistent"), None);
    }

    #[test]
    fn closest_usage_empty_string_returns_none() {
        assert_eq!(closest_command_usage(""), None);
    }

    // ---- script_status_label ----

    #[test]
    fn script_status_label_loaded() {
        assert_eq!(script_status_label(ScriptLoadStatus::Loaded), "loaded");
    }

    #[test]
    fn script_status_label_error() {
        assert_eq!(script_status_label(ScriptLoadStatus::Error), "error");
    }

    #[test]
    fn script_status_label_unloaded() {
        assert_eq!(script_status_label(ScriptLoadStatus::Unloaded), "unloaded");
    }

    #[test]
    fn script_status_label_all_variants_non_empty() {
        for status in
            [ScriptLoadStatus::Loaded, ScriptLoadStatus::Error, ScriptLoadStatus::Unloaded]
        {
            assert!(!script_status_label(status).is_empty());
        }
    }

    // ---- script_status_color ----

    #[test]
    fn script_status_color_loaded() {
        assert_eq!(script_status_color(ScriptLoadStatus::Loaded), Color32::from_rgb(110, 199, 141));
    }

    #[test]
    fn script_status_color_error() {
        assert_eq!(script_status_color(ScriptLoadStatus::Error), Color32::from_rgb(215, 83, 83));
    }

    #[test]
    fn script_status_color_unloaded() {
        assert_eq!(
            script_status_color(ScriptLoadStatus::Unloaded),
            Color32::from_rgb(232, 182, 83)
        );
    }

    #[test]
    fn script_status_color_all_variants_distinct() {
        let colors: Vec<Color32> =
            [ScriptLoadStatus::Loaded, ScriptLoadStatus::Error, ScriptLoadStatus::Unloaded]
                .iter()
                .map(|s| script_status_color(*s))
                .collect();
        assert_ne!(colors[0], colors[1]);
        assert_ne!(colors[1], colors[2]);
        assert_ne!(colors[0], colors[2]);
    }

    // ---- script_output_label ----

    #[test]
    fn script_output_label_stdout() {
        assert_eq!(script_output_label(ScriptOutputStream::Stdout), "stdout");
    }

    #[test]
    fn script_output_label_stderr() {
        assert_eq!(script_output_label(ScriptOutputStream::Stderr), "stderr");
    }

    #[test]
    fn script_output_label_all_variants_non_empty() {
        for stream in [ScriptOutputStream::Stdout, ScriptOutputStream::Stderr] {
            assert!(!script_output_label(stream).is_empty());
        }
    }

    // ---- script_output_color ----

    #[test]
    fn script_output_color_stdout() {
        assert_eq!(
            script_output_color(ScriptOutputStream::Stdout),
            Color32::from_rgb(110, 199, 141)
        );
    }

    #[test]
    fn script_output_color_stderr() {
        assert_eq!(script_output_color(ScriptOutputStream::Stderr), Color32::from_rgb(215, 83, 83));
    }

    #[test]
    fn script_output_color_variants_distinct() {
        assert_ne!(
            script_output_color(ScriptOutputStream::Stdout),
            script_output_color(ScriptOutputStream::Stderr)
        );
    }

    // ---- script_name_for_display ----

    #[test]
    fn script_name_for_display_extracts_stem() {
        assert_eq!(
            script_name_for_display(Path::new("/home/user/scripts/recon.py")),
            Some("recon".to_owned())
        );
    }

    #[test]
    fn script_name_for_display_no_extension() {
        assert_eq!(
            script_name_for_display(Path::new("/usr/bin/myscript")),
            Some("myscript".to_owned())
        );
    }

    #[test]
    fn script_name_for_display_just_filename() {
        assert_eq!(script_name_for_display(Path::new("tool.py")), Some("tool".to_owned()));
    }

    #[test]
    fn script_name_for_display_empty_path() {
        assert_eq!(script_name_for_display(Path::new("")), None);
    }

    #[test]
    fn script_name_for_display_root_path() {
        assert_eq!(script_name_for_display(Path::new("/")), None);
    }

    // ---- role_badge_color ----

    #[test]
    fn role_badge_color_admin() {
        assert_eq!(role_badge_color(Some("admin")), Color32::from_rgb(220, 80, 60));
    }

    #[test]
    fn role_badge_color_admin_case_insensitive() {
        assert_eq!(role_badge_color(Some("Admin")), Color32::from_rgb(220, 80, 60));
        assert_eq!(role_badge_color(Some("ADMIN")), Color32::from_rgb(220, 80, 60));
    }

    #[test]
    fn role_badge_color_operator() {
        assert_eq!(role_badge_color(Some("operator")), Color32::from_rgb(60, 130, 220));
    }

    #[test]
    fn role_badge_color_readonly_variants() {
        let expected = Color32::from_rgb(100, 180, 100);
        assert_eq!(role_badge_color(Some("readonly")), expected);
        assert_eq!(role_badge_color(Some("read-only")), expected);
        assert_eq!(role_badge_color(Some("analyst")), expected);
    }

    #[test]
    fn role_badge_color_unknown_role() {
        assert_eq!(role_badge_color(Some("superuser")), Color32::from_rgb(140, 140, 140));
    }

    #[test]
    fn role_badge_color_none() {
        assert_eq!(role_badge_color(None), Color32::from_rgb(140, 140, 140));
    }

    // ---- session_graph_status_color ----

    #[test]
    fn session_graph_status_color_active_variants() {
        let active_color = Color32::from_rgb(84, 170, 110);
        assert_eq!(session_graph_status_color("active"), active_color);
        assert_eq!(session_graph_status_color("alive"), active_color);
        assert_eq!(session_graph_status_color("online"), active_color);
        assert_eq!(session_graph_status_color("true"), active_color);
    }

    #[test]
    fn session_graph_status_color_active_case_insensitive() {
        let active_color = Color32::from_rgb(84, 170, 110);
        assert_eq!(session_graph_status_color("Active"), active_color);
        assert_eq!(session_graph_status_color("ALIVE"), active_color);
    }

    #[test]
    fn session_graph_status_color_dead() {
        let dead_color = Color32::from_rgb(174, 68, 68);
        assert_eq!(session_graph_status_color("dead"), dead_color);
        assert_eq!(session_graph_status_color("offline"), dead_color);
    }

    #[test]
    fn session_graph_status_color_unknown() {
        assert_eq!(session_graph_status_color("something_else"), Color32::from_rgb(174, 68, 68));
    }

    // ── Listener dialog & message builder tests ─────────────────────

    #[test]
    fn listener_protocol_label_round_trips() {
        for proto in ListenerProtocol::ALL {
            let label = proto.label();
            assert!(!label.is_empty());
        }
        assert_eq!(ListenerProtocol::Http.label(), "Http");
        assert_eq!(ListenerProtocol::Https.label(), "Https");
        assert_eq!(ListenerProtocol::Smb.label(), "Smb");
        assert_eq!(ListenerProtocol::External.label(), "External");
    }

    #[test]
    fn listener_dialog_new_create_defaults() {
        let dialog = ListenerDialogState::new_create();
        assert_eq!(dialog.mode, ListenerDialogMode::Create);
        assert_eq!(dialog.protocol, ListenerProtocol::Http);
        assert!(dialog.name.is_empty());
        assert!(dialog.host.is_empty());
        assert!(dialog.port.is_empty());
        assert!(!dialog.proxy_enabled);
    }

    #[test]
    fn listener_dialog_to_info_http() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "test-http".to_owned();
        dialog.protocol = ListenerProtocol::Http;
        dialog.host = "0.0.0.0".to_owned();
        dialog.port = "8080".to_owned();
        dialog.user_agent = "TestAgent/1.0".to_owned();
        dialog.headers = "X-Custom: val".to_owned();
        dialog.uris = "/api/v1".to_owned();
        dialog.host_header = "example.com".to_owned();

        let info = dialog.to_listener_info();
        assert_eq!(info.name.as_deref(), Some("test-http"));
        assert_eq!(info.protocol.as_deref(), Some("Http"));
        assert_eq!(info.host_bind.as_deref(), Some("0.0.0.0"));
        assert_eq!(info.port_bind.as_deref(), Some("8080"));
        assert_eq!(info.user_agent.as_deref(), Some("TestAgent/1.0"));
        assert_eq!(info.headers.as_deref(), Some("X-Custom: val"));
        assert_eq!(info.uris.as_deref(), Some("/api/v1"));
        assert_eq!(info.secure.as_deref(), Some("false"));
        assert_eq!(info.proxy_enabled.as_deref(), Some("false"));
        // Proxy fields should be None when not enabled
        assert!(info.proxy_type.is_none());
        assert!(info.proxy_host.is_none());
        // HostHeader is in extra
        assert_eq!(info.extra.get("HostHeader").and_then(|v| v.as_str()), Some("example.com"));
    }

    #[test]
    fn listener_dialog_to_info_https_with_proxy() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "test-https".to_owned();
        dialog.protocol = ListenerProtocol::Https;
        dialog.host = "0.0.0.0".to_owned();
        dialog.port = "443".to_owned();
        dialog.proxy_enabled = true;
        dialog.proxy_type = "http".to_owned();
        dialog.proxy_host = "proxy.local".to_owned();
        dialog.proxy_port = "3128".to_owned();
        dialog.proxy_username = "user".to_owned();
        dialog.proxy_password = Zeroizing::new("pass".to_owned());

        let info = dialog.to_listener_info();
        assert_eq!(info.protocol.as_deref(), Some("Https"));
        assert_eq!(info.secure.as_deref(), Some("true"));
        assert_eq!(info.proxy_enabled.as_deref(), Some("true"));
        assert_eq!(info.proxy_type.as_deref(), Some("http"));
        assert_eq!(info.proxy_host.as_deref(), Some("proxy.local"));
        assert_eq!(info.proxy_port.as_deref(), Some("3128"));
        assert_eq!(info.proxy_username.as_deref(), Some("user"));
        assert_eq!(info.proxy_password.as_deref(), Some("pass"));
    }

    /// The proxy_password field must be `Zeroizing<String>` so that heap memory is wiped on drop.
    /// This test is a compile-time contract: if the field type is changed to a bare `String`,
    /// the `Zeroizing::clone` call below will fail to compile.
    #[test]
    fn proxy_password_field_is_zeroizing() {
        let mut dialog = ListenerDialogState::new_create();
        *dialog.proxy_password = "secret".to_owned();
        // Confirm we hold a Zeroizing<String> — the explicit type annotation is the assertion.
        let _z: Zeroizing<String> = dialog.proxy_password.clone();
        assert_eq!(*_z, "secret");
    }

    #[test]
    fn listener_dialog_to_info_smb() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "smb-pipe".to_owned();
        dialog.protocol = ListenerProtocol::Smb;
        dialog.pipe_name = r"\\.\pipe\mypipe".to_owned();

        let info = dialog.to_listener_info();
        assert_eq!(info.name.as_deref(), Some("smb-pipe"));
        assert_eq!(info.protocol.as_deref(), Some("Smb"));
        assert_eq!(info.extra.get("PipeName").and_then(|v| v.as_str()), Some(r"\\.\pipe\mypipe"));
        // HTTP-specific fields should be default
        assert!(info.host_bind.is_none());
        assert!(info.port_bind.is_none());
    }

    #[test]
    fn listener_dialog_to_info_external() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "ext-listener".to_owned();
        dialog.protocol = ListenerProtocol::External;
        dialog.endpoint = "/callback".to_owned();

        let info = dialog.to_listener_info();
        assert_eq!(info.name.as_deref(), Some("ext-listener"));
        assert_eq!(info.protocol.as_deref(), Some("External"));
        assert_eq!(info.extra.get("Endpoint").and_then(|v| v.as_str()), Some("/callback"));
    }

    #[test]
    fn listener_dialog_new_edit_preserves_fields() {
        let mut source = ListenerInfo::default();
        source.host_bind = Some("10.0.0.1".to_owned());
        source.port_bind = Some("8443".to_owned());
        source.user_agent = Some("MyAgent".to_owned());
        source.proxy_enabled = Some("true".to_owned());
        source.proxy_type = Some("https".to_owned());
        source.proxy_host = Some("px.local".to_owned());
        source.extra.insert("PipeName".to_owned(), serde_json::Value::String("pipe1".to_owned()));

        let dialog = ListenerDialogState::new_edit("mylistener", "Https", &source);
        assert_eq!(dialog.mode, ListenerDialogMode::Edit);
        assert_eq!(dialog.name, "mylistener");
        assert_eq!(dialog.protocol, ListenerProtocol::Https);
        assert_eq!(dialog.host, "10.0.0.1");
        assert_eq!(dialog.port, "8443");
        assert_eq!(dialog.user_agent, "MyAgent");
        assert!(dialog.proxy_enabled);
        assert_eq!(dialog.proxy_type, "https");
        assert_eq!(dialog.proxy_host, "px.local");
        assert_eq!(dialog.pipe_name, "pipe1");
    }

    #[test]
    fn build_listener_new_creates_correct_message() {
        let info = ListenerInfo {
            name: Some("http-1".to_owned()),
            protocol: Some("Http".to_owned()),
            ..ListenerInfo::default()
        };
        let msg = build_listener_new(info, "operator1");
        match msg {
            OperatorMessage::ListenerNew(m) => {
                assert_eq!(m.head.event, EventCode::Listener);
                assert_eq!(m.head.user, "operator1");
                assert_eq!(m.info.name.as_deref(), Some("http-1"));
            }
            _ => panic!("expected ListenerNew"),
        }
    }

    #[test]
    fn build_listener_edit_creates_correct_message() {
        let info = ListenerInfo { name: Some("http-1".to_owned()), ..ListenerInfo::default() };
        let msg = build_listener_edit(info, "op2");
        match msg {
            OperatorMessage::ListenerEdit(m) => {
                assert_eq!(m.head.event, EventCode::Listener);
                assert_eq!(m.head.user, "op2");
            }
            _ => panic!("expected ListenerEdit"),
        }
    }

    #[test]
    fn build_listener_remove_creates_correct_message() {
        let msg = build_listener_remove("http-1", "op3");
        match msg {
            OperatorMessage::ListenerRemove(m) => {
                assert_eq!(m.head.event, EventCode::Listener);
                assert_eq!(m.head.user, "op3");
                assert_eq!(m.info.name, "http-1");
            }
            _ => panic!("expected ListenerRemove"),
        }
    }

    #[test]
    fn listener_dialog_http_empty_optional_fields_produce_none() {
        let mut dialog = ListenerDialogState::new_create();
        dialog.name = "minimal".to_owned();
        dialog.protocol = ListenerProtocol::Http;
        dialog.host = "0.0.0.0".to_owned();
        dialog.port = "80".to_owned();
        // Leave user_agent, headers, uris, host_header all empty

        let info = dialog.to_listener_info();
        assert!(info.user_agent.is_none());
        assert!(info.headers.is_none());
        assert!(info.uris.is_none());
        assert!(!info.extra.contains_key("HostHeader"));
    }

    // ── Payload dialog tests ────────────────────────────────────────

    #[test]
    fn payload_dialog_new_defaults() {
        let dialog = PayloadDialogState::new();
        assert_eq!(dialog.agent_type, "Demon");
        assert!(dialog.listener.is_empty());
        assert_eq!(dialog.arch, PayloadArch::X64);
        assert_eq!(dialog.format, PayloadFormat::WindowsExe);
        assert_eq!(dialog.sleep, "2");
        assert_eq!(dialog.jitter, "20");
        assert!(dialog.indirect_syscall);
        assert_eq!(dialog.sleep_technique, SleepTechnique::WaitForSingleObjectEx);
        assert_eq!(dialog.alloc, AllocMethod::NativeSyscall);
        assert_eq!(dialog.execute, ExecuteMethod::NativeSyscall);
        assert_eq!(dialog.spawn64, r"C:\Windows\System32\notepad.exe");
        assert_eq!(dialog.spawn32, r"C:\Windows\SysWOW64\notepad.exe");
        assert!(!dialog.building);
    }

    #[test]
    fn payload_dialog_config_json_contains_all_fields() {
        let dialog = PayloadDialogState::new();
        let json_str = dialog.config_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["Sleep"], "2");
        assert_eq!(parsed["Jitter"], "20");
        assert_eq!(parsed["IndirectSyscall"], true);
        assert_eq!(parsed["SleepTechnique"], "WaitForSingleObjectEx");
        assert_eq!(parsed["Alloc"], "Native/Syscall");
        assert_eq!(parsed["Execute"], "Native/Syscall");
        assert_eq!(parsed["Spawn64"], r"C:\Windows\System32\notepad.exe");
        assert_eq!(parsed["Spawn32"], r"C:\Windows\SysWOW64\notepad.exe");
    }

    #[test]
    fn payload_dialog_config_json_reflects_changes() {
        let mut dialog = PayloadDialogState::new();
        dialog.sleep = "10".to_owned();
        dialog.jitter = "50".to_owned();
        dialog.indirect_syscall = false;
        dialog.sleep_technique = SleepTechnique::Ekko;
        dialog.alloc = AllocMethod::Win32;
        dialog.execute = ExecuteMethod::Win32;

        let json_str = dialog.config_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["Sleep"], "10");
        assert_eq!(parsed["Jitter"], "50");
        assert_eq!(parsed["IndirectSyscall"], false);
        assert_eq!(parsed["SleepTechnique"], "Ekko");
        assert_eq!(parsed["Alloc"], "Win32");
        assert_eq!(parsed["Execute"], "Win32");
    }

    #[test]
    fn build_payload_request_creates_correct_message() {
        let mut dialog = PayloadDialogState::new();
        dialog.listener = "http-listener".to_owned();
        dialog.arch = PayloadArch::X86;
        dialog.format = PayloadFormat::WindowsShellcode;

        let msg = build_payload_request(&dialog, "operator1");
        match msg {
            OperatorMessage::BuildPayloadRequest(m) => {
                assert_eq!(m.head.event, EventCode::Gate);
                assert_eq!(m.head.user, "operator1");
                assert_eq!(m.info.agent_type, "Demon");
                assert_eq!(m.info.listener, "http-listener");
                assert_eq!(m.info.arch, "x86");
                assert_eq!(m.info.format, "Windows Shellcode");
                // Config should be valid JSON
                let config: serde_json::Value = serde_json::from_str(&m.info.config).unwrap();
                assert_eq!(config["Sleep"], "2");
            }
            _ => panic!("expected BuildPayloadRequest"),
        }
    }

    #[test]
    fn payload_arch_labels() {
        assert_eq!(PayloadArch::X64.label(), "x64");
        assert_eq!(PayloadArch::X86.label(), "x86");
    }

    #[test]
    fn payload_format_labels() {
        assert_eq!(PayloadFormat::WindowsExe.label(), "Windows Exe");
        assert_eq!(PayloadFormat::WindowsServiceExe.label(), "Windows Service Exe");
        assert_eq!(PayloadFormat::WindowsDll.label(), "Windows Dll");
        assert_eq!(PayloadFormat::WindowsReflectiveDll.label(), "Windows Reflective Dll");
        assert_eq!(PayloadFormat::WindowsShellcode.label(), "Windows Shellcode");
    }

    #[test]
    fn sleep_technique_labels() {
        assert_eq!(SleepTechnique::WaitForSingleObjectEx.label(), "WaitForSingleObjectEx");
        assert_eq!(SleepTechnique::Ekko.label(), "Ekko");
        assert_eq!(SleepTechnique::Zilean.label(), "Zilean");
        assert_eq!(SleepTechnique::None.label(), "None");
    }

    #[test]
    fn alloc_execute_method_labels() {
        assert_eq!(AllocMethod::NativeSyscall.label(), "Native/Syscall");
        assert_eq!(AllocMethod::Win32.label(), "Win32");
        assert_eq!(ExecuteMethod::NativeSyscall.label(), "Native/Syscall");
        assert_eq!(ExecuteMethod::Win32.label(), "Win32");
    }

    #[test]
    fn build_console_message_color_mapping() {
        assert_eq!(build_console_message_color("Good"), Color32::from_rgb(85, 255, 85));
        assert_eq!(build_console_message_color("Error"), Color32::from_rgb(255, 85, 85));
        assert_eq!(build_console_message_color("Warning"), Color32::from_rgb(255, 200, 50));
        assert_eq!(build_console_message_color("Info"), Color32::from_rgb(180, 180, 220));
        assert_eq!(build_console_message_color("unknown"), Color32::from_rgb(180, 180, 220));
    }

    #[test]
    fn build_console_message_prefix_mapping() {
        assert_eq!(build_console_message_prefix("Good"), "[+]");
        assert_eq!(build_console_message_prefix("Error"), "[-]");
        assert_eq!(build_console_message_prefix("Warning"), "[!]");
        assert_eq!(build_console_message_prefix("Info"), "[*]");
        assert_eq!(build_console_message_prefix("other"), "[*]");
    }

    // ---- console prompt format tests ----

    #[test]
    fn format_console_prompt_includes_operator_and_agent_id() {
        let prompt = format_console_prompt("alice", "DEAD1234");
        assert_eq!(prompt, "[alice/DEAD1234] demon.x64 >> ");
    }

    #[test]
    fn format_console_prompt_uses_fallback_when_operator_empty() {
        let prompt = format_console_prompt("", "DEAD1234");
        assert_eq!(prompt, "[operator/DEAD1234] demon.x64 >> ");
    }

    // ---- help command tests ----

    #[test]
    fn handle_local_command_help_returns_command_table() {
        let output = handle_local_command("help").expect("help should be handled locally");
        assert!(output.contains("Demon Commands"));
        assert!(output.contains("Command"));
        assert!(output.contains("Type"));
        assert!(output.contains("Description"));
        // Verify a sample of commands appear in the table.
        assert!(output.contains("shell"));
        assert!(output.contains("sleep"));
        assert!(output.contains("token"));
        assert!(output.contains("inline-execute"));
    }

    #[test]
    fn handle_local_command_help_specific_command() {
        let output = handle_local_command("help shell").expect("help shell should be handled");
        assert!(output.contains("shell"));
        assert!(output.contains("Usage:"));
        assert!(output.contains("Description:"));
    }

    #[test]
    fn handle_local_command_help_unknown_topic() {
        let output = handle_local_command("help nonexistent").expect("should still return output");
        assert!(output.contains("Unknown command"));
    }

    #[test]
    fn handle_local_command_question_mark_alias() {
        let output = handle_local_command("?").expect("? should work as help alias");
        assert!(output.contains("Demon Commands"));
    }

    #[test]
    fn handle_local_command_returns_none_for_remote_commands() {
        assert!(handle_local_command("ps").is_none());
        assert!(handle_local_command("shell whoami").is_none());
        assert!(handle_local_command("sleep 10").is_none());
    }

    // ---- new command dispatch tests ----

    #[test]
    fn build_console_task_shell_command() {
        let result = build_console_task("ABCD1234", "shell whoami", "operator");
        let msg = result.unwrap_or_else(|e| panic!("shell task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
        assert_eq!(info.arguments.as_deref(), Some("whoami"));
    }

    #[test]
    fn build_console_task_sleep_with_jitter() {
        let result = build_console_task("ABCD1234", "sleep 30 50%", "operator");
        let msg = result.unwrap_or_else(|e| panic!("sleep task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandSleep).to_string());
        assert_eq!(info.arguments.as_deref(), Some("30;50"));
    }

    #[test]
    fn build_console_task_sleep_without_jitter() {
        let result = build_console_task("ABCD1234", "sleep 10", "operator");
        let msg = result.unwrap_or_else(|e| panic!("sleep task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.arguments.as_deref(), Some("10;0"));
    }

    #[test]
    fn build_console_task_sleep_rejects_missing_delay() {
        let result = build_console_task("ABCD1234", "sleep", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_dir_uses_explorer_format() {
        let result = build_console_task("ABCD1234", "dir C:\\Temp", "operator");
        let msg = result.unwrap_or_else(|e| panic!("dir task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandFs).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("dir"));
        assert!(info.arguments.as_deref().unwrap_or_default().contains("C:\\Temp"));
    }

    #[test]
    fn build_console_task_cp_requires_two_args() {
        let result = build_console_task("ABCD1234", "cp /tmp/a", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_cp_sends_both_paths() {
        let result = build_console_task("ABCD1234", "cp /tmp/a /tmp/b", "operator");
        let msg = result.unwrap_or_else(|e| panic!("cp task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.sub_command.as_deref(), Some("cp"));
        assert_eq!(info.arguments.as_deref(), Some("/tmp/a;/tmp/b"));
    }

    #[test]
    fn build_console_task_mv_sends_both_paths() {
        let result = build_console_task("ABCD1234", "mv /tmp/a /tmp/b", "operator");
        let msg = result.unwrap_or_else(|e| panic!("mv task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.sub_command.as_deref(), Some("move"));
    }

    #[test]
    fn build_console_task_token_list() {
        let result = build_console_task("ABCD1234", "token list", "operator");
        let msg = result.unwrap_or_else(|e| panic!("token task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandToken).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("list"));
    }

    #[test]
    fn build_console_task_token_requires_subcommand() {
        let result = build_console_task("ABCD1234", "token", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_net_domain() {
        let result = build_console_task("ABCD1234", "net domain", "operator");
        let msg = result.unwrap_or_else(|e| panic!("net task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandNet).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("domain"));
    }

    #[test]
    fn build_console_task_config_sets_subcommand() {
        let result = build_console_task("ABCD1234", "config sleep-obf true", "operator");
        let msg = result.unwrap_or_else(|e| panic!("config task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("sleep-obf"));
        assert_eq!(info.arguments.as_deref(), Some("true"));
    }

    #[test]
    fn build_console_task_pivot_requires_subcommand() {
        let result = build_console_task("ABCD1234", "pivot", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_kerberos_luid() {
        let result = build_console_task("ABCD1234", "kerberos luid", "operator");
        let msg = result.unwrap_or_else(|e| panic!("kerberos task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandKerberos).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("luid"));
    }

    #[test]
    fn build_console_task_rportfwd_list() {
        let result = build_console_task("ABCD1234", "rportfwd list", "operator");
        let msg = result.unwrap_or_else(|e| panic!("rportfwd task should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandSocket).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("rportfwd list"));
    }

    #[test]
    fn build_console_task_proc_modules() {
        let result = build_console_task("ABCD1234", "proc modules", "operator");
        let msg = result.unwrap_or_else(|e| panic!("proc modules should build: {e}"));
        let (_, info) = unwrap_agent_task(msg);
        assert_eq!(info.command_id, u32::from(DemonCommand::CommandProc).to_string());
        assert_eq!(info.sub_command.as_deref(), Some("modules"));
    }

    #[test]
    fn build_console_task_proc_invalid_subcommand() {
        let result = build_console_task("ABCD1234", "proc bogus", "operator");
        assert!(result.is_err());
    }

    #[test]
    fn build_console_task_help_is_not_dispatched_remotely() {
        let result = build_console_task("ABCD1234", "help", "operator");
        assert!(result.is_err(), "help should not produce a remote task");
    }

    #[test]
    fn build_help_output_full_table_lists_all_commands() {
        let output = build_help_output(None);
        for spec in &CONSOLE_COMMANDS {
            assert!(output.contains(spec.name), "help table should contain `{}`", spec.name);
        }
    }

    #[test]
    fn build_help_output_specific_command_shows_details() {
        let output = build_help_output(Some("token"));
        assert!(output.contains("token"));
        assert!(output.contains("Usage:"));
        assert!(output.contains("Type:"));
        assert!(output.contains("Description:"));
    }

    #[test]
    fn build_help_output_alias_resolves() {
        let output = build_help_output(Some("bof"));
        assert!(output.contains("inline-execute"));
    }

    #[test]
    fn console_commands_all_have_descriptions() {
        for spec in &CONSOLE_COMMANDS {
            assert!(!spec.description.is_empty(), "command `{}` missing description", spec.name);
            assert!(!spec.cmd_type.is_empty(), "command `{}` missing type", spec.name);
            assert!(!spec.usage.is_empty(), "command `{}` missing usage", spec.name);
        }
    }

    #[test]
    fn console_commands_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for spec in &CONSOLE_COMMANDS {
            assert!(seen.insert(spec.name), "duplicate command name: {}", spec.name);
        }
    }

    #[test]
    fn completion_includes_new_commands() {
        let all = console_completion_candidates("");
        assert!(all.contains(&"shell"));
        assert!(all.contains(&"sleep"));
        assert!(all.contains(&"token"));
        assert!(all.contains(&"inline-execute"));
        assert!(all.contains(&"net"));
        assert!(all.contains(&"config"));
        assert!(all.contains(&"help"));
    }

    #[test]
    fn completion_pivot_matches_p_prefix() {
        let matches = console_completion_candidates("pi");
        assert!(matches.contains(&"pivot"));
    }

    // ── Loot panel types ─────────────────────────────────────────────────

    #[test]
    fn loot_tab_default_is_credentials() {
        assert_eq!(LootTab::default(), LootTab::Credentials);
    }

    #[test]
    fn credential_sort_column_default_is_name() {
        assert_eq!(CredentialSortColumn::default(), CredentialSortColumn::Name);
    }

    #[test]
    fn loot_panel_state_default_values() {
        let state = LootPanelState::default();
        assert_eq!(state.active_tab, LootTab::Credentials);
        assert!(state.selected_screenshot.is_none());
        assert!(!state.cred_sort_desc);
        assert!(state.filter_dirty);
        assert!(state.filtered_loot.is_empty());
    }

    #[test]
    fn build_filtered_loot_indices_returns_matching_positions() {
        let loot = vec![
            make_loot_item(LootKind::Credential, "alice hash", "AA", "2026-03-10T12:00:00Z"),
            make_loot_item(LootKind::File, "report.pdf", "BB", "2026-03-11T12:00:00Z"),
            make_loot_item(LootKind::Credential, "bob hash", "BB", "2026-03-12T12:00:00Z"),
        ];

        let indices = build_filtered_loot_indices(
            &loot,
            LootTypeFilter::Credentials,
            CredentialSubFilter::All,
            FileSubFilter::All,
            "bb",
            "",
            "",
            "hash",
        );

        assert_eq!(indices, vec![2]);
    }

    #[test]
    fn loot_panel_refresh_filtered_loot_rebuilds_when_revision_changes() {
        let mut panel = LootPanelState { active_tab: LootTab::Files, ..LootPanelState::default() };
        let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
        state.loot.push(make_loot_item(LootKind::File, "report.pdf", "AA", "2026-03-10T12:00:00Z"));
        state.loot_revision = 1;

        panel.refresh_filtered_loot(
            &state,
            CredentialSubFilter::All,
            FileSubFilter::Document,
            "",
            "",
            "",
            "",
        );
        assert_eq!(panel.filtered_loot, vec![0]);
        assert!(!panel.filter_dirty);

        state.loot.push(make_loot_item(LootKind::File, "backup.zip", "AA", "2026-03-11T12:00:00Z"));
        state.loot[1].file_path = Some("C:\\Temp\\backup.zip".to_owned());
        state.loot_revision += 1;

        panel.refresh_filtered_loot(
            &state,
            CredentialSubFilter::All,
            FileSubFilter::Archive,
            "",
            "",
            "",
            "",
        );

        assert_eq!(panel.filtered_loot, vec![1]);
        assert_eq!(panel.cached_loot_revision, state.loot_revision);
    }

    #[test]
    fn credential_category_color_returns_distinct_colors() {
        let ntlm_item = LootItem {
            id: Some(1),
            kind: LootKind::Credential,
            name: "NTLM hash".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let plain_item = LootItem {
            id: Some(2),
            kind: LootKind::Credential,
            name: "plaintext password".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let ntlm_color = credential_category_color(&ntlm_item);
        let plain_color = credential_category_color(&plain_item);
        assert_ne!(ntlm_color, plain_color);
    }

    #[test]
    fn credential_category_color_kerberos_and_certificate() {
        let kerb = LootItem {
            id: Some(3),
            kind: LootKind::Credential,
            name: "kerberos ticket".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let cert = LootItem {
            id: Some(4),
            kind: LootKind::Credential,
            name: "certificate".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        let kerb_color = credential_category_color(&kerb);
        let cert_color = credential_category_color(&cert);
        assert_ne!(kerb_color, cert_color);
        // Kerberos = purple, Certificate = cyan
        assert_eq!(kerb_color, Color32::from_rgb(140, 120, 220));
        assert_eq!(cert_color, Color32::from_rgb(80, 180, 220));
    }

    #[test]
    fn credential_category_color_unknown_returns_gray() {
        let unknown = LootItem {
            id: Some(5),
            kind: LootKind::Credential,
            name: "some random cred".to_owned(),
            agent_id: String::new(),
            source: String::new(),
            collected_at: String::new(),
            file_path: None,
            size_bytes: None,
            content_base64: None,
            preview: None,
        };
        assert_eq!(credential_category_color(&unknown), Color32::GRAY);
    }

    #[test]
    fn screenshot_texture_cache_debug_shows_count() {
        let cache = ScreenshotTextureCache::default();
        let debug = format!("{cache:?}");
        assert!(debug.contains("count"));
        assert!(debug.contains('0'));
    }
}
