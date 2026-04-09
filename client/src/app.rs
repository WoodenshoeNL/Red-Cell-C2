//! Application shell: [`ClientApp`], lifecycle phase, main window layout, and egui frame hook.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use eframe::egui;
use red_cell_common::operator::OperatorMessage;

use crate::bootstrap::Cli;
use crate::known_servers::KnownServersStore;
use crate::local_config::LocalConfig;
use crate::login::{LoginAction, LoginState, render_login_dialog};
use crate::python::PythonRuntime;
use crate::tasks::build_file_browser_list_task;
use crate::tls;
use crate::transport::{AppState, ClientTransport, SharedAppState, TlsVerification};
use crate::{AgentSortColumn, SessionPanelState};

pub(crate) const SESSION_GRAPH_HEIGHT: f32 = 280.0;
pub(crate) const SESSION_GRAPH_MIN_ZOOM: f32 = 0.35;
pub(crate) const SESSION_GRAPH_MAX_ZOOM: f32 = 2.5;
pub(crate) const SESSION_GRAPH_ROOT_ID: &str = "__teamserver__";

/// Server-side session TTL (teamserver expires tokens after 1 hour).
pub(crate) const SESSION_TTL: Duration = Duration::from_secs(3600);
/// How far before expiry to show the warning banner.
pub(crate) const SESSION_WARN_BEFORE: Duration = Duration::from_secs(300);

/// Application lifecycle phase.
pub(crate) enum AppPhase {
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

pub(crate) struct ClientApp {
    pub(crate) phase: AppPhase,
    pub(crate) local_config: LocalConfig,
    pub(crate) known_servers: KnownServersStore,
    pub(crate) cli_server_url: String,
    pub(crate) scripts_dir: Option<PathBuf>,
    pub(crate) tls_verification: TlsVerification,
    pub(crate) session_panel: SessionPanelState,
    pub(crate) outgoing_tx: Option<tokio::sync::mpsc::UnboundedSender<OperatorMessage>>,
    pub(crate) python_runtime: Option<PythonRuntime>,
    /// Whether the Known Servers verification window is open.
    pub(crate) show_known_servers: bool,
    /// Preserved agent/loot state from the most recent session.  Set when a session
    /// expires so the operator can still see their data while re-authenticating.
    pub(crate) retained_app_state: Option<SharedAppState>,
}

impl ClientApp {
    pub(crate) fn new(cli: Cli) -> Result<Self> {
        let local_config = LocalConfig::load();
        let known_servers = KnownServersStore::load();
        let login_state = LoginState::new(&cli.server, &local_config);
        let tls_verification =
            tls::resolve_tls_verification(&cli, &local_config, &known_servers, &cli.server)?;

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

    pub(crate) fn snapshot(app_state: &SharedAppState) -> AppState {
        match app_state.lock() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub(crate) fn render_main_ui(&mut self, ctx: &egui::Context, app_state: &SharedAppState) {
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

    pub(crate) fn current_operator_username(&self) -> String {
        match &self.phase {
            AppPhase::Connected { app_state, .. } | AppPhase::Authenticating { app_state, .. } => {
                let snapshot = Self::snapshot(app_state);
                snapshot.operator_info.map(|info| info.username).unwrap_or_default()
            }
            AppPhase::Login(_) => String::new(),
        }
    }

    pub(crate) fn build_file_browser_list_message(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Option<OperatorMessage> {
        Some(build_file_browser_list_task(agent_id, path, &self.current_operator_username()))
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
