//! Login dialog submission, authentication transitions, and session expiry handling.

use std::sync::{Arc, Mutex};

use eframe::egui::{self, Align, Layout};

use crate::app::{AppPhase, ClientApp, SESSION_TTL};
use crate::known_servers::host_port_from_url;
use crate::login::{LoginAction, LoginState, render_login_dialog};
use crate::python::PythonRuntime;
use crate::transport::{
    AppState, ClientTransport, ConnectionStatus, SharedAppState, TlsVerification,
};

impl ClientApp {
    pub(crate) fn handle_login_submit(&mut self, ctx: &egui::Context) {
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

    pub(crate) fn check_auth_response(&mut self) {
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
            if let AppPhase::Authenticating { login_state, .. } = &mut self.phase {
                login_state.clear_password();
            }
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
    pub(crate) fn check_session_expiry(&mut self) {
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

    pub(crate) fn render_current_phase(
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
}
