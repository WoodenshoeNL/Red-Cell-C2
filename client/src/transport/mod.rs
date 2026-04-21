pub(super) mod command_enc;
pub(crate) mod event_bus;
pub(super) mod operator_msg;
pub(super) mod tls;

pub(crate) use event_bus::*;
pub(crate) use tls::{TlsVerification, classify_tls_error, classify_tls_failure_kind};
use tls::{build_tls_connector, is_tls_cert_error, normalize_server_url};

#[cfg(test)]
use tls::FingerprintCertificateVerifier;
#[cfg(test)]
pub(crate) use tls::certificate_fingerprint;

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

use eframe::egui;
use futures_util::StreamExt;
use red_cell_common::crypto::{WsEnvelope, derive_ws_hmac_key, open_ws_frame};
use red_cell_common::operator::OperatorMessage;
use thiserror::Error;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        self,
        client::IntoClientRequest,
        protocol::{CloseFrame, Message as WebSocketMessage, frame::coding::CloseCode},
    },
};
use tracing::warn;

use crate::login::TlsFailure;
use crate::python::PythonRuntime;

type WsHmacKey = Arc<tokio::sync::Mutex<Option<[u8; 32]>>>;

/// Extract the session token embedded in an `InitConnectionSuccess` message.
fn extract_session_token(message: &str) -> Option<&str> {
    message.split_once("SessionToken=").map(|(_, token)| token)
}

const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

/// Compute the next reconnect delay using exponential backoff.
///
/// Doubles `current` up to [`MAX_RECONNECT_DELAY`]. The caller is responsible
/// for resetting to [`INITIAL_RECONNECT_DELAY`] after a successful connection.
fn next_reconnect_delay(current: Duration) -> Duration {
    std::cmp::min(current.saturating_mul(2), MAX_RECONNECT_DELAY)
}

#[derive(Debug)]
pub(crate) struct ClientTransport {
    runtime: Option<Runtime>,
    shutdown_tx: watch::Sender<bool>,
    outgoing_tx: mpsc::UnboundedSender<OperatorMessage>,
}

impl ClientTransport {
    pub(crate) fn spawn(
        server_url: String,
        app_state: SharedAppState,
        repaint: egui::Context,
        python_runtime: Option<PythonRuntime>,
        tls_verification: TlsVerification,
    ) -> Result<Self, TransportError> {
        red_cell_common::tls::install_default_crypto_provider();

        let normalized_server_url = normalize_server_url(&server_url)?;
        {
            let mut state = lock_app_state(&app_state);
            state.server_url = normalized_server_url.clone();
        }

        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("red-cell-client-ws")
            .build()
            .map_err(TransportError::RuntimeInit)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let shared_outgoing_rx = Arc::new(tokio::sync::Mutex::new(outgoing_rx));

        let task_state = app_state.clone();
        runtime.spawn(async move {
            run_connection_manager(
                normalized_server_url,
                task_state,
                shared_outgoing_rx,
                shutdown_rx,
                repaint,
                python_runtime,
                tls_verification,
            )
            .await;
        });

        Ok(Self { runtime: Some(runtime), shutdown_tx, outgoing_tx })
    }

    #[allow(dead_code)]
    pub(crate) fn queue_message(&self, message: OperatorMessage) -> Result<(), TransportError> {
        self.outgoing_tx.send(message).map_err(|_| TransportError::OutgoingQueueClosed)
    }

    pub(crate) fn outgoing_sender(&self) -> mpsc::UnboundedSender<OperatorMessage> {
        self.outgoing_tx.clone()
    }

    /// Create a dummy transport for unit tests (no runtime, no real connection).
    #[cfg(test)]
    pub(crate) fn dummy() -> Self {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (outgoing_tx, _outgoing_rx) = mpsc::unbounded_channel();
        Self { runtime: None, shutdown_tx, outgoing_tx }
    }
}

impl Drop for ClientTransport {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_millis(250));
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum TransportError {
    #[error("failed to initialize Tokio runtime: {0}")]
    RuntimeInit(std::io::Error),
    #[error("invalid teamserver URL `{url}`: {source}")]
    InvalidUrl { url: String, source: url::ParseError },
    #[error("unsupported teamserver URL scheme `{scheme}`")]
    UnsupportedScheme { scheme: String },
    #[error("teamserver URL must include a host")]
    MissingHost,
    #[error("failed to build rustls client config: {0}")]
    Rustls(#[source] Box<tokio_rustls::rustls::Error>),
    #[error("failed to read custom CA certificate from `{path}`: {source}")]
    CustomCaRead { path: String, source: std::io::Error },
    #[error("failed to parse PEM-encoded CA certificate: {0}")]
    CustomCaParse(std::io::Error),
    #[error("no certificates found in the custom CA PEM file `{0}`")]
    CustomCaEmpty(String),
    #[error("custom CA certificate rejected by root store: {0}")]
    CustomCaInvalid(String),
    #[error("failed to build certificate verifier: {0}")]
    RustlsVerifier(String),
    #[error("failed to create websocket request: {0}")]
    WebSocketRequest(#[source] Box<tungstenite::Error>),
    #[error("failed to serialize websocket command: {0}")]
    Serialize(#[from] serde_json::Error),
    #[allow(dead_code)]
    #[error("client transport outgoing queue is closed")]
    OutgoingQueueClosed,
}

type ClientWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn run_connection_manager(
    server_url: String,
    app_state: SharedAppState,
    outgoing_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<OperatorMessage>>>,
    mut shutdown_rx: watch::Receiver<bool>,
    repaint: egui::Context,
    python_runtime: Option<PythonRuntime>,
    tls_verification: TlsVerification,
) {
    let mut reconnect_delay = INITIAL_RECONNECT_DELAY;
    loop {
        if *shutdown_rx.borrow() {
            set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
            return;
        }

        set_connection_status(&app_state, &repaint, ConnectionStatus::Connecting);

        // Fresh fingerprint sink for each connection attempt.
        let fingerprint_sink: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::new(None));

        let disconnect_reason = match connect_websocket(
            &server_url,
            &tls_verification,
            &fingerprint_sink,
        )
        .await
        {
            Ok(socket) => {
                reconnect_delay = INITIAL_RECONNECT_DELAY;
                // Clear any stale TLS failure from a previous attempt so the login
                // UI does not show a cert error panel after a successful reconnect.
                lock_app_state(&app_state).tls_failure = None;
                set_connection_status(&app_state, &repaint, ConnectionStatus::Connected);

                // Per-connection HMAC key — reset on every reconnect attempt.
                let hmac_key: WsHmacKey = Arc::new(tokio::sync::Mutex::new(None));
                let send_seq = Arc::new(AtomicU64::new(0));

                let (write, read) = socket.split();
                let mut receive_task = tokio::spawn(run_receive_loop(
                    read,
                    app_state.clone(),
                    repaint.clone(),
                    python_runtime.clone(),
                    hmac_key.clone(),
                ));
                let mut send_task = tokio::spawn(command_enc::run_send_loop(
                    write,
                    outgoing_rx.clone(),
                    hmac_key,
                    send_seq,
                ));

                let reason = tokio::select! {
                    result = &mut receive_task => join_disconnect_reason(result, "receive task stopped"),
                    result = &mut send_task => join_disconnect_reason(result, "send task stopped"),
                    changed = shutdown_rx.changed() => {
                        match changed {
                            Ok(()) if *shutdown_rx.borrow() => {
                                receive_task.abort();
                                send_task.abort();
                                set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
                                return;
                            }
                            Ok(()) | Err(_) => "connection manager stopped".to_owned(),
                        }
                    }
                };

                receive_task.abort();
                send_task.abort();
                reason
            }
            Err(error) => {
                let raw = error.to_string();
                let captured_fp = fingerprint_sink.lock().ok().and_then(|guard| guard.clone());

                if is_tls_cert_error(&raw) {
                    // TLS certificate errors do not self-heal — stop retrying and surface
                    // the cert fingerprint so the UI can offer an exception prompt.
                    let message = classify_tls_error(&raw);
                    let kind = classify_tls_failure_kind(&raw);
                    {
                        let mut state = lock_app_state(&app_state);
                        state.tls_failure = Some(TlsFailure {
                            message: message.clone(),
                            cert_fingerprint: captured_fp,
                            kind,
                        });
                        state.connection_status = ConnectionStatus::Error(message);
                    }
                    repaint.request_repaint();
                    // Wait for shutdown before returning.
                    let _ = shutdown_rx.changed().await;
                    set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
                    return;
                }

                classify_tls_error(&raw)
            }
        };

        if *shutdown_rx.borrow() {
            set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
            return;
        }

        set_connection_status(
            &app_state,
            &repaint,
            ConnectionStatus::Retrying(format!(
                "{disconnect_reason}. Retrying in {}s",
                reconnect_delay.as_secs()
            )),
        );

        tokio::select! {
            _ = sleep(reconnect_delay) => {}
            changed = shutdown_rx.changed() => {
                match changed {
                    Ok(()) if *shutdown_rx.borrow() => {
                        set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
                        return;
                    }
                    Ok(()) | Err(_) => {
                        set_connection_status(&app_state, &repaint, ConnectionStatus::Disconnected);
                        return;
                    }
                }
            }
        }

        reconnect_delay = next_reconnect_delay(reconnect_delay);
    }
}

async fn connect_websocket(
    server_url: &str,
    tls_verification: &TlsVerification,
    fingerprint_sink: &Arc<std::sync::Mutex<Option<String>>>,
) -> Result<ClientWebSocket, TransportError> {
    let request = server_url
        .into_client_request()
        .map_err(|error| TransportError::WebSocketRequest(Box::new(error)))?;
    let connector = build_tls_connector(tls_verification, Arc::clone(fingerprint_sink))?;
    let (stream, _) = connect_async_tls_with_config(request, None, false, Some(connector))
        .await
        .map_err(|error| TransportError::WebSocketRequest(Box::new(error)))?;
    Ok(stream)
}

async fn run_receive_loop(
    mut read: futures_util::stream::SplitStream<ClientWebSocket>,
    app_state: SharedAppState,
    repaint: egui::Context,
    python_runtime: Option<PythonRuntime>,
    hmac_key: WsHmacKey,
) -> Result<(), String> {
    let mut recv_seq: Option<u64> = None;

    while let Some(frame) = read.next().await {
        match frame {
            Ok(WebSocketMessage::Text(payload)) => {
                let key_snapshot = *hmac_key.lock().await;

                let message: OperatorMessage = if let Some(key) = key_snapshot {
                    // Post-login: every frame must be a valid WsEnvelope.
                    match serde_json::from_str::<WsEnvelope>(&payload) {
                        Ok(envelope) => match open_ws_frame(&key, &envelope, recv_seq) {
                            Ok(inner_json) => {
                                recv_seq = Some(envelope.seq);
                                match serde_json::from_str(&inner_json) {
                                    Ok(msg) => msg,
                                    Err(error) => {
                                        let msg =
                                            format!("failed to decode inner message: {error}");
                                        {
                                            let mut state = lock_app_state(&app_state);
                                            state.connection_status =
                                                ConnectionStatus::Error(msg.clone());
                                        }
                                        repaint.request_repaint();
                                        continue;
                                    }
                                }
                            }
                            Err(_) => {
                                return Err(
                                    "HMAC verification failed — possible tampering".to_owned()
                                );
                            }
                        },
                        Err(error) => {
                            let msg = format!("failed to decode HMAC envelope: {error}");
                            {
                                let mut state = lock_app_state(&app_state);
                                state.connection_status = ConnectionStatus::Error(msg.clone());
                            }
                            repaint.request_repaint();
                            continue;
                        }
                    }
                } else {
                    // Pre-login: plain JSON frame.
                    match serde_json::from_str::<OperatorMessage>(&payload) {
                        Ok(msg) => {
                            if let OperatorMessage::InitConnectionSuccess(ref m) = msg {
                                match extract_session_token(&m.info.message) {
                                    Some(token) => {
                                        *hmac_key.lock().await = Some(derive_ws_hmac_key(token));
                                    }
                                    None => {
                                        warn!(
                                            message_len = m.info.message.len(),
                                            "InitConnectionSuccess missing SessionToken — \
                                             cannot derive HMAC key; closing connection"
                                        );
                                        return Err("InitConnectionSuccess did not contain a \
                                             SessionToken; HMAC key could not be derived"
                                            .to_owned());
                                    }
                                }
                            }
                            msg
                        }
                        Err(error) => {
                            let msg = format!("failed to decode operator message: {error}");
                            {
                                let mut state = lock_app_state(&app_state);
                                state.connection_status = ConnectionStatus::Error(msg.clone());
                            }
                            repaint.request_repaint();
                            continue;
                        }
                    }
                };

                let events = {
                    let mut state = lock_app_state(&app_state);
                    state.apply_operator_message(message)
                };
                if let Some(runtime) = &python_runtime {
                    for event in events {
                        match event {
                            AppEvent::AgentCheckin(agent_id) => {
                                if let Err(error) = runtime.emit_agent_checkin(agent_id) {
                                    warn!(error = %error, "failed to deliver python agent checkin event");
                                }
                            }
                            AppEvent::AgentTaskResult { task_id, agent_id, output } => {
                                runtime.notify_task_result(task_id, agent_id, output);
                            }
                            AppEvent::CommandResponse { agent_id, task_id, output } => {
                                if let Err(error) =
                                    runtime.emit_command_response(agent_id, task_id, output)
                                {
                                    warn!(error = %error, "failed to deliver python command response event");
                                }
                            }
                            AppEvent::LootCaptured(loot_item) => {
                                if let Err(error) = runtime.emit_loot_captured(loot_item) {
                                    warn!(error = %error, "failed to deliver python loot captured event");
                                }
                            }
                            AppEvent::ListenerChanged { name, action } => {
                                if let Err(error) = runtime.emit_listener_changed(name, action) {
                                    warn!(error = %error, "failed to deliver python listener changed event");
                                }
                            }
                        }
                    }
                }
                repaint.request_repaint();
            }
            Ok(WebSocketMessage::Ping(_)) | Ok(WebSocketMessage::Pong(_)) => {}
            Ok(WebSocketMessage::Close(frame)) => {
                return Err(close_reason(frame));
            }
            Ok(WebSocketMessage::Binary(_)) | Ok(WebSocketMessage::Frame(_)) => {}
            Err(error) => return Err(error.to_string()),
        }
    }

    Err("teamserver websocket closed".to_owned())
}

fn set_connection_status(
    app_state: &SharedAppState,
    repaint: &egui::Context,
    status: ConnectionStatus,
) {
    {
        let mut state = lock_app_state(app_state);
        state.connection_status = status;
    }
    repaint.request_repaint();
}

fn lock_app_state(app_state: &SharedAppState) -> MutexGuard<'_, AppState> {
    match app_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(
                "app state mutex poisoned in transport layer — recovering with potentially corrupted state"
            );
            poisoned.into_inner()
        }
    }
}

fn join_disconnect_reason(
    result: Result<Result<(), String>, tokio::task::JoinError>,
    default_message: &str,
) -> String {
    match result {
        Ok(Ok(())) => default_message.to_owned(),
        Ok(Err(message)) => message,
        Err(error) => error.to_string(),
    }
}

fn close_reason(frame: Option<CloseFrame>) -> String {
    frame
        .map(|close| match close.code {
            CloseCode::Normal => "teamserver websocket closed".to_owned(),
            _ => format!("teamserver closed connection: {}", close.reason),
        })
        .unwrap_or_else(|| "teamserver websocket closed".to_owned())
}

#[cfg(test)]
mod tests;
