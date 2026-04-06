pub(super) mod command_enc;
pub(crate) mod event_bus;
pub(super) mod operator_msg;

pub(crate) use event_bus::*;

use std::io::BufReader;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

use eframe::egui;
use futures_util::StreamExt;
use red_cell_common::crypto::{WsEnvelope, derive_ws_hmac_key, open_ws_frame};
use red_cell_common::operator::OperatorMessage;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{self, aws_lc_rs};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        self,
        client::IntoClientRequest,
        protocol::{CloseFrame, Message as WebSocketMessage, frame::coding::CloseCode},
    },
};
use tracing::warn;
use url::Url;

use crate::login::{TlsFailure, TlsFailureKind};
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

/// Controls how the client verifies the teamserver's TLS certificate.
#[derive(Debug, Clone)]
pub(crate) enum TlsVerification {
    /// Verify against system/webpki root CA certificates (default, secure).
    CertificateAuthority,
    /// Verify against a custom CA certificate loaded from a PEM file.
    CustomCa(PathBuf),
    /// Pin against a specific SHA-256 certificate fingerprint (hex-encoded).
    Fingerprint(String),
    /// Skip all certificate verification. Requires explicit opt-in via
    /// `--accept-invalid-certs`. Logs a prominent warning on every connection.
    DangerousSkipVerify,
}
#[derive(Debug)]
pub(crate) struct ClientTransport {
    runtime: Option<Runtime>,
    shutdown_tx: watch::Sender<bool>,
    #[allow(dead_code)]
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
/// Returns true when the error string indicates a TLS *certificate* problem that will not
/// self-heal on retry (e.g. expired cert, hostname mismatch, untrusted CA).
fn is_tls_cert_error(err: &str) -> bool {
    err.contains("invalid peer certificate:") || err.contains("certificate fingerprint mismatch")
}

/// Translate a raw connection error into an actionable message for the UI.
/// Falls back to the raw error string when no specific pattern matches.
pub(crate) fn classify_tls_error(err: &str) -> String {
    if err.contains("invalid peer certificate:") {
        if err.contains("certificate expired") || err.contains("Expired") {
            return "The server's TLS certificate has expired. \
                     Contact your teamserver administrator to renew it."
                .to_owned();
        }
        if err.contains("not valid for name") || err.contains("NotValidForName") {
            return "TLS hostname mismatch: the server URL's hostname does not match \
                     the certificate. Verify the server address."
                .to_owned();
        }
        if err.contains("UnknownIssuer") || err.contains("unknown issuer") {
            return "The server's TLS certificate is signed by an unknown authority. \
                     Use --ca-cert to specify the CA certificate, or trust the \
                     certificate by its fingerprint."
                .to_owned();
        }
        return format!("TLS certificate error: {err}");
    }
    if err.contains("certificate fingerprint mismatch") {
        return "The server's certificate fingerprint does not match the pinned value. \
                 The certificate may have been renewed — verify with your administrator."
            .to_owned();
    }
    if err.contains("Connection refused")
        || err.contains("connection refused")
        || err.contains("os error 111")
    {
        return "Connection refused: check that the teamserver is running \
                 and the address is correct."
            .to_owned();
    }
    err.to_owned()
}

/// Classify the TLS failure into a [`TlsFailureKind`] for UI rendering.
///
/// Fingerprint mismatches (from TOFU pinned certs) map to [`TlsFailureKind::CertificateChanged`].
/// Unknown-issuer errors (self-signed, first connect) map to [`TlsFailureKind::UnknownServer`].
/// Everything else is a generic [`TlsFailureKind::CertificateError`].
pub(crate) fn classify_tls_failure_kind(err: &str) -> TlsFailureKind {
    if err.contains("certificate fingerprint mismatch") {
        // Extract the stored (expected) fingerprint from the error message.
        // Format: "certificate fingerprint mismatch: expected <hex64>, got <hex64>"
        let stored = err
            .strip_suffix(|_: char| false)
            .unwrap_or(err)
            .split("expected ")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .unwrap_or("")
            .trim()
            .to_owned();
        return TlsFailureKind::CertificateChanged { stored_fingerprint: stored };
    }
    if err.contains("UnknownIssuer") || err.contains("unknown issuer") {
        return TlsFailureKind::UnknownServer;
    }
    TlsFailureKind::CertificateError
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
                                if let Some(token) = extract_session_token(&m.info.message) {
                                    *hmac_key.lock().await = Some(derive_ws_hmac_key(token));
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

fn build_tls_connector(
    verification: &TlsVerification,
    fingerprint_sink: Arc<std::sync::Mutex<Option<String>>>,
) -> Result<Connector, TransportError> {
    let provider = aws_lc_rs::default_provider();

    let mut client_config = match verification {
        TlsVerification::CertificateAuthority => {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let inner: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store),
                provider.clone().into(),
            )
            .build()
            .map_err(|e| TransportError::RustlsVerifier(e.to_string()))?;
            let verifier = Arc::new(CapturingCertVerifier { inner, fingerprint_sink });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        TlsVerification::CustomCa(path) => {
            let ca_pem = std::fs::read(path).map_err(|source| TransportError::CustomCaRead {
                path: path.display().to_string(),
                source,
            })?;
            let mut reader = BufReader::new(ca_pem.as_slice());
            let mut root_store = RootCertStore::empty();
            let mut found_any = false;
            for cert_result in rustls_pemfile::certs(&mut reader) {
                let cert = cert_result.map_err(TransportError::CustomCaParse)?;
                root_store
                    .add(cert)
                    .map_err(|error| TransportError::CustomCaInvalid(error.to_string()))?;
                found_any = true;
            }
            if !found_any {
                return Err(TransportError::CustomCaEmpty(path.display().to_string()));
            }
            let inner: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store),
                provider.clone().into(),
            )
            .build()
            .map_err(|e| TransportError::RustlsVerifier(e.to_string()))?;
            let verifier = Arc::new(CapturingCertVerifier { inner, fingerprint_sink });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        TlsVerification::Fingerprint(expected) => {
            let verifier = Arc::new(FingerprintCertificateVerifier {
                expected_fingerprint: expected.to_ascii_lowercase(),
                provider: provider.clone(),
                fingerprint_sink,
            });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        TlsVerification::DangerousSkipVerify => {
            warn!(
                "TLS certificate verification is DISABLED — connections are vulnerable to MITM attacks"
            );
            let verifier = Arc::new(DangerousCertificateVerifier { provider: provider.clone() });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };

    // Advertise HTTP/1.1 via ALPN so the server does not default to HTTP/2,
    // which does not support the WebSocket upgrade mechanism.
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Connector::Rustls(Arc::new(client_config)))
}

/// Wraps an inner [`ServerCertVerifier`], capturing the end-entity certificate's SHA-256
/// fingerprint before delegating. This lets the caller display or pin the server's certificate
/// even when CA verification fails.
#[derive(Debug)]
struct CapturingCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    fingerprint_sink: Arc<std::sync::Mutex<Option<String>>>,
}

impl ServerCertVerifier for CapturingCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        // Capture the fingerprint before verification so it's available even on failure.
        let fp = certificate_fingerprint(end_entity.as_ref());
        if let Ok(mut sink) = self.fingerprint_sink.lock() {
            *sink = Some(fp);
        }
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn normalize_server_url(server_url: &str) -> Result<String, TransportError> {
    let mut url = Url::parse(server_url)
        .map_err(|source| TransportError::InvalidUrl { url: server_url.to_owned(), source })?;

    match url.scheme() {
        "ws" | "wss" => {}
        other => {
            return Err(TransportError::UnsupportedScheme { scheme: other.to_owned() });
        }
    }

    if url.host_str().is_none() {
        return Err(TransportError::MissingHost);
    }

    let normalized_path = match url.path() {
        "" | "/" => "/havoc/",
        "/havoc" => "/havoc/",
        path => path,
    }
    .to_owned();
    url.set_path(&normalized_path);

    Ok(url.to_string())
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

/// Compute the lowercase hex-encoded SHA-256 fingerprint of a DER-encoded certificate.
pub(crate) fn certificate_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Verifies the server certificate by comparing its SHA-256 fingerprint against
/// a pinned value. Signature verification still uses the real crypto provider.
#[derive(Debug)]
struct FingerprintCertificateVerifier {
    expected_fingerprint: String,
    provider: crypto::CryptoProvider,
    /// Captures the server's actual certificate fingerprint (may differ from expected).
    fingerprint_sink: Arc<std::sync::Mutex<Option<String>>>,
}

impl ServerCertVerifier for FingerprintCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let actual = certificate_fingerprint(end_entity.as_ref());
        // Always capture the actual fingerprint so the caller can show it on mismatch.
        if let Ok(mut sink) = self.fingerprint_sink.lock() {
            *sink = Some(actual.clone());
        }
        if actual == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(tokio_rustls::rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected {}, got {actual}",
                self.expected_fingerprint
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Accepts any server certificate without verification. Only used when the operator
/// explicitly passes `--accept-invalid-certs`.
#[derive(Debug)]
struct DangerousCertificateVerifier {
    provider: crypto::CryptoProvider,
}

impl ServerCertVerifier for DangerousCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests;
