//! `red-cell-cli session` — persistent NDJSON WebSocket pipe.
//!
//! Establishes a single authenticated WebSocket connection to the teamserver's
//! `/api/v1/ws` endpoint and relays newline-delimited JSON between stdin and
//! the server.  Each command sent on stdin produces exactly one response line
//! on stdout.
//!
//! # Authentication
//!
//! The operator API token is injected into the `x-api-key` header of the HTTP
//! upgrade request.  This is the same token used by the REST API — no separate
//! login step is required.
//!
//! # Transport
//!
//! A single WebSocket connection is opened at session start and kept alive for
//! the lifetime of the session.  All commands travel over this one connection,
//! preserving connection semantics (authentication, rate limiting) and
//! eliminating per-command TCP/TLS overhead.
//!
//! The teamserver session endpoint is tracked in issue `red-cell-c2-9ebj4`
//! (zone:teamserver).
//!
//! # Protocol
//!
//! **stdin** — one JSON object per line:
//! ```json
//! {"cmd": "agent.exec", "id": "abc123", "command": "whoami", "wait": true}
//! ```
//!
//! **stdout** — success responses, one JSON object per line:
//! ```json
//! {"ok": true,  "cmd": "agent.exec", "data": {"output": "DOMAIN\\user", "exit_code": 0}}
//! ```
//!
//! **stderr** — error responses, one JSON object per line:
//! ```json
//! {"ok": false, "cmd": "agent.exec", "error": "NOT_FOUND", "message": "agent not found"}
//! ```
//!
//! The session terminates on:
//! - EOF on stdin
//! - `{"cmd": "exit"}`
//! - Server closing the WebSocket connection
//! - Ctrl-C
//!
//! # Locally handled commands
//!
//! | `cmd`  | Behaviour                                  |
//! |--------|--------------------------------------------|
//! | `ping` | Answered immediately; no server round-trip |
//! | `exit` | Sends WS close frame and exits cleanly     |
//!
//! Any other `cmd` must match a known session command (same names as the
//! `red-cell-cli` surface and the teamserver session router).  Unknown
//! commands produce a single local JSON line on **stdout** (same `ok`/`cmd`/
//! `error`/`message` envelope as other session errors, written to stdout) and
//! are not sent to the server:
//! ```json
//! {"ok": false, "cmd": "agent.lst", "error": "UNKNOWN_COMMAND", "message": "unknown command `agent.lst`"}
//! ```
//!
//! All recognised commands are forwarded to the server unchanged.
//!
//! # Default agent
//!
//! When `--agent <id>` is passed to `red-cell-cli session`, the session injects
//! the agent id into any incoming command that has no `"id"` field before
//! forwarding it to the server.

use std::collections::HashSet;
use std::sync::LazyLock;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::io::AsyncBufReadExt as _;
use tokio_tungstenite::tungstenite::{Message, protocol::CloseFrame};
use tracing::instrument;

use crate::AgentId;
use crate::config::{ResolvedConfig, TlsMode};
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::tls::build_fingerprint_client_config;

/// HTTP header name used by the teamserver for API-key authentication.
const API_KEY_HEADER: &str = "x-api-key";

/// Valid `cmd` values for session NDJSON (keep in sync with teamserver
/// `build_session_rest_request` in `teamserver/src/api.rs`, plus CLI-stable
/// aliases for subcommands that callers expect to spell like the CLI).
static SESSION_KNOWN_COMMANDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "status",
        "agent.list",
        "agent.show",
        "agent.exec",
        "agent.output",
        "agent.kill",
        "agent.upload",
        "agent.download",
        "agent.groups",
        "agent.set_groups",
        "listener.list",
        "listener.show",
        "listener.create",
        "listener.update",
        "listener.start",
        "listener.stop",
        "listener.delete",
        "listener.mark",
        "listener.access",
        "listener.set_access",
        "operator.list",
        "operator.create",
        "operator.delete",
        "operator.set_role",
        "operator.show_agent_groups",
        "operator.set_agent_groups",
        "audit.list",
        "log.list",
        "log.tail",
        "session_activity.list",
        "credential.list",
        "credential.show",
        "job.list",
        "job.show",
        "loot.list",
        "loot.download",
        "loot.show",
        "payload.list",
        "payload.build",
        "payload.job",
        "payload.download",
        "payload_cache.flush",
        "payload-cache.flush",
        "webhooks.stats",
    ])
});

#[inline]
fn is_known_session_command(cmd: &str) -> bool {
    SESSION_KNOWN_COMMANDS.contains(cmd)
}

// ── URL helpers ──────────────────────────────────────────────────────────────

/// Convert an HTTP(S) server URL to its WebSocket equivalent.
///
/// - `https://…` → `wss://…`
/// - `http://…`  → `ws://…`
/// - Other forms → `ws://…` (safe fallback for bare host:port strings)
///
/// # Examples
///
/// ```
/// assert_eq!(server_to_ws_url("https://ts.example.com:40056"), "wss://ts.example.com:40056");
/// assert_eq!(server_to_ws_url("http://localhost:8080"), "ws://localhost:8080");
/// ```
fn server_to_ws_url(server: &str) -> String {
    if let Some(rest) = server.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{server}")
    }
}

/// Build a `tokio_tungstenite::Connector` for the given TLS mode.
///
/// For `wss://` URLs the connector is used to perform the TLS handshake.
/// For `ws://` URLs pass `Connector::Plain` so tungstenite skips TLS.
fn build_connector(
    tls_mode: &TlsMode,
    is_tls: bool,
) -> Result<tokio_tungstenite::Connector, CliError> {
    if !is_tls {
        return Ok(tokio_tungstenite::Connector::Plain);
    }

    match tls_mode {
        TlsMode::SystemRoots => {
            // System roots are handled by the rustls-tls-webpki-roots feature
            // baked into tokio-tungstenite; return Plain so connect_async uses
            // the crate's own default TLS stack.
            Ok(tokio_tungstenite::Connector::Plain)
        }

        TlsMode::CustomCa(path) => {
            let pem = std::fs::read(path).map_err(|e| {
                CliError::General(format!("failed to read CA cert {}: {e}", path.display()))
            })?;

            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut &pem[..]).filter_map(|r| r.ok()).collect();

            if certs.is_empty() {
                return Err(CliError::General(format!(
                    "no valid certificates found in CA file {}",
                    path.display()
                )));
            }

            let mut root_store = rustls::RootCertStore::empty();
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| CliError::General(format!("failed to add CA certificate: {e}")))?;
            }

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            Ok(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(config)))
        }

        TlsMode::Fingerprint(hex) => {
            let config = build_fingerprint_client_config(hex)?;
            Ok(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(config)))
        }
    }
}

// ── WebSocket connection ──────────────────────────────────────────────────────

/// Returns `true` when `tls_err` is a TLS certificate validation failure
/// (unknown issuer, expired cert, name mismatch, etc.) as opposed to a
/// protocol or configuration error.
///
/// Only [`tokio_tungstenite::tungstenite::error::TlsError::Rustls`] is
/// inspected because this crate uses the `rustls-tls-webpki-roots` feature
/// exclusively.
fn is_tls_cert_failure(tls_err: &tokio_tungstenite::tungstenite::error::TlsError) -> bool {
    use tokio_tungstenite::tungstenite::error::TlsError;
    matches!(
        tls_err,
        TlsError::Rustls(
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
        )
    )
}

/// Map a tungstenite error to a [`CliError`].
fn map_ws_error(e: tokio_tungstenite::tungstenite::Error, url: &str) -> CliError {
    use tokio_tungstenite::tungstenite::Error as WsErr;
    match e {
        WsErr::Io(io_err) if io_err.kind() == std::io::ErrorKind::ConnectionRefused => {
            CliError::ServerUnreachable(format!("cannot connect to {url}: connection refused"))
        }
        WsErr::Io(io_err) => {
            CliError::ServerUnreachable(format!("network error connecting to {url}: {io_err}"))
        }
        WsErr::Tls(tls_err) => {
            // TLS errors are connectivity/trust problems, not authentication failures.
            // Give a more specific message for certificate validation failures so
            // callers do not confuse them with bad credentials (exit code 3).
            if is_tls_cert_failure(&tls_err) {
                CliError::ServerUnreachable(format!(
                    "TLS certificate trust failure for {url}: {tls_err} \
                     — verify the server certificate or configure \
                     --tls-ca / --tls-fingerprint"
                ))
            } else {
                CliError::ServerUnreachable(format!("TLS handshake failed for {url}: {tls_err}"))
            }
        }
        WsErr::Http(ref resp) if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 => {
            CliError::AuthFailure(format!("WebSocket upgrade rejected: {}", resp.status()))
        }
        _ => CliError::ServerUnreachable(format!("failed to connect WebSocket at {url}: {e}")),
    }
}

/// Open an authenticated WebSocket connection to the teamserver session endpoint.
///
/// Converts the configured HTTP(S) server URL to a WS(S) URL, builds the
/// appropriate TLS connector, and performs the HTTP upgrade with the
/// `x-api-key` header set.
#[instrument(skip(config), fields(server = %config.server))]
async fn connect_websocket(
    config: &ResolvedConfig,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    CliError,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let ws_base = server_to_ws_url(&config.server);
    let ws_url = format!("{ws_base}/api/v1/ws");
    let is_tls = ws_url.starts_with("wss://");

    let mut request = ws_url
        .as_str()
        .into_client_request()
        .map_err(|e| CliError::General(format!("invalid WebSocket URL '{ws_url}': {e}")))?;

    request.headers_mut().insert(
        API_KEY_HEADER,
        config
            .token
            .parse()
            .map_err(|e| CliError::General(format!("invalid token header value: {e}")))?,
    );

    let connector = build_connector(&config.tls_mode, is_tls)?;

    // Use connect_async for SystemRoots (lets the crate's built-in TLS stack
    // run) and connect_async_tls_with_config for custom connectors.
    let (ws, _response) = match connector {
        tokio_tungstenite::Connector::Plain if is_tls => {
            // SystemRoots: delegate to crate default (webpki-roots feature).
            tokio_tungstenite::connect_async(request).await.map_err(|e| map_ws_error(e, &ws_url))?
        }
        connector => {
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(|e| map_ws_error(e, &ws_url))?
        }
    };

    Ok(ws)
}

// ── session loop ─────────────────────────────────────────────────────────────

/// Run the session.
///
/// Connects to the teamserver WebSocket session endpoint and relays NDJSON
/// between stdin and the connection.
///
/// Returns an exit code:
/// - [`EXIT_SUCCESS`] on clean EOF, `{"cmd":"exit"}`, or server-initiated close
/// - [`EXIT_GENERAL`] on fatal I/O or WebSocket errors
pub async fn run(config: &ResolvedConfig, default_agent: Option<AgentId>) -> i32 {
    let ws = match connect_websocket(config).await {
        Ok(ws) => ws,
        Err(e) => {
            emit_error_to(&mut std::io::stderr(), "", &e).ok();
            return e.exit_code();
        }
    };

    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();

    tokio::select! {
        code = run_with_io(reader, &mut stdout, &mut stderr, ws, default_agent) => code,
        _ = tokio::signal::ctrl_c() => EXIT_SUCCESS,
    }
}

/// Inner session loop — reads from `reader`, relays via `ws`, writes to `writer`.
///
/// Extracted so tests can inject a `BufReader<&[u8]>` for stdin and a `Vec<u8>`
/// for stdout without touching real file descriptors, and a mock WebSocket
/// stream without needing a real teamserver.
async fn run_with_io<R, Out, ErrOut, S>(
    reader: R,
    stdout: &mut Out,
    stderr: &mut ErrOut,
    ws: tokio_tungstenite::WebSocketStream<S>,
    default_agent: Option<AgentId>,
) -> i32
where
    R: tokio::io::AsyncBufRead + Unpin,
    Out: std::io::Write,
    ErrOut: std::io::Write,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = ws.split();
    let mut lines = reader.lines();

    loop {
        tokio::select! {
            biased;
            line_result = lines.next_line() => {
                match process_stdin_line(line_result, stdout, stderr, &mut sink, default_agent).await {
                    LoopControl::Continue => {}
                    LoopControl::Exit(code) => return code,
                    LoopControl::StdinEof => {
                        // Stdin reached EOF and we sent a WS close frame.
                        // Drain any remaining WebSocket messages (e.g. in-flight
                        // server responses) before exiting so we don't silently
                        // drop responses that arrived after our last send.
                        while let Some(msg) = stream.next().await {
                            match process_ws_message(Some(msg), stdout, stderr, false) {
                                LoopControl::Continue | LoopControl::StdinEof => {}
                                LoopControl::Exit(code) => return code,
                            }
                        }
                        return EXIT_SUCCESS;
                    }
                }
            }

            ws_msg = stream.next() => {
                match process_ws_message(ws_msg, stdout, stderr, true) {
                    LoopControl::Continue | LoopControl::StdinEof => {}
                    LoopControl::Exit(code) => return code,
                }
            }
        }
    }
}

/// Control flow token returned by the per-event handlers.
enum LoopControl {
    Continue,
    Exit(i32),
    /// Stdin reached EOF; the outer loop should drain remaining WebSocket
    /// messages before exiting.
    StdinEof,
}

/// Diagnostic emitted to stdout when the server ends the session.
struct SessionClosedEvent {
    reason: &'static str,
    code: Option<u16>,
    close_reason: Option<String>,
}

/// Handle one line read from stdin.
///
/// - Empty lines are skipped.
/// - Invalid JSON produces a local error response and continues.
/// - `{"cmd":"ping"}` is answered immediately without a server round-trip.
/// - `{"cmd":"exit"}` sends a WebSocket close frame and exits cleanly.
/// - Unknown `cmd` values produce a local JSON error on stdout (no forward).
/// - All other commands have the default agent id injected (if applicable) and
///   are forwarded to the server as a WebSocket text frame.
async fn process_stdin_line<Out, ErrOut, Si>(
    line_result: std::io::Result<Option<String>>,
    stdout: &mut Out,
    stderr: &mut ErrOut,
    sink: &mut Si,
    default_agent: Option<AgentId>,
) -> LoopControl
where
    Out: std::io::Write,
    ErrOut: std::io::Write,
    Si: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    match line_result {
        Err(e) => {
            emit_error_to(stderr, "", &CliError::General(format!("stdin read error: {e}"))).ok();
            LoopControl::Exit(EXIT_GENERAL)
        }

        Ok(None) => {
            // Clean EOF — send WS close frame and signal the outer loop to
            // drain any in-flight server responses before exiting.
            let _ = sink.close().await;
            LoopControl::StdinEof
        }

        Ok(Some(line)) => {
            let line = line.trim().to_owned();
            if line.is_empty() {
                return LoopControl::Continue;
            }

            let mut val: serde_json::Value = match serde_json::from_str(&line) {
                Err(e) => {
                    if emit_error_to(stderr, "", &CliError::General(format!("invalid JSON: {e}")))
                        .is_err()
                    {
                        return LoopControl::Exit(EXIT_GENERAL);
                    }
                    return LoopControl::Continue;
                }
                Ok(v) => v,
            };

            let cmd = val.get("cmd").and_then(|c| c.as_str()).unwrap_or("").to_owned();

            // ── locally handled commands ──────────────────────────────────
            if cmd == "ping" {
                if emit_ok_to(stdout, "ping", serde_json::json!({"pong": true})).is_err() {
                    return LoopControl::Exit(EXIT_GENERAL);
                }
                return LoopControl::Continue;
            }

            if cmd == "exit" {
                let _ = sink.close().await;
                return LoopControl::Exit(EXIT_SUCCESS);
            }

            if !is_known_session_command(&cmd) {
                if emit_error_to(stdout, &cmd, &CliError::UnknownSessionCommand(cmd.clone()))
                    .is_err()
                {
                    return LoopControl::Exit(EXIT_GENERAL);
                }
                return LoopControl::Continue;
            }

            // ── default-agent injection ───────────────────────────────────
            if let Err(err) = normalize_agent_id_field(&cmd, &mut val, default_agent) {
                if emit_error_to(stderr, &cmd, &err).is_err() {
                    return LoopControl::Exit(EXIT_GENERAL);
                }
                return LoopControl::Continue;
            }

            // ── forward to server ─────────────────────────────────────────
            let text = match serde_json::to_string(&val) {
                Ok(s) => s,
                Err(e) => {
                    if emit_error_to(
                        stderr,
                        &cmd,
                        &CliError::General(format!("serialise error: {e}")),
                    )
                    .is_err()
                    {
                        return LoopControl::Exit(EXIT_GENERAL);
                    }
                    return LoopControl::Continue;
                }
            };

            if let Err(e) = sink.send(Message::Text(text.into())).await {
                emit_error_to(stderr, &cmd, &CliError::ServerUnreachable(e.to_string())).ok();
                LoopControl::Exit(EXIT_GENERAL)
            } else {
                LoopControl::Continue
            }
        }
    }
}

fn normalize_agent_id_field(
    cmd: &str,
    value: &mut serde_json::Value,
    default_agent: Option<AgentId>,
) -> Result<(), CliError> {
    if !command_accepts_agent_id(cmd) {
        return Ok(());
    }

    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };

    let normalized = match object.get("id") {
        Some(raw) if !raw.is_null() => Some(parse_agent_id_value(raw)?),
        _ => default_agent,
    };

    if let Some(id) = normalized {
        object.insert("id".to_owned(), serde_json::json!(id));
    }

    Ok(())
}

fn command_accepts_agent_id(cmd: &str) -> bool {
    matches!(
        cmd,
        "agent.show"
            | "agent.exec"
            | "agent.output"
            | "agent.kill"
            | "agent.upload"
            | "agent.download"
            | "agent.groups"
            | "agent.set_groups"
    )
}

fn parse_agent_id_value(value: &serde_json::Value) -> Result<AgentId, CliError> {
    serde_json::from_value::<AgentId>(value.clone())
        .map_err(|err| CliError::InvalidArgs(format!("invalid agent id: {err}")))
}

/// Handle one message received from the WebSocket.
///
/// - Text frames are written verbatim to stdout as a line.
/// - Close frames terminate the session cleanly.
/// - Binary / Ping / Pong frames are silently ignored.
/// - A closed stream (`None`) or an error terminates the session.
fn process_ws_message<Out, ErrOut>(
    msg: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    stdout: &mut Out,
    stderr: &mut ErrOut,
    emit_close_event: bool,
) -> LoopControl
where
    Out: std::io::Write,
    ErrOut: std::io::Write,
{
    let emit_disconnect_event = |stdout: &mut Out, event: SessionClosedEvent| {
        emit_session_closed_to(stdout, event)
            .map_or(LoopControl::Exit(EXIT_GENERAL), |_| LoopControl::Exit(EXIT_SUCCESS))
    };

    match msg {
        // Server closed the stream.
        None if emit_close_event => emit_disconnect_event(
            stdout,
            SessionClosedEvent { reason: "connection_lost", code: None, close_reason: None },
        ),
        None => LoopControl::Exit(EXIT_SUCCESS),

        Some(Err(e)) => {
            use tokio_tungstenite::tungstenite::Error as WsErr;
            use tokio_tungstenite::tungstenite::error::ProtocolError;
            // Connection-closed variants indicate the server has ended the
            // session — treat them as a clean exit rather than an error.
            match &e {
                WsErr::ConnectionClosed | WsErr::AlreadyClosed if emit_close_event => {
                    emit_disconnect_event(
                        stdout,
                        SessionClosedEvent {
                            reason: "connection_lost",
                            code: None,
                            close_reason: None,
                        },
                    )
                }
                WsErr::ConnectionClosed | WsErr::AlreadyClosed => LoopControl::Exit(EXIT_SUCCESS),
                WsErr::Io(io_err)
                    if io_err.kind() == std::io::ErrorKind::ConnectionReset
                        || io_err.kind() == std::io::ErrorKind::UnexpectedEof
                        || io_err.kind() == std::io::ErrorKind::BrokenPipe =>
                {
                    if emit_close_event {
                        emit_disconnect_event(
                            stdout,
                            SessionClosedEvent {
                                reason: "connection_lost",
                                code: None,
                                close_reason: None,
                            },
                        )
                    } else {
                        LoopControl::Exit(EXIT_SUCCESS)
                    }
                }
                // TCP was torn down before the WS close handshake completed —
                // this is normal when the server drops the connection quickly.
                WsErr::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                    if emit_close_event {
                        emit_disconnect_event(
                            stdout,
                            SessionClosedEvent {
                                reason: "connection_lost",
                                code: None,
                                close_reason: None,
                            },
                        )
                    } else {
                        LoopControl::Exit(EXIT_SUCCESS)
                    }
                }
                _ => {
                    emit_error_to(
                        stderr,
                        "",
                        &CliError::ServerUnreachable(format!("websocket error: {e}")),
                    )
                    .ok();
                    LoopControl::Exit(EXIT_GENERAL)
                }
            }
        }

        Some(Ok(Message::Text(text))) => {
            let target: &mut dyn std::io::Write =
                if response_is_error_envelope(&text) { stderr } else { stdout };

            if writeln!(target, "{text}").is_err() {
                LoopControl::Exit(EXIT_GENERAL)
            } else {
                LoopControl::Continue
            }
        }

        Some(Ok(Message::Close(frame))) if emit_close_event => {
            emit_disconnect_event(stdout, SessionClosedEvent::from_close_frame(frame.as_ref()))
        }
        Some(Ok(Message::Close(_))) => LoopControl::Exit(EXIT_SUCCESS),

        // Binary, Ping, Pong — ignore.
        Some(Ok(_)) => LoopControl::Continue,
    }
}

// ── output helpers ────────────────────────────────────────────────────────────

/// Write a success response line to `writer`.
fn emit_ok_to(
    writer: &mut impl std::io::Write,
    cmd: &str,
    data: serde_json::Value,
) -> std::io::Result<()> {
    let envelope = serde_json::json!({"ok": true, "cmd": cmd, "data": data});
    match serde_json::to_string(&envelope) {
        Ok(s) => writeln!(writer, "{s}"),
        Err(_) => writeln!(writer, r#"{{"ok":true,"cmd":"{cmd}"}}"#),
    }
}

/// Write an error response line to `writer`.
fn emit_error_to(
    writer: &mut impl std::io::Write,
    cmd: &str,
    err: &CliError,
) -> std::io::Result<()> {
    let envelope = serde_json::json!({
        "ok": false,
        "cmd": cmd,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    match serde_json::to_string(&envelope) {
        Ok(s) => writeln!(writer, "{s}"),
        Err(_) => writeln!(writer, r#"{{"ok":false,"cmd":"{cmd}","error":"ERROR"}}"#),
    }
}

/// Write a session-close diagnostic line to `writer`.
fn emit_session_closed_to(
    writer: &mut impl std::io::Write,
    event: SessionClosedEvent,
) -> std::io::Result<()> {
    let mut envelope = serde_json::json!({
        "event": "session_closed",
        "reason": event.reason,
    });

    if let Some(code) = event.code {
        envelope["code"] = serde_json::json!(code);
    }

    if let Some(close_reason) = event.close_reason {
        envelope["close_reason"] = serde_json::json!(close_reason);
    }

    match serde_json::to_string(&envelope) {
        Ok(s) => writeln!(writer, "{s}"),
        Err(_) => writeln!(writer, r#"{{"event":"session_closed","reason":"{}"}}"#, event.reason),
    }
}

/// Return `true` when a server text frame is a structured error envelope.
///
/// Session mode preserves the CLI-wide stream contract:
/// - success responses on stdout
/// - structured errors on stderr
fn response_is_error_envelope(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
        == Some(false)
}

impl SessionClosedEvent {
    fn from_close_frame(frame: Option<&CloseFrame>) -> Self {
        match frame {
            Some(frame) => Self {
                reason: "server_close",
                code: Some(u16::from(frame.code)),
                close_reason: (!frame.reason.is_empty()).then(|| frame.reason.to_string()),
            },
            // Tungstenite may surface a clean close without frame details as
            // `Message::Close(None)`. Treat that as the WebSocket normal-close
            // status code so session diagnostics remain stable.
            None => Self { reason: "server_close", code: Some(1000), close_reason: None },
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── server_to_ws_url ───────────────────────────────────────────────────────

    #[test]
    fn https_becomes_wss() {
        assert_eq!(server_to_ws_url("https://ts.example.com:40056"), "wss://ts.example.com:40056");
    }

    #[test]
    fn http_becomes_ws() {
        assert_eq!(server_to_ws_url("http://localhost:8080"), "ws://localhost:8080");
    }

    #[test]
    fn bare_host_gets_ws_scheme() {
        assert_eq!(server_to_ws_url("localhost:8080"), "ws://localhost:8080");
    }

    // ── emit_ok_to / emit_error_to ─────────────────────────────────────────────

    #[test]
    fn emit_ok_produces_valid_json_envelope() {
        let mut buf = Vec::new();
        emit_ok_to(&mut buf, "ping", serde_json::json!({"pong": true})).expect("write");
        let line = String::from_utf8(buf).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["ok"], true);
        assert_eq!(val["cmd"], "ping");
        assert_eq!(val["data"]["pong"], true);
    }

    #[test]
    fn emit_error_produces_valid_json_envelope() {
        let mut buf = Vec::new();
        let err = CliError::NotFound("agent xyz".to_owned());
        emit_error_to(&mut buf, "agent.show", &err).expect("write");
        let line = String::from_utf8(buf).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["ok"], false);
        assert_eq!(val["cmd"], "agent.show");
        assert_eq!(val["error"], "NOT_FOUND");
        assert!(val["message"].as_str().is_some_and(|m| m.contains("not found")));
    }

    #[test]
    fn emit_session_closed_produces_valid_json_envelope() {
        let mut buf = Vec::new();
        emit_session_closed_to(
            &mut buf,
            SessionClosedEvent {
                reason: "server_close",
                code: Some(1000),
                close_reason: Some("normal".to_owned()),
            },
        )
        .expect("write");

        let line = String::from_utf8(buf).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["event"], "session_closed");
        assert_eq!(val["reason"], "server_close");
        assert_eq!(val["code"], 1000);
        assert_eq!(val["close_reason"], "normal");
    }

    #[test]
    fn response_is_error_envelope_detects_ok_false_json() {
        assert!(response_is_error_envelope(
            r#"{"ok":false,"cmd":"agent.show","error":"NOT_FOUND","message":"missing"}"#
        ));
        assert!(!response_is_error_envelope(
            r#"{"ok":true,"cmd":"agent.show","data":{"id":"abc"}}"#
        ));
        assert!(!response_is_error_envelope("not json"));
    }

    // ── session command allowlist ──────────────────────────────────────────────

    #[test]
    fn known_session_commands_match_teamserver_router() {
        assert!(is_known_session_command("agent.list"));
        assert!(is_known_session_command("credential.list"));
        assert!(is_known_session_command("operator.set_role"));
    }

    #[test]
    fn unknown_session_commands_rejected_before_forward() {
        assert!(!is_known_session_command("agent.lst"));
        assert!(!is_known_session_command("nosuch"));
        assert!(!is_known_session_command(""));
    }

    #[test]
    fn unknown_session_command_uses_error_envelope_on_stdout() {
        let mut buf = Vec::new();
        let err = CliError::UnknownSessionCommand("agent.lst".to_owned());
        emit_error_to(&mut buf, "agent.lst", &err).expect("write");
        let val: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).expect("utf8").trim()).expect("json");
        assert_eq!(val["ok"], false);
        assert_eq!(val["cmd"], "agent.lst");
        assert_eq!(val["error"], "UNKNOWN_COMMAND");
        assert_eq!(val["message"].as_str(), Some("unknown command `agent.lst`"));
    }

    // ── run_with_io via mock WebSocket server ──────────────────────────────────

    /// Spin up a local plain-text WebSocket server and return the listening
    /// address.  The `handler` closure is invoked once per accepted connection.
    async fn mock_ws_server<F, Fut>(handler: F) -> std::net::SocketAddr
    where
        F: Fn(tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let ws = tokio_tungstenite::accept_async(stream).await.expect("ws accept");
                handler(ws).await;
            }
        });
        addr
    }

    /// Connect to a `ws://` server and return the client WebSocket stream.
    async fn ws_connect(
        addr: std::net::SocketAddr,
        api_key: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
        let url = format!("ws://{addr}/api/v1/ws");
        let mut req = url.as_str().into_client_request().expect("build request");
        req.headers_mut().insert(API_KEY_HEADER, api_key.parse().expect("header value"));
        tokio_tungstenite::connect_async(req).await.expect("connect").0
    }

    /// `{"cmd":"ping"}` must be answered locally — no message reaches the server.
    #[tokio::test]
    async fn ping_is_handled_locally_without_server_roundtrip() {
        let addr = mock_ws_server(|mut ws| async move {
            // Receive any message — if ping is forwarded, this succeeds and the
            // test would pass without the local-handling assertion.
            // We just need to keep the connection alive long enough.
            while let Some(Ok(Message::Close(_))) = ws.next().await {}
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let input = b"{\"cmd\":\"ping\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;

        // `ping` is locally handled — code 0 (EOF after ping)
        assert_eq!(code, EXIT_SUCCESS, "ping then EOF must exit cleanly");

        assert!(stderr.is_empty(), "ping must not write to stderr");
        let line = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["ok"], true, "ping must produce ok:true");
        assert_eq!(val["data"]["pong"], true, "ping must include pong:true");
    }

    /// `{"cmd":"exit"}` must send a close frame and exit with code 0.
    #[tokio::test]
    async fn exit_command_closes_connection_cleanly() {
        let addr = mock_ws_server(|mut ws| async move {
            // Expect a close frame.
            while let Some(msg) = ws.next().await {
                if let Ok(Message::Close(_)) = msg {
                    break;
                }
            }
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let input = b"{\"cmd\":\"exit\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "exit command must exit with code 0");
        assert!(stdout.is_empty(), "exit must not produce stdout");
        assert!(stderr.is_empty(), "exit must not produce stderr");
    }

    /// Non-`ping`/`exit` commands are forwarded to the server; the server
    /// response is written verbatim to stdout.
    #[tokio::test]
    async fn command_is_forwarded_and_response_relayed() {
        let addr = mock_ws_server(|mut ws| async move {
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                // Echo back a canned response.
                let val: serde_json::Value =
                    serde_json::from_str(&text).expect("parse forwarded cmd");
                let cmd = val["cmd"].as_str().unwrap_or("").to_owned();
                let resp = serde_json::json!({"ok": true, "cmd": cmd, "data": []});
                ws.send(Message::Text(serde_json::to_string(&resp).expect("ser").into()))
                    .await
                    .expect("server send");
            }
            // Explicit close so the client receives a clean Close frame rather
            // than an abrupt TCP reset.
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let input = b"{\"cmd\":\"agent.list\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "clean server close must exit 0");

        assert!(stderr.is_empty(), "successful server response must not hit stderr");
        let line = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("parse relay");
        assert_eq!(val["ok"], true, "relayed response must be ok:true");
        assert_eq!(val["cmd"], "agent.list");
    }

    /// A typo in `cmd` must be rejected locally with no WebSocket text frame.
    #[tokio::test]
    async fn unknown_command_is_not_forwarded() {
        let addr = mock_ws_server(|mut ws| async move {
            let mut saw_text = false;
            while let Some(msg) = ws.next().await {
                match msg {
                    Ok(Message::Text(_)) => saw_text = true,
                    Ok(Message::Close(_)) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
            assert!(!saw_text, "unknown command must not be forwarded as text");
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let input = b"{\"cmd\":\"agent.lst\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS);

        assert!(stderr.is_empty(), "local unknown-command error must not hit stderr");
        let line = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["ok"], false);
        assert_eq!(val["cmd"], "agent.lst");
        assert_eq!(val["error"], "UNKNOWN_COMMAND");
        assert!(val["message"].as_str().is_some_and(|m| m.contains("agent.lst")));
    }

    /// Invalid JSON on stdin must produce a local error line and continue
    /// rather than crashing or exiting.
    #[tokio::test]
    async fn invalid_json_produces_local_error_and_continues() {
        // The server stays alive until the client closes — it does not respond
        // to anything.  Both bad-JSON and ping are handled locally by the
        // client and never reach the server, so the server just waits for the
        // close frame that arrives when stdin reaches EOF.
        let addr = mock_ws_server(|mut ws| async move {
            while let Some(Ok(msg)) = ws.next().await {
                if let Message::Close(_) = msg {
                    break;
                }
            }
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        // First line: bad JSON; second line: ping (handled locally, no forward).
        let input = b"not json at all\n{\"cmd\":\"ping\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "invalid json must not cause non-zero exit");

        let stderr_text = String::from_utf8(stderr).expect("utf8");
        let error_line: serde_json::Value = serde_json::from_str(stderr_text.trim()).expect("json");
        assert_eq!(error_line["ok"], false, "bad JSON must produce ok:false");
        assert!(
            error_line["message"].as_str().is_some_and(|m| m.contains("invalid JSON")),
            "error message must mention invalid JSON, got: {}",
            error_line["message"]
        );

        let stdout_text = String::from_utf8(stdout).expect("utf8");
        let ping_line: serde_json::Value = serde_json::from_str(stdout_text.trim()).expect("json");
        assert_eq!(ping_line["ok"], true);
        assert_eq!(ping_line["data"]["pong"], true);
    }

    /// Empty lines on stdin must be silently skipped.
    #[tokio::test]
    async fn empty_lines_are_skipped() {
        let addr = mock_ws_server(|mut ws| async move {
            // Should only receive a close — no forwarded commands.
            while let Some(Ok(Message::Close(_))) = ws.next().await {}
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let input = b"\n   \n\t\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "whitespace-only stdin must exit 0");
        assert!(stdout.is_empty(), "empty lines must not produce stdout");
        assert!(stderr.is_empty(), "empty lines must not produce stderr");
    }

    /// When `default_agent` is set and the command has no `"id"` field, the
    /// agent id is injected before forwarding.
    #[tokio::test]
    async fn default_agent_is_injected_when_id_absent() {
        let addr = mock_ws_server(|mut ws| async move {
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                let val: serde_json::Value = serde_json::from_str(&text).expect("parse forwarded");
                let resp = serde_json::json!({
                    "ok": true,
                    "cmd": "agent.show",
                    "data": {"received_id": val["id"]}
                });
                ws.send(Message::Text(serde_json::to_string(&resp).expect("ser").into()))
                    .await
                    .expect("server send");
            }
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        // Command has no "id" field.
        let input = b"{\"cmd\":\"agent.show\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        run_with_io(reader, &mut stdout, &mut stderr, ws, Some(AgentId::new(0xA001))).await;

        assert!(stderr.is_empty(), "successful response must not hit stderr");
        let text = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(text.trim()).expect("parse response");
        assert_eq!(
            val["data"]["received_id"], "0000A001",
            "default agent must be injected when id is absent"
        );
    }

    /// When `default_agent` is set but the command already has an `"id"` field,
    /// the existing id is NOT overwritten.
    #[tokio::test]
    async fn default_agent_does_not_overwrite_explicit_id() {
        let addr = mock_ws_server(|mut ws| async move {
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                let val: serde_json::Value = serde_json::from_str(&text).expect("parse");
                let resp = serde_json::json!({
                    "ok": true,
                    "cmd": "agent.show",
                    "data": {"received_id": val["id"]}
                });
                ws.send(Message::Text(serde_json::to_string(&resp).expect("ser").into()))
                    .await
                    .expect("server send");
            }
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let input = b"{\"cmd\":\"agent.show\",\"id\":\"abc123\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        run_with_io(reader, &mut stdout, &mut stderr, ws, Some(AgentId::new(0xA001))).await;

        assert!(stderr.is_empty(), "successful response must not hit stderr");
        let text = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(text.trim()).expect("parse");
        assert_eq!(
            val["data"]["received_id"], "00ABC123",
            "explicit id must not be overwritten by default_agent"
        );
    }

    /// Server-initiated close must exit cleanly with code 0.
    #[tokio::test]
    async fn server_close_exits_cleanly() {
        let addr = mock_ws_server(|mut ws| async move {
            // Immediately close.
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let (_stdin_tx, stdin_rx) = tokio::io::duplex(64);
        let reader = tokio::io::BufReader::new(stdin_rx);
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "server close must exit 0");
        let line = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["event"], "session_closed");
        assert_eq!(val["reason"], "server_close");
        assert_eq!(val["code"], 1000);
        assert!(stderr.is_empty(), "server close must not produce stderr");
    }

    /// Server close frames with a reason phrase must be surfaced to stdout.
    #[tokio::test]
    async fn server_close_reason_phrase_is_emitted() {
        let addr = mock_ws_server(|mut ws| async move {
            let _ = ws
                .close(Some(CloseFrame {
                    code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away,
                    reason: "maintenance".into(),
                }))
                .await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let (_stdin_tx, stdin_rx) = tokio::io::duplex(64);
        let reader = tokio::io::BufReader::new(stdin_rx);
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "server close with reason must exit 0");

        let line = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["event"], "session_closed");
        assert_eq!(val["reason"], "server_close");
        assert_eq!(val["code"], 1001);
        assert_eq!(val["close_reason"], "maintenance");
        assert!(stderr.is_empty(), "close diagnostics must stay on stdout");
    }

    /// Abrupt disconnects without a close frame must be surfaced as connection loss.
    #[tokio::test]
    async fn abrupt_disconnect_emits_connection_lost_diagnostic() {
        let addr = mock_ws_server(|ws| async move {
            drop(ws);
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let (_stdin_tx, stdin_rx) = tokio::io::duplex(64);
        let reader = tokio::io::BufReader::new(stdin_rx);
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "abrupt disconnect must still exit 0");

        let line = String::from_utf8(stdout).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["event"], "session_closed");
        assert_eq!(val["reason"], "connection_lost");
        assert!(val.get("code").is_none(), "abrupt disconnect must not include a close code");
        assert!(stderr.is_empty(), "disconnect diagnostics must stay on stdout");
    }

    /// Multiple commands in sequence are each forwarded and their responses
    /// relayed to stdout in order.
    #[tokio::test]
    async fn multiple_commands_are_relayed_in_order() {
        let addr = mock_ws_server(|mut ws| async move {
            let mut seq = 0u32;
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    Message::Text(text) => {
                        let val: serde_json::Value = serde_json::from_str(&text).expect("parse");
                        let cmd = val["cmd"].as_str().unwrap_or("").to_owned();
                        seq += 1;
                        let resp =
                            serde_json::json!({"ok": true, "cmd": cmd, "data": {"seq": seq}});
                        ws.send(Message::Text(serde_json::to_string(&resp).expect("ser").into()))
                            .await
                            .expect("server send");
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        // Use stdin EOF (no "exit" command) so the client enters the drain loop
        // and reads both server responses before exiting.  Using an explicit
        // "exit" command would cause the client to close the WebSocket before
        // the in-flight server responses are received.
        let input = b"{\"cmd\":\"agent.list\"}\n{\"cmd\":\"listener.list\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS);

        assert!(stderr.is_empty(), "successful responses must not hit stderr");
        let text = String::from_utf8(stdout).expect("utf8");
        let responses: Vec<serde_json::Value> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("json"))
            .collect();

        assert_eq!(responses.len(), 2, "must have two responses for two forwarded commands");
        assert_eq!(responses[0]["cmd"], "agent.list");
        assert_eq!(responses[0]["data"]["seq"], 1);
        assert_eq!(responses[1]["cmd"], "listener.list");
        assert_eq!(responses[1]["data"]["seq"], 2);
    }

    /// Server-provided error envelopes must be routed to stderr, not stdout.
    #[tokio::test]
    async fn server_error_response_is_relayed_to_stderr() {
        let addr = mock_ws_server(|mut ws| async move {
            if let Some(Ok(Message::Text(_))) = ws.next().await {
                let resp = serde_json::json!({
                    "ok": false,
                    "cmd": "agent.show",
                    "error": "NOT_FOUND",
                    "message": "agent not found"
                });
                ws.send(Message::Text(serde_json::to_string(&resp).expect("ser").into()))
                    .await
                    .expect("server send");
            }
            let _ = ws.close(None).await;
        })
        .await;

        let ws = ws_connect(addr, "test-token").await;
        let input = b"{\"cmd\":\"agent.show\",\"id\":\"0xDEADBEEF\"}\n";
        let reader = tokio::io::BufReader::new(input.as_slice());
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut stdout, &mut stderr, ws, None).await;
        assert_eq!(code, EXIT_SUCCESS, "server error response must not force non-zero exit");
        assert!(stdout.is_empty(), "server error response must not hit stdout");

        let line = String::from_utf8(stderr).expect("utf8");
        let val: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(val["ok"], false);
        assert_eq!(val["error"], "NOT_FOUND");
    }

    /// `connect_websocket` against an unreachable address must return
    /// `CliError::ServerUnreachable`.
    #[tokio::test]
    async fn connect_websocket_returns_server_unreachable_on_refused() {
        let cfg = crate::config::ResolvedConfig {
            server: "http://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let result = connect_websocket(&cfg).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "unreachable server must return ServerUnreachable, got {result:?}"
        );
    }

    // ── map_ws_error / is_tls_cert_failure ───────────────────────────────────

    /// A rustls `InvalidCertificate` error must be classified as a cert failure.
    #[test]
    fn is_tls_cert_failure_detects_invalid_certificate() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err =
            TlsError::Rustls(rustls::Error::InvalidCertificate(rustls::CertificateError::Expired));
        assert!(is_tls_cert_failure(&tls_err));
    }

    /// `UnknownIssuer` is a certificate validation failure.
    #[test]
    fn is_tls_cert_failure_detects_unknown_issuer() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err = TlsError::Rustls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert!(is_tls_cert_failure(&tls_err));
    }

    /// `NoCertificatesPresented` is a certificate validation failure.
    #[test]
    fn is_tls_cert_failure_detects_no_certificates_presented() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err = TlsError::Rustls(rustls::Error::NoCertificatesPresented);
        assert!(is_tls_cert_failure(&tls_err));
    }

    /// A protocol error (e.g. no shared cipher suites) is NOT a cert failure.
    #[test]
    fn is_tls_cert_failure_returns_false_for_protocol_error() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err = TlsError::Rustls(rustls::Error::DecryptError);
        assert!(!is_tls_cert_failure(&tls_err));
    }

    /// A TLS certificate error must map to `ServerUnreachable`, not `AuthFailure`.
    #[test]
    fn map_ws_error_tls_cert_error_is_server_unreachable_not_auth_failure() {
        use tokio_tungstenite::tungstenite::Error as WsErr;
        use tokio_tungstenite::tungstenite::error::TlsError;
        let err = WsErr::Tls(TlsError::Rustls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        )));
        let mapped = map_ws_error(err, "wss://ts.example.com");
        assert!(
            matches!(mapped, CliError::ServerUnreachable(_)),
            "TLS cert error must be ServerUnreachable, got {mapped:?}"
        );
        // Exit code must be 4 (server unreachable), not 3 (auth failure).
        assert_eq!(mapped.exit_code(), crate::error::EXIT_SERVER_UNREACHABLE);
    }

    /// The `ServerUnreachable` message for a cert failure must mention TLS trust.
    #[test]
    fn map_ws_error_tls_cert_error_message_mentions_trust() {
        use tokio_tungstenite::tungstenite::Error as WsErr;
        use tokio_tungstenite::tungstenite::error::TlsError;
        let err = WsErr::Tls(TlsError::Rustls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        )));
        let mapped = map_ws_error(err, "wss://ts.example.com");
        let msg = mapped.to_string();
        assert!(
            msg.contains("trust") || msg.contains("certificate"),
            "message must mention trust/certificate, got: {msg}"
        );
    }

    /// A non-cert TLS error must still map to `ServerUnreachable` (not `AuthFailure`).
    #[test]
    fn map_ws_error_non_cert_tls_error_is_server_unreachable() {
        use tokio_tungstenite::tungstenite::Error as WsErr;
        use tokio_tungstenite::tungstenite::error::TlsError;
        let err = WsErr::Tls(TlsError::Rustls(rustls::Error::DecryptError));
        let mapped = map_ws_error(err, "wss://ts.example.com");
        assert!(
            matches!(mapped, CliError::ServerUnreachable(_)),
            "non-cert TLS error must be ServerUnreachable, got {mapped:?}"
        );
        assert_eq!(mapped.exit_code(), crate::error::EXIT_SERVER_UNREACHABLE);
    }
}
