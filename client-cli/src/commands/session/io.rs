//! Stdin/stdout/stderr framing, WebSocket message relay, and NDJSON envelopes.

use futures_util::SinkExt as _;
use tokio_tungstenite::tungstenite::{Message, protocol::CloseFrame};

use super::normalize::{is_known_session_command, normalize_agent_id_field};
use crate::AgentId;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};

/// Control flow token returned by the per-event handlers.
pub(crate) enum LoopControl {
    Continue,
    Exit(i32),
    /// Stdin reached EOF; the outer loop should drain remaining WebSocket
    /// messages before exiting.
    StdinEof,
}

/// Diagnostic emitted to stdout when the server ends the session.
pub(crate) struct SessionClosedEvent {
    pub(crate) reason: &'static str,
    pub(crate) code: Option<u16>,
    pub(crate) close_reason: Option<String>,
}

/// Handle one line read from stdin.
///
/// - Empty lines are skipped.
/// - Invalid JSON produces a local error response and continues.
/// - `{"cmd":"ping"}` is answered immediately without a server round-trip.
/// - `{"cmd":"exit"}` sends a WebSocket close frame and exits cleanly.
/// - Unknown `cmd` values produce a local JSON error on stderr (no forward).
/// - All other commands have the default agent id injected (if applicable) and
///   are forwarded to the server as a WebSocket text frame.
pub(crate) async fn process_stdin_line<Out, ErrOut, Si>(
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
                if emit_error_to(stderr, &cmd, &CliError::UnknownSessionCommand(cmd.clone()))
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

/// Handle one message received from the WebSocket.
///
/// - Text frames are written verbatim to stdout as a line.
/// - Close frames terminate the session cleanly.
/// - Binary / Ping / Pong frames are silently ignored.
/// - A closed stream (`None`) or an error terminates the session.
pub(crate) fn process_ws_message<Out, ErrOut>(
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

/// Write a success response line to `writer`.
pub(crate) fn emit_ok_to(
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
pub(crate) fn emit_error_to(
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
pub(crate) fn emit_session_closed_to(
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
pub(crate) fn response_is_error_envelope(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
        == Some(false)
}

impl SessionClosedEvent {
    pub(crate) fn from_close_frame(frame: Option<&CloseFrame>) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let err = crate::error::CliError::NotFound("agent xyz".to_owned());
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

    #[test]
    fn unknown_session_command_error_envelope_format() {
        let mut buf = Vec::new();
        let err = crate::error::CliError::UnknownSessionCommand("agent.lst".to_owned());
        emit_error_to(&mut buf, "agent.lst", &err).expect("write");
        let val: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).expect("utf8").trim()).expect("json");
        assert_eq!(val["ok"], false);
        assert_eq!(val["cmd"], "agent.lst");
        assert_eq!(val["error"], "UNKNOWN_COMMAND");
        assert_eq!(val["message"].as_str(), Some("unknown command `agent.lst`"));
    }
}
