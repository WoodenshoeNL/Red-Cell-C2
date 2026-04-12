//! Top-level session entrypoint and stdin/WebSocket multiplex loop.

use futures_util::StreamExt as _;
use tokio::io::AsyncBufReadExt as _;

use crate::AgentId;
use crate::config::ResolvedConfig;
use crate::error::EXIT_SUCCESS;

use super::connect::connect_websocket;
use super::io::{LoopControl, emit_error_to, process_stdin_line, process_ws_message};

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
pub(crate) async fn run_with_io<R, Out, ErrOut, S>(
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

#[cfg(test)]
mod tests {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::{Message, protocol::CloseFrame};

    use crate::AgentId;
    use crate::error::EXIT_SUCCESS;

    use super::super::connect::API_KEY_HEADER;
    use super::run_with_io;

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

        assert!(stdout.is_empty(), "local unknown-command error must not hit stdout");
        let line = String::from_utf8(stderr).expect("utf8");
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
}
