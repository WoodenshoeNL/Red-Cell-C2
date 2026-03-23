//! `red-cell-cli session` — persistent newline-delimited JSON pipe.
//!
//! Reads one JSON command per line from stdin, dispatches each to the
//! teamserver via the existing HTTP API, and writes one JSON response per line
//! to stdout.  A single [`ApiClient`] is reused across all commands so the
//! authentication token is resolved only once.
//!
//! # Protocol
//!
//! **stdin** — one JSON object per line:
//! ```json
//! {"cmd": "agent.exec", "id": "abc123", "command": "whoami", "wait": true}
//! ```
//!
//! **stdout** — one JSON object per line:
//! ```json
//! {"ok": true,  "cmd": "agent.exec", "data": {"output": "DOMAIN\\user", "exit_code": 0}}
//! {"ok": false, "cmd": "agent.exec", "error": "NOT_FOUND", "message": "agent not found"}
//! ```
//!
//! The session terminates on:
//! - EOF on stdin
//! - `{"cmd": "exit"}`
//! - Ctrl-C
//!
//! # Supported commands
//!
//! | `cmd` | Required fields | Optional fields |
//! |---|---|---|
//! | `ping` | — | — |
//! | `exit` | — | — |
//! | `agent.list` | — | — |
//! | `agent.show` | `id` | — |
//! | `agent.exec` | `id`, `command` | `wait`, `timeout` |
//! | `agent.output` | `id` | `since` |
//! | `agent.kill` | `id` | `wait`, `timeout` |
//! | `listener.list` | — | — |
//! | `listener.show` | `name` | — |

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt as _;
use tokio::time::sleep;
use tracing::instrument;

use super::agent::{JobPageResponse, RawAgent, TaskQueuedResponse};
use super::listener::RawListenerSummary;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};

/// Default timeout for `agent.exec` with `"wait": true`, in seconds.
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 60;
/// Polling interval for wait loops.
const POLL_INTERVAL: Duration = Duration::from_millis(1_000);

// ── inbound message shape ─────────────────────────────────────────────────────

/// A single command message read from stdin.
///
/// Fields are unioned — a given command only uses the fields relevant to it.
/// Unknown fields are silently ignored.
#[derive(Debug, Deserialize)]
struct SessionCmd {
    /// Command name (e.g. `"agent.exec"`, `"ping"`, `"exit"`).
    cmd: String,
    /// Agent or resource identifier.
    #[serde(default)]
    id: Option<String>,
    /// Shell command string for `agent.exec`.
    #[serde(default)]
    command: Option<String>,
    /// Block until completion for `agent.exec` or `agent.kill`.
    #[serde(default)]
    wait: Option<bool>,
    /// Timeout in seconds for `agent.exec` with `wait = true`.
    #[serde(default)]
    timeout: Option<u64>,
    /// Only return output newer than this job ID (`agent.output`).
    #[serde(default)]
    #[allow(dead_code)]
    since: Option<String>,
    /// Listener name for `listener.show`.
    #[serde(default)]
    name: Option<String>,
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Run the session loop.
///
/// Reads newline-delimited JSON from stdin, dispatches each command to the
/// teamserver, and writes a JSON response line to stdout for each.
///
/// `default_agent` is used as the agent `id` when a command does not include
/// an `"id"` field.
///
/// Returns `EXIT_SUCCESS` on clean EOF or `{"cmd":"exit"}`, or `EXIT_GENERAL`
/// on a fatal stdin I/O error.
pub async fn run(client: &ApiClient, default_agent: Option<&str>) -> i32 {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut stdout = std::io::stdout();

    tokio::select! {
        code = run_with_io(reader, &mut stdout, client, default_agent) => code,
        _ = tokio::signal::ctrl_c() => EXIT_SUCCESS,
    }
}

/// Inner session loop — reads from `reader`, writes to `writer`.
///
/// Extracted from [`run`] so that tests can inject a `BufReader<&[u8]>` for
/// stdin and a `Vec<u8>` for stdout without touching real file descriptors.
async fn run_with_io<R, W>(
    reader: R,
    writer: &mut W,
    client: &ApiClient,
    default_agent: Option<&str>,
) -> i32
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: std::io::Write,
{
    let mut lines = reader.lines();

    loop {
        match lines.next_line().await {
            Err(e) => {
                // Fatal I/O error on stdin.
                emit_error_to(writer, "", &CliError::General(format!("stdin read error: {e}")));
                return EXIT_GENERAL;
            }
            Ok(None) => {
                // Clean EOF — exit normally.
                return EXIT_SUCCESS;
            }
            Ok(Some(line)) => {
                let line = line.trim().to_owned();
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<SessionCmd>(&line) {
                    Err(e) => {
                        emit_error_to(writer, "", &CliError::General(format!("invalid JSON: {e}")));
                    }
                    Ok(msg) => {
                        let cmd_name = msg.cmd.clone();
                        if cmd_name == "exit" {
                            return EXIT_SUCCESS;
                        }
                        let result = dispatch(client, &msg, default_agent).await;
                        match result {
                            Ok(data) => emit_ok_to(writer, &cmd_name, data),
                            Err(e) => emit_error_to(writer, &cmd_name, &e),
                        }
                    }
                }
            }
        }
    }
}

// ── command dispatcher ────────────────────────────────────────────────────────

/// Resolve an agent ID from the message or the session default.
fn agent_id<'a>(msg: &'a SessionCmd, default_agent: Option<&'a str>) -> Result<&'a str, CliError> {
    msg.id.as_deref().or(default_agent).ok_or_else(|| {
        CliError::InvalidArgs("command requires an agent id (set \"id\" or --agent)".to_owned())
    })
}

/// Dispatch a parsed command to the appropriate API call.
///
/// Returns the data payload to be included in the `"data"` field of the
/// success envelope, or a [`CliError`] to be turned into an error envelope.
async fn dispatch(
    client: &ApiClient,
    msg: &SessionCmd,
    default_agent: Option<&str>,
) -> Result<serde_json::Value, CliError> {
    match msg.cmd.as_str() {
        "ping" => Ok(serde_json::json!({"pong": true})),

        "agent.list" => {
            let agents: Vec<RawAgent> = client.get("/agents").await?;
            Ok(serde_json::to_value(agents)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "agent.show" => {
            let id = agent_id(msg, default_agent)?;
            let agent: RawAgent = client.get(&format!("/agents/{id}")).await?;
            Ok(serde_json::to_value(agent)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "agent.exec" => {
            let id = agent_id(msg, default_agent)?;
            let command = msg.command.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("agent.exec requires a \"command\" field".to_owned())
            })?;
            let wait = msg.wait.unwrap_or(false);
            let timeout_secs = msg.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS);
            exec(client, id, command, wait, timeout_secs).await
        }

        "agent.output" => {
            // The teamserver does not expose a REST output endpoint.
            // Operators should use the WebSocket client for live output.
            Err(CliError::General(
                "agent output is not available via the REST API; \
                 use the WebSocket client (red-cell-client) to receive command output"
                    .to_owned(),
            ))
        }

        "agent.kill" => {
            let id = agent_id(msg, default_agent)?;
            let wait = msg.wait.unwrap_or(false);
            let timeout_secs = msg.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS);
            kill(client, id, wait, timeout_secs).await
        }

        "listener.list" => {
            let listeners: Vec<RawListenerSummary> = client.get("/listeners").await?;
            Ok(serde_json::to_value(listeners)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "listener.show" => {
            let name = msg.name.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("listener.show requires a \"name\" field".to_owned())
            })?;
            let listener: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
            Ok(serde_json::to_value(listener)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        unknown => Err(CliError::InvalidArgs(format!("unknown session command: {unknown:?}"))),
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// Execute a shell command on an agent, optionally waiting for completion.
///
/// Submits the command via `POST /agents/{id}/task` using the Demon
/// `AgentTaskInfo` wire format.  With `wait=true`, polls
/// `GET /jobs?agent_id={id}&task_id={tid}` until the job is dequeued by the
/// agent or `timeout_secs` elapse.  Output is not available via REST.
#[instrument(skip(client))]
async fn exec(
    client: &ApiClient,
    agent_id: &str,
    command: &str,
    wait: bool,
    timeout_secs: u64,
) -> Result<serde_json::Value, CliError> {
    #[derive(Serialize)]
    struct Body<'a> {
        #[serde(rename = "CommandLine")]
        command_line: &'a str,
        #[serde(rename = "CommandID")]
        command_id: &'static str,
        #[serde(rename = "DemonID")]
        demon_id: &'a str,
        #[serde(rename = "TaskID")]
        task_id: &'static str,
    }

    let resp: TaskQueuedResponse = client
        .post(
            &format!("/agents/{agent_id}/task"),
            &Body { command_line: command, command_id: "21", demon_id: agent_id, task_id: "" },
        )
        .await?;
    let task_id = resp.task_id;

    if !wait {
        return Ok(serde_json::json!({"job_id": task_id}));
    }

    // Poll until the agent dequeues the job or the deadline is reached.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let poll_path = format!("/jobs?agent_id={agent_id}&task_id={task_id}");

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for job {task_id} to be picked up after {timeout_secs}s"
            )));
        }

        let page: JobPageResponse = client.get(&poll_path).await?;

        if page.total == 0 {
            return Ok(serde_json::json!({
                "job_id": task_id,
                "output": "output is not available via the REST API; \
                           use the WebSocket client (red-cell-client) to receive command output",
                "exit_code": null,
            }));
        }

        sleep(POLL_INTERVAL).await;
    }
}

/// Send a kill command to an agent, optionally waiting until it is dead.
///
/// Issues `DELETE /agents/{id}` which the server interprets as a
/// `CommandExit` task queued on the agent.
#[instrument(skip(client))]
async fn kill(
    client: &ApiClient,
    agent_id: &str,
    wait: bool,
    timeout_secs: u64,
) -> Result<serde_json::Value, CliError> {
    client.delete_no_body(&format!("/agents/{agent_id}")).await?;

    if !wait {
        return Ok(serde_json::json!({"agent_id": agent_id, "status": "kill_sent"}));
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for agent {agent_id} to die after {timeout_secs}s"
            )));
        }

        let raw: RawAgent = client.get(&format!("/agents/{agent_id}")).await?;
        if raw.status == "dead" {
            return Ok(serde_json::json!({"agent_id": agent_id, "status": raw.status}));
        }

        sleep(POLL_INTERVAL).await;
    }
}

// ── output helpers ────────────────────────────────────────────────────────────

/// Write a success response line to `writer`.
fn emit_ok_to(writer: &mut impl std::io::Write, cmd: &str, data: serde_json::Value) {
    let envelope = serde_json::json!({"ok": true, "cmd": cmd, "data": data});
    match serde_json::to_string(&envelope) {
        Ok(s) => {
            let _ = writeln!(writer, "{s}");
        }
        Err(_) => {
            let _ = writeln!(writer, r#"{{"ok":true,"cmd":"{cmd}"}}"#);
        }
    }
}

/// Write an error response line to `writer`.
///
/// In session mode all output (including errors) goes to the same stream so
/// the consuming process reads a single coherent NDJSON stream.
fn emit_error_to(writer: &mut impl std::io::Write, cmd: &str, err: &CliError) {
    let envelope = serde_json::json!({
        "ok": false,
        "cmd": cmd,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    match serde_json::to_string(&envelope) {
        Ok(s) => {
            let _ = writeln!(writer, "{s}");
        }
        Err(_) => {
            let _ = writeln!(
                writer,
                r#"{{"ok":false,"cmd":"{cmd}","error":"ERROR","message":"unknown error"}}"#
            );
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SessionCmd deserialisation ─────────────────────────────────────────────

    #[test]
    fn ping_deserialises() {
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"ping"}"#).expect("parse ping");
        assert_eq!(msg.cmd, "ping");
        assert!(msg.id.is_none());
    }

    #[test]
    fn exit_deserialises() {
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"exit"}"#).expect("parse exit");
        assert_eq!(msg.cmd, "exit");
    }

    #[test]
    fn agent_exec_deserialises_all_fields() {
        let json =
            r#"{"cmd":"agent.exec","id":"abc123","command":"whoami","wait":true,"timeout":30}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("parse agent.exec");
        assert_eq!(msg.cmd, "agent.exec");
        assert_eq!(msg.id.as_deref(), Some("abc123"));
        assert_eq!(msg.command.as_deref(), Some("whoami"));
        assert_eq!(msg.wait, Some(true));
        assert_eq!(msg.timeout, Some(30));
    }

    #[test]
    fn agent_output_with_since_deserialises() {
        let json = r#"{"cmd":"agent.output","id":"abc","since":"job_xyz"}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("parse agent.output");
        assert_eq!(msg.since.as_deref(), Some("job_xyz"));
    }

    #[test]
    fn listener_show_deserialises_name() {
        let json = r#"{"cmd":"listener.show","name":"http1"}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("parse listener.show");
        assert_eq!(msg.name.as_deref(), Some("http1"));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let json = r#"{"cmd":"ping","totally_unknown_field":42}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("unknown fields must not error");
        assert_eq!(msg.cmd, "ping");
    }

    // ── agent_id resolution ────────────────────────────────────────────────────

    #[test]
    fn agent_id_prefers_message_field_over_default() {
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"agent.show","id":"from-msg"}"#).expect("parse");
        let resolved = agent_id(&msg, Some("from-default")).expect("resolve");
        assert_eq!(resolved, "from-msg");
    }

    #[test]
    fn agent_id_falls_back_to_default() {
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"agent.show"}"#).expect("parse");
        let resolved = agent_id(&msg, Some("default-agent")).expect("resolve");
        assert_eq!(resolved, "default-agent");
    }

    #[test]
    fn agent_id_errors_when_neither_present() {
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"agent.show"}"#).expect("parse");
        let result = agent_id(&msg, None);
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs, got {result:?}"
        );
    }

    // ── emit_ok / emit_error output shape ─────────────────────────────────────

    #[test]
    fn emit_ok_produces_valid_json_envelope() {
        // We capture via serde_json directly rather than stdout.
        let data = serde_json::json!({"pong": true});
        let envelope = serde_json::json!({"ok": true, "cmd": "ping", "data": data});
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["cmd"], "ping");
        assert_eq!(envelope["data"]["pong"], true);
    }

    #[test]
    fn emit_error_produces_valid_json_envelope() {
        let err = CliError::NotFound("agent xyz".to_owned());
        let envelope = serde_json::json!({
            "ok": false,
            "cmd": "agent.show",
            "error": err.error_code(),
            "message": err.to_string(),
        });
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"], "NOT_FOUND");
        assert!(envelope["message"].as_str().is_some_and(|m| m.contains("not found")));
    }

    #[test]
    fn emit_error_for_invalid_args() {
        let err = CliError::InvalidArgs("missing id".to_owned());
        let envelope = serde_json::json!({
            "ok": false,
            "cmd": "agent.exec",
            "error": err.error_code(),
            "message": err.to_string(),
        });
        assert_eq!(envelope["error"], "INVALID_ARGS");
    }

    // ── dispatch: unknown command ──────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_unknown_command_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"does.not.exist"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs for unknown command, got {result:?}"
        );
    }

    // ── dispatch: ping (no network) ───────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_ping_returns_pong_without_network() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"ping"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await.expect("ping must succeed");
        assert_eq!(result["pong"], true);
    }

    // ── dispatch: missing agent id ────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_agent_show_without_id_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"agent.show"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when id missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_agent_exec_without_command_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"agent.exec","id":"abc"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when command missing, got {result:?}"
        );
    }

    // ── dispatch: network commands return ServerUnreachable (port 1 is closed) ─

    #[tokio::test]
    async fn dispatch_agent_list_returns_server_unreachable_on_no_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"agent.list"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_listener_list_returns_server_unreachable_on_no_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"listener.list"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got {result:?}"
        );
    }

    // ── dispatch: agent.output ────────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_agent_output_without_since_returns_general_error() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"agent.output","id":"agent1"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::General(_))),
            "expected General error (output not available via REST API), got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_agent_output_with_since_returns_general_error() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"agent.output","id":"agent1","since":"job_xyz"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::General(_))),
            "expected General error (output not available via REST API), got {result:?}"
        );
    }

    // ── dispatch: listener.show ───────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_listener_show_with_name_hits_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"listener.show","name":"http1"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable for listener.show with name, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_listener_show_without_name_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"listener.show"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when name missing, got {result:?}"
        );
    }

    // ── exec / kill polling paths (using wiremock) ────────────────────────────

    /// Helper: build a `ResolvedConfig` pointing at the given mock server URI.
    fn mock_cfg(server_uri: &str) -> crate::config::ResolvedConfig {
        crate::config::ResolvedConfig {
            server: server_uri.to_owned(),
            token: "test-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        }
    }

    /// Helper: a minimal JSON object that deserialises as [`RawAgent`].
    fn raw_agent_json(status: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "agent1",
            "hostname": "host1",
            "os": "linux",
            "last_seen": "2026-01-01T00:00:00Z",
            "status": status
        })
    }

    /// `exec wait=false` — POST task, return task_id immediately without polling.
    #[tokio::test]
    async fn exec_wait_false_returns_job_id_without_polling() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/agent1/task"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "agent_id": "AGENT1",
                "task_id": "TASK-ABC",
                "queued_jobs": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = exec(&client, "agent1", "whoami", false, 60).await.expect("exec must succeed");

        assert_eq!(result["job_id"], "TASK-ABC");
    }

    /// `exec wait=true` — poll until agent dequeues the job.  REST does not
    /// provide output, but the function must succeed with the task_id.
    #[tokio::test]
    async fn exec_wait_true_returns_task_id_when_job_dequeued() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/agent1/task"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "agent_id": "AGENT1",
                "task_id": "TASK-XYZ",
                "queued_jobs": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Immediate dequeue (total=0) so no sleep is needed.
        Mock::given(method("GET"))
            .and(path("/api/v1/jobs"))
            .and(query_param("agent_id", "agent1"))
            .and(query_param("task_id", "TASK-XYZ"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total": 0,
                "limit": 50,
                "offset": 0,
                "items": []
            })))
            .mount(&server)
            .await;

        let client = ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result =
            exec(&client, "agent1", "whoami", true, 60).await.expect("exec wait=true must succeed");

        assert_eq!(result["job_id"], "TASK-XYZ");
        // REST API does not provide output.
        assert!(
            result["output"].as_str().is_some_and(|s| s.contains("WebSocket client")),
            "output message must mention WebSocket client"
        );
    }

    /// `exec wait=true, timeout=0` — deadline is already expired on first loop
    /// iteration → returns `CliError::Timeout` without polling.
    #[tokio::test]
    async fn exec_wait_true_timeout_zero_returns_cli_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/agent1/task"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "agent_id": "AGENT1",
                "task_id": "TASK-TIMEOUT",
                "queued_jobs": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = exec(&client, "agent1", "whoami", true, 0).await;

        assert!(
            matches!(result, Err(CliError::Timeout(_))),
            "expected Timeout with timeout_secs=0, got {result:?}"
        );
    }

    /// `kill wait=false` — DELETE /agents/{id}, return `kill_sent` immediately.
    #[tokio::test]
    async fn kill_wait_false_returns_kill_sent_without_polling() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/agents/agent1"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "agent_id": "AGENT1",
                "task_id": "KILL-TASK",
                "queued_jobs": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result =
            kill(&client, "agent1", false, 60).await.expect("kill wait=false must succeed");

        assert_eq!(result["agent_id"], "agent1");
        assert_eq!(result["status"], "kill_sent");
    }

    /// `kill wait=true` — DELETE then poll until agent status is `"dead"`.
    #[tokio::test]
    async fn kill_wait_true_returns_success_when_agent_dies() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/agents/agent1"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "agent_id": "AGENT1",
                "task_id": "KILL-TASK",
                "queued_jobs": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_agent_json("dead")))
            .expect(1)
            .mount(&server)
            .await;

        let client = ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = kill(&client, "agent1", true, 60).await.expect("kill wait=true must succeed");

        assert_eq!(result["agent_id"], "agent1");
        assert_eq!(result["status"], "dead");
    }

    /// `kill wait=true, timeout=0` — deadline is already expired on first loop
    /// iteration → returns `CliError::Timeout` without polling the agent status.
    #[tokio::test]
    async fn kill_wait_true_timeout_zero_returns_cli_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/agents/agent1"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "agent_id": "AGENT1",
                "task_id": "KILL-TASK",
                "queued_jobs": 1
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = kill(&client, "agent1", true, 0).await;

        assert!(
            matches!(result, Err(CliError::Timeout(_))),
            "expected Timeout with timeout_secs=0, got {result:?}"
        );
    }

    // ── run_with_io: stdin-loop paths ─────────────────────────────────────────

    /// Build a no-network `ApiClient` for loop tests.
    fn loop_client() -> ApiClient {
        ApiClient::new(&crate::config::ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        })
        .expect("build client")
    }

    /// Parse all NDJSON lines from `buf` into a `Vec<serde_json::Value>`.
    fn parse_lines(buf: &[u8]) -> Vec<serde_json::Value> {
        std::str::from_utf8(buf)
            .expect("utf8 output")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("valid JSON line"))
            .collect()
    }

    /// Happy path: `{"cmd":"ping"}` → loop emits `{"ok":true,...,"pong":true}`.
    #[tokio::test]
    async fn run_loop_ping_emits_pong_response() {
        let input = b"{\"cmd\":\"ping\"}\n";
        let reader = tokio::io::BufReader::new(input.as_ref());
        let client = loop_client();
        let mut out: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut out, &client, None).await;

        assert_eq!(code, EXIT_SUCCESS);
        let lines = parse_lines(&out);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["ok"], true);
        assert_eq!(lines[0]["cmd"], "ping");
        assert_eq!(lines[0]["data"]["pong"], true);
    }

    /// Exit command: `{"cmd":"exit"}` → returns EXIT_SUCCESS, no output line.
    #[tokio::test]
    async fn run_loop_exit_cmd_terminates_with_success() {
        let input = b"{\"cmd\":\"exit\"}\n";
        let reader = tokio::io::BufReader::new(input.as_ref());
        let client = loop_client();
        let mut out: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut out, &client, None).await;

        assert_eq!(code, EXIT_SUCCESS);
        // exit must not emit any response line
        assert!(parse_lines(&out).is_empty());
    }

    /// Invalid JSON: loop emits `{"ok":false,"error":"GENERAL",...}` then continues.
    #[tokio::test]
    async fn run_loop_invalid_json_emits_error_and_continues() {
        // Invalid line first, then a valid ping so we can confirm the loop continues.
        let input = b"{not valid json}\n{\"cmd\":\"ping\"}\n";
        let reader = tokio::io::BufReader::new(input.as_ref());
        let client = loop_client();
        let mut out: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut out, &client, None).await;

        assert_eq!(code, EXIT_SUCCESS);
        let lines = parse_lines(&out);
        // First line: error for invalid JSON — CliError::General maps to "ERROR"
        assert_eq!(lines[0]["ok"], false);
        assert_eq!(lines[0]["error"], "ERROR");
        // Second line: successful ping response (proves loop continued)
        assert_eq!(lines[1]["ok"], true);
        assert_eq!(lines[1]["data"]["pong"], true);
    }

    /// Empty lines are skipped; the ping between them is still dispatched.
    #[tokio::test]
    async fn run_loop_empty_lines_skipped_valid_command_still_dispatched() {
        let input = b"\n   \n{\"cmd\":\"ping\"}\n\n";
        let reader = tokio::io::BufReader::new(input.as_ref());
        let client = loop_client();
        let mut out: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut out, &client, None).await;

        assert_eq!(code, EXIT_SUCCESS);
        let lines = parse_lines(&out);
        // Only the ping response; empty lines must produce no output.
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["data"]["pong"], true);
    }

    /// Clean EOF on an empty stdin → EXIT_SUCCESS, no output.
    #[tokio::test]
    async fn run_loop_clean_eof_returns_success() {
        let input: &[u8] = b"";
        let reader = tokio::io::BufReader::new(input);
        let client = loop_client();
        let mut out: Vec<u8> = Vec::new();

        let code = run_with_io(reader, &mut out, &client, None).await;

        assert_eq!(code, EXIT_SUCCESS);
        assert!(parse_lines(&out).is_empty());
    }
}
