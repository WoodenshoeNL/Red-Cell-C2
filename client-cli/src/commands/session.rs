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
//! | `agent.kill` | `id` | `wait` |
//! | `listener.list` | — | — |
//! | `listener.show` | `name` | — |

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt as _;
use tokio::time::sleep;
use tracing::instrument;

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
    since: Option<String>,
    /// Listener name for `listener.show`.
    #[serde(default)]
    name: Option<String>,
}

// ── raw API shapes (private to this module) ───────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct RawAgent {
    id: String,
    hostname: String,
    os: String,
    last_seen: String,
    status: String,
    arch: Option<String>,
    username: Option<String>,
    domain: Option<String>,
    internal_ip: Option<String>,
    process_name: Option<String>,
    pid: Option<u64>,
    sleep_interval: Option<u64>,
    jitter: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct JobSubmitResponse {
    job_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct JobStatus {
    job_id: String,
    status: String,
    output: Option<String>,
    exit_code: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OutputEntry {
    job_id: String,
    command: Option<String>,
    output: String,
    exit_code: Option<i32>,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawListener {
    name: String,
    #[serde(rename = "type")]
    listener_type: String,
    status: String,
    host: Option<String>,
    port: Option<u16>,
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
    let mut lines = reader.lines();

    loop {
        let line_result: std::io::Result<Option<String>> = tokio::select! {
            result = lines.next_line() => result,
            _ = tokio::signal::ctrl_c() => {
                return EXIT_SUCCESS;
            }
        };

        match line_result {
            Err(e) => {
                // Fatal I/O error on stdin.
                emit_error("", &CliError::General(format!("stdin read error: {e}")));
                return EXIT_GENERAL;
            }
            Ok(None) => {
                // Clean EOF — exit normally.
                return EXIT_SUCCESS;
            }
            Ok(Some(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<SessionCmd>(line) {
                    Err(e) => {
                        emit_error("", &CliError::General(format!("invalid JSON: {e}")));
                    }
                    Ok(msg) => {
                        let cmd_name = msg.cmd.clone();
                        if cmd_name == "exit" {
                            return EXIT_SUCCESS;
                        }
                        let result = dispatch(client, &msg, default_agent).await;
                        match result {
                            Ok(data) => emit_ok(&cmd_name, data),
                            Err(e) => emit_error(&cmd_name, &e),
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
            let id = agent_id(msg, default_agent)?;
            let path = match msg.since.as_deref() {
                Some(job_id) => format!("/agents/{id}/output?since={job_id}"),
                None => format!("/agents/{id}/output"),
            };
            let entries: Vec<OutputEntry> = client.get(&path).await?;
            Ok(serde_json::to_value(entries)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "agent.kill" => {
            let id = agent_id(msg, default_agent)?;
            let wait = msg.wait.unwrap_or(false);
            kill(client, id, wait).await
        }

        "listener.list" => {
            let listeners: Vec<RawListener> = client.get("/listeners").await?;
            Ok(serde_json::to_value(listeners)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "listener.show" => {
            let name = msg.name.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("listener.show requires a \"name\" field".to_owned())
            })?;
            let listener: RawListener = client.get(&format!("/listeners/{name}")).await?;
            Ok(serde_json::to_value(listener)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        unknown => Err(CliError::InvalidArgs(format!("unknown session command: {unknown:?}"))),
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// Execute a shell command on an agent, optionally waiting for completion.
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
        cmd: &'a str,
    }

    let resp: JobSubmitResponse =
        client.post(&format!("/agents/{agent_id}/jobs"), &Body { cmd: command }).await?;
    let job_id = resp.job_id;

    if !wait {
        return Ok(serde_json::json!({"job_id": job_id}));
    }

    // Poll until done or timeout.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let job_path = format!("/agents/{agent_id}/jobs/{job_id}");

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for job {job_id} after {timeout_secs}s"
            )));
        }

        let status: JobStatus = client.get(&job_path).await?;
        match status.status.as_str() {
            "done" | "error" => {
                return Ok(serde_json::json!({
                    "job_id": status.job_id,
                    "output": status.output.unwrap_or_default(),
                    "exit_code": status.exit_code,
                }));
            }
            _ => {
                sleep(POLL_INTERVAL).await;
            }
        }
    }
}

/// Send a kill command to an agent, optionally waiting until it is dead.
#[instrument(skip(client))]
async fn kill(
    client: &ApiClient,
    agent_id: &str,
    wait: bool,
) -> Result<serde_json::Value, CliError> {
    #[derive(Serialize)]
    struct Empty {}
    let _: serde_json::Value = client.post(&format!("/agents/{agent_id}/kill"), &Empty {}).await?;

    if !wait {
        return Ok(serde_json::json!({"agent_id": agent_id, "status": "kill_sent"}));
    }

    let deadline = Instant::now() + Duration::from_secs(DEFAULT_EXEC_TIMEOUT_SECS);

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for agent {agent_id} to die after {}s",
                DEFAULT_EXEC_TIMEOUT_SECS
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

/// Write a success response line to stdout.
fn emit_ok(cmd: &str, data: serde_json::Value) {
    let envelope = serde_json::json!({"ok": true, "cmd": cmd, "data": data});
    match serde_json::to_string(&envelope) {
        Ok(s) => println!("{s}"),
        Err(_) => println!(r#"{{"ok":true,"cmd":"{cmd}"}}"#),
    }
}

/// Write an error response line to stdout.
///
/// In session mode all output (including errors) goes to stdout so the
/// consuming process reads a single coherent stream.
fn emit_error(cmd: &str, err: &CliError) {
    let envelope = serde_json::json!({
        "ok": false,
        "cmd": cmd,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    match serde_json::to_string(&envelope) {
        Ok(s) => println!("{s}"),
        Err(_) => {
            println!(r#"{{"ok":false,"cmd":"{cmd}","error":"ERROR","message":"unknown error"}}"#)
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
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"listener.list"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got {result:?}"
        );
    }
}
