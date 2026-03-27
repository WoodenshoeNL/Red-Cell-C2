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
//! | `agent.upload` | `id`, `src`, `dst` | — |
//! | `agent.download` | `id`, `src` | `dst` |
//! | `listener.list` | — | — |
//! | `listener.show` | `name` | — |
//! | `listener.create` | `name`, `type` | `port`, `host`, `domain`, `pipe_name`, `endpoint`, `secure`, `config_json` |
//! | `listener.start` | `name` | — |
//! | `listener.stop` | `name` | — |
//! | `listener.delete` | `name` | — |
//! | `operator.list` | — | — |
//! | `operator.create` | `username`, `password`, `role` | — |
//! | `operator.delete` | `username` | — |
//! | `operator.set-role` | `username`, `role` | — |
//! | `payload.list` | — | — |
//! | `payload.build` | `listener`, `arch`, `format` | `sleep`, `wait`, `timeout` |
//! | `payload.download` | `id`, `dst` | — |
//! | `log.list` | — | `operator`, `action`, `since`, `id` (agent filter), `limit` |
//! | `log.tail` | — | — |

use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt as _;
use tokio::time::sleep;
use tracing::instrument;

use super::agent::{RawAgent, TaskQueuedResponse};
use super::listener::{RawListenerSummary, build_create_body};
use super::operator::validate_role;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};

/// Default timeout for `agent.exec` with `"wait": true`, in seconds.
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 60;
/// Default timeout for `payload.build` with `"wait": true`, in seconds.
const DEFAULT_BUILD_TIMEOUT_SECS: u64 = 300;
/// Default number of entries returned by `log.list` when `limit` is not set.
const DEFAULT_LOG_LIMIT: u32 = 50;
/// Number of entries fetched by `log.tail`.
const LOG_TAIL_LIMIT: u32 = 20;
/// Polling interval for wait loops.
const POLL_INTERVAL: Duration = Duration::from_millis(1_000);
/// Polling interval for build wait loops.
const BUILD_POLL_INTERVAL: Duration = Duration::from_millis(2_000);

// ── inbound message shape ─────────────────────────────────────────────────────

/// A single command message read from stdin.
///
/// Fields are unioned — a given command only uses the fields relevant to it.
/// Unknown fields are silently ignored.
#[derive(Debug, Deserialize)]
struct SessionCmd {
    /// Command name (e.g. `"agent.exec"`, `"ping"`, `"exit"`).
    cmd: String,
    /// Agent or resource identifier (agent ID, payload ID for `payload.download`).
    #[serde(default)]
    id: Option<String>,
    /// Shell command string for `agent.exec`.
    #[serde(default)]
    command: Option<String>,
    /// Block until completion for `agent.exec`, `agent.kill`, or `payload.build`.
    #[serde(default)]
    wait: Option<bool>,
    /// Timeout in seconds for `*wait=true` commands.
    #[serde(default)]
    timeout: Option<u64>,
    /// Only return output newer than this job ID (`agent.output`) or ISO-8601
    /// timestamp (`log.list`).
    #[serde(default)]
    since: Option<String>,
    /// Listener name for `listener.show/start/stop/delete`.
    #[serde(default)]
    name: Option<String>,

    // ── listener.create ───────────────────────────────────────────────────────
    /// Listener protocol type: `"http"`, `"https"`, `"dns"`, `"smb"`, `"external"`.
    #[serde(rename = "type", default)]
    listener_type: Option<String>,
    /// Port to bind for `listener.create`.
    #[serde(default)]
    port: Option<u16>,
    /// Host/interface to bind for `listener.create` (default `"0.0.0.0"`).
    #[serde(default)]
    host: Option<String>,
    /// DNS domain for `listener.create --type dns`.
    #[serde(default)]
    domain: Option<String>,
    /// Named-pipe name for `listener.create --type smb`.
    #[serde(default)]
    pipe_name: Option<String>,
    /// Bridge endpoint for `listener.create --type external`.
    #[serde(default)]
    endpoint: Option<String>,
    /// Enable TLS for `listener.create --type http`.
    #[serde(default)]
    secure: bool,
    /// Raw inner-config JSON for `listener.create` (overrides all other flags).
    #[serde(default)]
    config_json: Option<String>,

    // ── operator commands ─────────────────────────────────────────────────────
    /// Operator username for `operator.create/delete/set-role`.
    #[serde(default)]
    username: Option<String>,
    /// Operator password for `operator.create`.
    #[serde(default)]
    password: Option<String>,
    /// Operator role for `operator.create/set-role` (`"admin"`, `"operator"`, `"analyst"`).
    #[serde(default)]
    role: Option<String>,

    // ── payload commands ──────────────────────────────────────────────────────
    /// Listener name to embed in the payload (`payload.build`).
    #[serde(default)]
    listener: Option<String>,
    /// CPU architecture for `payload.build` (e.g. `"x86_64"`, `"x86"`).
    #[serde(default)]
    arch: Option<String>,
    /// Payload format for `payload.build`: `"exe"`, `"dll"`, or `"bin"`.
    #[serde(default)]
    format: Option<String>,
    /// Sleep interval in seconds to bake into the payload (`payload.build`).
    #[serde(default)]
    sleep: Option<u64>,
    /// Destination / local file path for `payload.download` and `agent.download`.
    #[serde(default)]
    dst: Option<String>,
    /// Source / local file path for `agent.upload`, or remote path for
    /// `agent.download`.
    #[serde(default)]
    src: Option<String>,

    // ── log commands ──────────────────────────────────────────────────────────
    /// Operator name filter for `log.list`.
    #[serde(default)]
    operator: Option<String>,
    /// Action filter for `log.list`.
    #[serde(default)]
    action: Option<String>,
    /// Maximum number of entries to return for `log.list`.
    #[serde(default)]
    limit: Option<u32>,
}

// ── local raw API response shapes for new commands ────────────────────────────

use super::types::{OutputPage, output_url};

/// Minimal operator record returned by `GET /operators` and `POST /operators`.
#[derive(Debug, Deserialize, Serialize)]
struct RawOperator {
    username: String,
    role: String,
    online: bool,
    last_seen: Option<String>,
}

/// Response from `POST /operators`.
#[derive(Debug, Deserialize, Serialize)]
struct RawOperatorCreate {
    username: String,
    role: String,
}

/// Minimal payload record returned by `GET /payloads`.
#[derive(Debug, Deserialize, Serialize)]
struct RawPayload {
    id: String,
    name: String,
    arch: String,
    format: String,
    built_at: String,
    #[serde(default)]
    size_bytes: Option<u64>,
}

/// Response from `POST /payloads/build`.
#[derive(Debug, Deserialize)]
struct BuildSubmitted {
    job_id: String,
}

/// Status response from `GET /payloads/jobs/{job_id}`.
#[derive(Debug, Deserialize)]
struct BuildStatus {
    job_id: String,
    /// `"pending"` | `"running"` | `"done"` | `"error"`
    status: String,
    payload_id: Option<String>,
    size_bytes: Option<u64>,
    error: Option<String>,
}

/// A single audit record returned by `GET /audit`.
#[derive(Debug, Deserialize, Serialize)]
struct RawAuditRecord {
    #[allow(dead_code)]
    id: i64,
    actor: String,
    action: String,
    agent_id: Option<String>,
    occurred_at: String,
}

/// Paged audit response from `GET /audit`.
#[derive(Debug, Deserialize)]
struct RawAuditPage {
    #[allow(dead_code)]
    total: usize,
    items: Vec<RawAuditRecord>,
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

/// Percent-encode characters that are not safe in query-string values.
fn percent_encode(s: &str) -> String {
    s.bytes()
        .flat_map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                vec![b as char]
            }
            other => format!("%{other:02X}").chars().collect::<Vec<_>>(),
        })
        .collect()
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

        // ── agent ─────────────────────────────────────────────────────────────
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
            let page: OutputPage = client.get(&output_url(id, msg.since.as_deref())).await?;
            let entries: Vec<serde_json::Value> = page
                .entries
                .into_iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "task_id": e.task_id,
                        "command": e.command_line,
                        "output": if e.output.is_empty() { e.message } else { e.output },
                        "received_at": e.received_at,
                    })
                })
                .collect();
            Ok(serde_json::json!(entries))
        }

        "agent.kill" => {
            let id = agent_id(msg, default_agent)?;
            let wait = msg.wait.unwrap_or(false);
            let timeout_secs = msg.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS);
            kill(client, id, wait, timeout_secs).await
        }

        "agent.upload" => {
            let id = agent_id(msg, default_agent)?;
            let src = msg.src.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("agent.upload requires a \"src\" field".to_owned())
            })?;
            let dst = msg.dst.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("agent.upload requires a \"dst\" field".to_owned())
            })?;

            use base64::Engine;
            use base64::engine::general_purpose::STANDARD as BASE64;

            let file_bytes = tokio::fs::read(src)
                .await
                .map_err(|e| CliError::General(format!("failed to read local file {src}: {e}")))?;
            let content = BASE64.encode(&file_bytes);

            #[derive(Serialize)]
            struct Body<'a> {
                remote_path: &'a str,
                content: &'a str,
            }

            let resp: TaskQueuedResponse = client
                .post(
                    &format!("/agents/{id}/upload"),
                    &Body { remote_path: dst, content: &content },
                )
                .await?;

            Ok(serde_json::json!({
                "agent_id": id,
                "job_id": resp.task_id,
                "local_path": src,
                "remote_path": dst
            }))
        }

        "agent.download" => {
            let id = agent_id(msg, default_agent)?;
            let src = msg.src.as_deref().ok_or_else(|| {
                CliError::InvalidArgs(
                    "agent.download requires a \"src\" field (remote path)".to_owned(),
                )
            })?;

            #[derive(Serialize)]
            struct Body<'a> {
                remote_path: &'a str,
            }

            let resp: TaskQueuedResponse =
                client.post(&format!("/agents/{id}/download"), &Body { remote_path: src }).await?;

            Ok(serde_json::json!({
                "agent_id": id,
                "job_id": resp.task_id,
                "remote_path": src,
                "local_path": msg.dst.as_deref().unwrap_or("")
            }))
        }

        // ── listener ──────────────────────────────────────────────────────────
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

        "listener.create" => {
            let name = msg.name.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("listener.create requires a \"name\" field".to_owned())
            })?;
            let listener_type = msg.listener_type.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("listener.create requires a \"type\" field".to_owned())
            })?;
            let host = msg.host.as_deref().unwrap_or("0.0.0.0");
            let body = build_create_body(
                name,
                listener_type,
                msg.port,
                host,
                msg.domain.as_deref(),
                msg.pipe_name.as_deref(),
                msg.endpoint.as_deref(),
                msg.secure,
                msg.config_json.as_deref(),
            )?;
            let raw: RawListenerSummary = client.post("/listeners", &body).await?;
            Ok(serde_json::to_value(raw)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "listener.start" => {
            let name = msg.name.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("listener.start requires a \"name\" field".to_owned())
            })?;
            listener_set_state(client, name, "start").await
        }

        "listener.stop" => {
            let name = msg.name.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("listener.stop requires a \"name\" field".to_owned())
            })?;
            listener_set_state(client, name, "stop").await
        }

        "listener.delete" => {
            let name = msg.name.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("listener.delete requires a \"name\" field".to_owned())
            })?;
            client.delete_no_body(&format!("/listeners/{name}")).await?;
            Ok(serde_json::json!({"name": name, "deleted": true}))
        }

        // ── operator ──────────────────────────────────────────────────────────
        "operator.list" => {
            let operators: Vec<RawOperator> = client.get("/operators").await?;
            Ok(serde_json::to_value(operators)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "operator.create" => {
            let username = msg.username.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("operator.create requires a \"username\" field".to_owned())
            })?;
            let password = msg.password.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("operator.create requires a \"password\" field".to_owned())
            })?;
            let role = msg.role.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("operator.create requires a \"role\" field".to_owned())
            })?;
            validate_role(role)?;
            let body =
                serde_json::json!({ "username": username, "password": password, "role": role });
            let raw: RawOperatorCreate = client.post("/operators", &body).await?;
            Ok(serde_json::to_value(raw)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "operator.delete" => {
            let username = msg.username.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("operator.delete requires a \"username\" field".to_owned())
            })?;
            client.delete_no_body(&format!("/operators/{username}")).await?;
            Ok(serde_json::json!({"username": username, "deleted": true}))
        }

        "operator.set-role" => {
            let username = msg.username.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("operator.set-role requires a \"username\" field".to_owned())
            })?;
            let role = msg.role.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("operator.set-role requires a \"role\" field".to_owned())
            })?;
            validate_role(role)?;
            let body = serde_json::json!({ "role": role });
            let raw: RawOperator =
                client.put(&format!("/operators/{username}/role"), &body).await?;
            Ok(serde_json::to_value(raw)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        // ── payload ───────────────────────────────────────────────────────────
        "payload.list" => {
            let payloads: Vec<RawPayload> = client.get("/payloads").await?;
            Ok(serde_json::to_value(payloads)
                .map_err(|e| CliError::General(format!("serialise error: {e}")))?)
        }

        "payload.build" => {
            let listener = msg.listener.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("payload.build requires a \"listener\" field".to_owned())
            })?;
            let arch = msg.arch.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("payload.build requires an \"arch\" field".to_owned())
            })?;
            let format = msg.format.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("payload.build requires a \"format\" field".to_owned())
            })?;
            super::payload::validate_format(format)?;
            let wait = msg.wait.unwrap_or(false);
            let timeout_secs = msg.timeout.unwrap_or(DEFAULT_BUILD_TIMEOUT_SECS);
            payload_build(client, listener, arch, format, msg.sleep, wait, timeout_secs).await
        }

        "payload.download" => {
            let id = msg.id.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("payload.download requires an \"id\" field".to_owned())
            })?;
            let dst = msg.dst.as_deref().ok_or_else(|| {
                CliError::InvalidArgs("payload.download requires a \"dst\" field".to_owned())
            })?;
            payload_download(client, id, dst).await
        }

        // ── log ───────────────────────────────────────────────────────────────
        "log.list" => {
            let limit = msg.limit.unwrap_or(DEFAULT_LOG_LIMIT);
            log_list(
                client,
                limit,
                msg.since.as_deref(),
                msg.operator.as_deref(),
                msg.id.as_deref(),
                msg.action.as_deref(),
            )
            .await
        }

        "log.tail" => log_list(client, LOG_TAIL_LIMIT, None, None, None, None).await,

        unknown => Err(CliError::InvalidArgs(format!("unknown session command: {unknown:?}"))),
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// Execute a shell command on an agent, optionally waiting for completion.
///
/// Submits the command via `POST /agents/{id}/task` using the Demon
/// `AgentTaskInfo` wire format.
///
/// With `wait=true`, polls `GET /agents/{id}/output` until an entry matching
/// the submitted task appears, or the timeout expires.
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

    if !wait {
        return Ok(serde_json::json!({"job_id": resp.task_id}));
    }

    // Poll the output endpoint for the task's result.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut cursor: Option<String> = None;

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for output from task {} after {timeout_secs}s",
                resp.task_id
            )));
        }

        sleep(POLL_INTERVAL).await;

        let page: OutputPage = client.get(&output_url(agent_id, cursor.as_deref())).await?;

        for entry in &page.entries {
            cursor = Some(entry.id.to_string());
            if entry.task_id.as_deref() == Some(resp.task_id.as_str()) {
                let output = if entry.output.is_empty() { &entry.message } else { &entry.output };
                return Ok(serde_json::json!({
                    "job_id": resp.task_id,
                    "output": output,
                    "exit_code": serde_json::Value::Null
                }));
            }
        }
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

/// Transition a listener to a new state (`"start"` or `"stop"`).
///
/// Issues `PUT /listeners/{name}/{action}`.  Handles idempotent responses:
/// if the server reports `listener_already_running` or `listener_not_running`
/// the current state is fetched and returned with `"already_in_state": true`.
#[instrument(skip(client))]
async fn listener_set_state(
    client: &ApiClient,
    name: &str,
    action: &str,
) -> Result<serde_json::Value, CliError> {
    let already_in_state = match client
        .put_empty::<RawListenerSummary>(&format!("/listeners/{name}/{action}"))
        .await
    {
        Ok(raw) => {
            return Ok(serde_json::json!({
                "name": name,
                "status": raw.state.status,
                "already_in_state": false,
            }));
        }
        Err(CliError::General(msg))
            if msg.contains("listener_already_running") || msg.contains("listener_not_running") =>
        {
            true
        }
        Err(e) => return Err(e),
    };

    let raw: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
    Ok(serde_json::json!({
        "name": name,
        "status": raw.state.status,
        "already_in_state": already_in_state,
    }))
}

/// Submit a payload build job, optionally waiting for completion.
///
/// With `wait=true`, polls `GET /payloads/jobs/{job_id}` until the build
/// finishes or `timeout_secs` elapse.
#[instrument(skip(client))]
async fn payload_build(
    client: &ApiClient,
    listener: &str,
    arch: &str,
    format: &str,
    sleep_secs: Option<u64>,
    wait: bool,
    timeout_secs: u64,
) -> Result<serde_json::Value, CliError> {
    let mut body = serde_json::json!({
        "listener": listener,
        "arch": arch,
        "format": format,
    });
    if let Some(s) = sleep_secs {
        body["sleep"] = serde_json::json!(s);
    }

    let submitted: BuildSubmitted = client.post("/payloads/build", &body).await?;

    if !wait {
        return Ok(serde_json::json!({"job_id": submitted.job_id}));
    }

    // Poll until done or timeout.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let job_path = format!("/payloads/jobs/{}", submitted.job_id);

    loop {
        if Instant::now() > deadline {
            return Err(CliError::Timeout(format!(
                "payload build job {} did not complete within {timeout_secs}s",
                submitted.job_id
            )));
        }

        let status: BuildStatus = client.get(&job_path).await?;

        match status.status.as_str() {
            "done" => {
                let payload_id = status.payload_id.ok_or_else(|| {
                    CliError::General(format!(
                        "build job {} reported done but returned no payload_id",
                        status.job_id
                    ))
                })?;
                return Ok(serde_json::json!({
                    "id": payload_id,
                    "size_bytes": status.size_bytes.unwrap_or(0),
                }));
            }
            "error" => {
                let msg = status.error.unwrap_or_else(|| "unknown build error".to_owned());
                return Err(CliError::General(format!(
                    "build job {} failed: {msg}",
                    status.job_id
                )));
            }
            // "pending" | "running" — keep polling
            _ => {}
        }

        sleep(BUILD_POLL_INTERVAL).await;
    }
}

/// Download a payload binary and write it to disk.
///
/// Calls `GET /payloads/{id}/download`, then writes the raw bytes to `dst`,
/// creating any missing parent directories.
#[instrument(skip(client))]
async fn payload_download(
    client: &ApiClient,
    id: &str,
    dst: &str,
) -> Result<serde_json::Value, CliError> {
    let bytes = client.get_raw_bytes(&format!("/payloads/{id}/download")).await?;
    let size_bytes = bytes.len() as u64;

    let dst_path = Path::new(dst);
    if let Some(parent) = dst_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::General(format!("failed to create destination directory: {e}"))
            })?;
        }
    }

    std::fs::write(dst_path, &bytes)
        .map_err(|e| CliError::General(format!("failed to write payload to {dst}: {e}")))?;

    Ok(serde_json::json!({
        "id": id,
        "dst": dst,
        "size_bytes": size_bytes,
    }))
}

/// Fetch audit log entries with optional filters.
///
/// Entries are returned newest-first.  The `agent_id` filter uses the `id`
/// field in the session message (consistent with other agent-targeting
/// commands).
#[instrument(skip(client))]
async fn log_list(
    client: &ApiClient,
    limit: u32,
    since: Option<&str>,
    operator: Option<&str>,
    agent_id: Option<&str>,
    action: Option<&str>,
) -> Result<serde_json::Value, CliError> {
    let mut params: Vec<String> = vec![format!("limit={limit}")];
    if let Some(s) = since {
        params.push(format!("since={}", percent_encode(s)));
    }
    if let Some(op) = operator {
        params.push(format!("operator={}", percent_encode(op)));
    }
    if let Some(aid) = agent_id {
        params.push(format!("agent_id={}", percent_encode(aid)));
    }
    if let Some(act) = action {
        params.push(format!("action={}", percent_encode(act)));
    }

    let path = format!("/audit?{}", params.join("&"));
    let page: RawAuditPage = client.get(&path).await?;
    serde_json::to_value(page.items).map_err(|e| CliError::General(format!("serialise error: {e}")))
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
    fn listener_create_deserialises_all_fields() {
        let json = r#"{"cmd":"listener.create","name":"http1","type":"http","port":443,"host":"0.0.0.0","secure":true}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("parse listener.create");
        assert_eq!(msg.name.as_deref(), Some("http1"));
        assert_eq!(msg.listener_type.as_deref(), Some("http"));
        assert_eq!(msg.port, Some(443));
        assert!(msg.secure);
    }

    #[test]
    fn operator_create_deserialises_all_fields() {
        let json =
            r#"{"cmd":"operator.create","username":"alice","password":"s3cr3t","role":"operator"}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("parse operator.create");
        assert_eq!(msg.username.as_deref(), Some("alice"));
        assert_eq!(msg.password.as_deref(), Some("s3cr3t"));
        assert_eq!(msg.role.as_deref(), Some("operator"));
    }

    #[test]
    fn payload_build_deserialises_all_fields() {
        let json = r#"{"cmd":"payload.build","listener":"http1","arch":"x86_64","format":"exe","sleep":5,"wait":true,"timeout":120}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("parse payload.build");
        assert_eq!(msg.listener.as_deref(), Some("http1"));
        assert_eq!(msg.arch.as_deref(), Some("x86_64"));
        assert_eq!(msg.format.as_deref(), Some("exe"));
        assert_eq!(msg.sleep, Some(5));
        assert_eq!(msg.wait, Some(true));
        assert_eq!(msg.timeout, Some(120));
    }

    #[test]
    fn log_list_deserialises_all_fields() {
        let json = r#"{"cmd":"log.list","operator":"alice","action":"agent.exec","id":"agent1","since":"2026-01-01T00:00:00Z","limit":25}"#;
        let msg: SessionCmd = serde_json::from_str(json).expect("parse log.list");
        assert_eq!(msg.operator.as_deref(), Some("alice"));
        assert_eq!(msg.action.as_deref(), Some("agent.exec"));
        assert_eq!(msg.id.as_deref(), Some("agent1"));
        assert_eq!(msg.since.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(msg.limit, Some(25));
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

    // ── percent_encode ─────────────────────────────────────────────────────────

    #[test]
    fn percent_encode_leaves_safe_chars_unchanged() {
        assert_eq!(percent_encode("abc123"), "abc123");
    }

    #[test]
    fn percent_encode_encodes_space() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_iso8601_timestamp_unchanged() {
        assert_eq!(percent_encode("2026-01-01T00:00:00Z"), "2026-01-01T00:00:00Z");
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

    // ── dispatch: agent.exec with wait=true against unreachable server ────────

    #[tokio::test]
    async fn dispatch_agent_exec_wait_returns_server_unreachable() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(
            r#"{"cmd":"agent.exec","id":"abc","command":"whoami","wait":true}"#,
        )
        .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable for agent.exec with wait=true against no server, got {result:?}"
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

    // ── dispatch: agent.output against unreachable server ───────────────────

    #[tokio::test]
    async fn dispatch_agent_output_without_since_returns_server_unreachable() {
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
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable for agent.output against no server, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_agent_output_with_since_returns_server_unreachable() {
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
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable for agent.output against no server, got {result:?}"
        );
    }

    // ── dispatch: agent.upload / agent.download — validation errors ──────────

    #[tokio::test]
    async fn dispatch_agent_upload_requires_src_field() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"agent.upload","id":"agent1"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "agent.upload without src must return InvalidArgs, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_agent_download_requires_src_field() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"agent.download","id":"agent1"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "agent.download without src must return InvalidArgs, got {result:?}"
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

    // ── dispatch: listener.create ─────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_listener_create_without_name_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"listener.create","type":"http"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when name missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_listener_create_without_type_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"listener.create","name":"http1"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when type missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_listener_create_with_valid_args_hits_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(
            r#"{"cmd":"listener.create","name":"http1","type":"http","port":443}"#,
        )
        .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable when server not running, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_listener_create_with_unknown_type_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"listener.create","name":"x","type":"ftp"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs for unknown listener type, got {result:?}"
        );
    }

    // ── dispatch: listener.start / listener.stop ──────────────────────────────

    #[tokio::test]
    async fn dispatch_listener_start_without_name_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"listener.start"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when name missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_listener_stop_without_name_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"listener.stop"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when name missing, got {result:?}"
        );
    }

    // ── dispatch: listener.delete ─────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_listener_delete_without_name_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"listener.delete"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when name missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_listener_delete_with_name_hits_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"listener.delete","name":"http1"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable when server not running, got {result:?}"
        );
    }

    // ── dispatch: operator commands ───────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_operator_list_hits_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"operator.list"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_operator_create_without_username_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"operator.create","password":"p","role":"operator"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when username missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_operator_create_without_password_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(
            r#"{"cmd":"operator.create","username":"alice","role":"operator"}"#,
        )
        .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when password missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_operator_create_without_role_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"operator.create","username":"alice","password":"p"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when role missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_operator_create_with_bad_role_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(
            r#"{"cmd":"operator.create","username":"alice","password":"p","role":"superuser"}"#,
        )
        .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs for unknown role, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_operator_delete_without_username_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"operator.delete"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when username missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_operator_set_role_without_username_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"operator.set-role","role":"admin"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when username missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_operator_set_role_without_role_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"operator.set-role","username":"alice"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when role missing, got {result:?}"
        );
    }

    // ── dispatch: payload commands ────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_payload_list_hits_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"payload.list"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_payload_build_without_listener_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"payload.build","arch":"x86_64","format":"exe"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when listener missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_payload_build_without_arch_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"payload.build","listener":"http1","format":"exe"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when arch missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_payload_build_without_format_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"payload.build","listener":"http1","arch":"x86_64"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when format missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_payload_build_with_bad_format_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(
            r#"{"cmd":"payload.build","listener":"http1","arch":"x86_64","format":"zip"}"#,
        )
        .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs for unknown format, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_payload_download_without_id_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"payload.download","dst":"/tmp/out.exe"}"#)
                .expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when id missing, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_payload_download_without_dst_returns_invalid_args() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd =
            serde_json::from_str(r#"{"cmd":"payload.download","id":"abc123"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::InvalidArgs(_))),
            "expected InvalidArgs when dst missing, got {result:?}"
        );
    }

    // ── dispatch: log commands ────────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_log_list_hits_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"log.list"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_log_tail_hits_server() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let msg: SessionCmd = serde_json::from_str(r#"{"cmd":"log.tail"}"#).expect("parse");
        let result = dispatch(&client, &msg, None).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got {result:?}"
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
    /// Build a minimal `ApiAgentInfo`-shaped JSON value (PascalCase fields).
    ///
    /// `active` should be `false` to simulate a dead agent (status="dead")
    /// and `true` for a live agent (status="alive").
    fn raw_agent_json(active: bool) -> serde_json::Value {
        serde_json::json!({
            "AgentID": 1,
            "Hostname": "host1",
            "Username": "user1",
            "DomainName": "LAB",
            "ExternalIP": "1.2.3.4",
            "InternalIP": "10.0.0.1",
            "ProcessName": "demon.exe",
            "ProcessPath": "C:\\demon.exe",
            "BaseAddress": 0,
            "ProcessPID": 1000,
            "ProcessTID": 1001,
            "ProcessPPID": 500,
            "ProcessArch": "x64",
            "Elevated": false,
            "OSVersion": "Linux",
            "OSBuild": 0,
            "OSArch": "x64",
            "SleepDelay": 5,
            "SleepJitter": 10,
            "KillDate": null,
            "WorkingHours": null,
            "FirstCallIn": "2026-01-01T00:00:00Z",
            "LastCallIn": "2026-01-01T00:00:00Z",
            "Active": active,
            "Reason": "http",
            "Note": ""
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

    /// `exec wait=true` — submits the task then fails because the server is
    /// unreachable.
    #[tokio::test]
    async fn exec_wait_true_returns_server_unreachable() {
        use crate::config::ResolvedConfig;
        let cfg = ResolvedConfig {
            server: "https://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("build client");
        let result = exec(&client, "agent1", "whoami", true, 60).await;

        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "exec wait=true must return ServerUnreachable against no server, got {result:?}"
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
            .respond_with(ResponseTemplate::new(200).set_body_json(raw_agent_json(false)))
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
