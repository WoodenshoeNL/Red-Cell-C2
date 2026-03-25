//! `red-cell-cli agent` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `agent list` | `GET /agents` | table of all agents |
//! | `agent show <id>` | `GET /agents/{id}` | full agent record |
//! | `agent exec <id> --cmd <cmd>` | `POST /agents/{id}/task` | submit task |
//! | `agent exec --wait` | **unsupported** — REST API lacks output endpoint | returns exit 6 |
//! | `agent output <id>` | **unsupported** — REST API lacks output endpoint | returns exit 6 |
//! | `agent kill <id>` | `DELETE /agents/{id}` | terminate |
//! | `agent kill --wait` | kill then poll `GET /agents/{id}` until dead | block |
//! | `agent upload <id>` | **unsupported** — REST API lacks endpoint | returns exit 6 |
//! | `agent download <id>` | **unsupported** — REST API lacks endpoint | returns exit 6 |

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::instrument;

use crate::AgentCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};

/// Default polling timeout for `--wait` operations, in seconds.
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 60;
/// Polling interval for `--wait` and `--watch` operations.
const POLL_INTERVAL: Duration = Duration::from_millis(1_000);

// ── raw API response shapes ───────────────────────────────────────────────────

/// Wire format returned by `GET /agents` and `GET /agents/{id}`.
///
/// Field names and types mirror `ApiAgentInfo` in the teamserver
/// (`teamserver/src/api.rs`) exactly so that serde can deserialise the
/// server response without loss of data.  All PascalCase renames match
/// the `#[serde(rename = "…")]` attributes on `ApiAgentInfo`.
///
/// Some fields are captured here for schema completeness but are not
/// forwarded to `RawAgent` — they are required by serde for a
/// successful deserialisation and are intentionally unused afterwards.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiAgentWire {
    #[serde(rename = "AgentID")]
    agent_id: u32,
    #[serde(rename = "Active")]
    active: bool,
    #[serde(rename = "Reason")]
    reason: String,
    #[serde(rename = "Note")]
    note: String,
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "DomainName")]
    domain_name: String,
    #[serde(rename = "ExternalIP")]
    external_ip: String,
    #[serde(rename = "InternalIP")]
    internal_ip: String,
    #[serde(rename = "ProcessName")]
    process_name: String,
    #[serde(rename = "BaseAddress")]
    base_address: u64,
    #[serde(rename = "ProcessPID")]
    process_pid: u32,
    #[serde(rename = "ProcessTID")]
    process_tid: u32,
    #[serde(rename = "ProcessPPID")]
    process_ppid: u32,
    #[serde(rename = "ProcessArch")]
    process_arch: String,
    #[serde(rename = "Elevated")]
    elevated: bool,
    #[serde(rename = "OSVersion")]
    os_version: String,
    #[serde(rename = "OSBuild")]
    os_build: u32,
    #[serde(rename = "OSArch")]
    os_arch: String,
    #[serde(rename = "SleepDelay")]
    sleep_delay: u32,
    #[serde(rename = "SleepJitter")]
    sleep_jitter: u32,
    #[serde(rename = "KillDate")]
    kill_date: Option<i64>,
    #[serde(rename = "WorkingHours")]
    working_hours: Option<i32>,
    #[serde(rename = "FirstCallIn")]
    first_call_in: String,
    #[serde(rename = "LastCallIn")]
    last_call_in: String,
}

/// Normalised agent record used throughout the CLI.
///
/// The teamserver returns agent data as `ApiAgentInfo` (PascalCase fields).
/// `RawAgent` is populated from the wire format via `#[serde(from =
/// "ApiAgentWire")]` — all deserialization goes through `ApiAgentWire` and
/// the `From` impl below converts PascalCase fields and derives computed
/// values (`id` as hex string, `os` as combined version+arch, `status` from
/// the `Active` boolean).
#[derive(Debug, Deserialize, Serialize)]
#[serde(from = "ApiAgentWire")]
pub(crate) struct RawAgent {
    /// Agent identifier as an uppercase hex string, e.g. `"DEADBEEF"`.
    pub(crate) id: String,
    pub(crate) hostname: String,
    /// Combined OS string, e.g. `"Windows 11 x64"`.
    pub(crate) os: String,
    /// RFC 3339 timestamp of the agent's last check-in (`LastCallIn`).
    pub(crate) last_seen: String,
    /// RFC 3339 timestamp of the agent's first check-in (`FirstCallIn`).
    pub(crate) first_seen: String,
    /// `"alive"` when `Active == true`, `"dead"` otherwise.
    pub(crate) status: String,
    pub(crate) arch: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) external_ip: Option<String>,
    pub(crate) internal_ip: Option<String>,
    pub(crate) process_name: Option<String>,
    pub(crate) pid: Option<u64>,
    pub(crate) elevated: Option<bool>,
    pub(crate) sleep_interval: Option<u64>,
    pub(crate) jitter: Option<u64>,
}

impl From<ApiAgentWire> for RawAgent {
    fn from(w: ApiAgentWire) -> Self {
        Self {
            id: format!("{:08X}", w.agent_id),
            hostname: w.hostname,
            os: format!("{} {}", w.os_version, w.os_arch),
            last_seen: w.last_call_in,
            first_seen: w.first_call_in,
            status: if w.active { "alive".to_owned() } else { "dead".to_owned() },
            arch: Some(w.process_arch),
            username: Some(w.username),
            domain: Some(w.domain_name),
            external_ip: Some(w.external_ip),
            internal_ip: Some(w.internal_ip),
            process_name: Some(w.process_name),
            pid: Some(w.process_pid as u64),
            elevated: Some(w.elevated),
            sleep_interval: Some(w.sleep_delay as u64),
            jitter: Some(w.sleep_jitter as u64),
        }
    }
}

/// Response from `POST /agents/{id}/task` and `DELETE /agents/{id}`.
#[derive(Debug, Deserialize)]
pub(crate) struct TaskQueuedResponse {
    pub(crate) task_id: String,
}

/// Minimal projection of the `GET /jobs` paged response used for polling.
///
/// Currently unused because `exec_wait` returns `Unsupported`, but retained
/// for when the teamserver adds a command-output REST endpoint.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct JobPageResponse {
    pub(crate) total: usize,
}

// ── public output types ───────────────────────────────────────────────────────

/// Summary row returned by `agent list`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentSummary {
    /// Unique agent identifier.
    pub id: String,
    /// Hostname of the compromised host.
    pub hostname: String,
    /// Operating system (e.g. `"Windows 10 x64"`).
    pub os: String,
    /// RFC 3339 timestamp of the agent's last check-in.
    pub last_seen: String,
    /// Liveness status: `"alive"` or `"dead"`.
    pub status: String,
}

impl TextRow for AgentSummary {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "Hostname", "OS", "Last Seen", "Status"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.hostname.clone(),
            self.os.clone(),
            self.last_seen.clone(),
            self.status.clone(),
        ]
    }
}

/// Full agent record returned by `agent show`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentDetail {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub arch: Option<String>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub external_ip: Option<String>,
    pub internal_ip: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u64>,
    pub elevated: Option<bool>,
    pub first_seen: String,
    pub last_seen: String,
    pub status: String,
    pub sleep_interval: Option<u64>,
    pub jitter: Option<u64>,
}

impl TextRender for AgentDetail {
    fn render_text(&self) -> String {
        use comfy_table::{Cell, ContentArrangement, Table};
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header([Cell::new("Field"), Cell::new("Value")]);
        let rows: &[(&str, String)] = &[
            ("id", self.id.clone()),
            ("hostname", self.hostname.clone()),
            ("os", self.os.clone()),
            ("arch", self.arch.clone().unwrap_or_default()),
            ("username", self.username.clone().unwrap_or_default()),
            ("domain", self.domain.clone().unwrap_or_default()),
            ("external_ip", self.external_ip.clone().unwrap_or_default()),
            ("internal_ip", self.internal_ip.clone().unwrap_or_default()),
            ("process_name", self.process_name.clone().unwrap_or_default()),
            ("pid", self.pid.map_or_else(String::new, |p| p.to_string())),
            ("elevated", self.elevated.map_or_else(String::new, |e| e.to_string())),
            ("first_seen", self.first_seen.clone()),
            ("last_seen", self.last_seen.clone()),
            ("status", self.status.clone()),
            ("sleep_interval", self.sleep_interval.map_or_else(String::new, |s| s.to_string())),
            ("jitter", self.jitter.map_or_else(String::new, |j| j.to_string())),
        ];
        for (field, val) in rows {
            table.add_row([Cell::new(*field), Cell::new(val)]);
        }
        table.to_string()
    }
}

/// Result of `agent exec` without `--wait`.
#[derive(Debug, Clone, Serialize)]
pub struct JobSubmitted {
    /// Identifier for the queued job.
    pub job_id: String,
}

impl TextRender for JobSubmitted {
    fn render_text(&self) -> String {
        format!("Job submitted: {}", self.job_id)
    }
}

/// Result of `agent exec --wait`.
#[derive(Debug, Clone, Serialize)]
pub struct ExecResult {
    pub job_id: String,
    pub output: String,
    pub exit_code: Option<i32>,
}

impl TextRender for ExecResult {
    fn render_text(&self) -> String {
        let code = self.exit_code.map_or_else(|| "?".to_owned(), |c| c.to_string());
        format!("[job {}  exit {}]\n{}", self.job_id, code, self.output)
    }
}

/// Single output entry returned by `agent output`.
#[derive(Debug, Clone, Serialize)]
pub struct OutputEntry {
    pub job_id: String,
    pub command: Option<String>,
    pub output: String,
    pub exit_code: Option<i32>,
    pub created_at: String,
}

impl TextRow for OutputEntry {
    fn headers() -> Vec<&'static str> {
        vec!["Job ID", "Command", "Exit", "Created At", "Output"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.job_id.clone(),
            self.command.clone().unwrap_or_default(),
            self.exit_code.map_or_else(String::new, |c| c.to_string()),
            self.created_at.clone(),
            // Truncate long output in table mode.
            self.output.chars().take(80).collect(),
        ]
    }
}

/// Result of `agent kill`.
#[derive(Debug, Clone, Serialize)]
pub struct KillResult {
    pub agent_id: String,
    pub status: String,
}

impl TextRender for KillResult {
    fn render_text(&self) -> String {
        format!("Agent {}  status: {}", self.agent_id, self.status)
    }
}

/// Result of `agent upload` and `agent download`.
#[derive(Debug, Clone, Serialize)]
pub struct TransferResult {
    pub agent_id: String,
    pub job_id: Option<String>,
    pub local_path: String,
    pub remote_path: String,
}

impl TextRender for TransferResult {
    fn render_text(&self) -> String {
        match &self.job_id {
            Some(jid) => format!(
                "Transfer job {jid}  agent: {}  remote: {}  local: {}",
                self.agent_id, self.remote_path, self.local_path
            ),
            None => format!(
                "Transfer complete  agent: {}  remote: {}  local: {}",
                self.agent_id, self.remote_path, self.local_path
            ),
        }
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch an [`AgentCommands`] variant and return a process exit code.
///
/// All output (success and error) is written inside this function so that the
/// caller in `main.rs` only needs to propagate the exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: AgentCommands) -> i32 {
    match action {
        AgentCommands::List => match list(client).await {
            Ok(data) => {
                print_success(fmt, &data);
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
                e.exit_code()
            }
        },

        AgentCommands::Show { id } => match show(client, &id).await {
            Ok(data) => {
                print_success(fmt, &data);
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
                e.exit_code()
            }
        },

        AgentCommands::Exec { id, cmd, wait, timeout } => {
            let timeout_secs = timeout.unwrap_or(DEFAULT_WAIT_TIMEOUT_SECS);
            if wait {
                match exec_wait(client, &id, &cmd, timeout_secs).await {
                    Ok(data) => {
                        print_success(fmt, &data);
                        EXIT_SUCCESS
                    }
                    Err(e) => {
                        print_error(&e);
                        e.exit_code()
                    }
                }
            } else {
                match exec_submit(client, &id, &cmd).await {
                    Ok(data) => {
                        print_success(fmt, &data);
                        EXIT_SUCCESS
                    }
                    Err(e) => {
                        print_error(&e);
                        e.exit_code()
                    }
                }
            }
        }

        AgentCommands::Output { id, watch, since } => {
            if watch {
                watch_output(client, fmt, &id, since.as_deref()).await
            } else {
                match fetch_output(client, &id, since.as_deref()).await {
                    Ok(data) => {
                        print_success(fmt, &data);
                        EXIT_SUCCESS
                    }
                    Err(e) => {
                        print_error(&e);
                        e.exit_code()
                    }
                }
            }
        }

        AgentCommands::Kill { id, wait } => match kill(client, &id, wait).await {
            Ok(data) => {
                print_success(fmt, &data);
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
                e.exit_code()
            }
        },

        AgentCommands::Upload { id, src, dst } => match upload(client, &id, &src, &dst).await {
            Ok(data) => {
                print_success(fmt, &data);
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
                e.exit_code()
            }
        },

        AgentCommands::Download { id, src, dst } => match download(client, &id, &src, &dst).await {
            Ok(data) => {
                print_success(fmt, &data);
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
                e.exit_code()
            }
        },
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// `agent list` — fetch all registered agents.
///
/// # Examples
/// ```text
/// red-cell-cli agent list
/// ```
#[instrument(skip(client))]
async fn list(client: &ApiClient) -> Result<Vec<AgentSummary>, CliError> {
    let raw: Vec<RawAgent> = client.get("/agents").await?;
    Ok(raw.into_iter().map(agent_summary_from_raw).collect())
}

/// `agent show <id>` — fetch full details of a single agent.
///
/// # Examples
/// ```text
/// red-cell-cli agent show abc123
/// ```
#[instrument(skip(client))]
async fn show(client: &ApiClient, id: &str) -> Result<AgentDetail, CliError> {
    let raw: RawAgent = client.get(&format!("/agents/{id}")).await?;
    Ok(agent_detail_from_raw(raw))
}

/// `agent exec <id> --cmd <cmd>` — submit a command task to an agent.
///
/// POSTs to `POST /agents/{id}/task` using the Demon `AgentTaskInfo` wire
/// format and returns immediately with the server-assigned task ID.
///
/// # Examples
/// ```text
/// red-cell-cli agent exec abc123 --cmd "whoami"
/// ```
#[instrument(skip(client))]
async fn exec_submit(client: &ApiClient, id: &str, cmd: &str) -> Result<JobSubmitted, CliError> {
    /// Minimal `AgentTaskInfo` projection — field names match the PascalCase
    /// serde renames on the canonical `red_cell_common::operator::AgentTaskInfo`
    /// struct so the server can deserialise them without modification.
    #[derive(Serialize)]
    struct Body<'a> {
        #[serde(rename = "CommandLine")]
        command_line: &'a str,
        /// Numeric demon command identifier as a decimal string.
        /// `21` = `DemonCommand::CommandJob` — the generic job/shell command.
        #[serde(rename = "CommandID")]
        command_id: &'static str,
        /// Target agent identifier (upper-hex).  The server normalises this
        /// value; an empty string is replaced with the path parameter.
        #[serde(rename = "DemonID")]
        demon_id: &'a str,
        /// Leave blank so the server generates a unique task identifier.
        #[serde(rename = "TaskID")]
        task_id: &'static str,
    }

    let resp: TaskQueuedResponse = client
        .post(
            &format!("/agents/{id}/task"),
            &Body { command_line: cmd, command_id: "21", demon_id: id, task_id: "" },
        )
        .await?;
    Ok(JobSubmitted { job_id: resp.task_id })
}

/// `agent exec <id> --cmd <cmd> --wait` — not yet supported.
///
/// The `--wait` flag promises to block until the agent completes the command
/// and return the output with an exit code.  The current REST API does not
/// expose a command-output endpoint, so this contract cannot be fulfilled.
/// Rather than returning a misleading success with `exit_code: null` and a
/// placeholder message, we return [`CliError::Unsupported`] so the caller
/// knows the feature is not yet available.
///
/// Use `agent exec` without `--wait` to submit the task, and
/// `red-cell-client` (the WebSocket GUI) to observe command output.
///
/// # Errors
///
/// Always returns [`CliError::Unsupported`].
#[instrument(skip(_client))]
async fn exec_wait(
    _client: &ApiClient,
    _id: &str,
    _cmd: &str,
    _timeout_secs: u64,
) -> Result<ExecResult, CliError> {
    Err(CliError::Unsupported(
        "exec --wait requires command-output retrieval which is not yet available via \
         the REST API; submit without --wait and use the WebSocket client (red-cell-client) \
         to observe output"
            .to_owned(),
    ))
}

/// `agent output <id>` — not yet supported via the REST API.
///
/// The teamserver does not expose a REST endpoint for agent callback output.
/// Connect with the WebSocket client (`red-cell-client`) to receive live
/// command output from agents.
///
/// # Errors
///
/// Always returns [`CliError::Unsupported`].
#[instrument(skip(_client))]
async fn fetch_output(
    _client: &ApiClient,
    _id: &str,
    _since: Option<&str>,
) -> Result<Vec<OutputEntry>, CliError> {
    Err(CliError::Unsupported(
        "agent output is not yet available via the REST API; \
         use the WebSocket client (red-cell-client) to receive command output"
            .to_owned(),
    ))
}

/// `agent output <id> --watch` — stream new output as JSON lines until Ctrl-C.
///
/// Polls every second and prints each new entry as an individual JSON line.
///
/// # Examples
/// ```text
/// red-cell-cli agent output abc123 --watch
/// red-cell-cli agent output abc123 --watch --since job_xyz
/// ```
async fn watch_output(
    client: &ApiClient,
    fmt: &OutputFormat,
    id: &str,
    since: Option<&str>,
) -> i32 {
    let mut cursor: Option<String> = since.map(ToOwned::to_owned);
    // Create the ctrl_c future once and pin it so we can reuse the same OS-level
    // signal listener across all loop iterations. Creating a new ctrl_c() future
    // on every iteration registers a new listener each time; after ~64 iterations
    // the Tokio global receiver capacity (128) can be exhausted.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        let poll_result = tokio::select! {
            result = fetch_output(client, id, cursor.as_deref()) => result,
            _ = &mut ctrl_c => {
                return EXIT_SUCCESS;
            }
        };

        match poll_result {
            Err(e) => {
                print_error(&e);
                return e.exit_code();
            }
            Ok(entries) => {
                for entry in &entries {
                    // Update cursor so next poll only fetches newer entries.
                    cursor = Some(entry.job_id.clone());
                    match fmt {
                        OutputFormat::Json => {
                            let line = serde_json::json!({"ok": true, "data": entry});
                            match serde_json::to_string(&line) {
                                Ok(s) => println!("{s}"),
                                Err(_) => println!(r#"{{"ok":true}}"#),
                            }
                        }
                        OutputFormat::Text => {
                            let code =
                                entry.exit_code.map_or_else(|| "?".to_owned(), |c| c.to_string());
                            println!("[{}  exit {}]  {}", entry.job_id, code, entry.output);
                        }
                    }
                }
            }
        }

        let sleep_fut = sleep(POLL_INTERVAL);
        tokio::select! {
            _ = sleep_fut => {}
            _ = &mut ctrl_c => {
                return EXIT_SUCCESS;
            }
        }
    }
}

/// `agent kill <id> [--wait]` — send terminate command to an agent.
///
/// Issues `DELETE /agents/{id}` which queues a [`DemonCommand::CommandExit`]
/// job on the server side.  With `--wait`, polls `GET /agents/{id}` until
/// `status == "dead"` or 60 s elapse.
///
/// # Examples
/// ```text
/// red-cell-cli agent kill abc123
/// red-cell-cli agent kill abc123 --wait
/// ```
#[instrument(skip(client))]
async fn kill(client: &ApiClient, id: &str, wait: bool) -> Result<KillResult, CliError> {
    client.delete_no_body(&format!("/agents/{id}")).await?;

    if !wait {
        return Ok(KillResult { agent_id: id.to_owned(), status: "kill_sent".to_owned() });
    }

    let deadline = Instant::now() + Duration::from_secs(DEFAULT_WAIT_TIMEOUT_SECS);

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for agent {id} to die after {}s",
                DEFAULT_WAIT_TIMEOUT_SECS
            )));
        }

        let raw: RawAgent = client.get(&format!("/agents/{id}")).await?;
        if raw.status == "dead" {
            return Ok(KillResult { agent_id: id.to_owned(), status: raw.status });
        }

        sleep(POLL_INTERVAL).await;
    }
}

/// `agent upload <id> --src <local> --dst <remote>` — not yet supported via
/// the REST API.
///
/// File upload to an agent is not exposed as a REST endpoint in the current
/// teamserver.  Use the interactive WebSocket client (`red-cell-client`) for
/// file transfers.
///
/// # Errors
///
/// Always returns [`CliError::Unsupported`].
#[instrument(skip(_client))]
async fn upload(
    _client: &ApiClient,
    _id: &str,
    _src: &str,
    _dst: &str,
) -> Result<TransferResult, CliError> {
    Err(CliError::Unsupported(
        "file upload is not yet supported via the REST API; \
         use the WebSocket client (red-cell-client) for file transfers"
            .to_owned(),
    ))
}

/// `agent download <id> --src <remote> --dst <local>` — not yet supported via
/// the REST API.
///
/// File download from an agent is not exposed as a REST endpoint in the current
/// teamserver.  Use the interactive WebSocket client (`red-cell-client`) for
/// file transfers.
///
/// # Errors
///
/// Always returns [`CliError::Unsupported`].
#[instrument(skip(_client))]
async fn download(
    _client: &ApiClient,
    _id: &str,
    _src: &str,
    _dst: &str,
) -> Result<TransferResult, CliError> {
    Err(CliError::Unsupported(
        "file download is not yet supported via the REST API; \
         use the WebSocket client (red-cell-client) for file transfers"
            .to_owned(),
    ))
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn agent_summary_from_raw(r: RawAgent) -> AgentSummary {
    AgentSummary {
        id: r.id,
        hostname: r.hostname,
        os: r.os,
        last_seen: r.last_seen,
        status: r.status,
    }
}

fn agent_detail_from_raw(r: RawAgent) -> AgentDetail {
    AgentDetail {
        id: r.id,
        hostname: r.hostname,
        os: r.os,
        arch: r.arch,
        username: r.username,
        domain: r.domain,
        external_ip: r.external_ip,
        internal_ip: r.internal_ip,
        process_name: r.process_name,
        pid: r.pid,
        elevated: r.elevated,
        first_seen: r.first_seen,
        last_seen: r.last_seen,
        status: r.status,
        sleep_interval: r.sleep_interval,
        jitter: r.jitter,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AgentSummary ──────────────────────────────────────────────────────────

    #[test]
    fn agent_summary_serialises_required_fields() {
        let s = AgentSummary {
            id: "abc".to_owned(),
            hostname: "WIN10".to_owned(),
            os: "Windows 10".to_owned(),
            last_seen: "2026-01-01T00:00:00Z".to_owned(),
            status: "alive".to_owned(),
        };
        let v = serde_json::to_value(&s).expect("serialise");
        assert_eq!(v["id"], "abc");
        assert_eq!(v["hostname"], "WIN10");
        assert_eq!(v["status"], "alive");
    }

    #[test]
    fn agent_summary_text_row_headers_match_row_length() {
        let s = AgentSummary {
            id: "x".to_owned(),
            hostname: "h".to_owned(),
            os: "linux".to_owned(),
            last_seen: "t".to_owned(),
            status: "alive".to_owned(),
        };
        assert_eq!(AgentSummary::headers().len(), s.row().len());
    }

    #[test]
    fn vec_agent_summary_renders_table() {
        let items = vec![AgentSummary {
            id: "abc".to_owned(),
            hostname: "WIN10".to_owned(),
            os: "Windows 10".to_owned(),
            last_seen: "2026-01-01T00:00:00Z".to_owned(),
            status: "alive".to_owned(),
        }];
        let rendered = items.render_text();
        assert!(rendered.contains("abc"));
        assert!(rendered.contains("WIN10"));
        assert!(rendered.contains("alive"));
    }

    // ── AgentDetail ───────────────────────────────────────────────────────────

    #[test]
    fn agent_detail_serialises_optional_fields_as_null() {
        let d = AgentDetail {
            id: "x".to_owned(),
            hostname: "h".to_owned(),
            os: "linux".to_owned(),
            arch: None,
            username: None,
            domain: None,
            external_ip: None,
            internal_ip: None,
            process_name: None,
            pid: None,
            elevated: None,
            first_seen: "t0".to_owned(),
            last_seen: "t".to_owned(),
            status: "alive".to_owned(),
            sleep_interval: None,
            jitter: None,
        };
        let v = serde_json::to_value(&d).expect("serialise");
        assert!(v["arch"].is_null());
        assert!(v["pid"].is_null());
        assert!(v["external_ip"].is_null());
        assert!(v["elevated"].is_null());
    }

    #[test]
    fn agent_detail_render_text_contains_key_fields() {
        let d = AgentDetail {
            id: "abc123".to_owned(),
            hostname: "myhost".to_owned(),
            os: "Windows".to_owned(),
            arch: Some("x86_64".to_owned()),
            username: Some("DOMAIN\\alice".to_owned()),
            domain: Some("CORP".to_owned()),
            external_ip: Some("203.0.113.1".to_owned()),
            internal_ip: Some("10.0.0.1".to_owned()),
            process_name: Some("svchost.exe".to_owned()),
            pid: Some(1234),
            elevated: Some(true),
            first_seen: "2026-01-01T00:00:00Z".to_owned(),
            last_seen: "2026-01-02T00:00:00Z".to_owned(),
            status: "alive".to_owned(),
            sleep_interval: Some(60),
            jitter: Some(10),
        };
        let rendered = d.render_text();
        assert!(rendered.contains("abc123"));
        assert!(rendered.contains("myhost"));
        assert!(rendered.contains("x86_64"));
        assert!(rendered.contains("1234"));
        assert!(rendered.contains("203.0.113.1"));
        assert!(rendered.contains("true"));
    }

    // ── JobSubmitted ──────────────────────────────────────────────────────────

    #[test]
    fn job_submitted_serialises_job_id() {
        let j = JobSubmitted { job_id: "job_abc".to_owned() };
        let v = serde_json::to_value(&j).expect("serialise");
        assert_eq!(v["job_id"], "job_abc");
    }

    #[test]
    fn job_submitted_render_text_contains_job_id() {
        let j = JobSubmitted { job_id: "job_abc".to_owned() };
        assert!(j.render_text().contains("job_abc"));
    }

    // ── ExecResult ────────────────────────────────────────────────────────────

    #[test]
    fn exec_result_serialises_all_fields() {
        let r =
            ExecResult { job_id: "j1".to_owned(), output: "root\n".to_owned(), exit_code: Some(0) };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["job_id"], "j1");
        assert_eq!(v["output"], "root\n");
        assert_eq!(v["exit_code"], 0);
    }

    #[test]
    fn exec_result_render_text_contains_output_and_exit() {
        let r =
            ExecResult { job_id: "j1".to_owned(), output: "root\n".to_owned(), exit_code: Some(0) };
        let rendered = r.render_text();
        assert!(rendered.contains("root"));
        assert!(rendered.contains('0'));
    }

    // ── OutputEntry ───────────────────────────────────────────────────────────

    #[test]
    fn output_entry_text_row_headers_match_row_length() {
        let e = OutputEntry {
            job_id: "j".to_owned(),
            command: None,
            output: "out".to_owned(),
            exit_code: Some(0),
            created_at: "t".to_owned(),
        };
        assert_eq!(OutputEntry::headers().len(), e.row().len());
    }

    #[test]
    fn output_entry_row_79_chars_not_truncated() {
        let output: String = "x".repeat(79);
        let e = OutputEntry {
            job_id: "j".to_owned(),
            command: None,
            output: output.clone(),
            exit_code: None,
            created_at: "t".to_owned(),
        };
        let row = e.row();
        assert_eq!(row[4], output);
        assert_eq!(row[4].chars().count(), 79);
    }

    #[test]
    fn output_entry_row_80_chars_not_truncated() {
        let output: String = "x".repeat(80);
        let e = OutputEntry {
            job_id: "j".to_owned(),
            command: None,
            output: output.clone(),
            exit_code: None,
            created_at: "t".to_owned(),
        };
        let row = e.row();
        assert_eq!(row[4], output);
        assert_eq!(row[4].chars().count(), 80);
    }

    #[test]
    fn output_entry_row_81_chars_truncated_to_80() {
        let output: String = "x".repeat(81);
        let e = OutputEntry {
            job_id: "j".to_owned(),
            command: None,
            output,
            exit_code: None,
            created_at: "t".to_owned(),
        };
        let row = e.row();
        assert_eq!(row[4].chars().count(), 80);
        assert_eq!(row[4], "x".repeat(80));
    }

    #[test]
    fn output_entry_row_truncation_counts_unicode_chars_not_bytes() {
        // Each 'é' is 2 bytes but 1 Unicode scalar value.
        // 81 such chars should be truncated to 80 chars (not 80 bytes).
        let output: String = "é".repeat(81);
        let e = OutputEntry {
            job_id: "j".to_owned(),
            command: None,
            output,
            exit_code: None,
            created_at: "t".to_owned(),
        };
        let row = e.row();
        assert_eq!(row[4].chars().count(), 80);
        assert_eq!(row[4], "é".repeat(80));
    }

    // ── KillResult ────────────────────────────────────────────────────────────

    #[test]
    fn kill_result_render_text_contains_id_and_status() {
        let k = KillResult { agent_id: "abc".to_owned(), status: "dead".to_owned() };
        let rendered = k.render_text();
        assert!(rendered.contains("abc"));
        assert!(rendered.contains("dead"));
    }

    // ── TransferResult ────────────────────────────────────────────────────────

    #[test]
    fn transfer_result_upload_render_contains_job_id() {
        let t = TransferResult {
            agent_id: "abc".to_owned(),
            job_id: Some("j1".to_owned()),
            local_path: "/tmp/f".to_owned(),
            remote_path: "C:\\f".to_owned(),
        };
        assert!(t.render_text().contains("j1"));
    }

    #[test]
    fn transfer_result_download_render_no_job_id() {
        let t = TransferResult {
            agent_id: "abc".to_owned(),
            job_id: None,
            local_path: "/tmp/f".to_owned(),
            remote_path: "/etc/passwd".to_owned(),
        };
        let rendered = t.render_text();
        assert!(rendered.contains("complete"));
        assert!(rendered.contains("/etc/passwd"));
    }

    // ── from_raw helpers ──────────────────────────────────────────────────────

    #[test]
    fn agent_summary_from_raw_maps_all_fields() {
        let raw = RawAgent {
            id: "id1".to_owned(),
            hostname: "host".to_owned(),
            os: "linux".to_owned(),
            last_seen: "ts".to_owned(),
            first_seen: "ts0".to_owned(),
            status: "alive".to_owned(),
            arch: None,
            username: None,
            domain: None,
            external_ip: None,
            internal_ip: None,
            process_name: None,
            pid: None,
            elevated: None,
            sleep_interval: None,
            jitter: None,
        };
        let s = agent_summary_from_raw(raw);
        assert_eq!(s.id, "id1");
        assert_eq!(s.hostname, "host");
        assert_eq!(s.status, "alive");
    }

    #[test]
    fn agent_detail_from_raw_preserves_optional_fields() {
        let raw = RawAgent {
            id: "id2".to_owned(),
            hostname: "h".to_owned(),
            os: "win".to_owned(),
            last_seen: "t".to_owned(),
            first_seen: "t0".to_owned(),
            status: "dead".to_owned(),
            arch: Some("x86".to_owned()),
            username: Some("user".to_owned()),
            domain: None,
            external_ip: Some("1.2.3.4".to_owned()),
            internal_ip: None,
            process_name: None,
            pid: Some(42),
            elevated: Some(false),
            sleep_interval: Some(30),
            jitter: None,
        };
        let d = agent_detail_from_raw(raw);
        assert_eq!(d.arch, Some("x86".to_owned()));
        assert_eq!(d.pid, Some(42));
        assert_eq!(d.domain, None);
        assert_eq!(d.external_ip, Some("1.2.3.4".to_owned()));
        assert_eq!(d.elevated, Some(false));
    }

    // ── ApiAgentWire deserialization (matches real ApiAgentInfo schema) ───────

    /// Full `ApiAgentInfo`-shaped JSON (as the teamserver serialises it)
    /// deserialized into `RawAgent` via `ApiAgentWire`.  Field names are
    /// PascalCase to match `ApiAgentInfo`'s `#[serde(rename)]` attributes.
    #[test]
    fn api_agent_wire_deserialises_full_api_agent_info_payload() {
        let json = serde_json::json!({
            "AgentID":      3735928559u32,  // 0xDEADBEEF
            "Active":       true,
            "Reason":       "http",
            "Note":         "",
            "Hostname":     "WORKSTATION01",
            "Username":     "CORP\\alice",
            "DomainName":   "CORP",
            "ExternalIP":   "203.0.113.10",
            "InternalIP":   "10.0.0.10",
            "ProcessName":  "demon.exe",
            "BaseAddress":  0x1400_0000u64,
            "ProcessPID":   4444u32,
            "ProcessTID":   4445u32,
            "ProcessPPID":  1000u32,
            "ProcessArch":  "x64",
            "Elevated":     true,
            "OSVersion":    "Windows 11",
            "OSBuild":      22000u32,
            "OSArch":       "x64",
            "SleepDelay":   5u32,
            "SleepJitter":  10u32,
            "KillDate":     null,
            "WorkingHours": null,
            "FirstCallIn":  "2026-03-01T00:00:00Z",
            "LastCallIn":   "2026-03-01T00:05:00Z"
        });

        let raw: RawAgent = serde_json::from_value(json).expect("deserialise RawAgent");

        assert_eq!(raw.id, "DEADBEEF");
        assert_eq!(raw.hostname, "WORKSTATION01");
        assert_eq!(raw.os, "Windows 11 x64");
        assert_eq!(raw.last_seen, "2026-03-01T00:05:00Z");
        assert_eq!(raw.first_seen, "2026-03-01T00:00:00Z");
        assert_eq!(raw.status, "alive");
        assert_eq!(raw.username, Some("CORP\\alice".to_owned()));
        assert_eq!(raw.domain, Some("CORP".to_owned()));
        assert_eq!(raw.external_ip, Some("203.0.113.10".to_owned()));
        assert_eq!(raw.internal_ip, Some("10.0.0.10".to_owned()));
        assert_eq!(raw.process_name, Some("demon.exe".to_owned()));
        assert_eq!(raw.pid, Some(4444));
        assert_eq!(raw.elevated, Some(true));
        assert_eq!(raw.sleep_interval, Some(5));
        assert_eq!(raw.jitter, Some(10));
    }

    /// Inactive agent (`Active = false`) maps to `status = "dead"`.
    #[test]
    fn api_agent_wire_inactive_agent_maps_status_to_dead() {
        let json = serde_json::json!({
            "AgentID":      1u32,
            "Active":       false,
            "Reason":       "killed",
            "Note":         "",
            "Hostname":     "HOST",
            "Username":     "user",
            "DomainName":   ".",
            "ExternalIP":   "1.2.3.4",
            "InternalIP":   "10.0.0.1",
            "ProcessName":  "a.exe",
            "BaseAddress":  0u64,
            "ProcessPID":   100u32,
            "ProcessTID":   101u32,
            "ProcessPPID":  1u32,
            "ProcessArch":  "x86",
            "Elevated":     false,
            "OSVersion":    "Windows 10",
            "OSBuild":      19045u32,
            "OSArch":       "x64",
            "SleepDelay":   60u32,
            "SleepJitter":  0u32,
            "KillDate":     null,
            "WorkingHours": null,
            "FirstCallIn":  "2026-01-01T00:00:00Z",
            "LastCallIn":   "2026-01-02T00:00:00Z"
        });

        let raw: RawAgent = serde_json::from_value(json).expect("deserialise");
        assert_eq!(raw.status, "dead");
        assert_eq!(raw.id, "00000001");
        assert_eq!(raw.os, "Windows 10 x64");
    }

    /// `Vec<RawAgent>` (the list-endpoint shape) deserializes from a JSON
    /// array of `ApiAgentInfo` objects.
    #[test]
    fn api_agent_wire_vec_deserialises_list_endpoint_shape() {
        let json = serde_json::json!([{
            "AgentID":      1u32,
            "Active":       true,
            "Reason":       "http",
            "Note":         "",
            "Hostname":     "HOST-A",
            "Username":     "admin",
            "DomainName":   "LAB",
            "ExternalIP":   "5.6.7.8",
            "InternalIP":   "192.168.1.1",
            "ProcessName":  "b.exe",
            "BaseAddress":  0u64,
            "ProcessPID":   200u32,
            "ProcessTID":   201u32,
            "ProcessPPID":  2u32,
            "ProcessArch":  "x64",
            "Elevated":     false,
            "OSVersion":    "Windows Server 2022",
            "OSBuild":      20348u32,
            "OSArch":       "x64",
            "SleepDelay":   30u32,
            "SleepJitter":  5u32,
            "KillDate":     null,
            "WorkingHours": null,
            "FirstCallIn":  "2026-02-01T00:00:00Z",
            "LastCallIn":   "2026-02-01T00:01:00Z"
        }]);

        let agents: Vec<RawAgent> = serde_json::from_value(json).expect("deserialise list");
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].hostname, "HOST-A");
        assert_eq!(agents[0].status, "alive");
        assert_eq!(agents[0].os, "Windows Server 2022 x64");
    }

    // ── exec_wait / fetch_output / watch_output ────────────────────────────────

    /// Build a `ResolvedConfig` pointing at the given mock server URI.
    fn mock_cfg(server_uri: &str) -> crate::config::ResolvedConfig {
        crate::config::ResolvedConfig {
            server: server_uri.to_owned(),
            token: "test-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        }
    }

    /// `exec_wait` always returns `CliError::Unsupported` because command
    /// output retrieval is not available via the REST API.
    #[tokio::test]
    async fn exec_wait_returns_unsupported() {
        let cfg = mock_cfg("http://127.0.0.1:1");
        let client = crate::client::ApiClient::new(&cfg).expect("build client");
        let result = exec_wait(&client, "agent1", "whoami", 30).await;
        assert!(
            matches!(result, Err(crate::error::CliError::Unsupported(_))),
            "exec_wait must return CliError::Unsupported; got: {result:?}"
        );
    }

    /// `fetch_output` always returns a `CliError::Unsupported` because the REST
    /// API does not expose an agent output endpoint.
    #[tokio::test]
    async fn fetch_output_returns_unsupported_error() {
        let cfg = mock_cfg("http://127.0.0.1:1");
        let client = crate::client::ApiClient::new(&cfg).expect("build client");
        let result = fetch_output(&client, "agent1", None).await;
        assert!(
            matches!(result, Err(crate::error::CliError::Unsupported(_))),
            "fetch_output must return CliError::Unsupported; got: {result:?}"
        );
    }

    /// `fetch_output` with a `since` cursor also returns `CliError::Unsupported` —
    /// the cursor value makes no difference when the endpoint does not exist.
    #[tokio::test]
    async fn fetch_output_with_since_cursor_also_returns_unsupported() {
        let cfg = mock_cfg("http://127.0.0.1:1");
        let client = crate::client::ApiClient::new(&cfg).expect("build client");
        let result = fetch_output(&client, "agent1", Some("cursor-job")).await;
        assert!(
            matches!(result, Err(crate::error::CliError::Unsupported(_))),
            "fetch_output with cursor must still return CliError::Unsupported; got: {result:?}"
        );
    }

    /// `watch_output` exits immediately with a non-zero code because the first
    /// call to `fetch_output` returns a `CliError::Unsupported`.
    #[tokio::test]
    async fn watch_output_exits_immediately_with_error() {
        let cfg = mock_cfg("http://127.0.0.1:1");
        let client = crate::client::ApiClient::new(&cfg).expect("build client");

        let exit_code =
            watch_output(&client, &crate::output::OutputFormat::Json, "agent1", None).await;
        assert_eq!(
            exit_code,
            crate::error::EXIT_UNSUPPORTED,
            "watch_output must exit with EXIT_UNSUPPORTED"
        );
    }
}
