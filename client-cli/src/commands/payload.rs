//! `red-cell-cli payload` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `payload list` | `GET /payloads` | table of all built payloads |
//! | `payload build` | `POST /payloads/build` | submit build job; `--wait` polls until done |
//! | `payload download <id>` | `GET /payloads/{id}/download` | saves raw bytes to disk |
//! | `payload cache-flush` | `POST /payload-cache` | flush all cached build artifacts (admin) |

use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::instrument;

use crate::PayloadCommands;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::PAYLOAD_BUILD_WAIT_TIMEOUT_SECS;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};
/// Default sleep duration (seconds) when the server returns HTTP 429 without
/// a `Retry-After` header.
const RATE_LIMIT_DEFAULT_WAIT_SECS: u64 = 10;

// ── raw API response shapes ───────────────────────────────────────────────────

/// The server also sends `size_bytes` which is silently ignored by serde.
#[derive(Debug, Deserialize)]
struct RawPayloadSummary {
    id: String,
    name: String,
    arch: String,
    format: String,
    built_at: String,
}

#[derive(Debug, Deserialize)]
struct BuildSubmitResponse {
    job_id: String,
}

#[derive(Debug, Deserialize)]
struct BuildJobStatus {
    job_id: String,
    /// `"pending"` | `"running"` | `"done"` | `"error"`
    status: String,
    agent_type: Option<String>,
    payload_id: Option<String>,
    size_bytes: Option<u64>,
    error: Option<String>,
}

// ── public output types ───────────────────────────────────────────────────────

/// Summary row returned by `payload list`.
#[derive(Debug, Clone, Serialize)]
pub struct PayloadRow {
    /// Unique payload identifier.
    pub id: String,
    /// Display name of the payload.
    pub name: String,
    /// Target CPU architecture (e.g. `"x86_64"`).
    pub arch: String,
    /// File format: `"exe"`, `"dll"`, or `"bin"`.
    pub format: String,
    /// RFC 3339 build timestamp.
    pub built_at: String,
}

impl TextRow for PayloadRow {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "Name", "Arch", "Format", "Built At"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.name.clone(),
            self.arch.clone(),
            self.format.clone(),
            self.built_at.clone(),
        ]
    }
}

/// Result returned by `payload build` without `--wait`.
#[derive(Debug, Clone, Serialize)]
pub struct BuildJobSubmitted {
    /// Server-assigned build job identifier.
    pub job_id: String,
}

impl TextRender for BuildJobSubmitted {
    fn render_text(&self) -> String {
        format!("Build job submitted: {}", self.job_id)
    }
}

/// Result returned by `payload build --wait` on success.
#[derive(Debug, Clone, Serialize)]
pub struct BuildCompleted {
    /// Unique identifier of the finished payload.
    pub id: String,
    /// Size of the finished payload in bytes.
    pub size_bytes: u64,
}

impl TextRender for BuildCompleted {
    fn render_text(&self) -> String {
        format!("Payload {} built ({} bytes)", self.id, self.size_bytes)
    }
}

/// Result returned by `payload build-status`.
#[derive(Debug, Clone, Serialize)]
pub struct BuildJobStatusResult {
    /// Build job identifier.
    pub job_id: String,
    /// Current status: `"pending"`, `"running"`, `"done"`, or `"error"`.
    pub status: String,
    /// Agent type that was requested.
    pub agent_type: Option<String>,
    /// Payload identifier (set when status is `"done"`).
    pub payload_id: Option<String>,
    /// Artifact size in bytes (set when status is `"done"`).
    pub size_bytes: Option<u64>,
    /// Error message (set when status is `"error"`).
    pub error: Option<String>,
}

impl TextRender for BuildJobStatusResult {
    fn render_text(&self) -> String {
        let mut parts = vec![format!("Job {} — {}", self.job_id, self.status)];
        if let Some(ref agent) = self.agent_type {
            parts.push(format!("  agent: {agent}"));
        }
        if let Some(ref pid) = self.payload_id {
            parts.push(format!("  payload_id: {pid}"));
        }
        if let Some(bytes) = self.size_bytes {
            parts.push(format!("  size: {bytes} bytes"));
        }
        if let Some(ref err) = self.error {
            parts.push(format!("  error: {err}"));
        }
        parts.join("\n")
    }
}

/// Result returned by `payload build-wait` on success.
#[derive(Debug, Clone, Serialize)]
pub struct BuildWaitCompleted {
    /// Unique identifier of the finished payload.
    pub payload_id: String,
    /// Size of the finished payload in bytes.
    pub size_bytes: u64,
    /// Local path where the payload was saved (if `--output` was used).
    pub output: Option<String>,
}

impl TextRender for BuildWaitCompleted {
    fn render_text(&self) -> String {
        let base = format!("Payload {} built ({} bytes)", self.payload_id, self.size_bytes);
        match self.output {
            Some(ref path) => format!("{base} → {path}"),
            None => base,
        }
    }
}

/// Result returned by `payload download`.
#[derive(Debug, Clone, Serialize)]
pub struct DownloadResult {
    /// Payload ID that was downloaded.
    pub id: String,
    /// Local path where the payload was written.
    pub dst: String,
    /// Number of bytes written to disk.
    pub size_bytes: u64,
}

impl TextRender for DownloadResult {
    fn render_text(&self) -> String {
        format!("Saved {} ({} bytes) → {}", self.id, self.size_bytes, self.dst)
    }
}

/// Result returned by `payload cache-flush`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheFlushResult {
    /// Number of cached payload entries that were removed.
    pub flushed: u64,
}

impl TextRender for CacheFlushResult {
    fn render_text(&self) -> String {
        format!("Flushed {} cached payload(s).", self.flushed)
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch a [`PayloadCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: PayloadCommands) -> i32 {
    match action {
        PayloadCommands::List => match list(client).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        PayloadCommands::Build {
            listener,
            arch,
            format,
            agent,
            sleep: sleep_secs,
            wait,
            wait_timeout,
            detach,
        } => {
            let effective_wait = wait && !detach;
            let build_timeout_secs = wait_timeout.unwrap_or(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS);
            match build(
                client,
                &listener,
                &arch,
                &format,
                &agent,
                sleep_secs,
                effective_wait,
                build_timeout_secs,
            )
            .await
            {
                Ok(outcome) => match outcome {
                    BuildOutcome::Submitted(job) => match print_success(fmt, &job) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                    BuildOutcome::Completed(done) => match print_success(fmt, &done) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        PayloadCommands::BuildStatus { job_id } => match build_status(client, &job_id).await {
            Ok(result) => match print_success(fmt, &result) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        PayloadCommands::BuildWait { job_id, output, wait_timeout } => {
            let timeout_secs = wait_timeout.unwrap_or(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS);
            match build_wait(client, &job_id, output.as_deref(), timeout_secs).await {
                Ok(result) => match print_success(fmt, &result) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        PayloadCommands::Download { id, dst } => match download(client, &id, &dst).await {
            Ok(result) => match print_success(fmt, &result) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        PayloadCommands::CacheFlush => match cache_flush(client).await {
            Ok(result) => match print_success(fmt, &result) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        // Handled before config resolution in dispatch.rs; this arm exists
        // only for exhaustiveness.
        PayloadCommands::Inspect { .. } => EXIT_SUCCESS,
    }
}

// ── internal enum for build outcome ──────────────────────────────────────────

/// Outcome of a build command — either submitted (no `--wait`) or completed
/// (`--wait` used and the build finished successfully).
#[derive(Debug)]
enum BuildOutcome {
    Submitted(BuildJobSubmitted),
    Completed(BuildCompleted),
}

// ── command implementations ───────────────────────────────────────────────────

/// Validate that `format` is one of the accepted payload formats.
///
/// Returns `Ok(())` for `"exe"`, `"dll"`, or `"bin"`; otherwise returns
/// [`CliError::InvalidArgs`].
pub(crate) fn validate_format(format: &str) -> Result<(), CliError> {
    match format {
        "exe" | "dll" | "bin" => Ok(()),
        other => Err(CliError::InvalidArgs(format!(
            "unknown format '{other}': expected exe, dll, or bin"
        ))),
    }
}

/// `payload list` — fetch all built payloads.
///
/// # Examples
/// ```text
/// red-cell-cli payload list
/// ```
#[instrument(skip(client))]
async fn list(client: &ApiClient) -> Result<Vec<PayloadRow>, CliError> {
    let raw: Vec<RawPayloadSummary> = client.get("/payloads").await?;
    Ok(raw.into_iter().map(payload_row_from_raw).collect())
}

/// `payload build` — submit a payload build job, optionally waiting for
/// completion.
///
/// # Examples
/// ```text
/// red-cell-cli payload build --listener http1 --arch x86_64 --format exe
/// red-cell-cli payload build --listener http1 --arch x86_64 --format exe --wait
/// red-cell-cli payload build --listener http1 --arch x86_64 --format bin --agent phantom
/// ```
#[instrument(skip(client))]
async fn build(
    client: &ApiClient,
    listener: &str,
    arch: &str,
    format: &str,
    agent: &str,
    sleep_secs: Option<u64>,
    wait: bool,
    timeout_secs: u64,
) -> Result<BuildOutcome, CliError> {
    validate_format(format)?;

    let mut body = serde_json::json!({
        "listener": listener,
        "arch": arch,
        "format": format,
        "agent": agent,
    });

    if let Some(s) = sleep_secs {
        body["sleep"] = serde_json::json!(s);
    }

    let submitted: BuildSubmitResponse = client.post("/payloads/build", &body).await?;

    if !wait {
        return Ok(BuildOutcome::Submitted(BuildJobSubmitted { job_id: submitted.job_id }));
    }

    // Poll until done or timeout.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let job_path = format!("/payloads/jobs/{}", submitted.job_id);
    let mut backoff = Backoff::new();

    loop {
        if Instant::now() > deadline {
            return Err(CliError::Timeout(format!(
                "build job {} did not complete within {} seconds",
                submitted.job_id, timeout_secs
            )));
        }

        match client.get::<BuildJobStatus>(&job_path).await {
            Err(CliError::RateLimited { retry_after_secs }) => {
                let wait =
                    Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS));
                sleep(wait).await;
            }
            Err(e) => return Err(e),
            Ok(status) => {
                match status.status.as_str() {
                    "done" => {
                        let payload_id = status.payload_id.ok_or_else(|| {
                            CliError::General(format!(
                                "build job {} reported done but returned no payload_id",
                                status.job_id
                            ))
                        })?;
                        let size_bytes = status.size_bytes.unwrap_or(0);
                        return Ok(BuildOutcome::Completed(BuildCompleted {
                            id: payload_id,
                            size_bytes,
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
                    _ => {
                        backoff.record_empty();
                        sleep(backoff.delay()).await;
                    }
                }
            }
        }
    }
}

/// `payload build-status <job-id>` — check the status of a build job.
///
/// # Examples
/// ```text
/// red-cell-cli payload build-status abc123
/// ```
#[instrument(skip(client))]
async fn build_status(client: &ApiClient, job_id: &str) -> Result<BuildJobStatusResult, CliError> {
    let job_path = format!("/payloads/jobs/{job_id}");
    let status: BuildJobStatus = client.get(&job_path).await?;
    Ok(BuildJobStatusResult {
        job_id: status.job_id,
        status: status.status,
        agent_type: status.agent_type,
        payload_id: status.payload_id,
        size_bytes: status.size_bytes,
        error: status.error,
    })
}

/// `payload build-wait <job-id>` — poll until a build job finishes, optionally
/// downloading the artifact.
///
/// # Examples
/// ```text
/// red-cell-cli payload build-wait abc123
/// red-cell-cli payload build-wait abc123 --output ./payload.exe
/// ```
#[instrument(skip(client))]
async fn build_wait(
    client: &ApiClient,
    job_id: &str,
    output: Option<&str>,
    timeout_secs: u64,
) -> Result<BuildWaitCompleted, CliError> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let job_path = format!("/payloads/jobs/{job_id}");
    let mut backoff = Backoff::new();

    let (payload_id, size_bytes) = loop {
        if Instant::now() > deadline {
            return Err(CliError::Timeout(format!(
                "build job {job_id} did not complete within {timeout_secs} seconds"
            )));
        }

        match client.get::<BuildJobStatus>(&job_path).await {
            Err(CliError::RateLimited { retry_after_secs }) => {
                let wait =
                    Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS));
                sleep(wait).await;
            }
            Err(e) => return Err(e),
            Ok(status) => match status.status.as_str() {
                "done" => {
                    let pid = status.payload_id.ok_or_else(|| {
                        CliError::General(format!(
                            "build job {job_id} reported done but returned no payload_id"
                        ))
                    })?;
                    break (pid, status.size_bytes.unwrap_or(0));
                }
                "error" => {
                    let msg = status.error.unwrap_or_else(|| "unknown build error".to_owned());
                    return Err(CliError::General(format!("build job {job_id} failed: {msg}")));
                }
                _ => {
                    backoff.record_empty();
                    sleep(backoff.delay()).await;
                }
            },
        }
    };

    if let Some(dst) = output {
        let bytes = client.get_raw_bytes(&format!("/payloads/{payload_id}/download")).await?;
        let dst_path = Path::new(dst);
        if let Some(parent) = dst_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    CliError::General(format!(
                        "failed to create directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        tokio::fs::write(dst_path, &bytes)
            .await
            .map_err(|e| CliError::General(format!("failed to write payload to {dst}: {e}")))?;
    }

    Ok(BuildWaitCompleted { payload_id, size_bytes, output: output.map(|s| s.to_owned()) })
}

/// `payload download <id> --dst <path>` — download a payload binary to disk.
///
/// # Examples
/// ```text
/// red-cell-cli payload download abc123 --dst ./payload.exe
/// ```
#[instrument(skip(client))]
async fn download(client: &ApiClient, id: &str, dst: &str) -> Result<DownloadResult, CliError> {
    let bytes = client.get_raw_bytes(&format!("/payloads/{id}/download")).await?;
    let size_bytes = bytes.len() as u64;

    let dst_path = Path::new(dst);
    if let Some(parent) = dst_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                CliError::General(format!("failed to create directory {}: {e}", parent.display()))
            })?;
        }
    }

    tokio::fs::write(dst_path, &bytes)
        .await
        .map_err(|e| CliError::General(format!("failed to write payload to {dst}: {e}")))?;

    Ok(DownloadResult { id: id.to_owned(), dst: dst.to_owned(), size_bytes })
}

/// `payload cache-flush` — flush all cached build artifacts (admin only).
///
/// # Examples
/// ```text
/// red-cell-cli payload cache-flush
/// ```
#[instrument(skip(client))]
async fn cache_flush(client: &ApiClient) -> Result<CacheFlushResult, CliError> {
    client.post_empty("/payload-cache").await
}

// ── payload inspect (local, no server) ───────────────────────────────────────

/// Metadata extracted from a built payload's embedded manifest.
#[derive(Debug, Serialize)]
pub struct InspectResult {
    pub agent_type: String,
    pub arch: String,
    pub format: String,
    pub callback_url: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<u16>,
    pub secure: bool,
    pub sleep_ms: Option<u64>,
    pub jitter: Option<u32>,
    pub init_secret_hash: Option<String>,
    pub kill_date: Option<String>,
    pub working_hours_mask: Option<u32>,
    pub listener_name: String,
    pub export_name: Option<String>,
    pub built_at: String,
}

impl TextRender for InspectResult {
    fn render_text(&self) -> String {
        let mut lines = Vec::with_capacity(16);
        lines.push(format!("Agent type:       {}", self.agent_type));
        lines.push(format!("Architecture:     {}", self.arch));
        lines.push(format!("Format:           {}", self.format));
        if let Some(ref url) = self.callback_url {
            lines.push(format!("Callback URL:     {url}"));
        }
        if !self.hosts.is_empty() {
            lines.push(format!("Hosts:            {}", self.hosts.join(", ")));
        }
        if let Some(port) = self.port {
            lines.push(format!("Port:             {port}"));
        }
        lines.push(format!("TLS:              {}", self.secure));
        if let Some(ms) = self.sleep_ms {
            lines.push(format!("Sleep:            {ms} ms"));
        }
        if let Some(j) = self.jitter {
            lines.push(format!("Jitter:           {j}%"));
        }
        if let Some(ref h) = self.init_secret_hash {
            lines.push(format!("Init secret hash: {h}"));
        }
        if let Some(ref kd) = self.kill_date {
            lines.push(format!("Kill date:        {kd}"));
        }
        if let Some(mask) = self.working_hours_mask {
            lines.push(format!("Working hours:    0x{mask:08X}"));
        }
        lines.push(format!("Listener:         {}", self.listener_name));
        if let Some(ref name) = self.export_name {
            lines.push(format!("Export name:      {name}"));
        }
        lines.push(format!("Built at:         {}", self.built_at));
        lines.join("\n")
    }
}

/// Inspect a local payload file and print its embedded build manifest.
///
/// This is a synchronous, server-independent operation dispatched before
/// config resolution by [`crate::dispatch::dispatch`].
pub fn inspect_local(file: &str, fmt: &OutputFormat) -> i32 {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            let err = CliError::Io(format!("failed to read {file}: {e}"));
            print_error(&err).ok();
            return err.exit_code();
        }
    };

    let manifest = match red_cell_common::payload_manifest::extract_manifest(&data) {
        Some(m) => m,
        None => {
            let err = CliError::General(format!(
                "no build manifest found in {file} — the payload may have been \
                 built before manifest embedding was added, or the file is not \
                 a Red Cell payload"
            ));
            print_error(&err).ok();
            return err.exit_code();
        }
    };

    let result = InspectResult {
        agent_type: manifest.agent_type,
        arch: manifest.arch,
        format: manifest.format,
        callback_url: manifest.callback_url,
        hosts: manifest.hosts,
        port: manifest.port,
        secure: manifest.secure,
        sleep_ms: manifest.sleep_ms,
        jitter: manifest.jitter,
        init_secret_hash: manifest.init_secret_hash,
        kill_date: manifest.kill_date,
        working_hours_mask: manifest.working_hours_mask,
        listener_name: manifest.listener_name,
        export_name: manifest.export_name,
        built_at: manifest.built_at,
    };

    match print_success(fmt, &result) {
        Ok(()) => EXIT_SUCCESS,
        Err(e) => {
            print_error(&e).ok();
            e.exit_code()
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn payload_row_from_raw(raw: RawPayloadSummary) -> PayloadRow {
    PayloadRow {
        id: raw.id,
        name: raw.name,
        arch: raw.arch,
        format: raw.format,
        built_at: raw.built_at,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PayloadRow ────────────────────────────────────────────────────────────

    #[test]
    fn payload_row_headers_match_row_length() {
        let row = PayloadRow {
            id: "abc123".to_owned(),
            name: "demon_x64.exe".to_owned(),
            arch: "x86_64".to_owned(),
            format: "exe".to_owned(),
            built_at: "2026-03-21T00:00:00Z".to_owned(),
        };
        assert_eq!(PayloadRow::headers().len(), row.row().len());
    }

    #[test]
    fn payload_row_serialises_all_fields() {
        let row = PayloadRow {
            id: "xyz".to_owned(),
            name: "demon.bin".to_owned(),
            arch: "aarch64".to_owned(),
            format: "bin".to_owned(),
            built_at: "2026-03-21T12:00:00Z".to_owned(),
        };
        let v = serde_json::to_value(&row).expect("serialise");
        assert_eq!(v["id"], "xyz");
        assert_eq!(v["arch"], "aarch64");
        assert_eq!(v["format"], "bin");
    }

    #[test]
    fn vec_payload_row_renders_table_with_data() {
        let rows = vec![PayloadRow {
            id: "abc".to_owned(),
            name: "demon.exe".to_owned(),
            arch: "x86_64".to_owned(),
            format: "exe".to_owned(),
            built_at: "2026-03-21T00:00:00Z".to_owned(),
        }];
        let rendered = rows.render_text();
        assert!(rendered.contains("abc"));
        assert!(rendered.contains("x86_64"));
        assert!(rendered.contains("exe"));
    }

    #[test]
    fn vec_payload_row_empty_renders_none() {
        let rows: Vec<PayloadRow> = vec![];
        assert_eq!(rows.render_text(), "(none)");
    }

    // ── BuildJobSubmitted ─────────────────────────────────────────────────────

    #[test]
    fn build_job_submitted_render_contains_job_id() {
        let r = BuildJobSubmitted { job_id: "job-001".to_owned() };
        assert!(r.render_text().contains("job-001"));
    }

    #[test]
    fn build_job_submitted_serialises_job_id() {
        let r = BuildJobSubmitted { job_id: "j1".to_owned() };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["job_id"], "j1");
    }

    // ── BuildCompleted ────────────────────────────────────────────────────────

    #[test]
    fn build_completed_render_contains_id_and_size() {
        let r = BuildCompleted { id: "p1".to_owned(), size_bytes: 12345 };
        let rendered = r.render_text();
        assert!(rendered.contains("p1"));
        assert!(rendered.contains("12345"));
    }

    #[test]
    fn build_completed_serialises_id_and_size() {
        let r = BuildCompleted { id: "p1".to_owned(), size_bytes: 99 };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["id"], "p1");
        assert_eq!(v["size_bytes"], 99);
    }

    // ── DownloadResult ────────────────────────────────────────────────────────

    #[test]
    fn download_result_render_contains_all_fields() {
        let r =
            DownloadResult { id: "p2".to_owned(), dst: "./out.exe".to_owned(), size_bytes: 65536 };
        let rendered = r.render_text();
        assert!(rendered.contains("p2"));
        assert!(rendered.contains("./out.exe"));
        assert!(rendered.contains("65536"));
    }

    #[test]
    fn download_result_serialises_correctly() {
        let r = DownloadResult { id: "p3".to_owned(), dst: "/tmp/x.bin".to_owned(), size_bytes: 1 };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["id"], "p3");
        assert_eq!(v["dst"], "/tmp/x.bin");
        assert_eq!(v["size_bytes"], 1);
    }

    // ── payload_row_from_raw ──────────────────────────────────────────────────

    #[test]
    fn payload_row_from_raw_maps_all_fields() {
        let raw = RawPayloadSummary {
            id: "id1".to_owned(),
            name: "n".to_owned(),
            arch: "x86_64".to_owned(),
            format: "dll".to_owned(),
            built_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let row = payload_row_from_raw(raw);
        assert_eq!(row.id, "id1");
        assert_eq!(row.format, "dll");
        assert_eq!(row.arch, "x86_64");
    }

    // ── build sends agent field ──────────────────────────────────────────────

    #[tokio::test]
    async fn build_sends_agent_field_in_request_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payloads/build"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "job_id": "test-job-1"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build(
            &client,
            "http1",
            "x64",
            "exe",
            "phantom",
            None,
            false,
            PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
        )
        .await;
        assert!(result.is_ok(), "build must succeed: {result:?}");

        // Verify the request body contained the agent field.
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("parse body");
        assert_eq!(body["agent"], "phantom", "request body must include agent field");
        assert_eq!(body["listener"], "http1");
        assert_eq!(body["arch"], "x64");
        assert_eq!(body["format"], "exe");
    }

    #[tokio::test]
    async fn build_sends_default_demon_agent() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payloads/build"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "job_id": "test-job-2"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let _ = build(
            &client,
            "http1",
            "x64",
            "exe",
            "demon",
            None,
            false,
            PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
        )
        .await;

        let requests = server.received_requests().await.expect("requests");
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("parse body");
        assert_eq!(body["agent"], "demon", "default agent must be 'demon'");
    }

    // ── format validation ─────────────────────────────────────────────────────

    #[test]
    fn validate_format_rejects_unknown_format() {
        assert!(matches!(validate_format("elf"), Err(CliError::InvalidArgs(_))));
        assert!(matches!(validate_format("shellcode"), Err(CliError::InvalidArgs(_))));
        assert!(matches!(validate_format(""), Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn validate_format_accepts_valid_formats() {
        for fmt in ["exe", "dll", "bin"] {
            assert!(validate_format(fmt).is_ok(), "format '{fmt}' should be accepted");
        }
    }

    // ── download writes file to disk ──────────────────────────────────────────

    #[tokio::test]
    async fn download_writes_bytes_to_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let payload_bytes = b"HELLO WORLD PAYLOAD";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/test-id/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload_bytes.as_ref()))
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let tmp = tempfile::tempdir().expect("tempdir");
        let dst = tmp.path().join("payload.bin");
        let dst_str = dst.to_str().expect("valid path");

        let result = download(&client, "test-id", dst_str).await.expect("download");

        assert_eq!(result.id, "test-id");
        assert_eq!(result.dst, dst_str);
        assert_eq!(result.size_bytes, payload_bytes.len() as u64);
        assert_eq!(std::fs::read(&dst).expect("read file"), payload_bytes);
    }

    #[tokio::test]
    async fn download_creates_parent_directory() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/nested-id/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"DATA".as_ref()))
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a").join("b").join("payload.exe");
        let dst_str = nested.to_str().expect("valid path");

        let result = download(&client, "nested-id", dst_str).await.expect("download");

        assert!(nested.exists(), "download must create parent directories");
        assert_eq!(result.size_bytes, 4);
    }

    // ── CacheFlushResult ──────────────────────────────────────────────────────

    #[test]
    fn cache_flush_result_render_contains_count() {
        let r = CacheFlushResult { flushed: 7 };
        let text = r.render_text();
        assert!(text.contains("7"), "render must include flushed count");
        assert!(text.to_lowercase().contains("flush"), "render must mention flush");
    }

    #[test]
    fn cache_flush_result_render_zero() {
        let r = CacheFlushResult { flushed: 0 };
        let text = r.render_text();
        assert!(text.contains("0"));
    }

    #[test]
    fn cache_flush_result_serialises_flushed_field() {
        let r = CacheFlushResult { flushed: 42 };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["flushed"], 42);
    }

    // ── cache_flush HTTP call ─────────────────────────────────────────────────

    #[tokio::test]
    async fn cache_flush_calls_post_payload_cache_and_returns_count() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payload-cache"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "flushed": 3 })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = cache_flush(&client).await.expect("cache_flush must succeed");
        assert_eq!(result.flushed, 3);
    }

    #[tokio::test]
    async fn cache_flush_returns_auth_failure_on_403() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payload-cache"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "non-admin-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = cache_flush(&client).await.expect_err("must fail with 403");
        assert!(matches!(err, CliError::AuthFailure(_)), "expected AuthFailure, got {err:?}");
    }

    // ── inspect_local ────────────────────────────────────────────────────────

    #[test]
    fn inspect_local_returns_success_for_valid_manifest() {
        use red_cell_common::payload_manifest::{PayloadManifest, encode_manifest};

        let manifest = PayloadManifest {
            agent_type: "Demon".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            hosts: vec!["192.168.1.100".to_owned()],
            port: Some(443),
            secure: true,
            callback_url: Some("https://192.168.1.100:443/".to_owned()),
            sleep_ms: Some(5000),
            jitter: Some(20),
            init_secret_hash: Some("abc123def4567890".to_owned()),
            kill_date: None,
            working_hours_mask: None,
            listener_name: "http1".to_owned(),
            export_name: None,
            built_at: "2026-04-25T12:00:00Z".to_owned(),
        };

        let mut payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        payload.extend_from_slice(&[0u8; 100]);
        payload.extend_from_slice(&encode_manifest(&manifest).expect("encode"));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.exe");
        std::fs::write(&path, &payload).expect("write");

        let code = inspect_local(path.to_str().expect("path"), &OutputFormat::Json);
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn inspect_local_returns_error_for_missing_file() {
        let code = inspect_local("/nonexistent/file.exe", &OutputFormat::Json);
        assert_ne!(code, EXIT_SUCCESS);
    }

    #[test]
    fn inspect_local_returns_error_for_no_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bare.bin");
        std::fs::write(&path, b"no manifest here").expect("write");

        let code = inspect_local(path.to_str().expect("path"), &OutputFormat::Json);
        assert_ne!(code, EXIT_SUCCESS);
    }

    #[test]
    fn inspect_result_text_render_includes_key_fields() {
        let result = InspectResult {
            agent_type: "Phantom".to_owned(),
            arch: "x64".to_owned(),
            format: "elf".to_owned(),
            callback_url: Some("https://10.0.0.1:8443/".to_owned()),
            hosts: vec!["10.0.0.1".to_owned()],
            port: Some(8443),
            secure: true,
            sleep_ms: Some(10000),
            jitter: Some(50),
            init_secret_hash: Some("0123456789abcdef".to_owned()),
            kill_date: Some("2027-01-01T00:00:00Z".to_owned()),
            working_hours_mask: Some(0x00FF_FF00),
            listener_name: "https-main".to_owned(),
            export_name: None,
            built_at: "2026-04-25T12:00:00Z".to_owned(),
        };

        let text = result.render_text();
        assert!(text.contains("Phantom"), "agent_type");
        assert!(text.contains("https://10.0.0.1:8443/"), "callback_url");
        assert!(text.contains("10000 ms"), "sleep");
        assert!(text.contains("50%"), "jitter");
        assert!(text.contains("0123456789abcdef"), "init_secret_hash");
        assert!(text.contains("2027-01-01"), "kill_date");
        assert!(text.contains("0x00FFFF00"), "working_hours_mask");
    }

    #[test]
    fn inspect_result_serialises_to_json() {
        let result = InspectResult {
            agent_type: "Demon".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            callback_url: None,
            hosts: vec!["c2.example.com".to_owned()],
            port: Some(443),
            secure: true,
            sleep_ms: None,
            jitter: None,
            init_secret_hash: None,
            kill_date: None,
            working_hours_mask: None,
            listener_name: "http1".to_owned(),
            export_name: None,
            built_at: "2026-04-25T00:00:00Z".to_owned(),
        };
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["agent_type"], "Demon");
        assert_eq!(json["hosts"][0], "c2.example.com");
        assert!(json["callback_url"].is_null());
    }

    // ── BuildJobStatusResult ─────────────────────────────────────────────────

    #[test]
    fn build_job_status_result_render_contains_job_id_and_status() {
        let r = BuildJobStatusResult {
            job_id: "job-42".to_owned(),
            status: "running".to_owned(),
            agent_type: Some("Demon".to_owned()),
            payload_id: None,
            size_bytes: None,
            error: None,
        };
        let text = r.render_text();
        assert!(text.contains("job-42"));
        assert!(text.contains("running"));
        assert!(text.contains("Demon"));
    }

    #[test]
    fn build_job_status_result_render_done_includes_payload_id() {
        let r = BuildJobStatusResult {
            job_id: "job-99".to_owned(),
            status: "done".to_owned(),
            agent_type: None,
            payload_id: Some("pay-123".to_owned()),
            size_bytes: Some(65536),
            error: None,
        };
        let text = r.render_text();
        assert!(text.contains("pay-123"));
        assert!(text.contains("65536"));
    }

    #[test]
    fn build_job_status_result_render_error_includes_message() {
        let r = BuildJobStatusResult {
            job_id: "job-err".to_owned(),
            status: "error".to_owned(),
            agent_type: None,
            payload_id: None,
            size_bytes: None,
            error: Some("linker failed".to_owned()),
        };
        let text = r.render_text();
        assert!(text.contains("linker failed"));
    }

    #[test]
    fn build_job_status_result_serialises_all_fields() {
        let r = BuildJobStatusResult {
            job_id: "j1".to_owned(),
            status: "done".to_owned(),
            agent_type: Some("Phantom".to_owned()),
            payload_id: Some("p1".to_owned()),
            size_bytes: Some(100),
            error: None,
        };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["job_id"], "j1");
        assert_eq!(v["status"], "done");
        assert_eq!(v["agent_type"], "Phantom");
        assert_eq!(v["payload_id"], "p1");
        assert_eq!(v["size_bytes"], 100);
        assert!(v["error"].is_null());
    }

    // ── BuildWaitCompleted ───────────────────────────────────────────────────

    #[test]
    fn build_wait_completed_render_without_output() {
        let r =
            BuildWaitCompleted { payload_id: "pay-1".to_owned(), size_bytes: 2048, output: None };
        let text = r.render_text();
        assert!(text.contains("pay-1"));
        assert!(text.contains("2048"));
        assert!(!text.contains("→"));
    }

    #[test]
    fn build_wait_completed_render_with_output() {
        let r = BuildWaitCompleted {
            payload_id: "pay-2".to_owned(),
            size_bytes: 4096,
            output: Some("./out.exe".to_owned()),
        };
        let text = r.render_text();
        assert!(text.contains("pay-2"));
        assert!(text.contains("./out.exe"));
        assert!(text.contains("→"));
    }

    #[test]
    fn build_wait_completed_serialises_all_fields() {
        let r = BuildWaitCompleted {
            payload_id: "p99".to_owned(),
            size_bytes: 512,
            output: Some("/tmp/a.bin".to_owned()),
        };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["payload_id"], "p99");
        assert_eq!(v["size_bytes"], 512);
        assert_eq!(v["output"], "/tmp/a.bin");
    }

    #[test]
    fn build_wait_completed_serialises_null_output() {
        let r = BuildWaitCompleted { payload_id: "p100".to_owned(), size_bytes: 1, output: None };
        let v = serde_json::to_value(&r).expect("serialise");
        assert!(v["output"].is_null());
    }

    // ── build_status HTTP call ───────────────────────────────────────────────

    #[tokio::test]
    async fn build_status_returns_pending_job() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-s1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "job-s1",
                "status": "pending",
                "agent_type": "Demon"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build_status(&client, "job-s1").await.expect("build_status");
        assert_eq!(result.job_id, "job-s1");
        assert_eq!(result.status, "pending");
        assert_eq!(result.agent_type.as_deref(), Some("Demon"));
        assert!(result.payload_id.is_none());
    }

    #[tokio::test]
    async fn build_status_returns_done_job() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-s2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "job-s2",
                "status": "done",
                "agent_type": "Phantom",
                "payload_id": "pay-done",
                "size_bytes": 99999
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build_status(&client, "job-s2").await.expect("build_status");
        assert_eq!(result.status, "done");
        assert_eq!(result.payload_id.as_deref(), Some("pay-done"));
        assert_eq!(result.size_bytes, Some(99999));
    }

    #[tokio::test]
    async fn build_status_returns_not_found() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/no-such-job"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = build_status(&client, "no-such-job").await.expect_err("must fail with 404");
        assert!(matches!(err, CliError::NotFound(_)), "expected NotFound, got {err:?}");
    }

    // ── build_wait HTTP call ─────────────────────────────────────────────────

    #[tokio::test]
    async fn build_wait_polls_until_done() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-w1"))
            .respond_with(move |_req: &Request| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-w1",
                        "status": "running",
                        "agent_type": "Demon"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-w1",
                        "status": "done",
                        "agent_type": "Demon",
                        "payload_id": "pay-w1",
                        "size_bytes": 8192
                    }))
                }
            })
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build_wait(&client, "job-w1", None, 30).await.expect("build_wait");
        assert_eq!(result.payload_id, "pay-w1");
        assert_eq!(result.size_bytes, 8192);
        assert!(result.output.is_none());
        assert!(call_count.load(Ordering::SeqCst) >= 3, "must have polled at least 3 times");
    }

    #[tokio::test]
    async fn build_wait_returns_error_on_build_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-fail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "job-fail",
                "status": "error",
                "agent_type": "Demon",
                "error": "compilation failed"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err =
            build_wait(&client, "job-fail", None, 30).await.expect_err("must fail on build error");
        let msg = format!("{err}");
        assert!(msg.contains("compilation failed"), "error must include message: {msg}");
    }

    #[tokio::test]
    async fn build_wait_downloads_on_output() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-dl"))
            .respond_with(move |_req: &Request| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-dl",
                        "status": "pending",
                        "agent_type": "Demon"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-dl",
                        "status": "done",
                        "agent_type": "Demon",
                        "payload_id": "pay-dl",
                        "size_bytes": 5
                    }))
                }
            })
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/pay-dl/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ABCDE".as_ref()))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let tmp = tempfile::tempdir().expect("tempdir");
        let dst = tmp.path().join("out.bin");
        let dst_str = dst.to_str().expect("valid path");

        let result = build_wait(&client, "job-dl", Some(dst_str), 30).await.expect("build_wait");
        assert_eq!(result.payload_id, "pay-dl");
        assert_eq!(result.output.as_deref(), Some(dst_str));
        assert_eq!(std::fs::read(&dst).expect("read file"), b"ABCDE");
    }
}
