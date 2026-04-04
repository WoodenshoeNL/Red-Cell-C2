//! `red-cell-cli payload` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `payload list` | `GET /payloads` | table of all built payloads |
//! | `payload build` | `POST /payloads/build` | submit build job; `--wait` polls until done |
//! | `payload download <id>` | `GET /payloads/{id}/download` | saves raw bytes to disk |

use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::instrument;

use crate::PayloadCommands;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};

/// Default polling timeout for `--wait` builds, in seconds.
const DEFAULT_BUILD_TIMEOUT_SECS: u64 = 300;
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
        } => {
            let build_timeout_secs = wait_timeout.unwrap_or(DEFAULT_BUILD_TIMEOUT_SECS);
            match build(
                client,
                &listener,
                &arch,
                &format,
                &agent,
                sleep_secs,
                wait,
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

        let result = build(&client, "http1", "x64", "exe", "phantom", None, false, DEFAULT_BUILD_TIMEOUT_SECS).await;
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

        let _ = build(&client, "http1", "x64", "exe", "demon", None, false, DEFAULT_BUILD_TIMEOUT_SECS).await;

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
}
