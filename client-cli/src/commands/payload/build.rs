//! Build, list, status, wait, and cache-flush handlers for `payload` subcommands.

use std::path::Path;
use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::instrument;

use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::RATE_LIMIT_DEFAULT_WAIT_SECS;
use crate::error::CliError;

use super::types::{
    BuildCompleted, BuildJobStatus, BuildJobStatusResult, BuildJobSubmitted, BuildSubmitResponse,
    BuildWaitCompleted, CacheFlushResult, PayloadRow, RawPayloadSummary, payload_row_from_raw,
};

// ── internal enum for build outcome ──────────────────────────────────────────

/// Outcome of a build command — either submitted (no `--wait`) or completed
/// (`--wait` used and the build finished successfully).
#[derive(Debug)]
pub(super) enum BuildOutcome {
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
pub(super) async fn list(client: &ApiClient) -> Result<Vec<PayloadRow>, CliError> {
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
pub(super) async fn build(
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
pub(super) async fn build_status(
    client: &ApiClient,
    job_id: &str,
) -> Result<BuildJobStatusResult, CliError> {
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
pub(super) async fn build_wait(
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

/// `payload cache-flush` — flush all cached build artifacts (admin only).
///
/// # Examples
/// ```text
/// red-cell-cli payload cache-flush
/// ```
#[instrument(skip(client))]
pub(super) async fn cache_flush(client: &ApiClient) -> Result<CacheFlushResult, CliError> {
    client.post_empty("/payload-cache").await
}
