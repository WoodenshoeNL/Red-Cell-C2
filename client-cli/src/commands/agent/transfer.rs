//! `agent upload` / `agent download` — file transfer tasks.

use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::instrument;

use serde_json::Value;

use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::error::CliError;
use crate::util::percent_encode;

use super::task_correlation::loot_matches_expected_task_id;
use super::types::TransferResult;
use super::wire::TaskQueuedResponse;

/// `agent upload <id> --src <local> --dst <remote>` — upload a local file
/// to the agent via the REST API.
///
/// Reads the local file at `src`, base64-encodes it, and POSTs to
/// `POST /agents/{id}/upload` with `{ remote_path, content }`.
///
/// The `max_upload_mb` parameter sets the upper bound on file size (in
/// mebibytes) before the file is read into memory.  Files exceeding that
/// limit are rejected early with [`CliError::InvalidArgs`].
///
/// # Errors
///
/// Returns [`CliError::InvalidArgs`] if the file exceeds `max_upload_mb`.
/// Returns [`CliError::General`] if the local file cannot be read, or
/// propagates HTTP errors from the server.
#[instrument(skip(client))]
pub(crate) async fn upload(
    client: &ApiClient,
    id: AgentId,
    src: &str,
    dst: &str,
    max_upload_mb: u64,
) -> Result<TransferResult, CliError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let limit_bytes = max_upload_mb * 1024 * 1024;
    let metadata = tokio::fs::metadata(src)
        .await
        .map_err(|e| CliError::General(format!("failed to stat local file {src}: {e}")))?;
    if metadata.len() > limit_bytes {
        return Err(CliError::InvalidArgs(format!(
            "file too large for single upload ({max_upload_mb} MB limit); use chunked transfer",
        )));
    }

    let file_bytes = tokio::fs::read(src)
        .await
        .map_err(|e| CliError::General(format!("failed to read local file {src}: {e}")))?;
    let content = BASE64.encode(&file_bytes);

    #[derive(serde::Serialize)]
    struct Body<'a> {
        remote_path: &'a str,
        content: &'a str,
    }

    let resp: TaskQueuedResponse = client
        .post(&format!("/agents/{id}/upload"), &Body { remote_path: dst, content: &content })
        .await?;

    Ok(TransferResult {
        agent_id: id,
        job_id: Some(resp.task_id),
        local_path: src.to_owned(),
        remote_path: dst.to_owned(),
    })
}

/// `agent download <id> --src <remote> --dst <local>` — download a remote file
/// to local disk via the agent.
///
/// POSTs to `POST /agents/{id}/download` with `{ remote_path }`, then polls
/// `GET /loot` until the loot entry with the matching task_id appears, fetches
/// the loot bytes, and writes them to `dst`.
///
/// # Errors
///
/// Returns [`CliError::Timeout`] if the loot entry does not appear within 120 s.
/// Propagates HTTP errors and filesystem errors.
#[instrument(skip(client))]
pub(crate) async fn download(
    client: &ApiClient,
    id: AgentId,
    src: &str,
    dst: &str,
) -> Result<TransferResult, CliError> {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        remote_path: &'a str,
    }
    #[derive(serde::Deserialize)]
    struct RawLootSummary {
        id: i64,
        task_id: Option<String>,
        has_data: bool,
        #[serde(default)]
        metadata: Option<Value>,
    }
    #[derive(serde::Deserialize)]
    struct RawLootPage {
        items: Vec<RawLootSummary>,
    }

    let resp: TaskQueuedResponse =
        client.post(&format!("/agents/{id}/download"), &Body { remote_path: src }).await?;
    let task_id = resp.task_id.clone();

    // Poll for the loot entry created by this download task (up to 120 s).
    const TIMEOUT_SECS: u64 = 120;
    let deadline = Instant::now() + Duration::from_secs(TIMEOUT_SECS);
    let mut backoff = Backoff::new();
    let loot_id = loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for download loot entry for task {task_id} after {TIMEOUT_SECS}s"
            )));
        }
        let agent_str = id.to_string();
        let path = format!("/loot?kind=download&agent_id={}", percent_encode(&agent_str));
        let page: RawLootPage = client.get(&path).await?;
        if let Some(entry) = page.items.iter().find(|e| {
            e.has_data
                && loot_matches_expected_task_id(
                    &task_id,
                    e.task_id.as_deref(),
                    e.metadata.as_ref(),
                )
        }) {
            break entry.id;
        }
        backoff.record_empty();
        sleep(backoff.delay()).await;
    };

    // Fetch the loot bytes and write to dst.
    let bytes = client.get_raw_bytes(&format!("/loot/{loot_id}")).await?;
    tokio::fs::write(dst, &bytes)
        .await
        .map_err(|e| CliError::General(format!("failed to write download to {dst:?}: {e}")))?;

    Ok(TransferResult {
        agent_id: id,
        job_id: Some(resp.task_id),
        local_path: dst.to_owned(),
        remote_path: src.to_owned(),
    })
}
