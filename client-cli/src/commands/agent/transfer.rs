//! `agent upload` / `agent download` — file transfer tasks.

use tracing::instrument;

use crate::AgentId;
use crate::client::ApiClient;
use crate::error::CliError;

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

/// `agent download <id> --src <remote> --dst <local>` — queue a file
/// download task on the agent via the REST API.
///
/// POSTs to `POST /agents/{id}/download` with `{ remote_path }`.  The
/// actual file content will arrive asynchronously via agent callbacks;
/// the CLI returns the task ID so the caller can poll for completion.
///
/// # Errors
///
/// Propagates HTTP errors from the server.
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

    let resp: TaskQueuedResponse =
        client.post(&format!("/agents/{id}/download"), &Body { remote_path: src }).await?;

    Ok(TransferResult {
        agent_id: id,
        job_id: Some(resp.task_id),
        local_path: dst.to_owned(),
        remote_path: src.to_owned(),
    })
}
