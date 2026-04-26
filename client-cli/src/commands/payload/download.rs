//! `payload download` handler.

use std::path::Path;

use tracing::instrument;

use crate::client::ApiClient;
use crate::error::CliError;

use super::types::DownloadResult;

/// `payload download <id> --dst <path>` — download a payload binary to disk.
///
/// # Examples
/// ```text
/// red-cell-cli payload download abc123 --dst ./payload.exe
/// ```
#[instrument(skip(client))]
pub(super) async fn download(
    client: &ApiClient,
    id: &str,
    dst: &str,
) -> Result<DownloadResult, CliError> {
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
