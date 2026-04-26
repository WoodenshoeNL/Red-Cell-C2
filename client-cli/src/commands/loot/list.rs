//! `loot list` and `loot download` subcommands.

use std::io::Write as _;

use tracing::instrument;

use crate::AgentId;
use crate::client::ApiClient;
use crate::error::CliError;
use crate::util::percent_encode;

use super::types::{LootEntry, RawLootPage, loot_entry_from_raw};

/// `loot list` — fetch captured loot with optional filters.
///
/// # Examples
/// ```text
/// red-cell-cli loot list
/// red-cell-cli loot list --kind screenshot
/// red-cell-cli loot list --agent DEADBEEF --limit 20
/// ```
#[instrument(skip(client))]
pub(super) async fn list(
    client: &ApiClient,
    limit: Option<u32>,
    since: Option<&str>,
    kind: Option<&str>,
    agent_id: Option<AgentId>,
    operator: Option<&str>,
) -> Result<Vec<LootEntry>, CliError> {
    let mut params: Vec<String> = Vec::new();

    if let Some(l) = limit {
        params.push(format!("limit={l}"));
    }
    if let Some(s) = since {
        params.push(format!("since={}", percent_encode(s)));
    }
    if let Some(k) = kind {
        params.push(format!("kind={}", percent_encode(k)));
    }
    if let Some(aid) = agent_id {
        params.push(format!("agent_id={}", percent_encode(&aid.to_string())));
    }
    if let Some(op) = operator {
        params.push(format!("operator={}", percent_encode(op)));
    }

    let path =
        if params.is_empty() { "/loot".to_owned() } else { format!("/loot?{}", params.join("&")) };
    let page: RawLootPage = client.get(&path).await?;
    Ok(page.items.into_iter().map(loot_entry_from_raw).collect())
}

/// `loot download <id> --out <path>` — download raw loot bytes to a local file.
///
/// # Examples
/// ```text
/// red-cell-cli loot download 42 --out ./screenshot.png
/// ```
#[instrument(skip(client))]
pub(super) async fn download(client: &ApiClient, id: i64, out: &str) -> Result<usize, CliError> {
    let bytes = client.get_raw_bytes(&format!("/loot/{id}")).await?;
    let n = bytes.len();
    let mut file = std::fs::File::create(out)
        .map_err(|e| CliError::General(format!("cannot create output file {out:?}: {e}")))?;
    file.write_all(&bytes)
        .map_err(|e| CliError::General(format!("failed to write to {out:?}: {e}")))?;
    Ok(n)
}
