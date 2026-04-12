//! `agent kill` — terminate an agent.

use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::instrument;

use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::AGENT_EXEC_WAIT_TIMEOUT_SECS;
use crate::error::CliError;

use super::RATE_LIMIT_DEFAULT_WAIT_SECS;
use super::types::KillResult;
use super::wire::RawAgent;

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
pub(crate) async fn kill(
    client: &ApiClient,
    id: AgentId,
    wait: bool,
) -> Result<KillResult, CliError> {
    client.delete_no_body(&format!("/agents/{id}")).await?;

    if !wait {
        return Ok(KillResult { agent_id: id, status: "kill_sent".to_owned() });
    }

    let deadline = Instant::now() + Duration::from_secs(AGENT_EXEC_WAIT_TIMEOUT_SECS);
    let mut backoff = Backoff::new();

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for agent {id} to die after {}s",
                AGENT_EXEC_WAIT_TIMEOUT_SECS
            )));
        }

        match client.get::<RawAgent>(&format!("/agents/{id}")).await {
            Err(CliError::RateLimited { retry_after_secs }) => {
                let wait =
                    Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS));
                sleep(wait).await;
            }
            Err(e) => return Err(e),
            Ok(raw) => {
                if raw.status == "dead" {
                    return Ok(KillResult { agent_id: id, status: raw.status });
                }
                backoff.record_empty();
                sleep(backoff.delay()).await;
            }
        }
    }
}
