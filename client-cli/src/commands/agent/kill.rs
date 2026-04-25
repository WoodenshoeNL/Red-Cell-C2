//! `agent kill` — terminate or deregister an agent.

use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::instrument;

use super::types::KillResult;
use super::wire::RawAgent;
use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::{AGENT_EXEC_WAIT_TIMEOUT_SECS, RATE_LIMIT_DEFAULT_WAIT_SECS};
use crate::error::CliError;

/// Controls how `agent kill` interacts with the teamserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillMode {
    /// Queue a kill task; return immediately (default).
    Default,
    /// Queue a kill task; poll until status becomes `"dead"`.
    Wait,
    /// Queue a kill task **and** immediately deregister the agent server-side.
    Force,
    /// Skip the kill task; only remove the agent from the teamserver registry.
    DeregisterOnly,
}

/// `agent kill <id>` — send terminate command and/or deregister an agent.
///
/// | Mode | API call | Behaviour |
/// |------|----------|-----------|
/// | `Default` | `DELETE /agents/{id}` | Queue kill task, return immediately |
/// | `Wait` | `DELETE /agents/{id}` + poll | Block until `status == "dead"` |
/// | `Force` | `DELETE /agents/{id}?force=true` | Kill + deregister, no wait |
/// | `DeregisterOnly` | `DELETE /agents/{id}?deregister_only=true` | Deregister only |
#[instrument(skip(client))]
pub(crate) async fn kill(
    client: &ApiClient,
    id: AgentId,
    mode: KillMode,
) -> Result<KillResult, CliError> {
    let path = match mode {
        KillMode::Default | KillMode::Wait => format!("/agents/{id}"),
        KillMode::Force => format!("/agents/{id}?force=true"),
        KillMode::DeregisterOnly => format!("/agents/{id}?deregister_only=true"),
    };
    client.delete_no_body(&path).await?;

    let status = match mode {
        KillMode::Force | KillMode::DeregisterOnly => "deregistered",
        _ => "kill_sent",
    };

    if mode != KillMode::Wait {
        return Ok(KillResult { agent_id: id, status: status.to_owned() });
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
