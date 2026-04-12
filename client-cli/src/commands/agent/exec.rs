//! `agent exec` — submit tasks and optional `--wait` polling.

use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::time::sleep;
use tracing::instrument;

use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::error::CliError;

use super::RATE_LIMIT_DEFAULT_WAIT_SECS;
use super::output_cmd::fetch_output;
use super::types::{ExecResult, JobSubmitted};
use super::wire::TaskQueuedResponse;

/// Map a user-supplied command name to a Demon `CommandID` decimal string.
///
/// Built-in agent commands that do not go through the generic job/shell
/// handler (command ID 21 = `DemonCommand::CommandJob`) are listed here so
/// the CLI can route them to the correct handler without the caller needing
/// to know numeric IDs.
///
/// | User command | CommandID | Demon constant |
/// |---|---|---|
/// | `screenshot` | `2510` | `CommandScreenshot` |
/// | anything else | `21` | `CommandJob` |
pub(crate) fn command_id_for(cmd: &str) -> &'static str {
    // Only the first word is checked so that future parameterised commands
    // like `screenshot /path/to/save.png` route correctly.
    let verb = cmd.split_whitespace().next().unwrap_or(cmd).to_ascii_lowercase();
    match verb.as_str() {
        "screenshot" => "2510",
        _ => "21",
    }
}

/// `agent exec <id> --cmd <cmd>` — submit a command task to an agent.
///
/// POSTs to `POST /agents/{id}/task` using the Demon `AgentTaskInfo` wire
/// format and returns immediately with the server-assigned task ID.
///
/// Built-in commands such as `screenshot` are routed to their specific Demon
/// `CommandID`; all other commands use the generic shell handler (ID 21).
///
/// # Examples
/// ```text
/// red-cell-cli agent exec abc123 --cmd "whoami"
/// red-cell-cli agent exec abc123 --cmd "screenshot"
/// ```
#[instrument(skip(client))]
pub(crate) async fn exec_submit(
    client: &ApiClient,
    id: AgentId,
    cmd: &str,
) -> Result<JobSubmitted, CliError> {
    /// Minimal `AgentTaskInfo` projection — field names match the PascalCase
    /// serde renames on the canonical `red_cell_common::operator::AgentTaskInfo`
    /// struct so the server can deserialise them without modification.
    #[derive(Serialize)]
    struct Body<'a> {
        #[serde(rename = "CommandLine")]
        command_line: &'a str,
        /// Numeric Demon command identifier as a decimal string.
        #[serde(rename = "CommandID")]
        command_id: &'a str,
        /// Target agent identifier (upper-hex).  The server normalises this
        /// value; an empty string is replaced with the path parameter.
        #[serde(rename = "DemonID")]
        demon_id: &'a str,
        /// Leave blank so the server generates a unique task identifier.
        #[serde(rename = "TaskID")]
        task_id: &'static str,
    }

    let cid = command_id_for(cmd);
    let demon_id = id.to_string();
    let resp: TaskQueuedResponse = client
        .post(
            &format!("/agents/{id}/task"),
            &Body { command_line: cmd, command_id: cid, demon_id: &demon_id, task_id: "" },
        )
        .await?;
    Ok(JobSubmitted { job_id: resp.task_id })
}

/// `agent exec <id> --cmd <cmd> --wait` — submit and poll for output.
///
/// Submits the task via `POST /agents/{id}/task`, then polls
/// `GET /agents/{id}/output?since=<cursor>` until at least one output
/// entry appears for that task, or the timeout is reached.
///
/// # Errors
///
/// Returns [`CliError::Timeout`] if no output is received within the
/// deadline, or propagates any HTTP errors from the underlying calls.
#[instrument(skip(client))]
pub(crate) async fn exec_wait(
    client: &ApiClient,
    id: AgentId,
    cmd: &str,
    timeout_secs: u64,
) -> Result<ExecResult, CliError> {
    let submitted = exec_submit(client, id, cmd).await?;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    // Start with no cursor — the server returns all entries; we advance the
    // cursor by numeric entry_id so subsequent polls only fetch newer rows.
    let mut cursor: Option<i64> = None;
    let mut backoff = Backoff::new();

    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Timeout(format!(
                "timed out waiting for output from task {} after {timeout_secs}s",
                submitted.job_id
            )));
        }

        match fetch_output(client, id, cursor).await {
            Err(CliError::RateLimited { retry_after_secs }) => {
                let wait =
                    Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS));
                sleep(wait).await;
            }
            Err(e) => return Err(e),
            Ok(entries) => {
                if entries.is_empty() {
                    backoff.record_empty();
                } else {
                    backoff.record_non_empty();
                    for entry in &entries {
                        // Advance the numeric cursor so next poll is incremental.
                        cursor = Some(entry.entry_id);
                        if entry.job_id == submitted.job_id {
                            return Ok(ExecResult {
                                job_id: entry.job_id.clone(),
                                output: entry.output.clone(),
                                exit_code: entry.exit_code,
                            });
                        }
                    }
                }
                sleep(backoff.delay()).await;
            }
        }
    }
}
