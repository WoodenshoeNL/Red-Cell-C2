//! `agent exec` — submit tasks and optional `--wait` polling.

use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::time::sleep;
use tracing::instrument;

use red_cell_common::demon::{
    COMMAND_PROC_CREATE_ID, COMMAND_SCREENSHOT_ID, format_proc_create_args,
};

use super::output_cmd::fetch_output;
use super::types::{ExecResult, JobSubmitted, OutputEntry};
use super::wire::TaskQueuedResponse;
use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::RATE_LIMIT_DEFAULT_WAIT_SECS;
use crate::error::CliError;

/// Map a user-supplied command name to a Demon `CommandID` decimal string.
///
/// Built-in agent commands that do not go through the generic process-create
/// handler (command ID 5 = `DemonCommand::CommandProc`) are listed here so
/// the CLI can route them to the correct handler without the caller needing
/// to know numeric IDs.
///
/// | User command | CommandID | Demon constant |
/// |---|---|---|
/// | `screenshot` | `2510` | `CommandScreenshot` |
/// | anything else | `4112` | `CommandProc` (0x1010, Create) |
pub(crate) fn command_id_for(cmd: &str) -> &'static str {
    let verb = cmd.split_whitespace().next().unwrap_or(cmd).to_ascii_lowercase();
    match verb.as_str() {
        "screenshot" => COMMAND_SCREENSHOT_ID,
        _ => COMMAND_PROC_CREATE_ID,
    }
}

/// Returns true when this output row belongs to the submitted task.
///
/// Matches the server's `task_id` field when present; otherwise compares
/// `request_id` to `submitted_job_id` interpreted as hex (same as `next_task_id()`).
fn output_entry_matches_submitted_job(entry: &OutputEntry, submitted_job_id: &str) -> bool {
    if entry.job_id == submitted_job_id {
        return true;
    }
    let trimmed = submitted_job_id.trim();
    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if let Ok(expected) = u32::from_str_radix(hex_digits, 16) {
        if entry.request_id == expected {
            return true;
        }
    }
    false
}

/// Returns `true` when the command ID maps to `CommandProc` (process create).
fn is_proc_create(command_id: &str) -> bool {
    command_id == COMMAND_PROC_CREATE_ID
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
    #[derive(Serialize)]
    struct Body<'a> {
        #[serde(rename = "CommandLine")]
        command_line: &'a str,
        #[serde(rename = "CommandID")]
        command_id: &'a str,
        #[serde(rename = "DemonID")]
        demon_id: &'a str,
        #[serde(rename = "TaskID")]
        task_id: &'static str,
        #[serde(rename = "SubCommand", skip_serializing_if = "Option::is_none")]
        sub_command: Option<&'a str>,
        #[serde(rename = "Args", skip_serializing_if = "Option::is_none")]
        args: Option<String>,
    }

    let cid = command_id_for(cmd);
    let demon_id = id.to_string();

    let (sub_command, args) = if is_proc_create(cid) {
        (Some("create"), Some(format_proc_create_args(cmd)))
    } else {
        (None, None)
    };

    let resp: TaskQueuedResponse = client
        .post(
            &format!("/agents/{id}/task"),
            &Body {
                command_line: cmd,
                command_id: cid,
                demon_id: &demon_id,
                task_id: "",
                sub_command,
                args,
            },
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
                        if output_entry_matches_submitted_job(entry, &submitted.job_id) {
                            return Ok(ExecResult {
                                job_id: submitted.job_id.clone(),
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

#[cfg(test)]
mod output_match_tests {
    use super::super::types::OutputEntry;
    use super::output_entry_matches_submitted_job;

    #[test]
    fn matches_equal_job_id() {
        let entry = OutputEntry {
            entry_id: 1,
            request_id: 7,
            job_id: "CUSTOM".to_owned(),
            command: None,
            output: String::new(),
            exit_code: None,
            created_at: String::new(),
        };
        assert!(output_entry_matches_submitted_job(&entry, "CUSTOM"));
        assert!(!output_entry_matches_submitted_job(&entry, "OTHER"));
    }

    #[test]
    fn matches_request_id_when_job_id_is_row_fallback() {
        let entry = OutputEntry {
            entry_id: 100,
            request_id: 0xDEAD_BEEF,
            job_id: "100".to_owned(),
            command: None,
            output: "ok".to_owned(),
            exit_code: None,
            created_at: String::new(),
        };
        assert!(output_entry_matches_submitted_job(&entry, "DEADBEEF"));
        assert!(output_entry_matches_submitted_job(&entry, "deadbeef"));
        assert!(output_entry_matches_submitted_job(&entry, "0xDEADBEEF"));
    }
}
