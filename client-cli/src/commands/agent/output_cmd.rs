//! `agent output` — persisted output and `--watch` streaming.

use std::time::Duration;

use tokio::time::sleep;
use tracing::instrument;

use super::types::OutputEntry;
use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::commands::types::{OutputPage, output_url};
use crate::defaults::RATE_LIMIT_DEFAULT_WAIT_SECS;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_cursor_reset_warning, print_error, print_stream_entry};

/// If the polling cursor is `Some(n)` with `n > 0` and the server returns no
/// rows, the cursor may be **stale** (output log pruned or reset).  Callers
/// should emit [`crate::output::print_cursor_reset_warning`] at most once per
/// command invocation until any output has been observed.
///
/// Returns `Some(missed_from)` when a warning should be written to stderr;
/// updates `already_warned` so the warning is not repeated on subsequent empty
/// polls.
pub(crate) fn take_cursor_reset_warning(
    cursor: Option<i64>,
    seen_output: bool,
    already_warned: &mut bool,
) -> Option<i64> {
    if seen_output || *already_warned {
        return None;
    }
    if cursor.is_some_and(|c| c > 0) {
        *already_warned = true;
        cursor
    } else {
        None
    }
}

/// `agent output <id>` — fetch persisted output entries for an agent.
///
/// Calls `GET /agents/{id}/output[?since=<cursor>]`.  When `since` is
/// supplied the server returns only entries with a database id greater than
/// the cursor value, enabling efficient long-polling.
///
/// # Errors
///
/// Returns [`CliError`] variants from the underlying HTTP call.
#[instrument(skip(client))]
pub(crate) async fn fetch_output(
    client: &ApiClient,
    id: AgentId,
    since: Option<i64>,
) -> Result<Vec<OutputEntry>, CliError> {
    let path = output_url(id, since);
    let page: OutputPage = client.get(&path).await?;
    Ok(page
        .entries
        .into_iter()
        .map(|e| OutputEntry {
            entry_id: e.id,
            request_id: e.request_id,
            job_id: e.task_id.unwrap_or_else(|| e.id.to_string()),
            command: e.command_line,
            output: if e.output.is_empty() { e.message } else { e.output },
            exit_code: e.exit_code,
            created_at: e.received_at,
        })
        .collect())
}

/// `agent output <id> --watch` — stream new output as JSON lines until Ctrl-C.
///
/// Polls with backoff and prints each new entry as an individual JSON line.
///
/// If `--since` is greater than zero and the first poll returns no rows, **stderr**
/// may receive `{"warning":"cursor_reset","missed_from":N}` once — the cursor
/// could be past the end of the retained log (for example after server pruning).
/// Consumers waiting for a marker string should handle this warning and resync.
///
/// # Examples
/// ```text
/// red-cell-cli agent output abc123 --watch
/// red-cell-cli agent output abc123 --watch --since 42
/// ```
pub(crate) async fn watch_output(
    client: &ApiClient,
    fmt: &OutputFormat,
    id: AgentId,
    since: Option<i64>,
) -> i32 {
    let mut cursor: Option<i64> = since;
    let mut seen_output = false;
    let mut warned_cursor_reset = false;
    let mut backoff = Backoff::new();
    // Create the ctrl_c future once and pin it so we can reuse the same OS-level
    // signal listener across all loop iterations. Creating a new ctrl_c() future
    // on every iteration registers a new listener each time; after ~64 iterations
    // the Tokio global receiver capacity (128) can be exhausted.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        let poll_result = tokio::select! {
            result = fetch_output(client, id, cursor) => result,
            _ = &mut ctrl_c => {
                return EXIT_SUCCESS;
            }
        };

        let sleep_duration = match poll_result {
            Err(CliError::RateLimited { retry_after_secs }) => {
                // Sleep for the server-specified delay then retry without
                // advancing the backoff — rate limiting is transient.
                Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS))
            }
            Err(e) => {
                print_error(&e).ok();
                return e.exit_code();
            }
            Ok(entries) => {
                if entries.is_empty() {
                    if let Some(missed) =
                        take_cursor_reset_warning(cursor, seen_output, &mut warned_cursor_reset)
                    {
                        if let Err(e) = print_cursor_reset_warning(missed) {
                            print_error(&CliError::Io(e.to_string())).ok();
                            return EXIT_GENERAL;
                        }
                    }
                    backoff.record_empty();
                } else {
                    seen_output = true;
                    backoff.record_non_empty();
                    for entry in &entries {
                        // Advance the numeric cursor so next poll only fetches newer entries.
                        cursor = Some(entry.entry_id);
                        if let Err(e) =
                            print_stream_entry(fmt, entry, &render_output_stream_line(entry))
                        {
                            print_error(&e).ok();
                            return e.exit_code();
                        }
                    }
                }
                backoff.delay()
            }
        };

        tokio::select! {
            _ = sleep(sleep_duration) => {}
            _ = &mut ctrl_c => {
                return EXIT_SUCCESS;
            }
        }
    }
}

pub(crate) fn render_output_stream_line(entry: &OutputEntry) -> String {
    let code = entry.exit_code.map_or_else(|| "?".to_owned(), |c| c.to_string());
    format!("[{}  exit {}]  {}", entry.job_id, code, entry.output)
}
