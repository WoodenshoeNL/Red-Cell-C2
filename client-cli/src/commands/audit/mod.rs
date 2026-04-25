//! `red-cell-cli log` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `log list [filters]` | `GET /api/v1/audit?...` | newest-first, filterable |
//! | `log tail` | `GET /api/v1/audit?limit=20` | last 20 entries |
//! | `log tail --follow` | poll `GET /api/v1/audit?since=<ts>` | stream JSON lines |
//! | `log purge [--confirm]` | `DELETE /api/v1/audit/purge` | delete old entries |
//! | `log server-tail` | `GET /api/v1/debug/server-logs?lines=N` | teamserver log ring buffer |

mod follow;

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{instrument, warn};

use crate::AgentId;
use crate::AuditCommands;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::{AUDIT_LIST_FOLLOW_POLL_INTERVAL_SECS, AUDIT_TAIL_FOLLOW_POLL_INTERVAL_SECS};
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};
use crate::util::percent_encode;
use follow::{FollowCursor, follow_consecutive_timeouts_exhausted, print_entry_line};

/// Number of entries fetched by `log tail` (without --follow).
const TAIL_LIMIT: u32 = 20;
/// Default sleep duration (seconds) when the server returns HTTP 429 without
/// a `Retry-After` header.
const RATE_LIMIT_DEFAULT_WAIT_SECS: u64 = 10;

// ── raw API response shapes ───────────────────────────────────────────────────

/// Mirrors the fields of `teamserver::audit::AuditRecord` that are consumed
/// by the CLI.  The server also sends `id`, `parameters` which are silently
/// ignored by serde — no `deny_unknown_fields` is set.
#[derive(Debug, Deserialize)]
struct RawAuditRecord {
    actor: String,
    action: String,
    target_kind: String,
    target_id: Option<String>,
    agent_id: Option<AgentId>,
    command: Option<String>,
    result_status: String,
    occurred_at: String,
}

/// Mirrors `AuditPurgeResponse` from the teamserver.
#[derive(Debug, Deserialize)]
struct RawPurgeResponse {
    deleted: u64,
    cutoff: String,
}

/// Mirrors `teamserver::audit::AuditPage`.  Pagination metadata (`total`,
/// `limit`, `offset`) is silently ignored by serde — no `deny_unknown_fields`
/// is set.
#[derive(Debug, Deserialize)]
struct RawAuditPage {
    items: Vec<RawAuditRecord>,
}

/// Mirrors `ServerLogsResponse` from the teamserver debug endpoint.
#[derive(Debug, Deserialize)]
struct RawServerLogsResponse {
    logs: Vec<ServerLogEntry>,
}

// ── public output types ───────────────────────────────────────────────────────

/// A single audit log entry returned by `log list` / `log tail`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// ISO 8601 UTC timestamp of the event.
    pub ts: String,
    /// Operator / API-key actor who performed the action.
    pub operator: String,
    /// Action type (e.g. `"agent.task"`, `"operator.login"`).
    pub action: String,
    /// Agent ID the action was performed on, if applicable.
    pub agent_id: Option<AgentId>,
    /// Sub-action label or target reference for this event.
    pub detail: Option<String>,
    /// Outcome: `"success"` or `"failure"`.
    pub result_status: String,
}

impl TextRow for AuditEntry {
    fn headers() -> Vec<&'static str> {
        vec!["Timestamp", "Operator", "Action", "Agent ID", "Detail", "Result"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.ts.clone(),
            self.operator.clone(),
            self.action.clone(),
            self.agent_id.map_or_else(String::new, |id| id.to_string()),
            self.detail.clone().unwrap_or_default(),
            self.result_status.clone(),
        ]
    }
}

/// Result returned by `log purge`.
#[derive(Debug, Clone, Serialize)]
pub struct PurgeResult {
    /// Number of audit log rows deleted.
    pub deleted: u64,
    /// RFC 3339 timestamp used as the deletion cutoff.
    pub cutoff: String,
}

impl TextRender for PurgeResult {
    fn render_text(&self) -> String {
        format!("Purged {} audit log entries (cutoff: {}).", self.deleted, self.cutoff)
    }
}

/// A single teamserver log entry returned by `log server-tail`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLogEntry {
    /// Timestamp from the teamserver log message header.
    pub timestamp: String,
    /// Log message text.
    pub text: String,
}

impl TextRow for ServerLogEntry {
    fn headers() -> Vec<&'static str> {
        vec!["Timestamp", "Message"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.timestamp.clone(), self.text.clone()]
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

// `log list --follow` streams new entries and cannot honor `--until`; we reject the pair explicitly.
fn list_follow_conflicts_with_until(follow: bool, until: Option<&str>) -> bool {
    follow && until.is_some()
}

/// Dispatch an [`AuditCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: AuditCommands) -> i32 {
    match action {
        AuditCommands::List {
            operator,
            action,
            agent,
            since,
            until,
            limit,
            follow,
            max_failures,
        } => {
            if list_follow_conflicts_with_until(follow, until.as_deref()) {
                print_error(&CliError::InvalidArgs(
                    "--until cannot be used with --follow (the stream has no end time); \
                     omit --until, or run `log list` without --follow to cap results by time"
                        .to_owned(),
                ))
                .ok();
                return EXIT_GENERAL;
            }
            if follow {
                list_follow(
                    client,
                    fmt,
                    limit,
                    since.as_deref(),
                    operator.as_deref(),
                    agent,
                    action.as_deref(),
                    max_failures,
                )
                .await
            } else {
                match list(
                    client,
                    limit,
                    since.as_deref(),
                    until.as_deref(),
                    operator.as_deref(),
                    agent,
                    action.as_deref(),
                )
                .await
                {
                    Ok(data) => match print_success(fmt, &data) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                }
            }
        }

        AuditCommands::Purge { confirm, older_than_days } => {
            if !confirm {
                print_error(&CliError::InvalidArgs(
                    "pass --confirm to acknowledge that this will permanently delete audit log entries".to_owned(),
                ))
                .ok();
                return EXIT_GENERAL;
            }
            match purge(client, older_than_days).await {
                Ok(result) => match print_success(fmt, &result) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        AuditCommands::Tail { follow, max_failures } => {
            if follow {
                tail_follow(client, fmt, max_failures).await
            } else {
                match list(client, TAIL_LIMIT, None, None, None, None, None).await {
                    Ok(data) => match print_success(fmt, &data) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                }
            }
        }

        AuditCommands::ServerTail { lines } => match server_tail(client, lines).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// `log purge` — delete audit log entries older than the retention window.
///
/// # Examples
/// ```text
/// red-cell-cli log purge --confirm
/// red-cell-cli log purge --confirm --older-than-days 30
/// ```
#[instrument(skip(client))]
async fn purge(client: &ApiClient, older_than_days: Option<u32>) -> Result<PurgeResult, CliError> {
    let path = match older_than_days {
        Some(days) => format!("/audit/purge?older_than_days={days}"),
        None => "/audit/purge".to_owned(),
    };
    let raw: RawPurgeResponse = client.delete_json(&path).await?;
    Ok(PurgeResult { deleted: raw.deleted, cutoff: raw.cutoff })
}

/// `log server-tail` — fetch recent teamserver log lines.
///
/// # Examples
/// ```text
/// red-cell-cli log server-tail
/// red-cell-cli log server-tail --lines 50
/// ```
#[instrument(skip(client))]
async fn server_tail(client: &ApiClient, lines: u32) -> Result<Vec<ServerLogEntry>, CliError> {
    let raw: RawServerLogsResponse =
        client.get(&format!("/debug/server-logs?lines={lines}")).await?;
    Ok(raw.logs)
}

/// `log list` — fetch audit log entries with optional filters.
///
/// Entries are returned newest-first.
///
/// # Examples
/// ```text
/// red-cell-cli log list
/// red-cell-cli log list --operator alice --limit 50
/// red-cell-cli log list --since 2026-03-21T00:00:00Z --agent abc123
/// ```
#[instrument(skip(client))]
async fn list(
    client: &ApiClient,
    limit: u32,
    since: Option<&str>,
    until: Option<&str>,
    operator: Option<&str>,
    agent_id: Option<AgentId>,
    action: Option<&str>,
) -> Result<Vec<AuditEntry>, CliError> {
    let mut params: Vec<String> = vec![format!("limit={limit}")];

    if let Some(s) = since {
        params.push(format!("since={}", percent_encode(s)));
    }
    if let Some(u) = until {
        params.push(format!("until={}", percent_encode(u)));
    }
    if let Some(op) = operator {
        params.push(format!("operator={}", percent_encode(op)));
    }
    if let Some(aid) = agent_id {
        params.push(format!("agent_id={}", percent_encode(&aid.to_string())));
    }
    if let Some(act) = action {
        params.push(format!("action={}", percent_encode(act)));
    }

    let path = format!("/audit?{}", params.join("&"));
    let page: RawAuditPage = client.get(&path).await?;
    Ok(page.items.into_iter().map(audit_entry_from_raw).collect())
}

/// `log tail --follow` — print the last 20 entries then stream new ones as
/// JSON lines until Ctrl-C.
///
/// Uses the `occurred_at` timestamp of the most recent entry as a cursor for
/// incremental polling so that each entry is emitted exactly once.
///
/// # Examples
/// ```text
/// red-cell-cli log tail --follow
/// red-cell-cli log tail --follow --max-failures 10
/// ```
#[instrument(skip(client, fmt), fields(max_failures = max_failures))]
async fn tail_follow(client: &ApiClient, fmt: &OutputFormat, max_failures: u32) -> i32 {
    let mut backoff = Backoff::with_initial_delay(AUDIT_TAIL_FOLLOW_POLL_INTERVAL_SECS);
    let mut consecutive_timeouts = 0u32;

    // Fetch initial batch of 20 entries (same transient-timeout retry policy as the poll loop).
    let initial_entries = loop {
        let initial_result = tokio::select! {
            result = list(client, TAIL_LIMIT, None, None, None, None, None) => result,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };

        match initial_result {
            Ok(entries) => break entries,
            Err(CliError::Timeout(msg)) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                warn!(
                    attempt = consecutive_timeouts,
                    max_failures,
                    error = %msg,
                    "audit log tail --follow: HTTP request timed out while fetching initial snapshot; retrying after backoff"
                );
                if consecutive_timeouts >= max_failures {
                    let err = follow_consecutive_timeouts_exhausted(max_failures, &msg);
                    print_error(&err).ok();
                    return err.exit_code();
                }
                backoff.record_empty();
                tokio::select! {
                    _ = sleep(backoff.delay()) => {}
                    _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
                }
            }
            Err(e) => {
                print_error(&e).ok();
                return e.exit_code();
            }
        }
    };

    consecutive_timeouts = 0;

    // Print existing entries the same way as a plain `log tail`.
    for entry in &initial_entries {
        if let Err(e) = print_entry_line(fmt, entry) {
            print_error(&e).ok();
            return e.exit_code();
        }
    }
    let mut cursor = FollowCursor::from_printed_entries(&initial_entries);

    // Poll for new entries using the cursor timestamp.
    loop {
        let poll_result = tokio::select! {
            result = list(client, 100, cursor.since(), None, None, None, None) => result,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };

        let sleep_duration = match poll_result {
            Err(CliError::RateLimited { retry_after_secs }) => {
                consecutive_timeouts = 0;
                // Treat rate limiting as a transient condition: sleep for the
                // requested delay then resume polling without exiting.
                Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS))
            }
            Err(CliError::Timeout(msg)) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                warn!(
                    attempt = consecutive_timeouts,
                    max_failures,
                    error = %msg,
                    "audit log tail --follow: HTTP request timed out; retrying after backoff"
                );
                if consecutive_timeouts >= max_failures {
                    let err = follow_consecutive_timeouts_exhausted(max_failures, &msg);
                    print_error(&err).ok();
                    return err.exit_code();
                }
                backoff.record_empty();
                backoff.delay()
            }
            Err(e) => {
                print_error(&e).ok();
                return e.exit_code();
            }
            Ok(entries) => {
                consecutive_timeouts = 0;
                let fresh = cursor.drain_new_entries(&entries);
                if fresh.is_empty() {
                    backoff.record_empty();
                } else {
                    backoff.record_non_empty();
                    for entry in fresh {
                        if let Err(e) = print_entry_line(fmt, entry) {
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
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        }
    }
}

/// `log list --follow` — print initial filtered entries then stream new ones.
///
/// Like `tail_follow` but applies the caller's filters (operator, action,
/// agent) on each poll and uses the initial `--since` / `--limit` for the
/// first fetch.
#[instrument(
    skip(client, fmt, since, operator, agent_id, action),
    fields(max_failures = max_failures)
)]
async fn list_follow(
    client: &ApiClient,
    fmt: &OutputFormat,
    limit: u32,
    since: Option<&str>,
    operator: Option<&str>,
    agent_id: Option<AgentId>,
    action: Option<&str>,
    max_failures: u32,
) -> i32 {
    let mut backoff = Backoff::with_initial_delay(AUDIT_LIST_FOLLOW_POLL_INTERVAL_SECS);
    let mut consecutive_timeouts = 0u32;

    let initial = loop {
        let result = tokio::select! {
            r = list(client, limit, since, None, operator, agent_id, action) => r,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };
        match result {
            Ok(entries) => break entries,
            Err(CliError::Timeout(msg)) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                warn!(
                    attempt = consecutive_timeouts,
                    max_failures,
                    error = %msg,
                    "log list --follow: timed out fetching initial snapshot; retrying"
                );
                if consecutive_timeouts >= max_failures {
                    let err = follow_consecutive_timeouts_exhausted(max_failures, &msg);
                    print_error(&err).ok();
                    return err.exit_code();
                }
                backoff.record_empty();
                tokio::select! {
                    _ = sleep(backoff.delay()) => {}
                    _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
                }
            }
            Err(e) => {
                print_error(&e).ok();
                return e.exit_code();
            }
        }
    };

    consecutive_timeouts = 0;

    for entry in &initial {
        if let Err(e) = print_entry_line(fmt, entry) {
            print_error(&e).ok();
            return e.exit_code();
        }
    }
    let mut cursor = FollowCursor::from_printed_entries(&initial);

    loop {
        let poll_result = tokio::select! {
            r = list(client, 100, cursor.since(), None, operator, agent_id, action) => r,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };

        let sleep_duration = match poll_result {
            Err(CliError::RateLimited { retry_after_secs }) => {
                consecutive_timeouts = 0;
                Duration::from_secs(retry_after_secs.unwrap_or(RATE_LIMIT_DEFAULT_WAIT_SECS))
            }
            Err(CliError::Timeout(msg)) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                warn!(
                    attempt = consecutive_timeouts,
                    max_failures,
                    error = %msg,
                    "log list --follow: timed out; retrying"
                );
                if consecutive_timeouts >= max_failures {
                    let err = follow_consecutive_timeouts_exhausted(max_failures, &msg);
                    print_error(&err).ok();
                    return err.exit_code();
                }
                backoff.record_empty();
                backoff.delay()
            }
            Err(e) => {
                print_error(&e).ok();
                return e.exit_code();
            }
            Ok(entries) => {
                consecutive_timeouts = 0;
                let fresh = cursor.drain_new_entries(&entries);
                if fresh.is_empty() {
                    backoff.record_empty();
                } else {
                    backoff.record_non_empty();
                    for entry in fresh {
                        if let Err(e) = print_entry_line(fmt, entry) {
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
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Map a raw `AuditRecord` from the server into a display-friendly
/// [`AuditEntry`].
///
/// Field mapping:
/// - `ts`           ← `occurred_at`
/// - `operator`     ← `actor`
/// - `action`       ← `action`
/// - `agent_id`     ← `agent_id`
/// - `detail`       ← `command` if present, otherwise `target_kind`:`target_id`
/// - `result_status`← `result_status`
fn audit_entry_from_raw(raw: RawAuditRecord) -> AuditEntry {
    let detail = raw.command.clone().or_else(|| {
        raw.target_id.as_deref().map(|tid| format!("{}:{}", raw.target_kind, tid)).or_else(|| {
            if raw.target_kind.is_empty() { None } else { Some(raw.target_kind.clone()) }
        })
    });

    AuditEntry {
        ts: raw.occurred_at,
        operator: raw.actor,
        action: raw.action,
        agent_id: raw.agent_id,
        detail,
        result_status: raw.result_status,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_follow_conflicts_with_until_only_when_both_set() {
        assert!(list_follow_conflicts_with_until(true, Some("2026-04-25T23:59:59Z")));
        assert!(!list_follow_conflicts_with_until(true, None));
        assert!(!list_follow_conflicts_with_until(false, Some("2026-04-25T23:59:59Z")));
        assert!(!list_follow_conflicts_with_until(false, None));
    }

    fn agent_id(value: u32) -> AgentId {
        AgentId::new(value)
    }

    fn sample_raw_record(
        actor: &str,
        action: &str,
        target_kind: &str,
        target_id: Option<&str>,
        agent_id: Option<AgentId>,
        command: Option<&str>,
        result_status: &str,
        occurred_at: &str,
    ) -> RawAuditRecord {
        RawAuditRecord {
            actor: actor.to_owned(),
            action: action.to_owned(),
            target_kind: target_kind.to_owned(),
            target_id: target_id.map(ToOwned::to_owned),
            agent_id,
            command: command.map(ToOwned::to_owned),
            result_status: result_status.to_owned(),
            occurred_at: occurred_at.to_owned(),
        }
    }

    // ── audit_entry_from_raw ──────────────────────────────────────────────────

    #[test]
    fn audit_entry_from_raw_maps_all_fields() {
        let raw = sample_raw_record(
            "alice",
            "agent.task",
            "agent",
            Some("CAFE0001"),
            Some(agent_id(0xABC123)),
            Some("whoami"),
            "success",
            "2026-03-21T12:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.ts, "2026-03-21T12:00:00Z");
        assert_eq!(entry.operator, "alice");
        assert_eq!(entry.action, "agent.task");
        assert_eq!(entry.agent_id, Some(agent_id(0xABC123)));
        assert_eq!(entry.detail.as_deref(), Some("whoami"));
        assert_eq!(entry.result_status, "success");
    }

    #[test]
    fn audit_entry_from_raw_detail_falls_back_to_target_kind_and_id() {
        let raw = sample_raw_record(
            "bob",
            "operator.create",
            "operator",
            Some("charlie"),
            None,
            None, // no command
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        // Without a command, detail is built from target_kind:target_id.
        assert_eq!(entry.detail.as_deref(), Some("operator:charlie"));
    }

    #[test]
    fn audit_entry_from_raw_detail_falls_back_to_target_kind_only() {
        let raw = sample_raw_record(
            "admin",
            "config.reload",
            "config",
            None, // no target_id
            None,
            None,
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.detail.as_deref(), Some("config"));
    }

    #[test]
    fn audit_entry_from_raw_detail_none_when_target_kind_empty_and_no_command() {
        let raw = sample_raw_record(
            "admin",
            "system.ping",
            "", // empty target_kind
            None,
            None,
            None,
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert!(entry.detail.is_none());
    }

    #[test]
    fn audit_entry_from_raw_handles_none_agent_id() {
        let raw = sample_raw_record(
            "bob",
            "operator.login",
            "session",
            None,
            None,
            None,
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert!(entry.agent_id.is_none());
    }

    #[test]
    fn audit_entry_from_raw_failure_result_status() {
        let raw = sample_raw_record(
            "eve",
            "operator.login",
            "session",
            None,
            None,
            None,
            "failure",
            "2026-03-21T09:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.result_status, "failure");
    }

    // ── AuditEntry / TextRow ──────────────────────────────────────────────────

    #[test]
    fn audit_entry_headers_match_row_length() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "agent.task".to_owned(),
            agent_id: Some(agent_id(0xABC123)),
            detail: Some("whoami".to_owned()),
            result_status: "success".to_owned(),
        };
        assert_eq!(AuditEntry::headers().len(), entry.row().len());
    }

    #[test]
    fn audit_entry_row_uses_empty_string_for_none_fields() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "operator.login".to_owned(),
            agent_id: None,
            detail: None,
            result_status: "success".to_owned(),
        };
        let row = entry.row();
        assert_eq!(row[3], ""); // agent_id column
        assert_eq!(row[4], ""); // detail column
    }

    #[test]
    fn audit_entry_serialises_all_fields() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "carol".to_owned(),
            action: "agent.kill".to_owned(),
            agent_id: Some(agent_id(0xFED789)),
            detail: Some("SIGTERM".to_owned()),
            result_status: "success".to_owned(),
        };
        let v = serde_json::to_value(&entry).expect("serialise");
        assert_eq!(v["ts"], "2026-03-21T12:00:00Z");
        assert_eq!(v["operator"], "carol");
        assert_eq!(v["action"], "agent.kill");
        assert_eq!(v["agent_id"], "00FED789");
        assert_eq!(v["detail"], "SIGTERM");
        assert_eq!(v["result_status"], "success");
    }

    #[test]
    fn vec_audit_entry_renders_table_with_data() {
        let entries = vec![AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "dave".to_owned(),
            action: "agent.task".to_owned(),
            agent_id: Some(agent_id(0xABC)),
            detail: Some("id".to_owned()),
            result_status: "success".to_owned(),
        }];
        let rendered = entries.render_text();
        assert!(rendered.contains("dave"));
        assert!(rendered.contains("agent.task"));
        assert!(rendered.contains("00000ABC"));
    }

    #[test]
    fn vec_audit_entry_empty_renders_none() {
        let entries: Vec<AuditEntry> = vec![];
        assert_eq!(entries.render_text(), "(none)");
    }

    // ── purge wiremock ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn purge_calls_delete_audit_purge_and_returns_result() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/audit/purge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "deleted": 5,
                "cutoff": "2026-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = purge(&client, None).await.expect("purge must succeed");
        assert_eq!(result.deleted, 5);
        assert_eq!(result.cutoff, "2026-01-01T00:00:00Z");
    }

    #[tokio::test]
    async fn purge_returns_auth_failure_on_403() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/audit/purge"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "non-admin-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = purge(&client, None).await.expect_err("must fail with 403");
        assert!(matches!(err, CliError::AuthFailure(_)), "expected AuthFailure, got {err:?}");
    }

    // ── server-tail ─────────────────────────────────────────────────────────

    #[test]
    fn server_log_entry_serializes_correctly() {
        let entry = ServerLogEntry {
            timestamp: "12:00:01".to_owned(),
            text: "listener started".to_owned(),
        };
        let v = serde_json::to_value(&entry).expect("serialise");
        assert_eq!(v["timestamp"], "12:00:01");
        assert_eq!(v["text"], "listener started");
    }

    #[test]
    fn server_log_entry_text_row_headers() {
        let hdrs = ServerLogEntry::headers();
        assert_eq!(hdrs, vec!["Timestamp", "Message"]);
    }

    #[test]
    fn server_log_entry_text_row_values() {
        let entry = ServerLogEntry { timestamp: "12:34:56".to_owned(), text: "hello".to_owned() };
        let row = entry.row();
        assert_eq!(row, vec!["12:34:56", "hello"]);
    }

    #[test]
    fn vec_server_log_entry_renders_table() {
        let entries = vec![
            ServerLogEntry { timestamp: "12:00:01".to_owned(), text: "started".to_owned() },
            ServerLogEntry { timestamp: "12:00:02".to_owned(), text: "listening".to_owned() },
        ];
        let rendered = entries.render_text();
        assert!(rendered.contains("started"));
        assert!(rendered.contains("listening"));
        assert!(rendered.contains("12:00:01"));
    }

    #[test]
    fn vec_server_log_entry_empty_renders_none() {
        let entries: Vec<ServerLogEntry> = vec![];
        assert_eq!(entries.render_text(), "(none)");
    }

    #[tokio::test]
    async fn server_tail_calls_debug_server_logs_and_returns_entries() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/debug/server-logs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "logs": [
                    {"timestamp": "12:00:01", "text": "teamserver started"},
                    {"timestamp": "12:00:02", "text": "listener bound"}
                ],
                "count": 2
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let entries = server_tail(&client, 200).await.expect("server_tail must succeed");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "teamserver started");
        assert_eq!(entries[1].text, "listener bound");
    }

    #[tokio::test]
    async fn server_tail_returns_not_found_on_404() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/debug/server-logs"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = server_tail(&client, 200).await.expect_err("must fail with 404");
        assert!(matches!(err, CliError::NotFound(_)), "expected NotFound, got {err:?}");
    }

    #[tokio::test]
    async fn server_tail_returns_auth_failure_on_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/debug/server-logs"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "bad-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = server_tail(&client, 200).await.expect_err("must fail with 401");
        assert!(matches!(err, CliError::AuthFailure(_)), "expected AuthFailure, got {err:?}");
    }
}
