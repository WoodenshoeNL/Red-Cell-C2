//! `red-cell-cli log` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `log list [filters]` | `GET /api/v1/audit?...` | newest-first, filterable |
//! | `log tail` | `GET /api/v1/audit?limit=20` | last 20 entries |
//! | `log tail --follow` | poll `GET /api/v1/audit?since=<ts>` | stream JSON lines |

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{instrument, warn};

use crate::AgentId;
use crate::AuditCommands;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::AUDIT_TAIL_FOLLOW_POLL_INTERVAL_SECS;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRow, print_error, print_stream_entry, print_success};

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

/// Mirrors `teamserver::audit::AuditPage`.  Pagination metadata (`total`,
/// `limit`, `offset`) is silently ignored by serde — no `deny_unknown_fields`
/// is set.
#[derive(Debug, Deserialize)]
struct RawAuditPage {
    items: Vec<RawAuditRecord>,
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

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch an [`AuditCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: AuditCommands) -> i32 {
    match action {
        AuditCommands::List { operator, action, agent, since, until, limit } => {
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
    }
}

// ── command implementations ───────────────────────────────────────────────────

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

/// Error returned when [`tail_follow`] has seen `max_failures` consecutive HTTP timeouts.
fn follow_consecutive_timeouts_exhausted(max_failures: u32, last_detail: &str) -> CliError {
    CliError::Timeout(format!(
        "audit log poll: reached {max_failures} consecutive request timeouts (last: {last_detail})"
    ))
}

/// Write a single audit entry to stdout.
///
/// In JSON mode emits `{"ok": true, "data": <entry>}` — the same envelope as
/// every other command — so that streaming output is consistent with bulk
/// responses.  In text mode emits a human-readable one-line summary.
fn print_entry_line(fmt: &OutputFormat, entry: &AuditEntry) -> Result<(), CliError> {
    let text_line = format!(
        "[{}]  {:20}  {:16}  agent={}  {}  [{}]",
        entry.ts,
        entry.operator,
        entry.action,
        entry.agent_id.map_or_else(|| "-".to_owned(), |id| id.to_string()),
        entry.detail.as_deref().unwrap_or(""),
        entry.result_status,
    );
    print_stream_entry(fmt, entry, &text_line)
}

/// Follow-mode state for the inclusive `since` cursor exposed by the server.
///
/// The teamserver returns entries with `occurred_at >= since`, so the CLI
/// keeps the last seen timestamp plus fingerprints for entries already printed
/// from that timestamp bucket. This prevents re-emitting the tail record while
/// still allowing genuinely new records at the current cursor timestamp.
#[derive(Debug, Default)]
struct FollowCursor {
    since: Option<String>,
    seen_at_cursor: HashSet<String>,
}

impl FollowCursor {
    fn from_printed_entries(entries: &[AuditEntry]) -> Self {
        let Some(latest_ts) = entries.first().map(|entry| entry.ts.clone()) else {
            return Self::default();
        };

        let seen_at_cursor = entries
            .iter()
            .take_while(|entry| entry.ts == latest_ts)
            .map(follow_entry_key)
            .collect();

        Self { since: Some(latest_ts), seen_at_cursor }
    }

    fn since(&self) -> Option<&str> {
        self.since.as_deref()
    }

    fn drain_new_entries<'a>(&mut self, entries: &'a [AuditEntry]) -> Vec<&'a AuditEntry> {
        let mut fresh = Vec::new();

        for entry in entries {
            if self.is_new_entry(entry) {
                fresh.push(entry);
            }
        }

        self.observe_emitted_entries(&fresh);
        fresh
    }

    fn is_new_entry(&self, entry: &AuditEntry) -> bool {
        match self.since.as_deref() {
            None => true,
            Some(cursor) if entry.ts.as_str() > cursor => true,
            Some(cursor) if entry.ts.as_str() == cursor => {
                !self.seen_at_cursor.contains(&follow_entry_key(entry))
            }
            Some(_) => false,
        }
    }

    fn observe_emitted_entries(&mut self, entries: &[&AuditEntry]) {
        let Some(latest_ts) = entries.first().map(|entry| entry.ts.clone()) else {
            return;
        };

        if self.since.as_deref() != Some(latest_ts.as_str()) {
            self.since = Some(latest_ts.clone());
            self.seen_at_cursor.clear();
        }

        for entry in entries.iter().take_while(|entry| entry.ts == latest_ts) {
            self.seen_at_cursor.insert(follow_entry_key(entry));
        }
    }
}

fn follow_entry_key(entry: &AuditEntry) -> String {
    let agent_id = entry.agent_id.map_or_else(String::new, |id| id.to_string());
    format!(
        "{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}",
        entry.ts,
        entry.operator,
        entry.action,
        agent_id,
        entry.detail.as_deref().unwrap_or(""),
        entry.result_status,
    )
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

/// Percent-encode a query-parameter value.
///
/// Characters safe in a URL query string are left unchanged; all others are
/// encoded as `%XX`.  The set of safe characters matches RFC 3986 unreserved
/// characters plus `:` (for ISO 8601 timestamps).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(byte as char)
            }
            b => {
                out.push('%');
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
                out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
            }
        }
    }
    out
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_id(value: u32) -> AgentId {
        AgentId::new(value)
    }
    use crate::output::TextRender as _;

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

    // ── print_entry_line JSON envelope contract ───────────────────────────────
    //
    // `print_entry_line` delegates to `output::print_stream_entry` which writes
    // to real stdout.  We test the envelope contract via the internal
    // `write_stream_entry` helper (which accepts any `io::Write`) to avoid
    // stdout-capture gymnastics.

    fn sample_entry() -> AuditEntry {
        AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "agent.task".to_owned(),
            agent_id: Some(agent_id(0xABC123)),
            detail: Some("whoami".to_owned()),
            result_status: "success".to_owned(),
        }
    }

    fn sample_entry_with(ts: &str, operator: &str, detail: &str) -> AuditEntry {
        AuditEntry {
            ts: ts.to_owned(),
            operator: operator.to_owned(),
            action: "agent.task".to_owned(),
            agent_id: Some(agent_id(0xABC123)),
            detail: Some(detail.to_owned()),
            result_status: "success".to_owned(),
        }
    }

    #[test]
    fn entry_line_json_mode_emits_ok_true_envelope() {
        let entry = sample_entry();
        let text = "[...] alice  agent.task  agent=00ABC123  whoami  [success]".to_owned();
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        crate::output::write_stream_entry(
            &mut out,
            &mut err_out,
            &OutputFormat::Json,
            &entry,
            &text,
        )
        .expect("no write error");

        let line = String::from_utf8(out).expect("utf-8");
        let v: serde_json::Value = serde_json::from_str(line.trim()).expect("single JSON line");
        assert_eq!(v["ok"], true, "ok must be true");
        assert_eq!(v["data"]["ts"], "2026-03-21T12:00:00Z");
        assert_eq!(v["data"]["operator"], "alice");
        assert_eq!(v["data"]["action"], "agent.task");
        assert_eq!(v["data"]["agent_id"], "00ABC123");
        assert_eq!(v["data"]["detail"], "whoami");
        assert_eq!(v["data"]["result_status"], "success");
        assert!(err_out.is_empty());
    }

    #[test]
    fn entry_line_json_mode_data_has_no_bare_fields_at_root() {
        // Verify no audit fields leak into the root of the envelope.
        let entry = sample_entry();
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        crate::output::write_stream_entry(
            &mut out,
            &mut err_out,
            &OutputFormat::Json,
            &entry,
            "ignored",
        )
        .expect("no write error");

        let line = String::from_utf8(out).expect("utf-8");
        let v: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");
        // Root must only have "ok" and "data".
        let obj = v.as_object().expect("root is object");
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert!(keys.contains(&"ok"), "root must have 'ok'");
        assert!(keys.contains(&"data"), "root must have 'data'");
        assert!(!keys.contains(&"ts"), "'ts' must not appear at root level");
        assert!(!keys.contains(&"operator"), "'operator' must not appear at root level");
    }

    #[test]
    fn entry_line_text_mode_contains_key_fields() {
        let entry = sample_entry();
        let agent = entry.agent_id.map_or_else(|| "-".to_owned(), |id| id.to_string());
        let detail = entry.detail.as_deref().unwrap_or("");
        let text_line = format!(
            "[{}]  {:20}  {:16}  agent={}  {}  [{}]",
            entry.ts, entry.operator, entry.action, agent, detail, entry.result_status,
        );
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        crate::output::write_stream_entry(
            &mut out,
            &mut err_out,
            &OutputFormat::Text,
            &entry,
            &text_line,
        )
        .expect("no write error");

        let line = String::from_utf8(out).expect("utf-8");
        assert!(line.contains("alice"), "should contain operator");
        assert!(line.contains("agent.task"), "should contain action");
        assert!(line.contains("00ABC123"), "should contain agent_id");
        assert!(line.contains("whoami"), "should contain detail");
        assert!(line.contains("success"), "should contain result_status");
    }

    // ── follow cursor ────────────────────────────────────────────────────────

    #[test]
    fn follow_cursor_initialises_with_latest_timestamp_bucket() {
        let entries = vec![
            sample_entry_with("2026-03-21T12:00:01Z", "alice", "whoami"),
            sample_entry_with("2026-03-21T12:00:01Z", "bob", "hostname"),
            sample_entry_with("2026-03-21T12:00:00Z", "carol", "pwd"),
        ];

        let cursor = FollowCursor::from_printed_entries(&entries);

        assert_eq!(cursor.since(), Some("2026-03-21T12:00:01Z"));
        assert_eq!(cursor.seen_at_cursor.len(), 2);
        assert!(cursor.seen_at_cursor.contains(&follow_entry_key(&entries[0])));
        assert!(cursor.seen_at_cursor.contains(&follow_entry_key(&entries[1])));
    }

    #[test]
    fn follow_cursor_deduplicates_inclusive_since_bucket() {
        let initial = vec![
            sample_entry_with("2026-03-21T12:00:01Z", "alice", "whoami"),
            sample_entry_with("2026-03-21T12:00:01Z", "bob", "hostname"),
            sample_entry_with("2026-03-21T12:00:00Z", "carol", "pwd"),
        ];
        let mut cursor = FollowCursor::from_printed_entries(&initial);
        let poll = vec![
            sample_entry_with("2026-03-21T12:00:02Z", "dave", "id"),
            sample_entry_with("2026-03-21T12:00:01Z", "erin", "ipconfig"),
            sample_entry_with("2026-03-21T12:00:01Z", "alice", "whoami"),
            sample_entry_with("2026-03-21T12:00:01Z", "bob", "hostname"),
        ];

        let fresh = cursor.drain_new_entries(&poll);

        assert_eq!(fresh.len(), 2);
        assert_eq!(fresh[0].detail.as_deref(), Some("id"));
        assert_eq!(fresh[1].detail.as_deref(), Some("ipconfig"));
        assert_eq!(cursor.since(), Some("2026-03-21T12:00:02Z"));
        assert_eq!(cursor.seen_at_cursor.len(), 1);
        assert!(cursor.seen_at_cursor.contains(&follow_entry_key(&poll[0])));
    }

    #[test]
    fn follow_cursor_steady_state_poll_emits_nothing_and_keeps_cursor() {
        let initial = vec![
            sample_entry_with("2026-03-21T12:00:01Z", "alice", "whoami"),
            sample_entry_with("2026-03-21T12:00:01Z", "bob", "hostname"),
        ];
        let mut cursor = FollowCursor::from_printed_entries(&initial);
        let duplicate_poll = vec![
            sample_entry_with("2026-03-21T12:00:01Z", "alice", "whoami"),
            sample_entry_with("2026-03-21T12:00:01Z", "bob", "hostname"),
        ];

        let fresh = cursor.drain_new_entries(&duplicate_poll);

        assert!(fresh.is_empty());
        assert_eq!(cursor.since(), Some("2026-03-21T12:00:01Z"));
        assert_eq!(cursor.seen_at_cursor.len(), 2);
    }

    // ── percent_encode ────────────────────────────────────────────────────────

    #[test]
    fn percent_encode_leaves_safe_chars_unchanged() {
        assert_eq!(percent_encode("abc123-_.~:"), "abc123-_.~:");
    }

    #[test]
    fn percent_encode_encodes_space() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_encodes_ampersand_and_equals() {
        assert_eq!(percent_encode("a=b&c=d"), "a%3db%26c%3dd");
    }

    #[test]
    fn percent_encode_iso8601_timestamp_unchanged() {
        // Colons in ISO 8601 timestamps must not be encoded.
        assert_eq!(percent_encode("2026-03-21T12:00:00Z"), "2026-03-21T12:00:00Z");
    }

    #[test]
    fn percent_encode_until_timestamp_unchanged() {
        assert_eq!(percent_encode("2026-03-22T23:59:59Z"), "2026-03-22T23:59:59Z");
    }

    #[test]
    fn percent_encode_at_sign_in_operator_name() {
        // @ is not in the safe set and must be encoded.
        let encoded = percent_encode("alice@example.com");
        assert!(encoded.contains('%'));
        assert!(!encoded.contains('@'));
    }

    // ── follow timeout exhaustion ─────────────────────────────────────────────

    #[test]
    fn follow_consecutive_timeouts_exhausted_maps_to_timeout_exit() {
        let err = follow_consecutive_timeouts_exhausted(5, "request to https://x timed out");
        assert!(matches!(err, CliError::Timeout(_)));
        assert_eq!(err.exit_code(), crate::error::EXIT_TIMEOUT);
        let s = err.to_string();
        assert!(s.contains('5'), "message should include max failures: {s}");
        assert!(s.contains("https://x"), "message should include last error detail: {s}");
    }
}
