//! Follow-mode state, rendering helpers, and streaming loops for
//! `log tail --follow` and `log list --follow`.

use std::collections::HashSet;
use std::time::Duration;

use tokio::time::sleep;
use tracing::{instrument, warn};

use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::{
    AUDIT_LIST_FOLLOW_POLL_INTERVAL_SECS, AUDIT_TAIL_FOLLOW_POLL_INTERVAL_SECS,
    RATE_LIMIT_DEFAULT_WAIT_SECS,
};
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_error, print_stream_entry};

use super::list::list;
use super::types::AuditEntry;

/// Number of entries fetched by `log tail` (without --follow).
pub(super) const TAIL_LIMIT: u32 = 20;

/// Error returned when a follow loop has seen `max_failures` consecutive HTTP timeouts.
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
pub(super) fn print_entry_line(fmt: &OutputFormat, entry: &AuditEntry) -> Result<(), CliError> {
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
pub(super) struct FollowCursor {
    since: Option<String>,
    seen_at_cursor: HashSet<String>,
}

impl FollowCursor {
    pub(super) fn from_printed_entries(entries: &[AuditEntry]) -> Self {
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

    pub(super) fn since(&self) -> Option<&str> {
        self.since.as_deref()
    }

    pub(super) fn drain_new_entries<'a>(
        &mut self,
        entries: &'a [AuditEntry],
    ) -> Vec<&'a AuditEntry> {
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

// ── follow loops ─────────────────────────────────────────────────────────────

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
pub(super) async fn tail_follow(client: &ApiClient, fmt: &OutputFormat, max_failures: u32) -> i32 {
    let mut backoff = Backoff::with_initial_delay(AUDIT_TAIL_FOLLOW_POLL_INTERVAL_SECS);
    let mut consecutive_timeouts = 0u32;

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

    for entry in &initial_entries {
        if let Err(e) = print_entry_line(fmt, entry) {
            print_error(&e).ok();
            return e.exit_code();
        }
    }
    let mut cursor = FollowCursor::from_printed_entries(&initial_entries);

    loop {
        let poll_result = tokio::select! {
            result = list(client, 100, cursor.since(), None, None, None, None) => result,
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
pub(super) async fn list_follow(
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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentId;
    use crate::commands::audit::types::AuditEntry;
    use crate::output::OutputFormat;

    fn agent_id(value: u32) -> AgentId {
        AgentId::new(value)
    }

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

    // ── print_entry_line JSON envelope contract ───────────────────────────────

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

    // ── follow cursor ─────────────────────────────────────────────────────────

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
