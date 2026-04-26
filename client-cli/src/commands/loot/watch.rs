//! `loot list --watch` — streaming follow mode for loot entries.

use std::collections::HashSet;
use std::time::Duration;

use tokio::time::sleep;
use tracing::{instrument, warn};

use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::{LOOT_LIST_WATCH_POLL_INTERVAL_SECS, RATE_LIMIT_DEFAULT_WAIT_SECS};
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_error, print_stream_entry, print_success};

use super::list::list;
use super::types::LootEntry;

fn watch_timeout_exhausted(max_failures: u32, last_detail: &str) -> CliError {
    CliError::Timeout(format!(
        "loot list --watch: reached {max_failures} consecutive request timeouts (last: {last_detail})"
    ))
}

fn render_loot_stream_text(entry: &LootEntry) -> String {
    format!(
        "[loot #{}]  {}  {}  agent={}  {}",
        entry.id, entry.kind, entry.name, entry.agent_id, entry.captured_at,
    )
}

/// Follow-mode state for loot entries.
///
/// Tracks seen entry IDs at the cursor timestamp to deduplicate inclusive
/// `since` results — same pattern as `audit::follow::FollowCursor`.
#[derive(Debug, Default)]
struct LootFollowCursor {
    since: Option<String>,
    seen_ids: HashSet<i64>,
}

impl LootFollowCursor {
    fn from_entries(entries: &[LootEntry]) -> Self {
        if entries.is_empty() {
            return Self::default();
        }
        let latest_ts = entries.iter().map(|e| e.captured_at.as_str()).max().map(str::to_owned);
        let seen_ids = entries
            .iter()
            .filter(|e| Some(e.captured_at.as_str()) == latest_ts.as_deref())
            .map(|e| e.id)
            .collect();
        Self { since: latest_ts, seen_ids }
    }

    fn since(&self) -> Option<&str> {
        self.since.as_deref()
    }

    fn drain_new_entries<'a>(&mut self, entries: &'a [LootEntry]) -> Vec<&'a LootEntry> {
        let fresh: Vec<&LootEntry> = entries
            .iter()
            .filter(|e| match self.since.as_deref() {
                None => true,
                Some(cursor) if e.captured_at.as_str() > cursor => true,
                Some(cursor) if e.captured_at.as_str() == cursor => !self.seen_ids.contains(&e.id),
                _ => false,
            })
            .collect();

        if let Some(latest_ts) = fresh.iter().map(|e| e.captured_at.as_str()).max() {
            if self.since.as_deref() != Some(latest_ts) {
                self.since = Some(latest_ts.to_owned());
                self.seen_ids.clear();
            }
            for e in fresh.iter().filter(|e| e.captured_at.as_str() == latest_ts) {
                self.seen_ids.insert(e.id);
            }
        }

        fresh
    }
}

/// `loot list --watch` — print the initial entries then stream new ones.
#[instrument(
    skip(client, fmt, since, kind, operator),
    fields(max_failures = max_failures)
)]
pub(super) async fn watch_loot(
    client: &ApiClient,
    fmt: &OutputFormat,
    limit: Option<u32>,
    since: Option<&str>,
    kind: Option<&str>,
    agent_id: Option<AgentId>,
    operator: Option<&str>,
    max_failures: u32,
) -> i32 {
    let mut backoff = Backoff::with_initial_delay(LOOT_LIST_WATCH_POLL_INTERVAL_SECS);
    let mut consecutive_timeouts = 0u32;

    let initial = loop {
        let result = tokio::select! {
            r = list(client, limit, since, kind, agent_id, operator) => r,
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
                    "loot list --watch: timed out fetching initial snapshot; retrying"
                );
                if consecutive_timeouts >= max_failures {
                    let err = watch_timeout_exhausted(max_failures, &msg);
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

    if let Err(e) = print_success(fmt, &initial) {
        print_error(&e).ok();
        return e.exit_code();
    }

    let mut cursor = LootFollowCursor::from_entries(&initial);

    loop {
        let poll_result = tokio::select! {
            r = list(client, None, cursor.since(), kind, agent_id, operator) => r,
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
                    "loot list --watch: timed out; retrying"
                );
                if consecutive_timeouts >= max_failures {
                    let err = watch_timeout_exhausted(max_failures, &msg);
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
                    for entry in &fresh {
                        if let Err(e) =
                            print_stream_entry(fmt, *entry, &render_loot_stream_text(entry))
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
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentId;

    fn sample_loot_entry(id: i64, captured_at: &str) -> LootEntry {
        LootEntry {
            id,
            agent_id: AgentId::new(0xDEAD),
            kind: "screenshot".to_owned(),
            name: format!("item_{id}"),
            file_path: None,
            size_bytes: Some(1024),
            captured_at: captured_at.to_owned(),
            has_data: true,
            operator: None,
        }
    }

    #[test]
    fn loot_cursor_from_empty_entries() {
        let cursor = LootFollowCursor::from_entries(&[]);
        assert!(cursor.since().is_none());
        assert!(cursor.seen_ids.is_empty());
    }

    #[test]
    fn loot_cursor_from_entries_uses_max_timestamp() {
        let entries = vec![
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
            sample_loot_entry(2, "2026-01-01T13:00:00Z"),
            sample_loot_entry(3, "2026-01-01T12:30:00Z"),
        ];
        let cursor = LootFollowCursor::from_entries(&entries);
        assert_eq!(cursor.since(), Some("2026-01-01T13:00:00Z"));
        assert!(cursor.seen_ids.contains(&2));
        assert_eq!(cursor.seen_ids.len(), 1);
    }

    #[test]
    fn loot_cursor_deduplicates_same_timestamp_entries() {
        let entries = vec![
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
        ];
        let cursor = LootFollowCursor::from_entries(&entries);
        assert_eq!(cursor.since(), Some("2026-01-01T12:00:00Z"));
        assert_eq!(cursor.seen_ids.len(), 2);
    }

    #[test]
    fn loot_cursor_drain_new_detects_new_entries() {
        let initial = vec![
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
        ];
        let mut cursor = LootFollowCursor::from_entries(&initial);

        let poll = vec![
            sample_loot_entry(3, "2026-01-01T13:00:00Z"),
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
        ];
        let fresh = cursor.drain_new_entries(&poll);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, 3);
        assert_eq!(cursor.since(), Some("2026-01-01T13:00:00Z"));
    }

    #[test]
    fn loot_cursor_drain_no_new_returns_empty() {
        let initial = vec![sample_loot_entry(1, "2026-01-01T12:00:00Z")];
        let mut cursor = LootFollowCursor::from_entries(&initial);
        let poll = vec![sample_loot_entry(1, "2026-01-01T12:00:00Z")];
        let fresh = cursor.drain_new_entries(&poll);
        assert!(fresh.is_empty());
    }

    #[test]
    fn loot_cursor_drain_new_at_same_timestamp_different_id() {
        let initial = vec![sample_loot_entry(1, "2026-01-01T12:00:00Z")];
        let mut cursor = LootFollowCursor::from_entries(&initial);
        let poll = vec![
            sample_loot_entry(2, "2026-01-01T12:00:00Z"),
            sample_loot_entry(1, "2026-01-01T12:00:00Z"),
        ];
        let fresh = cursor.drain_new_entries(&poll);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, 2);
    }

    #[test]
    fn render_loot_stream_text_contains_key_fields() {
        let entry = sample_loot_entry(42, "2026-01-01T12:00:00Z");
        let text = render_loot_stream_text(&entry);
        assert!(text.contains("42"));
        assert!(text.contains("screenshot"));
        assert!(text.contains("0000DEAD"));
    }

    #[test]
    fn watch_timeout_exhausted_is_timeout_error() {
        let err = watch_timeout_exhausted(3, "connection refused");
        assert!(matches!(err, CliError::Timeout(_)));
        assert_eq!(err.exit_code(), crate::error::EXIT_TIMEOUT);
        let msg = err.to_string();
        assert!(msg.contains('3'));
        assert!(msg.contains("connection refused"));
    }
}
