//! `agent list` — fetch all registered agents and optionally watch for changes.

use std::collections::HashMap;
use std::time::Duration;

use serde::Serialize;
use tokio::time::sleep;
use tracing::{instrument, warn};

use crate::AgentId;
use crate::backoff::Backoff;
use crate::client::ApiClient;
use crate::defaults::AGENT_LIST_WATCH_POLL_INTERVAL_SECS;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_error, print_stream_entry, print_success};

use super::RATE_LIMIT_DEFAULT_WAIT_SECS;
use super::types::AgentSummary;
use super::wire::RawAgent;

/// Map a [`RawAgent`] to a table row for `agent list`.
pub(crate) fn agent_summary_from_raw(r: RawAgent) -> AgentSummary {
    AgentSummary {
        id: r.id,
        hostname: r.hostname,
        os: r.os,
        last_seen: r.last_seen,
        status: r.status,
    }
}

/// `agent list` — fetch all registered agents.
///
/// # Examples
/// ```text
/// red-cell-cli agent list
/// ```
#[instrument(skip(client))]
pub async fn list(client: &ApiClient) -> Result<Vec<AgentSummary>, CliError> {
    let raw: Vec<RawAgent> = client.get("/agents").await?;
    Ok(raw.into_iter().map(agent_summary_from_raw).collect())
}

/// Event emitted by `agent list --watch` when the agent roster changes.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentEvent {
    pub event: &'static str,
    pub agent: AgentSummary,
}

fn render_agent_event_text(ev: &AgentEvent) -> String {
    format!(
        "[{}]  {}  {}  {}  {}",
        ev.event, ev.agent.id, ev.agent.hostname, ev.agent.status, ev.agent.last_seen,
    )
}

fn build_snapshot(agents: &[AgentSummary]) -> HashMap<AgentId, AgentSummary> {
    agents.iter().map(|a| (a.id, a.clone())).collect()
}

fn diff_agents(prev: &HashMap<AgentId, AgentSummary>, current: &[AgentSummary]) -> Vec<AgentEvent> {
    let current_map: HashMap<AgentId, &AgentSummary> = current.iter().map(|a| (a.id, a)).collect();
    let mut events = Vec::new();

    for agent in current {
        match prev.get(&agent.id) {
            None => events.push(AgentEvent { event: "checkin", agent: agent.clone() }),
            Some(old) if old.status != agent.status => {
                events.push(AgentEvent { event: "status_change", agent: agent.clone() });
            }
            _ => {}
        }
    }

    for (id, old_agent) in prev {
        if !current_map.contains_key(id) {
            events.push(AgentEvent { event: "disconnect", agent: old_agent.clone() });
        }
    }

    events
}

fn watch_timeout_exhausted(max_failures: u32, last_detail: &str) -> CliError {
    CliError::Timeout(format!(
        "agent list --watch: reached {max_failures} consecutive request timeouts (last: {last_detail})"
    ))
}

/// `agent list --watch` — print the initial roster then stream change events.
#[instrument(skip(client, fmt), fields(max_failures = max_failures))]
pub(crate) async fn watch_agents(client: &ApiClient, fmt: &OutputFormat, max_failures: u32) -> i32 {
    let mut backoff = Backoff::with_initial_delay(AGENT_LIST_WATCH_POLL_INTERVAL_SECS);
    let mut consecutive_timeouts = 0u32;

    let initial = loop {
        let result = tokio::select! {
            r = list(client) => r,
            _ = tokio::signal::ctrl_c() => return EXIT_SUCCESS,
        };
        match result {
            Ok(agents) => break agents,
            Err(CliError::Timeout(msg)) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                warn!(
                    attempt = consecutive_timeouts,
                    max_failures,
                    error = %msg,
                    "agent list --watch: timed out fetching initial snapshot; retrying"
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

    let mut snapshot = build_snapshot(&initial);

    loop {
        let poll_result = tokio::select! {
            r = list(client) => r,
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
                    "agent list --watch: timed out; retrying"
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
            Ok(current) => {
                consecutive_timeouts = 0;
                let events = diff_agents(&snapshot, &current);
                if events.is_empty() {
                    backoff.record_empty();
                } else {
                    backoff.record_non_empty();
                    for ev in &events {
                        if let Err(e) = print_stream_entry(fmt, ev, &render_agent_event_text(ev)) {
                            print_error(&e).ok();
                            return e.exit_code();
                        }
                    }
                }
                snapshot = build_snapshot(&current);
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

    fn agent(id: u32, status: &str) -> AgentSummary {
        AgentSummary {
            id: AgentId::new(id),
            hostname: "host".to_owned(),
            os: "Windows".to_owned(),
            last_seen: "2026-01-01T00:00:00Z".to_owned(),
            status: status.to_owned(),
        }
    }

    #[test]
    fn diff_detects_new_agent() {
        let snapshot = build_snapshot(&[agent(1, "alive")]);
        let current = vec![agent(1, "alive"), agent(2, "alive")];
        let events = diff_agents(&snapshot, &current);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "checkin");
        assert_eq!(events[0].agent.id, AgentId::new(2));
    }

    #[test]
    fn diff_detects_removed_agent() {
        let snapshot = build_snapshot(&[agent(1, "alive"), agent(2, "alive")]);
        let current = vec![agent(1, "alive")];
        let events = diff_agents(&snapshot, &current);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "disconnect");
        assert_eq!(events[0].agent.id, AgentId::new(2));
    }

    #[test]
    fn diff_detects_status_change() {
        let snapshot = build_snapshot(&[agent(1, "alive")]);
        let current = vec![agent(1, "dead")];
        let events = diff_agents(&snapshot, &current);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "status_change");
        assert_eq!(events[0].agent.status, "dead");
    }

    #[test]
    fn diff_no_change_produces_empty_events() {
        let snapshot = build_snapshot(&[agent(1, "alive"), agent(2, "alive")]);
        let current = vec![agent(1, "alive"), agent(2, "alive")];
        let events = diff_agents(&snapshot, &current);
        assert!(events.is_empty());
    }

    #[test]
    fn diff_empty_to_nonempty_all_checkins() {
        let snapshot: HashMap<AgentId, AgentSummary> = HashMap::new();
        let current = vec![agent(1, "alive"), agent(2, "alive")];
        let events = diff_agents(&snapshot, &current);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.event == "checkin"));
    }

    #[test]
    fn diff_nonempty_to_empty_all_disconnects() {
        let snapshot = build_snapshot(&[agent(1, "alive"), agent(2, "alive")]);
        let current: Vec<AgentSummary> = vec![];
        let events = diff_agents(&snapshot, &current);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.event == "disconnect"));
    }

    #[test]
    fn render_agent_event_text_contains_event_and_id() {
        let ev = AgentEvent { event: "checkin", agent: agent(0xDEAD, "alive") };
        let text = render_agent_event_text(&ev);
        assert!(text.contains("checkin"));
        assert!(text.contains("0000DEAD"));
    }

    #[test]
    fn watch_timeout_exhausted_is_timeout_error() {
        let err = watch_timeout_exhausted(5, "connection refused");
        assert!(matches!(err, CliError::Timeout(_)));
        assert_eq!(err.exit_code(), crate::error::EXIT_TIMEOUT);
        let msg = err.to_string();
        assert!(msg.contains('5'));
        assert!(msg.contains("connection refused"));
    }
}
