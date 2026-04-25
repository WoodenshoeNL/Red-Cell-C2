//! Shared default values for `red-cell-cli` polling loops and help text.

use std::sync::OnceLock;

/// Default end-to-end polling timeout for `agent exec --wait`, in seconds.
pub const AGENT_EXEC_WAIT_TIMEOUT_SECS: u64 = 60;

/// Default end-to-end polling timeout for `payload build --wait`, in seconds.
pub const PAYLOAD_BUILD_WAIT_TIMEOUT_SECS: u64 = 300;

/// Default initial polling interval for `log tail --follow`, in seconds.
pub const AUDIT_TAIL_FOLLOW_POLL_INTERVAL_SECS: u64 = 1;

/// Default number of consecutive HTTP request timeouts before `log tail --follow`
/// exits with code 5 ([`EXIT_TIMEOUT`][crate::error::EXIT_TIMEOUT]).
pub const AUDIT_TAIL_FOLLOW_MAX_FAILURES_DEFAULT: u32 = 5;

/// Default consecutive-timeout threshold shared by `--watch` / `--follow` on
/// list commands (`agent list`, `loot list`, `log list`).
pub const WATCH_MAX_FAILURES_DEFAULT: u32 = 5;

/// Default sleep duration (seconds) when the server returns HTTP 429 without
/// a `Retry-After` header.
pub const RATE_LIMIT_DEFAULT_WAIT_SECS: u64 = 10;

/// Default initial polling interval for `agent list --watch`, in seconds.
pub const AGENT_LIST_WATCH_POLL_INTERVAL_SECS: u64 = 2;

/// Default initial polling interval for `loot list --watch`, in seconds.
pub const LOOT_LIST_WATCH_POLL_INTERVAL_SECS: u64 = 2;

/// Default initial polling interval for `log list --follow`, in seconds.
pub const AUDIT_LIST_FOLLOW_POLL_INTERVAL_SECS: u64 = 1;

static AGENT_EXEC_WAIT_TIMEOUT_HELP: OnceLock<String> = OnceLock::new();
static PAYLOAD_BUILD_WAIT_TIMEOUT_HELP: OnceLock<String> = OnceLock::new();
static AUDIT_TAIL_FOLLOW_HELP: OnceLock<String> = OnceLock::new();
static AGENT_LIST_WATCH_HELP: OnceLock<String> = OnceLock::new();
static LOOT_LIST_WATCH_HELP: OnceLock<String> = OnceLock::new();
static AUDIT_LIST_FOLLOW_HELP: OnceLock<String> = OnceLock::new();

/// Return the `--wait-timeout` help text for `agent exec`.
pub fn agent_exec_wait_timeout_help() -> &'static str {
    AGENT_EXEC_WAIT_TIMEOUT_HELP.get_or_init(|| {
        format!(
            "Poll for up to {secs} seconds (default: {secs}; override with --wait-timeout). Controls the polling loop budget, not the per-request HTTP timeout (--timeout).",
            secs = AGENT_EXEC_WAIT_TIMEOUT_SECS
        )
    })
}

/// Return the `--wait-timeout` help text for `payload build`.
pub fn payload_build_wait_timeout_help() -> &'static str {
    PAYLOAD_BUILD_WAIT_TIMEOUT_HELP.get_or_init(|| {
        format!(
            "Poll for up to {secs} seconds (default: {secs}; override with --wait-timeout). Controls the polling loop budget, not the per-request HTTP timeout (--timeout).",
            secs = PAYLOAD_BUILD_WAIT_TIMEOUT_SECS
        )
    })
}

/// Return the `--follow` help text for `log tail`.
pub fn audit_tail_follow_help() -> &'static str {
    AUDIT_TAIL_FOLLOW_HELP.get_or_init(|| {
        format!(
            "Stream new entries as they arrive (prints JSON lines until Ctrl-C). Polls every {secs} second initially (default: {secs}; exponential backoff applies while idle).",
            secs = AUDIT_TAIL_FOLLOW_POLL_INTERVAL_SECS
        )
    })
}

/// Return the `--watch` help text for `agent list`.
pub fn agent_list_watch_help() -> &'static str {
    AGENT_LIST_WATCH_HELP.get_or_init(|| {
        format!(
            "Stream agent roster changes (checkin/disconnect/status_change) as JSON-Lines until Ctrl-C. Polls every {secs} seconds initially (default: {secs}; exponential backoff while idle).",
            secs = AGENT_LIST_WATCH_POLL_INTERVAL_SECS
        )
    })
}

/// Return the `--watch` help text for `loot list`.
pub fn loot_list_watch_help() -> &'static str {
    LOOT_LIST_WATCH_HELP.get_or_init(|| {
        format!(
            "Stream new loot entries as JSON-Lines until Ctrl-C. Polls every {secs} seconds initially (default: {secs}; exponential backoff while idle).",
            secs = LOOT_LIST_WATCH_POLL_INTERVAL_SECS
        )
    })
}

/// Return the `--follow` help text for `log list`.
pub fn audit_list_follow_help() -> &'static str {
    AUDIT_LIST_FOLLOW_HELP.get_or_init(|| {
        format!(
            "Stream new entries matching the given filters as JSON-Lines until Ctrl-C. Polls every {secs} second initially (default: {secs}; exponential backoff while idle).",
            secs = AUDIT_LIST_FOLLOW_POLL_INTERVAL_SECS
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_exec_help_mentions_default_timeout() {
        assert!(agent_exec_wait_timeout_help().contains("default: 60"));
    }

    #[test]
    fn payload_build_help_mentions_default_timeout() {
        assert!(payload_build_wait_timeout_help().contains("default: 300"));
    }

    #[test]
    fn audit_tail_help_mentions_default_poll_interval() {
        assert!(audit_tail_follow_help().contains("default: 1"));
    }

    #[test]
    fn agent_list_watch_help_mentions_default_poll_interval() {
        assert!(agent_list_watch_help().contains("default: 2"));
    }

    #[test]
    fn loot_list_watch_help_mentions_default_poll_interval() {
        assert!(loot_list_watch_help().contains("default: 2"));
    }

    #[test]
    fn audit_list_follow_help_mentions_default_poll_interval() {
        assert!(audit_list_follow_help().contains("default: 1"));
    }

    #[test]
    fn rate_limit_default_wait_is_stable() {
        assert_eq!(RATE_LIMIT_DEFAULT_WAIT_SECS, 10);
    }
}
