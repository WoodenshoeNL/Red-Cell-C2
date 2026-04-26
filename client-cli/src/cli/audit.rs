use clap::Subcommand;

use crate::AgentId;

/// Audit log subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommands {
    /// List audit log entries (newest first).
    ///
    /// With --follow, prints the initial list then streams new entries
    /// matching the given filters as JSON-Lines until Ctrl-C.
    ///
    /// Examples:
    ///   red-cell-cli log list
    ///   red-cell-cli log list --operator alice --limit 50
    ///   red-cell-cli log list --action exec
    ///   red-cell-cli log list --since 2026-03-21T00:00:00Z --agent abc123
    ///   red-cell-cli log list --since 2026-03-21T00:00:00Z --until 2026-03-22T00:00:00Z
    ///   red-cell-cli log list --follow --action exec
    ///   red-cell-cli log list --follow --operator alice
    #[command(verbatim_doc_comment)]
    List {
        /// Filter by operator username
        #[arg(long)]
        operator: Option<String>,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<AgentId>,
        /// Only return entries at or after this ISO 8601 UTC timestamp
        #[arg(long)]
        since: Option<String>,
        /// Only return entries at or before this ISO 8601 UTC timestamp
        #[arg(long)]
        until: Option<String>,
        /// Maximum entries to return (initial fetch only when combined with --follow)
        #[arg(long, default_value = "100")]
        limit: u32,
        /// Stream new entries as JSON-Lines until Ctrl-C (filters still apply).
        #[arg(long, help = crate::defaults::audit_list_follow_help())]
        follow: bool,
        /// Exit with timeout (code 5) after this many consecutive HTTP request
        /// timeouts while polling (only applies with `--follow`).
        #[arg(
            long,
            default_value_t = crate::defaults::WATCH_MAX_FAILURES_DEFAULT,
            value_parser = clap::value_parser!(u32).range(1..=1024)
        )]
        max_failures: u32,
    },

    /// Delete audit log entries older than the configured retention period.
    ///
    /// When `--older-than-days` is omitted, the teamserver uses the value
    /// configured in its HCL profile (default: 90 days).
    ///
    /// Examples:
    ///   red-cell-cli log purge --confirm
    ///   red-cell-cli log purge --confirm --older-than-days 30
    #[command(verbatim_doc_comment)]
    Purge {
        /// Required confirmation flag — prevents accidental data loss.
        #[arg(long)]
        confirm: bool,
        /// Override the retention window for this purge (in days).
        #[arg(long)]
        older_than_days: Option<u32>,
    },

    /// Stream new audit log entries as they arrive.
    ///
    /// Prints the last 20 entries.  With --follow, streams new entries as
    /// JSON lines until Ctrl-C.
    ///
    /// Examples:
    ///   red-cell-cli log tail
    ///   red-cell-cli log tail --follow
    ///   red-cell-cli log tail --follow --max-failures 10
    #[command(verbatim_doc_comment)]
    Tail {
        #[arg(long, help = crate::defaults::audit_tail_follow_help())]
        follow: bool,
        /// Exit with timeout (code 5) after this many consecutive HTTP request
        /// timeouts while polling (only applies with `--follow`). Transient
        /// timeouts are retried with exponential backoff; each retry logs a
        /// warning to stderr.
        #[arg(
            long,
            default_value_t = crate::defaults::AUDIT_TAIL_FOLLOW_MAX_FAILURES_DEFAULT,
            value_parser = clap::value_parser!(u32).range(1..=1024)
        )]
        max_failures: u32,
    },

    /// Fetch recent teamserver log output.
    ///
    /// Retrieves log messages from the teamserver's in-memory ring buffer
    /// via the /api/v1/debug/server-logs endpoint.
    ///
    /// Examples:
    ///   red-cell-cli log server-tail
    ///   red-cell-cli log server-tail --lines 200
    ///   red-cell-cli log server-tail --lines 50
    #[command(verbatim_doc_comment)]
    ServerTail {
        /// Maximum number of log lines to return (most-recent last).
        #[arg(long, default_value_t = 200)]
        lines: u32,
    },
}
