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
mod list;
mod server_logs;
mod types;

#[allow(unused_imports)]
pub use types::{AuditEntry, PurgeResult, ServerLogEntry};

use crate::AuditCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_error, print_success};

use follow::TAIL_LIMIT;

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
                follow::list_follow(
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
                match list::list(
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
            match list::purge(client, older_than_days).await {
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
                follow::tail_follow(client, fmt, max_failures).await
            } else {
                match list::list(client, TAIL_LIMIT, None, None, None, None, None).await {
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

        AuditCommands::ServerTail { lines } => {
            match server_logs::server_tail(client, lines).await {
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
}
