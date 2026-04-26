//! `red-cell-cli loot` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `loot list [filters]` | `GET /api/v1/loot?...` | paginated, filterable |
//! | `loot download <id> --out <path>` | `GET /api/v1/loot/{id}` | save bytes to disk |
//! | `loot export --format csv\|jsonl` | `GET /api/v1/loot?...` | flat export; without `--file`, payload → stdout, metadata JSON → stderr |

mod export;
mod list;
mod types;
mod watch;

use types::LootDownloadResult;

use crate::LootCommands;
use crate::client::ApiClient;
use crate::error::EXIT_SUCCESS;
use crate::output::{OutputFormat, print_error, print_success, print_success_metadata_stderr};

/// Dispatch a [`LootCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: LootCommands) -> i32 {
    match action {
        LootCommands::List { kind, agent, operator, since, limit, watch, max_failures } => {
            if watch {
                watch::watch_loot(
                    client,
                    fmt,
                    limit,
                    since.as_deref(),
                    kind.as_deref(),
                    agent,
                    operator.as_deref(),
                    max_failures,
                )
                .await
            } else {
                match list::list(
                    client,
                    limit,
                    since.as_deref(),
                    kind.as_deref(),
                    agent,
                    operator.as_deref(),
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

        LootCommands::Download { id, out } => match list::download(client, id, &out).await {
            Ok(bytes) => match print_success(fmt, &LootDownloadResult { id, saved: out, bytes }) {
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

        LootCommands::Export { format, file, kind, agent, operator, since, limit } => {
            match export::export(
                client,
                &format,
                file.as_deref(),
                limit,
                since.as_deref(),
                kind.as_deref(),
                agent,
                operator.as_deref(),
            )
            .await
            {
                Ok(result) => {
                    let print = if result.destination == "stdout" {
                        print_success_metadata_stderr(fmt, &result)
                    } else {
                        print_success(fmt, &result)
                    };
                    match print {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    }
                }
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }
    }
}
