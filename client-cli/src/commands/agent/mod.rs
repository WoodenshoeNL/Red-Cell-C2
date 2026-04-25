//! `red-cell-cli agent` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `agent list` | `GET /agents` | table of all agents |
//! | `agent show <id>` | `GET /agents/{id}` | full agent record |
//! | `agent exec <id> --cmd <cmd>` | `POST /agents/{id}/task` | submit task |
//! | `agent exec --wait` | `POST /agents/{id}/task` then poll `/output` | block |
//! | `agent shell <id>` | repeated `exec --wait` via rustyline REPL | interactive |
//! | `agent output <id>` | `GET /agents/{id}/output` | persisted output |
//! | `agent kill <id>` | `DELETE /agents/{id}` | terminate |
//! | `agent kill --wait` | kill then poll `GET /agents/{id}` until dead | block |
//! | `agent upload <id>` | `POST /agents/{id}/upload` | queue upload task |
//! | `agent download <id>` | `POST /agents/{id}/download` | queue download task |
//! | `agent groups <id>` | `GET /agents/{id}/groups` | RBAC group tags on the agent |
//! | `agent set-groups <id>` | `PUT /agents/{id}/groups` | replace group membership |

pub(crate) mod exec;
pub(crate) mod groups;
pub(crate) mod kill;
pub(crate) mod list;
pub(crate) mod output_cmd;
pub(crate) mod shell;
pub(crate) mod show;
pub(crate) mod transfer;
pub(crate) mod types;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

/// Default sleep duration (seconds) when the server returns HTTP 429 without
/// a `Retry-After` header.
pub(crate) const RATE_LIMIT_DEFAULT_WAIT_SECS: u64 = 10;

use crate::AgentCommands;
use crate::client::ApiClient;
use crate::defaults::AGENT_EXEC_WAIT_TIMEOUT_SECS;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_cursor_reset_warning, print_error, print_success};

use self::exec::{exec_submit, exec_wait};
use self::groups::{get_groups, set_groups};
use self::kill::kill;
use self::list::list;
use self::output_cmd::{fetch_output, take_cursor_reset_warning, watch_output};
use self::show::show;
use self::transfer::{download, upload};

/// Dispatch an [`AgentCommands`] variant and return a process exit code.
///
/// All output (success and error) is written inside this function so that the
/// caller in `main.rs` only needs to propagate the exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: AgentCommands) -> i32 {
    match action {
        AgentCommands::List => match list(client).await {
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

        AgentCommands::Show { id } => match show(client, id).await {
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

        AgentCommands::Exec { id, cmd, wait, wait_timeout } => {
            let timeout_secs = wait_timeout.unwrap_or(AGENT_EXEC_WAIT_TIMEOUT_SECS);
            if wait {
                match exec_wait(client, id, &cmd, timeout_secs).await {
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
            } else {
                match exec_submit(client, id, &cmd).await {
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

        AgentCommands::Shell { id, timeout } => shell::run(client, id, timeout).await,

        AgentCommands::Output { id, watch, since } => {
            if watch {
                watch_output(client, fmt, id, since).await
            } else {
                match fetch_output(client, id, since).await {
                    Ok(data) => {
                        let mut warned_cursor_reset = false;
                        if data.is_empty() {
                            if let Some(missed) =
                                take_cursor_reset_warning(since, false, &mut warned_cursor_reset)
                            {
                                if let Err(e) = print_cursor_reset_warning(missed) {
                                    print_error(&CliError::Io(e.to_string())).ok();
                                    return EXIT_GENERAL;
                                }
                            }
                        }
                        match print_success(fmt, &data) {
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

        AgentCommands::Kill { id, wait } => match kill(client, id, wait).await {
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

        AgentCommands::Upload { id, src, dst, max_upload_mb } => {
            match upload(client, id, &src, &dst, max_upload_mb).await {
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

        AgentCommands::Download { id, src, dst } => match download(client, id, &src, &dst).await {
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

        AgentCommands::Groups { id } => match get_groups(client, id).await {
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

        AgentCommands::SetGroups { id, group } => match set_groups(client, id, &group).await {
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
