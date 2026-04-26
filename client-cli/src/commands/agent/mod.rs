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
//! | `agent shell <id> --unsafe-tty` | repeated `exec --wait` via rustyline REPL | interactive, raw stdout |
//! | `agent output <id>` | `GET /agents/{id}/output` | persisted output |
//! | `agent kill <id>` | `DELETE /agents/{id}` | queue kill task |
//! | `agent kill --wait` | kill then poll `GET /agents/{id}` until dead | block |
//! | `agent kill --force` | `DELETE /agents/{id}?force=true` | kill + deregister |
//! | `agent kill --deregister-only` | `DELETE /agents/{id}?deregister_only=true` | deregister only |
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

use crate::AgentCommands;
use crate::client::ApiClient;
use crate::defaults::AGENT_EXEC_WAIT_TIMEOUT_SECS;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_cursor_reset_warning, print_error, print_success};

use self::exec::{exec_submit, exec_wait};
use self::groups::{get_groups, set_groups};
use self::kill::{KillMode, kill};
use self::list::{list, watch_agents};
use self::output_cmd::{fetch_output, take_cursor_reset_warning, watch_output};
use self::show::show;
use self::transfer::{download, upload};

/// Dispatch an [`AgentCommands`] variant and return a process exit code.
///
/// All output (success and error) is written inside this function so that the
/// caller in `main.rs` only needs to propagate the exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: AgentCommands) -> i32 {
    match action {
        AgentCommands::List { watch, max_failures } => {
            if watch {
                watch_agents(client, fmt, max_failures).await
            } else {
                match list(client).await {
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

        AgentCommands::Shell { id, timeout, unsafe_tty, enable_local_shell } => {
            if !unsafe_tty {
                let err = CliError::InvalidArgs(
                    "agent shell requires --unsafe-tty because it uses interactive I/O \
                     and raw stdout (not the JSON envelope). For machine-consumable \
                     interaction, use `session --agent <id>` instead."
                        .to_owned(),
                );
                print_error(&err).ok();
                return err.exit_code();
            }
            let local_shell = enable_local_shell || crate::config::resolve_enable_local_shell();
            let operator = match resolve_operator_name(client).await {
                Ok(name) => name,
                Err(e) => {
                    print_error(&e).ok();
                    return e.exit_code();
                }
            };
            shell::run(client, id, timeout, local_shell, &operator).await
        }

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

        AgentCommands::Kill { id, wait, force, deregister_only } => {
            let mode = if deregister_only {
                KillMode::DeregisterOnly
            } else if force {
                KillMode::Force
            } else if wait {
                KillMode::Wait
            } else {
                KillMode::Default
            };
            match kill(client, id, mode).await {
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

// ── helpers ──────────────────────────────────────────────────────────────────

/// Minimal wire type for `GET /operators/whoami` — only the `name` field.
#[derive(serde::Deserialize)]
struct WhoamiName {
    name: String,
}

/// Resolve the operator name for the current API token via the whoami endpoint.
async fn resolve_operator_name(client: &ApiClient) -> Result<String, CliError> {
    let resp: WhoamiName = client.get("/operators/whoami").await?;
    Ok(resp.name)
}
