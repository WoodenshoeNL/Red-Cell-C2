//! `red-cell-cli operator` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `operator list` | `GET /operators` | table of all operators |
//! | `operator create <name> --role <role>` | `POST /operators` | prints username and assigned role |
//! | `operator delete <name>` | `DELETE /operators/{username}` | hard delete |
//! | `operator set-role <name> <role>` | `PUT /operators/{username}/role` | role update |
//! | `operator show-agent-groups <name>` | `GET /operators/{username}/agent-groups` | allowed agent groups |
//! | `operator set-agent-groups <name>` | `PUT /operators/{username}/agent-groups` | replace group restrictions |
//! | `operator active` | `GET /operators/active` | currently connected operators |
//! | `operator logout <name>` | `POST /operators/{username}/logout` | revoke active sessions |

pub(crate) mod handlers;
pub(crate) mod types;

#[cfg(test)]
mod tests;

use crate::OperatorCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, print_error, print_success};

use self::handlers::{
    active, create, delete, get_operator_agent_groups, list, logout, set_operator_agent_groups,
    set_role,
};

// ── valid roles ───────────────────────────────────────────────────────────────

const VALID_ROLES: &[&str] = &["admin", "operator", "analyst"];

pub(crate) fn validate_role(role: &str) -> Result<(), CliError> {
    if VALID_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(CliError::InvalidArgs(format!(
            "unknown role '{role}': expected admin, operator, or analyst"
        )))
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch an [`OperatorCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: OperatorCommands) -> i32 {
    match action {
        OperatorCommands::List => match list(client).await {
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

        OperatorCommands::Create { username, password, role } => {
            match create(client, &username, &password, &role).await {
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

        OperatorCommands::Delete { username } => match delete(client, &username).await {
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
        },

        OperatorCommands::SetRole { username, role } => {
            match set_role(client, &username, &role).await {
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

        OperatorCommands::ShowAgentGroups { username } => {
            match get_operator_agent_groups(client, &username).await {
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

        OperatorCommands::SetAgentGroups { username, group } => {
            match set_operator_agent_groups(client, &username, &group).await {
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

        OperatorCommands::Active => match active(client).await {
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

        OperatorCommands::Logout { username } => match logout(client, &username).await {
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
        },
    }
}
