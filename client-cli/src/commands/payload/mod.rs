//! `red-cell-cli payload` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `payload list` | `GET /payloads` | table of all built payloads |
//! | `payload build` | `POST /payloads/build` | submit build job; `--wait` polls until done |
//! | `payload download <id>` | `GET /payloads/{id}/download` | saves raw bytes to disk |
//! | `payload cache-flush` | `POST /payload-cache` | flush all cached build artifacts (admin) |

mod build;
mod download;
pub mod inspect;
mod types;

pub use inspect::inspect_local;

use crate::PayloadCommands;
use crate::client::ApiClient;
use crate::defaults::PAYLOAD_BUILD_WAIT_TIMEOUT_SECS;
use crate::error::EXIT_SUCCESS;
use crate::output::{OutputFormat, print_error, print_success};

use build::BuildOutcome;

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch a [`PayloadCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: PayloadCommands) -> i32 {
    match action {
        PayloadCommands::List => match build::list(client).await {
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

        PayloadCommands::Build {
            listener,
            arch,
            format,
            agent,
            sleep: sleep_secs,
            wait,
            wait_timeout,
            detach,
        } => {
            let effective_wait = wait && !detach;
            let build_timeout_secs = wait_timeout.unwrap_or(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS);
            match build::build(
                client,
                &listener,
                &arch,
                &format,
                &agent,
                sleep_secs,
                effective_wait,
                build_timeout_secs,
            )
            .await
            {
                Ok(outcome) => match outcome {
                    BuildOutcome::Submitted(job) => match print_success(fmt, &job) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                    BuildOutcome::Completed(done) => match print_success(fmt, &done) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        PayloadCommands::BuildStatus { job_id } => {
            match build::build_status(client, &job_id).await {
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

        PayloadCommands::BuildWait { job_id, dst, wait_timeout } => {
            let timeout_secs = wait_timeout.unwrap_or(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS);
            match build::build_wait(client, &job_id, dst.as_deref(), timeout_secs).await {
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

        PayloadCommands::Download { id, dst } => {
            match download::download(client, &id, &dst).await {
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

        PayloadCommands::CacheFlush => match build::cache_flush(client).await {
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

        // Handled before config resolution in dispatch.rs; this arm exists
        // only for exhaustiveness.
        PayloadCommands::Inspect { .. } => EXIT_SUCCESS,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
