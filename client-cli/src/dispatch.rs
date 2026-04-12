//! Async command dispatch and synchronous `help` routing.

use std::io::Write as _;

use crate::cli::{Cli, Commands};
use crate::client;
use crate::commands;
use crate::config;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output;

/// Print help for the given subcommand name, or top-level help if `None`.
///
/// Returns the appropriate process exit code.
pub(crate) fn handle_help(command: Option<&str>) -> i32 {
    use clap::CommandFactory;
    let mut root = Cli::command();
    match command {
        None => {
            if root.print_help().is_err() || writeln!(std::io::stdout()).is_err() {
                return EXIT_GENERAL;
            }
            EXIT_SUCCESS
        }
        Some(name) => {
            if let Some(sub) = root.find_subcommand_mut(name) {
                if sub.print_long_help().is_err() || writeln!(std::io::stdout()).is_err() {
                    return EXIT_GENERAL;
                }
                EXIT_SUCCESS
            } else {
                output::print_error(&CliError::InvalidArgs(format!("unknown command '{name}'")))
                    .ok();
                root.print_help().ok();
                writeln!(std::io::stdout()).ok();
                EXIT_GENERAL
            }
        }
    }
}

/// Run the parsed CLI command and return a process exit code.
pub async fn dispatch(cli: Cli) -> i32 {
    // Capture output format before partial moves.
    let fmt = cli.output.clone();

    // Resolve configuration (CLI flags + env vars were already absorbed by
    // clap; this step adds the file-based fallbacks).
    let resolved = match config::resolve(
        cli.server,
        cli.token,
        cli.timeout,
        cli.ca_cert,
        cli.cert_fingerprint,
        cli.pin_intermediate,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            let err: CliError = e.into();
            output::print_error(&err).ok();
            return err.exit_code();
        }
    };

    // Build the shared API client.
    let api_client = match client::ApiClient::new(&resolved) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e).ok();
            return e.exit_code();
        }
    };

    let Some(command) = cli.command else {
        // Unreachable: bare invocation is handled in main().
        return EXIT_SUCCESS;
    };

    match command {
        Commands::Status => match commands::status::run(&api_client).await {
            Ok(data) => match output::print_success(&fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    output::print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                output::print_error(&e).ok();
                e.exit_code()
            }
        },

        Commands::Agent { action } => commands::agent::run(&api_client, &fmt, action).await,

        Commands::Listener { action } => commands::listener::run(&api_client, &fmt, action).await,

        Commands::Payload { action } => commands::payload::run(&api_client, &fmt, action).await,

        Commands::Loot { action } => commands::loot::run(&api_client, &fmt, action).await,

        Commands::Audit { action } => commands::audit::run(&api_client, &fmt, action).await,

        Commands::Session { agent } => commands::session::run(&resolved, agent).await,

        Commands::Operator { action } => commands::operator::run(&api_client, &fmt, action).await,

        // Handled synchronously in main() before the runtime is started;
        // this arm exists only for exhaustiveness.
        Commands::Help { .. } => EXIT_SUCCESS,
    }
}
