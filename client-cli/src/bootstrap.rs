//! Process entry: tracing, clap parsing, help shortcuts, and async runtime bootstrap.

use std::io::Write as _;

use clap::Parser;
use clap::error::ErrorKind;
use tracing_subscriber::EnvFilter;

use crate::cli::Cli;
use crate::cli::Commands;
use crate::dispatch::{dispatch, handle_help};
use crate::error::{self, CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output;

/// Initializes tracing, parses argv, handles bare invocation and `help`, then runs async dispatch.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Clap defaults to exit 2 for usage errors; AGENTS.md reserves 2 for "not found".
            // `--help` / `--version` are reported as errors by `try_parse` but must exit 0.
            let code = match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => EXIT_SUCCESS,
                _ => EXIT_GENERAL,
            };
            let _ = e.print();
            std::process::exit(code);
        }
    };

    // Bare invocation: print help and exit 0.
    if cli.command.is_none() {
        use clap::CommandFactory;
        let ok = Cli::command().print_help().is_ok() && writeln!(std::io::stdout()).is_ok();
        std::process::exit(if ok { EXIT_SUCCESS } else { EXIT_GENERAL });
    }

    // `help [command]` doesn't need a server or token — handle it before the
    // async runtime is started.
    if let Some(Commands::Help { ref command }) = cli.command {
        let code = handle_help(command.as_deref());
        std::process::exit(code);
    }

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            output::print_error(&CliError::General(format!("failed to build async runtime: {e}")))
                .ok();
            std::process::exit(error::EXIT_GENERAL);
        }
    };

    let exit_code = rt.block_on(dispatch(cli));
    std::process::exit(exit_code);
}
