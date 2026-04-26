use clap::Parser;

use crate::cli::{Cli, Commands};
use crate::dispatch::handle_help;
use crate::error::{self, CliError, EXIT_GENERAL, EXIT_SUCCESS};

// ── help subcommand parsing ───────────────────────────────────────────────

#[test]
fn bare_invocation_yields_none_command() {
    let cli = Cli::try_parse_from(["red-cell-cli"]).expect("parse bare invocation");
    assert!(cli.command.is_none());
}

#[test]
fn help_subcommand_parses_with_no_arg() {
    let cli = Cli::try_parse_from(["red-cell-cli", "help"]).expect("parse 'help'");
    assert!(matches!(cli.command, Some(Commands::Help { command: None })));
}

#[test]
fn help_subcommand_parses_with_agent_arg() {
    let cli = Cli::try_parse_from(["red-cell-cli", "help", "agent"]).expect("parse 'help agent'");
    assert!(
        matches!(&cli.command, Some(Commands::Help { command: Some(c) }) if c == "agent"),
        "expected Help {{ command: Some(\"agent\") }}"
    );
}

#[test]
fn help_subcommand_parses_with_listener_arg() {
    let cli =
        Cli::try_parse_from(["red-cell-cli", "help", "listener"]).expect("parse 'help listener'");
    assert!(matches!(&cli.command, Some(Commands::Help { command: Some(c) }) if c == "listener"));
}

// ── unknown command handling ──────────────────────────────────────────────

#[test]
fn unknown_command_fails_to_parse_without_panic() {
    let result = Cli::try_parse_from(["red-cell-cli", "frobnicator"]);
    assert!(result.is_err(), "unknown command must fail to parse");
}

#[test]
fn handle_help_unknown_returns_exit_general() {
    let code = handle_help(Some("totally-unknown-command"));
    assert_eq!(code, EXIT_GENERAL);
}

/// Unknown-command error uses INVALID_ARGS code so parsers see structured JSON.
#[test]
fn unknown_command_error_uses_invalid_args_code() {
    let err = CliError::InvalidArgs("unknown command 'bogus'".to_owned());
    assert_eq!(err.error_code(), error::ERROR_CODE_INVALID_ARGS);
    let envelope = serde_json::json!({
        "ok": false,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"], "INVALID_ARGS");
    assert!(envelope["message"].as_str().unwrap_or("").contains("unknown command"));
}

/// Runtime-build error uses ERROR code so parsers see structured JSON.
#[test]
fn runtime_build_error_uses_general_code() {
    let err =
        CliError::General("failed to build async runtime: out of file descriptors".to_owned());
    assert_eq!(err.error_code(), error::ERROR_CODE_GENERAL);
    let envelope = serde_json::json!({
        "ok": false,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"], "ERROR");
    assert!(envelope["message"].as_str().unwrap_or("").contains("async runtime"));
}

#[test]
fn handle_help_none_returns_exit_success() {
    let code = handle_help(None);
    assert_eq!(code, EXIT_SUCCESS);
}

#[test]
fn handle_help_known_command_returns_exit_success() {
    let code = handle_help(Some("agent"));
    assert_eq!(code, EXIT_SUCCESS);
}
