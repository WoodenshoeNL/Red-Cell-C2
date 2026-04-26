use clap::Parser;

use crate::cli::{Cli, Commands};
use crate::output::OutputFormat;

// ── global flag round-trips ───────────────────────────────────────────────

#[test]
fn server_flag_is_captured() {
    let cli = Cli::try_parse_from(["red-cell-cli", "--server", "https://ts.example.com:40056"])
        .expect("--server flag must parse");
    assert_eq!(cli.server.as_deref(), Some("https://ts.example.com:40056"));
}

#[test]
fn token_flag_is_captured() {
    let cli = Cli::try_parse_from(["red-cell-cli", "--token", "secret-token-abc"])
        .expect("--token flag must parse");
    assert_eq!(cli.token.as_deref(), Some("secret-token-abc"));
}

#[test]
fn output_flag_json_is_captured() {
    let cli = Cli::try_parse_from(["red-cell-cli", "--output", "json"])
        .expect("--output json must parse");
    assert!(matches!(cli.output, OutputFormat::Json));
}

#[test]
fn output_flag_text_is_captured() {
    let cli = Cli::try_parse_from(["red-cell-cli", "--output", "text"])
        .expect("--output text must parse");
    assert!(matches!(cli.output, OutputFormat::Text));
}

#[test]
fn default_output_format_is_json() {
    let cli = Cli::try_parse_from(["red-cell-cli"]).expect("bare invocation must parse");
    assert!(matches!(cli.output, OutputFormat::Json), "default --output must be json");
}

#[test]
fn timeout_flag_is_captured() {
    let cli = Cli::try_parse_from(["red-cell-cli", "--timeout", "60"])
        .expect("--timeout flag must parse");
    assert_eq!(cli.timeout, Some(60));
}

#[test]
fn default_timeout_is_none_when_omitted() {
    let cli = Cli::try_parse_from(["red-cell-cli"]).expect("bare invocation must parse");
    assert!(cli.timeout.is_none(), "omitting --timeout must yield None, not a sentinel");
}

#[test]
fn server_and_token_and_timeout_together() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "--server",
        "https://ts:40056",
        "--token",
        "tok",
        "--timeout",
        "120",
        "status",
    ])
    .expect("combined global flags with subcommand must parse");
    assert_eq!(cli.server.as_deref(), Some("https://ts:40056"));
    assert_eq!(cli.token.as_deref(), Some("tok"));
    assert_eq!(cli.timeout, Some(120));
    assert!(matches!(cli.command, Some(Commands::Status)));
}

// ── invalid flags produce errors ──────────────────────────────────────────

#[test]
fn invalid_flag_returns_error() {
    let result = Cli::try_parse_from(["red-cell-cli", "--invalid-flag"]);
    assert!(result.is_err(), "unknown flag must return an error");
}

#[test]
fn invalid_output_value_returns_error() {
    let result = Cli::try_parse_from(["red-cell-cli", "--output", "yaml"]);
    assert!(result.is_err(), "invalid --output value must return an error");
}

#[test]
fn non_numeric_timeout_returns_error() {
    let result = Cli::try_parse_from(["red-cell-cli", "--timeout", "notanumber"]);
    assert!(result.is_err(), "non-numeric --timeout must return an error");
}
