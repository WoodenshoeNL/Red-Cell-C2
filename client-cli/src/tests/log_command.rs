use clap::{CommandFactory, Parser};

use crate::cli::{AuditCommands, Cli, Commands};

// ── log command name ──────────────────────────────────────────────────────

#[test]
fn audit_variant_is_exposed_as_log_command() {
    // The CLI name must be "log", not "audit".
    let cli = Cli::try_parse_from(["red-cell-cli", "log", "list"]).expect("'log list' must parse");
    assert!(matches!(cli.command, Some(Commands::Audit { .. })));
}

#[test]
fn log_list_until_flag_parses() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "log",
        "list",
        "--since",
        "2026-03-21T00:00:00Z",
        "--until",
        "2026-03-22T00:00:00Z",
    ])
    .expect("log list --since --until must parse");
    match cli.command {
        Some(Commands::Audit { action: AuditCommands::List { since, until, .. } }) => {
            assert_eq!(since.as_deref(), Some("2026-03-21T00:00:00Z"));
            assert_eq!(until.as_deref(), Some("2026-03-22T00:00:00Z"));
        }
        _ => panic!("expected log list"),
    }
}

#[test]
fn log_list_until_is_optional() {
    let cli =
        Cli::try_parse_from(["red-cell-cli", "log", "list", "--since", "2026-01-01T00:00:00Z"])
            .expect("log list --since only must parse");
    match cli.command {
        Some(Commands::Audit { action: AuditCommands::List { until, .. } }) => {
            assert!(until.is_none(), "--until should default to None");
        }
        _ => panic!("expected log list"),
    }
}

#[test]
fn log_tail_follow_default_max_failures_is_five() {
    let cli = Cli::try_parse_from(["red-cell-cli", "log", "tail", "--follow"]).expect("parse");
    match cli.command {
        Some(Commands::Audit { action: AuditCommands::Tail { follow, max_failures } }) => {
            assert!(follow);
            assert_eq!(max_failures, crate::defaults::AUDIT_TAIL_FOLLOW_MAX_FAILURES_DEFAULT);
        }
        _ => panic!("expected log tail --follow"),
    }
}

#[test]
fn log_tail_follow_parses_max_failures() {
    let cli =
        Cli::try_parse_from(["red-cell-cli", "log", "tail", "--follow", "--max-failures", "7"])
            .expect("parse");
    match cli.command {
        Some(Commands::Audit { action: AuditCommands::Tail { follow, max_failures } }) => {
            assert!(follow);
            assert_eq!(max_failures, 7);
        }
        _ => panic!("expected log tail --follow"),
    }
}

#[test]
fn audit_tail_help_mentions_default_poll_interval() {
    let mut cmd = Cli::command();
    let help = cmd
        .find_subcommand_mut("log")
        .expect("log subcommand")
        .find_subcommand_mut("tail")
        .expect("log tail subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("default: 1"), "log tail help must mention the default poll interval");
    assert!(help.contains("Polls every 1 second"), "log tail help must mention polling");
    assert!(help.contains("--max-failures"), "log tail help must mention --max-failures");
    assert!(
        help.contains("default: 5"),
        "log tail help must mention the default max consecutive HTTP timeouts"
    );
}

#[test]
fn log_server_tail_help_mentions_examples() {
    let mut cmd = Cli::command();
    let help = cmd
        .find_subcommand_mut("log")
        .expect("log subcommand")
        .find_subcommand_mut("server-tail")
        .expect("log server-tail subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("Examples:"), "log server-tail help missing Examples");
    assert!(help.contains("--lines"), "log server-tail help must mention --lines");
}
