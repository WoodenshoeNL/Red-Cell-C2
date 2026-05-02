use clap::{CommandFactory, Parser};

use crate::AgentId;
use crate::cli::{AgentCommands, Cli, Commands};

// ── --wait-timeout flags ─────────────────────────────────────────────────

#[test]
fn agent_exec_wait_timeout_is_captured() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "agent",
        "exec",
        "abc123",
        "--cmd",
        "whoami",
        "--wait",
        "--wait-timeout",
        "120",
    ])
    .expect("agent exec --wait --wait-timeout must parse");
    match cli.command {
        Some(Commands::Agent { action: AgentCommands::Exec { wait_timeout, .. } }) => {
            assert_eq!(wait_timeout, Some(120));
        }
        other => panic!("expected Agent::Exec, got {other:?}"),
    }
}

#[test]
fn agent_exec_wait_timeout_defaults_to_none_when_omitted() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "agent",
        "exec",
        "abc123",
        "--cmd",
        "whoami",
        "--wait",
    ])
    .expect("agent exec --wait without --wait-timeout must parse");
    match cli.command {
        Some(Commands::Agent { action: AgentCommands::Exec { wait_timeout, .. } }) => {
            assert!(
                wait_timeout.is_none(),
                "omitting --wait-timeout must yield None (default applied in handler)"
            );
        }
        other => panic!("expected Agent::Exec, got {other:?}"),
    }
}

#[test]
fn agent_show_rejects_ambiguous_digit_only_id() {
    let err = Cli::try_parse_from(["red-cell-cli", "agent", "show", "1234"])
        .expect_err("ambiguous digit-only id must be rejected");
    let rendered = err.to_string();
    assert!(rendered.contains("ambiguous agent id '1234'"));
    assert!(rendered.contains("0x<hex>"));
}

#[test]
fn session_accepts_explicit_decimal_default_agent() {
    let cli = Cli::try_parse_from(["red-cell-cli", "session", "--agent", "dec:42"])
        .expect("explicit decimal default agent must parse");
    match cli.command {
        Some(Commands::Session { agent }) => assert_eq!(agent, Some(AgentId::new(42))),
        other => panic!("expected Session, got {other:?}"),
    }
}

#[test]
fn agent_exec_help_mentions_default_wait_timeout() {
    let mut cmd = Cli::command();
    let help = cmd
        .find_subcommand_mut("agent")
        .expect("agent subcommand")
        .find_subcommand_mut("exec")
        .expect("agent exec subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("default: 60"), "agent exec help must mention the default timeout");
    assert!(help.contains("--wait-timeout"), "agent exec help must mention the override flag");
}

// ── machine-consumable CLI: no interactive agent shell ─────────────────────

#[test]
fn agent_shell_subcommand_removed() {
    let err = Cli::try_parse_from(["red-cell-cli", "agent", "shell", "abc123"])
        .expect_err("shell removed");
    let msg = err.to_string();
    assert!(
        msg.contains("shell") && (msg.contains("unrecognized") || msg.contains("subcommand")),
        "expected parse error for removed subcommand; got: {msg}"
    );
}

#[test]
fn agent_help_has_exec_not_shell() {
    let mut cmd = Cli::command();
    let agent = cmd.find_subcommand_mut("agent").expect("agent subcommand");
    let names: Vec<_> = agent.get_subcommands().map(|s| s.get_name().to_owned()).collect();
    assert!(
        !names.iter().any(|n| n == "shell"),
        "agent shell must not appear in help (machine-consumable CLI contract)"
    );
    assert!(names.iter().any(|n| n == "exec"), "expected agent exec subcommand; got {names:?}");
}
