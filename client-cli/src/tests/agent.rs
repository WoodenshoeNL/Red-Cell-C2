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

// ── agent shell ──────────────────────────────────────────────────────────

#[test]
fn agent_shell_without_unsafe_tty_fails() {
    let err = Cli::try_parse_from(["red-cell-cli", "agent", "shell", "abc123"])
        .expect("agent shell without --unsafe-tty must parse (gate is at dispatch)");
    match err.command {
        Some(Commands::Agent { action: AgentCommands::Shell { unsafe_tty, .. } }) => {
            assert!(!unsafe_tty, "omitting --unsafe-tty must default to false");
        }
        other => panic!("expected Agent::Shell, got {other:?}"),
    }
}

#[test]
fn agent_shell_with_unsafe_tty_parses() {
    let cli = Cli::try_parse_from(["red-cell-cli", "agent", "shell", "abc123", "--unsafe-tty"])
        .expect("agent shell --unsafe-tty must parse");
    match cli.command {
        Some(Commands::Agent { action: AgentCommands::Shell { unsafe_tty, .. } }) => {
            assert!(unsafe_tty, "--unsafe-tty must be true when passed");
        }
        other => panic!("expected Agent::Shell, got {other:?}"),
    }
}

#[test]
fn agent_shell_help_mentions_unsafe_tty() {
    let mut cmd = Cli::command();
    let help = cmd
        .find_subcommand_mut("agent")
        .expect("agent subcommand")
        .find_subcommand_mut("shell")
        .expect("agent shell subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("--unsafe-tty"), "agent shell help must mention --unsafe-tty");
    assert!(
        help.contains("session --agent"),
        "agent shell help must point to session as alternative"
    );
}

#[test]
fn agent_shell_enable_local_shell_defaults_to_false() {
    let cli = Cli::try_parse_from(["red-cell-cli", "agent", "shell", "abc123", "--unsafe-tty"])
        .expect("must parse");
    match cli.command {
        Some(Commands::Agent { action: AgentCommands::Shell { enable_local_shell, .. } }) => {
            assert!(!enable_local_shell, "--enable-local-shell must default to false");
        }
        other => panic!("expected Agent::Shell, got {other:?}"),
    }
}

#[test]
fn agent_shell_enable_local_shell_flag_parses() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "agent",
        "shell",
        "abc123",
        "--unsafe-tty",
        "--enable-local-shell",
    ])
    .expect("must parse");
    match cli.command {
        Some(Commands::Agent { action: AgentCommands::Shell { enable_local_shell, .. } }) => {
            assert!(enable_local_shell, "--enable-local-shell must be true when passed");
        }
        other => panic!("expected Agent::Shell, got {other:?}"),
    }
}

#[test]
fn agent_shell_help_mentions_operator_host() {
    let mut cmd = Cli::command();
    let help = cmd
        .find_subcommand_mut("agent")
        .expect("agent subcommand")
        .find_subcommand_mut("shell")
        .expect("agent shell subcommand")
        .render_long_help()
        .to_string();

    assert!(
        help.contains("OPERATOR HOST"),
        "agent shell help must warn that ! runs on the operator host"
    );
    assert!(
        help.contains("--enable-local-shell"),
        "agent shell help must mention --enable-local-shell"
    );
}
