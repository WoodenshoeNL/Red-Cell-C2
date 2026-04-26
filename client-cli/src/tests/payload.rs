use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Commands, PayloadCommands};

// ── payload build --agent flag ───────────────────────────────────────────

#[test]
fn payload_build_agent_defaults_to_demon() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "payload",
        "build",
        "--listener",
        "http1",
        "--arch",
        "x64",
        "--format",
        "exe",
    ])
    .expect("payload build must parse without --agent");
    match cli.command {
        Some(Commands::Payload { action: PayloadCommands::Build { agent, .. } }) => {
            assert_eq!(agent, "demon", "--agent must default to 'demon'")
        }
        other => panic!("expected Payload::Build, got {other:?}"),
    }
}

#[test]
fn payload_build_agent_flag_is_captured() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "payload",
        "build",
        "--listener",
        "http1",
        "--arch",
        "x64",
        "--format",
        "bin",
        "--agent",
        "phantom",
    ])
    .expect("payload build --agent phantom must parse");
    match cli.command {
        Some(Commands::Payload { action: PayloadCommands::Build { agent, .. } }) => {
            assert_eq!(agent, "phantom")
        }
        other => panic!("expected Payload::Build, got {other:?}"),
    }
}

// ── --wait-timeout flags ─────────────────────────────────────────────────

#[test]
fn payload_build_wait_timeout_is_captured() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "payload",
        "build",
        "--listener",
        "http1",
        "--arch",
        "x86_64",
        "--format",
        "exe",
        "--wait",
        "--wait-timeout",
        "600",
    ])
    .expect("payload build --wait --wait-timeout must parse");
    match cli.command {
        Some(Commands::Payload { action: PayloadCommands::Build { wait_timeout, .. } }) => {
            assert_eq!(wait_timeout, Some(600));
        }
        other => panic!("expected Payload::Build, got {other:?}"),
    }
}

#[test]
fn payload_build_wait_timeout_defaults_to_none_when_omitted() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "payload",
        "build",
        "--listener",
        "http1",
        "--arch",
        "x86_64",
        "--format",
        "exe",
    ])
    .expect("payload build without --wait-timeout must parse");
    match cli.command {
        Some(Commands::Payload { action: PayloadCommands::Build { wait_timeout, .. } }) => {
            assert!(
                wait_timeout.is_none(),
                "omitting --wait-timeout must yield None (default applied in handler)"
            );
        }
        other => panic!("expected Payload::Build, got {other:?}"),
    }
}

#[test]
fn payload_build_help_mentions_default_wait_timeout() {
    let mut cmd = Cli::command();
    let help = cmd
        .find_subcommand_mut("payload")
        .expect("payload subcommand")
        .find_subcommand_mut("build")
        .expect("payload build subcommand")
        .render_long_help()
        .to_string();

    assert!(help.contains("default: 300"), "payload build help must mention the default timeout");
    assert!(help.contains("--wait-timeout"), "payload build help must mention the override flag");
}

// ── payload inspect ─────────────────────────────────────────────────────

#[test]
fn payload_inspect_parses_file_argument() {
    let cli = Cli::try_parse_from(["red-cell-cli", "payload", "inspect", "./agent.exe"])
        .expect("payload inspect must parse");
    match cli.command {
        Some(Commands::Payload { action: PayloadCommands::Inspect { file } }) => {
            assert_eq!(file, "./agent.exe")
        }
        other => panic!("expected Payload::Inspect, got {other:?}"),
    }
}

#[test]
fn payload_inspect_rejects_missing_file_argument() {
    let result = Cli::try_parse_from(["red-cell-cli", "payload", "inspect"]);
    assert!(result.is_err(), "payload inspect without file arg must fail");
}
