use clap::Parser;

use crate::cli::{Cli, Commands, ListenerCommands};

// ── listener start/stop/delete --name flag ────────────────────────────

#[test]
fn listener_start_positional() {
    let cli = Cli::try_parse_from(["red-cell-cli", "listener", "start", "http1"])
        .expect("positional name must parse");
    match cli.command {
        Some(Commands::Listener { action: ListenerCommands::Start { name, name_flag } }) => {
            assert_eq!(name.as_deref(), Some("http1"));
            assert!(name_flag.is_none());
        }
        other => panic!("expected Listener::Start, got {other:?}"),
    }
}

#[test]
fn listener_start_name_flag() {
    let cli = Cli::try_parse_from(["red-cell-cli", "listener", "start", "--name", "http1"])
        .expect("--name flag must parse");
    match cli.command {
        Some(Commands::Listener { action: ListenerCommands::Start { name, name_flag } }) => {
            assert!(name.is_none());
            assert_eq!(name_flag.as_deref(), Some("http1"));
        }
        other => panic!("expected Listener::Start, got {other:?}"),
    }
}

#[test]
fn listener_start_rejects_both_positional_and_flag() {
    let result =
        Cli::try_parse_from(["red-cell-cli", "listener", "start", "http1", "--name", "http2"]);
    assert!(result.is_err(), "both positional and --name must conflict");
}

#[test]
fn listener_start_rejects_no_name() {
    let result = Cli::try_parse_from(["red-cell-cli", "listener", "start"]);
    assert!(result.is_err(), "listener start with no name must fail");
}

#[test]
fn listener_stop_name_flag() {
    let cli = Cli::try_parse_from(["red-cell-cli", "listener", "stop", "--name", "dns1"])
        .expect("--name flag must parse");
    match cli.command {
        Some(Commands::Listener { action: ListenerCommands::Stop { name, name_flag } }) => {
            assert!(name.is_none());
            assert_eq!(name_flag.as_deref(), Some("dns1"));
        }
        other => panic!("expected Listener::Stop, got {other:?}"),
    }
}

#[test]
fn listener_delete_name_flag() {
    let cli = Cli::try_parse_from(["red-cell-cli", "listener", "delete", "--name", "smb1"])
        .expect("--name flag must parse");
    match cli.command {
        Some(Commands::Listener { action: ListenerCommands::Delete { name, name_flag } }) => {
            assert!(name.is_none());
            assert_eq!(name_flag.as_deref(), Some("smb1"));
        }
        other => panic!("expected Listener::Delete, got {other:?}"),
    }
}
