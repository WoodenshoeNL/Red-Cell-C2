use clap::Parser;

use crate::cli::{Cli, Commands, ServerCommands};

// ── server cert ────────────────────────────────────────────────────────

#[test]
fn server_cert_parses_defaults() {
    let cli =
        Cli::try_parse_from(["red-cell-cli", "server", "cert"]).expect("server cert must parse");
    match cli.command {
        Some(Commands::Server { action: ServerCommands::Cert { chain, pem } }) => {
            assert!(!chain, "--chain must default to false");
            assert!(!pem, "--pem must default to false");
        }
        other => panic!("expected Server::Cert, got {other:?}"),
    }
}

#[test]
fn server_cert_chain_flag_parses() {
    let cli = Cli::try_parse_from(["red-cell-cli", "server", "cert", "--chain"])
        .expect("server cert --chain must parse");
    match cli.command {
        Some(Commands::Server { action: ServerCommands::Cert { chain, pem } }) => {
            assert!(chain);
            assert!(!pem);
        }
        other => panic!("expected Server::Cert, got {other:?}"),
    }
}

#[test]
fn server_cert_pem_flag_parses() {
    let cli = Cli::try_parse_from(["red-cell-cli", "server", "cert", "--pem"])
        .expect("server cert --pem must parse");
    match cli.command {
        Some(Commands::Server { action: ServerCommands::Cert { chain, pem } }) => {
            assert!(!chain);
            assert!(pem);
        }
        other => panic!("expected Server::Cert, got {other:?}"),
    }
}

#[test]
fn server_cert_chain_and_pem_together() {
    let cli = Cli::try_parse_from(["red-cell-cli", "server", "cert", "--chain", "--pem"])
        .expect("server cert --chain --pem must parse");
    match cli.command {
        Some(Commands::Server { action: ServerCommands::Cert { chain, pem } }) => {
            assert!(chain);
            assert!(pem);
        }
        other => panic!("expected Server::Cert, got {other:?}"),
    }
}

#[test]
fn server_cert_with_global_server_flag() {
    let cli =
        Cli::try_parse_from(["red-cell-cli", "--server", "https://ts:40056", "server", "cert"])
            .expect("global --server with server cert must parse");
    assert_eq!(cli.server.as_deref(), Some("https://ts:40056"));
    assert!(matches!(cli.command, Some(Commands::Server { action: ServerCommands::Cert { .. } })));
}
