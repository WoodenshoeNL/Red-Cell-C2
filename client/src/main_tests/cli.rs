//! Tests for [`crate::bootstrap::Cli`] argument parsing.

use clap::Parser;
use std::path::PathBuf;

use crate::bootstrap::{Cli, DEFAULT_SERVER_URL};

#[test]
fn cli_uses_default_server_url() {
    let cli = Cli::parse_from(["red-cell-client"]);
    assert_eq!(cli.server, DEFAULT_SERVER_URL);
}

#[test]
fn cli_accepts_custom_server_url() {
    let cli =
        Cli::parse_from(["red-cell-client", "--server", "wss://teamserver.example.test/havoc/"]);
    assert_eq!(cli.server, "wss://teamserver.example.test/havoc/");
}

#[test]
fn cli_accepts_scripts_dir() {
    let cli = Cli::parse_from(["red-cell-client", "--scripts-dir", "/tmp/red-cell-client-scripts"]);
    assert_eq!(cli.scripts_dir, Some(PathBuf::from("/tmp/red-cell-client-scripts")));
}

#[test]
fn cli_accepts_tls_flags() {
    let cli = Cli::parse_from([
        "red-cell-client",
        "--ca-cert",
        "/tmp/ca.pem",
        "--cert-fingerprint",
        "abcd1234",
    ]);
    assert_eq!(cli.ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
    assert_eq!(cli.cert_fingerprint.as_deref(), Some("abcd1234"));
    assert!(!cli.accept_invalid_certs);
}

#[test]
fn cli_optional_fields_default_to_none() {
    let cli = Cli::parse_from(["red-cell-client"]);
    assert!(cli.scripts_dir.is_none());
    assert!(cli.ca_cert.is_none());
    assert!(cli.cert_fingerprint.is_none());
}

#[test]
fn cli_accept_invalid_certs_defaults_to_false() {
    let cli = Cli::parse_from(["red-cell-client"]);
    assert!(!cli.accept_invalid_certs);
}

#[test]
fn cli_accept_invalid_certs_flag_sets_true() {
    let cli = Cli::parse_from(["red-cell-client", "--accept-invalid-certs"]);
    assert!(cli.accept_invalid_certs);
}

#[test]
fn cli_rejects_unknown_args() {
    let result = Cli::try_parse_from(["red-cell-client", "--nonexistent-flag"]);
    assert!(result.is_err());
}

#[test]
fn cli_rejects_unknown_positional_args() {
    let result = Cli::try_parse_from(["red-cell-client", "unexpected-positional"]);
    assert!(result.is_err());
}
