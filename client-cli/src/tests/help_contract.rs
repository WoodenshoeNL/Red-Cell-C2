use clap::CommandFactory;

use crate::cli::Cli;

// ── top-level help content ───────────────────────────────────────────────

#[test]
fn top_level_help_contains_rc_server() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("RC_SERVER"), "top-level help must mention RC_SERVER");
}

#[test]
fn top_level_help_contains_rc_token() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("RC_TOKEN"), "top-level help must mention RC_TOKEN");
}

#[test]
fn top_level_help_contains_rc_cert_fingerprint() {
    let help = Cli::command().render_long_help().to_string();
    assert!(
        help.contains("RC_CERT_FINGERPRINT"),
        "top-level help must mention RC_CERT_FINGERPRINT"
    );
}

#[test]
fn top_level_help_contains_examples_section() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("Examples:"), "top-level help must have an Examples section");
    assert!(
        help.contains("red-cell-cli status"),
        "top-level help examples must include 'red-cell-cli status'"
    );
    assert!(
        help.contains("red-cell-cli agent list"),
        "top-level help examples must include 'red-cell-cli agent list'"
    );
}

#[test]
fn top_level_help_contains_environment_section() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("Environment:"), "top-level help must have an Environment section");
}

// ── per-subcommand examples ──────────────────────────────────────────────

/// Every direct child of the root command must have "Examples:" in its long help.
#[test]
fn every_top_level_subcommand_has_examples() {
    let mut cmd = Cli::command();
    for sub in cmd.get_subcommands_mut() {
        let name = sub.get_name().to_owned();
        let help = sub.render_long_help().to_string();
        assert!(
            help.contains("Examples:"),
            "subcommand '{name}' help is missing an Examples section"
        );
    }
}

/// Spot-check a selection of second-level subcommands for examples.
#[test]
fn nested_subcommands_have_examples() {
    let mut cmd = Cli::command();

    // agent → exec
    let agent_exec_help = cmd
        .find_subcommand_mut("agent")
        .expect("agent subcommand")
        .find_subcommand_mut("exec")
        .expect("agent exec subcommand")
        .render_long_help()
        .to_string();
    assert!(agent_exec_help.contains("Examples:"), "agent exec help missing Examples");

    // listener → create
    let mut cmd2 = Cli::command();
    let listener_create_help = cmd2
        .find_subcommand_mut("listener")
        .expect("listener subcommand")
        .find_subcommand_mut("create")
        .expect("listener create subcommand")
        .render_long_help()
        .to_string();
    assert!(listener_create_help.contains("Examples:"), "listener create help missing Examples");

    // log → list
    let mut cmd3 = Cli::command();
    let log_list_help = cmd3
        .find_subcommand_mut("log")
        .expect("log subcommand")
        .find_subcommand_mut("list")
        .expect("log list subcommand")
        .render_long_help()
        .to_string();
    assert!(log_list_help.contains("Examples:"), "log list help missing Examples");
}

#[test]
fn agent_output_help_describes_numeric_since_cursor() {
    let mut cmd = Cli::command();
    let help = cmd
        .find_subcommand_mut("agent")
        .expect("agent subcommand")
        .find_subcommand_mut("output")
        .expect("agent output subcommand")
        .render_long_help()
        .to_string();

    assert!(
        help.contains("numeric output entry id"),
        "agent output help must describe --since as a numeric output entry id"
    );
    assert!(help.contains("--since 42"), "agent output help must show a numeric --since example");
    assert!(
        help.contains("cursor_reset"),
        "agent output help must mention cursor_reset stderr warning"
    );
}
