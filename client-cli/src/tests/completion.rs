use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Commands};

#[test]
fn completion_bash_parses() {
    let cli = Cli::try_parse_from(["red-cell-cli", "completion", "bash"])
        .expect("parse 'completion bash'");
    assert!(matches!(
        cli.command,
        Some(Commands::Completion { shell: clap_complete::Shell::Bash })
    ));
}

#[test]
fn completion_zsh_parses() {
    let cli =
        Cli::try_parse_from(["red-cell-cli", "completion", "zsh"]).expect("parse 'completion zsh'");
    assert!(matches!(cli.command, Some(Commands::Completion { shell: clap_complete::Shell::Zsh })));
}

#[test]
fn completion_fish_parses() {
    let cli = Cli::try_parse_from(["red-cell-cli", "completion", "fish"])
        .expect("parse 'completion fish'");
    assert!(matches!(
        cli.command,
        Some(Commands::Completion { shell: clap_complete::Shell::Fish })
    ));
}

#[test]
fn completion_without_shell_fails() {
    let result = Cli::try_parse_from(["red-cell-cli", "completion"]);
    assert!(result.is_err(), "completion without a shell argument must fail");
}

#[test]
fn completion_bash_generates_output() {
    let mut buf = Vec::new();
    clap_complete::generate(
        clap_complete::Shell::Bash,
        &mut Cli::command(),
        "red-cell-cli",
        &mut buf,
    );
    let script = String::from_utf8(buf).expect("valid UTF-8");
    assert!(script.contains("red-cell-cli"), "bash completion must reference binary name");
    assert!(script.contains("complete"), "bash completion must contain 'complete' directive");
}

#[test]
fn completion_help_mentions_bash_zsh_fish() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("completion"), "top-level help must list 'completion' subcommand");
}
