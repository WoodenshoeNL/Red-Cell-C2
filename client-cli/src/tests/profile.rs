use clap::Parser;

use crate::cli::{Cli, Commands, ProfileCommands};

// ── profile validate ───────────────────────────────────────────────────

#[test]
fn profile_validate_parses_path_argument() {
    let cli = Cli::try_parse_from(["red-cell-cli", "profile", "validate", "profiles/havoc.yaotl"])
        .expect("profile validate must parse");
    match cli.command {
        Some(Commands::Profile { action: ProfileCommands::Validate { path } }) => {
            assert_eq!(path.to_str(), Some("profiles/havoc.yaotl"));
        }
        other => panic!("expected Profile::Validate, got {other:?}"),
    }
}

#[test]
fn profile_validate_rejects_missing_path_argument() {
    let result = Cli::try_parse_from(["red-cell-cli", "profile", "validate"]);
    assert!(result.is_err(), "profile validate without path arg must fail");
}
