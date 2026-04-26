use clap::Parser;

use crate::cli::{Cli, Commands, LootCommands};

#[test]
fn loot_export_csv_parses() {
    let cli = Cli::try_parse_from(["red-cell-cli", "loot", "export", "--format", "csv"])
        .expect("loot export --format csv must parse");
    match cli.command {
        Some(Commands::Loot { action: LootCommands::Export { format, file, .. } }) => {
            assert!(matches!(format, crate::cli::ExportFormat::Csv));
            assert!(file.is_none());
        }
        other => panic!("expected Loot::Export, got {other:?}"),
    }
}

#[test]
fn loot_export_jsonl_parses() {
    let cli = Cli::try_parse_from(["red-cell-cli", "loot", "export", "--format", "jsonl"])
        .expect("loot export --format jsonl must parse");
    match cli.command {
        Some(Commands::Loot { action: LootCommands::Export { format, .. } }) => {
            assert!(matches!(format, crate::cli::ExportFormat::Jsonl));
        }
        other => panic!("expected Loot::Export, got {other:?}"),
    }
}

#[test]
fn loot_export_with_file_parses() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "loot",
        "export",
        "--format",
        "csv",
        "--file",
        "loot.csv",
    ])
    .expect("loot export --file must parse");
    match cli.command {
        Some(Commands::Loot { action: LootCommands::Export { file, .. } }) => {
            assert_eq!(file.as_deref(), Some("loot.csv"));
        }
        other => panic!("expected Loot::Export, got {other:?}"),
    }
}

#[test]
fn loot_export_with_filters_parses() {
    let cli = Cli::try_parse_from([
        "red-cell-cli",
        "loot",
        "export",
        "--format",
        "csv",
        "--kind",
        "screenshot",
        "--since",
        "2026-04-01",
        "--limit",
        "100",
    ])
    .expect("loot export with filters must parse");
    match cli.command {
        Some(Commands::Loot { action: LootCommands::Export { kind, since, limit, .. } }) => {
            assert_eq!(kind.as_deref(), Some("screenshot"));
            assert_eq!(since.as_deref(), Some("2026-04-01"));
            assert_eq!(limit, Some(100));
        }
        other => panic!("expected Loot::Export, got {other:?}"),
    }
}

#[test]
fn loot_export_rejects_missing_format() {
    let result = Cli::try_parse_from(["red-cell-cli", "loot", "export"]);
    assert!(result.is_err(), "loot export without --format must fail");
}

#[test]
fn loot_export_rejects_invalid_format() {
    let result = Cli::try_parse_from(["red-cell-cli", "loot", "export", "--format", "xml"]);
    assert!(result.is_err(), "loot export --format xml must fail");
}
