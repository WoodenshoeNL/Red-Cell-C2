use clap::Subcommand;

use crate::AgentId;

/// Loot subcommands.
#[derive(Debug, Subcommand)]
pub enum LootCommands {
    /// List captured loot entries.
    ///
    /// With --watch, prints the initial list then streams new loot entries
    /// as JSON-Lines until Ctrl-C.
    ///
    /// Examples:
    ///   red-cell-cli loot list
    ///   red-cell-cli loot list --kind screenshot
    ///   red-cell-cli loot list --agent DEADBEEF --limit 20
    ///   red-cell-cli loot list --since 2026-01-01T00:00:00Z
    ///   red-cell-cli loot list --watch
    ///   red-cell-cli loot list --watch --kind credential
    #[command(verbatim_doc_comment)]
    List {
        /// Filter by loot type (e.g. screenshot, credential, file)
        #[arg(long)]
        kind: Option<String>,
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<AgentId>,
        /// Filter by operator username
        #[arg(long)]
        operator: Option<String>,
        /// Only return entries captured at or after this ISO 8601 UTC timestamp
        #[arg(long)]
        since: Option<String>,
        /// Maximum entries to return (initial fetch only when combined with --watch)
        #[arg(long)]
        limit: Option<u32>,
        /// Stream new loot entries as JSON-Lines until Ctrl-C.
        #[arg(long, help = crate::defaults::loot_list_watch_help())]
        watch: bool,
        /// Exit with timeout (code 5) after this many consecutive HTTP request
        /// timeouts while polling (only applies with `--watch`).
        #[arg(
            long,
            default_value_t = crate::defaults::WATCH_MAX_FAILURES_DEFAULT,
            value_parser = clap::value_parser!(u32).range(1..=1024)
        )]
        max_failures: u32,
    },

    /// Download the raw bytes for a loot item to a local file.
    ///
    /// Examples:
    ///   red-cell-cli loot download 42 --out ./screenshot.png
    ///   red-cell-cli loot download 7 --out ./creds.txt
    #[command(verbatim_doc_comment)]
    Download {
        /// Numeric loot identifier (from `loot list`)
        id: i64,
        /// Local path to write the downloaded bytes
        #[arg(long)]
        out: String,
    },

    /// Export loot entries as CSV or JSONL.
    ///
    /// Uses the same query path as `loot list` but writes rows in a
    /// flat export format suitable for downstream tooling. Writes to
    /// stdout by default; use --file to redirect to a file. With default
    /// `--output json`, the success metadata line is on stderr so stdout is
    /// only the raw CSV/JSONL (safe to pipe to other tools).
    ///
    /// Examples:
    ///   red-cell-cli loot export --format csv
    ///   red-cell-cli loot export --format jsonl
    ///   red-cell-cli loot export --format csv --file loot.csv
    ///   red-cell-cli loot export --format csv --kind screenshot --since 2026-04-01
    #[command(verbatim_doc_comment)]
    Export {
        /// Export format: csv or jsonl
        #[arg(long)]
        format: ExportFormat,
        /// Write export to a file instead of stdout
        #[arg(long)]
        file: Option<String>,
        /// Filter by loot type (e.g. screenshot, credential, file)
        #[arg(long)]
        kind: Option<String>,
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<AgentId>,
        /// Filter by operator username
        #[arg(long)]
        operator: Option<String>,
        /// Only return entries captured at or after this ISO 8601 UTC timestamp
        #[arg(long)]
        since: Option<String>,
        /// Maximum entries to return
        #[arg(long)]
        limit: Option<u32>,
    },
}

/// Export format for `loot export`.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ExportFormat {
    /// Comma-separated values with a header row.
    Csv,
    /// One JSON object per line (JSON Lines).
    Jsonl,
}
