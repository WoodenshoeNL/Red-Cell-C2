use std::path::PathBuf;

use clap::Subcommand;

/// Profile subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    /// Validate a YAOTL profile file for parse and semantic errors.
    ///
    /// Exits 0 with {"ok":true} when the profile is valid.
    /// Exits 1 with {"ok":false,"errors":[...]} when validation fails.
    ///
    /// Examples:
    ///   red-cell-cli profile validate profiles/havoc.yaotl
    ///   red-cell-cli profile validate /tmp/test.yaotl
    #[command(verbatim_doc_comment)]
    Validate {
        /// Path to the .yaotl profile file.
        path: PathBuf,
    },

    /// Show the running teamserver's effective profile (secrets redacted).
    ///
    /// Queries the teamserver for its loaded profile and displays the
    /// effective configuration with passwords and API key values redacted.
    ///
    /// Examples:
    ///   red-cell-cli profile show
    #[command(verbatim_doc_comment)]
    Show,
}
