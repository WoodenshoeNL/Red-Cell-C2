//! Clap schema for `red-cell-cli`: global flags and all subcommand enums.

mod agent;
mod audit;
mod listener;
mod loot;
mod operator;
mod payload;
mod profile;
mod server;

pub use agent::AgentCommands;
pub use audit::AuditCommands;
pub use listener::ListenerCommands;
pub use loot::{ExportFormat, LootCommands};
pub use operator::OperatorCommands;
pub use payload::PayloadCommands;
pub use profile::ProfileCommands;
pub use server::ServerCommands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::AgentId;
use crate::output::OutputFormat;

// ── top-level CLI ─────────────────────────────────────────────────────────────

/// Red Cell C2 command-line client.
///
/// Communicates with a Red Cell teamserver over its JSON REST/WebSocket API.
/// All output is JSON by default — machine-parseable on stdout, structured
/// errors on stderr.
///
/// Authentication and TLS pinning are resolved in this order (first wins):
///
///   1. --server / --token / --cert-fingerprint flags
///   2. RC_SERVER / RC_TOKEN / RC_CERT_FINGERPRINT environment variables
///   3. .red-cell-cli.toml in the current or any parent directory
///   4. ~/.config/red-cell-cli/config.toml
///
/// Exit codes:
///   0  success
///   1  general / argument error
///   2  not found
///   3  auth failure (bad token, insufficient role)
///   4  server unreachable
///   5  timeout exceeded
///   6  rate limited (HTTP 429); polling loops should retry with backoff / Retry-After
#[derive(Debug, Parser)]
#[command(name = "red-cell-cli", author, version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(disable_help_subcommand = true)]
#[command(
    after_help = "Environment:\n  RC_SERVER             Teamserver URL  (e.g. https://ts.example.com:40056)\n  RC_TOKEN              API token\n  RC_CERT_FINGERPRINT   SHA-256 cert fingerprint (64 hex chars) for TLS pinning\n\nExamples:\n  red-cell-cli status\n  red-cell-cli agent list\n  red-cell-cli agent exec abc123 --cmd whoami --wait"
)]
pub struct Cli {
    /// Teamserver base URL (e.g. https://teamserver:40056)
    #[arg(long, short = 's', env = "RC_SERVER", global = true)]
    pub server: Option<String>,

    /// API authentication token
    #[arg(long, short = 't', env = "RC_TOKEN", global = true)]
    pub token: Option<String>,

    /// Output format
    #[arg(long, short = 'o', global = true, default_value = "json")]
    pub output: OutputFormat,

    /// Request timeout in seconds (default: 30)
    #[arg(long, global = true)]
    pub timeout: Option<u64>,

    /// Path to a custom CA certificate (PEM) used to verify the teamserver's
    /// TLS certificate.  Built-in root CAs are disabled; only this CA is
    /// trusted.  Overridden by --cert-fingerprint when both are supplied.
    #[arg(long, global = true)]
    pub ca_cert: Option<PathBuf>,

    /// SHA-256 fingerprint (lowercase hex, 64 chars) of a certificate to pin.
    /// Overrides --ca-cert when both are supplied.  By default only the
    /// end-entity (leaf) certificate is compared; use --pin-intermediate to
    /// require a match anywhere in the server-presented chain (e.g. pin an
    /// intermediate CA so leaf renewal does not require updating the pin).
    #[arg(long, global = true, env = "RC_CERT_FINGERPRINT")]
    pub cert_fingerprint: Option<String>,

    /// With --cert-fingerprint, match the fingerprint against any certificate
    /// in the TLS chain (leaf + intermediates) instead of only the leaf.
    /// Stronger default is leaf-only pinning; chain pinning survives leaf
    /// rotation but is a looser check (any chain cert with that fingerprint
    /// satisfies the pin).
    #[arg(long, global = true)]
    pub pin_intermediate: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

// ── subcommands ───────────────────────────────────────────────────────────────

/// Available top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Check teamserver connectivity and verify credentials.
    ///
    /// Examples:
    ///   red-cell-cli status
    ///   red-cell-cli --server https://ts:40056 --token mytoken status
    #[command(verbatim_doc_comment)]
    Status,

    /// Inspect the teamserver's TLS certificate.
    ///
    /// Connects to the server, performs a TLS handshake, and reports the
    /// certificate fingerprint and metadata.  No authentication required.
    ///
    /// Examples:
    ///   red-cell-cli server cert
    ///   red-cell-cli server cert --chain
    ///   red-cell-cli server cert --pem
    ///   red-cell-cli --server https://ts:40056 server cert --output text
    #[command(verbatim_doc_comment)]
    Server {
        #[command(subcommand)]
        action: ServerCommands,
    },

    /// Manage connected agents.
    ///
    /// Examples:
    ///   red-cell-cli agent list
    ///   red-cell-cli agent show <id>
    ///   red-cell-cli agent exec <id> --cmd whoami --wait
    ///   red-cell-cli agent groups <id>
    ///   red-cell-cli agent set-groups <id> --group tier1
    #[command(verbatim_doc_comment)]
    Agent {
        #[command(subcommand)]
        action: AgentCommands,
    },

    /// Manage listeners (HTTP/S, DNS, SMB, external).
    ///
    /// Examples:
    ///   red-cell-cli listener list
    ///   red-cell-cli listener show mylistener
    ///   red-cell-cli listener create --name http1 --type http --port 443
    ///   red-cell-cli listener access http1
    ///   red-cell-cli listener set-access http1 --allow-operator alice
    #[command(verbatim_doc_comment)]
    Listener {
        #[command(subcommand)]
        action: ListenerCommands,
    },

    /// Build and manage payloads.
    ///
    /// Examples:
    ///   red-cell-cli payload list
    ///   red-cell-cli payload build --listener http1 --os windows --arch x86_64
    ///   red-cell-cli payload download <id> --out ./payload.exe
    #[command(verbatim_doc_comment)]
    Payload {
        #[command(subcommand)]
        action: PayloadCommands,
    },

    /// Manage operators and role-based access control.
    ///
    /// Examples:
    ///   red-cell-cli operator list
    ///   red-cell-cli operator active
    ///   red-cell-cli operator create alice --role operator
    ///   red-cell-cli operator set-role alice admin
    ///   red-cell-cli operator logout alice
    ///   red-cell-cli operator show-agent-groups alice
    ///   red-cell-cli operator set-agent-groups bob --group corp-dc
    #[command(verbatim_doc_comment)]
    Operator {
        #[command(subcommand)]
        action: OperatorCommands,
    },

    /// Browse and download captured loot (screenshots, credentials, files).
    ///
    /// Examples:
    ///   red-cell-cli loot list
    ///   red-cell-cli loot list --kind screenshot
    ///   red-cell-cli loot download 42 --out ./screenshot.png
    #[command(verbatim_doc_comment)]
    Loot {
        #[command(subcommand)]
        action: LootCommands,
    },

    /// Validate a YAOTL profile without starting the teamserver.
    ///
    /// Parses and validates the profile at <path>, reporting parse errors and
    /// semantic validation failures as structured JSON.  No server connection
    /// is required — this is a purely local operation.
    ///
    /// Examples:
    ///   red-cell-cli profile validate profiles/havoc.yaotl
    ///   red-cell-cli profile validate /tmp/test.yaotl --output text
    #[command(verbatim_doc_comment)]
    Profile {
        #[command(subcommand)]
        action: ProfileCommands,
    },

    /// View and stream the audit log.
    ///
    /// Examples:
    ///   red-cell-cli log list
    ///   red-cell-cli log list --operator alice --limit 50
    ///   red-cell-cli log tail
    ///   red-cell-cli log tail --follow --max-failures 10
    #[command(name = "log", verbatim_doc_comment)]
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Start a persistent JSON-pipe session for long-running agent interactions.
    ///
    /// Reads newline-delimited JSON commands from stdin and writes successful
    /// JSON responses to stdout and structured errors to stderr.  Keeps a
    /// single authenticated connection open so re-auth overhead is paid only once.
    ///
    /// If --agent is given, commands that require an agent ID will use it as
    /// the default when "id" is not present in the JSON message.
    ///
    /// Examples:
    ///   red-cell-cli session
    ///   red-cell-cli session --agent abc123
    ///   echo '{"cmd":"ping"}' | red-cell-cli session
    #[command(verbatim_doc_comment)]
    Session {
        /// Default agent ID (used when a command does not include "id")
        #[arg(long)]
        agent: Option<AgentId>,
    },

    /// Authenticate and persist credentials to the CLI config file.
    ///
    /// Validates the provided token against the teamserver health endpoint,
    /// then writes server URL, token, and (optionally) certificate fingerprint
    /// to ~/.config/red-cell-cli/config.toml.
    ///
    /// The --token value is the API key from the teamserver profile.
    /// Token expiry / refresh is not implemented in v1.
    ///
    /// Examples:
    ///   RC_TOKEN=myapikey red-cell-cli login --server https://ts:40056
    ///   cat /path/to/keyfile | red-cell-cli login --server https://ts:40056 --token-stdin
    ///   red-cell-cli login --server https://ts:40056 --token myapikey --cert-fingerprint ab12...
    #[command(verbatim_doc_comment)]
    Login {
        /// Teamserver base URL (e.g. https://teamserver:40056).
        /// Required — the global --server flag is ignored for login.
        #[arg(long, required = true)]
        server: String,

        /// API token (the api_key value from the teamserver profile).
        /// Prefer RC_TOKEN env var or --token-stdin over this flag to avoid
        /// leaking the token in shell history and process listings.
        #[arg(long, env = "RC_TOKEN", required_unless_present = "token_stdin")]
        token: Option<String>,

        /// Read the API token from stdin (one line). Avoids process-list and
        /// shell-history exposure entirely.
        #[arg(long, conflicts_with = "token")]
        token_stdin: bool,

        /// SHA-256 certificate fingerprint for TLS pinning (lowercase hex, 64 chars).
        /// Stored alongside server and token in the config file.
        #[arg(long)]
        cert_fingerprint: Option<String>,
    },

    /// Generate shell tab-completion scripts.
    ///
    /// Install completions by redirecting stdout to the appropriate file:
    ///   bash: red-cell-cli completion bash > ~/.local/share/bash-completion/completions/red-cell-cli
    ///   zsh:  red-cell-cli completion zsh  > ~/.zfunc/_red-cell-cli
    ///   fish: red-cell-cli completion fish > ~/.config/fish/completions/red-cell-cli.fish
    ///
    /// Examples:
    ///   red-cell-cli completion bash
    ///   red-cell-cli completion zsh
    ///   red-cell-cli completion fish
    #[command(verbatim_doc_comment)]
    Completion {
        /// Target shell
        shell: clap_complete::Shell,
    },

    /// Show help for a subcommand (alias: `<command> --help`).
    ///
    /// Examples:
    ///   red-cell-cli help
    ///   red-cell-cli help agent
    ///   red-cell-cli help listener
    #[command(verbatim_doc_comment)]
    Help {
        /// Subcommand to show help for (omit for top-level help)
        command: Option<String>,
    },
}
