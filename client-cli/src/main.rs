use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

mod client;
mod commands;
mod config;
mod error;
mod output;

use error::{CliError, EXIT_SUCCESS};

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

    /// Request timeout in seconds
    #[arg(long, global = true, default_value = "30")]
    pub timeout: u64,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Output format for command results.
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Structured JSON (machine-readable, default)
    Json,
    /// Human-readable text
    Text,
}

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
    #[command(verbatim_doc_comment)]
    Operator {
        #[command(subcommand)]
        action: OperatorCommands,
    },

    /// View and stream the audit log.
    ///
    /// Examples:
    ///   red-cell-cli audit list
    ///   red-cell-cli audit tail
    #[command(verbatim_doc_comment)]
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Start a persistent JSON-pipe session with an agent.
    ///
    /// Examples:
    ///   red-cell-cli session --agent abc123
    #[command(verbatim_doc_comment)]
    Session {
        /// Agent ID to open a session with
        #[arg(long)]
        agent: String,
    },
}

/// Agent subcommands.
#[derive(Debug, Subcommand)]
pub enum AgentCommands {
    /// List all registered agents
    List,
    /// Show details of a single agent
    Show {
        /// Agent ID
        id: String,
    },
    /// Execute a shell command on an agent
    Exec {
        /// Agent ID
        id: String,
        /// Command to execute
        #[arg(long)]
        cmd: String,
        /// Wait for output before returning
        #[arg(long)]
        wait: bool,
        /// Override per-command timeout (seconds)
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Retrieve pending task output from an agent
    Output {
        /// Agent ID
        id: String,
        /// Stream new output as it arrives
        #[arg(long)]
        watch: bool,
    },
    /// Terminate an agent
    Kill {
        /// Agent ID
        id: String,
        /// Wait for confirmation before returning
        #[arg(long)]
        wait: bool,
    },
    /// Upload a file to an agent
    Upload {
        /// Agent ID
        id: String,
        /// Local source file path
        #[arg(long)]
        src: String,
        /// Remote destination path on the agent
        #[arg(long)]
        dst: String,
    },
    /// Download a file from an agent
    Download {
        /// Agent ID
        id: String,
        /// Remote source path on the agent
        #[arg(long)]
        src: String,
        /// Local destination path
        #[arg(long)]
        dst: String,
    },
}

/// Listener subcommands.
#[derive(Debug, Subcommand)]
pub enum ListenerCommands {
    /// List all configured listeners
    List,
    /// Show details of a listener
    Show {
        /// Listener name or ID
        name: String,
    },
    /// Create a new listener
    Create {
        /// Listener name
        #[arg(long)]
        name: String,
        /// Protocol (http, dns, smb, external)
        #[arg(long = "type")]
        listener_type: String,
    },
    /// Start a stopped listener
    Start {
        /// Listener name or ID
        name: String,
    },
    /// Stop a running listener
    Stop {
        /// Listener name or ID
        name: String,
    },
    /// Delete a listener (must be stopped first)
    Delete {
        /// Listener name or ID
        name: String,
    },
}

/// Payload subcommands.
#[derive(Debug, Subcommand)]
pub enum PayloadCommands {
    /// Build a new payload
    Build {
        /// Listener ID the payload connects back to
        #[arg(long)]
        listener: String,
        /// Target OS (windows, linux, macos)
        #[arg(long)]
        os: String,
        /// Target architecture (x86_64, x86, aarch64)
        #[arg(long)]
        arch: String,
    },
    /// List previously built payloads
    List,
    /// Download a built payload to disk
    Download {
        /// Payload ID
        id: String,
        /// Local output path
        #[arg(long)]
        out: String,
    },
}

/// Operator subcommands.
#[derive(Debug, Subcommand)]
pub enum OperatorCommands {
    /// List all operators
    List,
    /// Create a new operator account
    Create {
        /// Operator username
        username: String,
        /// Role (admin, operator, viewer)
        #[arg(long, default_value = "operator")]
        role: String,
    },
    /// Delete an operator account
    Delete {
        /// Operator username
        username: String,
    },
    /// Change an operator's role
    SetRole {
        /// Operator username
        username: String,
        /// New role (admin, operator, viewer)
        role: String,
    },
}

/// Audit log subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommands {
    /// List audit log entries (newest first)
    List {
        /// Filter by operator username
        #[arg(long)]
        operator: Option<String>,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Maximum entries to return
        #[arg(long, default_value = "100")]
        limit: u32,
    },
    /// Stream new audit log entries as they arrive
    Tail,
}

// ── entry point ──────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Bare invocation: print help and exit 0.
    if cli.command.is_none() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        cmd.print_help().unwrap_or(());
        println!();
        std::process::exit(EXIT_SUCCESS);
    }

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fatal: failed to build async runtime: {e}");
            std::process::exit(error::EXIT_GENERAL);
        }
    };

    let exit_code = rt.block_on(dispatch(cli));
    std::process::exit(exit_code);
}

// ── async dispatcher ─────────────────────────────────────────────────────────

async fn dispatch(cli: Cli) -> i32 {
    // Resolve configuration (CLI flags + env vars were already absorbed by
    // clap; this step adds the file-based fallbacks).
    let resolved = match config::resolve(cli.server, cli.token, cli.timeout) {
        Ok(cfg) => cfg,
        Err(e) => {
            let err: CliError = e.into();
            output::print_error(&err);
            return err.exit_code();
        }
    };

    // Build the shared API client.
    let api_client = match client::ApiClient::new(&resolved) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e);
            return e.exit_code();
        }
    };

    let Some(command) = cli.command else {
        // Unreachable: bare invocation is handled in main().
        return EXIT_SUCCESS;
    };

    match command {
        Commands::Status => match commands::status::run(&api_client).await {
            Ok(data) => {
                output::print_success(&data);
                EXIT_SUCCESS
            }
            Err(e) => {
                output::print_error(&e);
                e.exit_code()
            }
        },
        // Remaining commands are implemented in downstream issues.
        Commands::Agent { .. }
        | Commands::Listener { .. }
        | Commands::Payload { .. }
        | Commands::Operator { .. }
        | Commands::Audit { .. }
        | Commands::Session { .. } => {
            let err = CliError::General("this subcommand is not yet implemented".to_owned());
            output::print_error(&err);
            err.exit_code()
        }
    }
}
