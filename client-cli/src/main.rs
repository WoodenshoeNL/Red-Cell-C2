use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

/// Red Cell C2 command-line client.
///
/// Communicates with a Red Cell teamserver over its JSON/WebSocket API.
/// All subcommands require a running teamserver and valid credentials.
#[derive(Debug, Parser)]
#[command(name = "red-cell-cli", author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Teamserver URL (e.g. wss://127.0.0.1:8443)
    #[arg(long, short = 's', env = "RED_CELL_SERVER", global = true)]
    pub server: Option<String>,

    /// Authentication token
    #[arg(long, short = 't', env = "RED_CELL_TOKEN", global = true)]
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

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Manage listeners (HTTP/S, DNS, SMB)
    Listener {
        #[command(subcommand)]
        action: ListenerCommands,
    },
    /// Manage connected agents
    Agent {
        #[command(subcommand)]
        action: AgentCommands,
    },
    /// Build and manage payloads
    Payload {
        #[command(subcommand)]
        action: PayloadCommands,
    },
    /// Manage operators and role-based access control
    Operator {
        #[command(subcommand)]
        action: OperatorCommands,
    },
    /// View and tail the audit log
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },
    /// Check teamserver connectivity and show current identity
    Status,
    /// Start an interactive session with an agent (persistent JSON pipe)
    Session {
        /// Agent ID to open a session with
        agent_id: String,
    },
}

/// Listener subcommands.
#[derive(Debug, Subcommand)]
pub enum ListenerCommands {
    /// List all configured listeners
    List,
    /// Show details of a single listener
    Show {
        /// Listener ID or name
        id: String,
    },
    /// Create a new listener from a profile
    Create {
        /// Path to HCL listener profile
        #[arg(long)]
        profile: String,
    },
    /// Start a stopped listener
    Start {
        /// Listener ID or name
        id: String,
    },
    /// Stop a running listener
    Stop {
        /// Listener ID or name
        id: String,
    },
    /// Delete a listener (must be stopped first)
    Delete {
        /// Listener ID or name
        id: String,
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
        command: String,
        /// Wait for the output before returning
        #[arg(long)]
        wait: bool,
    },
    /// Retrieve task output from an agent
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
    },
    /// Upload a file to an agent
    Upload {
        /// Agent ID
        id: String,
        /// Local file path to upload
        #[arg(long)]
        src: String,
        /// Destination path on the agent
        #[arg(long)]
        dst: String,
    },
    /// Download a file from an agent
    Download {
        /// Agent ID
        id: String,
        /// Remote file path to download
        #[arg(long)]
        src: String,
        /// Local destination path
        #[arg(long)]
        dst: String,
    },
}

/// Payload subcommands.
#[derive(Debug, Subcommand)]
pub enum PayloadCommands {
    /// Build a new payload
    Build {
        /// Listener ID the payload should connect back to
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
    /// Download a built payload
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
        /// Initial role (admin, operator, viewer)
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
    /// List audit log entries with optional filters
    List {
        /// Filter by operator username
        #[arg(long)]
        operator: Option<String>,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Maximum number of entries to return
        #[arg(long, default_value = "100")]
        limit: u32,
    },
    /// Stream new audit log entries as they arrive
    Tail,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if cli.command.is_none() {
        // Print help and exit when invoked with no subcommand.
        use clap::CommandFactory;
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        None => unreachable!("handled above"),
        Some(cmd) => {
            tracing::debug!(?cmd, "dispatching subcommand");
            // Subcommand implementations are tracked in downstream issues.
            // Each subcommand will establish a WebSocket connection to the
            // teamserver using cli.server and cli.token, execute the operation,
            // and write output according to cli.output.
            eprintln!(
                "subcommand not yet implemented — see downstream issues for red-cell-c2-wlzon"
            );
            tracing::info!("stub run reached for {:?}", cmd);
            Ok(())
        }
    }
}
