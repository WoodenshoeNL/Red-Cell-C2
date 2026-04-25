//! Clap schema for `red-cell-cli`: global flags and all subcommand enums.

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
    ///   red-cell-cli login --server https://ts:40056 --token myapikey
    ///   red-cell-cli login --server https://ts:40056 --token myapikey --cert-fingerprint ab12...
    #[command(verbatim_doc_comment)]
    Login {
        /// Teamserver base URL (e.g. https://teamserver:40056).
        /// Required — the global --server flag is ignored for login.
        #[arg(long, required = true)]
        server: String,

        /// API token (the api_key value from the teamserver profile)
        #[arg(long, required = true)]
        token: String,

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

// ── profile subcommands ──────────────────────────────────────────────────────

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
}

// ── agent subcommands ─────────────────────────────────────────────────────────

/// Agent subcommands.
#[derive(Debug, Subcommand)]
pub enum AgentCommands {
    /// List all registered agents.
    ///
    /// With --watch, prints the initial list then streams JSON-Lines events
    /// (checkin, disconnect, status_change) as the agent roster changes,
    /// until Ctrl-C.
    ///
    /// Examples:
    ///   red-cell-cli agent list
    ///   red-cell-cli agent list --watch
    ///   red-cell-cli agent list --watch --max-failures 10
    #[command(verbatim_doc_comment)]
    List {
        /// Stream agent roster changes as JSON-Lines events until Ctrl-C.
        #[arg(long, help = crate::defaults::agent_list_watch_help())]
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
    /// `--since` is the numeric output entry id (database row id) used as an
    /// incremental polling cursor. If the teamserver prunes or resets its log,
    /// a saved cursor may point past the newest retained row: the CLI then sees
    /// no matching entries. On the first empty response with `--since` greater
    /// than zero, **stderr** emits `{"warning":"cursor_reset","missed_from":N}`
    /// so automated consumers can resync (for example re-run without `--since`)
    /// instead of waiting forever for a marker that was pruned.
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
        /// Numeric output entry id — only fetch rows with id greater than this cursor
        #[arg(long)]
        since: Option<i64>,
    },

    /// Send a kill task to an agent and optionally wait for acknowledgement.
    ///
    /// By default, queues a CommandExit task on the teamserver for the agent
    /// to pick up on its next check-in, then returns immediately. Use --wait
    /// to block until the agent reports status "dead".
    ///
    /// When the agent is unresponsive, --force sends the kill task and then
    /// immediately deregisters the agent server-side without waiting.
    /// --deregister-only skips the kill task entirely and only removes the
    /// agent from the teamserver registry.
    ///
    /// Examples:
    ///   red-cell-cli agent kill abc123
    ///   red-cell-cli agent kill abc123 --wait
    ///   red-cell-cli agent kill abc123 --force
    ///   red-cell-cli agent kill abc123 --deregister-only
    #[command(verbatim_doc_comment)]
    Kill {
        /// Agent ID
        id: AgentId,
        /// Block until the agent's status becomes "dead"
        #[arg(long, conflicts_with_all = ["force", "deregister_only"])]
        wait: bool,
        /// Send kill task then immediately deregister the agent server-side
        /// without waiting for acknowledgement
        #[arg(long, conflicts_with_all = ["wait", "deregister_only"])]
        force: bool,
        /// Skip the kill task entirely — only remove the agent from the
        /// teamserver registry (server-side deregistration)
        #[arg(long, conflicts_with_all = ["wait", "force"])]
        deregister_only: bool,
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

    /// Open an interactive shell against a connected agent.
    ///
    /// Each input line is dispatched as `agent exec --wait`. Output is printed
    /// as plain text (no JSON envelope). Built-in commands: `help`, `exit`,
    /// `!<cmd>` (run on local host), `upload <src> <dst>`, `download <src> <dst>`,
    /// `sleep <secs>`.
    ///
    /// Examples:
    ///   red-cell-cli agent shell abc123
    ///   red-cell-cli agent shell abc123 --timeout 120
    #[command(verbatim_doc_comment)]
    Shell {
        /// Agent ID
        id: AgentId,
        /// Per-command timeout in seconds (default: 60)
        #[arg(long)]
        timeout: Option<u64>,
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

        /// Accept legacy Demon packets (0xDEADBEEF magic) on HTTP listeners.
        /// Required when the listener will receive traffic from unmodified
        /// Havoc Demon or Archon agents that have not been recompiled for the
        /// new protocol.
        #[arg(long, default_value_t = false)]
        legacy_mode: bool,

        /// Routable callback address(es) that agents use to reach this
        /// listener (repeat for multiple: --hosts 1.2.3.4 --hosts 5.6.7.8).
        /// Used when the teamserver bind address is not directly reachable
        /// from target hosts (e.g. NAT, redirector, or multi-homed setup).
        #[arg(long = "hosts", value_name = "HOST")]
        hosts: Vec<String>,

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
    ///   red-cell-cli listener start --name http1
    #[command(verbatim_doc_comment)]
    Start {
        /// Listener name (positional)
        #[arg(conflicts_with = "name_flag", required_unless_present = "name_flag")]
        name: Option<String>,
        /// Listener name (flag, alias for positional)
        #[arg(long = "name", id = "name_flag", required_unless_present = "name")]
        name_flag: Option<String>,
    },

    /// Stop a running listener (idempotent: already-stopped returns ok).
    ///
    /// Examples:
    ///   red-cell-cli listener stop http1
    ///   red-cell-cli listener stop --name http1
    #[command(verbatim_doc_comment)]
    Stop {
        /// Listener name (positional)
        #[arg(conflicts_with = "name_flag", required_unless_present = "name_flag")]
        name: Option<String>,
        /// Listener name (flag, alias for positional)
        #[arg(long = "name", id = "name_flag", required_unless_present = "name")]
        name_flag: Option<String>,
    },

    /// Delete a listener.
    ///
    /// Examples:
    ///   red-cell-cli listener delete http1
    ///   red-cell-cli listener delete --name http1
    #[command(verbatim_doc_comment)]
    Delete {
        /// Listener name (positional)
        #[arg(conflicts_with = "name_flag", required_unless_present = "name_flag")]
        name: Option<String>,
        /// Listener name (flag, alias for positional)
        #[arg(long = "name", id = "name_flag", required_unless_present = "name")]
        name_flag: Option<String>,
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
    /// With --detach:  always returns immediately (overrides --wait if both set).
    ///
    /// Examples:
    ///   red-cell-cli payload build --listener http1 --arch x86_64 --format exe
    ///   red-cell-cli payload build --listener dns1  --arch aarch64 --format bin --sleep 5 --wait
    ///   red-cell-cli payload build --listener http1 --arch x86_64 --format bin --agent phantom
    ///   red-cell-cli payload build --detach --listener http1 --arch x86_64 --format exe
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
        /// Return immediately with the job_id (explicit async mode)
        #[arg(long)]
        detach: bool,
    },

    /// Check the status of a running payload build job.
    ///
    /// Examples:
    ///   red-cell-cli payload build-status <job-id>
    #[command(verbatim_doc_comment)]
    BuildStatus {
        /// Build job ID returned by `payload build`
        job_id: String,
    },

    /// Wait for a payload build job to finish, optionally saving the artifact.
    ///
    /// Polls until the build completes or fails, then returns the result.
    /// With --output: downloads the built payload to the given path on success.
    ///
    /// Examples:
    ///   red-cell-cli payload build-wait <job-id>
    ///   red-cell-cli payload build-wait <job-id> --output ./payload.exe
    #[command(verbatim_doc_comment)]
    BuildWait {
        /// Build job ID returned by `payload build`
        job_id: String,
        /// Local path to write the built payload on success
        #[arg(long)]
        output: Option<String>,
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

    /// Flush all cached payload build artifacts (admin only).
    ///
    /// Examples:
    ///   red-cell-cli payload cache-flush
    #[command(verbatim_doc_comment)]
    CacheFlush,

    /// Inspect a built payload file and display its embedded build configuration.
    ///
    /// Reads the local file and extracts the build manifest embedded by the
    /// teamserver at build time.  Does not require a server connection.
    ///
    /// Examples:
    ///   red-cell-cli payload inspect ./demon.exe
    ///   red-cell-cli payload inspect /tmp/phantom
    #[command(verbatim_doc_comment)]
    Inspect {
        /// Path to the payload binary file
        file: String,
    },
}

// ── operator subcommands ──────────────────────────────────────────────────────

/// Operator subcommands.
#[derive(Debug, Subcommand)]
pub enum OperatorCommands {
    /// Print the currently authenticated operator's name and role.
    ///
    /// Examples:
    ///   red-cell-cli operator whoami
    #[command(verbatim_doc_comment)]
    Whoami,

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

    /// List operators with active WebSocket connections.
    ///
    /// Examples:
    ///   red-cell-cli operator active
    #[command(verbatim_doc_comment)]
    Active,

    /// Revoke all active sessions for an operator.
    ///
    /// Examples:
    ///   red-cell-cli operator logout alice
    #[command(verbatim_doc_comment)]
    Logout {
        /// Operator whose sessions should be revoked
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
}

// ── audit/log subcommands ─────────────────────────────────────────────────────

/// Audit log subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommands {
    /// List audit log entries (newest first).
    ///
    /// With --follow, prints the initial list then streams new entries
    /// matching the given filters as JSON-Lines until Ctrl-C.
    ///
    /// Examples:
    ///   red-cell-cli log list
    ///   red-cell-cli log list --operator alice --limit 50
    ///   red-cell-cli log list --action exec
    ///   red-cell-cli log list --since 2026-03-21T00:00:00Z --agent abc123
    ///   red-cell-cli log list --since 2026-03-21T00:00:00Z --until 2026-03-22T00:00:00Z
    ///   red-cell-cli log list --follow --action exec
    ///   red-cell-cli log list --follow --operator alice
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
        /// Only return entries at or before this ISO 8601 UTC timestamp
        #[arg(long)]
        until: Option<String>,
        /// Maximum entries to return (initial fetch only when combined with --follow)
        #[arg(long, default_value = "100")]
        limit: u32,
        /// Stream new entries as JSON-Lines until Ctrl-C (filters still apply).
        #[arg(long, help = crate::defaults::audit_list_follow_help())]
        follow: bool,
        /// Exit with timeout (code 5) after this many consecutive HTTP request
        /// timeouts while polling (only applies with `--follow`).
        #[arg(
            long,
            default_value_t = crate::defaults::WATCH_MAX_FAILURES_DEFAULT,
            value_parser = clap::value_parser!(u32).range(1..=1024)
        )]
        max_failures: u32,
    },

    /// Delete audit log entries older than the configured retention period.
    ///
    /// When `--older-than-days` is omitted, the teamserver uses the value
    /// configured in its HCL profile (default: 90 days).
    ///
    /// Examples:
    ///   red-cell-cli log purge --confirm
    ///   red-cell-cli log purge --confirm --older-than-days 30
    #[command(verbatim_doc_comment)]
    Purge {
        /// Required confirmation flag — prevents accidental data loss.
        #[arg(long)]
        confirm: bool,
        /// Override the retention window for this purge (in days).
        #[arg(long)]
        older_than_days: Option<u32>,
    },

    /// Stream new audit log entries as they arrive.
    ///
    /// Prints the last 20 entries.  With --follow, streams new entries as
    /// JSON lines until Ctrl-C.
    ///
    /// Examples:
    ///   red-cell-cli log tail
    ///   red-cell-cli log tail --follow
    ///   red-cell-cli log tail --follow --max-failures 10
    #[command(verbatim_doc_comment)]
    Tail {
        #[arg(long, help = crate::defaults::audit_tail_follow_help())]
        follow: bool,
        /// Exit with timeout (code 5) after this many consecutive HTTP request
        /// timeouts while polling (only applies with `--follow`). Transient
        /// timeouts are retried with exponential backoff; each retry logs a
        /// warning to stderr.
        #[arg(
            long,
            default_value_t = crate::defaults::AUDIT_TAIL_FOLLOW_MAX_FAILURES_DEFAULT,
            value_parser = clap::value_parser!(u32).range(1..=1024)
        )]
        max_failures: u32,
    },

    /// Fetch recent teamserver log output.
    ///
    /// Retrieves log messages from the teamserver's in-memory ring buffer
    /// via the /api/v1/debug/server-logs endpoint.
    ///
    /// Examples:
    ///   red-cell-cli log server-tail
    ///   red-cell-cli log server-tail --lines 200
    ///   red-cell-cli log server-tail --lines 50
    #[command(verbatim_doc_comment)]
    ServerTail {
        /// Maximum number of log lines to return (most-recent last).
        #[arg(long, default_value_t = 200)]
        lines: u32,
    },
}
