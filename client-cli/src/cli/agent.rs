use clap::Subcommand;

use crate::AgentId;

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
    /// as plain text (no JSON envelope). Requires `--unsafe-tty` because stdout
    /// is unstructured and the REPL is interactive — violating the CLI output
    /// contract. For machine-consumable agent interaction, use `session --agent`.
    ///
    /// Built-in commands: `help`, `exit`, `upload <src> <dst>`,
    /// `download <src> <dst>`, `sleep <secs> [jitter%]`.
    ///
    /// The `!<cmd>` built-in executes `<cmd>` on the OPERATOR HOST (not the
    /// remote agent). It is disabled by default; pass `--enable-local-shell`
    /// or set `enable_local_shell = true` in the config file to opt in.
    /// Every invocation is logged for audit purposes.
    ///
    /// Examples:
    ///   red-cell-cli agent shell abc123 --unsafe-tty
    ///   red-cell-cli agent shell abc123 --unsafe-tty --timeout 120
    ///   red-cell-cli agent shell abc123 --unsafe-tty --enable-local-shell
    #[command(verbatim_doc_comment)]
    Shell {
        /// Agent ID
        id: AgentId,
        /// Per-command timeout in seconds (default: 60)
        #[arg(long)]
        timeout: Option<u64>,
        /// Acknowledge that this command uses interactive I/O and raw stdout
        /// (not the standard JSON envelope).
        #[arg(long)]
        unsafe_tty: bool,
        /// Allow `!<cmd>` to execute commands on the local operator host.
        /// Disabled by default. Also settable via `enable_local_shell = true`
        /// in the config file or `RC_ENABLE_LOCAL_SHELL=1` env var.
        #[arg(long)]
        enable_local_shell: bool,
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

    /// Introspect a task by id: queue position, dispatch context, persisted
    /// callback rows, and a machine-friendly `lifecycle` label (`queued`,
    /// `dispatched_pending`, `responses_present`, `unknown`).
    ///
    /// Use after `agent exec` without `--wait` (or when `--wait` times out with
    /// exit 5) to see whether the job is still queued, was dispatched, or has
    /// stored output under correlated `request_id` / response row ids.
    ///
    /// Examples:
    ///   red-cell-cli agent task DEADBEEF --task-id A1B2C3D4
    #[command(verbatim_doc_comment)]
    Task {
        /// Agent ID
        id: AgentId,
        /// Task id returned when the job was submitted (`task_id` in JSON)
        #[arg(long)]
        task_id: String,
    },

    /// Fetch the last N raw protocol frames captured for an agent.
    ///
    /// Returns hex-encoded frames from the server-side packet ring-buffer.
    /// When the ring-buffer backing store is not yet populated the `frames`
    /// array will be empty and the response will include a `note` field.
    ///
    /// Used by the diagnostic bundle writer to populate `last_packets.bin`.
    ///
    /// Examples:
    ///   red-cell-cli agent packet-ring DEADBEEF
    ///   red-cell-cli agent packet-ring DEADBEEF --n 10
    #[command(verbatim_doc_comment)]
    PacketRing {
        /// Agent ID
        id: AgentId,
        /// Number of frames to request per direction (default: 5, server caps at 20)
        #[arg(long, default_value_t = 5)]
        n: u8,
    },
}
