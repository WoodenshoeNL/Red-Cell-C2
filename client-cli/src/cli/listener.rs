use clap::Subcommand;

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
