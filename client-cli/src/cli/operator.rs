use clap::Subcommand;

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
