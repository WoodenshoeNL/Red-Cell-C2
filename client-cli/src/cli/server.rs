use clap::Subcommand;

/// Server inspection subcommands.
#[derive(Debug, Subcommand)]
pub enum ServerCommands {
    /// Fetch the teamserver's TLS certificate fingerprint and metadata.
    ///
    /// Performs a TLS handshake and reports the SHA-256 fingerprint of the
    /// server certificate.  No authentication is required — only `--server`
    /// is needed.  The fingerprint is the value used with `--cert-fingerprint`
    /// for TLS pinning.
    ///
    /// Examples:
    ///   red-cell-cli server cert                         # leaf fingerprint (JSON)
    ///   red-cell-cli server cert --output text            # plain hex to stdout
    ///   red-cell-cli server cert --chain                  # all certs in the chain
    ///   red-cell-cli server cert --pem                    # include PEM-encoded certs
    #[command(verbatim_doc_comment)]
    Cert {
        /// Include all certificates in the chain, not just the leaf.
        #[arg(long)]
        chain: bool,

        /// Include PEM-encoded certificate data in the output.
        #[arg(long)]
        pem: bool,
    },
}
