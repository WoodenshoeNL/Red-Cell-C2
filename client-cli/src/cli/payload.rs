use clap::Subcommand;

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
