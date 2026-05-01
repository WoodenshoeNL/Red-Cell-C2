use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::{Parser, Subcommand};
use red_cell::{
    AgentLivenessMonitor, AgentRegistry, ApiRuntime, AuditLogPruner, AuditWebhookNotifier,
    AuthService, DEFAULT_AUDIT_PRUNE_INTERVAL_SECS, DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_BACKUP_INTERVAL_SECS, DEFAULT_DEGRADED_THRESHOLD, DEFAULT_MAX_REGISTERED_AGENTS,
    DEFAULT_PROBE_SECS, DEFAULT_QUERY_TIMEOUT_SECS, DEFAULT_WRITE_QUEUE_CAPACITY, Database,
    DatabaseBackupScheduler, DatabaseHealthMonitor, DbMasterKey, EventBus, ListenerManager,
    ListenerManagerError, LoginRateLimiter, NormalizedMakeService, OperatorConnectionManager,
    PayloadBuilderService, PluginRuntime, SocketRelayManager, TeamserverState, WriteQueue,
    build_router, spawn_agent_liveness_monitor,
};
use red_cell_common::config::{Profile, ProfileValidationError};
use red_cell_common::tls::{
    TlsKeyAlgorithm, install_default_crypto_provider, resolve_or_persist_tls_identity,
};
use rustls_pki_types::pem::PemObject;
use tokio::net::lookup_host;
use tracing::{info, instrument, warn};

mod logging;
mod preflight;

#[derive(Debug, Clone, Parser)]
#[command(name = "red-cell", about = "Red Cell teamserver")]
struct Cli {
    /// Path to the Havoc-compatible YAOTL profile.
    #[arg(long)]
    profile: PathBuf,
    /// Optional SQLite database path. Defaults to `<profile>.sqlite`.
    #[arg(long)]
    database: Option<PathBuf>,
    /// Enable debug-level logging.
    #[arg(long, default_value_t = false)]
    debug: bool,
    /// Enable wire-corpus capture.  Every agent HTTP request and response is
    /// written to `<DIR>/<agent_type>/<agent_id>/` in the CorpusPacketMeta
    /// format (see `common/src/corpus.rs`).  Session keys are exported to
    /// `session.keys.json`.  Requires `--capture-corpus` to be set on the
    /// Python test harness as well for the directories to match.
    #[arg(long, value_name = "DIR")]
    capture_corpus: Option<PathBuf>,
    /// Subcommand to run. If omitted, starts the teamserver.
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Clone, Subcommand)]
enum CliCommand {
    /// Create a hot backup of the SQLite database using VACUUM INTO.
    ///
    /// The backup file is named `red-cell-YYYYMMDD-HHMMSS.db` and written to
    /// the specified output directory.  Safe to run against a live teamserver.
    #[command(name = "db-backup")]
    DbBackup {
        /// Directory to write the backup file into.
        #[arg(long)]
        output_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let profile = load_profile(&cli.profile)
        .with_context(|| format!("failed to load profile from {}", cli.profile.display()))?;
    let _logging_guard = logging::init_tracing(Some(&profile), cli.debug)
        .map_err(|error| anyhow!("failed to initialize tracing: {error}"))?;

    if profile.demon.allow_legacy_ctr {
        warn!(
            "DEPRECATION WARNING: AllowLegacyCtr = true is set in your profile. \
             Legacy CTR mode resets the AES-CTR keystream to block offset 0 for every \
             packet, creating a two-time-pad vulnerability (P1 ⊕ P2 = C1 ⊕ C2). \
             Support for AllowLegacyCtr will be REMOVED on 2027-01-01. \
             Migrate Demon/Archon agents to Specter (Windows) or Phantom (Linux) before \
             that date — recompile with the new stager pointing to the same listener URL. \
             See docs/operator-security.md for the migration procedure."
        );
    }

    let database_path = resolve_database_path(&cli.profile, cli.database.as_ref());
    let master_key = load_or_create_master_key(&database_path).with_context(|| {
        format!("failed to load database master key for {}", database_path.display())
    })?;

    preflight::run(&profile, &master_key, &database_path)
        .context("startup preflight checks failed")?;

    let database = Database::connect_with_master_key(&database_path, master_key)
        .await
        .with_context(|| format!("failed to open database {}", database_path.display()))?;

    // Handle subcommands that only need the database, then exit.
    if let Some(cmd) = cli.command {
        return run_subcommand(cmd, &database).await;
    }

    let mut agent_registry = AgentRegistry::load_with_max_registered_agents(
        database.clone(),
        profile.teamserver.max_registered_agents.unwrap_or(DEFAULT_MAX_REGISTERED_AGENTS),
    )
    .await?;
    let events = EventBus::default();

    // Create a bounded write queue for deferred DB writes during degraded mode.
    let wq_capacity = profile
        .teamserver
        .database
        .as_ref()
        .and_then(|c| c.write_queue_capacity)
        .unwrap_or(DEFAULT_WRITE_QUEUE_CAPACITY);
    let write_queue = WriteQueue::new(wq_capacity);

    // Spawn database health monitor with write queue for automatic flush on recovery.
    let _db_health_monitor = {
        let db_cfg = profile.teamserver.database.as_ref();
        let timeout = Duration::from_secs(
            db_cfg.and_then(|c| c.query_timeout_secs).unwrap_or(DEFAULT_QUERY_TIMEOUT_SECS),
        );
        let threshold =
            db_cfg.and_then(|c| c.degraded_threshold).unwrap_or(DEFAULT_DEGRADED_THRESHOLD);
        let probe_interval =
            Duration::from_secs(db_cfg.and_then(|c| c.probe_secs).unwrap_or(DEFAULT_PROBE_SECS));
        info!(?timeout, threshold, ?probe_interval, "starting database health monitor");
        DatabaseHealthMonitor::spawn_with_write_queue(
            database.clone(),
            events.clone(),
            timeout,
            threshold,
            probe_interval,
            Some(write_queue.clone()),
        )
    };

    // Attach degraded-mode support to the agent registry so that writes are
    // buffered when the database circuit-breaker is open.
    agent_registry
        .set_degraded_mode_support(_db_health_monitor.health_state().clone(), write_queue);

    let _db_backup_scheduler: Option<DatabaseBackupScheduler> = {
        let db_cfg = profile.teamserver.database.as_ref();
        if let Some(dir_str) = db_cfg.and_then(|c| c.backup_dir.as_deref()) {
            let backup_dir = PathBuf::from(dir_str);
            let interval = Duration::from_secs(
                db_cfg.and_then(|c| c.backup_interval_secs).unwrap_or(DEFAULT_BACKUP_INTERVAL_SECS),
            );
            info!(dir = %backup_dir.display(), ?interval, "starting database backup scheduler");
            Some(DatabaseBackupScheduler::spawn(database.clone(), backup_dir, interval))
        } else {
            None
        }
    };

    let _audit_log_pruner: Option<AuditLogPruner> = {
        let db_cfg = profile.teamserver.database.as_ref();
        let retention_days =
            db_cfg.and_then(|c| c.audit_retention_days).unwrap_or(DEFAULT_AUDIT_RETENTION_DAYS);
        if retention_days > 0 {
            let interval = Duration::from_secs(
                db_cfg
                    .and_then(|c| c.audit_prune_interval_secs)
                    .unwrap_or(DEFAULT_AUDIT_PRUNE_INTERVAL_SECS),
            );
            info!(retention_days, ?interval, "starting audit-log retention pruner");
            Some(AuditLogPruner::spawn(database.clone(), retention_days, interval))
        } else {
            info!("audit-log retention pruning disabled (retention_days = 0)");
            None
        }
    };

    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let plugins = PluginRuntime::initialize(
        database.clone(),
        agent_registry.clone(),
        events.clone(),
        sockets.clone(),
        profile.teamserver.plugins_dir.as_ref().map(PathBuf::from),
    )
    .await
    .context("failed to initialize embedded Python runtime")?;
    let base_listeners = ListenerManager::with_max_download_bytes(
        database.clone(),
        agent_registry.clone(),
        events.clone(),
        sockets.clone(),
        Some(plugins.clone()),
        profile.teamserver.max_download_bytes.unwrap_or(512 * 1024 * 1024),
    );
    // Wire init-secret configuration from profile.
    // `InitSecrets` (versioned, for rotation) takes precedence over the deprecated
    // single `InitSecret` field.  Both cannot be set simultaneously (enforced by
    // profile validation).
    let mut listeners = if !profile.demon.init_secrets.is_empty() {
        let versioned: Vec<(u8, Vec<u8>)> = profile
            .demon
            .init_secrets
            .iter()
            .map(|entry| (entry.version, entry.secret.as_bytes().to_vec()))
            .collect();
        base_listeners.with_demon_init_secrets(versioned)
    } else {
        base_listeners.with_demon_init_secret(
            profile.demon.init_secret.as_deref().map(|s| s.as_bytes().to_vec()),
        )
    }
    .with_demon_allow_legacy_ctr(profile.demon.allow_legacy_ctr);
    if let Some(limit) = profile.teamserver.max_concurrent_downloads_per_agent {
        listeners = listeners.with_max_concurrent_downloads_per_agent(limit);
    }
    if let Some(limit) = profile.teamserver.max_aggregate_download_bytes {
        listeners = listeners.with_max_aggregate_download_bytes(limit);
    }
    if let Some(depth) = profile.teamserver.max_pivot_chain_depth {
        listeners = listeners.with_max_pivot_chain_depth(depth);
    }

    // Wire corpus capture when --capture-corpus is set.
    let corpus_dir = cli.capture_corpus.as_ref().map(|p| {
        let resolved = p.canonicalize().unwrap_or_else(|_| p.clone());
        info!(dir = %resolved.display(), "wire corpus capture enabled");
        resolved
    });
    if let Some(ref dir) = corpus_dir {
        listeners = listeners.with_corpus_dir(dir.clone());
    }

    plugins.attach_listener_manager(listeners.clone()).await;
    let payload_builder = PayloadBuilderService::from_profile(&profile)
        .context("failed to validate Demon build toolchain")?;
    let shutdown = listeners.shutdown_controller();
    let shutdown_timeout = Duration::from_secs(profile.teamserver.drain_timeout_secs.unwrap_or(30));

    listeners.sync_profile(&profile).await?;
    listeners.restore_running().await?;
    start_new_profile_listeners(&listeners, &profile).await?;
    let (loaded_plugins, plugins_failed) =
        plugins.load_plugins().await.context("failed to load Python plugins")?;
    let plugins_loaded = u32::try_from(loaded_plugins.len()).unwrap_or(u32::MAX);
    if !loaded_plugins.is_empty() || plugins_failed > 0 {
        info!(
            count = loaded_plugins.len(),
            failed = plugins_failed,
            plugins = ?loaded_plugins,
            "loaded Python plugins",
        );
    }

    let bind_addr = resolve_bind_addr(&profile).await?;
    install_default_crypto_provider();
    let tls_config = build_tls_config(&profile, &cli.profile).await?;
    let _agent_liveness_monitor: AgentLivenessMonitor = spawn_agent_liveness_monitor(
        agent_registry.clone(),
        sockets.clone(),
        events.clone(),
        database.clone(),
        &profile,
    );
    let metrics_handle = red_cell::install_prometheus_recorder()
        .map_err(|error| anyhow!("failed to install prometheus metrics: {error}"))?;
    let state = TeamserverState {
        profile: profile.clone(),
        profile_path: cli.profile.display().to_string(),
        auth: AuthService::from_profile_with_database(&profile, &database).await?,
        database,
        api: ApiRuntime::from_profile(&profile).context("OS RNG unavailable")?,
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry,
        sockets,
        listeners,
        payload_builder,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: shutdown.clone(),
        service_bridge: profile
            .service
            .as_ref()
            .map(|sc| red_cell::ServiceBridge::new(sc.clone()))
            .transpose()?,
        started_at: std::time::Instant::now(),
        plugins_loaded,
        plugins_failed,
        metrics: metrics_handle,
        corpus_dir,
    };
    let router = build_router(state.clone());
    let handle = Handle::new();

    if let Some(ref bridge) = state.service_bridge {
        info!(endpoint = %bridge.endpoint(), "service bridge enabled on /{}", bridge.endpoint());
    }

    let shutdown_task =
        tokio::spawn(wait_for_shutdown_signal(handle.clone(), shutdown, state, shutdown_timeout));

    info!("starting teamserver on https://{bind_addr}");

    let make_svc =
        NormalizedMakeService::new(router.into_make_service_with_connect_info::<SocketAddr>());

    axum_server::bind_rustls(bind_addr, tls_config)
        .handle(handle)
        .serve(make_svc)
        .await
        .context("teamserver exited with an error")?;

    shutdown_task
        .await
        .context("shutdown coordinator task failed to join")?
        .context("shutdown coordinator failed")?;

    Ok(())
}

/// Run a CLI subcommand and return.
async fn run_subcommand(command: CliCommand, database: &Database) -> Result<()> {
    match command {
        CliCommand::DbBackup { output_dir } => {
            if !output_dir.is_dir() {
                std::fs::create_dir_all(&output_dir).with_context(|| {
                    format!("failed to create backup output directory: {}", output_dir.display())
                })?;
            }
            let dest = red_cell::database::backup::snapshot_path(&output_dir)
                .map_err(|err| anyhow!("failed to build backup filename: {err}"))?;
            info!(path = %dest.display(), "creating database hot backup");
            database
                .backup(&dest)
                .await
                .with_context(|| format!("VACUUM INTO failed for {}", dest.display()))?;
            info!(path = %dest.display(), "database backup completed successfully");
            println!("{}", dest.display());
            Ok(())
        }
    }
}

#[instrument(skip(configured), fields(profile_path = %profile.display(), configured_database = configured.as_ref().map(|path| path.display().to_string())))]
fn resolve_database_path(profile: &Path, configured: Option<&PathBuf>) -> PathBuf {
    configured.cloned().unwrap_or_else(|| {
        let mut path = profile.to_path_buf();
        path.set_extension("sqlite");
        path
    })
}

/// Load the database master key from `<db_path>.key`, creating it on first run.
///
/// The key file stores exactly 32 raw bytes with mode 0600.  It must exist on
/// the same host as the teamserver process but at a different path from the
/// SQLite database so that exfiltrating the `.sqlite` file alone is not
/// sufficient to decrypt agent session keys.
fn load_or_create_master_key(db_path: &Path) -> Result<DbMasterKey> {
    use std::fs;
    use std::io::{Read, Write};

    let mut key_path = db_path.to_path_buf();
    let key_filename = format!("{}.key", db_path.file_name().unwrap_or_default().to_string_lossy());
    key_path.set_file_name(key_filename);

    if key_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&key_path)
                .with_context(|| format!("failed to stat key file {}", key_path.display()))?;
            let mode = meta.permissions().mode() & 0o777;
            anyhow::ensure!(
                mode == 0o600,
                "key file {} has mode {:#05o} — expected 0600; \
                 fix with: chmod 600 {}",
                key_path.display(),
                mode,
                key_path.display(),
            );
        }

        let mut file = fs::File::open(&key_path)
            .with_context(|| format!("failed to open key file {}", key_path.display()))?;
        let mut raw = zeroize::Zeroizing::new([0u8; 32]);
        file.read_exact(raw.as_mut()).with_context(|| {
            format!(
                "key file {} must contain exactly 32 bytes — it may be corrupt",
                key_path.display()
            )
        })?;

        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            anyhow::bail!(
                "key file {} contains more than 32 bytes — it may be corrupt or tampered with",
                key_path.display(),
            );
        }

        info!(path = %key_path.display(), "loaded database master key from key file");
        Ok(DbMasterKey::from_bytes(*raw))
    } else {
        let key = DbMasterKey::random()
            .context("failed to generate database master key: OS RNG unavailable")?;

        // Write with restricted permissions: owner read/write only.
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)
                .with_context(|| format!("failed to create key file {}", key_path.display()))?
        };
        #[cfg(not(unix))]
        let mut file = fs::File::create_new(&key_path)
            .with_context(|| format!("failed to create key file {}", key_path.display()))?;

        file.write_all(key.as_bytes())
            .with_context(|| format!("failed to write key file {}", key_path.display()))?;
        info!(path = %key_path.display(), "generated new database master key — keep this file safe");
        Ok(key)
    }
}

#[instrument(skip(path), fields(profile_path = %path.display()))]
fn load_profile(path: &PathBuf) -> Result<Profile> {
    let profile = Profile::from_file(path)?;
    profile.validate().map_err(invalid_profile)?;
    Ok(profile)
}

fn invalid_profile(error: ProfileValidationError) -> anyhow::Error {
    anyhow!(error)
}

async fn resolve_bind_addr(profile: &Profile) -> Result<SocketAddr> {
    let addrs = lookup_host((profile.teamserver.host.as_str(), profile.teamserver.port))
        .await
        .with_context(|| {
            format!(
                "failed to resolve bind address {}:{}",
                profile.teamserver.host, profile.teamserver.port
            )
        })?;

    first_resolved_addr(addrs, &profile.teamserver.host, profile.teamserver.port)
}

/// Picks the first socket address from an iterator of resolved addresses, returning a
/// descriptive error when the iterator is empty.
fn first_resolved_addr(
    mut addrs: impl Iterator<Item = SocketAddr>,
    host: &str,
    port: u16,
) -> Result<SocketAddr> {
    addrs.next().ok_or_else(|| anyhow!("no socket addresses resolved for {}:{}", host, port))
}

#[instrument(skip(profile, profile_path), fields(bind_host = %profile.teamserver.host))]
async fn build_tls_config(profile: &Profile, profile_path: &Path) -> Result<RustlsConfig> {
    let subject_alt_names = tls_subject_alt_names(&profile.teamserver.host);
    let cert_path = profile_path.with_extension("tls.crt");
    let key_path = profile_path.with_extension("tls.key");
    let identity = resolve_or_persist_tls_identity(
        &subject_alt_names,
        profile.teamserver.cert.as_ref(),
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .context("failed to resolve teamserver TLS identity")?;

    // Build a custom rustls ServerConfig that only advertises HTTP/1.1 via ALPN.
    // The default `RustlsConfig::from_pem` advertises ["h2", "http/1.1"] which causes
    // HTTP/2 to be negotiated, breaking WebSocket upgrades (which require HTTP/1.1).
    let certs: Vec<rustls_pki_types::CertificateDer> =
        rustls_pki_types::CertificateDer::pem_slice_iter(identity.certificate_pem())
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse TLS certificate PEM")?;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(identity.private_key_pem())
        .context("failed to parse TLS private key PEM")?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build rustls ServerConfig")?;

    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

fn tls_subject_alt_names(host: &str) -> Vec<String> {
    let mut names = vec![host.to_owned()];

    if host.parse::<IpAddr>().is_ok_and(|address| address.is_unspecified()) {
        names.push("127.0.0.1".to_owned());
        names.push("localhost".to_owned());
    }

    names
}

#[instrument(skip(handle, shutdown, state))]
async fn wait_for_shutdown_signal(
    handle: Handle<SocketAddr>,
    shutdown: red_cell::ShutdownController,
    state: TeamserverState,
    timeout: Duration,
) -> Result<()> {
    let signal = async {
        let ctrl_c = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {}
                Err(error) => tracing::error!(%error, "failed to listen for SIGINT"),
            }
        };

        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(error) => tracing::error!(%error, "failed to listen for SIGTERM"),
            }
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate => {}
        }
    };

    signal.await;
    info!(timeout_seconds = timeout.as_secs(), "shutdown signal received");
    run_shutdown_sequence(handle, shutdown, state, timeout).await
}

/// Orchestrates the shutdown sequence after a signal has been received.
///
/// Steps: initiate the shutdown controller, trigger Axum graceful shutdown,
/// drain listener callbacks, drain audit webhooks, and close the database.
#[instrument(skip(handle, shutdown, state))]
async fn run_shutdown_sequence(
    handle: Handle<SocketAddr>,
    shutdown: red_cell::ShutdownController,
    state: TeamserverState,
    timeout: Duration,
) -> Result<()> {
    shutdown.initiate();
    handle.graceful_shutdown(Some(timeout));

    let drained = state.listeners.shutdown(timeout).await;
    if !drained {
        tracing::warn!(
            active_callbacks = state.shutdown.active_callback_count(),
            timeout_seconds = timeout.as_secs(),
            "timed out waiting for in-flight agent callbacks to drain"
        );
    }

    if !state.webhooks.shutdown(timeout).await {
        tracing::warn!(timeout_seconds = timeout.as_secs(), "timed out waiting for audit webhooks");
    }

    state.database.close().await;
    Ok(())
}

#[instrument(skip(listeners, profile), fields(listener_count = profile_listener_names(profile).len()))]
async fn start_new_profile_listeners(
    listeners: &ListenerManager,
    profile: &Profile,
) -> Result<(), ListenerManagerError> {
    let profile_listener_names = profile_listener_names(profile);
    let summaries = listeners.list().await?;
    let new_profile_listeners: Vec<_> = summaries
        .into_iter()
        .filter(|summary| {
            summary.state.status == red_cell::ListenerStatus::Created
                && profile_listener_names.iter().any(|name| name == &summary.name)
        })
        .collect();

    for listener in new_profile_listeners {
        match listeners.start(listener.name.as_str()).await {
            Ok(_) | Err(ListenerManagerError::ListenerAlreadyRunning { .. }) => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn profile_listener_names(profile: &Profile) -> Vec<String> {
    let mut names = Vec::new();
    names.extend(profile.listeners.http.iter().map(|listener| listener.name.clone()));
    names.extend(profile.listeners.smb.iter().map(|listener| listener.name.clone()));
    names.extend(profile.listeners.dns.iter().map(|listener| listener.name.clone()));
    names.extend(profile.listeners.external.iter().map(|listener| listener.name.clone()));
    names
}

#[cfg(test)]
mod main_tests;
