//! Listener persistence, lifecycle control, and per-protocol runtime spawning.
//!
//! [`ListenerManager`] is the single entry point operators and the profile-sync
//! machinery use to create, update, start, stop, delete, and list listeners.
//! It owns the persisted-listener repository, the in-memory `active_handles`
//! map, the set of shared rate limiters applied to every listener runtime, and
//! the live `RustlsConfig` / cert-watcher handles backing HTTPS hot-reload.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_server::tls_rustls::RustlsConfig;
use red_cell_common::ListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::operator::{
    EventCode, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
};
use red_cell_common::tls::{load_tls_identity, validate_tls_not_expired};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};
use zeroize::Zeroizing;

use super::config::profile_listener_configs;
use super::dns::spawn_dns_listener_runtime;
use super::external::{ExternalListenerState, spawn_external_listener_runtime};
use super::http::spawn_http_listener_runtime;
use super::rate_limiters::{
    DemonInitRateLimiter, ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter,
};
use super::smb::spawn_smb_listener_runtime;
use super::summary::ListenerSummary;
use crate::{
    AgentRegistry, DEFAULT_MAX_DOWNLOAD_BYTES, Database, DemonInitSecretConfig, ListenerRepository,
    ListenerStatus, PluginRuntime, ShutdownController, SocketRelayManager, TeamserverError,
    dispatch::DownloadTracker, events::EventBus, json_error_response,
};

pub(crate) type ListenerRuntimeFuture = Pin<Box<dyn Future<Output = ListenerRuntimeResult> + Send>>;
pub(crate) type ListenerRuntimeResult = Result<(), String>;

/// Errors returned by [`ListenerManager`].
#[derive(Debug, thiserror::Error)]
pub enum ListenerManagerError {
    /// Listener persistence failed.
    #[error("{0}")]
    Database(#[from] TeamserverError),
    /// The requested listener already exists.
    #[error("listener `{name}` already exists")]
    DuplicateListener { name: String },
    /// The requested listener could not be found.
    #[error("listener `{name}` not found")]
    ListenerNotFound { name: String },
    /// The listener is already running.
    #[error("listener `{name}` is already running")]
    ListenerAlreadyRunning { name: String },
    /// The listener is not currently running.
    #[error("listener `{name}` is not running")]
    ListenerNotRunning { name: String },
    /// The operator payload could not be converted into a valid listener config.
    #[error("invalid listener configuration: {message}")]
    InvalidConfig { message: String },
    /// A listener runtime could not bind or initialize.
    #[error("failed to start listener `{name}`: {message}")]
    StartFailed { name: String, message: String },
    /// The WebSocket mark command used an unsupported action.
    #[error("unsupported listener mark `{mark}`")]
    UnsupportedMark { mark: String },
    /// An external listener endpoint path is already claimed by another listener.
    #[error("endpoint `{endpoint}` is already registered by listener `{existing_listener}`")]
    DuplicateEndpoint { endpoint: String, existing_listener: String },
    /// The listener is not a running HTTPS listener; TLS cert hot-reload requires it.
    #[error("listener `{name}` is not a running HTTPS listener")]
    NotTlsListener { name: String },
    /// TLS certificate validation or hot-reload failed.
    #[error("TLS certificate error: {message}")]
    TlsCertError { message: String },
    /// The caller is not permitted to act on this listener (RBAC allow-list or
    /// auth-layer failure).
    #[error(transparent)]
    Authorization(#[from] crate::AuthorizationError),
}

impl IntoResponse for ListenerManagerError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::DuplicateListener { .. } => (StatusCode::CONFLICT, "listener_already_exists"),
            Self::ListenerNotFound { .. } => (StatusCode::NOT_FOUND, "listener_not_found"),
            Self::ListenerAlreadyRunning { .. } => {
                (StatusCode::CONFLICT, "listener_already_running")
            }
            Self::ListenerNotRunning { .. } => (StatusCode::CONFLICT, "listener_not_running"),
            Self::InvalidConfig { .. } => (StatusCode::BAD_REQUEST, "listener_invalid_config"),
            Self::UnsupportedMark { .. } => (StatusCode::BAD_REQUEST, "listener_unsupported_mark"),
            Self::StartFailed { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "listener_start_failed"),
            Self::DuplicateEndpoint { .. } => (StatusCode::CONFLICT, "listener_duplicate_endpoint"),
            Self::NotTlsListener { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "listener_not_tls"),
            Self::TlsCertError { .. } => (StatusCode::BAD_REQUEST, "listener_tls_cert_error"),
            Self::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "listener_error"),
            // Defer to AuthorizationError's own status/code mapping so that
            // ListenerAccessDenied returns 403 and DatabaseError returns 500,
            // matching the other RBAC-protected endpoints.
            Self::Authorization(err) => return err.clone().into_response(),
        };

        json_error_response(status, code, self.to_string())
    }
}

/// Tracks persisted listeners and their active runtime tasks.
#[derive(Clone, Debug)]
pub struct ListenerManager {
    database: Database,
    agent_registry: AgentRegistry,
    events: EventBus,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    pub(super) downloads: DownloadTracker,
    demon_init_rate_limiter: DemonInitRateLimiter,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
    pub(super) active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
    operations: Arc<Mutex<()>>,
    /// Active external listener endpoints keyed by path (e.g. `"/bridge"`).
    external_endpoints: Arc<RwLock<BTreeMap<String, Arc<ExternalListenerState>>>>,
    /// Live `RustlsConfig` handles for running HTTPS listeners, keyed by listener name.
    ///
    /// Each entry is a cloneable handle into the running axum-server TLS config.
    /// Calling `reload_from_pem` on a cloned handle atomically swaps in a new
    /// certificate for all subsequent TLS handshakes without dropping any existing
    /// connection.
    tls_configs: Arc<RwLock<HashMap<String, RustlsConfig>>>,
    /// Certificate file-watcher task handles for HTTPS listeners with explicit cert paths.
    ///
    /// These tasks poll the cert file's mtime and call `reload_from_pem` automatically
    /// when the file changes.  They are aborted when the associated listener stops.
    watcher_handles: Arc<RwLock<HashMap<String, JoinHandle<()>>>>,
    /// Server-secret configuration for HKDF-based session key derivation.
    ///
    /// Passed to every [`DemonPacketParser`] spawned by this manager.
    /// `None` → raw agent keys stored directly (Demon / legacy mode).
    /// `Some((secrets, versioned))` where `versioned` distinguishes the
    /// single-secret (unversioned) and multi-secret (versioned) modes.
    ///
    /// Stored as `(versioned: bool, secrets: Vec<(u8, Vec<u8>)>)` so the
    /// manager can reconstruct the correct [`DemonInitSecretConfig`] variant.
    demon_init_secrets: Option<(bool, Vec<(u8, Vec<u8>)>)>,
    /// Whether to accept DEMON_INIT registrations that negotiate legacy CTR mode.
    ///
    /// Mirrors `DemonConfig.allow_legacy_ctr` from the HCL profile.  Defaults to
    /// `false`; must be explicitly enabled by the operator before the teamserver
    /// will accept agents that do not set `INIT_EXT_MONOTONIC_CTR`.
    demon_allow_legacy_ctr: bool,
    /// Maximum pivot-chain dispatch nesting depth passed to all dispatchers.
    ///
    /// Sourced from `TeamserverConfig.max_pivot_chain_depth`; defaults to
    /// [`crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH`] when absent.
    pub(super) max_pivot_chain_depth: usize,
}

impl ListenerManager {
    /// Build a listener manager backed by `database`.
    #[must_use]
    pub fn new(
        database: Database,
        agent_registry: AgentRegistry,
        events: EventBus,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
    ) -> Self {
        Self::with_max_download_bytes(
            database,
            agent_registry,
            events,
            sockets,
            plugins,
            DEFAULT_MAX_DOWNLOAD_BYTES,
        )
    }

    /// Build a listener manager backed by `database` with a custom per-download memory cap.
    #[must_use]
    pub fn with_max_download_bytes(
        database: Database,
        agent_registry: AgentRegistry,
        events: EventBus,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        max_download_bytes: u64,
    ) -> Self {
        let downloads = DownloadTracker::from_max_download_bytes(max_download_bytes);
        let cleanup_downloads = downloads.clone();
        agent_registry.register_cleanup_hook(move |agent_id| {
            let downloads = cleanup_downloads.clone();
            async move {
                let drained = downloads.drain_agent(agent_id).await;
                if drained > 0 {
                    tracing::info!(%agent_id, drained, "drained pending downloads during agent cleanup");
                }
            }
        });

        Self {
            database,
            agent_registry,
            events,
            sockets,
            plugins,
            downloads,
            demon_init_rate_limiter: DemonInitRateLimiter::new(),
            unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter::new(),
            reconnect_probe_rate_limiter: ReconnectProbeRateLimiter::new(),
            shutdown: ShutdownController::new(),
            active_handles: Arc::new(RwLock::new(BTreeMap::new())),
            operations: Arc::new(Mutex::new(())),
            external_endpoints: Arc::new(RwLock::new(BTreeMap::new())),
            tls_configs: Arc::new(RwLock::new(HashMap::new())),
            watcher_handles: Arc::new(RwLock::new(HashMap::new())),
            demon_init_secrets: None,
            demon_allow_legacy_ctr: false,
            max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        }
    }

    /// Override the per-agent concurrent download limit.
    ///
    /// Must be called before any listeners are started.
    #[must_use]
    pub fn with_max_concurrent_downloads_per_agent(mut self, limit: usize) -> Self {
        self.downloads = self.downloads.with_max_concurrent_per_agent(limit);
        self
    }

    /// Override the aggregate in-memory download cap across all active downloads.
    ///
    /// Must be called before any listeners are started.
    #[must_use]
    pub fn with_max_aggregate_download_bytes(mut self, limit: u64) -> Self {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        self.downloads = self.downloads.with_max_aggregate_bytes(limit);
        self
    }

    /// Override the maximum pivot-chain dispatch nesting depth.
    ///
    /// When an inbound callback tunnels commands through a pivot chain, the
    /// dispatch depth is incremented on each recursive hop. If this limit is
    /// reached the dispatch is rejected, an audit log entry is written, and an
    /// error event is broadcast to operators.
    ///
    /// Must be called before any listeners are started.
    #[must_use]
    pub fn with_max_pivot_chain_depth(mut self, depth: usize) -> Self {
        self.max_pivot_chain_depth = depth;
        self
    }

    /// Set a single unversioned HKDF server secret for all listener packet parsers.
    ///
    /// This corresponds to `Demon { InitSecret = "..." }` in the profile.  No version
    /// byte is expected in `DEMON_INIT` packets; use [`with_demon_init_secrets`] when
    /// you need zero-downtime rotation support.
    ///
    /// Call this before any listeners are spawned.
    #[must_use]
    pub fn with_demon_init_secret(mut self, secret: Option<Vec<u8>>) -> Self {
        self.demon_init_secrets = secret.map(|s| (false, vec![(0u8, s)]));
        self
    }

    /// Set versioned HKDF server secrets for all listener packet parsers.
    ///
    /// This corresponds to `Demon { InitSecrets = [...] }` in the profile.  Agents
    /// must emit a 1-byte version field in `DEMON_INIT`; the matching secret is
    /// selected for HKDF derivation.
    ///
    /// Call this before any listeners are spawned.
    #[must_use]
    pub fn with_demon_init_secrets(mut self, secrets: Vec<(u8, Vec<u8>)>) -> Self {
        if secrets.is_empty() {
            self.demon_init_secrets = None;
        } else {
            self.demon_init_secrets = Some((true, secrets));
        }
        self
    }

    /// Build the [`DemonInitSecretConfig`] to pass to listener packet parsers.
    fn init_secret_config(&self) -> DemonInitSecretConfig {
        match &self.demon_init_secrets {
            None => DemonInitSecretConfig::None,
            Some((false, secrets)) => {
                // Unversioned single secret: stored as vec with one entry keyed by 0.
                DemonInitSecretConfig::Unversioned(Zeroizing::new(
                    secrets.first().map(|(_, s)| s.clone()).unwrap_or_default(),
                ))
            }
            Some((true, secrets)) => DemonInitSecretConfig::Versioned(
                secrets.iter().map(|(v, s)| (*v, Zeroizing::new(s.clone()))).collect(),
            ),
        }
    }

    /// Control whether listener parsers accept DEMON_INIT registrations in legacy CTR mode.
    ///
    /// When `false` (the default), any agent that does not negotiate
    /// `INIT_EXT_MONOTONIC_CTR` is rejected.  Set to `true` only when the operator has
    /// explicitly opted in via `AllowLegacyCtr = true` in the profile `Demon` block.
    #[must_use]
    pub fn with_demon_allow_legacy_ctr(mut self, allow: bool) -> Self {
        self.demon_allow_legacy_ctr = allow;
        self
    }

    /// Override the maximum number of reconnect probes allowed per agent per window.
    ///
    /// The default is [`super::rate_limiters::MAX_RECONNECT_PROBES_PER_AGENT`] (10).
    /// Integration tests that send many rapid reconnect probes can raise this to
    /// avoid hitting the rate limiter.
    #[must_use]
    pub fn with_reconnect_probe_limit(mut self, max_probes: u32) -> Self {
        self.reconnect_probe_rate_limiter = ReconnectProbeRateLimiter::with_max_probes(max_probes);
        self
    }

    /// Return the listener persistence repository used by the manager.
    #[must_use]
    pub fn repository(&self) -> ListenerRepository {
        self.database.listeners()
    }

    /// Return the in-memory agent registry used by active listeners.
    #[must_use]
    pub fn agent_registry(&self) -> AgentRegistry {
        self.agent_registry.clone()
    }

    /// Look up an active External listener by its endpoint path.
    ///
    /// Returns `None` if no running External listener owns `path`.
    pub async fn external_state_for_path(&self, path: &str) -> Option<Arc<ExternalListenerState>> {
        self.external_endpoints.read().await.get(path).cloned()
    }

    /// Return the shared graceful-shutdown controller used by listener runtimes.
    #[must_use]
    pub fn shutdown_controller(&self) -> ShutdownController {
        self.shutdown.clone()
    }

    /// Enter shutdown mode, wait for tracked callbacks to drain, then stop active listeners.
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.shutdown.initiate();
        let drained = self.shutdown.wait_for_callback_drain(timeout).await;

        let names: Vec<_> = self.active_handles.read().await.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.stop(&name).await {
                warn!(listener = %name, error = %e, "listener stop failed during shutdown");
            }
        }

        drained
    }

    /// Create a persisted listener configuration in the stopped state.
    #[instrument(skip(self, config), fields(listener_name = %config.name(), protocol = ?config.protocol()))]
    pub async fn create(
        &self,
        config: ListenerConfig,
    ) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.create_locked(config).await
    }

    async fn create_locked(
        &self,
        config: ListenerConfig,
    ) -> Result<ListenerSummary, ListenerManagerError> {
        let repository = self.repository();

        if repository.exists(config.name()).await? {
            return Err(ListenerManagerError::DuplicateListener { name: config.name().to_owned() });
        }

        // Reject external listeners whose endpoint path is already claimed.
        if let ListenerConfig::External(ref ext) = config {
            for existing in repository.list().await? {
                if let ListenerConfig::External(ref other) = existing.config {
                    if other.endpoint == ext.endpoint {
                        return Err(ListenerManagerError::DuplicateEndpoint {
                            endpoint: ext.endpoint.clone(),
                            existing_listener: other.name.clone(),
                        });
                    }
                }
            }
        }

        repository.create(&config).await?;
        self.summary(config.name()).await
    }

    /// Replace an existing listener configuration.
    #[instrument(skip(self, config), fields(listener_name = %config.name(), protocol = ?config.protocol()))]
    pub async fn update(
        &self,
        config: ListenerConfig,
    ) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.update_locked(config).await
    }

    async fn update_locked(
        &self,
        config: ListenerConfig,
    ) -> Result<ListenerSummary, ListenerManagerError> {
        let repository = self.repository();
        let existing = repository.get(config.name()).await?.ok_or_else(|| {
            ListenerManagerError::ListenerNotFound { name: config.name().to_owned() }
        })?;

        // Reject external listeners whose endpoint path is already claimed by
        // another listener (same check as create_locked, excluding self).
        if let ListenerConfig::External(ref ext) = config {
            for other_stored in repository.list().await? {
                if let ListenerConfig::External(ref other) = other_stored.config {
                    if other.endpoint == ext.endpoint && other.name != ext.name {
                        return Err(ListenerManagerError::DuplicateEndpoint {
                            endpoint: ext.endpoint.clone(),
                            existing_listener: other.name.clone(),
                        });
                    }
                }
            }
        }

        let was_running = existing.state.status == ListenerStatus::Running;
        if was_running {
            self.stop_locked(config.name()).await?;
        }

        repository.update(&config).await?;
        repository.set_state(config.name(), ListenerStatus::Stopped, None).await?;

        if was_running {
            match self.start_locked(config.name()).await {
                Ok(summary) => return Ok(summary),
                Err(error) => return Err(error),
            }
        }

        self.summary(config.name()).await
    }

    /// Start the named listener runtime.
    #[instrument(skip(self), fields(listener_name = %name))]
    pub async fn start(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.start_locked(name).await
    }

    /// Stop the named listener runtime.
    #[instrument(skip(self), fields(listener_name = %name))]
    pub async fn stop(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let _guard = self.operations.lock().await;
        self.stop_locked(name).await
    }

    /// Delete the named listener, stopping it first if needed.
    #[instrument(skip(self), fields(listener_name = %name))]
    pub async fn delete(&self, name: &str) -> Result<(), ListenerManagerError> {
        let _guard = self.operations.lock().await;
        let repository = self.repository();
        let Some(listener) = repository.get(name).await? else {
            return Err(ListenerManagerError::ListenerNotFound { name: name.to_owned() });
        };

        if listener.state.status == ListenerStatus::Running {
            self.stop_locked(name).await?;
        }

        repository.delete(name).await?;
        self.active_handles.write().await.remove(name);
        Ok(())
    }

    /// Return the current persisted summary for `name`.
    #[instrument(skip(self), fields(listener_name = %name))]
    pub async fn summary(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        self.repository()
            .get(name)
            .await?
            .map(Into::into)
            .ok_or_else(|| ListenerManagerError::ListenerNotFound { name: name.to_owned() })
    }

    /// Return every persisted listener summary.
    #[instrument(skip(self))]
    pub async fn list(&self) -> Result<Vec<ListenerSummary>, ListenerManagerError> {
        Ok(self.repository().list().await?.into_iter().map(Into::into).collect())
    }

    /// Hot-reload the TLS certificate for a running HTTPS listener.
    ///
    /// The new certificate is validated (PEM parse, key/cert match, expiry check) before
    /// being swapped in.  All in-flight TLS connections keep their existing certificate;
    /// only new handshakes after this call will use the replacement.
    ///
    /// # Errors
    ///
    /// Returns [`ListenerManagerError::ListenerNotFound`] if `name` does not exist,
    /// [`ListenerManagerError::NotTlsListener`] if it is not a running HTTPS listener,
    /// or [`ListenerManagerError::TlsCertError`] if the supplied PEM data fails validation.
    #[instrument(skip(self, cert_pem, key_pem), fields(listener_name = %name))]
    pub async fn reload_tls_cert(
        &self,
        name: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<(), ListenerManagerError> {
        // Verify the listener exists and is a running HTTPS listener.
        let listener = self
            .repository()
            .get(name)
            .await?
            .ok_or_else(|| ListenerManagerError::ListenerNotFound { name: name.to_owned() })?;

        let is_running_https = matches!(&listener.config, ListenerConfig::Http(c) if c.secure)
            && listener.state.status == ListenerStatus::Running;

        if !is_running_https {
            return Err(ListenerManagerError::NotTlsListener { name: name.to_owned() });
        }

        // Validate: parse PEM, check key/cert compatibility, check expiry.
        load_tls_identity(cert_pem, key_pem)
            .map_err(|e| ListenerManagerError::TlsCertError { message: e.to_string() })?;

        validate_tls_not_expired(cert_pem)
            .map_err(|e| ListenerManagerError::TlsCertError { message: e.to_string() })?;

        // Retrieve the live RustlsConfig handle for this listener.
        let tls_config = self
            .tls_configs
            .read()
            .await
            .get(name)
            .cloned()
            .ok_or_else(|| ListenerManagerError::NotTlsListener { name: name.to_owned() })?;

        // Atomically swap in the new certificate; existing connections are unaffected.
        tls_config
            .reload_from_pem(cert_pem.to_vec(), key_pem.to_vec())
            .await
            .map_err(|e| ListenerManagerError::TlsCertError { message: e.to_string() })?;

        info!(listener = name, "TLS certificate hot-reloaded");
        Ok(())
    }

    /// Reconcile persisted listeners against the YAOTL profile.
    #[instrument(skip(self, profile))]
    pub async fn sync_profile(&self, profile: &Profile) -> Result<(), ListenerManagerError> {
        let _guard = self.operations.lock().await;
        let repository = self.repository();
        let profile_listeners = profile_listener_configs(profile)?
            .into_iter()
            .map(|config| (config.name().to_owned(), config))
            .collect::<BTreeMap<_, _>>();

        for name in repository.names().await? {
            if !profile_listeners.contains_key(&name) {
                self.delete_removed_profile_listener_locked(&name).await?;
            }
        }

        for config in profile_listeners.into_values() {
            match self.create_locked(config.clone()).await {
                Ok(_) => {}
                Err(ListenerManagerError::DuplicateListener { .. }) => {
                    self.update_locked(config).await?;
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }

    /// Start listeners that were last persisted in the running state.
    #[instrument(skip(self))]
    pub async fn restore_running(&self) -> Result<(), ListenerManagerError> {
        let listeners = self.repository().list().await?;

        for listener in listeners {
            if listener.state.status == ListenerStatus::Running {
                match self.start(&listener.name).await {
                    Ok(_) => {}
                    Err(error) => return Err(error),
                }
            }
        }

        Ok(())
    }

    async fn start_locked(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let repository = self.repository();
        let listener = repository
            .get(name)
            .await?
            .ok_or_else(|| ListenerManagerError::ListenerNotFound { name: name.to_owned() })?;
        self.prune_finished_handle(name).await;
        if self.active_handles.read().await.contains_key(name) {
            return Err(ListenerManagerError::ListenerAlreadyRunning { name: name.to_owned() });
        }

        match self.spawn_listener_runtime(&listener.config).await {
            Ok(handle) => {
                self.active_handles.write().await.insert(name.to_owned(), handle);
                repository.set_state(name, ListenerStatus::Running, None).await?;
                info!(listener = name, protocol = %listener.protocol, "listener started");
                for warning in super::opsec::opsec_warnings(&listener.config) {
                    warn!(listener = name, "{warning}");
                    self.events.broadcast(OperatorMessage::TeamserverLog(Message {
                        head: MessageHead {
                            event: EventCode::Teamserver,
                            user: String::new(),
                            timestamp: String::new(),
                            one_time: String::new(),
                        },
                        info: TeamserverLogInfo { text: warning.to_owned() },
                    }));
                }
                self.summary(name).await
            }
            Err(error) => {
                let error_text = error.to_string();
                repository
                    .set_state(name, ListenerStatus::Error, Some(error_text.as_str()))
                    .await?;
                warn!(listener = name, error = %error_text, "listener failed to start");
                Err(ListenerManagerError::StartFailed {
                    name: name.to_owned(),
                    message: error_text,
                })
            }
        }
    }

    async fn stop_locked(&self, name: &str) -> Result<ListenerSummary, ListenerManagerError> {
        let repository = self.repository();

        if repository.get(name).await?.is_none() {
            return Err(ListenerManagerError::ListenerNotFound { name: name.to_owned() });
        }

        let Some(handle) = self.active_handles.write().await.remove(name) else {
            return Err(ListenerManagerError::ListenerNotRunning { name: name.to_owned() });
        };

        handle.abort();
        if let Err(error) = handle.await {
            if error.is_panic() {
                tracing::warn!(listener = name, "listener task panicked during stop: {error}");
            }
        }

        // Clean up external listener endpoint registry entries that won't get
        // deregistered inside the aborted future.
        self.external_endpoints.write().await.retain(|_, state| state.listener_name() != name);

        // Stop the cert file-watcher task if one was spawned for this listener.
        if let Some(watcher) = self.watcher_handles.write().await.remove(name) {
            watcher.abort();
            let _ = watcher.await;
        }

        // Remove the live TLS config handle so hot-reload calls are rejected after stop.
        self.tls_configs.write().await.remove(name);

        repository.set_state(name, ListenerStatus::Stopped, None).await?;
        info!(listener = name, "listener stopped");
        self.summary(name).await
    }

    async fn prune_finished_handle(&self, name: &str) {
        let should_remove = {
            let handles = self.active_handles.read().await;
            handles.get(name).is_some_and(JoinHandle::is_finished)
        };

        if should_remove {
            self.active_handles.write().await.remove(name);
        }
    }

    async fn delete_removed_profile_listener_locked(
        &self,
        name: &str,
    ) -> Result<(), ListenerManagerError> {
        if let Some(handle) = self.active_handles.write().await.remove(name) {
            handle.abort();
            if let Err(error) = handle.await {
                if error.is_panic() {
                    tracing::warn!(
                        listener = name,
                        "listener task panicked during profile cleanup: {error}"
                    );
                }
            }
        }

        self.repository().delete(name).await?;
        info!(listener = name, "removed persisted listener absent from profile");

        Ok(())
    }

    async fn spawn_listener_runtime(
        &self,
        config: &ListenerConfig,
    ) -> Result<JoinHandle<()>, ListenerManagerError> {
        let runtime = match config {
            ListenerConfig::Http(config) => {
                spawn_http_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.downloads.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.unknown_callback_probe_audit_limiter.clone(),
                    self.reconnect_probe_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.max_pivot_chain_depth,
                    self.init_secret_config(),
                    self.demon_allow_legacy_ctr,
                    self.tls_configs.clone(),
                    self.watcher_handles.clone(),
                )
                .await
            }
            ListenerConfig::Smb(config) => {
                spawn_smb_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.downloads.clone(),
                    self.unknown_callback_probe_audit_limiter.clone(),
                    self.reconnect_probe_rate_limiter.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.init_secret_config(),
                    self.max_pivot_chain_depth,
                    self.demon_allow_legacy_ctr,
                )
                .await
            }
            ListenerConfig::Dns(config) => {
                spawn_dns_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.downloads.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.unknown_callback_probe_audit_limiter.clone(),
                    self.reconnect_probe_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.init_secret_config(),
                    self.max_pivot_chain_depth,
                    self.demon_allow_legacy_ctr,
                )
                .await
            }
            ListenerConfig::External(config) => spawn_external_listener_runtime(
                config,
                self.agent_registry.clone(),
                self.events.clone(),
                self.database.clone(),
                self.sockets.clone(),
                self.plugins.clone(),
                self.downloads.clone(),
                self.demon_init_rate_limiter.clone(),
                self.unknown_callback_probe_audit_limiter.clone(),
                self.reconnect_probe_rate_limiter.clone(),
                self.shutdown.clone(),
                self.external_endpoints.clone(),
                self.init_secret_config(),
                self.max_pivot_chain_depth,
                self.demon_allow_legacy_ctr,
            ),
        }?;

        Ok(spawn_managed_listener_task(
            config.name().to_owned(),
            runtime,
            self.repository(),
            self.active_handles.clone(),
        ))
    }
}

pub(crate) fn spawn_managed_listener_task(
    name: String,
    runtime: ListenerRuntimeFuture,
    repository: ListenerRepository,
    active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let outcome = runtime.await;
        active_handles.write().await.remove(&name);

        match outcome {
            Ok(()) => {
                if let Err(error) = repository.set_state(&name, ListenerStatus::Stopped, None).await
                {
                    warn!(
                        listener = %name,
                        %error,
                        "listener runtime exited but stopped state could not be persisted"
                    );
                } else {
                    info!(listener = %name, "listener runtime exited");
                }
            }
            Err(message) => {
                if let Err(error) =
                    repository.set_state(&name, ListenerStatus::Error, Some(message.as_str())).await
                {
                    warn!(
                        listener = %name,
                        runtime_error = %message,
                        %error,
                        "listener runtime failed and error state could not be persisted"
                    );
                } else {
                    warn!(listener = %name, error = %message, "listener runtime exited with error");
                }
            }
        }
    })
}
