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
use red_cell_common::tls::{load_tls_identity, validate_tls_not_expired};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{instrument, warn};
use zeroize::Zeroizing;

use super::config::profile_listener_configs;
use super::external::ExternalListenerState;
use super::rate_limiters::{
    DemonInitRateLimiter, EcdhRegistrationRateLimiter, ReconnectProbeRateLimiter,
    UnknownCallbackProbeAuditLimiter,
};
use super::summary::ListenerSummary;
use crate::{
    AgentRegistry, DEFAULT_MAX_DOWNLOAD_BYTES, Database, DemonInitSecretConfig, ListenerRepository,
    ListenerStatus, PluginRuntime, ShutdownController, SocketRelayManager, TeamserverError,
    dispatch::DownloadTracker, events::EventBus, json_error_response,
};

mod lifecycle;
#[cfg(test)]
pub(crate) use lifecycle::spawn_managed_listener_task;

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
    pub(super) database: Database,
    pub(super) agent_registry: AgentRegistry,
    pub(super) events: EventBus,
    pub(super) sockets: SocketRelayManager,
    pub(super) plugins: Option<PluginRuntime>,
    pub(super) downloads: DownloadTracker,
    pub(super) demon_init_rate_limiter: DemonInitRateLimiter,
    pub(super) unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    pub(super) reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    pub(super) ecdh_registration_rate_limiter: EcdhRegistrationRateLimiter,
    pub(super) shutdown: ShutdownController,
    pub(super) active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
    pub(super) operations: Arc<Mutex<()>>,
    /// Active external listener endpoints keyed by path (e.g. `"/bridge"`).
    pub(super) external_endpoints: Arc<RwLock<BTreeMap<String, Arc<ExternalListenerState>>>>,
    /// Live `RustlsConfig` handles for running HTTPS listeners, keyed by listener name.
    ///
    /// Each entry is a cloneable handle into the running axum-server TLS config.
    /// Calling `reload_from_pem` on a cloned handle atomically swaps in a new
    /// certificate for all subsequent TLS handshakes without dropping any existing
    /// connection.
    pub(super) tls_configs: Arc<RwLock<HashMap<String, RustlsConfig>>>,
    /// Certificate file-watcher task handles for HTTPS listeners with explicit cert paths.
    ///
    /// These tasks poll the cert file's mtime and call `reload_from_pem` automatically
    /// when the file changes.  They are aborted when the associated listener stops.
    pub(super) watcher_handles: Arc<RwLock<HashMap<String, JoinHandle<()>>>>,
    /// Server-secret configuration for HKDF-based session key derivation.
    ///
    /// Passed to every [`DemonPacketParser`] spawned by this manager.
    /// `None` → raw agent keys stored directly (Demon / legacy mode).
    /// `Some((secrets, versioned))` where `versioned` distinguishes the
    /// single-secret (unversioned) and multi-secret (versioned) modes.
    ///
    /// Stored as `(versioned: bool, secrets: Vec<(u8, Vec<u8>)>)` so the
    /// manager can reconstruct the correct [`DemonInitSecretConfig`] variant.
    pub(super) demon_init_secrets: Option<(bool, Vec<(u8, Vec<u8>)>)>,
    /// Whether to accept DEMON_INIT registrations that negotiate legacy CTR mode.
    ///
    /// Mirrors `DemonConfig.allow_legacy_ctr` from the HCL profile.  Defaults to
    /// `false`; must be explicitly enabled by the operator before the teamserver
    /// will accept agents that do not set `INIT_EXT_MONOTONIC_CTR`.
    pub(super) demon_allow_legacy_ctr: bool,
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

        let cleanup_ecdh_db = database.clone();
        agent_registry.register_cleanup_hook(move |agent_id| {
            let db = cleanup_ecdh_db.clone();
            async move {
                if let Err(e) = db.ecdh().delete_sessions_for_agent(agent_id).await {
                    tracing::warn!(%agent_id, error = %e, "failed to purge ECDH session rows during agent cleanup");
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
            ecdh_registration_rate_limiter: EcdhRegistrationRateLimiter::new(),
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
    pub(super) fn init_secret_config(&self) -> DemonInitSecretConfig {
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

        tracing::info!(listener = name, "TLS certificate hot-reloaded");
        Ok(())
    }

    /// Reconcile persisted listeners against the YAOTL profile.
    #[instrument(skip(self, profile))]
    pub async fn sync_profile(&self, profile: &Profile) -> Result<(), ListenerManagerError> {
        use std::collections::BTreeMap as BMap;
        let _guard = self.operations.lock().await;
        let repository = self.repository();
        let profile_listeners = profile_listener_configs(profile)?
            .into_iter()
            .map(|config| (config.name().to_owned(), config))
            .collect::<BMap<_, _>>();

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
        tracing::info!(listener = name, "removed persisted listener absent from profile");

        Ok(())
    }
}
