//! Listener lifecycle management for the teamserver.
//!
//! DNS C2 transport lives in [`dns`].

mod dns;
#[cfg(test)]
mod tests;

pub(crate) use dns::spawn_dns_listener_runtime;

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
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
    TlsKeyAlgorithm, install_default_crypto_provider, load_tls_identity, resolve_tls_identity,
    validate_tls_not_expired,
};
use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, SmbListenerConfig,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument, warn};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::{
    AgentRegistry, AuditResultStatus, CommandDispatchError, CommandDispatcher, Database,
    DemonInitSecretConfig, DemonPacketParser, DemonParserError, ListenerRepository, ListenerStatus,
    ParsedDemonPacket, PersistedListener, PersistedListenerState, PluginRuntime,
    ShutdownController, SocketRelayManager, TeamserverError,
    agent_events::{agent_new_event, agent_reregistered_event},
    audit_details, build_init_ack, build_reconnect_ack,
    dispatch::DownloadTracker,
    events::EventBus,
    json_error_response, parameter_object,
    rate_limiter::AttemptWindow,
    rate_limiter::{evict_oldest_windows, prune_expired_windows},
    record_operator_action,
    shutdown::ActiveCallbackGuard,
};

use crate::DEFAULT_MAX_DOWNLOAD_BYTES;
const MAX_DEMON_INIT_ATTEMPTS_PER_IP: u32 = 5;
const DEMON_INIT_WINDOW_DURATION: Duration = Duration::from_secs(60);
const MAX_DEMON_INIT_ATTEMPT_WINDOWS: usize = 10_000;
const MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE: u32 = 1;
const UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION: Duration = Duration::from_secs(60);
const MAX_UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOWS: usize = 10_000;
const MAX_RECONNECT_PROBES_PER_AGENT: u32 = 10;
const RECONNECT_PROBE_WINDOW_DURATION: Duration = Duration::from_secs(60);
const MAX_RECONNECT_PROBE_WINDOWS: usize = 10_000;
/// Maximum number of AXFR/ANY recon queries from a single IP before it is silently dropped.
pub(crate) const MAX_DNS_RECON_QUERIES_PER_IP: u32 = 5;
/// Sliding-window duration for DNS AXFR/ANY recon rate limiting.
pub(crate) const DNS_RECON_WINDOW_DURATION: Duration = Duration::from_secs(60);
const EXTRA_METHOD: &str = "Method";
const EXTRA_BEHIND_REDIRECTOR: &str = "BehindRedirector";
const EXTRA_TRUSTED_PROXY_PEERS: &str = "TrustedProxyPeers";
const EXTRA_CERT_PATH: &str = "Cert";
const EXTRA_KEY_PATH: &str = "Key";
const EXTRA_RESPONSE_BODY: &str = "ResponseBody";
const EXTRA_KILL_DATE: &str = "KillDate";
const EXTRA_WORKING_HOURS: &str = "WorkingHours";
const EXTRA_JA3_RANDOMIZE: &str = "Ja3Randomize";

#[derive(Clone, Debug, Default)]
pub(crate) struct DemonInitRateLimiter {
    windows: Arc<Mutex<HashMap<IpAddr, AttemptWindow>>>,
}

impl DemonInitRateLimiter {
    #[must_use]
    fn new() -> Self {
        Self::default()
    }

    async fn allow(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, DEMON_INIT_WINDOW_DURATION, now);
        if !windows.contains_key(&ip) && windows.len() >= MAX_DEMON_INIT_ATTEMPT_WINDOWS {
            evict_oldest_windows(&mut windows, MAX_DEMON_INIT_ATTEMPT_WINDOWS / 2);
        }

        let window = windows.entry(ip).or_default();
        if now.duration_since(window.window_start) >= DEMON_INIT_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        if window.attempts >= MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            return false;
        }

        window.attempts += 1;
        true
    }

    #[cfg(test)]
    async fn tracked_ip_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

/// Per-agent-ID sliding-window rate limiter for reconnect probes.
///
/// An empty `DEMON_INIT` payload is a lightweight reconnect probe.  Unlike full
/// registrations (gated by [`DemonInitRateLimiter`] per source IP), probes are
/// keyed by `agent_id` so that spamming from many IPs with the same agent ID is
/// still throttled.  Exceeding the limit results in an HTTP 429 response, making
/// the DoS signal visible to operators while avoiding the SQLite write that a
/// successful probe would trigger.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReconnectProbeRateLimiter {
    windows: Arc<Mutex<HashMap<u32, AttemptWindow>>>,
}

impl ReconnectProbeRateLimiter {
    #[must_use]
    fn new() -> Self {
        Self::default()
    }

    async fn allow(&self, agent_id: u32) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, RECONNECT_PROBE_WINDOW_DURATION, now);
        if !windows.contains_key(&agent_id) && windows.len() >= MAX_RECONNECT_PROBE_WINDOWS {
            evict_oldest_windows(&mut windows, MAX_RECONNECT_PROBE_WINDOWS / 2);
        }

        let window = windows.entry(agent_id).or_default();
        if now.duration_since(window.window_start) >= RECONNECT_PROBE_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        if window.attempts >= MAX_RECONNECT_PROBES_PER_AGENT {
            return false;
        }

        window.attempts += 1;
        true
    }

    #[cfg(test)]
    async fn tracked_agent_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UnknownCallbackProbeAuditLimiter {
    windows: Arc<Mutex<HashMap<String, AttemptWindow>>>,
}

impl UnknownCallbackProbeAuditLimiter {
    #[must_use]
    fn new() -> Self {
        Self::default()
    }

    async fn allow(&self, listener_name: &str, external_ip: &str) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();
        let source = format!("{listener_name}\0{external_ip}");

        prune_expired_windows(&mut windows, UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION, now);
        if !windows.contains_key(&source)
            && windows.len() >= MAX_UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOWS
        {
            let target_size = MAX_UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOWS / 2;
            evict_oldest_windows(&mut windows, target_size);
        }

        let window = windows.entry(source).or_default();
        if now.duration_since(window.window_start) >= UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        if window.attempts >= MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE {
            return false;
        }

        window.attempts += 1;
        true
    }

    #[cfg(test)]
    async fn tracked_source_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

/// Per-source-IP sliding-window rate limiter for DNS AXFR/ANY recon queries.
///
/// AXFR (zone transfer) and ANY queries have no legitimate use on our C2 DNS
/// listener and are indicators of active reconnaissance. This limiter tracks
/// how many such queries each IP has sent within the window and, once the
/// threshold is exceeded, returns `false` so the caller can drop further
/// queries without responding.
#[derive(Clone, Debug, Default)]
pub(crate) struct DnsReconBlockLimiter {
    pub(crate) windows: Arc<Mutex<HashMap<IpAddr, AttemptWindow>>>,
}

impl DnsReconBlockLimiter {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when the query should be allowed (below threshold).
    /// Returns `false` once the IP has sent more than
    /// [`MAX_DNS_RECON_QUERIES_PER_IP`] queries in the current window.
    pub(crate) async fn allow(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, DNS_RECON_WINDOW_DURATION, now);
        if !windows.contains_key(&ip) && windows.len() >= 10_000 {
            evict_oldest_windows(&mut windows, 5_000);
        }

        let window = windows.entry(ip).or_default();
        if now.duration_since(window.window_start) >= DNS_RECON_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        window.attempts += 1;
        window.attempts <= MAX_DNS_RECON_QUERIES_PER_IP
    }

    #[cfg(test)]
    pub(crate) async fn tracked_ip_count(&self) -> usize {
        self.windows.lock().await.len()
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
        self.to_operator_info_with_redaction(true)
    }

    #[must_use]
    fn to_operator_info_with_redaction(&self, redact_proxy_password: bool) -> ListenerInfo {
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
                if !redact_proxy_password {
                    info.proxy_password = config
                        .proxy
                        .as_ref()
                        .and_then(|proxy| proxy.password.as_deref().map(String::from));
                }
                info.secure = Some(config.secure.to_string());
                if let Some(ja3) = config.ja3_randomize {
                    info.extra.insert(
                        EXTRA_JA3_RANDOMIZE.to_owned(),
                        serde_json::Value::String(ja3.to_string()),
                    );
                }
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
        }

        info
    }

    #[cfg(test)]
    #[must_use]
    fn to_operator_info_with_secrets(&self) -> ListenerInfo {
        self.to_operator_info_with_redaction(false)
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
    /// An external listener endpoint path is already claimed by another listener.
    #[error("endpoint `{endpoint}` is already registered by listener `{existing_listener}`")]
    DuplicateEndpoint { endpoint: String, existing_listener: String },
    /// The listener is not a running HTTPS listener; TLS cert hot-reload requires it.
    #[error("listener `{name}` is not a running HTTPS listener")]
    NotTlsListener { name: String },
    /// TLS certificate validation or hot-reload failed.
    #[error("TLS certificate error: {message}")]
    TlsCertError { message: String },
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
    downloads: DownloadTracker,
    demon_init_rate_limiter: DemonInitRateLimiter,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
    active_handles: Arc<RwLock<BTreeMap<String, JoinHandle<()>>>>,
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
    max_pivot_chain_depth: usize,
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
use crate::MAX_AGENT_MESSAGE_LEN;
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
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
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
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
}

/// Shared state for an active External C2 bridge listener.
///
/// Stored in the [`ListenerManager`] external endpoint registry so that the
/// teamserver fallback handler can dispatch matching requests.
#[derive(Clone, Debug)]
pub struct ExternalListenerState {
    config: ExternalListenerConfig,
    registry: AgentRegistry,
    database: Database,
    parser: DemonPacketParser,
    events: EventBus,
    dispatcher: CommandDispatcher,
    /// Per-IP rate limiter for `DEMON_INIT` requests — same gate used by
    /// HTTP and DNS listeners (SMB uses per-connection admission; see
    /// `handle_smb_connection`).
    demon_init_rate_limiter: DemonInitRateLimiter,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
}

impl ExternalListenerState {
    /// Return the endpoint path this listener handles.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Return the listener display name.
    #[must_use]
    pub fn listener_name(&self) -> &str {
        &self.config.name
    }

    /// Acquire a shutdown callback guard so the in-flight request is tracked
    /// during graceful shutdown drain.
    ///
    /// Returns `None` once shutdown has been initiated — callers should reject
    /// the request immediately.
    pub fn try_track_callback(&self) -> Option<ActiveCallbackGuard> {
        self.shutdown.try_track_callback()
    }
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
    TooManyRequests,
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
        downloads: DownloadTracker,
        demon_init_rate_limiter: DemonInitRateLimiter,
        unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
        reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
        shutdown: ShutdownController,
        init_secret_config: DemonInitSecretConfig,
        max_pivot_chain_depth: usize,
        allow_legacy_ctr: bool,
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
            parser: DemonPacketParser::with_init_secret_config(
                registry.clone(),
                init_secret_config,
            )
            .with_allow_legacy_ctr(allow_legacy_ctr),
            dispatcher: CommandDispatcher::with_builtin_handlers_and_downloads(
                registry.clone(),
                events.clone(),
                database.clone(),
                sockets,
                plugins,
                downloads,
                max_pivot_chain_depth,
                allow_legacy_ctr,
            ),
            events,
            demon_init_rate_limiter,
            unknown_callback_probe_audit_limiter,
            reconnect_probe_rate_limiter,
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
        downloads: DownloadTracker,
        unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
        reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
        shutdown: ShutdownController,
        init_secret_config: DemonInitSecretConfig,
        max_pivot_chain_depth: usize,
        allow_legacy_ctr: bool,
    ) -> Self {
        Self {
            config: config.clone(),
            registry: registry.clone(),
            database: database.clone(),
            parser: DemonPacketParser::with_init_secret_config(
                registry.clone(),
                init_secret_config,
            )
            .with_allow_legacy_ctr(allow_legacy_ctr),
            events: events.clone(),
            unknown_callback_probe_audit_limiter,
            reconnect_probe_rate_limiter,
            shutdown,
            dispatcher: CommandDispatcher::with_builtin_handlers_and_downloads(
                registry.clone(),
                events.clone(),
                database,
                sockets,
                plugins,
                downloads,
                max_pivot_chain_depth,
                allow_legacy_ctr,
            ),
        }
    }
}

/// Validate and normalise an optional KillDate string from operator input,
/// converting it from the raw extra-field value into a unix-timestamp string.
fn validated_kill_date(raw: Option<String>) -> Result<Option<String>, ListenerManagerError> {
    red_cell_common::validate_kill_date(raw.as_deref())
        .map_err(|err| ListenerManagerError::InvalidConfig { message: err.to_string() })
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
            kill_date: validated_kill_date(optional_extra_string(info, EXTRA_KILL_DATE))?,
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
            ja3_randomize: parse_optional_extra_bool(info, EXTRA_JA3_RANDOMIZE)?,
            doh_domain: None,
            doh_provider: None,
        })),
        Ok(ListenerProtocol::Smb) => Ok(ListenerConfig::from(SmbListenerConfig {
            name: name.to_owned(),
            pipe_name: required_extra_string(info, "PipeName")?,
            kill_date: validated_kill_date(optional_extra_string(info, EXTRA_KILL_DATE))?,
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
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
            kill_date: validated_kill_date(optional_extra_string(info, EXTRA_KILL_DATE))?,
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
        })),
        Ok(ListenerProtocol::External) => Ok(ListenerConfig::from(ExternalListenerConfig {
            name: name.to_owned(),
            endpoint: required_extra_string(info, "Endpoint")?,
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
        ListenerConfig::Http(_) => "Http".to_owned(),
        ListenerConfig::Smb(_) => "Smb".to_owned(),
        ListenerConfig::Dns(_) => "Dns".to_owned(),
        ListenerConfig::External(_) => "External".to_owned(),
    }
}

fn profile_listener_configs(
    profile: &Profile,
) -> Result<Vec<ListenerConfig>, ListenerManagerError> {
    let mut listeners = Vec::new();
    for config in profile.listeners.http.iter().cloned() {
        listeners.push(ListenerConfig::from(HttpListenerConfig {
            name: config.name,
            kill_date: validated_kill_date(config.kill_date)?,
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
            response: config.response.map(Into::into),
            proxy: config.proxy.map(Into::into),
            ja3_randomize: config.ja3_randomize,
            doh_domain: config.doh_domain,
            doh_provider: config.doh_provider,
        }));
    }
    for config in profile.listeners.smb.iter().cloned() {
        listeners.push(ListenerConfig::from(SmbListenerConfig {
            name: config.name,
            pipe_name: config.pipe_name,
            kill_date: validated_kill_date(config.kill_date)?,
            working_hours: config.working_hours,
        }));
    }
    for config in profile.listeners.dns.iter().cloned() {
        listeners.push(ListenerConfig::from(DnsListenerConfig {
            name: config.name,
            host_bind: config.host_bind,
            port_bind: config.port_bind,
            domain: config.domain,
            record_types: config.record_types,
            kill_date: validated_kill_date(config.kill_date)?,
            working_hours: config.working_hours,
        }));
    }
    listeners.extend(profile.listeners.external.iter().cloned().map(|config| {
        ListenerConfig::from(ExternalListenerConfig {
            name: config.name,
            endpoint: config.endpoint,
        })
    }));
    Ok(listeners)
}

#[allow(clippy::too_many_arguments)]
async fn spawn_http_listener_runtime(
    config: &HttpListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    downloads: DownloadTracker,
    demon_init_rate_limiter: DemonInitRateLimiter,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
    max_pivot_chain_depth: usize,
    init_secret_config: DemonInitSecretConfig,
    allow_legacy_ctr: bool,
    tls_configs: Arc<RwLock<HashMap<String, RustlsConfig>>>,
    watcher_handles: Arc<RwLock<HashMap<String, JoinHandle<()>>>>,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    let state = Arc::new(HttpListenerState::build(
        config,
        registry,
        events,
        database,
        sockets,
        plugins,
        downloads,
        demon_init_rate_limiter,
        unknown_callback_probe_audit_limiter,
        reconnect_probe_rate_limiter,
        shutdown,
        init_secret_config,
        max_pivot_chain_depth,
        allow_legacy_ctr,
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

        // Register the live config handle so hot-reload can reach it later.
        tls_configs.write().await.insert(config.name.clone(), tls_config.clone());

        // If the cert comes from files, spawn a poller that hot-reloads on change.
        if let Some(cert_cfg) = &config.cert {
            let handle = spawn_cert_file_watcher(
                config.name.clone(),
                PathBuf::from(&cert_cfg.cert),
                PathBuf::from(&cert_cfg.key),
                tls_config.clone(),
            );
            watcher_handles.write().await.insert(config.name.clone(), handle);
        }

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

/// Spawn a background task that polls a certificate file for changes and hot-reloads it.
///
/// The task checks the cert file's modification time every 30 seconds.  When a change
/// is detected it reads both files, validates the new cert, and calls
/// [`RustlsConfig::reload_from_pem`].  Failed reloads are logged as warnings and
/// the watcher continues running so the next successful write is picked up.
///
/// The returned [`JoinHandle`] should be aborted when the listener stops.
fn spawn_cert_file_watcher(
    listener_name: String,
    cert_path: PathBuf,
    key_path: PathBuf,
    tls_config: RustlsConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        /// Poll interval for modification-time checks.
        const POLL_INTERVAL: Duration = Duration::from_secs(30);

        let mut interval = tokio::time::interval(POLL_INTERVAL);
        // Skip the first (immediate) tick so we don't reload on startup.
        interval.tick().await;

        let mut last_mtime = cert_mtime(&cert_path);

        loop {
            interval.tick().await;

            let current_mtime = cert_mtime(&cert_path);
            if current_mtime == last_mtime {
                continue;
            }

            match reload_tls_from_files(&cert_path, &key_path, &tls_config).await {
                Ok(()) => {
                    info!(
                        listener = %listener_name,
                        path = %cert_path.display(),
                        "TLS certificate auto-reloaded from file"
                    );
                    last_mtime = current_mtime;
                }
                Err(message) => {
                    warn!(
                        listener = %listener_name,
                        path = %cert_path.display(),
                        error = %message,
                        "TLS certificate auto-reload failed; retaining previous certificate"
                    );
                }
            }
        }
    })
}

/// Read the modification time of a file, returning `None` on any error.
fn cert_mtime(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Read cert + key from files, validate, and hot-reload into `tls_config`.
async fn reload_tls_from_files(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    tls_config: &RustlsConfig,
) -> Result<(), String> {
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .map_err(|e| format!("read {}: {e}", cert_path.display()))?;
    let key_pem =
        tokio::fs::read(key_path).await.map_err(|e| format!("read {}: {e}", key_path.display()))?;

    load_tls_identity(&cert_pem, &key_pem).map_err(|e| e.to_string())?;
    validate_tls_not_expired(&cert_pem).map_err(|e| e.to_string())?;

    tls_config.reload_from_pem(cert_pem, key_pem).await.map_err(|e| e.to_string())
}

async fn build_callback_response(
    dispatcher: &CommandDispatcher,
    agent_id: u32,
    packages: &[crate::DemonCallbackPackage],
) -> Result<Vec<u8>, ListenerManagerError> {
    dispatcher.dispatch_packages(agent_id, packages).await.map_err(map_command_dispatch_error)
}

#[allow(clippy::too_many_arguments)]
async fn process_demon_transport(
    listener_name: &str,
    registry: &AgentRegistry,
    database: &Database,
    parser: &DemonPacketParser,
    events: &EventBus,
    dispatcher: &CommandDispatcher,
    unknown_callback_probe_audit_limiter: &UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: &ReconnectProbeRateLimiter,
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
            let agent_id = init.agent.agent_id;
            let external_ip_for_audit = external_ip.clone();
            let listener_name_for_audit = listener_name.to_owned();
            if let Err(error) = record_operator_action(
                database,
                "teamserver",
                "agent.registered",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("registered"),
                    Some(parameter_object([
                        ("listener", serde_json::Value::String(listener_name_for_audit)),
                        ("external_ip", serde_json::Value::String(external_ip_for_audit)),
                    ])),
                ),
            )
            .await
            {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "failed to persist agent.registered audit entry"
                );
            }
            if let Ok(Some(plugins)) = PluginRuntime::current() {
                if let Err(error) = plugins.emit_agent_registered(agent_id).await {
                    tracing::warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        %error,
                        "failed to emit python agent_registered event"
                    );
                }
            }
            Ok(ProcessedDemonResponse {
                agent_id,
                payload: response,
                http_disposition: DemonHttpDisposition::Ok,
            })
        }
        Ok(ParsedDemonPacket::ReInit(init)) => {
            let response =
                build_init_ack(registry, init.agent.agent_id).await.map_err(|error| {
                    ListenerManagerError::InvalidConfig {
                        message: format!(
                            "failed to build demon init ack for re-registration: {error}"
                        ),
                    }
                })?;

            let pivots = registry.pivots(init.agent.agent_id).await;
            events.broadcast(agent_reregistered_event(
                listener_name,
                init.header.magic,
                &init.agent,
                &pivots,
            ));
            let agent_id = init.agent.agent_id;
            let external_ip_for_audit = external_ip.clone();
            let listener_name_for_audit = listener_name.to_owned();
            if let Err(error) = record_operator_action(
                database,
                "teamserver",
                "agent.reregistered",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("reregistered"),
                    Some(parameter_object([
                        ("listener", serde_json::Value::String(listener_name_for_audit)),
                        ("external_ip", serde_json::Value::String(external_ip_for_audit)),
                    ])),
                ),
            )
            .await
            {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "failed to persist agent.reregistered audit entry"
                );
            }
            if let Ok(Some(plugins)) = PluginRuntime::current() {
                if let Err(error) = plugins.emit_agent_registered(agent_id).await {
                    tracing::warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        %error,
                        "failed to emit python agent_registered event for re-registration"
                    );
                }
            }
            Ok(ProcessedDemonResponse {
                agent_id,
                payload: response,
                http_disposition: DemonHttpDisposition::Ok,
            })
        }
        Ok(ParsedDemonPacket::Reconnect { header, .. }) => {
            if !reconnect_probe_rate_limiter.allow(header.agent_id).await {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{:08X}", header.agent_id),
                    external_ip,
                    max_probes = MAX_RECONNECT_PROBES_PER_AGENT,
                    window_seconds = RECONNECT_PROBE_WINDOW_DURATION.as_secs(),
                    "reconnect probe rate limit exceeded — possible probe spam"
                );
                return Ok(ProcessedDemonResponse {
                    agent_id: header.agent_id,
                    payload: Vec::new(),
                    http_disposition: DemonHttpDisposition::TooManyRequests,
                });
            }

            let (payload, http_disposition) = if registry.get(header.agent_id).await.is_some() {
                build_reconnect_ack(registry, header.agent_id)
                    .await
                    .map_err(|error| ListenerManagerError::InvalidConfig {
                        message: format!("failed to build reconnect ack: {error}"),
                    })
                    .map(|payload| (payload, DemonHttpDisposition::Ok))?
            } else {
                if unknown_callback_probe_audit_limiter.allow(listener_name, &external_ip).await {
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
                } else {
                    debug!(
                        listener = listener_name,
                        agent_id = format_args!("{:08X}", header.agent_id),
                        external_ip,
                        "suppressing unknown reconnect probe audit row after per-source limit"
                    );
                }
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
        Err(DemonParserError::Registry(TeamserverError::AgentNotFound { agent_id })) => {
            if unknown_callback_probe_audit_limiter.allow(listener_name, &external_ip).await {
                warn!(
                    listener = listener_name,
                    agent_id = format_args!("{:08X}", agent_id),
                    external_ip,
                    "unknown agent sent callback probe"
                );
                record_unknown_callback_probe(database, listener_name, agent_id, &external_ip)
                    .await;
            } else {
                debug!(
                    listener = listener_name,
                    agent_id = format_args!("{:08X}", agent_id),
                    external_ip,
                    "suppressing unknown callback probe audit row after per-source limit"
                );
            }
            Ok(ProcessedDemonResponse {
                agent_id,
                payload: Vec::new(),
                http_disposition: DemonHttpDisposition::Fake404,
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

async fn record_unknown_callback_probe(
    database: &Database,
    listener_name: &str,
    agent_id: u32,
    external_ip: &str,
) {
    let details = audit_details(
        AuditResultStatus::Failure,
        Some(agent_id),
        Some("callback_probe"),
        Some(parameter_object([
            ("listener", serde_json::Value::String(listener_name.to_owned())),
            ("external_ip", serde_json::Value::String(external_ip.to_owned())),
        ])),
    );

    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.callback_probe",
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
            "failed to persist unknown callback probe audit entry"
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

/// Sliding-window admission for full `DEMON_INIT` registrations on a single SMB named-pipe
/// connection.  Unlike HTTP/DNS/External, SMB has no trustworthy remote IP; the only stable
/// transport identity is the connection itself, so we key the limiter here instead of using a
/// synthetic IPv4 derived from `agent_id` (which an attacker could rotate to bypass throttling).
async fn allow_demon_init_for_smb_connection(
    listener_name: &str,
    window: &Mutex<AttemptWindow>,
    body: &[u8],
) -> bool {
    if classify_demon_transport(body) != Some(DemonTransportKind::Init) {
        return true;
    }

    let mut w = window.lock().await;
    let now = Instant::now();
    if now.duration_since(w.window_start) >= DEMON_INIT_WINDOW_DURATION {
        w.attempts = 0;
        w.window_start = now;
    }
    if w.attempts >= MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        warn!(
            listener = listener_name,
            max_attempts = MAX_DEMON_INIT_ATTEMPTS_PER_IP,
            window_seconds = DEMON_INIT_WINDOW_DURATION.as_secs(),
            "rejecting DEMON_INIT because the per-SMB-connection rate limit was exceeded"
        );
        return false;
    }
    w.attempts += 1;
    true
}

#[allow(clippy::too_many_arguments)]
async fn spawn_smb_listener_runtime(
    config: &SmbListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    downloads: DownloadTracker,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
    init_secret_config: DemonInitSecretConfig,
    max_pivot_chain_depth: usize,
    allow_legacy_ctr: bool,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    let state = Arc::new(SmbListenerState::build(
        config,
        registry,
        events,
        database,
        sockets,
        plugins,
        downloads,
        unknown_callback_probe_audit_limiter,
        reconnect_probe_rate_limiter,
        shutdown,
        init_secret_config,
        max_pivot_chain_depth,
        allow_legacy_ctr,
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
        let shutdown_signal = state.shutdown.notified();
        tokio::pin!(shutdown_signal);

        loop {
            tokio::select! {
                _ = &mut shutdown_signal => return Ok(()),
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
    let demon_init_window = Mutex::new(AttemptWindow::default());
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

        // SMB runs over a local named pipe — no trustworthy remote IP.  Keep operator-facing
        // `external_ip` as a deterministic IPv4 derived from `agent_id` (Havoc-compatible),
        // but rate-limit full DEMON_INIT registrations per named-pipe connection (not per
        // attacker-chosen agent_id).
        let client_ip = IpAddr::V4(Ipv4Addr::from(frame.agent_id.to_be_bytes()));
        if !allow_demon_init_for_smb_connection(
            &state.config.name,
            &demon_init_window,
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
            &state.unknown_callback_probe_audit_limiter,
            &state.reconnect_probe_rate_limiter,
            &frame.payload,
            client_ip.to_string(),
        )
        .await
        {
            Ok(response) => {
                if response.http_disposition == DemonHttpDisposition::Fake404
                    || response.http_disposition == DemonHttpDisposition::TooManyRequests
                {
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

// ── External C2 Bridge Listener ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn spawn_external_listener_runtime(
    config: &ExternalListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    downloads: DownloadTracker,
    demon_init_rate_limiter: DemonInitRateLimiter,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
    external_endpoints: Arc<RwLock<BTreeMap<String, Arc<ExternalListenerState>>>>,
    init_secret_config: DemonInitSecretConfig,
    max_pivot_chain_depth: usize,
    allow_legacy_ctr: bool,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    let state = Arc::new(ExternalListenerState {
        config: config.clone(),
        registry: registry.clone(),
        database: database.clone(),
        parser: DemonPacketParser::with_init_secret_config(registry.clone(), init_secret_config)
            .with_allow_legacy_ctr(allow_legacy_ctr),
        events: events.clone(),
        demon_init_rate_limiter,
        unknown_callback_probe_audit_limiter,
        reconnect_probe_rate_limiter,
        shutdown,
        dispatcher: CommandDispatcher::with_builtin_handlers_and_downloads(
            registry.clone(),
            events.clone(),
            database,
            sockets,
            plugins,
            downloads,
            max_pivot_chain_depth,
            allow_legacy_ctr,
        ),
    });

    let endpoint = config.endpoint.clone();
    let listener_name = config.name.clone();
    let reg_state = state.clone();
    let endpoints_ref = external_endpoints.clone();

    Ok(Box::pin(async move {
        // Register endpoint so the teamserver fallback handler can route to us.
        endpoints_ref.write().await.insert(endpoint.clone(), reg_state);
        info!(listener = %listener_name, endpoint = %endpoint, "external listener registered");

        // Wait until shutdown is requested — actual HTTP serving is done by the
        // teamserver's fallback handler via the endpoint registry.
        let shutdown_signal = state.shutdown.notified();
        shutdown_signal.await;

        // Deregister endpoint on shutdown.
        endpoints_ref.write().await.remove(&endpoint);
        info!(listener = %listener_name, endpoint = %endpoint, "external listener deregistered");
        Ok(())
    }))
}

/// Process an inbound HTTP request on an External C2 bridge endpoint.
///
/// This is called by the teamserver fallback handler when the request path
/// matches a registered external listener endpoint.
pub async fn handle_external_request(
    state: &ExternalListenerState,
    peer: SocketAddr,
    body: &[u8],
) -> Result<Vec<u8>, StatusCode> {
    if !is_valid_demon_callback_request(body) {
        debug!(
            listener = %state.config.name,
            peer = %peer,
            "ignoring invalid external demon frame"
        );
        return Err(StatusCode::NOT_FOUND);
    }

    let Some(_callback_guard) = state.shutdown.try_track_callback() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    if !allow_demon_init_for_ip(&state.config.name, &state.demon_init_rate_limiter, peer.ip(), body)
        .await
    {
        return Err(StatusCode::NOT_FOUND);
    }

    let result = process_demon_transport(
        &state.config.name,
        &state.registry,
        &state.database,
        &state.parser,
        &state.events,
        &state.dispatcher,
        &state.unknown_callback_probe_audit_limiter,
        &state.reconnect_probe_rate_limiter,
        body,
        peer.ip().to_string(),
    )
    .await;

    match result {
        Ok(response) if response.http_disposition == DemonHttpDisposition::TooManyRequests => {
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
        Ok(response) if response.http_disposition == DemonHttpDisposition::Fake404 => {
            Err(StatusCode::NOT_FOUND)
        }
        Ok(response) => Ok(response.payload),
        Err(error) => {
            debug!(
                listener = %state.config.name,
                peer = %peer,
                %error,
                "external listener request failed"
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
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

/// Buffers an HTTP request body while performing an early pre-screen on the
/// Demon transport magic value.
///
/// The Demon magic value (`0xDEADBEEF`) occupies bytes 4–7 of every valid
/// Demon packet. Buffering the full body before checking the magic allows
/// an adversary to force the server to allocate up to `MAX_AGENT_MESSAGE_LEN`
/// (30 MiB) per connection before rejection. This function rejects bodies
/// that fail the magic check as soon as 8 bytes have been accumulated, which
/// limits per-connection allocation to a single network chunk (~16 KiB in
/// practice) for obviously non-Demon traffic.
///
/// Returns `None` if the body exceeds `max_len`, contains a read error, or
/// does not carry the correct Demon magic value.
pub(crate) async fn collect_body_with_magic_precheck(body: Body, max_len: usize) -> Option<Bytes> {
    use http_body_util::BodyExt as _;

    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    let mut magic_checked = false;

    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        let Ok(data) = frame.into_data() else {
            // Trailers and other non-data frames are skipped.
            continue;
        };
        if buf.len() + data.len() > max_len {
            return None;
        }
        buf.extend_from_slice(&data);
        // As soon as we have the 8 bytes that cover the magic field (bytes 4–7),
        // validate the magic and drop the connection immediately on mismatch.
        if !magic_checked && buf.len() >= 8 {
            if buf[4..8] != DEMON_MAGIC_VALUE.to_be_bytes() {
                return None;
            }
            magic_checked = true;
        }
    }

    // Bodies shorter than 8 bytes cannot pass the magic check.
    if !magic_checked {
        return None;
    }

    Some(Bytes::from(buf))
}

async fn http_listener_handler(
    State(state): State<Arc<HttpListenerState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    if !http_request_matches(&state, &request) {
        return state.fake_404_response();
    }

    // Reject traffic when the listener's kill_date has passed.
    if is_past_kill_date(state.config.kill_date.as_deref()) {
        debug!(listener = %state.config.name, "rejecting request — kill_date has passed");
        return state.fake_404_response();
    }

    // NOTE: WorkingHours enforcement is intentionally NOT done server-side.
    // In the Demon protocol, working hours are encoded into the payload and
    // enforced by the agent using the victim host's local clock.  Gating here
    // with the server's UTC clock would reject valid callbacks whenever the
    // server and target timezones differ.

    let external_ip = extract_external_ip(
        state.config.behind_redirector,
        &state.trusted_proxy_peers,
        peer,
        &request,
    );
    let (_, body) = request.into_parts();
    let Some(body) = collect_body_with_magic_precheck(body, MAX_AGENT_MESSAGE_LEN).await else {
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
        &state.unknown_callback_probe_audit_limiter,
        &state.reconnect_probe_rate_limiter,
        &body,
        external_ip.to_string(),
    )
    .await
    {
        Ok(response) if response.http_disposition == DemonHttpDisposition::TooManyRequests => {
            StatusCode::TOO_MANY_REQUESTS.into_response()
        }
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

/// Return `true` when `kill_date` is set and the current wall-clock time has
/// passed it.  The value is parsed through [`red_cell_common::parse_kill_date_to_epoch`],
/// which accepts both a plain unix timestamp and `YYYY-MM-DD HH:MM:SS` (UTC).
///
/// If the value is absent or empty, returns `false` (no kill-date set).
/// If the value is present but malformed, logs a warning and returns `true`
/// (fail-closed: reject traffic rather than silently disabling enforcement).
fn is_past_kill_date(kill_date: Option<&str>) -> bool {
    let Some(value) = kill_date.map(str::trim).filter(|v| !v.is_empty()) else {
        return false;
    };
    let timestamp = match red_cell_common::parse_kill_date_to_epoch(value) {
        Ok(ts) => ts,
        Err(err) => {
            tracing::warn!(%err, "malformed kill_date — treating as expired (fail-closed)");
            return true;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let Ok(kill_epoch) = u64::try_from(timestamp) else {
        // Negative timestamps are always in the past.
        return true;
    };
    now >= kill_epoch
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

fn parse_optional_extra_bool(
    info: &ListenerInfo,
    field: &'static str,
) -> Result<Option<bool>, ListenerManagerError> {
    match extra_value_as_str(info, field) {
        None => Ok(None),
        Some(value) => parse_bool(field, Some(value)).map(Some),
    }
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
        password: optional_trimmed(info.proxy_password.as_deref()).map(Zeroizing::new),
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
