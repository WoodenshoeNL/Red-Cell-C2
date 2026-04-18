//! External C2 bridge listener runtime.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use tokio::sync::RwLock;
use tracing::{debug, info};

use red_cell_common::ExternalListenerConfig;

use crate::{
    AgentRegistry, CommandDispatcher, Database, DemonInitSecretConfig, DemonPacketParser,
    PluginRuntime, ShutdownController, SocketRelayManager, dispatch::DownloadTracker,
    events::EventBus, shutdown::ActiveCallbackGuard,
};

use super::{
    DemonHttpDisposition, DemonInitRateLimiter, ListenerManagerError, ListenerRuntimeFuture,
    ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter, allow_demon_init_for_ip,
    is_valid_demon_callback_request, process_demon_transport,
};

/// Stored in the [`super::ListenerManager`] external endpoint registry so that the
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_external_listener_runtime(
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
        parser: DemonPacketParser::with_init_secret_config(
            registry.clone(),
            init_secret_config.clone(),
        )
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
            init_secret_config,
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
        &state.demon_init_rate_limiter,
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
