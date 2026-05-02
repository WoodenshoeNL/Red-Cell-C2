//! Production Axum router construction and operator-port fallback handling.

use std::net::SocketAddr;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{any, get},
};

use crate::{
    MAX_AGENT_MESSAGE_LEN, api_routes, handle_external_request,
    listeners::collect_body_with_magic_precheck, service_routes,
};

use super::state::TeamserverState;

/// Build the main teamserver router used by the binary and integration tests.
pub fn build_router(state: TeamserverState) -> Router {
    let api = state.api.clone();

    let mut router = Router::new()
        .route("/havoc", get(crate::websocket_handler::<TeamserverState>))
        .nest("/api/v1", api_routes(api));

    if let Some(ref bridge) = state.service_bridge {
        router = router.merge(service_routes(bridge));
    }

    router.fallback(any(teamserver_fallback)).with_state(state)
}

async fn teamserver_fallback(
    State(state): State<TeamserverState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path().to_owned();

    // Check if an active External listener owns this path.
    if let Some(ext_state) = state.listeners.external_state_for_path(&path).await {
        // Acquire the shutdown callback guard *before* body collection so this
        // request is tracked for the full duration of the external bridge path.
        // Without this, `run_shutdown_sequence` could decide the callback drain
        // is complete while body I/O is still in progress, closing the database
        // underneath the subsequent `handle_external_request` call.
        let Some(_fallback_guard) = ext_state.try_track_callback() else {
            return StatusCode::NOT_FOUND.into_response();
        };

        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)), |info| info.0);

        let body = match collect_body_with_magic_precheck(
            request.into_body(),
            MAX_AGENT_MESSAGE_LEN,
            true, // external listeners always relay Demon (legacy) traffic
        )
        .await
        {
            Some(bytes) => bytes,
            // Return a camouflage 404 — do not expose the size limit or bad magic as a 400.
            None => return StatusCode::NOT_FOUND.into_response(),
        };

        match handle_external_request(&ext_state, peer, &body).await {
            Ok(payload) => (StatusCode::OK, Bytes::from(payload)).into_response(),
            Err(status) => status.into_response(),
        }
    } else {
        tracing::debug!(
            method = %request.method(),
            path = %path,
            "teamserver operator port fallback hit"
        );
        StatusCode::NOT_FOUND.into_response()
    }
}
