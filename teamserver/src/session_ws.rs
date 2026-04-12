//! NDJSON WebSocket endpoint for `red-cell-cli session` mode (`GET /api/v1/ws`).
//!
//! Authenticated by the same `x-api-key` middleware as other REST routes; each
//! inbound text frame is treated as one JSON command and dispatched through
//! [`crate::api::api_routes`] so behaviour matches the REST API surface.

use std::net::SocketAddr;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde_json::Value;
use tracing::instrument;

use crate::api::{api_routes, extract_api_key, session_api_dispatch_line};
use crate::app::TeamserverState;

/// Maximum session WebSocket message size accepted by the teamserver (1 MiB).
pub(crate) const SESSION_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// WebSocket upgrade handler for `/api/v1/ws`.
///
/// Requires a valid `x-api-key` (or `Authorization: Bearer`) header; the
/// middleware runs before this handler. Each inbound text message is parsed as
/// JSON, dispatched to the REST router, and answered with one NDJSON line.
#[instrument(skip_all, fields(peer = %addr))]
pub(crate) async fn session_ws_handler(
    State(state): State<TeamserverState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Re-read the presented credential for per-command REST dispatches (middleware
    // already validated the key before this handler runs).
    let api_key = match extract_api_key(&headers) {
        Ok(k) => k,
        Err(_) => {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let client_ip = addr;
    let state_for_socket = state.clone();

    ws.max_message_size(SESSION_MAX_MESSAGE_SIZE).on_upgrade(move |socket| async move {
        run_session_socket(socket, state_for_socket, client_ip, api_key).await;
    })
}

async fn run_session_socket(
    mut socket: WebSocket,
    state: TeamserverState,
    client_ip: SocketAddr,
    api_key: String,
) {
    let app = api_routes(state.api.clone()).with_state(state);

    loop {
        let msg = match socket.recv().await {
            Some(m) => m,
            None => break,
        };

        let text = match msg {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(p)) => {
                let _ = socket.send(Message::Pong(p)).await;
                continue;
            }
            Ok(Message::Pong(_)) | Ok(Message::Binary(_)) => continue,
            Err(_) => break,
        };

        let line = text.trim();
        if line.is_empty() {
            continue;
        }

        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let err_line = serde_json::json!({
                    "ok": false,
                    "cmd": "",
                    "error": "INVALID_JSON",
                    "message": e.to_string(),
                });
                if socket.send(Message::Text(err_line.to_string().into())).await.is_err() {
                    break;
                }
                continue;
            }
        };

        let cmd = value.get("cmd").and_then(|c| c.as_str()).unwrap_or("").to_owned();

        let out = session_api_dispatch_line(&app, &cmd, &value, client_ip, &api_key).await;

        if socket.send(Message::Text(out.into())).await.is_err() {
            break;
        }
    }
}
