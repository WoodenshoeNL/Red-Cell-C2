//! Top-level session dispatch: routes NDJSON commands to internal REST requests.

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::HeaderValue;
use axum::http::Request as HttpRequest;
use serde_json::Value;
use tower::ServiceExt as _;

use super::builders::{build_session_rest_request, session_build_error_envelope};
use super::exec_wait::session_exec_wait;
use super::session_ws_envelope_response;
use crate::api::auth::API_KEY_HEADER;

/// Build and dispatch a single internal REST request through the Axum router,
/// returning the raw [`axum::response::Response`].
pub(super) async fn dispatch_one(
    app: &Router,
    req: HttpRequest<Body>,
    api_key: &str,
    client_ip: SocketAddr,
) -> Result<axum::response::Response, String> {
    let mut req = req;
    match HeaderValue::from_str(api_key) {
        Ok(hv) => {
            req.headers_mut().insert(API_KEY_HEADER, hv);
        }
        Err(_) => {
            return Err(serde_json::json!({
                "ok": false,
                "cmd": "agent.exec",
                "error": "INVALID_API_KEY_HEADER",
                "message": "API key header value is not valid HTTP"
            })
            .to_string());
        }
    }
    req.extensions_mut().insert(ConnectInfo(client_ip));

    app.clone().oneshot(req).await.map_err(|_| {
        serde_json::json!({
            "ok": false,
            "cmd": "agent.exec",
            "error": "DISPATCH_FAILED",
            "message": "failed to dispatch session request"
        })
        .to_string()
    })
}

/// Dispatch one session NDJSON command through the same REST [`super::super::api_routes`] router.
pub(crate) async fn session_api_dispatch_line(
    app: &Router,
    cmd: &str,
    value: &Value,
    client_ip: SocketAddr,
    api_key: &str,
) -> String {
    // Intercept agent.exec with wait=true to poll for output.
    if cmd == "agent.exec" && value.get("wait").and_then(|v| v.as_bool()) == Some(true) {
        return session_exec_wait(app, value, client_ip, api_key).await;
    }

    let inner = match build_session_rest_request(cmd, value) {
        Ok(r) => r,
        Err(e) => return session_build_error_envelope(cmd, &e),
    };

    let response = match dispatch_one(app, inner, api_key, client_ip).await {
        Ok(r) => r,
        Err(envelope) => return envelope,
    };
    session_ws_envelope_response(cmd, response).await
}
