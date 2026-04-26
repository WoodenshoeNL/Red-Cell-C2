//! `POST /api/v1/auth/login` — username + password credential exchange.
//!
//! This endpoint is **not** behind the API-key auth middleware; it is the
//! pre-auth entry point that lets a CLI operator exchange a username and
//! SHA3-256 password hash for a session token.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::app::TeamserverState;
use crate::auth::{AuthenticationFailure, AuthenticationResult};
use crate::{
    AuditResultStatus, audit_details, login_parameters, record_operator_action_with_notifications,
};

use super::errors::json_error_response;

/// Delay applied before responding to a failed REST login attempt, to slow
/// brute-force attacks and match the WebSocket login path behaviour.
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(2);

/// JSON request body for the login endpoint.
#[derive(Debug, Deserialize)]
pub(super) struct LoginRequest {
    /// Operator username.
    pub user: String,
    /// SHA3-256 hex-encoded password hash.
    pub password_sha3: String,
}

/// JSON response body for a successful login.
#[derive(Debug, Serialize)]
pub(super) struct LoginResponse {
    /// Opaque session token that can be used as a bearer credential for
    /// subsequent REST API calls.
    pub token: String,
    /// Authenticated operator username.
    pub user: String,
}

/// Extract client IP from `ConnectInfo` extension, if present.
fn client_ip(request: &Request) -> Option<IpAddr> {
    request.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip())
}

/// `POST /api/v1/auth/login`
///
/// Accepts a JSON body with `user` and `password_sha3`, verifies credentials
/// against the operator store, and returns a session token on success.
pub(super) async fn post_login(State(state): State<TeamserverState>, request: Request) -> Response {
    let ip = client_ip(&request);

    // Rate-limit check — shares the same LoginRateLimiter as the WS path.
    if let Some(ip) = ip {
        if !state.login_rate_limiter.try_acquire(ip).await {
            warn!(%ip, "REST login rate limited");
            return json_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many login attempts; try again later",
            );
        }
    }

    let body = match axum::body::to_bytes(request.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request body too large or unreadable",
            );
        }
    };

    let login_req: LoginRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("invalid JSON body: {e}"),
            );
        }
    };

    if login_req.user.is_empty() {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "user must not be empty",
        );
    }

    if login_req.password_sha3.is_empty() {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "password_sha3 must not be empty",
        );
    }

    let login_info = red_cell_common::operator::LoginInfo {
        user: login_req.user.clone(),
        password: login_req.password_sha3.clone(),
    };

    let connection_id = Uuid::new_v4();
    let result = state.auth.authenticate_login(connection_id, &login_info).await;

    match result {
        AuthenticationResult::Success(success) => {
            if let Some(ip) = ip {
                state.login_rate_limiter.record_success(ip).await;
            }
            debug!(user = %success.username, "REST login succeeded");
            if let Err(error) = record_operator_action_with_notifications(
                &state.database,
                &state.webhooks,
                &success.username,
                "operator.login",
                "operator",
                Some(success.username.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("login"),
                    Some(login_parameters(&success.username, &connection_id, "rest")),
                ),
            )
            .await
            {
                warn!(user = %success.username, %error, "failed to persist audit log entry");
            }
            (StatusCode::OK, Json(LoginResponse { token: success.token, user: success.username }))
                .into_response()
        }
        AuthenticationResult::Failure(failure) => {
            if let Some(ip) = ip {
                warn!(%ip, user = %login_req.user, "REST login failed");
            }
            if let Err(error) = record_operator_action_with_notifications(
                &state.database,
                &state.webhooks,
                &login_req.user,
                "operator.login",
                "operator",
                (!login_req.user.is_empty()).then_some(login_req.user.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("login"),
                    Some(login_parameters(&login_req.user, &connection_id, "rest")),
                ),
            )
            .await
            {
                warn!(user = %login_req.user, %error, "failed to persist audit log entry");
            }
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            let status = match failure {
                AuthenticationFailure::InvalidCredentials => StatusCode::UNAUTHORIZED,
                AuthenticationFailure::SessionCapExceeded => StatusCode::SERVICE_UNAVAILABLE,
            };
            json_error_response(status, "authentication_failed", failure.message())
        }
    }
}
