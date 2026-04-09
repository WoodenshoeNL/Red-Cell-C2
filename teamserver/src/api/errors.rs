//! Standard REST API error types and helpers.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// Standard REST error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ApiErrorBody {
    /// Nested error detail.
    pub error: ApiErrorDetail,
}

/// Detailed REST error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ApiErrorDetail {
    /// Stable machine-readable error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

/// Create a consistent JSON error response body.
#[must_use]
pub fn json_error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Response {
    let body =
        ApiErrorBody { error: ApiErrorDetail { code: code.into(), message: message.into() } };

    (status, Json(body)).into_response()
}

pub(super) async fn api_not_found() -> Response {
    json_error_response(StatusCode::NOT_FOUND, "not_found", "rest api route not found")
}
