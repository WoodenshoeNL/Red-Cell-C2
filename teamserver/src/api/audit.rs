//! Audit-trail and session-activity REST handlers.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

use crate::app::TeamserverState;
use crate::{
    AuditPage, AuditQuery, SessionActivityPage, SessionActivityQuery, TeamserverError,
    query_audit_log, query_session_activity,
};

use super::{ApiErrorBody, ReadApiAccess, json_error_response};

#[derive(Debug, Error)]
pub(super) enum AuditApiError {
    #[error("{0}")]
    Teamserver(#[from] TeamserverError),
}

impl IntoResponse for AuditApiError {
    fn into_response(self) -> Response {
        json_error_response(StatusCode::INTERNAL_SERVER_ERROR, "audit_api_error", self.to_string())
    }
}

#[utoipa::path(
    get,
    path = "/audit",
    context_path = "/api/v1",
    tag = "audit",
    security(("api_key" = [])),
    params(AuditQuery),
    responses(
        (status = 200, description = "Filtered and paginated audit trail", body = AuditPage),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_audit(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPage>, AuditApiError> {
    Ok(Json(query_audit_log(&state.database, &query).await?))
}

#[utoipa::path(
    get,
    path = "/session-activity",
    context_path = "/api/v1",
    tag = "session_activity",
    security(("api_key" = [])),
    params(SessionActivityQuery),
    responses(
        (status = 200, description = "Filtered and paginated operator session activity", body = SessionActivityPage),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_session_activity(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Query(query): Query<SessionActivityQuery>,
) -> Result<Json<SessionActivityPage>, AuditApiError> {
    Ok(Json(query_session_activity(&state.database, &query).await?))
}
