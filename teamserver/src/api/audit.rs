//! Audit-trail and session-activity REST handlers.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{IntoParams, ToSchema};

use crate::app::TeamserverState;
use crate::{
    AuditPage, AuditQuery, AuditResultStatus, DEFAULT_AUDIT_RETENTION_DAYS, SessionActivityPage,
    SessionActivityQuery, TeamserverError, audit_details, query_audit_log, query_session_activity,
    record_operator_action_with_notifications,
};

use super::{AdminApiAccess, ApiErrorBody, ReadApiAccess, json_error_response};

#[derive(Debug, Error)]
pub(super) enum AuditApiError {
    #[error("{0}")]
    Teamserver(#[from] TeamserverError),
    #[error("failed to compute cutoff timestamp")]
    TimestampFormat,
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
    // Audit log is intentionally not filtered by per-operator agent-group or
    // listener allow-lists: it is the canonical record of operator actions
    // (login, listener changes, payload builds, agent kills, etc.) and
    // restricting it would degrade incident response and cross-team review.
    // Tightening to AdminApiAccess remains an option for deployments where
    // operators must not see other operators' actions; revisit separately.
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

/// Query parameters for the audit-log purge endpoint.
#[derive(Debug, Deserialize, IntoParams)]
pub(super) struct AuditPurgeQuery {
    /// Override the retention period for this purge (in days).
    /// When absent, the configured `AuditRetentionDays` is used (default 90).
    pub older_than_days: Option<u32>,
}

/// Response body for a successful audit-log purge.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct AuditPurgeResponse {
    /// Number of audit-log rows deleted.
    pub deleted: u64,
    /// RFC 3339 cutoff timestamp used for pruning.
    pub cutoff: String,
}

#[utoipa::path(
    delete,
    path = "/audit/purge",
    context_path = "/api/v1",
    tag = "audit",
    security(("api_key" = [])),
    params(AuditPurgeQuery),
    responses(
        (status = 200, description = "Audit log rows pruned", body = AuditPurgeResponse),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "Admin role required", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn purge_audit(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Query(query): Query<AuditPurgeQuery>,
) -> Result<Json<AuditPurgeResponse>, AuditApiError> {
    let retention_days = query.older_than_days.unwrap_or_else(|| {
        state
            .profile
            .teamserver
            .database
            .as_ref()
            .and_then(|c| c.audit_retention_days)
            .unwrap_or(DEFAULT_AUDIT_RETENTION_DAYS)
    });

    let now = OffsetDateTime::now_utc();
    let cutoff_dt = now - time::Duration::days(i64::from(retention_days));
    let cutoff = cutoff_dt.format(&Rfc3339).map_err(|_| AuditApiError::TimestampFormat)?;

    let deleted = state.database.audit_log().delete_older_than(&cutoff).await?;

    // Record the purge action in the audit log itself.
    let details = audit_details(
        crate::AuditResultStatus::Success,
        None,
        Some("purge"),
        Some(serde_json::json!({
            "retention_days": retention_days,
            "cutoff": cutoff,
            "deleted": deleted,
        })),
    );
    if let Err(err) = record_operator_action_with_notifications(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "audit.purge",
        "audit_log",
        None,
        details,
    )
    .await
    {
        tracing::debug!(actor = %identity.key_id, %err, "failed to persist audit purge record");
    }

    Ok(Json(AuditPurgeResponse { deleted, cutoff }))
}

/// Request body for `POST /audit`.
#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct CreateAuditBody {
    /// Stable action label (e.g. `"operator.local_exec"`).
    pub action: String,
    /// Entity category acted upon (e.g. `"agent"`).
    pub target_kind: String,
    /// Optional target identifier.
    #[serde(default)]
    pub target_id: Option<String>,
    /// Optional related agent identifier (decimal `u32`).
    #[serde(default)]
    pub agent_id: Option<u32>,
    /// Optional command or sub-action label.
    #[serde(default)]
    pub command: Option<String>,
    /// Optional structured parameters.
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
}

/// Response for a successfully created audit entry.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct CreateAuditResponse {
    /// Database-assigned row id.
    pub id: i64,
}

#[utoipa::path(
    post,
    path = "/audit",
    context_path = "/api/v1",
    tag = "audit",
    security(("api_key" = [])),
    request_body = CreateAuditBody,
    responses(
        (status = 201, description = "Audit entry created", body = CreateAuditResponse),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn create_audit(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Json(body): Json<CreateAuditBody>,
) -> Result<(StatusCode, Json<CreateAuditResponse>), AuditApiError> {
    let details = audit_details(
        AuditResultStatus::Success,
        body.agent_id,
        body.command.as_deref(),
        body.parameters,
    );

    let id = record_operator_action_with_notifications(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        &body.action,
        &body.target_kind,
        body.target_id,
        details,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(CreateAuditResponse { id })))
}
