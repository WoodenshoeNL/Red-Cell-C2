//! Operator management, RBAC, agent-group access, and listener-access REST handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use utoipa::ToSchema;

use red_cell_common::config::OperatorRole;

use crate::app::TeamserverState;
use crate::listeners::ListenerManagerError;
use crate::{AuditResultStatus, AuthError, TeamserverError, audit_details, parameter_object};

use super::{AdminApiAccess, ApiErrorBody, ReadApiAccess, json_error_response, record_audit_entry};

// ── Request / response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub(super) struct OperatorSummary {
    pub(super) username: String,
    pub(super) role: OperatorRole,
    pub(super) online: bool,
    pub(super) last_seen: Option<String>,
}

/// A currently connected operator with session details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct ActiveOperatorEntry {
    /// Operator username.
    pub(super) username: String,
    /// ISO 8601 timestamp when the operator connected.
    pub(super) connect_time: String,
    /// Remote IP address of the operator.
    pub(super) remote_addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
pub(super) struct CreateOperatorRequest {
    username: String,
    password: String,
    role: OperatorRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct CreatedOperatorResponse {
    username: String,
    role: OperatorRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
pub(super) struct UpdateOperatorRoleRequest {
    role: OperatorRole,
}

/// Response body for operator group-access endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OperatorGroupAccessResponse {
    /// Operator username.
    pub username: String,
    /// Groups the operator may task agents from.  Empty means unrestricted.
    pub allowed_groups: Vec<String>,
}

/// Request body for setting operator group-access restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetOperatorGroupAccessRequest {
    /// Replacement allow-list.  Empty makes the operator unrestricted.
    pub allowed_groups: Vec<String>,
}

/// Response body for listener operator allow-list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListenerAccessResponse {
    /// Listener name.
    pub listener_name: String,
    /// Operators allowed to use this listener.  Empty means unrestricted.
    pub allowed_operators: Vec<String>,
}

/// Request body for setting the listener operator allow-list.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetListenerAccessRequest {
    /// Replacement allow-list.  Empty removes all restrictions.
    pub allowed_operators: Vec<String>,
}

/// Response body for the operator logout/session-revocation endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OperatorLogoutResponse {
    /// Operator whose active sessions were revoked.
    pub username: String,
    /// Number of active sessions that were invalidated by this request.
    pub revoked_sessions: usize,
}

/// Response body for `GET /operators/whoami`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct WhoamiResponse {
    /// Operator name (the API key identifier).
    pub(super) name: String,
    /// RBAC role assigned to this API key.
    pub(super) role: OperatorRole,
    /// Authentication method used for this request.
    pub(super) auth_method: String,
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub(super) enum OperatorApiError {
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("{0}")]
    Database(#[from] TeamserverError),
}

impl IntoResponse for OperatorApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Auth(AuthError::DuplicateUser { .. }) => {
                (StatusCode::CONFLICT, "operator_exists")
            }
            Self::Auth(AuthError::EmptyUsername | AuthError::EmptyPassword) => {
                (StatusCode::BAD_REQUEST, "invalid_operator")
            }
            Self::Auth(AuthError::OperatorNotFound { .. }) => {
                (StatusCode::NOT_FOUND, "operator_not_found")
            }
            Self::Auth(AuthError::ProfileOperator { .. }) => {
                (StatusCode::NOT_FOUND, "operator_not_found")
            }
            Self::Auth(AuthError::AuditLog(_)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "operator_audit_unavailable")
            }
            Self::Auth(_) | Self::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "operator_api_error")
            }
        };

        json_error_response(status, code, self.to_string())
    }
}

// ── Operator CRUD handlers ────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/operators",
    context_path = "/api/v1",
    tag = "operators",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "List configured and runtime-created operators with presence state", body = [OperatorSummary]),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 500, description = "Audit log unavailable for operator presence", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_operators(
    State(state): State<TeamserverState>,
    _identity: AdminApiAccess,
) -> Result<Json<Vec<OperatorSummary>>, OperatorApiError> {
    let operators = state
        .auth
        .operator_inventory()
        .await?
        .into_iter()
        .map(|operator| OperatorSummary {
            username: operator.username,
            role: operator.role,
            online: operator.online,
            last_seen: operator.last_seen,
        })
        .collect::<Vec<_>>();
    Ok(Json(operators))
}

#[utoipa::path(
    post,
    path = "/operators",
    context_path = "/api/v1",
    tag = "operators",
    security(("api_key" = [])),
    request_body = CreateOperatorRequest,
    responses(
        (status = 201, description = "Operator account created", body = CreatedOperatorResponse),
        (status = 400, description = "Invalid operator payload", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 409, description = "Operator already exists", body = ApiErrorBody)
    )
)]
pub(super) async fn create_operator(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Json(request): Json<CreateOperatorRequest>,
) -> Result<(StatusCode, Json<CreatedOperatorResponse>), OperatorApiError> {
    let username = request.username.trim().to_owned();
    match state
        .auth
        .create_operator(username.as_str(), request.password.as_str(), request.role)
        .await
    {
        Ok(()) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "operator.create",
                "operator",
                Some(username.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("create"),
                    Some(parameter_object([
                        ("username", Value::String(username.clone())),
                        ("role", Value::String(format!("{:?}", request.role))),
                    ])),
                ),
            )
            .await;

            Ok((
                StatusCode::CREATED,
                Json(CreatedOperatorResponse { username, role: request.role }),
            ))
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "operator.create",
                "operator",
                Some(username.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("create"),
                    Some(parameter_object([
                        ("username", Value::String(username)),
                        ("role", Value::String(format!("{:?}", request.role))),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            Err(error.into())
        }
    }
}

#[utoipa::path(
    delete,
    path = "/operators/{username}",
    context_path = "/api/v1",
    tag = "operators",
    security(("api_key" = [])),
    params(
        ("username" = String, Path, description = "Operator username to delete")
    ),
    responses(
        (status = 204, description = "Operator deleted"),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Operator not found or profile-configured", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn delete_operator(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(username): Path<String>,
) -> Result<StatusCode, OperatorApiError> {
    match state.auth.delete_operator(&username).await {
        Ok(()) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "operator.delete",
                "operator",
                Some(username.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("delete"),
                    Some(parameter_object([("username", Value::String(username))])),
                ),
            )
            .await;

            Ok(StatusCode::NO_CONTENT)
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "operator.delete",
                "operator",
                Some(username.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("delete"),
                    Some(parameter_object([
                        ("username", Value::String(username)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            Err(error.into())
        }
    }
}

#[utoipa::path(
    put,
    path = "/operators/{username}/role",
    context_path = "/api/v1",
    tag = "operators",
    security(("api_key" = [])),
    params(
        ("username" = String, Path, description = "Operator username")
    ),
    request_body = UpdateOperatorRoleRequest,
    responses(
        (status = 200, description = "Operator role updated", body = OperatorSummary),
        (status = 400, description = "Invalid role", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Operator not found or profile-configured", body = ApiErrorBody),
        (status = 500, description = "Audit log unavailable for operator presence", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn update_operator_role(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(username): Path<String>,
    Json(request): Json<UpdateOperatorRoleRequest>,
) -> Result<Json<OperatorSummary>, OperatorApiError> {
    match state.auth.update_operator_role(&username, request.role).await {
        Ok(()) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "operator.update_role",
                "operator",
                Some(username.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("update_role"),
                    Some(parameter_object([
                        ("username", Value::String(username.clone())),
                        ("role", Value::String(format!("{:?}", request.role))),
                    ])),
                ),
            )
            .await;

            // Fetch updated presence info for the response.
            let operators = state.auth.operator_inventory().await?;
            let summary = operators
                .into_iter()
                .find(|op| op.username == username)
                .map(|op| OperatorSummary {
                    username: op.username,
                    role: op.role,
                    online: op.online,
                    last_seen: op.last_seen,
                })
                .unwrap_or(OperatorSummary {
                    username,
                    role: request.role,
                    online: false,
                    last_seen: None,
                });

            Ok(Json(summary))
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "operator.update_role",
                "operator",
                Some(username.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("update_role"),
                    Some(parameter_object([
                        ("username", Value::String(username)),
                        ("role", Value::String(format!("{:?}", request.role))),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            Err(error.into())
        }
    }
}

// ── Whoami handler ───────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/operators/whoami",
    responses(
        (status = 200, description = "Authenticated operator identity", body = WhoamiResponse),
    ),
    security(("api_key" = []))
)]
/// Return the identity behind the current API key.
pub(super) async fn whoami(identity: ReadApiAccess) -> Json<WhoamiResponse> {
    Json(WhoamiResponse {
        name: identity.key_id.clone(),
        role: identity.role,
        auth_method: "api_key".to_owned(),
    })
}

// ── Active operators handler ─────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/operators/active",
    context_path = "/api/v1",
    tag = "operators",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "List of currently connected operators", body = [ActiveOperatorEntry]),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn active_operators(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
) -> Json<Vec<ActiveOperatorEntry>> {
    let active = state.connections.active_operators().await;
    let entries = active
        .into_iter()
        .map(|info| ActiveOperatorEntry {
            username: info.username,
            connect_time: info
                .connect_time
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| info.connect_time.to_string()),
            remote_addr: info.remote_addr.to_string(),
        })
        .collect();
    Json(entries)
}

// ── Logout / session revocation handler ───────────────────────────────────────

#[utoipa::path(
    post,
    path = "/operators/{username}/logout",
    context_path = "/api/v1",
    tag = "operators",
    security(("api_key" = [])),
    params(
        ("username" = String, Path, description = "Operator whose active sessions should be revoked")
    ),
    responses(
        (status = 200, description = "Active operator sessions revoked", body = OperatorLogoutResponse),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Operator not found", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn logout_operator(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(username): Path<String>,
) -> Result<Json<OperatorLogoutResponse>, OperatorApiError> {
    if !state.auth.is_operator_configured(&username).await {
        record_audit_entry(
            &state.database,
            &state.webhooks,
            &identity.key_id,
            "operator.logout",
            "operator",
            Some(username.clone()),
            audit_details(
                AuditResultStatus::Failure,
                None,
                Some("logout"),
                Some(parameter_object([
                    ("username", Value::String(username.clone())),
                    ("error", Value::String("operator_not_found".to_owned())),
                ])),
            ),
        )
        .await;
        return Err(OperatorApiError::Auth(AuthError::OperatorNotFound { username }));
    }

    let revoked = state.auth.revoke_sessions_for_username(&username).await;
    let revoked_connection_ids: Vec<Value> =
        revoked.iter().map(|session| Value::String(session.connection_id.to_string())).collect();
    let revoked_count = revoked.len();

    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "operator.logout",
        "operator",
        Some(username.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("logout"),
            Some(parameter_object([
                ("username", Value::String(username.clone())),
                ("revoked_sessions", Value::Number(serde_json::Number::from(revoked_count))),
                ("connection_ids", Value::Array(revoked_connection_ids)),
            ])),
        ),
    )
    .await;

    Ok(Json(OperatorLogoutResponse { username, revoked_sessions: revoked_count }))
}

// ── Agent group access handlers ───────────────────────────────────────────────

pub(super) async fn get_operator_agent_groups(
    State(state): State<TeamserverState>,
    _identity: AdminApiAccess,
    Path(username): Path<String>,
) -> Result<Json<OperatorGroupAccessResponse>, OperatorApiError> {
    let allowed_groups = state.database.agent_groups().operator_allowed_groups(&username).await?;
    Ok(Json(OperatorGroupAccessResponse { username, allowed_groups }))
}

pub(super) async fn set_operator_agent_groups(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(username): Path<String>,
    Json(request): Json<SetOperatorGroupAccessRequest>,
) -> Result<Json<OperatorGroupAccessResponse>, OperatorApiError> {
    state
        .database
        .agent_groups()
        .set_operator_allowed_groups(&username, &request.allowed_groups)
        .await?;
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "operator.set_agent_groups",
        "operator",
        Some(username.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("set_agent_groups"),
            Some(parameter_object([
                ("username", Value::String(username.clone())),
                (
                    "allowed_groups",
                    serde_json::to_value(&request.allowed_groups).unwrap_or(Value::Null),
                ),
            ])),
        ),
    )
    .await;
    Ok(Json(OperatorGroupAccessResponse { username, allowed_groups: request.allowed_groups }))
}

// ── Listener access handlers ──────────────────────────────────────────────────

pub(super) async fn get_listener_access(
    State(state): State<TeamserverState>,
    _identity: AdminApiAccess,
    Path(name): Path<String>,
) -> Result<Json<ListenerAccessResponse>, ListenerManagerError> {
    let allowed_operators = state.database.listener_access().allowed_operators(&name).await?;
    Ok(Json(ListenerAccessResponse { listener_name: name, allowed_operators }))
}

pub(super) async fn set_listener_access(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(name): Path<String>,
    Json(request): Json<SetListenerAccessRequest>,
) -> Result<Json<ListenerAccessResponse>, ListenerManagerError> {
    state
        .database
        .listener_access()
        .set_allowed_operators(&name, &request.allowed_operators)
        .await?;
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "listener.set_access",
        "listener",
        Some(name.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("set_access"),
            Some(parameter_object([
                ("listener_name", Value::String(name.clone())),
                (
                    "allowed_operators",
                    serde_json::to_value(&request.allowed_operators).unwrap_or(Value::Null),
                ),
            ])),
        ),
    )
    .await;
    Ok(Json(ListenerAccessResponse {
        listener_name: name,
        allowed_operators: request.allowed_operators,
    }))
}
