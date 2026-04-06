//! Listener CRUD, lifecycle, and TLS-cert hot-reload REST handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use red_cell_common::ListenerConfig;

use crate::app::TeamserverState;
use crate::listeners::{ListenerManagerError, ListenerMarkRequest, ListenerSummary};
use crate::{AuditResultStatus, ListenerStatus, audit_details, parameter_object};

use super::{
    AdminApiAccess, ApiErrorBody, ListenerManagementApiAccess, ReadApiAccess, now_rfc3339,
    record_audit_entry,
};

/// Request body for hot-reloading a running HTTPS listener's TLS certificate.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct TlsCertReloadRequest {
    /// PEM-encoded certificate chain (leaf + intermediates).
    pub cert_pem: String,
    /// PEM-encoded private key matching the leaf certificate.
    pub key_pem: String,
}

// ── Listener CRUD handlers ────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/listeners",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "List persisted listeners", body = [ListenerSummary]),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_listeners(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
) -> Result<Json<Vec<ListenerSummary>>, ListenerManagerError> {
    Ok(Json(state.listeners.list().await?))
}

#[utoipa::path(
    post,
    path = "/listeners",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    request_body = ListenerConfig,
    responses(
        (status = 201, description = "Listener created", body = ListenerSummary),
        (status = 400, description = "Invalid listener configuration", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 409, description = "Listener already exists", body = ApiErrorBody),
        (status = 422, description = "Listener failed to start", body = ApiErrorBody)
    )
)]
pub(super) async fn create_listener(
    State(state): State<TeamserverState>,
    identity: ListenerManagementApiAccess,
    Json(config): Json<ListenerConfig>,
) -> Result<(StatusCode, Json<ListenerSummary>), ListenerManagerError> {
    let parameters = serde_json::to_value(&config).ok();
    validate_listener_config_fields(&config)?;
    let listener_name = config.name().to_owned();
    let summary = match state.listeners.create(config).await {
        Ok(summary) => summary,
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "listener.create",
                "listener",
                Some(listener_name),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("create"),
                    Some(parameter_object([
                        ("config", parameters.unwrap_or(Value::Null)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error);
        }
    };
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "listener.create",
        "listener",
        Some(summary.name.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("create"),
            serde_json::to_value(&summary.config).ok(),
        ),
    )
    .await;
    Ok((StatusCode::CREATED, Json(summary)))
}

fn validate_listener_config_fields(config: &ListenerConfig) -> Result<(), ListenerManagerError> {
    if config.name().trim().is_empty() {
        return Err(ListenerManagerError::InvalidConfig {
            message: "listener name is required".to_owned(),
        });
    }

    if let ListenerConfig::Smb(config) = config
        && config.pipe_name.trim().is_empty()
    {
        return Err(ListenerManagerError::InvalidConfig {
            message: "pipe name is required".to_owned(),
        });
    }

    Ok(())
}

#[utoipa::path(
    get,
    path = "/listeners/{name}",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    params(("name" = String, Path, description = "Listener name")),
    responses(
        (status = 200, description = "Listener details", body = ListenerSummary),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody)
    )
)]
pub(super) async fn get_listener(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path(name): Path<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    Ok(Json(state.listeners.summary(&name).await?))
}

#[utoipa::path(
    put,
    path = "/listeners/{name}",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    params(("name" = String, Path, description = "Listener name")),
    request_body = ListenerConfig,
    responses(
        (status = 200, description = "Listener updated", body = ListenerSummary),
        (status = 400, description = "Invalid listener configuration", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody)
    )
)]
pub(super) async fn update_listener(
    State(state): State<TeamserverState>,
    identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
    Json(config): Json<ListenerConfig>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    let parameters = serde_json::to_value(&config).ok();
    // Snapshot the current config so we can detect no-op updates later.
    let old_config = state.listeners.summary(&name).await.ok().map(|s| s.config);
    if config.name() != name {
        let error = ListenerManagerError::InvalidConfig {
            message: "path name must match listener configuration name".to_owned(),
        };
        record_audit_entry(
            &state.database,
            &state.webhooks,
            &identity.key_id,
            "listener.update",
            "listener",
            Some(name),
            audit_details(
                AuditResultStatus::Failure,
                None,
                Some("update"),
                Some(parameter_object([
                    ("config", parameters.unwrap_or(Value::Null)),
                    ("error", Value::String(error.to_string())),
                ])),
            ),
        )
        .await;
        return Err(error);
    }

    let summary = match state.listeners.update(config).await {
        Ok(summary) => summary,
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "listener.update",
                "listener",
                Some(name),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("update"),
                    Some(parameter_object([
                        ("config", parameters.unwrap_or(Value::Null)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error);
        }
    };
    // Only invalidate cached payload builds when the listener config actually changed.
    // An identical PUT (same config resubmitted) must not mark valid payloads as stale.
    let config_changed = old_config.as_ref() != Some(&summary.config);
    if config_changed {
        // Errors are non-fatal: log and continue so the update itself still succeeds.
        match state
            .database
            .payload_builds()
            .invalidate_done_builds_for_listener(&summary.name, &now_rfc3339())
            .await
        {
            Ok(0) => {}
            Ok(count) => {
                tracing::info!(
                    listener = %summary.name,
                    invalidated = count,
                    "invalidated stale payload build records after listener config change"
                );
            }
            Err(err) => {
                tracing::warn!(
                    listener = %summary.name,
                    error = %err,
                    "failed to invalidate payload build records after listener config change"
                );
            }
        }
    }

    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "listener.update",
        "listener",
        Some(summary.name.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("update"),
            serde_json::to_value(&summary.config).ok(),
        ),
    )
    .await;
    Ok(Json(summary))
}

#[utoipa::path(
    delete,
    path = "/listeners/{name}",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    params(("name" = String, Path, description = "Listener name")),
    responses(
        (status = 204, description = "Listener deleted"),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody)
    )
)]
pub(super) async fn delete_listener(
    State(state): State<TeamserverState>,
    identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
) -> Result<StatusCode, ListenerManagerError> {
    match state.listeners.delete(&name).await {
        Ok(()) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "listener.delete",
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("delete"),
                    Some(parameter_object([("listener", Value::String(name))])),
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
                "listener.delete",
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("delete"),
                    Some(parameter_object([
                        ("listener", Value::String(name)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            Err(error)
        }
    }
}

#[utoipa::path(
    put,
    path = "/listeners/{name}/start",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    params(("name" = String, Path, description = "Listener name")),
    responses(
        (status = 200, description = "Listener started", body = ListenerSummary),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody),
        (status = 409, description = "Listener already running", body = ApiErrorBody),
        (status = 422, description = "Listener failed to start", body = ApiErrorBody)
    )
)]
pub(super) async fn start_listener(
    State(state): State<TeamserverState>,
    identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    let summary = match state.listeners.start(&name).await {
        Ok(summary) => summary,
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "listener.start",
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("start"),
                    Some(parameter_object([
                        ("listener", Value::String(name.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error);
        }
    };
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "listener.start",
        "listener",
        Some(summary.name.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("start"),
            Some(parameter_object([("listener", Value::String(summary.name.clone()))])),
        ),
    )
    .await;
    Ok(Json(summary))
}

#[utoipa::path(
    put,
    path = "/listeners/{name}/stop",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    params(("name" = String, Path, description = "Listener name")),
    responses(
        (status = 200, description = "Listener stopped", body = ListenerSummary),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody),
        (status = 409, description = "Listener not running", body = ApiErrorBody)
    )
)]
pub(super) async fn stop_listener(
    State(state): State<TeamserverState>,
    identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    let summary = match state.listeners.stop(&name).await {
        Ok(summary) => summary,
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "listener.stop",
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("stop"),
                    Some(parameter_object([
                        ("listener", Value::String(name.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error);
        }
    };
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "listener.stop",
        "listener",
        Some(summary.name.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("stop"),
            Some(parameter_object([("listener", Value::String(summary.name.clone()))])),
        ),
    )
    .await;
    Ok(Json(summary))
}

#[utoipa::path(
    post,
    path = "/listeners/{name}/mark",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    params(("name" = String, Path, description = "Listener name")),
    request_body = ListenerMarkRequest,
    responses(
        (status = 200, description = "Listener marked", body = ListenerSummary),
        (status = 400, description = "Unsupported mark request", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody)
    )
)]
pub(super) async fn mark_listener(
    State(state): State<TeamserverState>,
    identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
    Json(request): Json<ListenerMarkRequest>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    let summary = match request.mark.as_str() {
        mark if mark.eq_ignore_ascii_case("start") || mark.eq_ignore_ascii_case("online") => {
            match state.listeners.start(&name).await {
                Ok(summary) => summary,
                Err(error) => {
                    record_audit_entry(
                        &state.database,
                        &state.webhooks,
                        &identity.key_id,
                        "listener.start",
                        "listener",
                        Some(name.clone()),
                        audit_details(
                            AuditResultStatus::Failure,
                            None,
                            Some(request.mark.as_str()),
                            Some(parameter_object([
                                ("mark", Value::String(request.mark.clone())),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await;
                    return Err(error);
                }
            }
        }
        mark if mark.eq_ignore_ascii_case("stop") || mark.eq_ignore_ascii_case("offline") => {
            match state.listeners.stop(&name).await {
                Ok(summary) => summary,
                Err(error) => {
                    record_audit_entry(
                        &state.database,
                        &state.webhooks,
                        &identity.key_id,
                        "listener.stop",
                        "listener",
                        Some(name.clone()),
                        audit_details(
                            AuditResultStatus::Failure,
                            None,
                            Some(request.mark.as_str()),
                            Some(parameter_object([
                                ("mark", Value::String(request.mark.clone())),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await;
                    return Err(error);
                }
            }
        }
        _ => {
            return Err(ListenerManagerError::UnsupportedMark { mark: request.mark });
        }
    };

    let action = if summary.state.status == ListenerStatus::Running {
        "listener.start"
    } else {
        "listener.stop"
    };
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        action,
        "listener",
        Some(summary.name.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some(request.mark.as_str()),
            Some(parameter_object([("mark", Value::String(request.mark.clone()))])),
        ),
    )
    .await;

    Ok(Json(summary))
}

#[utoipa::path(
    post,
    path = "/listeners/{name}/tls-cert",
    context_path = "/api/v1",
    tag = "listeners",
    security(("api_key" = [])),
    params(("name" = String, Path, description = "Listener name")),
    request_body = TlsCertReloadRequest,
    responses(
        (status = 204, description = "Certificate hot-reloaded; new handshakes will use the new cert"),
        (status = 400, description = "Invalid PEM, expired certificate, or key mismatch", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks admin permission", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody),
        (status = 422, description = "Listener is not a running HTTPS listener", body = ApiErrorBody),
    )
)]
pub(super) async fn reload_listener_tls_cert(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(name): Path<String>,
    Json(body): Json<TlsCertReloadRequest>,
) -> Result<StatusCode, ListenerManagerError> {
    match state
        .listeners
        .reload_tls_cert(&name, body.cert_pem.as_bytes(), body.key_pem.as_bytes())
        .await
    {
        Ok(()) => {}
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "listener.tls_cert_reload",
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("tls_cert_reload"),
                    Some(parameter_object([
                        ("listener", Value::String(name.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error);
        }
    }

    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "listener.tls_cert_reload",
        "listener",
        Some(name.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("tls_cert_reload"),
            Some(parameter_object([("listener", Value::String(name))])),
        ),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
