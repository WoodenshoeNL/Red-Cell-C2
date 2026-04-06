//! Payload build, download, cache management, and webhook-stats REST handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::TeamserverState;
use crate::listeners::ListenerManagerError;
use crate::{
    AuditResultStatus, AuditWebhookNotifier, PayloadBuildRecord, audit_details, parameter_object,
};

use super::{
    AdminApiAccess, ApiErrorBody, ReadApiAccess, TaskAgentApiAccess, json_error_response,
    now_rfc3339, record_audit_entry,
};

// ── Webhook stats ─────────────────────────────────────────────────────────────

/// Delivery statistics for the Discord outbound webhook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct DiscordWebhookStats {
    /// Total number of permanent delivery failures (all retry attempts exhausted).
    failures: u64,
}

/// Aggregated outbound webhook delivery statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct WebhookStats {
    /// Discord webhook stats, or `null` when Discord is not configured.
    discord: Option<DiscordWebhookStats>,
}

#[utoipa::path(
    get,
    path = "/webhooks/stats",
    context_path = "/api/v1",
    tag = "webhooks",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Outbound webhook delivery statistics", body = WebhookStats),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody),
    )
)]
pub(super) async fn get_webhook_stats(
    State(webhooks): State<AuditWebhookNotifier>,
    _identity: ReadApiAccess,
) -> Json<WebhookStats> {
    let discord = if webhooks.is_enabled() {
        Some(DiscordWebhookStats { failures: webhooks.discord_failure_count() })
    } else {
        None
    };

    Json(WebhookStats { discord })
}

// ── Payload DTOs ──────────────────────────────────────────────────────────────

/// Summary returned by `GET /payloads` for each completed build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub(super) struct PayloadSummary {
    /// Unique build/payload identifier.
    id: String,
    /// Display name of the payload (e.g. `"demon.x64.exe"`).
    name: String,
    /// Target CPU architecture.
    arch: String,
    /// File format: `"exe"`, `"dll"`, or `"bin"`.
    format: String,
    /// RFC 3339 build timestamp.
    built_at: String,
    /// Artifact size in bytes, if available.
    size_bytes: Option<u64>,
}

/// Request body for `POST /payloads/build`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(super) struct PayloadBuildRequest {
    /// Name of the listener to embed in the payload.
    listener: String,
    /// Target CPU architecture (`"x64"` or `"x86"`).
    arch: String,
    /// Desired output format: `"exe"`, `"dll"`, or `"bin"`.
    format: String,
    /// Agent type to build: `"demon"`, `"archon"`, `"phantom"`, or `"specter"`.
    /// Defaults to `"demon"` when omitted.
    #[serde(default = "default_agent_type")]
    agent: String,
    /// Optional agent sleep interval in seconds.
    sleep: Option<u64>,
}

fn default_agent_type() -> String {
    "demon".to_owned()
}

/// Response returned by `POST /payloads/build`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct PayloadBuildSubmitResponse {
    /// Server-assigned build job identifier.
    job_id: String,
}

/// Response returned by `GET /payloads/jobs/{job_id}`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(super) struct PayloadJobStatus {
    /// Build job identifier.
    job_id: String,
    /// Current status: `"pending"`, `"running"`, `"done"`, or `"error"`.
    status: String,
    /// Agent type that was requested for this build (e.g. `"Demon"`, `"Phantom"`).
    agent_type: String,
    /// Payload identifier (set when status is `"done"`).
    payload_id: Option<String>,
    /// Artifact size in bytes (set when status is `"done"`).
    size_bytes: Option<u64>,
    /// Error message (set when status is `"error"`).
    error: Option<String>,
}

/// Response returned after flushing the payload build artifact cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct FlushPayloadCacheResponse {
    /// Number of cache entries removed.
    flushed: u64,
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Map CLI-style format names to Havoc builder format strings.
pub(super) fn cli_format_to_havoc(format: &str) -> Result<&'static str, String> {
    match format {
        "exe" => Ok("Windows Exe"),
        "dll" => Ok("Windows Dll"),
        "bin" => Ok("Windows Shellcode"),
        other => Err(format!("unsupported format '{other}': expected exe, dll, or bin")),
    }
}

/// Normalize a CLI agent type string (case-insensitive) to the canonical
/// PascalCase name expected by the payload builder.
///
/// Returns `Err` with a user-facing message for unrecognised values.
pub(super) fn normalize_agent_type(agent: &str) -> Result<&'static str, String> {
    match agent.to_lowercase().as_str() {
        "demon" => Ok("Demon"),
        "archon" => Ok("Archon"),
        "phantom" => Ok("Phantom"),
        "specter" => Ok("Specter"),
        other => Err(format!(
            "unsupported agent type '{other}': expected demon, archon, phantom, or specter"
        )),
    }
}

/// Validate that the requested format is supported for the given agent type.
///
/// Phantom and Specter are Rust agents with a fixed build pipeline that always
/// produces a single executable output regardless of the `format` field.
/// Accepting `dll` or `bin` for those agents would silently build an exe while
/// returning a successful response, misleading callers.  Demon and Archon use
/// the Havoc C/ASM toolchain and support all three output classes.
///
/// `agent_type` must already be normalised to PascalCase (i.e. the output of
/// [`normalize_agent_type`]).  `format` is the CLI short form (`"exe"`, `"dll"`,
/// or `"bin"`).
///
/// Returns `Err` with a user-facing message when the combination is unsupported.
pub(super) fn validate_agent_format_combination(
    agent_type: &str,
    format: &str,
) -> Result<(), String> {
    match agent_type {
        // Rust agents have a single fixed output format (exe).
        "Phantom" | "Specter" if format != "exe" => {
            Err(format!("agent '{agent_type}' only supports format 'exe'; got '{format}'"))
        }
        _ => Ok(()),
    }
}

// ── Payload handlers ──────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/payloads",
    context_path = "/api/v1",
    tag = "payloads",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "List of completed payload builds", body = Vec<PayloadSummary>),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody),
    )
)]
pub(super) async fn list_payloads(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
) -> Response {
    match state.database.payload_builds().list_summaries().await {
        Ok(records) => {
            let summaries: Vec<PayloadSummary> = records
                .into_iter()
                .filter(|r| r.status == "done")
                .map(|r| PayloadSummary {
                    id: r.id,
                    name: r.name,
                    arch: r.arch,
                    format: r.format,
                    built_at: r.created_at,
                    size_bytes: r.size_bytes.map(|s| s as u64),
                })
                .collect();
            Json(summaries).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to list payload builds");
            json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payload_list_failed",
                err.to_string(),
            )
        }
    }
}

#[utoipa::path(
    post,
    path = "/payloads/build",
    context_path = "/api/v1",
    tag = "payloads",
    security(("api_key" = [])),
    request_body = PayloadBuildRequest,
    responses(
        (status = 202, description = "Build job submitted", body = PayloadBuildSubmitResponse),
        (status = 400, description = "Invalid build request", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 404, description = "Listener not found", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody),
        (status = 500, description = "Internal server error during listener lookup or build", body = ApiErrorBody),
    )
)]
pub(super) async fn submit_payload_build(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Json(request): Json<PayloadBuildRequest>,
) -> Response {
    // Validate format.
    let havoc_format = match cli_format_to_havoc(&request.format) {
        Ok(f) => f,
        Err(msg) => {
            return json_error_response(StatusCode::BAD_REQUEST, "invalid_format", msg);
        }
    };

    // Validate and normalise agent type.
    let agent_type = match normalize_agent_type(&request.agent) {
        Ok(a) => a,
        Err(msg) => {
            return json_error_response(StatusCode::BAD_REQUEST, "invalid_agent_type", msg);
        }
    };

    // Validate that the agent/format combination is supported.
    if let Err(msg) = validate_agent_format_combination(agent_type, &request.format) {
        return json_error_response(StatusCode::BAD_REQUEST, "unsupported_agent_format", msg);
    }

    // Validate architecture.
    if !matches!(request.arch.as_str(), "x64" | "x86") {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_arch",
            format!("unsupported architecture '{}': expected x64 or x86", request.arch),
        );
    }

    // Look up the listener.
    let listener_summary = match state.listeners.summary(&request.listener).await {
        Ok(s) => s,
        Err(ListenerManagerError::ListenerNotFound { .. }) => {
            return json_error_response(
                StatusCode::NOT_FOUND,
                "listener_not_found",
                format!("listener '{}' not found", request.listener),
            );
        }
        Err(err) => {
            tracing::error!(listener = %request.listener, error = %err, "listener lookup failed during payload build");
            return json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payload_build_listener_lookup_failed",
                format!("failed to look up listener '{}': {err}", request.listener),
            );
        }
    };

    let job_id = Uuid::new_v4().to_string();
    let now = now_rfc3339();

    let record = PayloadBuildRecord {
        id: job_id.clone(),
        status: "pending".to_owned(),
        name: String::new(),
        arch: request.arch.clone(),
        format: request.format.clone(),
        listener: request.listener.clone(),
        agent_type: agent_type.to_owned(),
        sleep_secs: request.sleep.map(|s| i64::try_from(s).unwrap_or(i64::MAX)),
        artifact: None,
        size_bytes: None,
        error: None,
        created_at: now.clone(),
        updated_at: now,
    };

    if let Err(err) = state.database.payload_builds().create(&record).await {
        tracing::error!(error = %err, "failed to create payload build record");
        return json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "payload_build_create_failed",
            err.to_string(),
        );
    }

    // Spawn the background build task.
    let db = state.database.clone();
    let payload_builder = state.payload_builder.clone();
    let webhooks = state.webhooks.clone();
    let actor = identity.key_id.clone();
    let listener_config = listener_summary.config.clone();
    let listener_name = request.listener.clone();
    let arch = request.arch.clone();
    let format_cli = request.format.clone();
    let build_job_id = job_id.clone();

    let build_request = red_cell_common::operator::BuildPayloadRequestInfo {
        agent_type: agent_type.to_owned(),
        listener: request.listener.clone(),
        arch: request.arch.clone(),
        format: havoc_format.to_owned(),
        config: request
            .sleep
            .map_or_else(String::new, |s| serde_json::json!({"Sleep": s}).to_string()),
    };

    tokio::spawn(async move {
        // Mark running.
        if let Err(e) = db
            .payload_builds()
            .update_status(&build_job_id, "running", None, None, None, None, &now_rfc3339())
            .await
        {
            tracing::warn!(build_id = %build_job_id, error = %e, "failed to update payload build status to running");
        }

        match payload_builder.build_payload(&listener_config, &build_request, |_progress| {}).await
        {
            Ok(artifact) => {
                let size = i64::try_from(artifact.bytes.len()).unwrap_or(i64::MAX);
                if let Err(e) = db
                    .payload_builds()
                    .update_status(
                        &build_job_id,
                        "done",
                        Some(&artifact.file_name),
                        Some(&artifact.bytes),
                        Some(size),
                        None,
                        &now_rfc3339(),
                    )
                    .await
                {
                    tracing::warn!(build_id = %build_job_id, error = %e, "failed to update payload build status to done");
                }

                record_audit_entry(
                    &db,
                    &webhooks,
                    &actor,
                    "payload.build",
                    "payload",
                    Some(build_job_id),
                    audit_details(
                        AuditResultStatus::Success,
                        None,
                        None,
                        Some(parameter_object([
                            ("listener", Value::String(listener_name)),
                            ("arch", Value::String(arch)),
                            ("format", Value::String(format_cli)),
                        ])),
                    ),
                )
                .await;
            }
            Err(err) => {
                if let Err(e) = db
                    .payload_builds()
                    .update_status(
                        &build_job_id,
                        "error",
                        None,
                        None,
                        None,
                        Some(&err.to_string()),
                        &now_rfc3339(),
                    )
                    .await
                {
                    tracing::warn!(build_id = %build_job_id, error = %e, "failed to update payload build status to error");
                }

                record_audit_entry(
                    &db,
                    &webhooks,
                    &actor,
                    "payload.build",
                    "payload",
                    Some(build_job_id),
                    audit_details(
                        AuditResultStatus::Failure,
                        None,
                        None,
                        Some(parameter_object([
                            ("listener", Value::String(listener_name)),
                            ("arch", Value::String(arch)),
                            ("format", Value::String(format_cli)),
                            ("error", Value::String(err.to_string())),
                        ])),
                    ),
                )
                .await;
            }
        }
    });

    (StatusCode::ACCEPTED, Json(PayloadBuildSubmitResponse { job_id })).into_response()
}

#[utoipa::path(
    get,
    path = "/payloads/jobs/{job_id}",
    context_path = "/api/v1",
    tag = "payloads",
    security(("api_key" = [])),
    params(
        ("job_id" = String, Path, description = "Build job identifier")
    ),
    responses(
        (status = 200, description = "Build job status", body = PayloadJobStatus),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 404, description = "Job not found", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody),
    )
)]
pub(super) async fn get_payload_job(
    State(state): State<TeamserverState>,
    Path(job_id): Path<String>,
    _identity: ReadApiAccess,
) -> Response {
    match state.database.payload_builds().get_summary(&job_id).await {
        Ok(Some(record)) => {
            let payload_id = if record.status == "done" { Some(record.id.clone()) } else { None };
            Json(PayloadJobStatus {
                job_id: record.id,
                status: record.status,
                agent_type: record.agent_type,
                payload_id,
                size_bytes: record.size_bytes.map(|s| s as u64),
                error: record.error,
            })
            .into_response()
        }
        Ok(None) => json_error_response(
            StatusCode::NOT_FOUND,
            "job_not_found",
            format!("build job '{job_id}' not found"),
        ),
        Err(err) => {
            tracing::error!(error = %err, "failed to get payload build job");
            json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payload_job_fetch_failed",
                err.to_string(),
            )
        }
    }
}

#[utoipa::path(
    get,
    path = "/payloads/{id}/download",
    context_path = "/api/v1",
    tag = "payloads",
    security(("api_key" = [])),
    params(
        ("id" = String, Path, description = "Payload build identifier")
    ),
    responses(
        (status = 200, description = "Raw payload binary", content_type = "application/octet-stream"),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Payload not found or not yet built", body = ApiErrorBody),
        (status = 410, description = "Payload is stale — listener config changed after this payload was built", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody),
    )
)]
pub(super) async fn download_payload(
    State(state): State<TeamserverState>,
    Path(id): Path<String>,
    _identity: TaskAgentApiAccess,
) -> Response {
    match state.database.payload_builds().get(&id).await {
        Ok(Some(mut record)) if record.status == "done" && record.artifact.is_some() => {
            // SAFETY: guard above checks is_some(); use take() to avoid expect()/unwrap()
            let Some(artifact) = record.artifact.take() else {
                return json_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "artifact unexpectedly missing".to_string(),
                );
            };
            let file_name =
                if record.name.is_empty() { format!("payload-{id}.bin") } else { record.name };
            (
                StatusCode::OK,
                [
                    (CONTENT_TYPE, "application/octet-stream"),
                    (CONTENT_DISPOSITION, &format!("attachment; filename=\"{file_name}\"")),
                ],
                artifact,
            )
                .into_response()
        }
        Ok(Some(record)) if record.status == "stale" => json_error_response(
            StatusCode::GONE,
            "payload_stale",
            format!(
                "payload '{id}' is stale — the listener config was updated after this \
                 payload was built; submit a new build request"
            ),
        ),
        Ok(Some(_)) => json_error_response(
            StatusCode::NOT_FOUND,
            "payload_not_ready",
            format!("payload '{id}' is not yet built or build failed"),
        ),
        Ok(None) => json_error_response(
            StatusCode::NOT_FOUND,
            "payload_not_found",
            format!("payload '{id}' not found"),
        ),
        Err(err) => {
            tracing::error!(error = %err, "failed to fetch payload for download");
            json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "payload_download_failed",
                err.to_string(),
            )
        }
    }
}

#[utoipa::path(
    post,
    path = "/payload-cache",
    context_path = "/api/v1",
    tag = "payload_cache",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Cache flushed", body = FlushPayloadCacheResponse),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody),
        (status = 500, description = "Failed to flush cache", body = ApiErrorBody)
    )
)]
pub(super) async fn flush_payload_cache(
    State(state): State<TeamserverState>,
    _identity: AdminApiAccess,
) -> Response {
    match state.payload_builder.cache().flush().await {
        Ok(flushed) => {
            tracing::info!(flushed, "payload cache flushed via REST endpoint");
            Json(FlushPayloadCacheResponse { flushed }).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to flush payload cache");
            json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cache_flush_failed",
                err.to_string(),
            )
        }
    }
}
