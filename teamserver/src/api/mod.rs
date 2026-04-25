//! Versioned REST API framework for the Red Cell teamserver.
//!
//! Sub-modules by concern:
//! - [`auth`] — API-key authentication, rate-limiting, and permission guards
//! - [`errors`] — Standard error envelope types and helpers
//! - [`health`] — Health-check endpoint and response types
//! - [`docs`] — OpenAPI / Swagger documentation setup
//! - [`session`] — Session WebSocket dispatch (NDJSON → REST bridge)

pub mod agents;
pub mod audit;
pub mod auth;
mod docs;
pub mod errors;
mod health;
pub mod listeners;
pub mod loot;
pub mod operators;
pub mod payload;
mod profile;
mod server_logs;
pub(crate) mod session;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{delete, get, post, put};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::debug;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::app::TeamserverState;
use crate::{
    AuditDetails, AuditWebhookNotifier, Database, MAX_AGENT_MESSAGE_LEN,
    record_operator_action_with_notifications,
};

// Re-export public types that were previously defined in this module,
// preserving the `crate::api::X` and `super::X` import paths.
pub(crate) use auth::extract_api_key;
pub use auth::{
    AdminApiAccess, ApiAuthError, ApiIdentity, ApiPermissionGuard, ApiRateLimit, ApiRuntime,
    ListenerManagementApiAccess, ReadApiAccess, TaskAgentApiAccess,
};
pub use errors::{ApiErrorBody, ApiErrorDetail, json_error_response};
pub(crate) use session::session_api_dispatch_line;

const API_VERSION: &str = "v1";
const API_PREFIX: &str = "/api/v1";
const OPENAPI_PATH: &str = "/api/v1/openapi.json";
const DOCS_PATH: &str = "/api/v1/docs";
const OPENAPI_ROUTE: &str = "/openapi.json";
const DOCS_ROUTE: &str = "/docs";

// ── Route assembly ──────────────────────────────────────────────────────────

/// Build the `/api/v1` router, including version metadata and OpenAPI docs.
pub fn api_routes(api: ApiRuntime) -> Router<TeamserverState> {
    let protected = Router::new()
        .route("/agents", get(agents::list_agents))
        .route("/agents/{id}", get(agents::get_agent).delete(agents::kill_agent))
        .route("/agents/{id}/task", post(agents::queue_agent_task))
        .route("/agents/{id}/output", get(agents::get_agent_output))
        .route("/agents/{id}/upload", post(agents::transfer::agent_upload))
        .route("/agents/{id}/download", post(agents::transfer::agent_download))
        .route("/audit", get(audit::list_audit))
        .route("/audit/purge", delete(audit::purge_audit))
        .route("/session-activity", get(audit::list_session_activity))
        .route("/credentials", get(loot::list_credentials))
        .route("/credentials/{id}", get(loot::get_credential))
        .route("/jobs", get(loot::list_jobs))
        .route("/jobs/{agent_id}/{request_id}", get(loot::get_job))
        .route("/loot", get(loot::list_loot))
        .route("/loot/{id}", get(loot::get_loot))
        .route(
            "/agents/{id}/groups",
            get(agents::groups::get_agent_groups).put(agents::groups::set_agent_groups),
        )
        .route("/operators", get(operators::list_operators).post(operators::create_operator))
        .route("/operators/whoami", get(operators::whoami))
        .route("/operators/active", get(operators::active_operators))
        .route("/operators/{username}", delete(operators::delete_operator))
        .route("/operators/{username}/role", put(operators::update_operator_role))
        .route("/operators/{username}/logout", post(operators::logout_operator))
        .route(
            "/operators/{username}/agent-groups",
            get(operators::get_operator_agent_groups).put(operators::set_operator_agent_groups),
        )
        .route(
            "/listeners/{name}/access",
            get(operators::get_listener_access).put(operators::set_listener_access),
        )
        .route("/listeners", get(listeners::list_listeners).post(listeners::create_listener))
        .route(
            "/listeners/{name}",
            get(listeners::get_listener)
                .put(listeners::update_listener)
                .delete(listeners::delete_listener),
        )
        .route("/listeners/{name}/start", put(listeners::start_listener))
        .route("/listeners/{name}/stop", put(listeners::stop_listener))
        .route("/listeners/{name}/mark", post(listeners::mark_listener))
        .route("/listeners/{name}/tls-cert", post(listeners::reload_listener_tls_cert))
        .route("/webhooks/stats", get(payload::get_webhook_stats))
        .route("/payloads", get(payload::list_payloads))
        .route("/payloads/build", post(payload::submit_payload_build))
        .route("/payloads/jobs/{job_id}", get(payload::get_payload_job))
        .route("/payloads/{id}/download", get(payload::download_payload))
        .route("/payload-cache", post(payload::flush_payload_cache))
        .route("/ws", get(crate::session_ws::session_ws_handler))
        .route("/debug/server-logs", get(server_logs::get_server_logs))
        .route("/health", get(health::get_health))
        .route("/profile", get(profile::get_profile))
        .route("/metrics", get(crate::metrics::get_metrics))
        .route_layer(middleware::from_fn_with_state(api, auth::api_auth_middleware))
        .layer(DefaultBodyLimit::max(MAX_AGENT_MESSAGE_LEN));

    Router::new()
        .route("/", get(docs::api_root))
        .merge(protected)
        .merge(SwaggerUi::new(DOCS_ROUTE).url(OPENAPI_ROUTE, docs::ApiDoc::openapi()))
        .fallback(errors::api_not_found)
}

// ── Shared helpers used by sub-modules ──────────────────────────────────────

/// Parse a hex-encoded agent id from a REST path segment.
pub(super) fn parse_api_agent_id(value: &str) -> Result<u32, crate::websocket::AgentCommandError> {
    use crate::websocket::AgentCommandError;

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AgentCommandError::MissingAgentId);
    }

    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);

    u32::from_str_radix(hex_digits, 16)
        .map_err(|_| AgentCommandError::InvalidAgentId { agent_id: trimmed.to_owned() })
}

/// Generate a short random task ID.
pub(super) fn next_task_id() -> String {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    format!("{:08X}", u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Format the current UTC time as RFC 3339.
pub(super) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "unknown".to_owned())
}

/// Record an audit log entry, logging a warning if the write fails.
pub(super) async fn record_audit_entry(
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: AuditDetails,
) {
    if let Err(error) = record_operator_action_with_notifications(
        database,
        webhooks,
        actor,
        action,
        target_kind,
        target_id,
        details,
    )
    .await
    {
        debug!(actor, action, %error, "failed to persist audit log entry");
    }
}

#[cfg(test)]
mod tests;
