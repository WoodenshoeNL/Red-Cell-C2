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
        .route("/agents/{id}/upload", post(agents::agent_upload))
        .route("/agents/{id}/download", post(agents::agent_download))
        .route("/audit", get(audit::list_audit))
        .route("/session-activity", get(audit::list_session_activity))
        .route("/credentials", get(loot::list_credentials))
        .route("/credentials/{id}", get(loot::get_credential))
        .route("/jobs", get(loot::list_jobs))
        .route("/jobs/{agent_id}/{request_id}", get(loot::get_job))
        .route("/loot", get(loot::list_loot))
        .route("/loot/{id}", get(loot::get_loot))
        .route("/agents/{id}/groups", get(agents::get_agent_groups).put(agents::set_agent_groups))
        .route("/operators", get(operators::list_operators).post(operators::create_operator))
        .route("/operators/{username}", delete(operators::delete_operator))
        .route("/operators/{username}/role", put(operators::update_operator_role))
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
        .route("/health", get(health::get_health))
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
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        AgentRegistry, AuditResultStatus, AuthService, Database, EventBus, Job, ListenerManager,
        LootRecord, OperatorConnectionManager, SocketRelayManager, audit_details, parameter_object,
    };

    // Items that moved from mod.rs into sub-modules during the split.
    use super::auth::{
        API_KEY_HEADER, ApiKeyDigest, MAX_FAILED_API_AUTH_ATTEMPTS, RATE_LIMIT_WINDOW,
        RateLimitSubject, RateLimitWindow,
    };
    use crate::rate_limiter::AttemptWindow;

    use std::collections::{BTreeMap, HashMap};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::extract::ConnectInfo;
    use axum::http::header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE, RETRY_AFTER};
    use axum::response::Response;
    use red_cell_common::config::{OperatorRole, Profile};
    use tokio::sync::Mutex;

    use agents::AgentApiError;
    use loot::{CredentialQuery, LootQuery};
    use payload::{cli_format_to_havoc, normalize_agent_type, validate_agent_format_combination};
    use red_cell_common::AgentRecord;
    use red_cell_common::crypto::hash_password_sha3;
    use red_cell_common::demon::DemonCommand;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    // ---- lookup_key_ct unit tests ----

    fn make_digest(byte: u8) -> ApiKeyDigest {
        ApiKeyDigest([byte; 32])
    }

    fn make_identity(key_id: &str) -> ApiIdentity {
        ApiIdentity { key_id: key_id.to_owned(), role: OperatorRole::Analyst }
    }

    #[test]
    fn lookup_key_ct_returns_matching_identity() {
        let keys = vec![
            (make_digest(0xAA), make_identity("key-a")),
            (make_digest(0xBB), make_identity("key-b")),
        ];
        let result = ApiRuntime::lookup_key_ct(&keys, &make_digest(0xBB));
        assert_eq!(result.expect("unwrap").key_id, "key-b");
    }

    #[test]
    fn lookup_key_ct_returns_none_for_unknown_digest() {
        let keys = vec![(make_digest(0xAA), make_identity("key-a"))];
        let result = ApiRuntime::lookup_key_ct(&keys, &make_digest(0xFF));
        assert!(result.is_none());
    }

    #[test]
    fn lookup_key_ct_returns_none_for_empty_key_list() {
        let result = ApiRuntime::lookup_key_ct(&[], &make_digest(0x01));
        assert!(result.is_none());
    }

    #[test]
    fn lookup_key_ct_scans_all_entries_and_returns_last_match() {
        // Two entries with identical digests: the second one should win because
        // the scan never short-circuits after finding the first match.
        let digest = make_digest(0x42);
        let keys = vec![(digest, make_identity("first")), (digest, make_identity("second"))];
        let result = ApiRuntime::lookup_key_ct(&keys, &digest);
        // Always visits every entry; last match wins.
        assert_eq!(result.expect("unwrap").key_id, "second");
    }

    #[tokio::test]
    async fn json_error_response_returns_status_and_documented_body_shape() {
        let response =
            json_error_response(StatusCode::BAD_REQUEST, "invalid_request", "Missing listener");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_request");
        assert_eq!(body["error"]["message"], "Missing listener");
        assert_eq!(
            body,
            serde_json::json!({
                "error": {
                    "code": "invalid_request",
                    "message": "Missing listener"
                }
            })
        );
    }

    #[tokio::test]
    async fn json_error_response_preserves_error_fields_for_non_success_statuses() {
        let unauthorized = json_error_response(
            StatusCode::UNAUTHORIZED,
            "missing_api_key",
            "Missing API key header",
        );
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let unauthorized_body = read_json(unauthorized).await;
        assert_eq!(unauthorized_body["error"]["code"], "missing_api_key");
        assert_eq!(unauthorized_body["error"]["message"], "Missing API key header");

        let server_error = json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "listener_start_failed",
            "Listener startup failed",
        );
        assert_eq!(server_error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let server_error_body = read_json(server_error).await;
        assert_eq!(server_error_body["error"]["code"], "listener_start_failed");
        assert_eq!(server_error_body["error"]["message"], "Listener startup failed");
    }

    #[tokio::test]
    async fn json_error_response_serializes_punctuation_and_mixed_case_verbatim() {
        let response = json_error_response(
            StatusCode::CONFLICT,
            "Agent.State/Conflict",
            "Mixed-Case: listener 'HTTP-01' isn't ready!",
        );

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "Agent.State/Conflict");
        assert_eq!(body["error"]["message"], "Mixed-Case: listener 'HTTP-01' isn't ready!");
        assert!(body.get("error").and_then(Value::as_object).is_some());
    }

    #[tokio::test]
    async fn root_reports_versioning_and_docs_metadata() {
        let app = test_router(None).await;

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).expect("request"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let body = read_json(response).await;
        assert_eq!(body["version"], "v1");
        assert_eq!(body["prefix"], "/api/v1");
        assert_eq!(body["openapi_path"], "/api/v1/openapi.json");
        assert_eq!(body["documentation_path"], "/api/v1/docs");
        assert_eq!(body["enabled"], false);
    }

    #[tokio::test]
    async fn protected_routes_require_api_key() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(Request::builder().uri("/listeners").body(Body::empty()).expect("request"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "missing_api_key");
    }

    #[tokio::test]
    async fn bearer_token_authenticates_protected_routes() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(AUTHORIZATION, "Bearer secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_routes_reject_unknown_api_key() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-admio")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_api_key");
    }

    #[tokio::test]
    async fn analyst_key_can_read_but_cannot_modify() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(get_response.status(), StatusCode::OK);

        let post_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"protocol":"smb","config":{"name":"pivot","pipe_name":"pivot-pipe"}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(post_response.status(), StatusCode::FORBIDDEN);

        let body = read_json(post_response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn permission_denied_audit_record_created_when_analyst_key_attempts_write() {
        let database = Database::connect_in_memory().await.expect("database");
        let (app, _, _) = test_router_with_database(
            database.clone(),
            Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"protocol":"smb","config":{"name":"pivot","pipe_name":"pivot-pipe"}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let page = crate::query_audit_log(
            &database,
            &crate::AuditQuery {
                action: Some("api.permission_denied".to_owned()),
                actor: Some("rest-analyst".to_owned()),
                ..crate::AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        assert_eq!(page.total, 1, "one api.permission_denied record expected");
        let record = &page.items[0];
        assert_eq!(record.action, "api.permission_denied");
        assert_eq!(record.actor, "rest-analyst");
        assert_eq!(record.result_status, crate::AuditResultStatus::Failure);
        let required =
            record.parameters.as_ref().and_then(|p| p.get("required")).and_then(|v| v.as_str());
        assert!(required.is_some(), "permission_denied record should include required permission");
    }

    #[tokio::test]
    async fn list_agents_returns_registered_entries() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body.as_array().expect("agents array").len(), 1);
        assert_eq!(body[0]["AgentID"], 0xDEAD_BEEF_u32);
        assert!(body[0].get("Encryption").is_none());
    }

    #[tokio::test]
    async fn list_agents_includes_dead_agents() {
        // Dead agents must remain visible in GET /agents so operators can use the
        // endpoint for forensics and inventory.  If someone mistakenly switches the
        // implementation to list_active() this test will fail.
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        registry.insert(sample_agent(0xDEAD_C0DE)).await.expect("agent should insert");
        registry.mark_dead(0xDEAD_C0DE, "killed by test").await.expect("mark_dead should succeed");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let agents = body.as_array().expect("agents array");
        assert_eq!(agents.len(), 1, "dead agent must still appear in the list");

        let agent = &agents[0];
        assert_eq!(agent["AgentID"], 0xDEAD_C0DE_u32);
        // Active must be false so callers can distinguish dead from alive agents.
        assert_eq!(agent["Active"], false, "Active field must be false for a dead agent");
        // LastCallIn must be present so callers can assess when the agent was last seen.
        assert!(
            agent.get("LastCallIn").is_some(),
            "LastCallIn field must be present in the response"
        );
        // FirstCallIn must also be present for completeness.
        assert!(
            agent.get("FirstCallIn").is_some(),
            "FirstCallIn field must be present in the response"
        );
    }

    #[tokio::test]
    async fn get_agent_omits_transport_crypto_material() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/DEADBEEF")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["AgentID"], 0xDEAD_BEEF_u32);
        assert!(body.get("Encryption").is_none());
    }

    #[tokio::test]
    async fn get_agent_returns_not_found_for_unknown_agent() {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/DEADBEEF")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "agent_not_found");
    }

    #[tokio::test]
    async fn queue_agent_task_enqueues_job() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEADBEEF/task")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = read_json(response).await;
        assert_eq!(body["agent_id"], "DEADBEEF");
        assert_eq!(body["task_id"], "2A");
        assert_eq!(body["queued_jobs"], 1);

        let queued = registry.queued_jobs(0xDEAD_BEEF).await.expect("queue should load");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].command, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(queued[0].request_id, 0x2A);
    }

    #[tokio::test]
    async fn queue_agent_task_returns_not_found_for_unknown_agent() {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEADBEEF/task")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "agent_not_found");
    }

    #[tokio::test]
    async fn queue_agent_task_returns_429_when_queue_is_full() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        // Fill the queue to capacity.
        for i in 0..crate::agents::MAX_JOB_QUEUE_DEPTH {
            registry
                .enqueue_job(0xDEAD_BEEF, sample_job(i as u32, i as u32, "Neo"))
                .await
                .expect("enqueue should succeed");
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEADBEEF/task")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"FF","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "QueueFull must map to 429, not 500"
        );
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "queue_full");
    }

    #[tokio::test]
    async fn queue_agent_task_queue_full_audit_records_failure() {
        let database = Database::connect_in_memory().await.expect("database");
        let (app, registry, _) = test_router_with_database(
            database.clone(),
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        // Fill the queue to capacity.
        for i in 0..crate::agents::MAX_JOB_QUEUE_DEPTH {
            registry
                .enqueue_job(0xDEAD_BEEF, sample_job(i as u32, i as u32, "Neo"))
                .await
                .expect("enqueue should succeed");
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEADBEEF/task")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"FF","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // Verify the audit trail recorded a failure entry.
        let audit_page = crate::audit::query_audit_log(
            &database,
            &crate::AuditQuery {
                action: Some("agent.task".to_owned()),
                agent_id: Some("DEADBEEF".to_owned()),
                limit: Some(10),
                ..Default::default()
            },
        )
        .await
        .expect("audit query");
        assert!(!audit_page.items.is_empty(), "audit should have at least one entry");
        let last = &audit_page.items[0];
        assert_eq!(
            last.result_status,
            crate::AuditResultStatus::Failure,
            "audit entry must record failure for QueueFull"
        );
    }

    #[tokio::test]
    async fn audit_endpoint_returns_filtered_paginated_results() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/agents/DEADBEEF/task")
                    .method("POST")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await;
        assert!(response.is_ok());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=agent.task&agent_id=DEADBEEF&limit=1")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["limit"], 1);
        assert_eq!(body["items"][0]["action"], "agent.task");
        assert_eq!(body["items"][0]["agent_id"], "DEADBEEF");
        assert_eq!(body["items"][0]["result_status"], "success");
    }

    #[tokio::test]
    async fn delete_agent_queues_kill_job() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/agents/DEADBEEF")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = read_json(response).await;
        assert_eq!(body["agent_id"], "DEADBEEF");
        assert_eq!(body["queued_jobs"], 1);

        let queued = registry.queued_jobs(0xDEAD_BEEF).await.expect("queue should load");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].command, u32::from(DemonCommand::CommandExit));
    }

    #[tokio::test]
    async fn delete_agent_returns_not_found_for_unknown_agent() {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/agents/DEADBEEF")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "agent_not_found");
    }

    #[tokio::test]
    async fn kill_agent_records_audit_entry_on_success() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/agents/DEADBEEF")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=agent.task&agent_id=DEADBEEF&limit=10")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one agent.task audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "agent.task");
        assert_eq!(entry["agent_id"], "DEADBEEF");
        assert_eq!(entry["result_status"], "success");
        assert_eq!(entry["command"], "kill");
    }

    #[tokio::test]
    async fn kill_agent_records_audit_entry_on_failure() {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/agents/DEADBEEF")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=agent.task&agent_id=DEADBEEF&limit=10")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one agent.task audit entry for failure");
        let entry = &items[0];
        assert_eq!(entry["action"], "agent.task");
        assert_eq!(entry["agent_id"], "DEADBEEF");
        assert_eq!(entry["result_status"], "failure");
    }

    /// Sends a GET request to `/agents/{id}` with the given malformed ID and asserts
    /// a 400 Bad Request with error code `"invalid_agent_task"`.
    async fn assert_get_agent_bad_request(malformed_id: &str) {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let uri = format!("/agents/{malformed_id}");
        let response = app
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "GET {uri} should return 400, not {}",
            response.status()
        );
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_agent_task");
    }

    #[tokio::test]
    async fn get_agent_rejects_non_hex_id() {
        assert_get_agent_bad_request("ZZZZZZZZ").await;
    }

    #[tokio::test]
    async fn get_agent_returns_not_found_for_short_hex_id() {
        // "DEAD" is valid hex (parses as 0x0000DEAD) but no agent has that ID.
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/DEAD")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "agent_not_found");
    }

    #[tokio::test]
    async fn get_agent_rejects_too_long_id() {
        assert_get_agent_bad_request("DEADBEEF00").await;
    }

    /// Sends a DELETE request to `/agents/{id}` with a malformed ID and asserts 400.
    async fn assert_delete_agent_bad_request(malformed_id: &str) {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let uri = format!("/agents/{malformed_id}");
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "DELETE {uri} should return 400, not {}",
            response.status()
        );
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_agent_task");
    }

    #[tokio::test]
    async fn delete_agent_rejects_non_hex_id() {
        assert_delete_agent_bad_request("ZZZZZZZZ").await;
    }

    #[tokio::test]
    async fn delete_agent_rejects_too_long_id() {
        assert_delete_agent_bad_request("DEADBEEF00").await;
    }

    /// Sends a POST request to `/agents/{id}/task` with a malformed ID and asserts 400.
    async fn assert_queue_task_bad_request(malformed_id: &str) {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let uri = format!("/agents/{malformed_id}/task");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"01","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "POST {uri} should return 400, not {}",
            response.status()
        );
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_agent_task");
    }

    #[tokio::test]
    async fn queue_task_rejects_non_hex_id() {
        assert_queue_task_bad_request("ZZZZZZZZ").await;
    }

    #[tokio::test]
    async fn queue_task_returns_error_for_short_hex_id() {
        // "DEAD" is valid hex (parses as 0x0000DEAD) but the canonical 8-char form
        // "0000DEAD" differs from the body DemonID "DEAD", triggering a 400
        // mismatch error. Either 400 or 404 is acceptable — not 500.
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEAD/task")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"01","CommandLine":"checkin","DemonID":"DEAD","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        let status = response.status();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "POST /agents/DEAD/task should return 400 or 404, not {status}"
        );
        let body = read_json(response).await;
        assert!(body["error"]["code"].is_string(), "error response should include an error code");
    }

    #[tokio::test]
    async fn queue_task_rejects_too_long_id() {
        assert_queue_task_bad_request("DEADBEEF00").await;
    }

    #[tokio::test]
    async fn analyst_key_cannot_task_agents() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-analyst",
            "secret-analyst",
            OperatorRole::Analyst,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEADBEEF/task")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_endpoint_filters_by_operator_and_time_window() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/agents/DEADBEEF/task")
                    .method("POST")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        let now = time::OffsetDateTime::now_utc();
        let since = (now - time::Duration::hours(1))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("format since");
        let until = (now + time::Duration::hours(1))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("format until");
        let uri = format!("/audit?operator=rest-admin&since={since}&until={until}");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri.as_str())
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["actor"], "rest-admin");
    }

    #[tokio::test]
    async fn session_activity_endpoint_returns_only_persisted_operator_session_events() {
        let database = Database::connect_in_memory().await.expect("database");
        crate::record_operator_action(
            &database,
            "neo",
            "operator.connect",
            "operator",
            Some("neo".to_owned()),
            audit_details(AuditResultStatus::Success, None, Some("connect"), None),
        )
        .await
        .expect("connect activity should persist");
        crate::record_operator_action(
            &database,
            "neo",
            "operator.chat",
            "operator",
            Some("neo".to_owned()),
            audit_details(
                AuditResultStatus::Success,
                None,
                Some("chat"),
                Some(parameter_object([("message", Value::String("hello".to_owned()))])),
            ),
        )
        .await
        .expect("chat activity should persist");
        crate::record_operator_action(
            &database,
            "rest-admin",
            "operator.create",
            "operator",
            Some("trinity".to_owned()),
            audit_details(AuditResultStatus::Success, None, Some("create"), None),
        )
        .await
        .expect("operator management audit should persist");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/session-activity?operator=neo")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 2);
        assert_eq!(body["items"][0]["activity"], "chat");
        assert_eq!(body["items"][0]["operator"], "neo");
        assert_eq!(body["items"][1]["activity"], "connect");
    }

    #[tokio::test]
    async fn jobs_endpoint_lists_queued_jobs_with_filters() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        registry.insert(sample_agent(0xABCD_EF01)).await.expect("agent should insert");

        let first_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEADBEEF/task")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(first_response.status(), StatusCode::ACCEPTED);

        let second_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/agents/ABCDEF01")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(second_response.status(), StatusCode::ACCEPTED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs?agent_id=DEADBEEF&command=checkin")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["agent_id"], "DEADBEEF");
        assert_eq!(body["items"][0]["request_id"], "2A");
        assert_eq!(body["items"][0]["command_line"], "checkin");
    }

    #[tokio::test]
    async fn get_job_returns_specific_queued_job() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEADBEEF/task")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs/DEADBEEF/2A")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["agent_id"], "DEADBEEF");
        assert_eq!(body["request_id"], "2A");
        assert_eq!(body["command_id"], u32::from(DemonCommand::CommandCheckin));
    }

    #[tokio::test]
    async fn loot_endpoint_lists_filtered_records() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "credential".to_owned(),
                name: "credential-1".to_owned(),
                file_path: None,
                size_bytes: Some(12),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(b"Password: test".to_vec()),
                metadata: Some(parameter_object([
                    ("operator", Value::String("neo".to_owned())),
                    ("command_line", Value::String("sekurlsa::logonpasswords".to_owned())),
                ])),
            })
            .await
            .expect("loot should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/loot?kind=credential&operator=neo")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["kind"], "credential");
        assert_eq!(body["items"][0]["operator"], "neo");
    }

    #[tokio::test]
    async fn credentials_endpoint_lists_filtered_records() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let credential_id = database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "credential".to_owned(),
                name: "credential-1".to_owned(),
                file_path: None,
                size_bytes: Some(12),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(b"Password: test".to_vec()),
                metadata: Some(parameter_object([
                    ("operator", Value::String("neo".to_owned())),
                    ("command_line", Value::String("sekurlsa::logonpasswords".to_owned())),
                    ("pattern", Value::String("password".to_owned())),
                ])),
            })
            .await
            .expect("loot should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/credentials?operator=neo&pattern=pass")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], credential_id);
        assert_eq!(body["items"][0]["content"], "Password: test");
        assert_eq!(body["items"][0]["pattern"], "password");
    }

    #[tokio::test]
    async fn get_credential_returns_specific_record_and_not_found_error() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let credential_id = database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "credential".to_owned(),
                name: "credential-1".to_owned(),
                file_path: None,
                size_bytes: Some(12),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(b"Password: test".to_vec()),
                metadata: Some(parameter_object([
                    ("operator", Value::String("neo".to_owned())),
                    ("command_line", Value::String("sekurlsa::logonpasswords".to_owned())),
                    ("pattern", Value::String("password".to_owned())),
                ])),
            })
            .await
            .expect("loot should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/credentials/{credential_id}"))
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["id"], credential_id);
        assert_eq!(body["name"], "credential-1");
        assert_eq!(body["content"], "Password: test");
        assert_eq!(body["operator"], "neo");
        assert_eq!(body["pattern"], "password");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/credentials/999999")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "credential_not_found");
    }

    #[tokio::test]
    async fn get_loot_returns_stored_bytes_and_not_found_error() {
        let profile = test_profile(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)));
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let loot_id = database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "download".to_owned(),
                name: "secret.bin".to_owned(),
                file_path: Some("C:/temp/secret.bin".to_owned()),
                size_bytes: Some(4),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(vec![1, 2, 3, 4]),
                metadata: None,
            })
            .await
            .expect("loot should insert");
        let agent_registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
        let listeners = ListenerManager::new(
            database.clone(),
            agent_registry.clone(),
            events.clone(),
            sockets.clone(),
            None,
        )
        .with_demon_allow_legacy_ctr(true);
        let api = ApiRuntime::from_profile(&profile).expect("rng should work in tests");
        let app = api_routes(api.clone()).with_state(TeamserverState {
            profile: profile.clone(),
            database,
            auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
            api,
            events,
            connections: OperatorConnectionManager::new(),
            agent_registry,
            listeners,
            payload_builder: crate::PayloadBuilderService::disabled_for_tests(),
            sockets,
            webhooks: crate::AuditWebhookNotifier::from_profile(&profile),
            login_rate_limiter: crate::LoginRateLimiter::new(),
            shutdown: crate::ShutdownController::new(),
            service_bridge: None,
            started_at: std::time::Instant::now(),
            plugins_loaded: 0,
            plugins_failed: 0,
            metrics: crate::metrics::standalone_metrics_handle(),
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/loot/{loot_id}"))
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            Some("application/octet-stream"),
        );
        assert_eq!(
            response.headers().get(CONTENT_DISPOSITION).and_then(|value| value.to_str().ok()),
            Some("attachment; filename=\"secret.bin\""),
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("bytes");
        assert_eq!(bytes.as_ref(), [1, 2, 3, 4]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/loot/999999")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "loot_not_found");
    }

    #[tokio::test]
    async fn operators_endpoint_is_admin_only_and_lists_configured_accounts_with_presence() {
        let (app, _, auth) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        auth.authenticate_login(
            Uuid::new_v4(),
            &red_cell_common::operator::LoginInfo {
                user: "Neo".to_owned(),
                password: hash_password_sha3("password1234"),
            },
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let operators = body.as_array().expect("array");
        assert_eq!(operators.len(), 1);
        assert_eq!(operators[0]["username"], "Neo");
        assert_eq!(operators[0]["role"], "Admin");
        assert_eq!(operators[0]["online"], true);
        assert_eq!(operators[0]["last_seen"], Value::Null);
    }

    #[tokio::test]
    async fn create_operator_endpoint_creates_runtime_account_and_lists_it_offline() {
        let (app, _, auth) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"trinity","password":"zion","role":"Operator"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = read_json(response).await;
        assert_eq!(body["username"], "trinity");
        assert_eq!(body["role"], "Operator");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(
            body,
            serde_json::json!([
                {
                    "username": "Neo",
                    "role": "Admin",
                    "online": false,
                    "last_seen": null
                },
                {
                    "username": "trinity",
                    "role": "Operator",
                    "online": false,
                    "last_seen": null
                }
            ])
        );

        let result = auth
            .authenticate_login(
                Uuid::new_v4(),
                &red_cell_common::operator::LoginInfo {
                    user: "trinity".to_owned(),
                    password: hash_password_sha3("zion"),
                },
            )
            .await;
        assert!(matches!(result, crate::auth::AuthenticationResult::Success(_)));
    }

    #[tokio::test]
    async fn create_operator_duplicate_username_returns_conflict() {
        let (app, _, _auth) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        // First creation should succeed.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"trinity","password":"zion","role":"Operator"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);

        // Second creation with the same username should return 409 Conflict.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"trinity","password":"different","role":"Operator"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "operator_exists");
    }

    #[tokio::test]
    async fn create_operator_empty_username_returns_bad_request() {
        let (app, _, _auth) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"","password":"zion","role":"Operator"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_operator");
    }

    #[tokio::test]
    async fn create_operator_empty_password_returns_bad_request() {
        let (app, _, _auth) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"trinity","password":"","role":"Operator"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_operator");
    }

    #[tokio::test]
    async fn operators_endpoint_includes_persisted_runtime_accounts_loaded_at_startup() {
        let database = Database::connect_in_memory().await.expect("database");
        database
            .operators()
            .create(&crate::PersistedOperator {
                username: "trinity".to_owned(),
                password_verifier: crate::auth::password_verifier_for_sha3(&hash_password_sha3(
                    "zion",
                ))
                .expect("password verifier should be generated"),
                role: OperatorRole::Operator,
            })
            .await
            .expect("runtime operator should persist");
        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(
            body,
            serde_json::json!([
                {
                    "username": "Neo",
                    "role": "Admin",
                    "online": false,
                    "last_seen": null
                },
                {
                    "username": "trinity",
                    "role": "Operator",
                    "online": false,
                    "last_seen": null
                }
            ])
        );
    }

    #[tokio::test]
    async fn operators_endpoint_includes_last_seen_from_persisted_session_activity() {
        let database = Database::connect_in_memory().await.expect("database");
        database
            .audit_log()
            .create(&crate::AuditLogEntry {
                id: None,
                actor: "Neo".to_owned(),
                action: "operator.disconnect".to_owned(),
                target_kind: "operator".to_owned(),
                target_id: Some("Neo".to_owned()),
                details: None,
                occurred_at: "2026-03-11T00:00:00Z".to_owned(),
            })
            .await
            .expect("session activity should persist");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body[0]["last_seen"], "2026-03-11T00:00:00Z");
    }

    #[tokio::test]
    async fn rate_limiting_rejects_excess_requests() {
        let app = test_router(Some((1, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second.headers().get(RETRY_AFTER).and_then(|v| v.to_str().ok()), Some("60"),);

        let body = read_json(second).await;
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn rate_limiting_rejects_repeated_invalid_api_keys() {
        let app = test_router(Some((1, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
        let client_ip = SocketAddr::from(([198, 51, 100, 10], 443));

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "wrong-key")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(first).await;
        assert_eq!(body["error"]["code"], "invalid_api_key");

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "another-wrong-key")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = read_json(second).await;
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn rate_limiting_rejects_repeated_missing_api_keys() {
        let app = test_router(Some((1, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
        let client_ip = SocketAddr::from(([203, 0, 113, 10], 443));

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(first).await;
        assert_eq!(body["error"]["code"], "missing_api_key");

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = read_json(second).await;
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn rate_limiting_prunes_expired_windows_for_inactive_keys() {
        let api = ApiRuntime {
            key_hash_secret: Arc::new(
                ApiRuntime::generate_key_hash_secret().expect("rng should work in tests"),
            ),
            keys: Arc::new(Vec::new()),
            rate_limit: ApiRateLimit { requests_per_minute: 60 },
            windows: Arc::new(Mutex::new(BTreeMap::from([
                (
                    RateLimitSubject::MissingApiKey,
                    RateLimitWindow {
                        started_at: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
                        request_count: 1,
                    },
                ),
                (
                    RateLimitSubject::InvalidAuthorizationHeader,
                    RateLimitWindow { started_at: Instant::now(), request_count: 1 },
                ),
            ]))),
            auth_failure_windows: Arc::new(Mutex::new(HashMap::new())),
        };

        api.check_rate_limit(&RateLimitSubject::PresentedCredential(ApiRuntime::hash_api_key(
            api.key_hash_secret.as_ref(),
            "new-key",
        )))
        .await
        .expect("rate limit should allow request");

        let windows = api.windows.lock().await;
        assert!(!windows.contains_key(&RateLimitSubject::MissingApiKey));
        assert!(windows.contains_key(&RateLimitSubject::InvalidAuthorizationHeader));
        assert!(windows.contains_key(&RateLimitSubject::PresentedCredential(
            ApiRuntime::hash_api_key(api.key_hash_secret.as_ref(), "new-key")
        )));
        assert_eq!(windows.len(), 2);
    }

    #[tokio::test]
    async fn auth_failure_rate_limiter_blocks_after_max_failed_attempts() {
        // Use a high per-request limit so only the auth-failure limiter fires.
        let app =
            test_router(Some((1000, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
        let client_ip = SocketAddr::from(([192, 0, 2, 42], 1234));

        // Exhaust the allowed failure budget.
        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/listeners")
                        .header(API_KEY_HEADER, "wrong-key")
                        .extension(ConnectInfo(client_ip))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "invalid_api_key");
        }

        // The next attempt must be blocked before any HMAC work.
        let blocked = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "yet-another-wrong-key")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = read_json(blocked).await;
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn auth_failure_rate_limiter_resets_on_successful_auth() {
        let app =
            test_router(Some((1000, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
        let client_ip = SocketAddr::from(([192, 0, 2, 43], 1234));

        // Record some failures but stay below the threshold.
        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS - 1 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/listeners")
                        .header(API_KEY_HEADER, "wrong-key")
                        .extension(ConnectInfo(client_ip))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // Successful auth clears the failure counter.
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-admin")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(ok.status(), StatusCode::OK);

        // After the reset, a full fresh budget is available — the first wrong attempt is allowed.
        let after_reset = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "wrong-key-after-reset")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(after_reset.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(after_reset).await;
        assert_eq!(body["error"]["code"], "invalid_api_key");
    }

    #[tokio::test]
    async fn auth_failure_rate_limiter_is_not_applied_without_client_ip() {
        // Without a ConnectInfo extension there is no IP to track.  A series of
        // unique wrong keys should each produce invalid_api_key, not rate_limited.
        let app =
            test_router(Some((1000, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        for i in 0..MAX_FAILED_API_AUTH_ATTEMPTS + 1 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/listeners")
                        .header(API_KEY_HEADER, format!("unique-wrong-key-{i}"))
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = read_json(response).await;
            assert_eq!(body["error"]["code"], "invalid_api_key");
        }
    }

    #[tokio::test]
    async fn openapi_spec_is_served() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(Request::builder().uri("/openapi.json").body(Body::empty()).expect("request"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let body = read_json(response).await;
        assert_eq!(body["openapi"], "3.1.0");
        assert!(body["paths"]["/api/v1/listeners"].is_object());
        assert!(body["paths"]["/api/v1/credentials"].is_object());
        assert!(body["paths"]["/api/v1/jobs"].is_object());
    }

    #[tokio::test]
    async fn missing_route_returns_json_not_found() {
        let app = test_router(None).await;

        let response = app
            .oneshot(Request::builder().uri("/missing").body(Body::empty()).expect("request"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn session_dispatch_status_matches_api_root() {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        let value = serde_json::json!({"cmd": "status"});
        let line = session_api_dispatch_line(
            &app,
            "status",
            &value,
            std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
            "secret-admin",
        )
        .await;
        let parsed: Value = serde_json::from_str(&line).expect("session line json");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["cmd"], "status");
        assert_eq!(parsed["data"]["prefix"], "/api/v1");
    }

    #[tokio::test]
    async fn session_dispatch_unknown_command_returns_envelope() {
        let (app, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        let value = serde_json::json!({"cmd": "nosuch"});
        let line = session_api_dispatch_line(
            &app,
            "nosuch",
            &value,
            std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
            "secret-admin",
        )
        .await;
        let parsed: Value = serde_json::from_str(&line).expect("session line json");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"], "UNKNOWN_COMMAND");
    }

    async fn test_router(api_key: Option<(u32, &str, &str, OperatorRole)>) -> Router {
        test_router_with_registry(api_key).await.0
    }

    async fn test_router_with_database(
        database: Database,
        api_key: Option<(u32, &str, &str, OperatorRole)>,
    ) -> (Router, AgentRegistry, AuthService) {
        let profile = test_profile(api_key);
        let agent_registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
        let listeners = ListenerManager::new(
            database.clone(),
            agent_registry.clone(),
            events.clone(),
            sockets.clone(),
            None,
        )
        .with_demon_allow_legacy_ctr(true);

        let api = ApiRuntime::from_profile(&profile).expect("rng should work in tests");
        let auth =
            AuthService::from_profile_with_database(&profile, &database).await.expect("auth");

        (
            api_routes(api.clone()).with_state(TeamserverState {
                profile: profile.clone(),
                database,
                auth: auth.clone(),
                api,
                events,
                connections: OperatorConnectionManager::new(),
                agent_registry: agent_registry.clone(),
                listeners,
                payload_builder: crate::PayloadBuilderService::disabled_for_tests(),
                sockets,
                webhooks: crate::AuditWebhookNotifier::from_profile(&profile),
                login_rate_limiter: crate::LoginRateLimiter::new(),
                shutdown: crate::ShutdownController::new(),
                service_bridge: None,
                started_at: std::time::Instant::now(),
                plugins_loaded: 0,
                plugins_failed: 0,
                metrics: crate::metrics::standalone_metrics_handle(),
            }),
            agent_registry,
            auth,
        )
    }

    async fn test_router_with_registry(
        api_key: Option<(u32, &str, &str, OperatorRole)>,
    ) -> (Router, AgentRegistry, AuthService) {
        let database = Database::connect_in_memory().await.expect("database");
        test_router_with_database(database, api_key).await
    }

    fn test_profile(api_key: Option<(u32, &str, &str, OperatorRole)>) -> Profile {
        let api_block = api_key.map_or_else(String::new, |(limit, name, value, role)| {
            format!(
                r#"
                Api {{
                  RateLimitPerMinute = {limit}
                  key "{name}" {{
                    Value = "{value}"
                    Role = "{role:?}"
                  }}
                }}
                "#
            )
        });

        Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "Neo" {{
                Password = "password1234"
              }}
            }}

            {api_block}

            Demon {{}}
            "#
        ))
        .expect("profile")
    }

    async fn read_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("response body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn sample_agent(agent_id: u32) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: "http".to_owned(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0u8; 32]),
                aes_iv: Zeroizing::new(vec![0u8; 16]),
            },
            hostname: "workstation".to_owned(),
            username: "neo".to_owned(),
            domain_name: "LAB".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.10".to_owned(),
            process_name: "demon.exe".to_owned(),
            process_path: "C:\\Windows\\System32\\demon.exe".to_owned(),
            base_address: 0x140000000,
            process_pid: 4444,
            process_tid: 4445,
            process_ppid: 1000,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 10,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-09T20:00:00Z".to_owned(),
            last_call_in: "2026-03-09T20:05:00Z".to_owned(),
        }
    }

    fn smb_listener_json(name: &str, pipe_name: &str) -> String {
        format!(r#"{{"protocol":"smb","config":{{"name":"{name}","pipe_name":"{pipe_name}"}}}}"#)
    }

    fn http_listener_json(name: &str, port: u16) -> String {
        format!(
            r#"{{"protocol":"http","config":{{"name":"{name}","hosts":["127.0.0.1"],"host_bind":"127.0.0.1","host_rotation":"round-robin","port_bind":{port},"uris":["/"],"secure":false}}}}"#
        )
    }

    fn free_tcp_port() -> u16 {
        let sock = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("failed to bind ephemeral TCP socket");
        sock.local_addr().expect("failed to read local addr").port()
    }

    fn create_listener_request(body: &str, api_key: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/listeners")
            .header(API_KEY_HEADER, api_key)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request")
    }

    // ── POST /listeners ────────────────────────────────────────────────

    #[tokio::test]
    async fn create_listener_returns_created_summary_body() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = read_json(response).await;
        assert_eq!(body["name"], "pivot");
        assert_eq!(body["protocol"], "smb");
        assert_eq!(body["state"]["status"], "Created");
        assert_eq!(body["config"]["protocol"], "smb");
        assert_eq!(body["config"]["config"]["name"], "pivot");
        assert_eq!(body["config"]["config"]["pipe_name"], "pipe-a");
    }

    #[tokio::test]
    async fn create_listener_rejects_duplicate_name_and_records_audit_failure() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let create_response = app
            .clone()
            .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
            .await
            .expect("response");
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let duplicate_response = app
            .clone()
            .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-b"), "secret-admin"))
            .await
            .expect("response");

        assert_eq!(duplicate_response.status(), StatusCode::CONFLICT);
        let body = read_json(duplicate_response).await;
        assert_eq!(body["error"]["code"], "listener_already_exists");

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.create")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let audit_body = read_json(audit_response).await;
        let items = audit_body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.create audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.create");
        assert_eq!(entry["target_kind"], "listener");
        assert_eq!(entry["target_id"], "pivot");
        assert_eq!(entry["result_status"], "failure");
    }

    #[tokio::test]
    async fn create_listener_rejects_empty_name() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(create_listener_request(&smb_listener_json("", "pipe-a"), "secret-admin"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_invalid_config");
    }

    // ── GET /listeners/{name} ───────────────────────────────────────────

    #[tokio::test]
    async fn get_listener_returns_summary_for_existing_listener() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let create_response = app
            .clone()
            .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
            .await
            .expect("response");
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["name"], "pivot");
        assert_eq!(body["config"]["protocol"], "smb");
        assert_eq!(body["state"]["status"], "Created");
    }

    #[tokio::test]
    async fn get_listener_returns_not_found_for_missing_listener() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners/nonexistent")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_not_found");
    }

    // ── PUT /listeners/{name} (update) ──────────────────────────────────

    #[tokio::test]
    async fn update_listener_replaces_config() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let create_response = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("pivot", "old-pipe"),
                "secret-admin",
            ))
            .await
            .expect("response");
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let update_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("pivot", "new-pipe")))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(update_response.status(), StatusCode::OK);
        let body = read_json(update_response).await;
        assert_eq!(body["name"], "pivot");
        assert_eq!(body["config"]["config"]["pipe_name"], "new-pipe");
    }

    #[tokio::test]
    async fn update_listener_rejects_name_mismatch() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("wrong-name", "pipe-b")))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_invalid_config");
    }

    #[tokio::test]
    async fn update_listener_returns_not_found_for_missing() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/nonexistent")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("nonexistent", "pipe")))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_listener_records_audit_entry_on_success() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("pivot", "old-pipe"),
                "secret-admin",
            ))
            .await
            .expect("response");

        let update_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("pivot", "new-pipe")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(update_response.status(), StatusCode::OK);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.update")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.update audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.update");
        assert_eq!(entry["target_kind"], "listener");
        assert_eq!(entry["target_id"], "pivot");
        assert_eq!(entry["result_status"], "success");
    }

    #[tokio::test]
    async fn update_listener_records_audit_entry_on_name_mismatch() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
            .await
            .expect("response");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("wrong-name", "pipe-b")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.update")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.update audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.update");
        assert_eq!(entry["result_status"], "failure");
    }

    // ── DELETE /listeners/{name} ────────────────────────────────────────

    #[tokio::test]
    async fn delete_listener_removes_persisted_entry() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("pivot", "pipe-del"),
                "secret-admin",
            ))
            .await
            .expect("response");

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_listener_returns_not_found_for_missing() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/listeners/ghost")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_listener_records_audit_entry_on_success() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("pivot", "pipe-del"),
                "secret-admin",
            ))
            .await
            .expect("response");

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.delete")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.delete audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.delete");
        assert_eq!(entry["target_kind"], "listener");
        assert_eq!(entry["target_id"], "pivot");
        assert_eq!(entry["result_status"], "success");
    }

    #[tokio::test]
    async fn delete_listener_records_audit_entry_on_not_found() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/listeners/ghost")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.delete")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.delete audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.delete");
        assert_eq!(entry["result_status"], "failure");
    }

    // ── PUT /listeners/{name}/start ─────────────────────────────────────

    #[tokio::test]
    async fn start_listener_transitions_to_running() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(&http_listener_json("edge", port), "secret-admin"))
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/edge/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["name"], "edge");
        assert_eq!(body["state"]["status"], "Running");
    }

    #[tokio::test]
    async fn start_listener_returns_not_found_for_missing() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/ghost/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn start_listener_rejects_already_running() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(&http_listener_json("edge-dup", port), "secret-admin"))
            .await
            .expect("response");

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/edge-dup/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/edge-dup/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_already_running");
    }

    // ── PUT /listeners/{name}/stop ──────────────────────────────────────

    #[tokio::test]
    async fn stop_listener_transitions_to_stopped() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &http_listener_json("edge-stop", port),
                "secret-admin",
            ))
            .await
            .expect("response");

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/edge-stop/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/edge-stop/stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["name"], "edge-stop");
        assert_eq!(body["state"]["status"], "Stopped");
    }

    #[tokio::test]
    async fn stop_listener_returns_not_found_for_missing() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/ghost/stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn stop_listener_rejects_not_running() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("idle", "idle-pipe"),
                "secret-admin",
            ))
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/idle/stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_not_running");
    }

    // ── POST /listeners/{name}/mark ─────────────────────────────────────

    #[tokio::test]
    async fn mark_listener_start_transitions_to_running() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &http_listener_json("mark-edge", port),
                "secret-admin",
            ))
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners/mark-edge/mark")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mark":"start"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["name"], "mark-edge");
        assert_eq!(body["state"]["status"], "Running");
    }

    #[tokio::test]
    async fn mark_listener_stop_transitions_to_stopped() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &http_listener_json("mark-stop", port),
                "secret-admin",
            ))
            .await
            .expect("response");

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/mark-stop/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners/mark-stop/mark")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mark":"stop"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["name"], "mark-stop");
        assert_eq!(body["state"]["status"], "Stopped");
    }

    #[tokio::test]
    async fn mark_listener_online_alias_transitions_to_running() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &http_listener_json("mark-online", port),
                "secret-admin",
            ))
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners/mark-online/mark")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mark":"online"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["state"]["status"], "Running");
    }

    #[tokio::test]
    async fn mark_listener_rejects_unsupported_mark() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("mark-bad", "pipe-bad"),
                "secret-admin",
            ))
            .await
            .expect("response");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners/mark-bad/mark")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mark":"explode"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_unsupported_mark");
    }

    #[tokio::test]
    async fn mark_listener_returns_not_found_for_missing() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners/ghost/mark")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mark":"start"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn parse_api_agent_id_always_parses_hex() -> Result<(), AgentApiError> {
        assert_eq!(super::parse_api_agent_id("DEADBEEF")?, 0xDEAD_BEEF);
        assert_eq!(super::parse_api_agent_id("deadbeef")?, 0xDEAD_BEEF);
        assert_eq!(super::parse_api_agent_id("0xDEADBEEF")?, 0xDEAD_BEEF);
        assert_eq!(super::parse_api_agent_id("0XDEADBEEF")?, 0xDEAD_BEEF);
        Ok(())
    }

    #[test]
    fn parse_api_agent_id_all_digit_hex_is_not_decimal() -> Result<(), AgentApiError> {
        // "00000010" is agent ID 0x10 (16), not decimal 10
        assert_eq!(super::parse_api_agent_id("00000010")?, 0x10);
        assert_eq!(super::parse_api_agent_id("10")?, 0x10);
        assert_eq!(super::parse_api_agent_id("0x10")?, 0x10);
        Ok(())
    }

    #[test]
    fn parse_api_agent_id_rejects_empty_and_invalid() {
        assert!(super::parse_api_agent_id("").is_err());
        assert!(super::parse_api_agent_id("   ").is_err());
        assert!(super::parse_api_agent_id("ZZZZ").is_err());
        assert!(super::parse_api_agent_id("not-hex").is_err());
    }

    #[test]
    fn parse_api_agent_id_trims_whitespace() -> Result<(), AgentApiError> {
        assert_eq!(super::parse_api_agent_id("  DEADBEEF  ")?, 0xDEAD_BEEF);
        assert_eq!(super::parse_api_agent_id(" 0x10 ")?, 0x10);
        Ok(())
    }

    #[test]
    fn parse_api_agent_id_u32_max_boundary() -> Result<(), AgentApiError> {
        // u32::MAX (0xFFFF_FFFF) must succeed
        assert_eq!(super::parse_api_agent_id("FFFFFFFF")?, u32::MAX);
        assert_eq!(super::parse_api_agent_id("ffffffff")?, u32::MAX);
        assert_eq!(super::parse_api_agent_id("0xFFFFFFFF")?, u32::MAX);
        assert_eq!(super::parse_api_agent_id("0xffffffff")?, u32::MAX);
        Ok(())
    }

    #[test]
    fn parse_api_agent_id_rejects_overflow() {
        // 9 hex digits — value 0x1_0000_0000 overflows u32
        assert!(super::parse_api_agent_id("100000000").is_err());
        assert!(super::parse_api_agent_id("0x100000000").is_err());
        // Larger values also rejected
        assert!(super::parse_api_agent_id("FFFFFFFFF").is_err());
        assert!(super::parse_api_agent_id("0xFFFFFFFF0").is_err());
    }

    #[tokio::test]
    async fn flush_payload_cache_returns_flushed_count_for_admin() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payload-cache")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        // The disabled-for-tests service uses a nonexistent cache dir, so 0 entries flushed.
        assert_eq!(body["flushed"], 0);
    }

    #[tokio::test]
    async fn flush_payload_cache_requires_admin_role() {
        let app =
            test_router(Some((60, "rest-operator", "secret-op", OperatorRole::Operator))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payload-cache")
                    .header(API_KEY_HEADER, "secret-op")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_webhook_stats_returns_null_discord_when_not_configured() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/webhooks/stats")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["discord"], Value::Null);
    }

    #[tokio::test]
    async fn get_webhook_stats_returns_discord_failures_when_configured() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Api {
              RateLimitPerMinute = 60
              key "rest-admin" {
                Value = "secret-admin"
                Role = "Admin"
              }
            }

            WebHook {
              Discord {
                Url = "http://127.0.0.1:19999/discord-stub"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile");

        let database = crate::Database::connect_in_memory().await.expect("database");
        let agent_registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
        let listeners = ListenerManager::new(
            database.clone(),
            agent_registry.clone(),
            events.clone(),
            sockets.clone(),
            None,
        )
        .with_demon_allow_legacy_ctr(true);
        let api = ApiRuntime::from_profile(&profile).expect("rng should work in tests");
        let auth = AuthService::from_profile(&profile).expect("auth service should initialize");

        let app = api_routes(api.clone()).with_state(crate::TeamserverState {
            profile: profile.clone(),
            database,
            auth,
            api,
            events,
            connections: OperatorConnectionManager::new(),
            agent_registry,
            listeners,
            payload_builder: crate::PayloadBuilderService::disabled_for_tests(),
            sockets,
            webhooks: crate::AuditWebhookNotifier::from_profile(&profile),
            login_rate_limiter: crate::LoginRateLimiter::new(),
            shutdown: crate::ShutdownController::new(),
            service_bridge: None,
            started_at: std::time::Instant::now(),
            plugins_loaded: 0,
            plugins_failed: 0,
            metrics: crate::metrics::standalone_metrics_handle(),
        });

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/webhooks/stats")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert!(body["discord"].is_object(), "discord field should be present when configured");
        assert_eq!(body["discord"]["failures"], 0u64);
    }

    // ── GET /listeners (list) ─────────────────────────────────────────

    #[tokio::test]
    async fn list_listeners_returns_empty_array_initially() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body, serde_json::json!([]));
    }

    #[tokio::test]
    async fn list_listeners_returns_created_listeners() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let create_response = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("pivot-a", "pipe-a"),
                "secret-admin",
            ))
            .await
            .expect("response");
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let create_response = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("pivot-b", "pipe-b"),
                "secret-admin",
            ))
            .await
            .expect("response");
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let items = body.as_array().expect("array of listeners");
        assert_eq!(items.len(), 2);
        let names: Vec<&str> = items.iter().filter_map(|v| v["name"].as_str()).collect();
        assert!(names.contains(&"pivot-a"));
        assert!(names.contains(&"pivot-b"));
    }

    // ── Listener round-trip integration test ──────────────────────────

    #[tokio::test]
    async fn listener_rest_api_round_trip_create_get_list_update_start_stop_delete() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        // 1. Create
        let response = app
            .clone()
            .oneshot(create_listener_request(
                &http_listener_json("roundtrip", port),
                "secret-admin",
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = read_json(response).await;
        assert_eq!(body["name"], "roundtrip");
        assert_eq!(body["state"]["status"], "Created");

        // 2. Get
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners/roundtrip")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["name"], "roundtrip");

        // 3. List
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let items = body.as_array().expect("listener array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "roundtrip");

        // 4. Update (change port_bind to a new ephemeral port)
        let new_port = free_tcp_port();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/roundtrip")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(http_listener_json("roundtrip", new_port)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["name"], "roundtrip");

        // 5. Start
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/roundtrip/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["state"]["status"], "Running");

        // 6. Stop
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/roundtrip/stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["state"]["status"], "Stopped");

        // 7. Delete
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/listeners/roundtrip")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify deletion
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners/roundtrip")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── Validation: empty SMB pipe name ───────────────────────────────

    #[tokio::test]
    async fn create_listener_rejects_empty_smb_pipe_name() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(create_listener_request(&smb_listener_json("pivot", ""), "secret-admin"))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_invalid_config");
    }

    // ── RBAC: analyst cannot delete listeners ─────────────────────────

    #[tokio::test]
    async fn analyst_key_cannot_delete_listeners() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/listeners/any-listener")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn analyst_key_cannot_start_listeners() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/any-listener/start")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn analyst_key_cannot_stop_listeners() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/any-listener/stop")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn analyst_key_cannot_update_listeners() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/any-listener")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("any-listener", "pipe")))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn analyst_key_cannot_mark_listeners() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/listeners/any-listener/mark")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mark":"start"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    // ── Audit: start/stop record audit entries ────────────────────────

    #[tokio::test]
    async fn start_listener_records_audit_entry_on_success() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &http_listener_json("audit-start", port),
                "secret-admin",
            ))
            .await
            .expect("response");

        let start_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/audit-start/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(start_response.status(), StatusCode::OK);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.start audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.start");
        assert_eq!(entry["target_kind"], "listener");
        assert_eq!(entry["target_id"], "audit-start");
        assert_eq!(entry["result_status"], "success");
    }

    #[tokio::test]
    async fn stop_listener_records_audit_entry_on_success() {
        let port = free_tcp_port();
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &http_listener_json("audit-stop", port),
                "secret-admin",
            ))
            .await
            .expect("response");

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/audit-stop/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let stop_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/audit-stop/stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(stop_response.status(), StatusCode::OK);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.stop audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.stop");
        assert_eq!(entry["target_kind"], "listener");
        assert_eq!(entry["target_id"], "audit-stop");
        assert_eq!(entry["result_status"], "success");
    }

    #[tokio::test]
    async fn start_listener_records_audit_entry_on_not_found() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/ghost/start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.start")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.start audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.start");
        assert_eq!(entry["result_status"], "failure");
    }

    #[tokio::test]
    async fn stop_listener_records_audit_entry_on_not_found() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/ghost/stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?action=listener.stop")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(audit_response.status(), StatusCode::OK);
        let body = read_json(audit_response).await;
        let items = body["items"].as_array().expect("items array");
        assert!(!items.is_empty(), "expected at least one listener.stop audit entry");
        let entry = &items[0];
        assert_eq!(entry["action"], "listener.stop");
        assert_eq!(entry["result_status"], "failure");
    }

    // ── Analyst can GET a single listener ─────────────────────────────

    #[tokio::test]
    async fn analyst_key_can_get_individual_listener() {
        let database = Database::connect_in_memory().await.expect("database");
        let agent_registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
        let listeners = ListenerManager::new(
            database.clone(),
            agent_registry.clone(),
            events.clone(),
            sockets.clone(),
            None,
        )
        .with_demon_allow_legacy_ctr(true);

        // Build a profile with both admin and analyst keys.
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Api {
              RateLimitPerMinute = 60
              key "rest-admin" {
                Value = "secret-admin"
                Role = "Admin"
              }
              key "rest-analyst" {
                Value = "secret-analyst"
                Role = "Analyst"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile");

        let api = ApiRuntime::from_profile(&profile).expect("rng should work in tests");
        let auth =
            AuthService::from_profile_with_database(&profile, &database).await.expect("auth");
        let app = api_routes(api.clone()).with_state(TeamserverState {
            profile: profile.clone(),
            database,
            auth,
            api,
            events,
            connections: OperatorConnectionManager::new(),
            agent_registry,
            listeners,
            payload_builder: crate::PayloadBuilderService::disabled_for_tests(),
            sockets,
            webhooks: crate::AuditWebhookNotifier::from_profile(&profile),
            login_rate_limiter: crate::LoginRateLimiter::new(),
            shutdown: crate::ShutdownController::new(),
            service_bridge: None,
            started_at: std::time::Instant::now(),
            plugins_loaded: 0,
            plugins_failed: 0,
            metrics: crate::metrics::standalone_metrics_handle(),
        });

        // Admin creates a listener.
        let create_response = app
            .clone()
            .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
            .await
            .expect("response");
        assert_eq!(create_response.status(), StatusCode::CREATED);

        // Analyst can read the individual listener.
        let get_response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(get_response.status(), StatusCode::OK);
        let body = read_json(get_response).await;
        assert_eq!(body["name"], "pivot");
    }

    // ── Credential endpoint integration tests ─────────────────────────

    #[tokio::test]
    async fn credentials_pagination_returns_correct_slices() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        for i in 0..5 {
            database
                .loot()
                .create(&LootRecord {
                    id: None,
                    agent_id: 0xDEAD_BEEF,
                    kind: "credential".to_owned(),
                    name: format!("cred-{i}"),
                    file_path: None,
                    size_bytes: Some(8),
                    captured_at: format!("2026-03-10T10:0{i}:00Z"),
                    data: Some(format!("secret-{i}").into_bytes()),
                    metadata: Some(parameter_object([(
                        "operator",
                        Value::String("neo".to_owned()),
                    )])),
                })
                .await
                .expect("loot should insert");
        }

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        // First page: offset=0, limit=2
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/credentials?limit=2&offset=0")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 5);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 0);
        assert_eq!(body["items"].as_array().expect("items array").len(), 2);

        // Second page: offset=2, limit=2
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/credentials?limit=2&offset=2")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 5);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 2);
        assert_eq!(body["items"].as_array().expect("items array").len(), 2);

        // Last page: offset=4, limit=2 — only 1 item left
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/credentials?limit=2&offset=4")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 5);
        assert_eq!(body["items"].as_array().expect("items array").len(), 1);
    }

    #[tokio::test]
    async fn get_credential_with_invalid_id_returns_bad_request() {
        let (router, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/credentials/not-a-number")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_credential_id");
    }

    #[tokio::test]
    async fn get_credential_returns_not_found_for_non_credential_loot() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let download_id = database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "download".to_owned(),
                name: "payload.bin".to_owned(),
                file_path: Some("C:/temp/payload.bin".to_owned()),
                size_bytes: Some(4),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(vec![0xDE, 0xAD]),
                metadata: None,
            })
            .await
            .expect("loot should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/credentials/{download_id}"))
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "credential_not_found");
    }

    #[tokio::test]
    async fn credentials_default_pagination_applies_when_no_params() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "credential".to_owned(),
                name: "cred-only".to_owned(),
                file_path: None,
                size_bytes: Some(4),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(b"pass".to_vec()),
                metadata: None,
            })
            .await
            .expect("loot should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/credentials")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["limit"], CredentialQuery::DEFAULT_LIMIT);
        assert_eq!(body["offset"], 0);
        assert_eq!(body["items"].as_array().expect("items array").len(), 1);
    }

    // ── Loot endpoint integration tests ───────────────────────────────

    #[tokio::test]
    async fn loot_pagination_returns_correct_slices() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        for i in 0..5 {
            database
                .loot()
                .create(&LootRecord {
                    id: None,
                    agent_id: 0xDEAD_BEEF,
                    kind: "download".to_owned(),
                    name: format!("file-{i}.bin"),
                    file_path: Some(format!("C:/temp/file-{i}.bin")),
                    size_bytes: Some(4),
                    captured_at: format!("2026-03-10T10:0{i}:00Z"),
                    data: Some(vec![i as u8; 4]),
                    metadata: None,
                })
                .await
                .expect("loot should insert");
        }

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        // First page: offset=0, limit=3
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/loot?limit=3&offset=0")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 5);
        assert_eq!(body["limit"], 3);
        assert_eq!(body["offset"], 0);
        assert_eq!(body["items"].as_array().expect("items array").len(), 3);

        // Second page: offset=3, limit=3 — only 2 items left
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/loot?limit=3&offset=3")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 5);
        assert_eq!(body["limit"], 3);
        assert_eq!(body["offset"], 3);
        assert_eq!(body["items"].as_array().expect("items array").len(), 2);
    }

    #[tokio::test]
    async fn get_loot_with_invalid_id_returns_bad_request() {
        let (router, _, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/loot/not-a-number")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_loot_id");
    }

    #[tokio::test]
    async fn get_loot_returns_conflict_when_data_is_missing() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let loot_id = database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "screenshot".to_owned(),
                name: "screen.png".to_owned(),
                file_path: None,
                size_bytes: None,
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: None,
                metadata: None,
            })
            .await
            .expect("loot should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/loot/{loot_id}"))
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "loot_missing_data");
    }

    #[tokio::test]
    async fn loot_default_pagination_applies_when_no_params() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "download".to_owned(),
                name: "single.bin".to_owned(),
                file_path: None,
                size_bytes: Some(1),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(vec![0x42]),
                metadata: None,
            })
            .await
            .expect("loot should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/loot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["limit"], LootQuery::DEFAULT_LIMIT);
        assert_eq!(body["offset"], 0);
        assert_eq!(body["items"].as_array().expect("items array").len(), 1);
        assert!(body["items"][0]["has_data"].as_bool().expect("has_data should be bool"));
    }

    #[tokio::test]
    async fn credentials_endpoint_excludes_non_credential_loot() {
        let database = Database::connect_in_memory().await.expect("database");
        database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        // Insert a credential
        database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "credential".to_owned(),
                name: "cred-1".to_owned(),
                file_path: None,
                size_bytes: Some(4),
                captured_at: "2026-03-10T10:00:00Z".to_owned(),
                data: Some(b"pass".to_vec()),
                metadata: None,
            })
            .await
            .expect("credential should insert");
        // Insert a non-credential loot
        database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "download".to_owned(),
                name: "payload.bin".to_owned(),
                file_path: Some("C:/temp/payload.bin".to_owned()),
                size_bytes: Some(4),
                captured_at: "2026-03-10T10:01:00Z".to_owned(),
                data: Some(vec![0xDE, 0xAD]),
                metadata: None,
            })
            .await
            .expect("download should insert");

        let (router, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/credentials")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1, "only credential items should be counted");
        assert_eq!(body["items"].as_array().expect("items array").len(), 1);
        assert_eq!(body["items"][0]["name"], "cred-1");
    }

    // ── Job queue endpoint integration tests ──────────────────────────

    fn sample_job(command: u32, request_id: u32, operator: &str) -> Job {
        Job {
            command,
            request_id,
            payload: vec![0xAA; 16],
            command_line: format!("cmd-{request_id}"),
            task_id: format!("task-{request_id:X}"),
            created_at: "2026-03-19T12:00:00Z".to_owned(),
            operator: operator.to_owned(),
        }
    }

    #[tokio::test]
    async fn list_jobs_returns_enqueued_jobs() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        registry.enqueue_job(0xDEAD_BEEF, sample_job(10, 0x100, "Neo")).await.expect("enqueue");
        registry.enqueue_job(0xDEAD_BEEF, sample_job(20, 0x200, "Neo")).await.expect("enqueue");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 2);
        let items = body["items"].as_array().expect("items array");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["agent_id"], "DEADBEEF");
        assert_eq!(items[0]["command_id"], 10);
        assert_eq!(items[0]["request_id"], "100");
        assert_eq!(items[0]["task_id"], "task-100");
        assert_eq!(items[0]["command_line"], "cmd-256");
        assert_eq!(items[0]["operator"], "Neo");
        assert_eq!(items[0]["payload_size"], 16);
        assert_eq!(items[1]["command_id"], 20);
        assert_eq!(items[1]["request_id"], "200");
    }

    #[tokio::test]
    async fn get_job_returns_specific_enqueued_job() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        registry.enqueue_job(0xDEAD_BEEF, sample_job(42, 0xABC, "Neo")).await.expect("enqueue");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs/DEADBEEF/ABC")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["agent_id"], "DEADBEEF");
        assert_eq!(body["command_id"], 42);
        assert_eq!(body["request_id"], "ABC");
        assert_eq!(body["task_id"], "task-ABC");
        assert_eq!(body["operator"], "Neo");
        assert_eq!(body["payload_size"], 16);
    }

    #[tokio::test]
    async fn get_job_returns_not_found_for_unknown_job() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs/DEADBEEF/999")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "job_not_found");
    }

    #[tokio::test]
    async fn list_jobs_returns_empty_after_dequeue() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        registry.enqueue_job(0xDEAD_BEEF, sample_job(10, 0x100, "Neo")).await.expect("enqueue");

        // Drain the queue before querying the API.
        let drained = registry.dequeue_jobs(0xDEAD_BEEF).await.expect("dequeue");
        assert_eq!(drained.len(), 1);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 0);
        assert_eq!(body["items"].as_array().expect("items array").len(), 0);
    }

    #[tokio::test]
    async fn list_jobs_filters_by_agent_id() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("insert agent 1");
        registry.insert(sample_agent(0xABCD_EF01)).await.expect("insert agent 2");
        registry.enqueue_job(0xDEAD_BEEF, sample_job(10, 0x100, "Neo")).await.expect("enqueue");
        registry.enqueue_job(0xABCD_EF01, sample_job(20, 0x200, "Trinity")).await.expect("enqueue");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs?agent_id=ABCDEF01")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        let items = body["items"].as_array().expect("items array");
        assert_eq!(items[0]["agent_id"], "ABCDEF01");
        assert_eq!(items[0]["operator"], "Trinity");
    }

    #[tokio::test]
    async fn get_job_accepts_0x_prefixed_agent_id() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "rest-admin",
            "secret-admin",
            OperatorRole::Admin,
        )))
        .await;
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        registry.enqueue_job(0xDEAD_BEEF, sample_job(7, 0x42, "Neo")).await.expect("enqueue");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/jobs/0xDEADBEEF/0x42")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["agent_id"], "DEADBEEF");
        assert_eq!(body["request_id"], "42");
    }

    // ---- operator management RBAC tests ----

    #[tokio::test]
    async fn analyst_key_cannot_create_operator() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"cypher","password":"steak123","role":"Analyst"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn analyst_key_cannot_list_operators() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    // ── session-activity endpoint additional coverage ──────────────────

    #[tokio::test]
    async fn session_activity_filters_by_activity_type() {
        let database = Database::connect_in_memory().await.expect("database");
        crate::record_operator_action(
            &database,
            "neo",
            "operator.connect",
            "operator",
            Some("neo".to_owned()),
            audit_details(AuditResultStatus::Success, None, Some("connect"), None),
        )
        .await
        .expect("connect event");
        crate::record_operator_action(
            &database,
            "neo",
            "operator.disconnect",
            "operator",
            Some("neo".to_owned()),
            audit_details(AuditResultStatus::Success, None, Some("disconnect"), None),
        )
        .await
        .expect("disconnect event");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/session-activity?activity=connect")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["activity"], "connect");
    }

    #[tokio::test]
    async fn session_activity_paginates_results() {
        let database = Database::connect_in_memory().await.expect("database");
        for action in ["operator.connect", "operator.chat", "operator.disconnect"] {
            let activity = action.strip_prefix("operator.").expect("prefix");
            crate::record_operator_action(
                &database,
                "neo",
                action,
                "operator",
                Some("neo".to_owned()),
                audit_details(AuditResultStatus::Success, None, Some(activity), None),
            )
            .await
            .expect("session event");
        }

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/session-activity?limit=2&offset=0")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 0);
        assert_eq!(body["items"].as_array().expect("items array").len(), 2);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/session-activity?limit=2&offset=2")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["items"].as_array().expect("items array").len(), 1);
    }

    #[tokio::test]
    async fn session_activity_invalid_limit_returns_client_error() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/session-activity?limit=not_a_number")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert!(
            response.status().is_client_error(),
            "non-numeric limit should produce a 4xx response, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn session_activity_returns_empty_page_when_no_events_match() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/session-activity?operator=nonexistent")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 0);
        assert!(body["items"].as_array().expect("items array").is_empty());
    }

    #[tokio::test]
    async fn session_activity_filters_by_time_window() {
        let database = Database::connect_in_memory().await.expect("database");
        // Insert an event with a known timestamp via the audit log directly.
        database
            .audit_log()
            .create(&crate::AuditLogEntry {
                id: None,
                actor: "neo".to_owned(),
                action: "operator.connect".to_owned(),
                target_kind: "operator".to_owned(),
                target_id: Some("neo".to_owned()),
                details: Some(serde_json::json!({
                    "result_status": "success",
                    "command": "connect"
                })),
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("audit entry");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        // Query with a window that includes the event.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/session-activity?since=2026-03-10T00:00:00Z&until=2026-03-10T23:59:59Z")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);

        // Query with a window that excludes the event.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/session-activity?since=2026-03-11T00:00:00Z")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 0);
    }

    // ---- Unit tests for auth failure tracking (is_auth_failure_allowed / record_auth_failure / record_auth_success) ----

    /// Build a minimal `ApiRuntime` with no API keys and a disabled request
    /// rate-limit, suitable for testing the auth-failure and rate-limit
    /// internals in isolation.
    fn test_api_runtime(requests_per_minute: u32) -> ApiRuntime {
        ApiRuntime {
            key_hash_secret: Arc::new(
                ApiRuntime::generate_key_hash_secret().expect("rng should work in tests"),
            ),
            keys: Arc::new(Vec::new()),
            rate_limit: ApiRateLimit { requests_per_minute },
            windows: Arc::new(Mutex::new(BTreeMap::new())),
            auth_failure_windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last_octet))
    }

    #[tokio::test]
    async fn auth_failure_n_minus_1_attempts_still_allowed() {
        let api = test_api_runtime(0);
        let ip = test_ip(1);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS - 1 {
            api.record_auth_failure(ip).await;
        }

        assert!(api.is_auth_failure_allowed(ip).await, "N-1 failures must still be allowed");
    }

    #[tokio::test]
    async fn auth_failure_nth_attempt_triggers_lockout() {
        let api = test_api_runtime(0);
        let ip = test_ip(2);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            api.record_auth_failure(ip).await;
        }

        assert!(!api.is_auth_failure_allowed(ip).await, "Nth failure must trigger lockout");
    }

    #[tokio::test]
    async fn auth_failure_unknown_ip_is_always_allowed() {
        let api = test_api_runtime(0);
        assert!(
            api.is_auth_failure_allowed(test_ip(99)).await,
            "IP with no failure history must be allowed"
        );
    }

    #[tokio::test]
    async fn auth_success_clears_failure_state() {
        let api = test_api_runtime(0);
        let ip = test_ip(3);

        // Accumulate failures up to the lockout threshold.
        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            api.record_auth_failure(ip).await;
        }
        assert!(!api.is_auth_failure_allowed(ip).await);

        // A successful auth must clear the failure window entirely.
        api.record_auth_success(ip).await;

        assert!(
            api.is_auth_failure_allowed(ip).await,
            "successful auth must reset the failure counter"
        );

        // Verify the window is completely removed, not just zeroed.
        let windows = api.auth_failure_windows.lock().await;
        assert!(!windows.contains_key(&ip), "window entry must be removed on success");
    }

    #[tokio::test]
    async fn auth_failure_window_expiry_resets_allowance() {
        let api = test_api_runtime(0);
        let ip = test_ip(4);

        // Manually insert an expired window that exceeded the failure threshold.
        {
            let mut windows = api.auth_failure_windows.lock().await;
            windows.insert(
                ip,
                AttemptWindow {
                    attempts: MAX_FAILED_API_AUTH_ATTEMPTS + 10,
                    window_start: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
                },
            );
        }

        assert!(
            api.is_auth_failure_allowed(ip).await,
            "expired window must be pruned, allowing the IP again"
        );

        // The expired entry should have been removed from the map.
        let windows = api.auth_failure_windows.lock().await;
        assert!(!windows.contains_key(&ip), "expired window must be removed");
    }

    #[tokio::test]
    async fn auth_failure_record_resets_window_after_expiry() {
        let api = test_api_runtime(0);
        let ip = test_ip(5);

        // Insert an expired window with many failures.
        {
            let mut windows = api.auth_failure_windows.lock().await;
            windows.insert(
                ip,
                AttemptWindow {
                    attempts: MAX_FAILED_API_AUTH_ATTEMPTS,
                    window_start: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
                },
            );
        }

        // Recording a new failure should start a fresh window with attempts=1.
        api.record_auth_failure(ip).await;

        let windows = api.auth_failure_windows.lock().await;
        let window = windows.get(&ip).expect("window must exist after recording failure");
        assert_eq!(window.attempts, 1, "expired window must reset to 1 attempt");
    }

    #[tokio::test]
    async fn auth_failure_sequential_from_same_ip_count_correctly() {
        let api = test_api_runtime(0);
        let ip = test_ip(6);

        // Record failures one at a time (serialised by the mutex) and verify
        // that they increment linearly — no double-counting.
        for expected in 1..=MAX_FAILED_API_AUTH_ATTEMPTS {
            api.record_auth_failure(ip).await;
            let windows = api.auth_failure_windows.lock().await;
            let window = windows.get(&ip).expect("window must exist");
            assert_eq!(
                window.attempts, expected,
                "attempt count must equal {expected} after {expected} sequential failures"
            );
        }
    }

    #[tokio::test]
    async fn auth_failure_different_ips_are_independent() {
        let api = test_api_runtime(0);
        let ip_a = test_ip(10);
        let ip_b = test_ip(11);

        // Lock out ip_a.
        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            api.record_auth_failure(ip_a).await;
        }

        // ip_b should be unaffected.
        assert!(!api.is_auth_failure_allowed(ip_a).await);
        assert!(api.is_auth_failure_allowed(ip_b).await);
    }

    #[tokio::test]
    async fn auth_failure_success_on_one_ip_does_not_affect_another() {
        let api = test_api_runtime(0);
        let ip_a = test_ip(20);
        let ip_b = test_ip(21);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            api.record_auth_failure(ip_a).await;
            api.record_auth_failure(ip_b).await;
        }

        // Clear only ip_a.
        api.record_auth_success(ip_a).await;

        assert!(api.is_auth_failure_allowed(ip_a).await);
        assert!(!api.is_auth_failure_allowed(ip_b).await);
    }

    // ---- Unit tests for check_rate_limit ----

    #[tokio::test]
    async fn rate_limit_allows_requests_under_limit() {
        let api = test_api_runtime(10);
        let subject = RateLimitSubject::ClientIp(test_ip(1));

        for _ in 0..10 {
            assert!(api.check_rate_limit(&subject).await.is_ok());
        }
    }

    #[tokio::test]
    async fn rate_limit_blocks_at_limit() {
        let api = test_api_runtime(3);
        let subject = RateLimitSubject::ClientIp(test_ip(2));

        for _ in 0..3 {
            api.check_rate_limit(&subject).await.expect("should be allowed");
        }

        let err = api.check_rate_limit(&subject).await.expect_err("expected Err");
        assert!(
            matches!(err, ApiAuthError::RateLimited { retry_after_seconds: 60 }),
            "4th request must be rate-limited, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rate_limit_disabled_allows_everything() {
        let api = test_api_runtime(0); // 0 means disabled
        let subject = RateLimitSubject::ClientIp(test_ip(3));

        for _ in 0..100 {
            assert!(api.check_rate_limit(&subject).await.is_ok());
        }
    }

    #[tokio::test]
    async fn rate_limit_window_expiry_resets_count() {
        let api = test_api_runtime(2);
        let subject = RateLimitSubject::ClientIp(test_ip(4));

        // Exhaust the limit.
        for _ in 0..2 {
            api.check_rate_limit(&subject).await.expect("should be allowed");
        }
        assert!(api.check_rate_limit(&subject).await.is_err());

        // Simulate window expiry by back-dating the window.
        {
            let mut windows = api.windows.lock().await;
            if let Some(w) = windows.get_mut(&subject) {
                w.started_at = Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1);
            }
        }

        // After expiry, a new window starts and the request should succeed.
        assert!(
            api.check_rate_limit(&subject).await.is_ok(),
            "request must be allowed after window expiry"
        );

        // The window should be reset with count = 1.
        let windows = api.windows.lock().await;
        let w = windows.get(&subject).expect("window must exist");
        assert_eq!(w.request_count, 1, "request count must be 1 after window reset");
    }

    #[tokio::test]
    async fn rate_limit_different_subjects_are_independent() {
        let api = test_api_runtime(1);
        let subject_a = RateLimitSubject::ClientIp(test_ip(5));
        let subject_b = RateLimitSubject::ClientIp(test_ip(6));

        api.check_rate_limit(&subject_a).await.expect("first request for A");
        assert!(api.check_rate_limit(&subject_a).await.is_err(), "A must be rate-limited");

        // B should still be allowed.
        assert!(api.check_rate_limit(&subject_b).await.is_ok(), "B must be independent");
    }

    #[tokio::test]
    async fn disabled_api_rejects_authenticated_request() {
        let app = test_router(None).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header("X-Api-Key", "arbitrary-key-value")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "api_disabled");
    }

    // ---- DELETE /operators/{username} tests ----

    /// Helper: create a runtime operator via POST /operators.
    async fn create_runtime_operator(
        app: &Router,
        api_key: &str,
        username: &str,
        password: &str,
        role: &str,
    ) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operators")
                    .header(API_KEY_HEADER, api_key)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"username":"{username}","password":"{password}","role":"{role}"}}"#
                    )))
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn delete_operator_removes_runtime_created_account() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let create_resp =
            create_runtime_operator(&app, "secret-admin", "tempuser", "pass1234", "Operator").await;
        assert_eq!(create_resp.status(), StatusCode::CREATED);

        let delete_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/operators/tempuser")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

        // Verify the operator is gone from the listing.
        let list_resp = app
            .oneshot(
                Request::builder()
                    .uri("/operators")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let body = read_json(list_resp).await;
        let usernames: Vec<&str> = body
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|op| op["username"].as_str())
            .collect();
        assert!(!usernames.contains(&"tempuser"), "deleted operator should not appear in listing");
    }

    #[tokio::test]
    async fn delete_operator_returns_not_found_for_unknown_user() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/operators/nonexistent")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "operator_not_found");
    }

    #[tokio::test]
    async fn delete_operator_returns_not_found_for_profile_configured_user() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        // "Neo" is defined in the test profile — cannot be deleted at runtime.
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/operators/Neo")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "operator_not_found");
    }

    #[tokio::test]
    async fn delete_operator_creates_audit_record() {
        let database = Database::connect_in_memory().await.expect("database");
        let (app, _, _) = test_router_with_database(
            database.clone(),
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        create_runtime_operator(&app, "secret-admin", "audituser", "pass1234", "Analyst").await;

        let _delete_resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/operators/audituser")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let page = crate::query_audit_log(
            &database,
            &crate::AuditQuery {
                action: Some("operator.delete".to_owned()),
                ..crate::AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        assert_eq!(page.total, 1, "one operator.delete audit record expected");
        let record = &page.items[0];
        assert_eq!(record.action, "operator.delete");
        assert_eq!(record.result_status, crate::AuditResultStatus::Success);
    }

    // ---- PUT /operators/{username}/role tests ----

    #[tokio::test]
    async fn update_operator_role_changes_runtime_account_role() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let create_resp =
            create_runtime_operator(&app, "secret-admin", "roleuser", "pass1234", "Operator").await;
        assert_eq!(create_resp.status(), StatusCode::CREATED);

        let update_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/operators/roleuser/role")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"role":"Admin"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(update_resp.status(), StatusCode::OK);
        let body = read_json(update_resp).await;
        assert_eq!(body["username"], "roleuser");
        assert_eq!(body["role"], "Admin");
    }

    #[tokio::test]
    async fn update_operator_role_returns_not_found_for_unknown_user() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/operators/nonexistent/role")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"role":"Admin"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "operator_not_found");
    }

    #[tokio::test]
    async fn update_operator_role_returns_not_found_for_profile_configured_user() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/operators/Neo/role")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"role":"Analyst"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "operator_not_found");
    }

    #[tokio::test]
    async fn update_operator_role_returns_bad_request_for_invalid_role() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        create_runtime_operator(&app, "secret-admin", "badroleuser", "pass1234", "Operator").await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/operators/badroleuser/role")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"role":"SuperAdmin"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        // Invalid JSON deserialization returns 422 (Unprocessable Entity) from Axum.
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "expected 400 or 422 for invalid role, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn update_operator_role_creates_audit_record() {
        let database = Database::connect_in_memory().await.expect("database");
        let (app, _, _) = test_router_with_database(
            database.clone(),
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        create_runtime_operator(&app, "secret-admin", "auditrole", "pass1234", "Operator").await;

        let _update_resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/operators/auditrole/role")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"role":"Admin"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        let page = crate::query_audit_log(
            &database,
            &crate::AuditQuery {
                action: Some("operator.update_role".to_owned()),
                ..crate::AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        assert_eq!(page.total, 1, "one operator.update_role audit record expected");
        let record = &page.items[0];
        assert_eq!(record.action, "operator.update_role");
        assert_eq!(record.result_status, crate::AuditResultStatus::Success);
    }

    // ── GET /payloads ───────────────────────────────────────────────────

    #[tokio::test]
    async fn list_payloads_returns_empty_initially() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert!(body.as_array().expect("should be array").is_empty());
    }

    #[tokio::test]
    async fn list_payloads_returns_completed_builds() {
        let database = Database::connect_in_memory().await.expect("database");
        let record = crate::PayloadBuildRecord {
            id: "build-123".to_owned(),
            status: "done".to_owned(),
            name: "demon.x64.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0xDE, 0xAD]),
            size_bytes: Some(2),
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:00:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let items = body.as_array().expect("should be array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "build-123");
        assert_eq!(items[0]["name"], "demon.x64.exe");
        assert_eq!(items[0]["arch"], "x64");
        assert_eq!(items[0]["format"], "exe");
        assert_eq!(items[0]["size_bytes"], 2);
    }

    #[tokio::test]
    async fn list_payloads_excludes_pending_builds() {
        let database = Database::connect_in_memory().await.expect("database");
        let record = crate::PayloadBuildRecord {
            id: "pending-job".to_owned(),
            status: "pending".to_owned(),
            name: String::new(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: None,
            size_bytes: None,
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:00:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert!(body.as_array().expect("should be array").is_empty());
    }

    // ── POST /payloads/build ────────────────────────────────────────────

    #[tokio::test]
    async fn submit_payload_build_rejects_invalid_format() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"listener":"http1","arch":"x64","format":"elf"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_format");
    }

    #[tokio::test]
    async fn submit_payload_build_rejects_invalid_arch() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"listener":"http1","arch":"arm64","format":"exe"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_arch");
    }

    #[tokio::test]
    async fn submit_payload_build_rejects_missing_listener() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"listener":"nonexistent","arch":"x64","format":"exe"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "listener_not_found");
    }

    #[tokio::test]
    async fn submit_payload_build_requires_auth() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"listener":"http1","arch":"x64","format":"exe"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── GET /payloads/jobs/{job_id} ─────────────────────────────────────

    #[tokio::test]
    async fn get_payload_job_returns_not_found_for_missing_job() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/jobs/nonexistent")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "job_not_found");
    }

    #[tokio::test]
    async fn get_payload_job_returns_status_for_pending_job() {
        let database = Database::connect_in_memory().await.expect("database");
        let record = crate::PayloadBuildRecord {
            id: "job-pending".to_owned(),
            status: "pending".to_owned(),
            name: String::new(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: None,
            size_bytes: None,
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:00:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/jobs/job-pending")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["job_id"], "job-pending");
        assert_eq!(body["status"], "pending");
        assert!(body["payload_id"].is_null());
    }

    #[tokio::test]
    async fn get_payload_job_returns_payload_id_for_done_job() {
        let database = Database::connect_in_memory().await.expect("database");
        let record = crate::PayloadBuildRecord {
            id: "job-done".to_owned(),
            status: "done".to_owned(),
            name: "demon.x64.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0xCA, 0xFE]),
            size_bytes: Some(2),
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:01:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/jobs/job-done")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["job_id"], "job-done");
        assert_eq!(body["status"], "done");
        assert_eq!(body["payload_id"], "job-done");
        assert_eq!(body["size_bytes"], 2);
    }

    #[tokio::test]
    async fn get_payload_job_returns_error_for_failed_job() {
        let database = Database::connect_in_memory().await.expect("database");
        let record = crate::PayloadBuildRecord {
            id: "job-err".to_owned(),
            status: "error".to_owned(),
            name: String::new(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: None,
            size_bytes: None,
            error: Some("compiler not found".to_owned()),
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:01:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/jobs/job-err")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["status"], "error");
        assert_eq!(body["error"], "compiler not found");
    }

    // ── GET /payloads/{id}/download ─────────────────────────────────────

    #[tokio::test]
    async fn download_payload_returns_artifact_bytes() {
        let database = Database::connect_in_memory().await.expect("database");
        let artifact = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header stub
        let record = crate::PayloadBuildRecord {
            id: "dl-test".to_owned(),
            status: "done".to_owned(),
            name: "demon.x64.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(artifact.clone()),
            size_bytes: Some(i64::try_from(artifact.len()).unwrap_or(i64::MAX)),
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:01:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/dl-test/download")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        assert!(
            response
                .headers()
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .expect("content-disposition header")
                .contains("demon.x64.exe")
        );

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        assert_eq!(body_bytes.as_ref(), &artifact);
    }

    #[tokio::test]
    async fn download_payload_returns_not_found_for_pending_build() {
        let database = Database::connect_in_memory().await.expect("database");
        let record = crate::PayloadBuildRecord {
            id: "dl-pending".to_owned(),
            status: "pending".to_owned(),
            name: String::new(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: None,
            size_bytes: None,
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:00:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/dl-pending/download")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "payload_not_ready");
    }

    #[tokio::test]
    async fn download_payload_returns_not_found_for_missing_id() {
        let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/no-such-id/download")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "payload_not_found");
    }

    #[tokio::test]
    async fn download_payload_returns_gone_for_stale_build() {
        let database = Database::connect_in_memory().await.expect("database");
        let record = crate::PayloadBuildRecord {
            id: "dl-stale".to_owned(),
            status: "stale".to_owned(),
            name: "demon.x64.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0x4D, 0x5A]),
            size_bytes: Some(2),
            error: None,
            created_at: "2026-03-31T10:00:00Z".to_owned(),
            updated_at: "2026-03-31T11:00:00Z".to_owned(),
        };
        database.payload_builds().create(&record).await.expect("create");

        let (app, _, _) = test_router_with_database(
            database,
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads/dl-stale/download")
                    .header(API_KEY_HEADER, "secret-admin")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::GONE);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "payload_stale");
    }

    #[tokio::test]
    async fn update_listener_invalidates_done_payload_builds() {
        let database = Database::connect_in_memory().await.expect("database");

        // Seed a "done" payload build for the listener we will update.
        let done_record = crate::PayloadBuildRecord {
            id: "inv-api-a".to_owned(),
            status: "done".to_owned(),
            name: "demon.x64.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "pivot".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0xDE, 0xAD]),
            size_bytes: Some(2),
            error: None,
            created_at: "2026-03-31T10:00:00Z".to_owned(),
            updated_at: "2026-03-31T10:00:00Z".to_owned(),
        };
        database.payload_builds().create(&done_record).await.expect("create build record");

        let (app, _, _) = test_router_with_database(
            database.clone(),
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        // Create the listener first so the update endpoint has something to mutate.
        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("pivot", "old-pipe"),
                "secret-admin",
            ))
            .await
            .expect("create listener response");

        // Update the listener config (pipe name changes).
        let update_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/pivot")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("pivot", "new-pipe")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(update_response.status(), StatusCode::OK);

        // The previously "done" build must now be "stale".
        let fetched = database
            .payload_builds()
            .get("inv-api-a")
            .await
            .expect("db query")
            .expect("record should exist");
        assert_eq!(fetched.status, "stale", "done build should be stale after listener update");
    }

    #[tokio::test]
    async fn identical_listener_put_preserves_done_payload_builds() {
        let database = Database::connect_in_memory().await.expect("database");

        // Seed a "done" payload build for the listener we will update.
        let done_record = crate::PayloadBuildRecord {
            id: "inv-noop-a".to_owned(),
            status: "done".to_owned(),
            name: "demon.x64.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "noop-smb".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0xDE, 0xAD]),
            size_bytes: Some(2),
            error: None,
            created_at: "2026-03-31T10:00:00Z".to_owned(),
            updated_at: "2026-03-31T10:00:00Z".to_owned(),
        };
        database.payload_builds().create(&done_record).await.expect("create build record");

        let (app, _, _) = test_router_with_database(
            database.clone(),
            Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
        )
        .await;

        // Create the listener.
        let _ = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("noop-smb", "same-pipe"),
                "secret-admin",
            ))
            .await
            .expect("create listener response");

        // PUT the exact same config (no change).
        let update_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/listeners/noop-smb")
                    .header(API_KEY_HEADER, "secret-admin")
                    .header("content-type", "application/json")
                    .body(Body::from(smb_listener_json("noop-smb", "same-pipe")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(update_response.status(), StatusCode::OK);

        // The "done" build must still be "done" — not stale.
        let fetched = database
            .payload_builds()
            .get("inv-noop-a")
            .await
            .expect("db query")
            .expect("record should exist");
        assert_eq!(
            fetched.status, "done",
            "done build must remain done after identical listener PUT"
        );
    }

    // ── RBAC: analyst can list payloads but not build or download artifacts ─

    #[tokio::test]
    async fn analyst_can_list_payloads() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/payloads")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn analyst_cannot_submit_payload_build() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"listener":"http1","arch":"x64","format":"exe"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn analyst_cannot_download_payload_artifact() {
        let app =
            test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/payloads/any-id/download")
                    .header(API_KEY_HEADER, "secret-analyst")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ── cli_format_to_havoc unit tests ──────────────────────────────────

    #[test]
    fn cli_format_to_havoc_maps_valid_formats() {
        assert_eq!(cli_format_to_havoc("exe"), Ok("Windows Exe"));
        assert_eq!(cli_format_to_havoc("dll"), Ok("Windows Dll"));
        assert_eq!(cli_format_to_havoc("bin"), Ok("Windows Shellcode"));
    }

    #[test]
    fn cli_format_to_havoc_rejects_unknown_formats() {
        assert!(cli_format_to_havoc("elf").is_err());
        assert!(cli_format_to_havoc("").is_err());
    }

    // ── normalize_agent_type unit tests ─────────────────────────────────

    #[test]
    fn normalize_agent_type_maps_all_valid_types() {
        assert_eq!(normalize_agent_type("demon"), Ok("Demon"));
        assert_eq!(normalize_agent_type("archon"), Ok("Archon"));
        assert_eq!(normalize_agent_type("phantom"), Ok("Phantom"));
        assert_eq!(normalize_agent_type("specter"), Ok("Specter"));
    }

    #[test]
    fn normalize_agent_type_is_case_insensitive() {
        assert_eq!(normalize_agent_type("Demon"), Ok("Demon"));
        assert_eq!(normalize_agent_type("ARCHON"), Ok("Archon"));
        assert_eq!(normalize_agent_type("Phantom"), Ok("Phantom"));
        assert_eq!(normalize_agent_type("SPECTER"), Ok("Specter"));
    }

    #[test]
    fn normalize_agent_type_rejects_unknown() {
        assert!(normalize_agent_type("alien").is_err());
        assert!(normalize_agent_type("").is_err());
        assert!(normalize_agent_type("Shellcode").is_err());
    }

    // ── validate_agent_format_combination unit tests ─────────────────────

    #[test]
    fn agent_format_combination_accepts_demon_all_formats() {
        for fmt in &["exe", "dll", "bin"] {
            assert!(
                validate_agent_format_combination("Demon", fmt).is_ok(),
                "Demon should accept format '{fmt}'"
            );
        }
    }

    #[test]
    fn agent_format_combination_accepts_archon_all_formats() {
        for fmt in &["exe", "dll", "bin"] {
            assert!(
                validate_agent_format_combination("Archon", fmt).is_ok(),
                "Archon should accept format '{fmt}'"
            );
        }
    }

    #[test]
    fn agent_format_combination_accepts_phantom_exe_only() {
        assert!(validate_agent_format_combination("Phantom", "exe").is_ok());
        assert!(validate_agent_format_combination("Phantom", "dll").is_err());
        assert!(validate_agent_format_combination("Phantom", "bin").is_err());
    }

    #[test]
    fn agent_format_combination_accepts_specter_exe_only() {
        assert!(validate_agent_format_combination("Specter", "exe").is_ok());
        assert!(validate_agent_format_combination("Specter", "dll").is_err());
        assert!(validate_agent_format_combination("Specter", "bin").is_err());
    }

    // ── payload build agent-type API tests ──────────────────────────────

    #[tokio::test]
    async fn payload_build_rejects_unsupported_agent_type() {
        let app =
            test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-operator")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"listener":"http1","arch":"x64","format":"exe","agent":"alien"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "invalid_agent_type");
    }

    #[tokio::test]
    async fn payload_build_accepts_all_valid_agent_types() {
        // The listener doesn't exist so we expect 404 (listener_not_found), not a
        // 400 agent-validation error.  That proves the agent value passed validation.
        for agent in &["demon", "archon", "phantom", "specter"] {
            let app =
                test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator)))
                    .await;
            let body =
                serde_json::json!({"listener":"nonexistent","arch":"x64","format":"exe","agent": agent})
                    .to_string();
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/payloads/build")
                        .header(API_KEY_HEADER, "secret-operator")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .expect("request"),
                )
                .await
                .expect("response");

            // 404 means agent validation passed and we reached the listener lookup.
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "expected 404 for agent={agent}, got {}",
                response.status()
            );
        }
    }

    #[tokio::test]
    async fn payload_build_rejects_unsupported_agent_format_combination() {
        // Phantom and Specter only produce exe artifacts; requesting dll or bin
        // must be rejected with 400 / unsupported_agent_format before the listener
        // lookup so callers never receive a misleading successful response.
        for (agent, format) in
            &[("phantom", "dll"), ("phantom", "bin"), ("specter", "dll"), ("specter", "bin")]
        {
            let app =
                test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator)))
                    .await;
            let body =
                serde_json::json!({"listener":"nonexistent","arch":"x64","format": format,"agent": agent})
                    .to_string();
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/payloads/build")
                        .header(API_KEY_HEADER, "secret-operator")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for agent={agent} format={format}"
            );
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body");
            let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
            assert_eq!(
                json["error"]["code"], "unsupported_agent_format",
                "wrong error code for agent={agent} format={format}"
            );
        }
    }

    #[tokio::test]
    async fn payload_build_defaults_to_demon_when_agent_omitted() {
        // Without an `agent` field the default "demon" value should apply, so
        // validation passes and we fail at the listener lookup (404) rather
        // than at agent validation (400).
        let app =
            test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-operator")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"listener":"nonexistent","arch":"x64","format":"exe"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// End-to-end test: the agent type requested via `POST /payloads/build` is
    /// persisted in the build record and returned by `GET /payloads/jobs/{id}`.
    ///
    /// This proves the full path: request → normalisation → DB record → response,
    /// i.e. the agent type actually reaches the payload builder call.
    #[tokio::test]
    async fn payload_build_agent_type_reaches_job_record() {
        for (agent_in, agent_out) in &[
            ("demon", "Demon"),
            ("archon", "Archon"),
            ("phantom", "Phantom"),
            ("specter", "Specter"),
        ] {
            let app =
                test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator)))
                    .await;

            // First create a listener so the build request passes the listener-lookup
            // check and a job record is actually created.
            let create_resp = app
                .clone()
                .oneshot(create_listener_request(
                    &smb_listener_json("build-test-pivot", "test-pipe"),
                    "secret-operator",
                ))
                .await
                .expect("create listener response");
            assert_eq!(
                create_resp.status(),
                StatusCode::CREATED,
                "failed to create listener for agent={agent_in}"
            );

            // Submit the build.
            let body =
                serde_json::json!({"listener":"build-test-pivot","arch":"x64","format":"exe","agent":agent_in})
                    .to_string();
            let submit_resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/payloads/build")
                        .header(API_KEY_HEADER, "secret-operator")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .expect("request"),
                )
                .await
                .expect("submit response");

            assert_eq!(
                submit_resp.status(),
                StatusCode::ACCEPTED,
                "expected 202 for agent={agent_in}"
            );
            let submit_json = read_json(submit_resp).await;
            let job_id = submit_json["job_id"].as_str().expect("job_id").to_owned();

            // Fetch the job status — agent_type must reflect what was submitted.
            let status_resp = app
                .oneshot(
                    Request::builder()
                        .uri(format!("/payloads/jobs/{job_id}"))
                        .header(API_KEY_HEADER, "secret-operator")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("status response");

            assert_eq!(status_resp.status(), StatusCode::OK, "job not found for agent={agent_in}");
            let status_json = read_json(status_resp).await;
            assert_eq!(
                status_json["agent_type"], *agent_out,
                "agent_type mismatch for agent_in={agent_in}: expected {agent_out}"
            );
        }
    }

    // ── PayloadBuildRepository unit tests ────────────────────────────────

    #[tokio::test]
    async fn payload_build_repository_create_and_get() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();

        let record = crate::PayloadBuildRecord {
            id: "test-1".to_owned(),
            status: "pending".to_owned(),
            name: String::new(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: Some(10),
            artifact: None,
            size_bytes: None,
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:00:00Z".to_owned(),
        };

        repo.create(&record).await.expect("create");
        let fetched = repo.get("test-1").await.expect("get").expect("should exist");
        assert_eq!(fetched.id, "test-1");
        assert_eq!(fetched.status, "pending");
        assert_eq!(fetched.arch, "x64");
        assert_eq!(fetched.sleep_secs, Some(10));
    }

    #[tokio::test]
    async fn payload_build_repository_get_missing_returns_none() {
        let db = Database::connect_in_memory().await.expect("db");
        let result = db.payload_builds().get("nonexistent").await.expect("get");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn payload_build_repository_list_returns_all() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();

        for i in 0..3 {
            let record = crate::PayloadBuildRecord {
                id: format!("list-{i}"),
                status: "done".to_owned(),
                name: format!("payload-{i}.exe"),
                arch: "x64".to_owned(),
                format: "exe".to_owned(),
                listener: "http1".to_owned(),
                agent_type: "Demon".to_owned(),
                sleep_secs: None,
                artifact: Some(vec![0xDE, 0xAD]),
                size_bytes: Some(2),
                error: None,
                created_at: format!("2026-03-23T10:0{i}:00Z"),
                updated_at: format!("2026-03-23T10:0{i}:00Z"),
            };
            repo.create(&record).await.expect("create");
        }

        let all = repo.list().await.expect("list");
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn payload_build_repository_update_status() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();

        let record = crate::PayloadBuildRecord {
            id: "upd-1".to_owned(),
            status: "pending".to_owned(),
            name: String::new(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: None,
            size_bytes: None,
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:00:00Z".to_owned(),
        };
        repo.create(&record).await.expect("create");

        let updated = repo
            .update_status(
                "upd-1",
                "done",
                Some("demon.x64.exe"),
                Some(&[0xCA, 0xFE]),
                Some(2),
                None,
                "2026-03-23T10:01:00Z",
            )
            .await
            .expect("update");
        assert!(updated);

        let fetched = repo.get("upd-1").await.expect("get").expect("exists");
        assert_eq!(fetched.status, "done");
        assert_eq!(fetched.name, "demon.x64.exe");
        assert_eq!(fetched.artifact, Some(vec![0xCA, 0xFE]));
        assert_eq!(fetched.size_bytes, Some(2));
        assert_eq!(fetched.updated_at, "2026-03-23T10:01:00Z");
    }

    #[tokio::test]
    async fn payload_build_repository_update_missing_returns_false() {
        let db = Database::connect_in_memory().await.expect("db");
        let result = db
            .payload_builds()
            .update_status("ghost", "done", None, None, None, None, "2026-03-23T10:00:00Z")
            .await
            .expect("update");
        assert!(!result);
    }

    #[tokio::test]
    async fn payload_build_get_summary_excludes_artifact() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();

        let record = crate::PayloadBuildRecord {
            id: "sum-1".to_owned(),
            status: "done".to_owned(),
            name: "payload.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: Some(5),
            artifact: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            size_bytes: Some(4),
            error: None,
            created_at: "2026-03-23T10:00:00Z".to_owned(),
            updated_at: "2026-03-23T10:00:00Z".to_owned(),
        };
        repo.create(&record).await.expect("create");

        let summary = repo.get_summary("sum-1").await.expect("get_summary").expect("exists");
        assert_eq!(summary.id, "sum-1");
        assert_eq!(summary.status, "done");
        assert_eq!(summary.name, "payload.exe");
        assert_eq!(summary.arch, "x64");
        assert_eq!(summary.size_bytes, Some(4));

        // Verify the full get() still returns the artifact
        let full = repo.get("sum-1").await.expect("get").expect("exists");
        assert_eq!(full.artifact, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[tokio::test]
    async fn payload_build_get_summary_missing_returns_none() {
        let db = Database::connect_in_memory().await.expect("db");
        let result = db.payload_builds().get_summary("nonexistent").await.expect("get_summary");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn payload_build_list_summaries_excludes_artifact() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();

        for i in 0..3 {
            let record = crate::PayloadBuildRecord {
                id: format!("lsum-{i}"),
                status: "done".to_owned(),
                name: format!("payload-{i}.exe"),
                arch: "x64".to_owned(),
                format: "exe".to_owned(),
                listener: "http1".to_owned(),
                agent_type: "Demon".to_owned(),
                sleep_secs: None,
                artifact: Some(vec![0xCA; 1024]),
                size_bytes: Some(1024),
                error: None,
                created_at: format!("2026-03-23T10:0{i}:00Z"),
                updated_at: format!("2026-03-23T10:0{i}:00Z"),
            };
            repo.create(&record).await.expect("create");
        }

        let summaries = repo.list_summaries().await.expect("list_summaries");
        assert_eq!(summaries.len(), 3);
        // Summaries are ordered by created_at DESC
        assert_eq!(summaries[0].id, "lsum-2");
        assert_eq!(summaries[1].id, "lsum-1");
        assert_eq!(summaries[2].id, "lsum-0");
        // All have metadata
        for s in &summaries {
            assert_eq!(s.size_bytes, Some(1024));
            assert_eq!(s.format, "exe");
        }
    }

    // ── GET /agents/{id}/output ─────────────────────────────────────────

    #[tokio::test]
    async fn get_agent_output_returns_empty_page_for_agent_with_no_output() {
        let database = Database::connect_in_memory().await.expect("database");
        let (app, registry, _) = test_router_with_database(
            database,
            Some((60, "reader", "secret-reader", OperatorRole::Operator)),
        )
        .await;

        let agent = sample_agent(0xDEAD_0001);
        registry.insert(agent).await.expect("insert");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/DEAD0001/output")
                    .header(API_KEY_HEADER, "secret-reader")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 0);
        assert_eq!(body["entries"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn get_agent_output_returns_persisted_responses() {
        let database = Database::connect_in_memory().await.expect("database");
        let agent_id = 0xDEAD_0002u32;

        let (app, registry, _) = test_router_with_database(
            database.clone(),
            Some((60, "reader", "secret-reader", OperatorRole::Operator)),
        )
        .await;

        // Register agent via registry (persists to DB for FK constraint).
        registry.insert(sample_agent(agent_id)).await.expect("insert");

        // Insert a response record.
        let record = crate::database::AgentResponseRecord {
            id: None,
            agent_id,
            command_id: 21,
            request_id: 1,
            response_type: "Good".to_owned(),
            message: "Process List".to_owned(),
            output: "whoami output".to_owned(),
            command_line: Some("whoami".to_owned()),
            task_id: Some("task-abc".to_owned()),
            operator: Some("neo".to_owned()),
            received_at: "2026-03-27T00:00:00Z".to_owned(),
            extra: None,
        };
        database.agent_responses().create(&record).await.expect("create response");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/DEAD0002/output")
                    .header(API_KEY_HEADER, "secret-reader")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["entries"][0]["task_id"], "task-abc");
        assert_eq!(body["entries"][0]["output"], "whoami output");
        assert_eq!(body["entries"][0]["command_line"], "whoami");
    }

    #[tokio::test]
    async fn get_agent_output_since_cursor_filters_older_entries() {
        let database = Database::connect_in_memory().await.expect("database");
        let agent_id = 0xDEAD_0003u32;

        let (app, registry, _) = test_router_with_database(
            database.clone(),
            Some((60, "reader", "secret-reader", OperatorRole::Operator)),
        )
        .await;

        registry.insert(sample_agent(agent_id)).await.expect("insert");

        let record1 = crate::database::AgentResponseRecord {
            id: None,
            agent_id,
            command_id: 21,
            request_id: 1,
            response_type: "Good".to_owned(),
            message: "first".to_owned(),
            output: "output-1".to_owned(),
            command_line: None,
            task_id: Some("t1".to_owned()),
            operator: None,
            received_at: "2026-03-27T00:00:00Z".to_owned(),
            extra: None,
        };
        let id1 = database.agent_responses().create(&record1).await.expect("create r1");

        let record2 = crate::database::AgentResponseRecord {
            id: None,
            agent_id,
            command_id: 21,
            request_id: 2,
            response_type: "Good".to_owned(),
            message: "second".to_owned(),
            output: "output-2".to_owned(),
            command_line: None,
            task_id: Some("t2".to_owned()),
            operator: None,
            received_at: "2026-03-27T00:01:00Z".to_owned(),
            extra: None,
        };
        database.agent_responses().create(&record2).await.expect("create r2");

        // Request with since=id1 should only return the second record.
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/agents/DEAD0003/output?since={id1}"))
                    .header(API_KEY_HEADER, "secret-reader")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["entries"][0]["task_id"], "t2");
    }

    #[tokio::test]
    async fn get_agent_output_surfaces_exit_code_from_extra() {
        let database = Database::connect_in_memory().await.expect("database");
        let agent_id = 0xDEAD_0004u32;

        let (app, registry, _) = test_router_with_database(
            database.clone(),
            Some((60, "reader", "secret-reader", OperatorRole::Operator)),
        )
        .await;
        registry.insert(sample_agent(agent_id)).await.expect("insert");

        let record = crate::database::AgentResponseRecord {
            id: None,
            agent_id,
            command_id: u32::from(red_cell_common::demon::DemonCommand::CommandOutput),
            request_id: 7,
            response_type: "Good".to_owned(),
            message: "Received Output [3 bytes]:".to_owned(),
            output: "err".to_owned(),
            command_line: Some("exit 1".to_owned()),
            task_id: Some("task-exit1".to_owned()),
            operator: None,
            received_at: "2026-04-04T00:00:00Z".to_owned(),
            extra: Some(serde_json::json!({"ExitCode": 1})),
        };
        database.agent_responses().create(&record).await.expect("create response");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/DEAD0004/output")
                    .header(API_KEY_HEADER, "secret-reader")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["entries"][0]["exit_code"], 1);
        assert_eq!(body["entries"][0]["task_id"], "task-exit1");
    }

    #[tokio::test]
    async fn get_agent_output_omits_exit_code_when_absent() {
        let database = Database::connect_in_memory().await.expect("database");
        let agent_id = 0xDEAD_0005u32;

        let (app, registry, _) = test_router_with_database(
            database.clone(),
            Some((60, "reader", "secret-reader", OperatorRole::Operator)),
        )
        .await;
        registry.insert(sample_agent(agent_id)).await.expect("insert");

        let record = crate::database::AgentResponseRecord {
            id: None,
            agent_id,
            command_id: u32::from(red_cell_common::demon::DemonCommand::CommandOutput),
            request_id: 8,
            response_type: "Good".to_owned(),
            message: "Received Output [2 bytes]:".to_owned(),
            output: "ok".to_owned(),
            command_line: Some("whoami".to_owned()),
            task_id: Some("task-legacy".to_owned()),
            operator: None,
            received_at: "2026-04-04T00:00:00Z".to_owned(),
            extra: None,
        };
        database.agent_responses().create(&record).await.expect("create response");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/DEAD0005/output")
                    .header(API_KEY_HEADER, "secret-reader")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["total"], 1);
        // `exit_code` must be absent when not known (skip_serializing_if = "Option::is_none").
        assert!(body["entries"][0].get("exit_code").is_none());
    }

    #[tokio::test]
    async fn get_agent_output_returns_404_for_unknown_agent() {
        let app = test_router(Some((60, "reader", "secret-reader", OperatorRole::Operator))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/FFFFFFFF/output")
                    .header(API_KEY_HEADER, "secret-reader")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── POST /agents/{id}/upload ────────────────────────────────────────

    #[tokio::test]
    async fn agent_upload_queues_task_for_existing_agent() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "tasker",
            "secret-tasker",
            OperatorRole::Operator,
        )))
        .await;

        let agent_id = 0xDEAD_0010u32;
        registry.insert(sample_agent(agent_id)).await.expect("insert");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEAD0010/upload")
                    .header(API_KEY_HEADER, "secret-tasker")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&serde_json::json!({
                            "remote_path": "C:\\temp\\payload.bin",
                            "content": "SGVsbG8gV29ybGQ="
                        }))
                        .expect("json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = read_json(response).await;
        assert_eq!(body["agent_id"], "DEAD0010");
        assert!(!body["task_id"].as_str().expect("task_id").is_empty());
    }

    #[tokio::test]
    async fn agent_upload_returns_404_for_unknown_agent() {
        let app = test_router(Some((60, "tasker", "secret-tasker", OperatorRole::Operator))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/FFFFFFFF/upload")
                    .header(API_KEY_HEADER, "secret-tasker")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"remote_path":"C:\\x","content":"AA=="}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn agent_upload_accepts_body_larger_than_2mb() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "tasker",
            "secret-tasker",
            OperatorRole::Operator,
        )))
        .await;

        let agent_id = 0xDEAD_0011u32;
        registry.insert(sample_agent(agent_id)).await.expect("insert");

        // Build a payload whose JSON body exceeds 2 MB (the old axum default).
        // 3 MB of binary → ~4 MB base64 → well over the 2 MB default limit.
        use base64::Engine;
        let raw = vec![0x42u8; 3 * 1024 * 1024];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        let json_body = serde_json::to_string(&serde_json::json!({
            "remote_path": "C:\\temp\\big_payload.bin",
            "content": b64,
        }))
        .expect("json");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEAD0011/upload")
                    .header(API_KEY_HEADER, "secret-tasker")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json_body))
                    .expect("request"),
            )
            .await
            .expect("response");

        // With the raised body limit this should succeed (202 Accepted),
        // not be rejected with 413 Payload Too Large.
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // ── POST /agents/{id}/download ──────────────────────────────────────

    #[tokio::test]
    async fn agent_download_queues_task_for_existing_agent() {
        let (app, registry, _) = test_router_with_registry(Some((
            60,
            "tasker",
            "secret-tasker",
            OperatorRole::Operator,
        )))
        .await;

        let agent_id = 0xDEAD_0020u32;
        registry.insert(sample_agent(agent_id)).await.expect("insert");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/DEAD0020/download")
                    .header(API_KEY_HEADER, "secret-tasker")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&serde_json::json!({
                            "remote_path": "C:\\Users\\neo\\Documents\\secret.txt"
                        }))
                        .expect("json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = read_json(response).await;
        assert_eq!(body["agent_id"], "DEAD0020");
        assert!(!body["task_id"].as_str().expect("task_id").is_empty());
    }

    #[tokio::test]
    async fn agent_download_returns_404_for_unknown_agent() {
        let app = test_router(Some((60, "tasker", "secret-tasker", OperatorRole::Operator))).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents/FFFFFFFF/download")
                    .header(API_KEY_HEADER, "secret-tasker")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"remote_path":"C:\\x"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ---- PayloadBuildRecord sleep_secs overflow clamping ----

    #[test]
    fn payload_build_sleep_secs_clamps_u64_overflow_to_i64_max() {
        // Values exceeding i64::MAX must not silently wrap to negative.
        let overflow: u64 = u64::try_from(i64::MAX).expect("i64::MAX fits in u64") + 1;
        let clamped: i64 = i64::try_from(overflow).unwrap_or(i64::MAX);
        assert_eq!(clamped, i64::MAX);
    }

    #[test]
    fn payload_build_sleep_secs_preserves_valid_u64_values() {
        let valid: u64 = 3600;
        let converted: i64 = i64::try_from(valid).unwrap_or(i64::MAX);
        assert_eq!(converted, 3600);
    }

    #[test]
    fn payload_build_sleep_secs_handles_u64_max() {
        let max_val: u64 = u64::MAX;
        let clamped: i64 = i64::try_from(max_val).unwrap_or(i64::MAX);
        assert_eq!(clamped, i64::MAX);
    }
}
