//! OpenAPI / Swagger documentation setup and API root endpoint.

use axum::Json;
use axum::extract::State;
use red_cell_common::ListenerConfig;
use serde::Serialize;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

use super::auth::API_KEY_HEADER;
use super::auth::ApiRuntime;
use super::{API_PREFIX, API_VERSION, DOCS_PATH, OPENAPI_PATH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct ApiInfoResponse {
    version: String,
    prefix: String,
    openapi_path: String,
    documentation_path: String,
    authentication_header: String,
    enabled: bool,
    rate_limit_per_minute: Option<u32>,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        api_root,
        super::health::get_health,
        super::agents::list_agents,
        super::agents::get_agent,
        super::agents::kill_agent,
        super::agents::queue_agent_task,
        super::agents::get_agent_output,
        super::agents::agent_upload,
        super::agents::agent_download,
        super::audit::list_audit,
        super::audit::list_session_activity,
        super::loot::list_credentials,
        super::loot::get_credential,
        super::loot::list_jobs,
        super::loot::get_job,
        super::loot::list_loot,
        super::loot::get_loot,
        super::operators::list_operators,
        super::operators::create_operator,
        super::operators::delete_operator,
        super::operators::update_operator_role,
        super::listeners::list_listeners,
        super::listeners::create_listener,
        super::listeners::get_listener,
        super::listeners::update_listener,
        super::listeners::delete_listener,
        super::listeners::start_listener,
        super::listeners::stop_listener,
        super::listeners::mark_listener,
        super::listeners::reload_listener_tls_cert,
        super::payload::get_webhook_stats,
        super::payload::list_payloads,
        super::payload::submit_payload_build,
        super::payload::get_payload_job,
        super::payload::download_payload,
        super::payload::flush_payload_cache
    ),
    components(
        schemas(
            super::errors::ApiErrorBody,
            super::errors::ApiErrorDetail,
            ApiInfoResponse,
            super::health::HealthResponse,
            super::health::HealthAgentCounts,
            super::health::HealthListenerCounts,
            super::health::HealthPluginCounts,
            super::health::HealthPluginEntry,
            super::payload::WebhookStats,
            super::payload::DiscordWebhookStats,
            super::payload::FlushPayloadCacheResponse,
            super::payload::PayloadSummary,
            super::payload::PayloadBuildRequest,
            super::payload::PayloadBuildSubmitResponse,
            super::payload::PayloadJobStatus,
            super::agents::AgentTaskQueuedResponse,
            super::agents::AgentOutputEntry,
            super::agents::AgentOutputPage,
            super::agents::AgentUploadRequest,
            super::agents::AgentDownloadRequest,
            super::agents::ApiAgentInfo,
            super::agents::AgentGroupsResponse,
            super::agents::SetAgentGroupsRequest,
            crate::AuditPage,
            crate::SessionActivityPage,
            super::loot::CredentialPage,
            super::loot::CredentialSummary,
            super::loot::JobPage,
            super::loot::JobSummary,
            super::loot::LootPage,
            super::loot::LootSummary,
            super::operators::OperatorSummary,
            super::operators::CreateOperatorRequest,
            super::operators::CreatedOperatorResponse,
            super::operators::UpdateOperatorRoleRequest,
            super::operators::OperatorGroupAccessResponse,
            super::operators::SetOperatorGroupAccessRequest,
            super::operators::ListenerAccessResponse,
            super::operators::SetListenerAccessRequest,
            crate::AuditRecord,
            crate::AuditResultStatus,
            crate::SessionActivityRecord,
            red_cell_common::operator::AgentTaskInfo,
            ListenerConfig,
            crate::listeners::ListenerSummary,
            crate::listeners::ListenerMarkRequest,
            crate::PersistedListenerState,
            crate::ListenerStatus,
            red_cell_common::ListenerProtocol,
            red_cell_common::HttpListenerConfig,
            red_cell_common::SmbListenerConfig,
            red_cell_common::DnsListenerConfig,
            red_cell_common::ListenerTlsConfig,
            red_cell_common::HttpListenerResponseConfig,
            red_cell_common::HttpListenerProxyConfig,
            super::listeners::TlsCertReloadRequest
        )
    ),
    modifiers(&ApiSecurity),
    tags(
        (name = "rest", description = "Versioned REST API for Red Cell automation clients"),
        (name = "audit", description = "Operator audit trail endpoints"),
        (name = "session_activity", description = "Persisted operator session activity endpoints"),
        (name = "credentials", description = "Captured credential inventory endpoints"),
        (name = "agents", description = "Agent inventory and tasking endpoints"),
        (name = "jobs", description = "Queued agent job inspection endpoints"),
        (name = "loot", description = "Captured loot listing and download endpoints"),
        (name = "operators", description = "Administrative operator-management endpoints"),
        (name = "listeners", description = "Listener lifecycle management endpoints"),
        (name = "webhooks", description = "Outbound webhook delivery statistics"),
        (name = "payloads", description = "Payload build and download endpoints"),
        (name = "payload_cache", description = "Payload build artifact cache management")
    )
)]
pub(super) struct ApiDoc;

pub(super) struct ApiSecurity;

impl Modify for ApiSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new(API_KEY_HEADER))),
        );
    }
}

#[utoipa::path(
    get,
    path = "/",
    context_path = "/api/v1",
    tag = "rest",
    responses(
        (status = 200, description = "API version and discovery metadata", body = ApiInfoResponse)
    )
)]
pub(super) async fn api_root(State(api): State<ApiRuntime>) -> Json<ApiInfoResponse> {
    let rate_limit = api.rate_limit();

    Json(ApiInfoResponse {
        version: API_VERSION.to_owned(),
        prefix: API_PREFIX.to_owned(),
        openapi_path: OPENAPI_PATH.to_owned(),
        documentation_path: DOCS_PATH.to_owned(),
        authentication_header: API_KEY_HEADER.to_owned(),
        enabled: api.enabled(),
        rate_limit_per_minute: (!rate_limit.disabled()).then_some(rate_limit.requests_per_minute),
    })
}
