//! Versioned REST API framework for the Red Cell teamserver.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use red_cell_common::ListenerConfig;
use red_cell_common::config::{OperatorRole, Profile};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::debug;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::app::TeamserverState;
use crate::listeners::{ListenerManagerError, ListenerMarkRequest, ListenerSummary};
use crate::rbac::{CanManageListeners, CanRead, Permission, PermissionMarker};
const API_VERSION: &str = "v1";
const API_PREFIX: &str = "/api/v1";
const OPENAPI_PATH: &str = "/api/v1/openapi.json";
const DOCS_PATH: &str = "/api/v1/docs";
const OPENAPI_ROUTE: &str = "/openapi.json";
const DOCS_ROUTE: &str = "/docs";
const API_KEY_HEADER: &str = "x-api-key";
const BEARER_PREFIX: &str = "Bearer ";
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Fixed REST API rate-limiting configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiRateLimit {
    /// Maximum accepted requests per API key, per minute.
    pub requests_per_minute: u32,
}

impl ApiRateLimit {
    fn disabled(self) -> bool {
        self.requests_per_minute == 0
    }
}

#[derive(Debug, Clone)]
struct RateLimitWindow {
    started_at: Instant,
    request_count: u32,
}

impl Default for RateLimitWindow {
    fn default() -> Self {
        Self { started_at: Instant::now(), request_count: 0 }
    }
}

/// Authenticated REST API identity derived from an API key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiIdentity {
    /// Stable key identifier from the profile.
    pub key_id: String,
    /// RBAC role granted to the key.
    pub role: OperatorRole,
}

/// Shared REST API authentication and rate-limiting runtime state.
#[derive(Debug, Clone)]
pub struct ApiRuntime {
    keys: Arc<BTreeMap<String, ApiIdentity>>,
    rate_limit: ApiRateLimit,
    windows: Arc<Mutex<BTreeMap<String, RateLimitWindow>>>,
}

impl ApiRuntime {
    /// Build REST API runtime state from a validated profile.
    #[must_use]
    pub fn from_profile(profile: &Profile) -> Self {
        let (keys, requests_per_minute) = profile
            .api
            .as_ref()
            .map(|config| {
                let keys = config
                    .keys
                    .iter()
                    .map(|(name, key)| {
                        (key.value.clone(), ApiIdentity { key_id: name.clone(), role: key.role })
                    })
                    .collect::<BTreeMap<_, _>>();

                (keys, config.rate_limit_per_minute)
            })
            .unwrap_or_else(|| (BTreeMap::new(), 0));

        Self {
            keys: Arc::new(keys),
            rate_limit: ApiRateLimit { requests_per_minute },
            windows: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Return whether protected API routes are enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Return the configured rate-limit policy, if any.
    #[must_use]
    pub fn rate_limit(&self) -> ApiRateLimit {
        self.rate_limit
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<ApiIdentity, ApiAuthError> {
        if !self.enabled() {
            return Err(ApiAuthError::Disabled);
        }

        let presented_key = extract_api_key(headers)?;
        let identity =
            self.keys.get(presented_key.as_str()).cloned().ok_or(ApiAuthError::InvalidApiKey)?;

        self.check_rate_limit(&identity.key_id).await?;

        Ok(identity)
    }

    async fn check_rate_limit(&self, key_id: &str) -> Result<(), ApiAuthError> {
        if self.rate_limit.disabled() {
            return Ok(());
        }

        let mut windows = self.windows.lock().await;
        let window = windows.entry(key_id.to_owned()).or_default();

        if window.started_at.elapsed() >= RATE_LIMIT_WINDOW {
            window.started_at = Instant::now();
            window.request_count = 0;
        }

        if window.request_count >= self.rate_limit.requests_per_minute {
            return Err(ApiAuthError::RateLimited {
                retry_after_seconds: RATE_LIMIT_WINDOW.as_secs(),
            });
        }

        window.request_count += 1;
        Ok(())
    }
}

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

/// Errors raised while authenticating or authorizing REST API requests.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiAuthError {
    /// The REST API is mounted but no keys are configured.
    #[error("rest api is not configured")]
    Disabled,
    /// No API key was provided.
    #[error("missing api key")]
    MissingApiKey,
    /// The authorization header was malformed.
    #[error("invalid authorization header")]
    InvalidAuthorizationHeader,
    /// The API key was not recognized.
    #[error("invalid api key")]
    InvalidApiKey,
    /// The API key lacks the required permission.
    #[error("api key role `{role:?}` lacks `{required}` permission")]
    PermissionDenied {
        /// The role granted to the API key.
        role: OperatorRole,
        /// The required permission label.
        required: &'static str,
    },
    /// The rate limit was exceeded for the current key.
    #[error("rate limit exceeded")]
    RateLimited {
        /// Suggested retry interval in seconds.
        retry_after_seconds: u64,
    },
    /// The authentication middleware was not installed on this route.
    #[error("rest api middleware not configured for route")]
    MissingIdentity,
}

impl IntoResponse for ApiAuthError {
    fn into_response(self) -> Response {
        match self {
            Self::Disabled => json_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "api_disabled",
                self.to_string(),
            ),
            Self::MissingApiKey => {
                json_error_response(StatusCode::UNAUTHORIZED, "missing_api_key", self.to_string())
            }
            Self::InvalidAuthorizationHeader => json_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_authorization_header",
                self.to_string(),
            ),
            Self::InvalidApiKey => {
                json_error_response(StatusCode::UNAUTHORIZED, "invalid_api_key", self.to_string())
            }
            Self::PermissionDenied { .. } => {
                json_error_response(StatusCode::FORBIDDEN, "forbidden", self.to_string())
            }
            Self::RateLimited { .. } => {
                json_error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", self.to_string())
            }
            Self::MissingIdentity => json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "missing_identity",
                self.to_string(),
            ),
        }
    }
}

/// Extractor that exposes an authenticated API identity and enforces a permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPermissionGuard<P> {
    identity: ApiIdentity,
    _marker: PhantomData<P>,
}

impl<P> Deref for ApiPermissionGuard<P> {
    type Target = ApiIdentity;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

impl<P> FromRequestParts<TeamserverState> for ApiPermissionGuard<P>
where
    P: PermissionMarker + Send + Sync,
{
    type Rejection = ApiAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &TeamserverState,
    ) -> Result<Self, Self::Rejection> {
        let identity =
            parts.extensions.get::<ApiIdentity>().cloned().ok_or(ApiAuthError::MissingIdentity)?;

        authorize_api_role(identity.role, P::PERMISSION)?;

        Ok(Self { identity, _marker: PhantomData })
    }
}

/// Read-only access to protected REST API routes.
pub type ReadApiAccess = ApiPermissionGuard<CanRead>;
/// Listener-management access to protected REST API routes.
pub type ListenerManagementApiAccess = ApiPermissionGuard<CanManageListeners>;

/// Build the `/api/v1` router, including version metadata and OpenAPI docs.
pub fn api_routes(api: ApiRuntime) -> Router<TeamserverState> {
    let protected = Router::new()
        .route("/listeners", get(list_listeners).post(create_listener))
        .route("/listeners/{name}", get(get_listener).put(update_listener).delete(delete_listener))
        .route("/listeners/{name}/start", post(start_listener))
        .route("/listeners/{name}/stop", post(stop_listener))
        .route("/listeners/{name}/mark", post(mark_listener))
        .route_layer(middleware::from_fn_with_state(api, api_auth_middleware));

    Router::new()
        .route("/", get(api_root))
        .merge(protected)
        .merge(SwaggerUi::new(DOCS_ROUTE).url(OPENAPI_ROUTE, ApiDoc::openapi()))
        .fallback(api_not_found)
}

async fn api_auth_middleware(
    State(api): State<ApiRuntime>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiAuthError> {
    let identity = api.authenticate(request.headers()).await?;

    debug!(key_id = %identity.key_id, role = ?identity.role, "authenticated rest api request");
    request.extensions_mut().insert(identity);

    Ok(next.run(request).await)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct ApiInfoResponse {
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
        list_listeners,
        create_listener,
        get_listener,
        update_listener,
        delete_listener,
        start_listener,
        stop_listener,
        mark_listener
    ),
    components(
        schemas(
            ApiErrorBody,
            ApiErrorDetail,
            ApiInfoResponse,
            ListenerConfig,
            ListenerSummary,
            ListenerMarkRequest,
            crate::PersistedListenerState,
            crate::ListenerStatus,
            red_cell_common::ListenerProtocol,
            red_cell_common::HttpListenerConfig,
            red_cell_common::SmbListenerConfig,
            red_cell_common::ExternalListenerConfig,
            red_cell_common::DnsListenerConfig,
            red_cell_common::ListenerTlsConfig,
            red_cell_common::HttpListenerResponseConfig,
            red_cell_common::HttpListenerProxyConfig
        )
    ),
    modifiers(&ApiSecurity),
    tags(
        (name = "rest", description = "Versioned REST API for Red Cell automation clients"),
        (name = "listeners", description = "Listener lifecycle management endpoints")
    )
)]
struct ApiDoc;

struct ApiSecurity;

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
async fn api_root(State(api): State<ApiRuntime>) -> Json<ApiInfoResponse> {
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
async fn list_listeners(
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
async fn create_listener(
    State(state): State<TeamserverState>,
    _identity: ListenerManagementApiAccess,
    Json(config): Json<ListenerConfig>,
) -> Result<(StatusCode, Json<ListenerSummary>), ListenerManagerError> {
    let summary = state.listeners.create(config).await?;
    Ok((StatusCode::CREATED, Json(summary)))
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
async fn get_listener(
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
async fn update_listener(
    State(state): State<TeamserverState>,
    _identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
    Json(config): Json<ListenerConfig>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    if config.name() != name {
        return Err(ListenerManagerError::InvalidConfig {
            message: "path name must match listener configuration name".to_owned(),
        });
    }

    Ok(Json(state.listeners.update(config).await?))
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
async fn delete_listener(
    State(state): State<TeamserverState>,
    _identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
) -> Result<StatusCode, ListenerManagerError> {
    state.listeners.delete(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
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
async fn start_listener(
    State(state): State<TeamserverState>,
    _identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    Ok(Json(state.listeners.start(&name).await?))
}

#[utoipa::path(
    post,
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
async fn stop_listener(
    State(state): State<TeamserverState>,
    _identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    Ok(Json(state.listeners.stop(&name).await?))
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
async fn mark_listener(
    State(state): State<TeamserverState>,
    _identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
    Json(request): Json<ListenerMarkRequest>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    let summary = match request.mark.as_str() {
        mark if mark.eq_ignore_ascii_case("start") || mark.eq_ignore_ascii_case("online") => {
            state.listeners.start(&name).await?
        }
        mark if mark.eq_ignore_ascii_case("stop") || mark.eq_ignore_ascii_case("offline") => {
            state.listeners.stop(&name).await?
        }
        _ => {
            return Err(ListenerManagerError::UnsupportedMark { mark: request.mark });
        }
    };

    Ok(Json(summary))
}

async fn api_not_found() -> Response {
    json_error_response(StatusCode::NOT_FOUND, "not_found", "rest api route not found")
}

fn extract_api_key(headers: &HeaderMap) -> Result<String, ApiAuthError> {
    if let Some(value) = headers.get(API_KEY_HEADER) {
        let key = value.to_str().map_err(|_| ApiAuthError::InvalidAuthorizationHeader)?;
        if key.trim().is_empty() {
            return Err(ApiAuthError::MissingApiKey);
        }

        return Ok(key.to_owned());
    }

    let Some(value) = headers.get(AUTHORIZATION) else {
        return Err(ApiAuthError::MissingApiKey);
    };
    let value = value.to_str().map_err(|_| ApiAuthError::InvalidAuthorizationHeader)?;
    let Some(token) = value.strip_prefix(BEARER_PREFIX) else {
        return Err(ApiAuthError::InvalidAuthorizationHeader);
    };

    if token.trim().is_empty() {
        return Err(ApiAuthError::MissingApiKey);
    }

    Ok(token.to_owned())
}

fn authorize_api_role(role: OperatorRole, permission: Permission) -> Result<(), ApiAuthError> {
    if api_role_allows(role, permission) {
        Ok(())
    } else {
        Err(ApiAuthError::PermissionDenied { role, required: permission.as_str() })
    }
}

const fn api_role_allows(role: OperatorRole, permission: Permission) -> bool {
    match role {
        OperatorRole::Admin => true,
        OperatorRole::Operator => {
            matches!(
                permission,
                Permission::Read | Permission::TaskAgents | Permission::ManageListeners
            )
        }
        OperatorRole::Analyst => matches!(permission, Permission::Read),
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
        AgentRegistry, AuthService, Database, EventBus, ListenerManager, OperatorConnectionManager,
        SocketRelayManager,
    };

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

        let body = read_json(second).await;
        assert_eq!(body["error"]["code"], "rate_limited");
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

    async fn test_router(api_key: Option<(u32, &str, &str, OperatorRole)>) -> Router {
        let profile = test_profile(api_key);
        let database = Database::connect_in_memory().await.expect("database");
        let agent_registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
        let listeners = ListenerManager::new(
            database.clone(),
            agent_registry.clone(),
            events.clone(),
            sockets.clone(),
        );

        let api = ApiRuntime::from_profile(&profile);

        api_routes(api.clone()).with_state(TeamserverState {
            profile: profile.clone(),
            database,
            auth: AuthService::from_profile(&profile),
            api,
            events,
            connections: OperatorConnectionManager::new(),
            agent_registry,
            listeners,
            sockets,
        })
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
}
