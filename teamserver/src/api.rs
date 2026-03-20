//! Versioned REST API framework for the Red Cell teamserver.

use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use red_cell_common::config::{OperatorRole, Profile};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead};
use red_cell_common::{AgentRecord, ListenerConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Mutex;
use tracing::{debug, instrument};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::agents::QueuedJob;
use crate::app::TeamserverState;
use crate::database::LootFilter;
use crate::listeners::{ListenerManagerError, ListenerMarkRequest, ListenerSummary};
use crate::rate_limiter::{AttemptWindow, evict_oldest_windows, prune_expired_windows};
use crate::rbac::{
    CanAdminister, CanManageListeners, CanRead, CanTaskAgents, Permission, PermissionMarker,
};
use crate::websocket::{AgentCommandError, execute_agent_task};
use crate::{
    AuditPage, AuditQuery, AuditResultStatus, AuditWebhookNotifier, AuthError, Database,
    LootRecord, SessionActivityPage, SessionActivityQuery, TeamserverError, audit_details,
    parameter_object, query_audit_log, query_session_activity,
    record_operator_action_with_notifications,
};
const API_VERSION: &str = "v1";
const API_PREFIX: &str = "/api/v1";
const OPENAPI_PATH: &str = "/api/v1/openapi.json";
const DOCS_PATH: &str = "/api/v1/docs";
const OPENAPI_ROUTE: &str = "/openapi.json";
const DOCS_ROUTE: &str = "/docs";
const API_KEY_HEADER: &str = "x-api-key";
const BEARER_PREFIX: &str = "Bearer ";
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// Maximum number of failed API-key auth attempts from one IP before that IP is blocked.
const MAX_FAILED_API_AUTH_ATTEMPTS: u32 = 5;
/// Maximum number of per-IP auth-failure windows retained before the oldest are evicted.
const MAX_API_AUTH_FAILURE_WINDOWS: usize = 10_000;
const API_KEY_HASH_SECRET_SIZE: usize = 32;

type ApiKeyMac = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ApiKeyDigest([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RateLimitSubject {
    ClientIp(IpAddr),
    PresentedCredential(ApiKeyDigest),
    MissingApiKey,
    InvalidAuthorizationHeader,
}

/// Sanitized REST representation of an agent/session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
struct ApiAgentInfo {
    /// Numeric agent identifier.
    #[serde(rename = "AgentID")]
    agent_id: u32,
    /// Whether the agent is still marked active.
    #[serde(rename = "Active")]
    active: bool,
    /// Optional inactive reason or registration source.
    #[serde(rename = "Reason")]
    reason: String,
    /// Optional operator-authored note attached to the agent.
    #[serde(rename = "Note")]
    note: String,
    /// Computer hostname.
    #[serde(rename = "Hostname")]
    hostname: String,
    /// Logon username.
    #[serde(rename = "Username")]
    username: String,
    /// Logon domain.
    #[serde(rename = "DomainName")]
    domain_name: String,
    /// External callback IP.
    #[serde(rename = "ExternalIP")]
    external_ip: String,
    /// Internal workstation IP.
    #[serde(rename = "InternalIP")]
    internal_ip: String,
    /// Process executable name.
    #[serde(rename = "ProcessName")]
    process_name: String,
    /// Remote process base address.
    #[serde(rename = "BaseAddress")]
    base_address: u64,
    /// Remote process id.
    #[serde(rename = "ProcessPID")]
    process_pid: u32,
    /// Remote thread id.
    #[serde(rename = "ProcessTID")]
    process_tid: u32,
    /// Remote parent process id.
    #[serde(rename = "ProcessPPID")]
    process_ppid: u32,
    /// Process architecture label.
    #[serde(rename = "ProcessArch")]
    process_arch: String,
    /// Whether the current token is elevated.
    #[serde(rename = "Elevated")]
    elevated: bool,
    /// Operating system version string.
    #[serde(rename = "OSVersion")]
    os_version: String,
    /// Operating system build number (e.g. 22000 for Windows 11 21H2).
    #[serde(rename = "OSBuild")]
    os_build: u32,
    /// Operating system architecture label.
    #[serde(rename = "OSArch")]
    os_arch: String,
    /// Sleep interval in seconds.
    #[serde(rename = "SleepDelay")]
    sleep_delay: u32,
    /// Sleep jitter percentage.
    #[serde(rename = "SleepJitter")]
    sleep_jitter: u32,
    /// Optional kill-date value.
    #[serde(rename = "KillDate")]
    kill_date: Option<i64>,
    /// Optional working-hours bitmask.
    #[serde(rename = "WorkingHours")]
    working_hours: Option<i32>,
    /// Registration timestamp.
    #[serde(rename = "FirstCallIn")]
    first_call_in: String,
    /// Last callback timestamp.
    #[serde(rename = "LastCallIn")]
    last_call_in: String,
}

impl From<AgentRecord> for ApiAgentInfo {
    fn from(agent: AgentRecord) -> Self {
        Self::from(&agent)
    }
}

impl From<&AgentRecord> for ApiAgentInfo {
    fn from(agent: &AgentRecord) -> Self {
        Self {
            agent_id: agent.agent_id,
            active: agent.active,
            reason: agent.reason.clone(),
            note: agent.note.clone(),
            hostname: agent.hostname.clone(),
            username: agent.username.clone(),
            domain_name: agent.domain_name.clone(),
            external_ip: agent.external_ip.clone(),
            internal_ip: agent.internal_ip.clone(),
            process_name: agent.process_name.clone(),
            base_address: agent.base_address,
            process_pid: agent.process_pid,
            process_tid: agent.process_tid,
            process_ppid: agent.process_ppid,
            process_arch: agent.process_arch.clone(),
            elevated: agent.elevated,
            os_version: agent.os_version.clone(),
            os_build: agent.os_build,
            os_arch: agent.os_arch.clone(),
            sleep_delay: agent.sleep_delay,
            sleep_jitter: agent.sleep_jitter,
            kill_date: agent.kill_date,
            working_hours: agent.working_hours,
            first_call_in: agent.first_call_in.clone(),
            last_call_in: agent.last_call_in.clone(),
        }
    }
}

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

fn prune_expired_rate_limit_windows(
    windows: &mut BTreeMap<RateLimitSubject, RateLimitWindow>,
    now: Instant,
) {
    windows.retain(|_, window| now.duration_since(window.started_at) < RATE_LIMIT_WINDOW);
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
    key_hash_secret: Arc<[u8; API_KEY_HASH_SECRET_SIZE]>,
    /// Stored as a flat list so lookup can always visit every entry, enabling
    /// constant-time comparison via [`subtle::ConstantTimeEq`].
    keys: Arc<Vec<(ApiKeyDigest, ApiIdentity)>>,
    rate_limit: ApiRateLimit,
    windows: Arc<Mutex<BTreeMap<RateLimitSubject, RateLimitWindow>>>,
    /// Per-IP sliding windows tracking failed API-key auth attempts (wrong key presented).
    auth_failure_windows: Arc<Mutex<HashMap<IpAddr, AttemptWindow>>>,
}

impl ApiRuntime {
    /// Build REST API runtime state from a validated profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS random-number generator is unavailable when
    /// generating the HMAC secret used to hash API keys.
    pub fn from_profile(profile: &Profile) -> Result<Self, crate::TeamserverError> {
        let key_hash_secret = Arc::new(Self::generate_key_hash_secret()?);
        let (keys, requests_per_minute) = profile
            .api
            .as_ref()
            .map(|config| {
                let keys = config
                    .keys
                    .iter()
                    .map(|(name, key)| {
                        (
                            Self::hash_api_key(&key_hash_secret, &key.value),
                            ApiIdentity { key_id: name.clone(), role: key.role },
                        )
                    })
                    .collect::<Vec<_>>();

                (keys, config.rate_limit_per_minute)
            })
            .unwrap_or_else(|| (Vec::new(), 0));

        Ok(Self {
            key_hash_secret,
            keys: Arc::new(keys),
            rate_limit: ApiRateLimit { requests_per_minute },
            windows: Arc::new(Mutex::new(BTreeMap::new())),
            auth_failure_windows: Arc::new(Mutex::new(HashMap::new())),
        })
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

    async fn authenticate(
        &self,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
    ) -> Result<ApiIdentity, ApiAuthError> {
        if !self.enabled() {
            return Err(ApiAuthError::Disabled);
        }

        // Block IPs that have exceeded the failed-auth threshold before performing
        // any HMAC work. This prevents brute-forcing the key store at HMAC throughput.
        if let Some(ip) = client_ip {
            if !self.is_auth_failure_allowed(ip).await {
                return Err(ApiAuthError::RateLimited {
                    retry_after_seconds: RATE_LIMIT_WINDOW.as_secs(),
                });
            }
        }

        let presented_key = match extract_api_key(headers) {
            Ok(key) => key,
            Err(
                error @ (ApiAuthError::MissingApiKey | ApiAuthError::InvalidAuthorizationHeader),
            ) => {
                self.check_rate_limit(&rate_limit_subject_for_failed_auth(client_ip, &error))
                    .await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        let presented_key_digest = Self::hash_api_key(&self.key_hash_secret, &presented_key);
        let rate_limit_subject = client_ip
            .map(RateLimitSubject::ClientIp)
            .unwrap_or(RateLimitSubject::PresentedCredential(presented_key_digest));

        self.check_rate_limit(&rate_limit_subject).await?;

        match Self::lookup_key_ct(&self.keys, &presented_key_digest) {
            Some(identity) => {
                if let Some(ip) = client_ip {
                    self.record_auth_success(ip).await;
                }
                Ok(identity)
            }
            None => {
                if let Some(ip) = client_ip {
                    self.record_auth_failure(ip).await;
                }
                Err(ApiAuthError::InvalidApiKey)
            }
        }
    }

    /// Return `true` if the given IP has not exceeded the failed-auth attempt threshold.
    async fn is_auth_failure_allowed(&self, ip: IpAddr) -> bool {
        let mut windows = self.auth_failure_windows.lock().await;
        let Some(window) = windows.get_mut(&ip) else {
            return true;
        };
        if window.window_start.elapsed() >= RATE_LIMIT_WINDOW {
            windows.remove(&ip);
            return true;
        }
        window.attempts < MAX_FAILED_API_AUTH_ATTEMPTS
    }

    /// Record a failed API-key auth attempt from the given IP.
    async fn record_auth_failure(&self, ip: IpAddr) {
        let mut windows = self.auth_failure_windows.lock().await;
        let now = Instant::now();
        prune_expired_windows(&mut windows, RATE_LIMIT_WINDOW, now);
        if !windows.contains_key(&ip) && windows.len() >= MAX_API_AUTH_FAILURE_WINDOWS {
            evict_oldest_windows(&mut windows, MAX_API_AUTH_FAILURE_WINDOWS / 2);
        }
        let window = windows.entry(ip).or_default();
        if now.duration_since(window.window_start) >= RATE_LIMIT_WINDOW {
            window.attempts = 1;
            window.window_start = now;
        } else {
            window.attempts += 1;
        }
    }

    /// Clear the failure counter for an IP after a successful authentication.
    async fn record_auth_success(&self, ip: IpAddr) {
        self.auth_failure_windows.lock().await.remove(&ip);
    }

    /// Look up an [`ApiIdentity`] by digest using a constant-time comparison.
    ///
    /// Every entry in `keys` is always visited regardless of whether a match is
    /// found, so the duration of this function does not reveal whether (or at
    /// which index) a matching digest exists.
    fn lookup_key_ct(
        keys: &[(ApiKeyDigest, ApiIdentity)],
        digest: &ApiKeyDigest,
    ) -> Option<ApiIdentity> {
        let mut found: Option<ApiIdentity> = None;
        for (stored, identity) in keys {
            // ConstantTimeEq never short-circuits on the first differing byte.
            if stored.0.ct_eq(&digest.0).into() {
                found = Some(identity.clone());
            }
        }
        found
    }

    fn hash_api_key(secret: &[u8; API_KEY_HASH_SECRET_SIZE], api_key: &str) -> ApiKeyDigest {
        let mut mac = ApiKeyMac::new_from_slice(secret)
            .unwrap_or_else(|_| unreachable!("hmac accepts arbitrary secret lengths"));
        mac.update(api_key.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        ApiKeyDigest(bytes)
    }

    fn generate_key_hash_secret() -> Result<[u8; API_KEY_HASH_SECRET_SIZE], getrandom::Error> {
        let mut bytes = [0_u8; API_KEY_HASH_SECRET_SIZE];
        getrandom::fill(&mut bytes)?;
        Ok(bytes)
    }

    async fn check_rate_limit(&self, subject: &RateLimitSubject) -> Result<(), ApiAuthError> {
        if self.rate_limit.disabled() {
            return Ok(());
        }

        let mut windows = self.windows.lock().await;
        let now = Instant::now();
        prune_expired_rate_limit_windows(&mut windows, now);
        let window = windows.entry(subject.clone()).or_default();

        if now.duration_since(window.started_at) >= RATE_LIMIT_WINDOW {
            window.started_at = now;
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
            Self::RateLimited { retry_after_seconds } => {
                let mut response = json_error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    self.to_string(),
                );
                if let Ok(value) = retry_after_seconds.to_string().parse() {
                    response.headers_mut().insert(RETRY_AFTER, value);
                }
                response
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
        state: &TeamserverState,
    ) -> Result<Self, Self::Rejection> {
        let identity =
            parts.extensions.get::<ApiIdentity>().cloned().ok_or(ApiAuthError::MissingIdentity)?;

        if let Err(error) = authorize_api_role(identity.role, P::PERMISSION) {
            if let Err(audit_error) = record_operator_action_with_notifications(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "api.permission_denied",
                "api_key",
                Some(identity.key_id.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("permission_denied"),
                    Some(parameter_object([
                        ("required", Value::String(P::PERMISSION.as_str().to_owned())),
                        ("role", Value::String(format!("{:?}", identity.role))),
                    ])),
                ),
            )
            .await
            {
                tracing::warn!(%audit_error, "failed to persist api permission-denied audit record");
            }
            return Err(error);
        }

        Ok(Self { identity, _marker: PhantomData })
    }
}

/// Read-only access to protected REST API routes.
pub type ReadApiAccess = ApiPermissionGuard<CanRead>;
/// Listener-management access to protected REST API routes.
pub type ListenerManagementApiAccess = ApiPermissionGuard<CanManageListeners>;
/// Agent-tasking access to protected REST API routes.
pub type TaskAgentApiAccess = ApiPermissionGuard<CanTaskAgents>;
/// Administrative access to protected REST API routes.
pub type AdminApiAccess = ApiPermissionGuard<CanAdminister>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct AgentTaskQueuedResponse {
    agent_id: String,
    task_id: String,
    queued_jobs: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
struct LootSummary {
    id: i64,
    agent_id: String,
    kind: String,
    name: String,
    file_path: Option<String>,
    size_bytes: Option<i64>,
    captured_at: String,
    has_data: bool,
    operator: Option<String>,
    command_line: Option<String>,
    task_id: Option<String>,
    metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
struct OperatorSummary {
    username: String,
    role: OperatorRole,
    online: bool,
    last_seen: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
struct CreateOperatorRequest {
    username: String,
    password: String,
    role: OperatorRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct CreatedOperatorResponse {
    username: String,
    role: OperatorRole,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
struct LootPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<LootSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
struct CredentialSummary {
    id: i64,
    agent_id: String,
    name: String,
    captured_at: String,
    operator: Option<String>,
    command_line: Option<String>,
    task_id: Option<String>,
    pattern: Option<String>,
    content: Option<String>,
    metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
struct CredentialPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<CredentialSummary>,
}

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
struct CredentialQuery {
    agent_id: Option<String>,
    operator: Option<String>,
    command: Option<String>,
    name: Option<String>,
    pattern: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl CredentialQuery {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    fn limit(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT).clamp(1, Self::MAX_LIMIT)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct JobSummary {
    agent_id: String,
    command_id: u32,
    request_id: String,
    task_id: String,
    command_line: String,
    created_at: String,
    operator: Option<String>,
    payload_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct JobPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<JobSummary>,
}

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
struct JobQuery {
    agent_id: Option<String>,
    operator: Option<String>,
    command: Option<String>,
    task_id: Option<String>,
    request_id: Option<String>,
    command_id: Option<u32>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl JobQuery {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    fn limit(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT).clamp(1, Self::MAX_LIMIT)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
struct LootQuery {
    kind: Option<String>,
    agent_id: Option<String>,
    operator: Option<String>,
    command: Option<String>,
    name: Option<String>,
    file_path: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl LootQuery {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    fn limit(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT).clamp(1, Self::MAX_LIMIT)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }
}

#[derive(Debug, Error)]
enum AgentApiError {
    #[error("{0}")]
    Teamserver(#[from] crate::TeamserverError),
    #[error("{0}")]
    Task(#[from] AgentCommandError),
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Teamserver(crate::TeamserverError::AgentNotFound { .. }) => {
                (StatusCode::NOT_FOUND, "agent_not_found")
            }
            Self::Task(
                AgentCommandError::InvalidAgentId { .. }
                | AgentCommandError::MissingAgentId
                | AgentCommandError::MissingNote
                | AgentCommandError::InvalidCommandId { .. }
                | AgentCommandError::MissingField { .. }
                | AgentCommandError::InvalidBooleanField { .. }
                | AgentCommandError::InvalidNumericField { .. }
                | AgentCommandError::InvalidBase64Field { .. }
                | AgentCommandError::UnsupportedProcessSubcommand { .. }
                | AgentCommandError::UnsupportedFilesystemSubcommand { .. }
                | AgentCommandError::UnsupportedTokenSubcommand { .. }
                | AgentCommandError::UnsupportedSocketSubcommand { .. }
                | AgentCommandError::UnsupportedKerberosSubcommand { .. }
                | AgentCommandError::UnsupportedInjectionWay { .. }
                | AgentCommandError::UnsupportedInjectionTechnique { .. }
                | AgentCommandError::UnsupportedArchitecture { .. }
                | AgentCommandError::InvalidProcessCreateArguments
                | AgentCommandError::InvalidRemovePayload,
            ) => (StatusCode::BAD_REQUEST, "invalid_agent_task"),
            Self::Task(AgentCommandError::Teamserver(crate::TeamserverError::AgentNotFound {
                ..
            })) => (StatusCode::NOT_FOUND, "agent_not_found"),
            Self::Teamserver(_) | Self::Task(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "agent_api_error")
            }
        };

        json_error_response(status, code, self.to_string())
    }
}

#[derive(Debug, Error)]
enum AuditApiError {
    #[error("{0}")]
    Teamserver(#[from] crate::TeamserverError),
}

#[derive(Debug, Error)]
enum LootApiError {
    #[error("{0}")]
    Teamserver(#[from] crate::TeamserverError),
    #[error("invalid loot id `{value}`")]
    InvalidLootId { value: String },
    #[error("invalid agent id `{value}`")]
    InvalidAgentId { value: String },
    #[error("loot item `{id}` not found")]
    NotFound { id: i64 },
    #[error("loot item `{id}` does not contain downloadable data")]
    MissingData { id: i64 },
}

impl IntoResponse for LootApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::InvalidLootId { .. } => (StatusCode::BAD_REQUEST, "invalid_loot_id"),
            Self::InvalidAgentId { .. } => (StatusCode::BAD_REQUEST, "invalid_agent_id"),
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "loot_not_found"),
            Self::MissingData { .. } => (StatusCode::CONFLICT, "loot_missing_data"),
            Self::Teamserver(_) => (StatusCode::INTERNAL_SERVER_ERROR, "loot_api_error"),
        };

        json_error_response(status, code, self.to_string())
    }
}

#[derive(Debug, Error)]
enum CredentialApiError {
    #[error("{0}")]
    Teamserver(#[from] crate::TeamserverError),
    #[error("invalid credential id `{value}`")]
    InvalidCredentialId { value: String },
    #[error("invalid agent id `{value}`")]
    InvalidAgentId { value: String },
    #[error("credential `{id}` not found")]
    NotFound { id: i64 },
}

impl IntoResponse for CredentialApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::InvalidCredentialId { .. } => (StatusCode::BAD_REQUEST, "invalid_credential_id"),
            Self::InvalidAgentId { .. } => (StatusCode::BAD_REQUEST, "invalid_agent_id"),
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "credential_not_found"),
            Self::Teamserver(_) => (StatusCode::INTERNAL_SERVER_ERROR, "credential_api_error"),
        };

        json_error_response(status, code, self.to_string())
    }
}

#[derive(Debug, Error)]
enum JobApiError {
    #[error("{0}")]
    Teamserver(#[from] crate::TeamserverError),
    #[error("invalid agent id `{value}`")]
    InvalidAgentId { value: String },
    #[error("invalid request id `{value}`")]
    InvalidRequestId { value: String },
    #[error("queued job not found for agent `{agent_id}` request `{request_id}`")]
    NotFound { agent_id: String, request_id: String },
}

impl IntoResponse for JobApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::InvalidAgentId { .. } => (StatusCode::BAD_REQUEST, "invalid_agent_id"),
            Self::InvalidRequestId { .. } => (StatusCode::BAD_REQUEST, "invalid_request_id"),
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "job_not_found"),
            Self::Teamserver(_) => (StatusCode::INTERNAL_SERVER_ERROR, "job_api_error"),
        };

        json_error_response(status, code, self.to_string())
    }
}

#[derive(Debug, Error)]
enum OperatorApiError {
    #[error("{0}")]
    Auth(#[from] AuthError),
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
            Self::Auth(_) => (StatusCode::INTERNAL_SERVER_ERROR, "operator_api_error"),
        };

        json_error_response(status, code, self.to_string())
    }
}

impl IntoResponse for AuditApiError {
    fn into_response(self) -> Response {
        json_error_response(StatusCode::INTERNAL_SERVER_ERROR, "audit_api_error", self.to_string())
    }
}

/// Build the `/api/v1` router, including version metadata and OpenAPI docs.
pub fn api_routes(api: ApiRuntime) -> Router<TeamserverState> {
    let protected = Router::new()
        .route("/agents", get(list_agents))
        .route("/agents/{id}", get(get_agent).delete(kill_agent))
        .route("/agents/{id}/task", post(queue_agent_task))
        .route("/audit", get(list_audit))
        .route("/session-activity", get(list_session_activity))
        .route("/credentials", get(list_credentials))
        .route("/credentials/{id}", get(get_credential))
        .route("/jobs", get(list_jobs))
        .route("/jobs/{agent_id}/{request_id}", get(get_job))
        .route("/loot", get(list_loot))
        .route("/loot/{id}", get(get_loot))
        .route("/operators", get(list_operators).post(create_operator))
        .route("/listeners", get(list_listeners).post(create_listener))
        .route("/listeners/{name}", get(get_listener).put(update_listener).delete(delete_listener))
        .route("/listeners/{name}/start", put(start_listener))
        .route("/listeners/{name}/stop", put(stop_listener))
        .route("/listeners/{name}/mark", post(mark_listener))
        .route("/webhooks/stats", get(get_webhook_stats))
        .route("/payload-cache", post(flush_payload_cache))
        .route_layer(middleware::from_fn_with_state(api, api_auth_middleware));

    Router::new()
        .route("/", get(api_root))
        .merge(protected)
        .merge(SwaggerUi::new(DOCS_ROUTE).url(OPENAPI_ROUTE, ApiDoc::openapi()))
        .fallback(api_not_found)
}

#[instrument(skip(api, request, next))]
async fn api_auth_middleware(
    State(api): State<ApiRuntime>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiAuthError> {
    let identity = api.authenticate(request.headers(), client_ip(&request)).await?;

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
        list_agents,
        get_agent,
        kill_agent,
        queue_agent_task,
        list_audit,
        list_session_activity,
        list_credentials,
        get_credential,
        list_jobs,
        get_job,
        list_loot,
        get_loot,
        list_operators,
        create_operator,
        list_listeners,
        create_listener,
        get_listener,
        update_listener,
        delete_listener,
        start_listener,
        stop_listener,
        mark_listener,
        get_webhook_stats,
        flush_payload_cache
    ),
    components(
        schemas(
            ApiErrorBody,
            ApiErrorDetail,
            ApiInfoResponse,
            WebhookStats,
            DiscordWebhookStats,
            FlushPayloadCacheResponse,
            AgentTaskQueuedResponse,
            AuditPage,
            SessionActivityPage,
            CredentialPage,
            CredentialSummary,
            JobPage,
            JobSummary,
            LootPage,
            LootSummary,
            OperatorSummary,
            CreateOperatorRequest,
            CreatedOperatorResponse,
            crate::AuditRecord,
            crate::AuditResultStatus,
            crate::SessionActivityRecord,
            ApiAgentInfo,
            AgentTaskInfo,
            ListenerConfig,
            ListenerSummary,
            ListenerMarkRequest,
            crate::PersistedListenerState,
            crate::ListenerStatus,
            red_cell_common::ListenerProtocol,
            red_cell_common::HttpListenerConfig,
            red_cell_common::SmbListenerConfig,
            red_cell_common::DnsListenerConfig,
            red_cell_common::ListenerTlsConfig,
            red_cell_common::HttpListenerResponseConfig,
            red_cell_common::HttpListenerProxyConfig
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
        (name = "payload_cache", description = "Payload build artifact cache management")
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
    path = "/agents",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "List all tracked agents", body = [ApiAgentInfo]),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
async fn list_agents(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
) -> Json<Vec<ApiAgentInfo>> {
    Json(state.agent_registry.list().await.into_iter().map(ApiAgentInfo::from).collect())
}

#[utoipa::path(
    get,
    path = "/agents/{id}",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    responses(
        (status = 200, description = "Agent details", body = ApiAgentInfo),
        (status = 400, description = "Invalid agent id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody)
    )
)]
async fn get_agent(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Json<ApiAgentInfo>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    let agent = state
        .agent_registry
        .get(agent_id)
        .await
        .ok_or(crate::TeamserverError::AgentNotFound { agent_id })?;
    Ok(Json(ApiAgentInfo::from(agent)))
}

#[utoipa::path(
    delete,
    path = "/agents/{id}",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    responses(
        (status = 202, description = "Agent kill task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid agent id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody)
    )
)]
async fn kill_agent(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    let task_id = next_task_id();
    let message = Message {
        head: MessageHead {
            event: EventCode::Session,
            user: identity.key_id.clone(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: task_id.clone(),
            command_line: "kill".to_owned(),
            demon_id: format!("{agent_id:08X}"),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command: Some("kill".to_owned()),
            ..AgentTaskInfo::default()
        },
    };
    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        message,
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("kill"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("command", Value::String("kill".to_owned())),
                    ])),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some("kill"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("command", Value::String("kill".to_owned())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse { agent_id: format!("{agent_id:08X}"), task_id, queued_jobs }),
    ))
}

#[utoipa::path(
    post,
    path = "/agents/{id}/task",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    request_body = AgentTaskInfo,
    responses(
        (status = 202, description = "Agent task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid task payload", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody)
    )
)]
async fn queue_agent_task(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Json(mut task): Json<AgentTaskInfo>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    let canonical_id = format!("{agent_id:08X}");

    if !task.demon_id.is_empty() && !task.demon_id.eq_ignore_ascii_case(&canonical_id) {
        return Err(AgentCommandError::InvalidAgentId { agent_id: task.demon_id }.into());
    }
    if task.task_id.trim().is_empty() {
        task.task_id = next_task_id();
    }
    task.demon_id = canonical_id.clone();

    let audit_parameters = serde_json::to_value(&task).ok();
    let command = task.command.clone().unwrap_or_else(|| task.command_line.clone());
    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        Message {
            head: MessageHead {
                event: EventCode::Session,
                user: identity.key_id.clone(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: task.clone(),
        },
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some(command.as_str()),
                    audit_parameters.clone(),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some(command.as_str()),
                    Some(parameter_object([
                        ("task", audit_parameters.unwrap_or(Value::Null)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse {
            agent_id: canonical_id,
            task_id: task.task_id,
            queued_jobs,
        }),
    ))
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
async fn list_audit(
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
async fn list_session_activity(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Query(query): Query<SessionActivityQuery>,
) -> Result<Json<SessionActivityPage>, AuditApiError> {
    Ok(Json(query_session_activity(&state.database, &query).await?))
}

#[utoipa::path(
    get,
    path = "/credentials",
    context_path = "/api/v1",
    tag = "credentials",
    security(("api_key" = [])),
    params(CredentialQuery),
    responses(
        (status = 200, description = "Filtered and paginated captured credentials", body = CredentialPage),
        (status = 400, description = "Invalid filter value", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
async fn list_credentials(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Query(query): Query<CredentialQuery>,
) -> Result<Json<CredentialPage>, CredentialApiError> {
    let offset = query.offset();
    let limit = query.limit();
    let filter = LootFilter {
        kind_exact: Some("credential".to_owned()),
        agent_id: parse_optional_agent_id(query.agent_id.as_deref(), |value| {
            CredentialApiError::InvalidAgentId { value }
        })?,
        name_contains: query.name.clone(),
        operator_contains: query.operator.clone(),
        command_contains: query.command.clone(),
        pattern_contains: query.pattern.clone(),
        since: normalize_timestamp_filter(query.since.as_deref()),
        until: normalize_timestamp_filter(query.until.as_deref()),
        ..LootFilter::default()
    };
    let repo = state.database.loot();
    let items = repo
        .query_filtered(&filter, usize_to_i64(limit, "limit")?, usize_to_i64(offset, "offset")?)
        .await?
        .into_iter()
        .filter_map(credential_summary)
        .collect::<Vec<_>>();
    let total = i64_to_usize(repo.count_filtered(&filter).await?, "total")?;

    Ok(Json(CredentialPage { total, limit, offset, items }))
}

#[utoipa::path(
    get,
    path = "/credentials/{id}",
    context_path = "/api/v1",
    tag = "credentials",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Numeric credential identifier")),
    responses(
        (status = 200, description = "Captured credential details", body = CredentialSummary),
        (status = 400, description = "Invalid credential id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Credential not found", body = ApiErrorBody)
    )
)]
async fn get_credential(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Json<CredentialSummary>, CredentialApiError> {
    let credential_id = id
        .trim()
        .parse::<i64>()
        .map_err(|_| CredentialApiError::InvalidCredentialId { value: id.clone() })?;
    let record = state
        .database
        .loot()
        .get(credential_id)
        .await?
        .filter(|record| record.kind.eq_ignore_ascii_case("credential"))
        .ok_or(CredentialApiError::NotFound { id: credential_id })?;

    credential_summary(record).map(Json).ok_or(CredentialApiError::NotFound { id: credential_id })
}

#[utoipa::path(
    get,
    path = "/jobs",
    context_path = "/api/v1",
    tag = "jobs",
    security(("api_key" = [])),
    params(JobQuery),
    responses(
        (status = 200, description = "Queued jobs across all tracked agents", body = JobPage),
        (status = 400, description = "Invalid filter value", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
async fn list_jobs(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Query(query): Query<JobQuery>,
) -> Result<Json<JobPage>, JobApiError> {
    let normalized_agent_id = normalize_agent_filter(query.agent_id.as_deref(), |value| {
        JobApiError::InvalidAgentId { value }
    })?;
    let normalized_request_id = normalize_request_filter(query.request_id.as_deref(), |value| {
        JobApiError::InvalidRequestId { value }
    })?;

    let mut items = state
        .agent_registry
        .queued_jobs_all()
        .await
        .into_iter()
        .filter(|queued_job| {
            job_matches(
                &query,
                queued_job,
                normalized_agent_id.as_deref(),
                normalized_request_id.as_deref(),
            )
        })
        .map(job_summary)
        .collect::<Vec<_>>();

    let total = items.len();
    let offset = query.offset();
    let limit = query.limit();
    items = items.into_iter().skip(offset).take(limit).collect();

    Ok(Json(JobPage { total, limit, offset, items }))
}

#[utoipa::path(
    get,
    path = "/jobs/{agent_id}/{request_id}",
    context_path = "/api/v1",
    tag = "jobs",
    security(("api_key" = [])),
    params(
        ("agent_id" = String, Path, description = "Agent id in hex (with optional 0x prefix)"),
        ("request_id" = String, Path, description = "Request id in hex (with optional 0x prefix)")
    ),
    responses(
        (status = 200, description = "Queued job details", body = JobSummary),
        (status = 400, description = "Invalid identifier", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Queued job not found", body = ApiErrorBody)
    )
)]
async fn get_job(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path((agent_id, request_id)): Path<(String, String)>,
) -> Result<Json<JobSummary>, JobApiError> {
    let normalized_agent_id = normalize_agent_filter(Some(agent_id.as_str()), |value| {
        JobApiError::InvalidAgentId { value }
    })?
    .ok_or(JobApiError::InvalidAgentId { value: agent_id.clone() })?;
    let normalized_request_id = normalize_request_filter(Some(request_id.as_str()), |value| {
        JobApiError::InvalidRequestId { value }
    })?
    .ok_or(JobApiError::InvalidRequestId { value: request_id.clone() })?;

    state
        .agent_registry
        .queued_jobs_all()
        .await
        .into_iter()
        .find(|queued_job| {
            format!("{:08X}", queued_job.agent_id) == normalized_agent_id
                && format!("{:X}", queued_job.job.request_id) == normalized_request_id
        })
        .map(job_summary)
        .map(Json)
        .ok_or(JobApiError::NotFound {
            agent_id: normalized_agent_id,
            request_id: normalized_request_id,
        })
}

#[utoipa::path(
    get,
    path = "/loot",
    context_path = "/api/v1",
    tag = "loot",
    security(("api_key" = [])),
    params(LootQuery),
    responses(
        (status = 200, description = "Filtered and paginated captured loot", body = LootPage),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
async fn list_loot(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Query(query): Query<LootQuery>,
) -> Result<Json<LootPage>, LootApiError> {
    let offset = query.offset();
    let limit = query.limit();
    let filter = LootFilter {
        kind_contains: query.kind.clone(),
        agent_id: parse_optional_agent_id(query.agent_id.as_deref(), |value| {
            LootApiError::InvalidAgentId { value }
        })?,
        name_contains: query.name.clone(),
        file_path_contains: query.file_path.clone(),
        operator_contains: query.operator.clone(),
        command_contains: query.command.clone(),
        since: normalize_timestamp_filter(query.since.as_deref()),
        until: normalize_timestamp_filter(query.until.as_deref()),
        ..LootFilter::default()
    };
    let repo = state.database.loot();
    let items = repo
        .query_filtered(&filter, usize_to_i64(limit, "limit")?, usize_to_i64(offset, "offset")?)
        .await?
        .into_iter()
        .map(loot_summary)
        .collect::<Vec<_>>();
    let total = i64_to_usize(repo.count_filtered(&filter).await?, "total")?;

    Ok(Json(LootPage { total, limit, offset, items }))
}

#[utoipa::path(
    get,
    path = "/loot/{id}",
    context_path = "/api/v1",
    tag = "loot",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Numeric loot identifier")),
    responses(
        (status = 200, description = "Loot item binary content"),
        (status = 400, description = "Invalid loot id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Loot item not found", body = ApiErrorBody),
        (status = 409, description = "Loot item has no stored binary content", body = ApiErrorBody)
    )
)]
async fn get_loot(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Response, LootApiError> {
    let loot_id =
        id.parse::<i64>().map_err(|_| LootApiError::InvalidLootId { value: id.clone() })?;
    let record =
        state.database.loot().get(loot_id).await?.ok_or(LootApiError::NotFound { id: loot_id })?;
    let data = record.data.ok_or(LootApiError::MissingData { id: loot_id })?;
    let filename = sanitize_filename(record.name.as_str());
    let content_type = loot_content_type(record.kind.as_str(), filename.as_str());

    let mut response = Response::new(axum::body::Body::from(data));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        content_type.parse().map_err(|error: axum::http::header::InvalidHeaderValue| {
            LootApiError::Teamserver(crate::TeamserverError::InvalidPersistedValue {
                field: "content_type",
                message: error.to_string(),
            })
        })?,
    );
    headers.insert(
        CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"").parse().map_err(
            |error: axum::http::header::InvalidHeaderValue| {
                LootApiError::Teamserver(crate::TeamserverError::InvalidPersistedValue {
                    field: "content_disposition",
                    message: error.to_string(),
                })
            },
        )?,
    );

    Ok(response)
}

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
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
async fn list_operators(
    State(state): State<TeamserverState>,
    _identity: AdminApiAccess,
) -> Json<Vec<OperatorSummary>> {
    let operators = state
        .auth
        .operator_inventory()
        .await
        .into_iter()
        .map(|operator| OperatorSummary {
            username: operator.username,
            role: operator.role,
            online: operator.online,
            last_seen: operator.last_seen,
        })
        .collect::<Vec<_>>();
    Json(operators)
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
async fn create_operator(
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
    identity: ListenerManagementApiAccess,
    Path(name): Path<String>,
    Json(config): Json<ListenerConfig>,
) -> Result<Json<ListenerSummary>, ListenerManagerError> {
    let parameters = serde_json::to_value(&config).ok();
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
async fn delete_listener(
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
async fn start_listener(
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
async fn stop_listener(
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
async fn mark_listener(
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

    let action = if summary.state.status == crate::ListenerStatus::Running {
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

fn client_ip(request: &Request) -> Option<IpAddr> {
    request.extensions().get::<ConnectInfo<SocketAddr>>().map(|connect_info| connect_info.0.ip())
}

fn rate_limit_subject_for_failed_auth(
    client_ip: Option<IpAddr>,
    error: &ApiAuthError,
) -> RateLimitSubject {
    client_ip.map(RateLimitSubject::ClientIp).unwrap_or_else(|| match error {
        ApiAuthError::MissingApiKey => RateLimitSubject::MissingApiKey,
        ApiAuthError::InvalidAuthorizationHeader => RateLimitSubject::InvalidAuthorizationHeader,
        _ => unreachable!("only missing/invalid header auth errors map to failed auth buckets"),
    })
}

fn authorize_api_role(role: OperatorRole, permission: Permission) -> Result<(), ApiAuthError> {
    if api_role_allows(role, permission) {
        Ok(())
    } else {
        Err(ApiAuthError::PermissionDenied { role, required: permission.as_str() })
    }
}

fn parse_api_agent_id(value: &str) -> Result<u32, AgentApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AgentCommandError::MissingAgentId.into());
    }

    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);

    u32::from_str_radix(hex_digits, 16)
        .map_err(|_| AgentCommandError::InvalidAgentId { agent_id: trimmed.to_owned() }.into())
}

fn loot_summary(record: LootRecord) -> LootSummary {
    let (operator, command_line, task_id) = loot_context_fields(record.metadata.as_ref());
    LootSummary {
        id: record.id.unwrap_or_default(),
        agent_id: format!("{:08X}", record.agent_id),
        kind: record.kind,
        name: record.name,
        file_path: record.file_path,
        size_bytes: record.size_bytes,
        captured_at: record.captured_at,
        has_data: record.data.is_some(),
        operator,
        command_line,
        task_id,
        metadata: record.metadata,
    }
}

fn credential_summary(record: LootRecord) -> Option<CredentialSummary> {
    if !record.kind.eq_ignore_ascii_case("credential") {
        return None;
    }

    let (operator, command_line, task_id) = loot_context_fields(record.metadata.as_ref());
    Some(CredentialSummary {
        id: record.id.unwrap_or_default(),
        agent_id: format!("{:08X}", record.agent_id),
        name: record.name,
        captured_at: record.captured_at,
        operator,
        command_line,
        task_id,
        pattern: metadata_string_field(record.metadata.as_ref(), "pattern"),
        content: record.data.as_deref().map(|data| String::from_utf8_lossy(data).into_owned()),
        metadata: record.metadata,
    })
}

fn job_summary(queued_job: QueuedJob) -> JobSummary {
    JobSummary {
        agent_id: format!("{:08X}", queued_job.agent_id),
        command_id: queued_job.job.command,
        request_id: format!("{:X}", queued_job.job.request_id),
        task_id: queued_job.job.task_id,
        command_line: queued_job.job.command_line,
        created_at: queued_job.job.created_at,
        operator: (!queued_job.job.operator.is_empty()).then_some(queued_job.job.operator),
        payload_size: queued_job.job.payload.len(),
    }
}

fn normalize_agent_filter<E>(
    value: Option<&str>,
    invalid: impl FnOnce(String) -> E + Copy,
) -> Result<Option<String>, E> {
    value
        .map(|filter_value| match parse_hex_u32(filter_value) {
            Some(parsed) => Ok(format!("{parsed:08X}")),
            None => Err(invalid(filter_value.to_owned())),
        })
        .transpose()
}

fn normalize_request_filter<E>(
    value: Option<&str>,
    invalid: impl FnOnce(String) -> E + Copy,
) -> Result<Option<String>, E> {
    value
        .map(|filter_value| match parse_hex_u32(filter_value) {
            Some(parsed) => Ok(format!("{parsed:X}")),
            None => Err(invalid(filter_value.to_owned())),
        })
        .transpose()
}

fn job_matches(
    query: &JobQuery,
    queued_job: &QueuedJob,
    normalized_agent_id: Option<&str>,
    normalized_request_id: Option<&str>,
) -> bool {
    normalized_agent_id.is_none_or(|agent_id| format!("{:08X}", queued_job.agent_id) == agent_id)
        && normalized_request_id
            .is_none_or(|request_id| format!("{:X}", queued_job.job.request_id) == request_id)
        && query.command_id.is_none_or(|command_id| queued_job.job.command == command_id)
        && contains_filter(queued_job.job.command_line.as_str(), query.command.as_deref())
        && contains_filter(queued_job.job.task_id.as_str(), query.task_id.as_deref())
        && optional_contains_filter(
            (!queued_job.job.operator.is_empty()).then_some(queued_job.job.operator.as_str()),
            query.operator.as_deref(),
        )
}

fn loot_context_fields(
    metadata: Option<&Value>,
) -> (Option<String>, Option<String>, Option<String>) {
    let object = metadata.and_then(Value::as_object);
    let operator = object
        .and_then(|value| value.get("operator"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let command_line = object
        .and_then(|value| value.get("command_line"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let task_id = object
        .and_then(|value| value.get("task_id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    (operator, command_line, task_id)
}

fn metadata_string_field(metadata: Option<&Value>, key: &str) -> Option<String> {
    metadata
        .and_then(Value::as_object)
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn parse_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn normalize_timestamp_filter(value: Option<&str>) -> Option<String> {
    parse_rfc3339(value?)
        .and_then(|timestamp| timestamp.to_offset(time::UtcOffset::UTC).format(&Rfc3339).ok())
}

fn parse_optional_agent_id<E>(
    value: Option<&str>,
    invalid: impl FnOnce(String) -> E + Copy,
) -> Result<Option<u32>, E> {
    value
        .map(|filter_value| {
            parse_hex_u32(filter_value).ok_or_else(|| invalid(filter_value.to_owned()))
        })
        .transpose()
}

fn usize_to_i64(value: usize, field: &'static str) -> Result<i64, TeamserverError> {
    i64::try_from(value).map_err(|_| TeamserverError::InvalidPersistedValue {
        field,
        message: format!("{field} exceeds i64 range"),
    })
}

fn i64_to_usize(value: i64, field: &'static str) -> Result<usize, TeamserverError> {
    usize::try_from(value).map_err(|_| TeamserverError::InvalidPersistedValue {
        field,
        message: format!("{field} exceeds usize range"),
    })
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    u32::from_str_radix(hex_digits, 16).ok()
}

fn contains_filter(value: &str, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| value.contains(filter))
}

fn optional_contains_filter(value: Option<&str>, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| value.is_some_and(|value| value.contains(filter)))
}

fn sanitize_filename(filename: &str) -> String {
    let sanitized = filename.replace(['"', '\n', '\r'], "_");
    if sanitized.is_empty() { "loot.bin".to_owned() } else { sanitized }
}

fn loot_content_type(kind: &str, filename: &str) -> &'static str {
    if kind.eq_ignore_ascii_case("screenshot") || filename.ends_with(".png") {
        "image/png"
    } else if kind.eq_ignore_ascii_case("credential") || filename.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn next_task_id() -> String {
    let bytes = *Uuid::new_v4().as_bytes();
    format!("{:08X}", u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

async fn record_audit_entry(
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: crate::AuditDetails,
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

/// Delivery statistics for the Discord outbound webhook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct DiscordWebhookStats {
    /// Total number of permanent delivery failures (all retry attempts exhausted).
    failures: u64,
}

/// Aggregated outbound webhook delivery statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct WebhookStats {
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
async fn get_webhook_stats(
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

/// Response returned after flushing the payload build artifact cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
struct FlushPayloadCacheResponse {
    /// Number of cache entries removed.
    flushed: u64,
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
async fn flush_payload_cache(
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

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        AgentRegistry, AuthService, Database, EventBus, Job, ListenerManager,
        OperatorConnectionManager, SocketRelayManager,
    };
    use red_cell_common::crypto::hash_password_sha3;
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
        assert_eq!(result.unwrap().key_id, "key-b");
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
        assert_eq!(result.unwrap().key_id, "second");
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

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/audit?operator=rest-admin&since=2026-03-01T00:00:00Z&until=2026-03-31T23:59:59Z")
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
        );
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
        );

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
        );
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
        );

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

        let err = api.check_rate_limit(&subject).await.unwrap_err();
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
}
