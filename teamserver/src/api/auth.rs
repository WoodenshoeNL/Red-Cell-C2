//! REST API authentication, authorization, and rate-limiting.

use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use red_cell_common::config::{OperatorRole, Profile};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

use crate::app::TeamserverState;
use crate::rate_limiter::{AttemptWindow, evict_oldest_windows, prune_expired_windows};
use crate::rbac::{
    CanAdminister, CanManageListeners, CanRead, CanTaskAgents, Permission, PermissionMarker,
};
use crate::{audit_details, parameter_object, record_operator_action_with_notifications};

use super::errors::json_error_response;

pub(crate) const API_KEY_HEADER: &str = "x-api-key";
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

/// Fixed REST API rate-limiting configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiRateLimit {
    /// Maximum accepted requests per API key, per minute.
    pub requests_per_minute: u32,
}

impl ApiRateLimit {
    pub(crate) fn disabled(self) -> bool {
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
                    crate::AuditResultStatus::Failure,
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

// ── Auth middleware and helpers ──────────────────────────────────────────────

#[instrument(skip(api, request, next))]
pub(super) async fn api_auth_middleware(
    State(api): State<ApiRuntime>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiAuthError> {
    let identity = api.authenticate(request.headers(), client_ip(&request)).await?;

    debug!(key_id = %identity.key_id, role = ?identity.role, "authenticated rest api request");
    request.extensions_mut().insert(identity);

    Ok(next.run(request).await)
}

/// Extract API key from request headers (X-API-Key or Bearer token).
pub(crate) fn extract_api_key(headers: &HeaderMap) -> Result<String, ApiAuthError> {
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
    use std::net::SocketAddr;
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
