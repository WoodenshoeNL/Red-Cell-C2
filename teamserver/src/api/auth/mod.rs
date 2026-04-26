//! REST API authentication, authorization, and rate-limiting.

mod auth_failure;
mod authorization;
mod key;
mod rate_limit;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use subtle::ConstantTimeEq;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use red_cell_common::config::{OperatorRole, Profile};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, instrument};
use utoipa::ToSchema;

use super::errors::json_error_response;

use auth_failure::AuthFailureTracker;
use key::{API_KEY_HASH_SECRET_SIZE, ApiKeyDigest, generate_key_hash_secret, hash_api_key};
use rate_limit::{
    RATE_LIMIT_WINDOW, RateLimitSubject, RateLimitWindow, prune_expired_rate_limit_windows,
    rate_limit_subject_for_failed_auth,
};

// Re-export items used by sibling modules within `api`.
pub use authorization::{
    AdminApiAccess, ApiPermissionGuard, ListenerManagementApiAccess, ReadApiAccess,
    TaskAgentApiAccess,
};
pub(crate) use key::{API_KEY_HEADER, extract_api_key};
pub use rate_limit::ApiRateLimit;
#[cfg(test)]
pub(crate) const MAX_FAILED_API_AUTH_ATTEMPTS: u32 = auth_failure::MAX_FAILED_API_AUTH_ATTEMPTS;

/// How the caller authenticated to the REST API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Authenticated via a static API key in the `X-API-Key` header.
    ApiKey,
}

/// Authenticated REST API identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiIdentity {
    /// Stable key identifier from the profile.
    pub key_id: String,
    /// RBAC role granted to the key.
    pub role: OperatorRole,
    /// How this identity was authenticated.
    pub auth_method: AuthMethod,
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
    auth_failure_tracker: AuthFailureTracker,
}

impl ApiRuntime {
    /// Build REST API runtime state from a validated profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS random-number generator is unavailable when
    /// generating the HMAC secret used to hash API keys.
    pub fn from_profile(profile: &Profile) -> Result<Self, crate::TeamserverError> {
        let key_hash_secret = Arc::new(generate_key_hash_secret()?);
        let (keys, requests_per_minute) = profile
            .api
            .as_ref()
            .map(|config| {
                let keys = config
                    .keys
                    .iter()
                    .map(|(name, key)| {
                        (
                            hash_api_key(&key_hash_secret, &key.value),
                            ApiIdentity {
                                key_id: name.clone(),
                                role: key.role,
                                auth_method: AuthMethod::ApiKey,
                            },
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
            auth_failure_tracker: AuthFailureTracker::new(),
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
            if !self.auth_failure_tracker.is_auth_failure_allowed(ip).await {
                return Err(ApiAuthError::RateLimited {
                    retry_after_seconds: RATE_LIMIT_WINDOW.as_secs(),
                });
            }
        }

        let presented_key = match key::extract_api_key(headers) {
            Ok(k) => k,
            Err(
                error @ (ApiAuthError::MissingApiKey | ApiAuthError::InvalidAuthorizationHeader),
            ) => {
                self.check_rate_limit(&rate_limit_subject_for_failed_auth(client_ip, &error))
                    .await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        let presented_key_digest = hash_api_key(&self.key_hash_secret, &presented_key);
        let rate_limit_subject = RateLimitSubject::PresentedCredential(presented_key_digest);

        self.check_rate_limit(&rate_limit_subject).await?;

        match Self::lookup_key_ct(&self.keys, &presented_key_digest) {
            Some(identity) => {
                if let Some(ip) = client_ip {
                    self.auth_failure_tracker.record_auth_success(ip).await;
                }
                Ok(identity)
            }
            None => {
                if let Some(ip) = client_ip {
                    self.auth_failure_tracker.record_auth_failure(ip).await;
                }
                Err(ApiAuthError::InvalidApiKey)
            }
        }
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

fn client_ip(request: &Request) -> Option<IpAddr> {
    use std::net::SocketAddr;
    request.extensions().get::<ConnectInfo<SocketAddr>>().map(|connect_info| connect_info.0.ip())
}

#[cfg(test)]
mod tests {
    use super::key::ApiKeyDigest;
    use super::rate_limit::{ApiRateLimit, RATE_LIMIT_WINDOW, RateLimitSubject, RateLimitWindow};
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn make_digest(byte: u8) -> ApiKeyDigest {
        ApiKeyDigest([byte; 32])
    }

    fn make_identity(key_id: &str) -> ApiIdentity {
        ApiIdentity {
            key_id: key_id.to_owned(),
            role: OperatorRole::Analyst,
            auth_method: AuthMethod::ApiKey,
        }
    }

    fn test_api_runtime(requests_per_minute: u32) -> ApiRuntime {
        ApiRuntime {
            key_hash_secret: Arc::new(
                generate_key_hash_secret().expect("rng should work in tests"),
            ),
            keys: Arc::new(Vec::new()),
            rate_limit: ApiRateLimit { requests_per_minute },
            windows: Arc::new(Mutex::new(BTreeMap::new())),
            auth_failure_tracker: AuthFailureTracker::new(),
        }
    }

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    // ---- lookup_key_ct unit tests ----

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
        let digest = make_digest(0x42);
        let keys = vec![(digest, make_identity("first")), (digest, make_identity("second"))];
        let result = ApiRuntime::lookup_key_ct(&keys, &digest);
        assert_eq!(result.expect("unwrap").key_id, "second");
    }

    // ---- rate_limiting_prunes_expired_windows unit test ----

    #[tokio::test]
    async fn rate_limiting_prunes_expired_windows_for_inactive_keys() {
        let secret = Arc::new(generate_key_hash_secret().expect("rng should work in tests"));
        let api = ApiRuntime {
            key_hash_secret: Arc::clone(&secret),
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
            auth_failure_tracker: AuthFailureTracker::new(),
        };

        api.check_rate_limit(&RateLimitSubject::PresentedCredential(hash_api_key(
            &secret, "new-key",
        )))
        .await
        .expect("rate limit should allow request");

        let windows = api.windows.lock().await;
        assert!(!windows.contains_key(&RateLimitSubject::MissingApiKey));
        assert!(windows.contains_key(&RateLimitSubject::InvalidAuthorizationHeader));
        assert!(windows.contains_key(&RateLimitSubject::PresentedCredential(hash_api_key(
            &secret, "new-key"
        ))));
        assert_eq!(windows.len(), 2);
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
        let api = test_api_runtime(0);
        let subject = RateLimitSubject::ClientIp(test_ip(3));

        for _ in 0..100 {
            assert!(api.check_rate_limit(&subject).await.is_ok());
        }
    }

    #[tokio::test]
    async fn rate_limit_window_expiry_resets_count() {
        let api = test_api_runtime(2);
        let subject = RateLimitSubject::ClientIp(test_ip(4));

        for _ in 0..2 {
            api.check_rate_limit(&subject).await.expect("should be allowed");
        }
        assert!(api.check_rate_limit(&subject).await.is_err());

        {
            let mut windows = api.windows.lock().await;
            if let Some(w) = windows.get_mut(&subject) {
                w.started_at = Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1);
            }
        }

        assert!(
            api.check_rate_limit(&subject).await.is_ok(),
            "request must be allowed after window expiry"
        );

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

        assert!(api.check_rate_limit(&subject_b).await.is_ok(), "B must be independent");
    }

    #[tokio::test]
    async fn two_api_keys_from_same_ip_do_not_share_rate_limit_bucket() {
        let api = test_api_runtime(2);
        let key_a = RateLimitSubject::PresentedCredential(make_digest(0xAA));
        let key_b = RateLimitSubject::PresentedCredential(make_digest(0xBB));

        for _ in 0..2 {
            api.check_rate_limit(&key_a).await.expect("key A should be allowed");
        }
        assert!(
            api.check_rate_limit(&key_a).await.is_err(),
            "key A must be rate-limited after exhausting its quota"
        );

        for _ in 0..2 {
            api.check_rate_limit(&key_b)
                .await
                .expect("key B must not be affected by key A's exhausted quota");
        }
        assert!(
            api.check_rate_limit(&key_b).await.is_err(),
            "key B must be rate-limited after exhausting its own quota"
        );
    }
}
