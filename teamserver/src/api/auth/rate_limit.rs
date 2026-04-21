//! Per-key and per-IP request rate limiting.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::ApiAuthError;
use super::key::ApiKeyDigest;

pub(super) const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RateLimitSubject {
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
pub(super) struct RateLimitWindow {
    pub(super) started_at: Instant,
    pub(super) request_count: u32,
}

impl Default for RateLimitWindow {
    fn default() -> Self {
        Self { started_at: Instant::now(), request_count: 0 }
    }
}

pub(super) fn prune_expired_rate_limit_windows(
    windows: &mut BTreeMap<RateLimitSubject, RateLimitWindow>,
    now: Instant,
) {
    windows.retain(|_, window| now.duration_since(window.started_at) < RATE_LIMIT_WINDOW);
}

pub(super) fn rate_limit_subject_for_failed_auth(
    client_ip: Option<IpAddr>,
    error: &ApiAuthError,
) -> RateLimitSubject {
    client_ip.map(RateLimitSubject::ClientIp).unwrap_or_else(|| match error {
        ApiAuthError::MissingApiKey => RateLimitSubject::MissingApiKey,
        ApiAuthError::InvalidAuthorizationHeader => RateLimitSubject::InvalidAuthorizationHeader,
        _ => unreachable!("only missing/invalid header auth errors map to failed auth buckets"),
    })
}
