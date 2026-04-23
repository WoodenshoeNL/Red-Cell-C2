//! Failed-auth attempt tracking for the REST API.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use super::rate_limit::RATE_LIMIT_WINDOW;
use crate::rate_limiter::{AttemptWindow, evict_oldest_windows, prune_expired_windows};

pub(crate) const MAX_FAILED_API_AUTH_ATTEMPTS: u32 = 5;
const MAX_API_AUTH_FAILURE_WINDOWS: usize = 10_000;

/// Shared tracker for per-IP failed REST API authentication attempts.
#[derive(Debug, Clone, Default)]
pub(super) struct AuthFailureTracker {
    windows: Arc<Mutex<HashMap<IpAddr, AttemptWindow>>>,
}

impl AuthFailureTracker {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Return `true` if the given IP has not exceeded the failed-auth attempt threshold.
    pub(super) async fn is_auth_failure_allowed(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
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
    pub(super) async fn record_auth_failure(&self, ip: IpAddr) {
        let mut windows = self.windows.lock().await;
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
    pub(super) async fn record_auth_success(&self, ip: IpAddr) {
        self.windows.lock().await.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    #[tokio::test]
    async fn auth_failure_n_minus_1_attempts_still_allowed() {
        let tracker = AuthFailureTracker::new();
        let ip = test_ip(1);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS - 1 {
            tracker.record_auth_failure(ip).await;
        }

        assert!(tracker.is_auth_failure_allowed(ip).await, "N-1 failures must still be allowed");
    }

    #[tokio::test]
    async fn auth_failure_nth_attempt_triggers_lockout() {
        let tracker = AuthFailureTracker::new();
        let ip = test_ip(2);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            tracker.record_auth_failure(ip).await;
        }

        assert!(!tracker.is_auth_failure_allowed(ip).await, "Nth failure must trigger lockout");
    }

    #[tokio::test]
    async fn auth_failure_unknown_ip_is_always_allowed() {
        let tracker = AuthFailureTracker::new();
        assert!(
            tracker.is_auth_failure_allowed(test_ip(99)).await,
            "IP with no failure history must be allowed"
        );
    }

    #[tokio::test]
    async fn auth_success_clears_failure_state() {
        let tracker = AuthFailureTracker::new();
        let ip = test_ip(3);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            tracker.record_auth_failure(ip).await;
        }
        assert!(!tracker.is_auth_failure_allowed(ip).await);

        tracker.record_auth_success(ip).await;

        assert!(
            tracker.is_auth_failure_allowed(ip).await,
            "successful auth must reset the failure counter"
        );

        let windows = tracker.windows.lock().await;
        assert!(!windows.contains_key(&ip), "window entry must be removed on success");
    }

    #[tokio::test]
    async fn auth_failure_window_expiry_resets_allowance() {
        let tracker = AuthFailureTracker::new();
        let ip = test_ip(4);

        {
            let mut windows = tracker.windows.lock().await;
            windows.insert(
                ip,
                AttemptWindow {
                    attempts: MAX_FAILED_API_AUTH_ATTEMPTS + 10,
                    window_start: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
                },
            );
        }

        assert!(
            tracker.is_auth_failure_allowed(ip).await,
            "expired window must be pruned, allowing the IP again"
        );

        let windows = tracker.windows.lock().await;
        assert!(!windows.contains_key(&ip), "expired window must be removed");
    }

    #[tokio::test]
    async fn auth_failure_record_resets_window_after_expiry() {
        let tracker = AuthFailureTracker::new();
        let ip = test_ip(5);

        {
            let mut windows = tracker.windows.lock().await;
            windows.insert(
                ip,
                AttemptWindow {
                    attempts: MAX_FAILED_API_AUTH_ATTEMPTS,
                    window_start: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
                },
            );
        }

        tracker.record_auth_failure(ip).await;

        let windows = tracker.windows.lock().await;
        let window = windows.get(&ip).expect("window must exist after recording failure");
        assert_eq!(window.attempts, 1, "expired window must reset to 1 attempt");
    }

    #[tokio::test]
    async fn auth_failure_sequential_from_same_ip_count_correctly() {
        let tracker = AuthFailureTracker::new();
        let ip = test_ip(6);

        for expected in 1..=MAX_FAILED_API_AUTH_ATTEMPTS {
            tracker.record_auth_failure(ip).await;
            let windows = tracker.windows.lock().await;
            let window = windows.get(&ip).expect("window must exist");
            assert_eq!(
                window.attempts, expected,
                "attempt count must equal {expected} after {expected} sequential failures"
            );
        }
    }

    #[tokio::test]
    async fn auth_failure_different_ips_are_independent() {
        let tracker = AuthFailureTracker::new();
        let ip_a = test_ip(10);
        let ip_b = test_ip(11);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            tracker.record_auth_failure(ip_a).await;
        }

        assert!(!tracker.is_auth_failure_allowed(ip_a).await);
        assert!(tracker.is_auth_failure_allowed(ip_b).await);
    }

    #[tokio::test]
    async fn auth_failure_success_on_one_ip_does_not_affect_another() {
        let tracker = AuthFailureTracker::new();
        let ip_a = test_ip(20);
        let ip_b = test_ip(21);

        for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
            tracker.record_auth_failure(ip_a).await;
            tracker.record_auth_failure(ip_b).await;
        }

        tracker.record_auth_success(ip_a).await;

        assert!(tracker.is_auth_failure_allowed(ip_a).await);
        assert!(!tracker.is_auth_failure_allowed(ip_b).await);
    }
}
