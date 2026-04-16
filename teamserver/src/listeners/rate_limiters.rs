//! Sliding-window rate limiters used by listener runtimes.
//!
//! The limiters in this module gate abusive or noisy inbound traffic that
//! would otherwise amplify into database writes or operator-visible audit
//! events.  Each limiter keys on the identifier most useful for the traffic
//! shape (source IP, agent ID, or `listener\0external_ip`) and uses
//! [`AttemptWindow`] together with [`prune_expired_windows`] and
//! [`evict_oldest_windows`] for memory-bounded bookkeeping.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::rate_limiter::{AttemptWindow, evict_oldest_windows, prune_expired_windows};

pub(crate) const MAX_DEMON_INIT_ATTEMPTS_PER_IP: u32 = 5;
pub(crate) const DEMON_INIT_WINDOW_DURATION: Duration = Duration::from_secs(60);
pub(crate) const MAX_DEMON_INIT_ATTEMPT_WINDOWS: usize = 10_000;
pub(crate) const MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE: u32 = 1;
pub(crate) const UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION: Duration = Duration::from_secs(60);
pub(crate) const MAX_UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOWS: usize = 10_000;
pub(crate) const MAX_RECONNECT_PROBES_PER_AGENT: u32 = 10;
pub(crate) const RECONNECT_PROBE_WINDOW_DURATION: Duration = Duration::from_secs(60);
pub(crate) const MAX_RECONNECT_PROBE_WINDOWS: usize = 10_000;
/// Maximum number of AXFR/ANY recon queries from a single IP before it is silently dropped.
pub(crate) const MAX_DNS_RECON_QUERIES_PER_IP: u32 = 5;
/// Sliding-window duration for DNS AXFR/ANY recon rate limiting.
pub(crate) const DNS_RECON_WINDOW_DURATION: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Default)]
pub(crate) struct DemonInitRateLimiter {
    pub(super) windows: Arc<Mutex<HashMap<IpAddr, AttemptWindow>>>,
}

impl DemonInitRateLimiter {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn allow(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, DEMON_INIT_WINDOW_DURATION, now);
        if !windows.contains_key(&ip) && windows.len() >= MAX_DEMON_INIT_ATTEMPT_WINDOWS {
            evict_oldest_windows(&mut windows, MAX_DEMON_INIT_ATTEMPT_WINDOWS / 2);
        }

        let window = windows.entry(ip).or_default();
        if now.duration_since(window.window_start) >= DEMON_INIT_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        if window.attempts >= MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            return false;
        }

        window.attempts += 1;
        true
    }

    #[cfg(test)]
    pub(crate) async fn tracked_ip_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

/// Per-agent-ID sliding-window rate limiter for reconnect probes.
///
/// An empty `DEMON_INIT` payload is a lightweight reconnect probe.  Unlike full
/// registrations (gated by [`DemonInitRateLimiter`] per source IP), probes are
/// keyed by `agent_id` so that spamming from many IPs with the same agent ID is
/// still throttled.  Exceeding the limit results in an HTTP 429 response, making
/// the DoS signal visible to operators while avoiding the SQLite write that a
/// successful probe would trigger.
#[derive(Clone, Debug)]
pub(crate) struct ReconnectProbeRateLimiter {
    pub(super) windows: Arc<Mutex<HashMap<u32, AttemptWindow>>>,
    max_probes: u32,
}

impl Default for ReconnectProbeRateLimiter {
    fn default() -> Self {
        Self { windows: Arc::default(), max_probes: MAX_RECONNECT_PROBES_PER_AGENT }
    }
}

impl ReconnectProbeRateLimiter {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Create a rate limiter with a custom per-agent probe limit.
    #[must_use]
    pub(crate) fn with_max_probes(max_probes: u32) -> Self {
        Self { max_probes, ..Self::default() }
    }

    pub(crate) async fn allow(&self, agent_id: u32) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, RECONNECT_PROBE_WINDOW_DURATION, now);
        if !windows.contains_key(&agent_id) && windows.len() >= MAX_RECONNECT_PROBE_WINDOWS {
            evict_oldest_windows(&mut windows, MAX_RECONNECT_PROBE_WINDOWS / 2);
        }

        let window = windows.entry(agent_id).or_default();
        if now.duration_since(window.window_start) >= RECONNECT_PROBE_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        if window.attempts >= self.max_probes {
            return false;
        }

        window.attempts += 1;
        true
    }

    #[cfg(test)]
    pub(crate) async fn tracked_agent_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UnknownCallbackProbeAuditLimiter {
    pub(super) windows: Arc<Mutex<HashMap<String, AttemptWindow>>>,
}

impl UnknownCallbackProbeAuditLimiter {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn allow(&self, listener_name: &str, external_ip: &str) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();
        let source = format!("{listener_name}\0{external_ip}");

        prune_expired_windows(&mut windows, UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION, now);
        if !windows.contains_key(&source)
            && windows.len() >= MAX_UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOWS
        {
            let target_size = MAX_UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOWS / 2;
            evict_oldest_windows(&mut windows, target_size);
        }

        let window = windows.entry(source).or_default();
        if now.duration_since(window.window_start) >= UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        if window.attempts >= MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE {
            return false;
        }

        window.attempts += 1;
        true
    }

    #[cfg(test)]
    pub(crate) async fn tracked_source_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

/// Per-source-IP sliding-window rate limiter for DNS AXFR/ANY recon queries.
///
/// AXFR (zone transfer) and ANY queries have no legitimate use on our C2 DNS
/// listener and are indicators of active reconnaissance. This limiter tracks
/// how many such queries each IP has sent within the window and, once the
/// threshold is exceeded, returns `false` so the caller can drop further
/// queries without responding.
#[derive(Clone, Debug, Default)]
pub(crate) struct DnsReconBlockLimiter {
    pub(crate) windows: Arc<Mutex<HashMap<IpAddr, AttemptWindow>>>,
}

impl DnsReconBlockLimiter {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when the query should be allowed (below threshold).
    /// Returns `false` once the IP has sent more than
    /// [`MAX_DNS_RECON_QUERIES_PER_IP`] queries in the current window.
    pub(crate) async fn allow(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, DNS_RECON_WINDOW_DURATION, now);
        if !windows.contains_key(&ip) && windows.len() >= 10_000 {
            evict_oldest_windows(&mut windows, 5_000);
        }

        let window = windows.entry(ip).or_default();
        if now.duration_since(window.window_start) >= DNS_RECON_WINDOW_DURATION {
            window.attempts = 0;
            window.window_start = now;
        }

        if window.attempts >= MAX_DNS_RECON_QUERIES_PER_IP {
            return false;
        }

        window.attempts += 1;
        true
    }

    #[cfg(test)]
    pub(crate) async fn tracked_ip_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}
