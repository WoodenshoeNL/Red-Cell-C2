//! Shared sliding-window rate-limiter primitives.
//!
//! Both [`crate::listeners`] and [`crate::websocket`] maintain per-IP attempt
//! windows that share identical eviction and expiry logic.  This module
//! centralises those operations so a fix or policy change applies uniformly
//! to all callers.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A single sliding-window counter for one key.
///
/// Both `DemonInitRateLimiter` and `LoginRateLimiter` use this type as their
/// per-IP window value; the `attempts` field is interpreted differently by
/// each (accepted init requests vs. failed login attempts), but the window
/// bookkeeping is identical.
#[derive(Clone, Copy, Debug)]
pub struct AttemptWindow {
    /// Number of attempts recorded in this window.
    pub attempts: u32,
    /// When the current window started.
    pub window_start: Instant,
}

impl Default for AttemptWindow {
    fn default() -> Self {
        Self { attempts: 0, window_start: Instant::now() }
    }
}

/// Remove every entry whose window started more than `duration` ago.
pub fn prune_expired_windows<K>(
    windows: &mut HashMap<K, AttemptWindow>,
    duration: Duration,
    now: Instant,
) {
    windows.retain(|_, w| now.duration_since(w.window_start) < duration);
}

/// Reduce `windows` to at most `target_size` entries by removing the oldest.
///
/// Entries are ranked by `window_start`; the `to_remove` entries with the
/// earliest starts are dropped first.  Does nothing when
/// `windows.len() <= target_size`.
pub fn evict_oldest_windows<K: Eq + Hash + Copy>(
    windows: &mut HashMap<K, AttemptWindow>,
    target_size: usize,
) {
    if windows.len() <= target_size {
        return;
    }

    let to_remove = windows.len() - target_size;
    let mut entries: Vec<_> = windows.iter().map(|(k, w)| (*k, w.window_start)).collect();
    entries.sort_unstable_by_key(|(_, window_start)| *window_start);
    for (k, _) in entries.into_iter().take(to_remove) {
        windows.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::{AttemptWindow, evict_oldest_windows, prune_expired_windows};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn prune_removes_expired_keeps_fresh() {
        let mut windows: HashMap<IpAddr, AttemptWindow> = HashMap::new();
        let duration = Duration::from_secs(60);
        let now = Instant::now();

        windows.insert(
            ip(10, 0, 0, 1),
            AttemptWindow { attempts: 1, window_start: now - duration - Duration::from_secs(1) },
        );
        windows.insert(
            ip(10, 0, 0, 2),
            AttemptWindow { attempts: 1, window_start: now - Duration::from_secs(30) },
        );

        prune_expired_windows(&mut windows, duration, now);

        assert!(!windows.contains_key(&ip(10, 0, 0, 1)));
        assert!(windows.contains_key(&ip(10, 0, 0, 2)));
    }

    #[test]
    fn evict_removes_oldest_down_to_target() {
        let mut windows: HashMap<IpAddr, AttemptWindow> = HashMap::new();
        let base = Instant::now() - Duration::from_secs(100);
        for i in 0u8..10 {
            windows.insert(
                ip(10, 0, 0, i),
                AttemptWindow {
                    attempts: 1,
                    window_start: base + Duration::from_secs(u64::from(i)),
                },
            );
        }

        evict_oldest_windows(&mut windows, 5);

        assert_eq!(windows.len(), 5);
        // The 5 oldest (i = 0..4) must be gone; the 5 youngest (i = 5..9) must remain.
        for i in 0u8..5 {
            assert!(!windows.contains_key(&ip(10, 0, 0, i)));
        }
        for i in 5u8..10 {
            assert!(windows.contains_key(&ip(10, 0, 0, i)));
        }
    }

    #[test]
    fn evict_noop_when_at_or_below_target() {
        let mut windows: HashMap<IpAddr, AttemptWindow> = HashMap::new();
        windows.insert(ip(1, 2, 3, 4), AttemptWindow { attempts: 0, window_start: Instant::now() });

        evict_oldest_windows(&mut windows, 5);

        assert_eq!(windows.len(), 1);
    }
}
