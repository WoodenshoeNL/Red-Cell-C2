//! Exponential backoff for polling loops.
//!
//! Backoff starts at [`INITIAL_SECS`], doubles after each empty poll, and is
//! capped at [`MAX_SECS`].  A non-empty result resets it to [`INITIAL_SECS`].
//!
//! # Example
//!
//! ```rust,ignore
//! let mut backoff = Backoff::new();
//! loop {
//!     match poll().await {
//!         Ok(items) if items.is_empty() => backoff.record_empty(),
//!         Ok(_) => backoff.record_non_empty(),
//!         Err(_) => { /* handle error */ }
//!     }
//!     tokio::time::sleep(backoff.delay()).await;
//! }
//! ```

use std::time::Duration;

/// Initial polling interval, in seconds.
const INITIAL_SECS: u64 = 1;
/// Maximum polling interval, in seconds.
const MAX_SECS: u64 = 30;

/// Tracks the current backoff delay for a polling loop.
///
/// Call [`record_empty`][Backoff::record_empty] after a poll that returned no
/// useful data to double the delay (up to [`MAX_SECS`]).  Call
/// [`record_non_empty`][Backoff::record_non_empty] when data is found to reset
/// the delay to [`INITIAL_SECS`].  Read the current delay with
/// [`delay`][Backoff::delay] to obtain the `Duration` to sleep.
#[derive(Debug, Clone)]
pub struct Backoff {
    current: Duration,
}

impl Backoff {
    /// Create a new `Backoff` with the initial delay.
    pub fn new() -> Self {
        Self { current: Duration::from_secs(INITIAL_SECS) }
    }

    /// Create a new `Backoff` with a caller-specified initial delay.
    ///
    /// The initial delay is capped at [`MAX_SECS`] so all subsequent
    /// exponential growth stays within the documented bound.
    pub fn with_initial_delay(initial_secs: u64) -> Self {
        Self { current: Duration::from_secs(initial_secs.clamp(1, MAX_SECS)) }
    }

    /// Record an empty poll result: doubles the delay, capped at `MAX_SECS`.
    pub fn record_empty(&mut self) {
        let doubled = self.current.as_secs().saturating_mul(2);
        self.current = Duration::from_secs(doubled.min(MAX_SECS));
    }

    /// Record a non-empty poll result: resets the delay to `INITIAL_SECS`.
    pub fn record_non_empty(&mut self) {
        self.current = Duration::from_secs(INITIAL_SECS);
    }

    /// Return the current delay to sleep before the next poll.
    pub fn delay(&self) -> Duration {
        self.current
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_delay_is_one_second() {
        let b = Backoff::new();
        assert_eq!(b.delay(), Duration::from_secs(1));
    }

    #[test]
    fn record_empty_doubles_delay() {
        let mut b = Backoff::new();
        b.record_empty();
        assert_eq!(b.delay(), Duration::from_secs(2));
        b.record_empty();
        assert_eq!(b.delay(), Duration::from_secs(4));
    }

    #[test]
    fn record_empty_caps_at_max_secs() {
        let mut b = Backoff::new();
        // Exhaust the cap quickly.
        for _ in 0..10 {
            b.record_empty();
        }
        assert_eq!(b.delay(), Duration::from_secs(MAX_SECS));
        // Additional empties must not exceed the cap.
        b.record_empty();
        assert_eq!(b.delay(), Duration::from_secs(MAX_SECS));
    }

    #[test]
    fn record_non_empty_resets_to_initial() {
        let mut b = Backoff::new();
        b.record_empty();
        b.record_empty();
        assert_eq!(b.delay(), Duration::from_secs(4));
        b.record_non_empty();
        assert_eq!(b.delay(), Duration::from_secs(INITIAL_SECS));
    }

    #[test]
    fn delay_sequence_matches_expected_powers_of_two() {
        // Sequence: initial=1, then doubles each empty, capped at MAX_SECS=30.
        // Index i is the delay *after* i calls to record_empty.
        let expected: &[u64] = &[1, 2, 4, 8, 16, 30, 30];
        let mut b = Backoff::new();
        assert_eq!(b.delay().as_secs(), expected[0]);
        for &exp in &expected[1..] {
            b.record_empty();
            assert_eq!(b.delay().as_secs(), exp);
        }
    }

    #[test]
    fn default_produces_same_initial_as_new() {
        assert_eq!(Backoff::default().delay(), Backoff::new().delay());
    }

    #[test]
    fn with_initial_delay_uses_requested_delay_within_cap() {
        assert_eq!(Backoff::with_initial_delay(5).delay(), Duration::from_secs(5));
    }

    #[test]
    fn with_initial_delay_clamps_to_supported_range() {
        assert_eq!(Backoff::with_initial_delay(0).delay(), Duration::from_secs(1));
        assert_eq!(Backoff::with_initial_delay(99).delay(), Duration::from_secs(MAX_SECS));
    }
}
