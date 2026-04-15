//! Outbound audit webhook delivery.

mod delivery;
#[cfg(test)]
mod tests;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use red_cell_common::config::Profile;
use reqwest::StatusCode;
use thiserror::Error;
use tokio::sync::{Notify, Semaphore};
use tracing::warn;

use crate::AuditRecord;

use delivery::{
    DiscordWebhook, build_retry_delays, discord_webhook_client, is_transient_webhook_error,
};

const SUCCESS_COLOR: u32 = 0x002E_CC71;
const FAILURE_COLOR: u32 = 0x00E7_4C3C;
const DISCORD_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of concurrent in-flight detached delivery tasks.
///
/// When this limit is reached, new events are dropped with a warning rather
/// than allowing unbounded task accumulation under a slow/unavailable endpoint.
const MAX_CONCURRENT_DELIVERIES: usize = 256;

/// Default per-attempt backoff delays when no profile override is set.
///
/// Pattern: `base * 4^n` with `base = 1 s`.  Gives 1 s → 4 s → 16 s for three
/// retries (four total delivery attempts including the initial one).
const RETRY_DELAYS: [Duration; 3] =
    [Duration::from_secs(1), Duration::from_secs(4), Duration::from_secs(16)];

/// Best-effort outbound webhook dispatcher for audit events.
#[derive(Debug, Clone)]
pub struct AuditWebhookNotifier {
    discord: Option<Arc<DiscordWebhook>>,
    delivery_state: Arc<DeliveryState>,
    /// Counts permanent delivery failures (all retries exhausted) for the Discord webhook.
    discord_failure_count: Arc<AtomicU64>,
    /// Per-attempt backoff delays (first retry after delays[0], etc.).
    retry_delays: Arc<[Duration]>,
    /// Caps the number of concurrently in-flight detached delivery tasks.
    ///
    /// A task acquires one permit before being spawned and releases it when it
    /// completes (or is dropped).  Calls that cannot acquire a permit immediately
    /// drop the event with a warning instead of queuing it.
    delivery_semaphore: Arc<Semaphore>,
}

impl Default for AuditWebhookNotifier {
    fn default() -> Self {
        Self {
            discord: None,
            delivery_state: Arc::new(DeliveryState::default()),
            discord_failure_count: Arc::new(AtomicU64::new(0)),
            retry_delays: Arc::from(RETRY_DELAYS.as_slice()),
            delivery_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
        }
    }
}

impl AuditWebhookNotifier {
    /// Build a notifier from the loaded teamserver profile.
    #[must_use]
    pub fn from_profile(profile: &Profile) -> Self {
        let discord =
            profile.webhook.as_ref().and_then(|webhook| webhook.discord.as_ref()).and_then(
                |config| match discord_webhook_client() {
                    Ok(client) => Some(Arc::new(DiscordWebhook {
                        url: config.url.clone(),
                        username: config.user.clone(),
                        avatar_url: config.avatar_url.clone(),
                        client,
                    })),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "failed to build hardened Discord webhook client — \
                             webhook notifications disabled"
                        );
                        None
                    }
                },
            );

        let retry_delays = profile
            .webhook
            .as_ref()
            .and_then(|w| w.discord.as_ref())
            .map(|d| build_retry_delays(d.max_retries, d.retry_base_delay_secs))
            .unwrap_or_else(|| Arc::from(RETRY_DELAYS.as_slice()));

        Self {
            discord,
            delivery_state: Arc::new(DeliveryState::default()),
            discord_failure_count: Arc::new(AtomicU64::new(0)),
            retry_delays,
            delivery_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
        }
    }

    /// Return `true` when at least one outbound webhook is configured.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.discord.is_some()
    }

    /// Return the total number of permanent Discord webhook delivery failures
    /// (i.e. deliveries where all retry attempts were exhausted).
    #[must_use]
    pub fn discord_failure_count(&self) -> u64 {
        self.discord_failure_count.load(Ordering::Relaxed)
    }

    /// Build a notifier identical to [`from_profile`] but with no retry delays.
    ///
    /// Used in tests that assert on timing-sensitive shutdown behaviour so that
    /// a failing webhook does not introduce multi-second delays.
    #[doc(hidden)]
    pub fn from_profile_no_retry(profile: &Profile) -> Self {
        Self { retry_delays: Arc::from([]), ..Self::from_profile(profile) }
    }

    /// Simulate a pending webhook delivery that will never complete.
    ///
    /// Returns a guard that decrements the pending counter when dropped.
    /// Used to test shutdown timeout paths without real network I/O.
    #[cfg(feature = "test-helpers")]
    pub fn simulate_stuck_delivery(&self) -> StuckDeliveryGuard {
        self.delivery_state.pending.fetch_add(1, Ordering::SeqCst);
        StuckDeliveryGuard { delivery_state: self.delivery_state.clone() }
    }

    /// Emit a notification for a persisted audit record.
    pub async fn notify_audit_record(&self, record: &AuditRecord) -> Result<(), WebhookError> {
        if let Some(discord) = &self.discord {
            discord.send(record).await?;
        }

        Ok(())
    }

    /// Emit a notification for a persisted audit record without blocking the caller.
    ///
    /// Delivery is attempted up to `1 + retry_delays.len()` times.  Each retry
    /// is preceded by the corresponding element of `retry_delays` (default:
    /// 1 s, 2 s, 4 s).  If all attempts fail the permanent failure counter is
    /// incremented and a warning is logged; the event-dispatch loop is never
    /// blocked.
    pub fn notify_audit_record_detached(&self, record: AuditRecord) {
        if let Some(discord) = self.discord.clone() {
            // Increment pending *before* checking the closing flag so that shutdown()
            // cannot observe pending==0 and return between our flag-check and our
            // fetch_add.  If we then discover that closing was set concurrently we
            // undo the increment (and wake any waiting shutdown()) and discard the
            // record instead of spawning.
            self.delivery_state.pending.fetch_add(1, Ordering::SeqCst);

            if self.delivery_state.closing.load(Ordering::SeqCst) {
                self.delivery_state.pending.fetch_sub(1, Ordering::SeqCst);
                // Wake shutdown() if it started waiting between our fetch_add and our
                // load of closing.
                self.delivery_state.notify_if_drained();
                return;
            }

            // Enforce the concurrency cap.  try_acquire_owned() succeeds immediately
            // or returns an error — we never block the caller.
            let permit = match self.delivery_semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    // Cap exceeded: drop the event rather than accumulating tasks.
                    self.delivery_state.pending.fetch_sub(1, Ordering::SeqCst);
                    self.delivery_state.notify_if_drained();
                    warn!(
                        actor = record.actor,
                        action = record.action,
                        "webhook delivery dropped: concurrency cap ({MAX_CONCURRENT_DELIVERIES}) reached"
                    );
                    return;
                }
            };

            let delivery_state = self.delivery_state.clone();
            let failure_count = self.discord_failure_count.clone();
            let retry_delays = self.retry_delays.clone();
            tokio::spawn(async move {
                // Hold the permit for the full lifetime of this task.
                let _permit = permit;
                // Initial attempt.
                let mut last_err = match discord.send(&record).await {
                    Ok(()) => {
                        delivery_state.pending.fetch_sub(1, Ordering::SeqCst);
                        delivery_state.notify_if_drained();
                        return;
                    }
                    Err(e) => e,
                };

                // Retry with exponential backoff — transient errors only.
                // Non-transient errors (4xx client errors other than 429) are
                // permanent config/auth failures; retrying them is pointless.
                for &delay in retry_delays.iter() {
                    if !is_transient_webhook_error(&last_err) {
                        break;
                    }
                    tokio::time::sleep(delay).await;
                    match discord.send(&record).await {
                        Ok(()) => {
                            delivery_state.pending.fetch_sub(1, Ordering::SeqCst);
                            delivery_state.notify_if_drained();
                            return;
                        }
                        Err(e) => last_err = e,
                    }
                }

                // All attempts exhausted — record permanent failure.
                failure_count.fetch_add(1, Ordering::Relaxed);
                warn!(
                    actor = record.actor,
                    action = record.action,
                    error = %last_err,
                    "webhook delivery failed after all retries exhausted"
                );

                delivery_state.pending.fetch_sub(1, Ordering::SeqCst);
                delivery_state.notify_if_drained();
            });
        }
    }

    /// Stop accepting new detached deliveries and wait for in-flight webhook posts to complete.
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.delivery_state.closing.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + timeout;

        loop {
            if self.delivery_state.pending.load(Ordering::SeqCst) == 0 {
                return true;
            }

            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };

            if tokio::time::timeout(remaining, self.delivery_state.drained.notified())
                .await
                .is_err()
            {
                return self.delivery_state.pending.load(Ordering::SeqCst) == 0;
            }
        }
    }
}

/// RAII guard that simulates an in-flight webhook delivery for testing.
///
/// Dropping the guard decrements the pending counter and wakes any waiting
/// shutdown call so the test does not leak state.
#[cfg(feature = "test-helpers")]
#[derive(Debug)]
pub struct StuckDeliveryGuard {
    delivery_state: Arc<DeliveryState>,
}

#[cfg(feature = "test-helpers")]
impl Drop for StuckDeliveryGuard {
    fn drop(&mut self) {
        self.delivery_state.pending.fetch_sub(1, Ordering::SeqCst);
        self.delivery_state.notify_if_drained();
    }
}

#[derive(Debug, Default)]
struct DeliveryState {
    closing: AtomicBool,
    pending: AtomicUsize,
    drained: Notify,
}

impl DeliveryState {
    fn notify_if_drained(&self) {
        if self.pending.load(Ordering::SeqCst) == 0 {
            self.drained.notify_waiters();
        }
    }
}

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("failed to send Discord webhook request: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Discord webhook returned unexpected status {0}")]
    UnexpectedStatus(StatusCode),
}
