//! Outbound audit webhook delivery.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use red_cell_common::config::Profile;
use reqwest::StatusCode;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{Notify, Semaphore};
use tracing::warn;

use crate::{AuditRecord, AuditResultStatus};

const SUCCESS_COLOR: u32 = 0x002E_CC71;
const FAILURE_COLOR: u32 = 0x00E7_4C3C;
const DISCORD_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of concurrent in-flight detached delivery tasks.
///
/// When this limit is reached, new events are dropped with a warning rather
/// than allowing unbounded task accumulation under a slow/unavailable endpoint.
const MAX_CONCURRENT_DELIVERIES: usize = 256;

/// Backoff delays for webhook retries: 1 s, 2 s, 4 s (up to 3 retries).
const RETRY_DELAYS: [Duration; 3] =
    [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4)];

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

        Self {
            discord,
            delivery_state: Arc::new(DeliveryState::default()),
            discord_failure_count: Arc::new(AtomicU64::new(0)),
            retry_delays: Arc::from(RETRY_DELAYS.as_slice()),
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

                // Retry with exponential backoff.
                for &delay in retry_delays.iter() {
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

fn discord_webhook_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(DISCORD_WEBHOOK_TIMEOUT)
        // Disable redirects: a redirect-following client can be used to pivot to internal
        // services (SSRF) if an attacker controls DNS for the configured webhook hostname.
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[derive(Debug)]
struct DiscordWebhook {
    url: String,
    username: Option<String>,
    avatar_url: Option<String>,
    client: reqwest::Client,
}

impl DiscordWebhook {
    async fn send(&self, record: &AuditRecord) -> Result<(), WebhookError> {
        let response = self
            .client
            .post(&self.url)
            .json(&DiscordWebhookPayload::from_record(
                record,
                self.username.as_deref(),
                self.avatar_url.as_deref(),
            ))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(WebhookError::UnexpectedStatus(response.status()))
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

#[derive(Debug, Serialize)]
struct DiscordWebhookPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_url: Option<&'a str>,
    embeds: Vec<DiscordEmbed<'a>>,
}

impl<'a> DiscordWebhookPayload<'a> {
    fn from_record(
        record: &'a AuditRecord,
        username: Option<&'a str>,
        avatar_url: Option<&'a str>,
    ) -> Self {
        Self { username, avatar_url, embeds: vec![DiscordEmbed::from_record(record)] }
    }
}

#[derive(Debug, Serialize)]
struct DiscordEmbed<'a> {
    title: &'a str,
    description: String,
    color: u32,
    fields: Vec<DiscordField>,
    timestamp: &'a str,
}

impl<'a> DiscordEmbed<'a> {
    fn from_record(record: &'a AuditRecord) -> Self {
        let actor = sanitize_discord_text(&record.actor);
        let action = sanitize_discord_text(&record.action);
        let target_kind = sanitize_discord_text(&record.target_kind);

        let mut fields = vec![
            DiscordField::new("Actor", actor.clone(), true),
            DiscordField::new("Action", action.clone(), true),
            DiscordField::new("Target", target_kind.clone(), true),
            DiscordField::new("Result", record.result_status.as_str().to_owned(), true),
        ];

        if let Some(target_id) = &record.target_id {
            fields.push(DiscordField::new("Target ID", sanitize_discord_text(target_id), true));
        }

        if let Some(agent_id) = &record.agent_id {
            fields.push(DiscordField::new("Agent ID", sanitize_discord_text(agent_id), true));
        }

        if let Some(command) = &record.command {
            fields.push(DiscordField::new("Command", sanitize_discord_text(command), true));
        }

        if let Some(parameters) = &record.parameters {
            fields.push(DiscordField::new("Parameters", parameters.to_string(), false));
        }

        Self {
            title: "Red Cell audit event",
            description: format!("{actor} recorded `{action}` against `{target_kind}`."),
            color: if record.result_status == AuditResultStatus::Success {
                SUCCESS_COLOR
            } else {
                FAILURE_COLOR
            },
            fields,
            timestamp: &record.occurred_at,
        }
    }
}

/// Sanitize a string for safe embedding in Discord messages.
///
/// Strips characters and patterns that could break embed formatting or trigger
/// unintended Discord mentions:
/// - Backticks are removed (would break inline-code delimiters in the description).
/// - Newlines and carriage returns are replaced with spaces.
/// - `@everyone` and `@here` are defused by inserting a zero-width space after `@`.
/// - Angle-bracket mention syntax (`<@…>`, `<@&…>`, `<#…>`) is defused by
///   inserting a zero-width space before `<` so Discord does not parse them as mentions.
fn sanitize_discord_text(input: &str) -> String {
    let mut result = input.replace('`', "").replace(['\n', '\r'], " ");
    // Defuse broadcast mentions by inserting a zero-width space (U+200B) after @.
    result = result.replace("@everyone", "@\u{200b}everyone");
    result = result.replace("@here", "@\u{200b}here");
    // Defuse user/role/channel mention syntax: <@id>, <@&id>, <#id>.
    result = result.replace("<@", "\u{200b}<@");
    result = result.replace("<#", "\u{200b}<#");
    result
}

#[derive(Debug, Serialize)]
struct DiscordField {
    name: String,
    value: String,
    inline: bool,
}

impl DiscordField {
    fn new(name: &str, value: String, inline: bool) -> Self {
        Self { name: name.to_owned(), value, inline }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use axum::{Json, Router, http::StatusCode as HttpStatusCode, routing::post};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;
    use tokio::sync::{Semaphore, mpsc};

    use super::{AuditWebhookNotifier, WebhookError};
    use crate::{AuditRecord, AuditResultStatus};
    use red_cell_common::config::Profile;

    #[tokio::test]
    async fn notifier_is_disabled_without_webhook_profile() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "operator" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let notifier = AuditWebhookNotifier::from_profile(&profile);

        assert!(!notifier.is_enabled());
    }

    #[tokio::test]
    async fn discord_notifier_posts_embedded_audit_payload() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
                User = "Red Cell"
                AvatarUrl = "https://example.test/red-cell.png"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        notifier
            .notify_audit_record(&AuditRecord {
                id: 7,
                actor: "operator".to_owned(),
                action: "agent.task".to_owned(),
                target_kind: "agent".to_owned(),
                target_id: Some("DEADBEEF".to_owned()),
                agent_id: Some("DEADBEEF".to_owned()),
                command: Some("shell".to_owned()),
                parameters: Some(json!({"command": "whoami"})),
                result_status: AuditResultStatus::Success,
                occurred_at: "2026-03-11T10:00:00Z".to_owned(),
            })
            .await
            .expect("webhook delivery should succeed");

        let payload = receiver.recv().await.expect("payload should arrive");
        server.abort();

        assert_eq!(payload["username"], "Red Cell");
        assert_eq!(payload["avatar_url"], "https://example.test/red-cell.png");
        assert_eq!(payload["embeds"][0]["title"], "Red Cell audit event");
        assert_eq!(payload["embeds"][0]["color"], json!(super::SUCCESS_COLOR));
        assert_eq!(payload["embeds"][0]["fields"][0]["name"], "Actor");
        assert_eq!(payload["embeds"][0]["fields"][0]["value"], "operator");
        let command_field = payload["embeds"][0]["fields"]
            .as_array()
            .expect("embed fields should be an array")
            .iter()
            .find(|field| field["name"] == "Command")
            .expect("command field should be present");
        assert_eq!(command_field["value"], "shell");
    }

    #[tokio::test]
    async fn discord_embed_color_is_failure_color_for_failure_record() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        notifier
            .notify_audit_record(&AuditRecord {
                id: 12,
                actor: "operator".to_owned(),
                action: "agent.task".to_owned(),
                target_kind: "agent".to_owned(),
                target_id: Some("DEADBEEF".to_owned()),
                agent_id: Some("DEADBEEF".to_owned()),
                command: Some("shell".to_owned()),
                parameters: Some(json!({"command": "whoami"})),
                result_status: AuditResultStatus::Failure,
                occurred_at: "2026-03-14T10:00:00Z".to_owned(),
            })
            .await
            .expect("webhook delivery should succeed");

        let payload = receiver.recv().await.expect("payload should arrive");
        server.abort();

        assert_eq!(payload["embeds"][0]["color"], json!(super::FAILURE_COLOR));
    }

    #[tokio::test]
    async fn discord_payload_omits_username_and_avatar_url_when_none() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        notifier
            .notify_audit_record(&sample_record(80))
            .await
            .expect("webhook delivery should succeed");

        let payload = receiver.recv().await.expect("payload should arrive");
        server.abort();

        assert!(
            payload.get("username").is_none(),
            "username must be omitted when None; got: {payload}"
        );
        assert!(
            payload.get("avatar_url").is_none(),
            "avatar_url must be omitted when None; got: {payload}"
        );
        // Embeds should still be present.
        assert!(payload["embeds"][0]["title"].is_string());
    }

    #[tokio::test]
    async fn notifier_shutdown_waits_for_detached_delivery() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        notifier.notify_audit_record_detached(AuditRecord {
            id: 8,
            actor: "operator".to_owned(),
            action: "operator.login".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("operator".to_owned()),
            agent_id: None,
            command: Some("login".to_owned()),
            parameters: None,
            result_status: AuditResultStatus::Success,
            occurred_at: "2026-03-12T00:00:00Z".to_owned(),
        });

        assert!(notifier.shutdown(Duration::from_secs(5)).await);
        let payload = receiver.recv().await.expect("payload should arrive");
        server.abort();

        assert_eq!(payload["embeds"][0]["fields"][0]["value"], "operator");
    }

    #[tokio::test]
    async fn discord_notifier_returns_unexpected_status_for_non_success_response() {
        let (address, _receiver, server) = webhook_server(HttpStatusCode::TOO_MANY_REQUESTS).await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        let result = notifier
            .notify_audit_record(&AuditRecord {
                id: 9,
                actor: "operator".to_owned(),
                action: "agent.task".to_owned(),
                target_kind: "agent".to_owned(),
                target_id: Some("DEADBEEF".to_owned()),
                agent_id: Some("DEADBEEF".to_owned()),
                command: Some("shell".to_owned()),
                parameters: Some(json!({"command": "hostname"})),
                result_status: AuditResultStatus::Failure,
                occurred_at: "2026-03-12T08:00:00Z".to_owned(),
            })
            .await;
        server.abort();

        assert!(matches!(
            result,
            Err(WebhookError::UnexpectedStatus(status))
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
    }

    #[tokio::test]
    async fn notifier_shutdown_drains_detached_delivery_after_webhook_failure() {
        let (address, _receiver, server) =
            webhook_server(HttpStatusCode::INTERNAL_SERVER_ERROR).await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        // Use no-retry variant so the 500 response resolves immediately and
        // shutdown() is not delayed by the default 1 s + 2 s + 4 s backoff.
        let notifier = AuditWebhookNotifier::from_profile_no_retry(&profile);

        notifier.notify_audit_record_detached(AuditRecord {
            id: 10,
            actor: "operator".to_owned(),
            action: "operator.login".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("operator".to_owned()),
            agent_id: None,
            command: Some("login".to_owned()),
            parameters: None,
            result_status: AuditResultStatus::Failure,
            occurred_at: "2026-03-12T08:30:00Z".to_owned(),
        });

        assert!(notifier.shutdown(Duration::from_secs(5)).await);
        server.abort();
    }

    #[tokio::test]
    async fn notify_detached_is_dropped_when_closing() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        // Trigger shutdown — sets closing=true and returns immediately (no in-flight tasks).
        assert!(notifier.shutdown(Duration::from_secs(5)).await);

        // Any subsequent detached notification must be silently dropped.
        notifier.notify_audit_record_detached(AuditRecord {
            id: 11,
            actor: "operator".to_owned(),
            action: "operator.login".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("operator".to_owned()),
            agent_id: None,
            command: Some("login".to_owned()),
            parameters: None,
            result_status: AuditResultStatus::Success,
            occurred_at: "2026-03-14T00:00:00Z".to_owned(),
        });

        // Yield to the executor so any erroneously-spawned tasks get a chance to run.
        tokio::task::yield_now().await;

        // No POST should have reached the mock server.
        assert!(receiver.try_recv().is_err(), "no request should be sent after shutdown");

        // A second shutdown should also return true immediately (pending count was never
        // incremented by the dropped notification).
        assert!(notifier.shutdown(Duration::from_secs(1)).await);

        server.abort();
    }

    #[tokio::test]
    async fn shutdown_returns_true_immediately_when_notifier_is_disabled() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "operator" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let notifier = AuditWebhookNotifier::from_profile(&profile);
        assert!(!notifier.is_enabled(), "notifier should be disabled");

        // shutdown should resolve immediately — wrap in a tight timeout to catch any hang
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            notifier.shutdown(Duration::from_secs(1)),
        )
        .await
        .expect("shutdown should complete well before the outer timeout");

        assert!(result, "shutdown should return true when notifier is disabled");
    }

    /// Regression test for the shutdown race described in red-cell-c2-2me2.
    ///
    /// Verifies that `shutdown` returning `true` means *all* deliveries that were
    /// accepted (i.e. that incremented pending) have fully completed, even when
    /// `shutdown` is called concurrently with `notify_audit_record_detached`.
    #[tokio::test]
    async fn shutdown_does_not_return_true_while_delivery_still_pending() {
        // Use a slow webhook server: the handler sleeps briefly so the spawned
        // task is guaranteed to be in-flight when shutdown is called.
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<Value>();
        let app = Router::new().route(
            "/",
            post(move |Json(payload): Json<Value>| {
                let sender = sender.clone();
                async move {
                    // Small delay to keep the task in-flight long enough.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let _ = sender.send(payload);
                    (HttpStatusCode::OK, Json(json!({"ok": true})))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener address should resolve");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test webhook server should not fail");
        });

        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        // Fire a detached notification so it is in-flight (pending > 0).
        notifier.notify_audit_record_detached(AuditRecord {
            id: 20,
            actor: "operator".to_owned(),
            action: "operator.login".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: None,
            agent_id: None,
            command: None,
            parameters: None,
            result_status: AuditResultStatus::Success,
            occurred_at: "2026-03-15T00:00:00Z".to_owned(),
        });

        // shutdown must wait until the in-flight delivery finishes.
        let drained = notifier.shutdown(Duration::from_secs(5)).await;
        assert!(drained, "shutdown should report all deliveries complete");

        // The delivery must have actually reached the mock server.
        let mut rx = receiver;
        assert!(
            rx.try_recv().is_ok(),
            "webhook delivery must complete before shutdown returns true"
        );

        server.abort();
    }

    /// Webhook that fails on the first `fail_count` requests then succeeds.
    async fn flaky_webhook_server(
        fail_count: usize,
    ) -> (SocketAddr, mpsc::UnboundedReceiver<Value>, tokio::task::JoinHandle<()>) {
        use std::sync::atomic::AtomicUsize;
        let (sender, receiver) = mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/",
            post(move |Json(payload): Json<Value>| {
                let sender = sender.clone();
                let attempts = attempts.clone();
                async move {
                    let n = attempts.fetch_add(1, Ordering::Relaxed);
                    if n < fail_count {
                        (HttpStatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false})))
                    } else {
                        let _ = sender.send(payload);
                        (HttpStatusCode::OK, Json(json!({"ok": true})))
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener address should resolve");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test webhook server should not fail");
        });

        (address, receiver, server)
    }

    async fn webhook_server(
        response_status: HttpStatusCode,
    ) -> (SocketAddr, mpsc::UnboundedReceiver<Value>, tokio::task::JoinHandle<()>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/",
            post(move |Json(payload): Json<Value>| {
                let sender = sender.clone();
                let response_status = response_status;
                async move {
                    let _ = sender.send(payload);
                    (response_status, Json(json!({"ok": true})))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener address should resolve");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test webhook server should not fail");
        });

        (address, receiver, server)
    }

    /// Build a test profile pointing at the given address with a Discord webhook.
    fn discord_profile(address: SocketAddr) -> Profile {
        Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse")
    }

    fn sample_record(id: i64) -> AuditRecord {
        AuditRecord {
            id,
            actor: "operator".to_owned(),
            action: "operator.login".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: None,
            agent_id: None,
            command: None,
            parameters: None,
            result_status: AuditResultStatus::Success,
            occurred_at: "2026-03-15T00:00:00Z".to_owned(),
        }
    }

    /// Delivery that fails once then succeeds on the first retry should still
    /// deliver the record and not increment the failure counter.
    #[tokio::test]
    async fn retry_succeeds_on_second_attempt() {
        // Server fails the first request, accepts the second.
        let (address, mut receiver, server) = flaky_webhook_server(1).await;
        // Use zero-delay retries so the test runs instantly.
        let notifier = AuditWebhookNotifier {
            retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
            ..AuditWebhookNotifier::from_profile(&discord_profile(address))
        };

        notifier.notify_audit_record_detached(sample_record(30));
        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

        assert!(receiver.try_recv().is_ok(), "record must arrive after successful retry");
        assert_eq!(notifier.discord_failure_count(), 0, "no permanent failure on successful retry");

        server.abort();
    }

    /// When all attempts fail the permanent failure counter must be incremented
    /// and no payload should reach the webhook server after the final attempt.
    #[tokio::test]
    async fn failure_counter_increments_after_all_retries_exhausted() {
        let (address, _receiver, server) =
            webhook_server(HttpStatusCode::INTERNAL_SERVER_ERROR).await;
        // Three retries, all instantly, so we get 4 total attempts.
        let notifier = AuditWebhookNotifier {
            retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
            ..AuditWebhookNotifier::from_profile(&discord_profile(address))
        };

        notifier.notify_audit_record_detached(sample_record(31));
        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

        assert_eq!(notifier.discord_failure_count(), 1, "one permanent failure should be recorded");

        server.abort();
    }

    /// Sending two records where both exhaust all retries increments the counter
    /// to 2, not 1.
    #[tokio::test]
    async fn failure_counter_accumulates_across_multiple_failures() {
        let (address, _receiver, server) =
            webhook_server(HttpStatusCode::INTERNAL_SERVER_ERROR).await;
        let notifier = AuditWebhookNotifier {
            retry_delays: Arc::from([].as_slice()),
            ..AuditWebhookNotifier::from_profile(&discord_profile(address))
        };

        notifier.notify_audit_record_detached(sample_record(40));
        notifier.notify_audit_record_detached(sample_record(41));
        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

        assert_eq!(notifier.discord_failure_count(), 2);

        server.abort();
    }

    /// Build a notifier with a custom reqwest client timeout and no retries.
    ///
    /// Used by transport-level failure tests that need fast timeouts instead of
    /// the production 5-second default.
    fn notifier_with_timeout(address: SocketAddr, timeout: Duration) -> AuditWebhookNotifier {
        use std::sync::atomic::AtomicU64;

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client should build");
        AuditWebhookNotifier {
            discord: Some(Arc::new(super::DiscordWebhook {
                url: format!("http://{address}/"),
                username: None,
                avatar_url: None,
                client,
            })),
            delivery_state: Arc::new(super::DeliveryState::default()),
            discord_failure_count: Arc::new(AtomicU64::new(0)),
            retry_delays: Arc::from([].as_slice()),
            delivery_semaphore: Arc::new(Semaphore::new(super::MAX_CONCURRENT_DELIVERIES)),
        }
    }

    /// Synchronous delivery to a refused port must return `WebhookError::Request`.
    #[tokio::test]
    async fn notify_audit_record_returns_request_error_on_connection_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let address = listener.local_addr().expect("should resolve");
        drop(listener);

        let notifier = notifier_with_timeout(address, Duration::from_secs(1));
        let result = notifier.notify_audit_record(&sample_record(60)).await;

        assert!(
            matches!(result, Err(WebhookError::Request(_))),
            "connection refusal should produce WebhookError::Request, got {result:?}"
        );
    }

    /// Detached delivery to a refused port must drain on shutdown and increment
    /// the permanent failure counter.
    #[tokio::test]
    async fn detached_delivery_increments_failure_count_on_connection_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let address = listener.local_addr().expect("should resolve");
        drop(listener);

        let notifier = notifier_with_timeout(address, Duration::from_secs(1));
        notifier.notify_audit_record_detached(sample_record(61));
        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
        assert_eq!(
            notifier.discord_failure_count(),
            1,
            "permanent failure should be recorded after connection refusal"
        );
    }

    /// Synchronous delivery to a server that accepts but never responds must
    /// return `WebhookError::Request` once the client timeout elapses.
    #[tokio::test]
    async fn notify_audit_record_returns_request_error_on_client_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let address = listener.local_addr().expect("should resolve");
        let server = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    drop(socket);
                });
            }
        });

        let notifier = notifier_with_timeout(address, Duration::from_millis(100));
        let result = notifier.notify_audit_record(&sample_record(62)).await;

        assert!(
            matches!(result, Err(WebhookError::Request(_))),
            "client timeout should produce WebhookError::Request, got {result:?}"
        );
        server.abort();
    }

    /// Detached delivery to a stalling server must drain on shutdown and
    /// increment the permanent failure counter once the client timeout fires.
    #[tokio::test]
    async fn detached_delivery_increments_failure_count_on_client_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let address = listener.local_addr().expect("should resolve");
        let server = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    drop(socket);
                });
            }
        });

        let notifier = notifier_with_timeout(address, Duration::from_millis(100));
        notifier.notify_audit_record_detached(sample_record(63));
        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
        assert_eq!(
            notifier.discord_failure_count(),
            1,
            "permanent failure should be recorded after client timeout"
        );
        server.abort();
    }

    /// Retries must all be attempted before the failure counter increments,
    /// even when the underlying error is a transport-level connection refusal.
    #[tokio::test]
    async fn detached_retries_exhaust_on_connection_refused_before_incrementing_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let address = listener.local_addr().expect("should resolve");
        drop(listener);

        let notifier = AuditWebhookNotifier {
            retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
            ..notifier_with_timeout(address, Duration::from_secs(1))
        };

        notifier.notify_audit_record_detached(sample_record(64));
        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
        assert_eq!(
            notifier.discord_failure_count(),
            1,
            "exactly one permanent failure after all retries exhausted"
        );
    }

    /// Two detached deliveries both hitting connection refusal must each
    /// increment the failure counter independently.
    #[tokio::test]
    async fn failure_counter_accumulates_across_multiple_transport_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let address = listener.local_addr().expect("should resolve");
        drop(listener);

        let notifier = notifier_with_timeout(address, Duration::from_secs(1));
        notifier.notify_audit_record_detached(sample_record(65));
        notifier.notify_audit_record_detached(sample_record(66));
        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
        assert_eq!(
            notifier.discord_failure_count(),
            2,
            "each transport failure should independently increment the counter"
        );
    }

    /// When all optional `AuditRecord` fields (`target_id`, `agent_id`, `command`,
    /// `parameters`) are `None`, the embed must contain exactly the four base fields
    /// (Actor, Action, Target, Result) — no extras.
    #[tokio::test]
    async fn discord_embed_omits_optional_fields_when_none() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = discord_profile(address);
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        notifier
            .notify_audit_record(&sample_record(90))
            .await
            .expect("webhook delivery should succeed");

        let payload = receiver.recv().await.expect("payload should arrive");
        server.abort();

        let fields =
            payload["embeds"][0]["fields"].as_array().expect("embed fields should be an array");

        let field_names: Vec<&str> = fields
            .iter()
            .map(|f| f["name"].as_str().expect("field name should be a string"))
            .collect();

        assert_eq!(
            field_names,
            vec!["Actor", "Action", "Target", "Result"],
            "embed must contain only the four base fields when optional record fields are None; got: {field_names:?}"
        );

        // Every field value must be a non-empty string — Discord silently rejects
        // payloads containing null or empty-string field values.
        for field in fields {
            let value = field["value"].as_str().expect("field value should be a string");
            assert!(!value.is_empty(), "field {:?} must not have an empty value", field["name"]);
        }

        // The embed itself must not contain any null values at the top level.
        let embed = &payload["embeds"][0];
        assert!(embed["title"].is_string(), "embed title must be a non-null string");
        assert!(embed["description"].is_string(), "embed description must be a non-null string");
        assert!(embed["color"].is_number(), "embed color must be a non-null number");
        assert!(embed["timestamp"].is_string(), "embed timestamp must be a non-null string");

        // The payload must not contain any null-valued keys anywhere — walk the
        // entire JSON tree to catch serialization of `None` as `null`.
        fn assert_no_nulls(path: &str, value: &Value) {
            match value {
                Value::Null => panic!("unexpected null at {path}"),
                Value::Object(map) => {
                    for (key, val) in map {
                        assert_no_nulls(&format!("{path}.{key}"), val);
                    }
                }
                Value::Array(arr) => {
                    for (i, val) in arr.iter().enumerate() {
                        assert_no_nulls(&format!("{path}[{i}]"), val);
                    }
                }
                _ => {}
            }
        }
        assert_no_nulls("$", &payload);
    }

    /// Concurrent detached deliveries where some succeed and some fail must
    /// correctly update both the `pending` counter and `discord_failure_count`.
    ///
    /// Uses `flaky_webhook_server(2)` with 4 deliveries (zero-delay retries so
    /// each gets a single attempt).  The first 2 requests the server sees return
    /// 500; the next 2 return 200.  After shutdown the failure counter must be 2
    /// and exactly 2 payloads must have reached the server.
    #[tokio::test]
    async fn concurrent_mixed_success_and_failure_detached_deliveries() {
        let (address, mut receiver, server) = flaky_webhook_server(2).await;
        let notifier = AuditWebhookNotifier {
            retry_delays: Arc::from([].as_slice()),
            ..AuditWebhookNotifier::from_profile(&discord_profile(address))
        };

        // Fire 4 detached deliveries concurrently.
        for i in 0..4 {
            notifier.notify_audit_record_detached(sample_record(100 + i));
        }

        assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain all");

        // Exactly 2 deliveries should have permanently failed.
        assert_eq!(
            notifier.discord_failure_count(),
            2,
            "first 2 server hits return 500 with no retries → 2 permanent failures"
        );

        // Exactly 2 payloads should have been delivered successfully.
        let mut delivered = 0;
        while receiver.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, 2, "2 of 4 deliveries should reach the server successfully");

        // pending must be fully drained.
        assert_eq!(
            notifier.delivery_state.pending.load(Ordering::SeqCst),
            0,
            "pending counter must be zero after shutdown"
        );

        server.abort();
    }

    /// When an in-flight delivery never completes before the shutdown deadline,
    /// `shutdown()` must return `false` rather than hanging or reporting success.
    #[tokio::test]
    async fn shutdown_returns_false_when_delivery_exceeds_timeout() {
        // Spin up a server that accepts connections but never sends a response.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener address should resolve");
        let server = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                // Hold the connection open without responding.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    drop(socket);
                });
            }
        });

        let notifier = AuditWebhookNotifier {
            retry_delays: Arc::from([].as_slice()),
            ..AuditWebhookNotifier::from_profile(&discord_profile(address))
        };

        // Fire a detached notification — it will hang waiting for a response.
        notifier.notify_audit_record_detached(sample_record(50));

        // Give the spawned task a moment to start the HTTP request.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // shutdown with a very short timeout must return false.
        let drained = notifier.shutdown(Duration::from_millis(50)).await;
        assert!(
            !drained,
            "shutdown must return false when a delivery is still in-flight past the deadline"
        );

        server.abort();
    }

    /// Discord embed must sanitize special characters in audit record fields:
    /// backticks, newlines, `@everyone`/`@here` mentions, and angle-bracket
    /// mention syntax must not appear raw in the delivered payload.
    #[tokio::test]
    async fn discord_embed_sanitizes_special_characters_in_audit_fields() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = discord_profile(address);
        let notifier = AuditWebhookNotifier::from_profile(&profile);

        let record = AuditRecord {
            id: 200,
            actor: "op`erator".to_owned(),
            action: "@everyone".to_owned(),
            target_kind: "agent\ninjected".to_owned(),
            target_id: Some("<@123456>".to_owned()),
            agent_id: Some("normal-id".to_owned()),
            command: Some("@here".to_owned()),
            parameters: None,
            result_status: AuditResultStatus::Success,
            occurred_at: "2026-03-18T12:00:00Z".to_owned(),
        };

        notifier.notify_audit_record(&record).await.expect("webhook delivery should succeed");

        let payload = receiver.recv().await.expect("payload should arrive");
        server.abort();

        // The payload must be well-formed JSON (it parsed via serde already).
        let embed = &payload["embeds"][0];
        let description = embed["description"].as_str().expect("description should be a string");

        // The format string uses backticks for markdown: "X recorded `Y` against `Z`."
        // The actor value (op`erator → operator) must not introduce extra backticks
        // that would break the inline-code delimiters.  Count: exactly 4 backticks
        // from the format template.
        let backtick_count = description.chars().filter(|&c| c == '`').count();
        assert_eq!(
            backtick_count, 4,
            "description must contain exactly the 4 template backticks, not extras from input; got: {description}"
        );

        // @everyone must be defused (zero-width space inserted).
        assert!(
            !description.contains("@everyone"),
            "description must not contain raw @everyone; got: {description}"
        );

        // Newlines must be replaced with spaces.
        assert!(
            !description.contains('\n'),
            "description must not contain raw newlines; got: {description}"
        );

        // Verify field-level sanitization.
        let fields = embed["fields"].as_array().expect("embed fields should be an array");

        let actor_value = &fields[0]["value"];
        assert_eq!(actor_value, "operator", "backtick must be stripped from actor field value");

        let action_value = fields[1]["value"].as_str().expect("action value should be a string");
        assert!(
            !action_value.contains("@everyone") || action_value.contains("@\u{200b}everyone"),
            "action field must defuse @everyone; got: {action_value}"
        );

        let target_value = fields[2]["value"].as_str().expect("target value should be a string");
        assert!(
            !target_value.contains('\n'),
            "target field must not contain raw newlines; got: {target_value}"
        );

        // target_id with angle-bracket mention syntax must be defused.
        let target_id_field = fields
            .iter()
            .find(|f| f["name"] == "Target ID")
            .expect("Target ID field should be present");
        let target_id_value =
            target_id_field["value"].as_str().expect("target_id value should be a string");
        assert!(
            !target_id_value.starts_with("<@"),
            "target_id must not start with raw <@ mention syntax; got: {target_id_value}"
        );

        // command field with @here must be defused.
        let command_field = fields
            .iter()
            .find(|f| f["name"] == "Command")
            .expect("Command field should be present");
        let command_value =
            command_field["value"].as_str().expect("command value should be a string");
        assert!(
            !command_value.contains("@here") || command_value.contains("@\u{200b}here"),
            "command field must defuse @here; got: {command_value}"
        );
    }

    /// Unit test for the `sanitize_discord_text` helper covering all sanitization rules.
    #[test]
    fn sanitize_discord_text_covers_all_rules() {
        use super::sanitize_discord_text;

        // Backticks are removed.
        assert_eq!(sanitize_discord_text("a`b`c"), "abc");

        // Newlines and carriage returns become spaces.
        assert_eq!(sanitize_discord_text("line1\nline2\rline3"), "line1 line2 line3");

        // @everyone and @here are defused with zero-width space.
        let everyone = sanitize_discord_text("@everyone");
        assert!(!everyone.contains("@everyone") || everyone.contains("@\u{200b}everyone"));
        assert!(everyone.contains("@\u{200b}everyone"));

        let here = sanitize_discord_text("@here");
        assert!(here.contains("@\u{200b}here"));

        // Angle-bracket mentions are defused.
        let user_mention = sanitize_discord_text("<@123>");
        assert!(!user_mention.starts_with("<@"));

        let role_mention = sanitize_discord_text("<@&456>");
        assert!(!role_mention.starts_with("<@"));

        // Channel mentions are defused.
        let channel_mention = sanitize_discord_text("<#789>");
        assert!(!channel_mention.starts_with("<#"));
        assert!(channel_mention.contains("\u{200b}<#"));

        // Plain text passes through unchanged.
        assert_eq!(sanitize_discord_text("hello world"), "hello world");
    }

    // --- simulate_stuck_delivery tests (require the test-helpers feature) --------

    /// Happy path: `shutdown` must block while a `StuckDeliveryGuard` is alive and
    /// complete successfully once the guard is dropped.
    #[cfg(feature = "test-helpers")]
    #[tokio::test]
    async fn simulate_stuck_delivery_blocks_shutdown_until_guard_dropped() {
        let notifier = AuditWebhookNotifier::default();

        let guard = notifier.simulate_stuck_delivery();

        // shutdown should not resolve while the guard is still alive.
        let blocked = tokio::time::timeout(
            Duration::from_millis(50),
            notifier.shutdown(Duration::from_secs(5)),
        )
        .await;
        assert!(blocked.is_err(), "shutdown must not complete while guard is alive");

        // Dropping the guard decrements pending and wakes the shutdown waiter.
        drop(guard);

        // A fresh shutdown call must now resolve immediately (closing is already
        // true; pending == 0).
        let drained = tokio::time::timeout(
            Duration::from_millis(100),
            notifier.shutdown(Duration::from_secs(5)),
        )
        .await
        .expect("shutdown should complete promptly after guard is dropped");
        assert!(drained, "shutdown must return true once pending reaches zero");
    }

    /// Drop semantics: verify that the `pending` counter returns to zero when the
    /// guard is dropped, so subsequent `shutdown` calls drain without waiting.
    #[cfg(feature = "test-helpers")]
    #[tokio::test]
    async fn simulate_stuck_delivery_guard_drop_resets_pending_counter() {
        let notifier = AuditWebhookNotifier::default();

        let guard = notifier.simulate_stuck_delivery();
        assert_eq!(
            notifier.delivery_state.pending.load(Ordering::SeqCst),
            1,
            "pending must be 1 while guard is alive"
        );

        drop(guard);
        assert_eq!(
            notifier.delivery_state.pending.load(Ordering::SeqCst),
            0,
            "pending must return to zero after guard is dropped"
        );

        // Shutdown must now drain immediately since pending is zero.
        let drained = tokio::time::timeout(
            Duration::from_millis(100),
            notifier.shutdown(Duration::from_secs(1)),
        )
        .await
        .expect("shutdown should complete immediately with pending=0");
        assert!(drained, "shutdown must return true when no deliveries are pending");
    }

    /// Events submitted when the concurrency cap is exhausted must be dropped with
    /// a warning rather than spawning an unbounded number of tasks.
    ///
    /// The test builds a notifier whose semaphore is pre-exhausted (cap = 0) so
    /// every `notify_audit_record_detached` call hits the cap immediately.  No
    /// tasks should be spawned, the pending counter must stay at zero, and no
    /// payload must reach the mock server.
    #[tokio::test]
    async fn detached_events_dropped_when_concurrency_cap_is_reached() {
        let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
        let profile = discord_profile(address);

        // Build a notifier with an already-exhausted semaphore (cap = 0).
        let notifier = AuditWebhookNotifier {
            delivery_semaphore: Arc::new(Semaphore::new(0)),
            ..AuditWebhookNotifier::from_profile(&profile)
        };

        // Fire several detached notifications — all should be dropped.
        for i in 0..5 {
            notifier.notify_audit_record_detached(sample_record(500 + i));
        }

        // Yield so any erroneously spawned tasks get a chance to run.
        tokio::task::yield_now().await;

        // No payload must have reached the server.
        assert!(
            receiver.try_recv().is_err(),
            "no webhook request should be sent when the concurrency cap is exhausted"
        );

        // The pending counter must be zero — dropped events must not inflate it.
        assert_eq!(
            notifier.delivery_state.pending.load(Ordering::SeqCst),
            0,
            "pending counter must be zero after all events are dropped at the cap"
        );

        // shutdown must drain immediately (nothing in flight).
        assert!(
            notifier.shutdown(Duration::from_millis(100)).await,
            "shutdown must return true immediately when no tasks were spawned"
        );

        server.abort();
    }

    /// `discord_webhook_client()` must return `Ok` and the resulting client must
    /// reject redirects — a 302 response must not be followed.
    #[tokio::test]
    async fn discord_webhook_client_rejects_redirects() {
        // Spin up a server that responds with a 302 redirect to a second server.
        let (final_addr, mut final_rx, final_server) = webhook_server(HttpStatusCode::OK).await;
        let redirect_app = Router::new().route(
            "/",
            post(move || async move {
                (HttpStatusCode::FOUND, [("location", format!("http://{final_addr}/"))], "")
            }),
        );
        let redirect_listener =
            TcpListener::bind("127.0.0.1:0").await.expect("redirect listener should bind");
        let redirect_addr =
            redirect_listener.local_addr().expect("redirect address should resolve");
        let redirect_server = tokio::spawn(async move {
            axum::serve(redirect_listener, redirect_app)
                .await
                .expect("redirect server should not fail");
        });

        let client = super::discord_webhook_client().expect("client builder should succeed");
        let response = client
            .post(format!("http://{redirect_addr}/"))
            .json(&json!({"test": true}))
            .send()
            .await
            .expect("request should complete");

        // The client must NOT follow the redirect — it should return the 302 directly.
        assert_eq!(
            response.status(),
            reqwest::StatusCode::FOUND,
            "client must not follow redirects"
        );

        // The redirect target must not have received a request.
        assert!(
            final_rx.try_recv().is_err(),
            "redirect target must not receive a request when redirects are disabled"
        );

        redirect_server.abort();
        final_server.abort();
    }

    /// Multiple guards: `shutdown` must continue to block after the first guard is
    /// dropped and only complete once every guard has been dropped.
    #[cfg(feature = "test-helpers")]
    #[tokio::test]
    async fn simulate_stuck_delivery_multiple_guards_all_must_drop_before_shutdown() {
        let notifier = AuditWebhookNotifier::default();

        let guard1 = notifier.simulate_stuck_delivery();
        let guard2 = notifier.simulate_stuck_delivery();
        assert_eq!(
            notifier.delivery_state.pending.load(Ordering::SeqCst),
            2,
            "pending must be 2 with two guards alive"
        );

        // Drop guard1 — pending falls to 1, shutdown must still block.
        drop(guard1);
        assert_eq!(
            notifier.delivery_state.pending.load(Ordering::SeqCst),
            1,
            "pending must be 1 after first guard is dropped"
        );

        let still_blocked = tokio::time::timeout(
            Duration::from_millis(50),
            notifier.shutdown(Duration::from_secs(5)),
        )
        .await;
        assert!(
            still_blocked.is_err(),
            "shutdown must still block after dropping only one of two guards"
        );

        // Drop guard2 — pending falls to 0, shutdown must now complete.
        drop(guard2);

        let drained = tokio::time::timeout(
            Duration::from_millis(100),
            notifier.shutdown(Duration::from_secs(5)),
        )
        .await
        .expect("shutdown should complete after all guards are dropped");
        assert!(drained, "shutdown must return true after all guards are dropped");
    }
}
