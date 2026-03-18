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
use tokio::sync::Notify;
use tracing::warn;

use crate::{AuditRecord, AuditResultStatus};

const SUCCESS_COLOR: u32 = 0x002E_CC71;
const FAILURE_COLOR: u32 = 0x00E7_4C3C;
const DISCORD_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

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
}

impl Default for AuditWebhookNotifier {
    fn default() -> Self {
        Self {
            discord: None,
            delivery_state: Arc::new(DeliveryState::default()),
            discord_failure_count: Arc::new(AtomicU64::new(0)),
            retry_delays: Arc::from(RETRY_DELAYS.as_slice()),
        }
    }
}

impl AuditWebhookNotifier {
    /// Build a notifier from the loaded teamserver profile.
    #[must_use]
    pub fn from_profile(profile: &Profile) -> Self {
        let discord =
            profile.webhook.as_ref().and_then(|webhook| webhook.discord.as_ref()).map(|config| {
                Arc::new(DiscordWebhook {
                    url: config.url.clone(),
                    username: config.user.clone(),
                    avatar_url: config.avatar_url.clone(),
                    client: discord_webhook_client(),
                })
            });

        Self {
            discord,
            delivery_state: Arc::new(DeliveryState::default()),
            discord_failure_count: Arc::new(AtomicU64::new(0)),
            retry_delays: Arc::from(RETRY_DELAYS.as_slice()),
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
    #[cfg(test)]
    pub fn from_profile_no_retry(profile: &Profile) -> Self {
        Self { retry_delays: Arc::from([]), ..Self::from_profile(profile) }
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

            let delivery_state = self.delivery_state.clone();
            let failure_count = self.discord_failure_count.clone();
            let retry_delays = self.retry_delays.clone();
            tokio::spawn(async move {
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

fn discord_webhook_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(DISCORD_WEBHOOK_TIMEOUT)
        // Disable redirects: a redirect-following client can be used to pivot to internal
        // services (SSRF) if an attacker controls DNS for the configured webhook hostname.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
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
        let mut fields = vec![
            DiscordField::new("Actor", record.actor.clone(), true),
            DiscordField::new("Action", record.action.clone(), true),
            DiscordField::new("Target", record.target_kind.clone(), true),
            DiscordField::new("Result", record.result_status.as_str().to_owned(), true),
        ];

        if let Some(target_id) = &record.target_id {
            fields.push(DiscordField::new("Target ID", target_id.clone(), true));
        }

        if let Some(agent_id) = &record.agent_id {
            fields.push(DiscordField::new("Agent ID", agent_id.clone(), true));
        }

        if let Some(command) = &record.command {
            fields.push(DiscordField::new("Command", command.clone(), true));
        }

        if let Some(parameters) = &record.parameters {
            fields.push(DiscordField::new("Parameters", parameters.to_string(), false));
        }

        Self {
            title: "Red Cell audit event",
            description: format!(
                "{} recorded `{}` against `{}`.",
                record.actor, record.action, record.target_kind
            ),
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
    use tokio::sync::mpsc;

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
}
