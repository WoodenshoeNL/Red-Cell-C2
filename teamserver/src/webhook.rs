//! Outbound audit webhook delivery.

use std::{sync::Arc, time::Duration};

use red_cell_common::config::Profile;
use reqwest::StatusCode;
use serde::Serialize;
use thiserror::Error;
use tracing::warn;

use crate::{AuditRecord, AuditResultStatus};

const SUCCESS_COLOR: u32 = 0x002E_CC71;
const FAILURE_COLOR: u32 = 0x00E7_4C3C;
const DISCORD_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// Best-effort outbound webhook dispatcher for audit events.
#[derive(Debug, Clone, Default)]
pub struct AuditWebhookNotifier {
    discord: Option<Arc<DiscordWebhook>>,
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

        Self { discord }
    }

    /// Return `true` when at least one outbound webhook is configured.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.discord.is_some()
    }

    /// Emit a notification for a persisted audit record.
    pub async fn notify_audit_record(&self, record: &AuditRecord) -> Result<(), WebhookError> {
        if let Some(discord) = &self.discord {
            discord.send(record).await?;
        }

        Ok(())
    }

    /// Emit a notification for a persisted audit record without blocking the caller.
    pub fn notify_audit_record_detached(&self, record: AuditRecord) {
        if let Some(discord) = self.discord.clone() {
            tokio::spawn(async move {
                if let Err(error) = discord.send(&record).await {
                    warn!(
                        actor = record.actor,
                        action = record.action,
                        %error,
                        "failed to deliver audit webhook notification"
                    );
                }
            });
        }
    }
}

fn discord_webhook_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(DISCORD_WEBHOOK_TIMEOUT)
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

    use axum::{Json, Router, routing::post};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use super::AuditWebhookNotifier;
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
        let (address, mut receiver, server) = webhook_server().await;
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

    async fn webhook_server()
    -> (SocketAddr, mpsc::UnboundedReceiver<Value>, tokio::task::JoinHandle<()>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/",
            post(move |Json(payload): Json<Value>| {
                let sender = sender.clone();
                async move {
                    let _ = sender.send(payload);
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener address should resolve");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        (address, receiver, server)
    }
}
