//! Discord webhook HTTP delivery, payload formatting, and retry helpers.

use std::{sync::Arc, time::Duration};

use serde::Serialize;

use crate::{AuditRecord, AuditResultStatus};

use super::{DISCORD_WEBHOOK_TIMEOUT, FAILURE_COLOR, SUCCESS_COLOR, WebhookError};

pub(super) fn discord_webhook_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(DISCORD_WEBHOOK_TIMEOUT)
        // Disable redirects: a redirect-following client can be used to pivot to internal
        // services (SSRF) if an attacker controls DNS for the configured webhook hostname.
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[derive(Debug)]
pub(super) struct DiscordWebhook {
    pub(super) url: String,
    pub(super) username: Option<String>,
    pub(super) avatar_url: Option<String>,
    pub(super) client: reqwest::Client,
}

impl DiscordWebhook {
    pub(super) async fn send(&self, record: &AuditRecord) -> Result<(), WebhookError> {
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

/// Build an exponential backoff delay sequence for webhook retries.
///
/// Returns a slice of `max_retries` durations: `[base * 4^0, base * 4^1, …]`.
/// When `max_retries` is 0 the returned slice is empty (retries disabled).
/// Uses saturating arithmetic so large values do not overflow.
pub(super) fn build_retry_delays(max_retries: u32, base_secs: u64) -> Arc<[Duration]> {
    let delays: Vec<Duration> = (0..max_retries)
        .map(|i| Duration::from_secs(base_secs.saturating_mul(4u64.saturating_pow(i))))
        .collect();
    Arc::from(delays.as_slice())
}

/// Returns `true` when a webhook error is considered transient and worth retrying.
///
/// Network-level errors (connection refused, timeout) are always transient.
/// HTTP 429 (rate-limited) and 5xx (server error) are transient.
/// Other 4xx responses indicate a permanent configuration or auth failure and
/// must not be retried.
pub(super) fn is_transient_webhook_error(err: &WebhookError) -> bool {
    match err {
        WebhookError::Request(_) => true,
        WebhookError::UnexpectedStatus(status) => {
            status.as_u16() == 429 || status.is_server_error()
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct DiscordWebhookPayload<'a> {
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
pub(super) fn sanitize_discord_text(input: &str) -> String {
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
