use axum::{Json, Router, http::StatusCode as HttpStatusCode, routing::post};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::super::delivery::{discord_webhook_client, sanitize_discord_text};
use super::super::{AuditWebhookNotifier, WebhookError};
use crate::{AuditRecord, AuditResultStatus};
use red_cell_common::config::Profile;

use super::{discord_profile, sample_record, webhook_server};

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
    assert_eq!(payload["embeds"][0]["color"], json!(super::super::SUCCESS_COLOR));
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

    assert_eq!(payload["embeds"][0]["color"], json!(super::super::FAILURE_COLOR));
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

    let field_names: Vec<&str> =
        fields.iter().map(|f| f["name"].as_str().expect("field name should be a string")).collect();

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
    let command_field =
        fields.iter().find(|f| f["name"] == "Command").expect("Command field should be present");
    let command_value = command_field["value"].as_str().expect("command value should be a string");
    assert!(
        !command_value.contains("@here") || command_value.contains("@\u{200b}here"),
        "command field must defuse @here; got: {command_value}"
    );
}

/// Unit test for the `sanitize_discord_text` helper covering all sanitization rules.
#[test]
fn sanitize_discord_text_covers_all_rules() {
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
    let redirect_addr = redirect_listener.local_addr().expect("redirect address should resolve");
    let redirect_server = tokio::spawn(async move {
        axum::serve(redirect_listener, redirect_app)
            .await
            .expect("redirect server should not fail");
    });

    let client = discord_webhook_client().expect("client builder should succeed");
    let response = client
        .post(format!("http://{redirect_addr}/"))
        .json(&json!({"test": true}))
        .send()
        .await
        .expect("request should complete");

    // The client must NOT follow the redirect — it should return the 302 directly.
    assert_eq!(response.status(), reqwest::StatusCode::FOUND, "client must not follow redirects");

    // The redirect target must not have received a request.
    assert!(
        final_rx.try_recv().is_err(),
        "redirect target must not receive a request when redirects are disabled"
    );

    redirect_server.abort();
    final_server.abort();
}
