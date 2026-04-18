use std::time::Duration;

use axum::{Json, Router, http::StatusCode as HttpStatusCode, routing::post};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::super::AuditWebhookNotifier;
use crate::{AuditRecord, AuditResultStatus};
use red_cell_common::config::Profile;

use super::{discord_profile, sample_record, webhook_server};

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
async fn notifier_shutdown_drains_detached_delivery_after_webhook_failure() {
    let (address, _receiver, server) = webhook_server(HttpStatusCode::INTERNAL_SERVER_ERROR).await;
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
    let profile = discord_profile(address);
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
    let result =
        tokio::time::timeout(Duration::from_millis(100), notifier.shutdown(Duration::from_secs(1)))
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
    notifier.notify_audit_record_detached(sample_record(20));

    // shutdown must wait until the in-flight delivery finishes.
    let drained = notifier.shutdown(Duration::from_secs(5)).await;
    assert!(drained, "shutdown should report all deliveries complete");

    // The delivery must have actually reached the mock server.
    let mut rx = receiver;
    assert!(rx.try_recv().is_ok(), "webhook delivery must complete before shutdown returns true");

    server.abort();
}
