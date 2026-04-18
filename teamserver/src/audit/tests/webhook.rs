use std::{future::pending, net::SocketAddr, time::Duration};

use axum::{Json, Router, routing::post};
use red_cell_common::config::Profile;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::super::{AuditResultStatus, audit_details};
use crate::{AuditWebhookNotifier, Database, record_operator_action_with_notifications};

#[tokio::test]
async fn notifying_audit_helper_posts_to_configured_discord_webhook() {
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
          }}
        }}

        Demon {{}}
        "#
    ))
    .expect("profile should parse");
    let notifier = AuditWebhookNotifier::from_profile(&profile);
    let database = Database::connect_in_memory().await.expect("database should initialize");

    let id = record_operator_action_with_notifications(
        &database,
        &notifier,
        "operator",
        "listener.create",
        "listener",
        Some("http-1".to_owned()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("create"),
            Some(json!({"listener":"http-1"})),
        ),
    )
    .await
    .expect("audit record should persist");

    let payload = receiver.recv().await.expect("payload should arrive");
    server.abort();

    assert_eq!(id, 1);
    assert_eq!(payload["username"], "Red Cell");
    assert_eq!(payload["embeds"][0]["fields"][1]["value"], "listener.create");
    assert_eq!(payload["embeds"][0]["fields"][4]["value"], "http-1");
}

#[tokio::test]
async fn notifying_audit_helper_does_not_block_on_stalled_webhook() {
    let (address, server) = stalled_webhook_server().await;
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
    let database = Database::connect_in_memory().await.expect("database should initialize");

    let result = timeout(
        Duration::from_millis(250),
        record_operator_action_with_notifications(
            &database,
            &notifier,
            "operator",
            "listener.delete",
            "listener",
            Some("http-1".to_owned()),
            audit_details(
                AuditResultStatus::Success,
                None,
                Some("delete"),
                Some(json!({"listener":"http-1"})),
            ),
        ),
    )
    .await;

    server.abort();

    let id = result.expect("audit helper should not block").expect("audit record should persist");
    let stored = database.audit_log().list().await.expect("audit log should query");

    assert_eq!(id, 1);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].action, "listener.delete");
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
        axum::serve(listener, app).await.expect("test webhook server should not fail");
    });

    (address, receiver, server)
}

async fn stalled_webhook_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        post(|| async {
            pending::<()>().await;
            Json(json!({"ok": true}))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
    let address = listener.local_addr().expect("listener address should resolve");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("test stalled webhook server should not fail");
    });

    (address, server)
}
