mod audit;
mod delivery;
mod discord;
mod retry;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::{Json, Router, http::StatusCode as HttpStatusCode, routing::post};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::delivery::DiscordWebhook;
use super::{AuditWebhookNotifier, DeliveryState, MAX_CONCURRENT_DELIVERIES};
use crate::{AuditRecord, AuditResultStatus};
use red_cell_common::config::Profile;

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

/// Build a notifier with a custom HTTP client timeout, overriding
/// the production 5-second default.
fn notifier_with_timeout(address: SocketAddr, timeout: Duration) -> AuditWebhookNotifier {
    use std::sync::atomic::AtomicU64;
    use tokio::sync::Semaphore;

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("test client should build");
    AuditWebhookNotifier {
        discord: Some(Arc::new(DiscordWebhook {
            url: format!("http://{address}/"),
            username: None,
            avatar_url: None,
            client,
        })),
        delivery_state: Arc::new(DeliveryState::default()),
        discord_failure_count: Arc::new(AtomicU64::new(0)),
        retry_delays: Arc::from([].as_slice()),
        delivery_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
    }
}
