//! Integration tests verifying that audit events triggered by operator actions
//! are delivered to a configured webhook endpoint, including retry on transient
//! failure and graceful shutdown draining.
//!
//! These tests exercise the full WebSocket login flow (the same path that
//! production operators follow) and then verify that the expected Discord
//! webhook POST arrives at a mock HTTP server with the correct payload
//! structure.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::{Json, Router, http::StatusCode, routing::post};
use futures_util::SinkExt;
use red_cell_common::config::Profile;
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{EventCode, LoginInfo, Message, MessageHead, OperatorMessage};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Build a test profile with a Discord webhook URL pointing at the given address.
fn profile_with_webhook(webhook_addr: SocketAddr) -> Profile {
    Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 0
        }}

        Operators {{
          user "operator" {{
            Password = "password1234"
            Role = "Operator"
          }}
        }}

        WebHook {{
          Discord {{
            Url = "http://{webhook_addr}/"
            User = "Red Cell"
            AvatarUrl = "https://example.test/red-cell.png"
          }}
        }}

        Demon {{}}
        "#,
    ))
    .expect("profile with webhook should parse")
}

/// Stand up a mock HTTP server that always responds with `response_status`.
/// Returns the address, a receiver for captured payloads, and the server task handle.
async fn mock_webhook_server(
    response_status: StatusCode,
) -> (SocketAddr, mpsc::UnboundedReceiver<Value>, tokio::task::JoinHandle<()>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let app = Router::new().route(
        "/",
        post(move |Json(payload): Json<Value>| {
            let sender = sender.clone();
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

/// Stand up a mock HTTP server that fails on the first `fail_count` requests
/// then succeeds.
async fn flaky_webhook_server(
    fail_count: usize,
) -> (SocketAddr, mpsc::UnboundedReceiver<Value>, tokio::task::JoinHandle<()>) {
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
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false})))
                } else {
                    let _ = sender.send(payload);
                    (StatusCode::OK, Json(json!({"ok": true})))
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

/// Perform a WebSocket login and return the response.
async fn ws_login(
    addr: SocketAddr,
    username: &str,
    password: &str,
) -> Result<common::WsClient, Box<dyn std::error::Error>> {
    let url = format!("ws://{addr}/havoc");
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await?;

    let payload = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: username.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: LoginInfo { user: username.to_owned(), password: hash_password_sha3(password) },
    }))?;
    socket.send(WsMessage::Text(payload.into())).await?;
    let _ = common::read_operator_message(&mut socket).await?;
    let _ = common::read_operator_snapshot(&mut socket).await?;

    Ok(socket)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A successful operator login must trigger a webhook POST with a Discord
/// embed payload containing the correct audit event fields.
#[tokio::test]
async fn operator_login_delivers_webhook_with_correct_audit_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let (webhook_addr, mut webhook_rx, webhook_server) = mock_webhook_server(StatusCode::OK).await;
    let profile = profile_with_webhook(webhook_addr);
    let server = common::spawn_test_server(profile).await?;

    let mut socket = ws_login(server.addr, "operator", "password1234").await?;

    // The webhook fires asynchronously — wait for the payload to arrive.
    let payload = timeout(Duration::from_secs(5), webhook_rx.recv())
        .await
        .expect("webhook should arrive within timeout")
        .expect("webhook payload should be received");

    socket.close(None).await?;
    webhook_server.abort();

    // Verify Discord payload structure.
    assert_eq!(payload["username"], "Red Cell");
    assert_eq!(payload["avatar_url"], "https://example.test/red-cell.png");

    let embed = &payload["embeds"][0];
    assert_eq!(embed["title"], "Red Cell audit event");
    assert!(embed["color"].is_number(), "embed color must be present");
    assert!(embed["timestamp"].is_string(), "embed timestamp must be present");

    let fields = embed["fields"].as_array().expect("embed fields should be an array");

    // Actor field.
    assert_eq!(fields[0]["name"], "Actor");
    assert_eq!(fields[0]["value"], "operator");

    // Action field.
    assert_eq!(fields[1]["name"], "Action");
    assert_eq!(fields[1]["value"], "operator.login");

    // Target field.
    assert_eq!(fields[2]["name"], "Target");
    assert_eq!(fields[2]["value"], "operator");

    // Result field.
    assert_eq!(fields[3]["name"], "Result");
    assert_eq!(fields[3]["value"], "success");

    Ok(())
}

/// A failed operator login (wrong password) must deliver a webhook with
/// failure status and the failure color.
#[tokio::test]
async fn failed_login_delivers_webhook_with_failure_status()
-> Result<(), Box<dyn std::error::Error>> {
    let (webhook_addr, mut webhook_rx, webhook_server) = mock_webhook_server(StatusCode::OK).await;
    let profile = profile_with_webhook(webhook_addr);
    let server = common::spawn_test_server(profile).await?;

    // Attempt login with wrong password.
    let url = server.ws_url();
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await?;
    let payload = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: LoginInfo {
            user: "operator".to_owned(),
            password: hash_password_sha3("wrong-password"),
        },
    }))?;
    socket.send(WsMessage::Text(payload.into())).await?;
    let response = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(response, OperatorMessage::InitConnectionError(_)),
        "expected login failure, got {response:?}"
    );

    let webhook_payload = timeout(Duration::from_secs(5), webhook_rx.recv())
        .await
        .expect("webhook should arrive within timeout")
        .expect("webhook payload should be received");

    socket.close(None).await?;
    webhook_server.abort();

    let embed = &webhook_payload["embeds"][0];
    let result_field = embed["fields"]
        .as_array()
        .expect("fields should be an array")
        .iter()
        .find(|f| f["name"] == "Result")
        .expect("Result field should be present");

    assert_eq!(result_field["value"], "failure", "failed login webhook must report failure status");

    Ok(())
}

/// When the webhook endpoint returns a transient error, the notifier must
/// retry and eventually deliver the payload once the endpoint recovers.
///
/// A successful login emits two audit events (`operator.login` and
/// `operator.connect`), so we fail the first two requests and verify that
/// both are eventually delivered after their respective retries.
#[tokio::test]
async fn webhook_retries_on_transient_server_failure() -> Result<(), Box<dyn std::error::Error>> {
    // Fail the first 2 POSTs (one per audit event), then succeed.
    let (webhook_addr, mut webhook_rx, webhook_server) = flaky_webhook_server(2).await;
    let profile = profile_with_webhook(webhook_addr);
    let server = common::spawn_test_server(profile).await?;

    let mut socket = ws_login(server.addr, "operator", "password1234").await?;
    socket.close(None).await?;

    // Shutdown waits for all in-flight deliveries (including retries) to complete.
    assert!(
        server.webhooks.shutdown(Duration::from_secs(15)).await,
        "shutdown should drain after retries complete"
    );

    // Both audit events should have been delivered after retry.
    let first = webhook_rx.try_recv();
    let second = webhook_rx.try_recv();
    assert!(first.is_ok(), "first audit event must arrive after retry");
    assert!(second.is_ok(), "second audit event must arrive after retry");

    // Verify the payloads have the correct embed structure.
    for payload in [first.unwrap(), second.unwrap()] {
        assert_eq!(payload["embeds"][0]["fields"][0]["name"], "Actor");
        assert_eq!(payload["embeds"][0]["fields"][0]["value"], "operator");
    }

    // No permanent failure should have been recorded.
    assert_eq!(
        server.webhooks.discord_failure_count(),
        0,
        "successful retry must not increment the permanent failure counter"
    );

    webhook_server.abort();
    Ok(())
}

/// Shutdown must wait for in-flight webhook deliveries to complete before
/// returning `true`.
#[tokio::test]
async fn shutdown_drains_in_flight_webhook_deliveries() -> Result<(), Box<dyn std::error::Error>> {
    let (webhook_addr, mut webhook_rx, webhook_server) = mock_webhook_server(StatusCode::OK).await;
    let profile = profile_with_webhook(webhook_addr);
    let server = common::spawn_test_server(profile).await?;

    let mut socket = ws_login(server.addr, "operator", "password1234").await?;
    socket.close(None).await?;

    // Shutdown should wait for the detached webhook delivery to finish.
    let drained = server.webhooks.shutdown(Duration::from_secs(5)).await;
    assert!(drained, "shutdown should report all webhook deliveries drained");

    // The payload must have actually reached the mock server.
    assert!(
        webhook_rx.try_recv().is_ok(),
        "webhook delivery must complete before shutdown returns true"
    );

    webhook_server.abort();
    Ok(())
}

/// After shutdown, the webhook notifier must report that it is no longer
/// accepting new deliveries — a second `shutdown` call returns immediately.
#[tokio::test]
async fn second_shutdown_returns_immediately_after_drain() -> Result<(), Box<dyn std::error::Error>>
{
    let (webhook_addr, mut webhook_rx, webhook_server) = mock_webhook_server(StatusCode::OK).await;
    let profile = profile_with_webhook(webhook_addr);
    let server = common::spawn_test_server(profile).await?;

    // Trigger one login so the webhook fires and drain it.
    let mut socket = ws_login(server.addr, "operator", "password1234").await?;
    socket.close(None).await?;
    assert!(server.webhooks.shutdown(Duration::from_secs(5)).await);

    // Consume all delivered payloads.
    while webhook_rx.try_recv().is_ok() {}

    // A second shutdown call must return true immediately (no pending tasks
    // and the closing flag is already set).
    let drained =
        timeout(Duration::from_millis(100), server.webhooks.shutdown(Duration::from_secs(1)))
            .await
            .expect("second shutdown should complete instantly");
    assert!(drained, "second shutdown should report drained");

    webhook_server.abort();
    Ok(())
}

/// The webhook payload must not contain any null JSON values — Discord
/// silently rejects payloads with null fields.
#[tokio::test]
async fn webhook_payload_contains_no_null_values() -> Result<(), Box<dyn std::error::Error>> {
    let (webhook_addr, mut webhook_rx, webhook_server) = mock_webhook_server(StatusCode::OK).await;
    let profile = profile_with_webhook(webhook_addr);
    let server = common::spawn_test_server(profile).await?;

    let mut socket = ws_login(server.addr, "operator", "password1234").await?;

    let payload = timeout(Duration::from_secs(5), webhook_rx.recv())
        .await
        .expect("webhook should arrive within timeout")
        .expect("webhook payload should be received");

    socket.close(None).await?;
    webhook_server.abort();

    // Walk the entire JSON tree — no null values allowed.
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

    Ok(())
}
