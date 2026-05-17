//! Regression test: the session WebSocket at `/api/v1/ws` must enforce a
//! maximum frame size, rejecting oversized messages to prevent memory
//! amplification attacks.

mod common;

use futures_util::{SinkExt, StreamExt};
use red_cell_common::config::Profile;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::tungstenite::Message as ClientMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Must match `SESSION_MAX_MESSAGE_SIZE` in `teamserver/src/session_ws.rs`
/// (which equals `MAX_AGENT_MESSAGE_LEN` = 100 MiB).
const SESSION_MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

fn profile_with_api_key() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }
        Operators {
          user "operator" {
            Password = "password1234"
            Role     = "Operator"
          }
        }
        Api {
          RateLimitPerMinute = 120
          key "test-key" {
            Value = "test-secret"
            Role  = "Admin"
          }
        }
        Demon {}
        "#,
    )
    .expect("test profile should parse")
}

/// Connect a raw WebSocket to `/api/v1/ws` with the given API key.
async fn connect_session_ws(
    addr: std::net::SocketAddr,
    api_key: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{addr}/api/v1/ws");
    let mut request = url.into_client_request().expect("valid request");
    request.headers_mut().insert("x-api-key", api_key.parse().expect("valid header value"));
    let (stream, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WebSocket handshake should succeed");
    stream
}

/// Verifies the session WebSocket enforces a maximum frame size. With the limit
/// at 100 MiB (matching the REST body limit), actually allocating 100+ MiB in a
/// test is impractical — this test is gated behind `#[ignore]` and runs manually.
#[tokio::test]
#[ignore]
async fn session_ws_rejects_oversized_frame() {
    let server =
        common::spawn_test_server(profile_with_api_key()).await.expect("server should start");

    let mut ws = connect_session_ws(server.addr, "test-secret").await;

    let oversized = "x".repeat(SESSION_MAX_MESSAGE_SIZE + 1);
    ws.send(ClientMessage::Text(oversized.into())).await.expect("send should succeed");

    let frame = timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("socket should respond within timeout");

    match frame {
        Some(Ok(ClientMessage::Close(_))) => {}
        Some(Err(_)) => {}
        None => {}
        other => panic!("expected close/error/EOF, got {other:?}"),
    }
}

/// Regression: `agent.upload` with a 2 MiB base64 body was previously dropped
/// because the session WS hard-capped at 1 MiB. After the fix, the frame is
/// dispatched and the server responds with a JSON envelope (agent not found)
/// rather than closing the connection.
#[tokio::test]
async fn session_ws_accepts_upload_payload_exceeding_old_1mib_limit() {
    let server =
        common::spawn_test_server(profile_with_api_key()).await.expect("server should start");

    let mut ws = connect_session_ws(server.addr, "test-secret").await;

    // 2 MiB of base64 content — previously would have been dropped at the WS layer.
    let content = "A".repeat(2 * 1024 * 1024);
    let upload_cmd = serde_json::json!({
        "cmd": "agent.upload",
        "id": "nonexistent-agent",
        "src": "/tmp/bigfile.bin",
        "dst": "C:\\Windows\\Temp\\bigfile.bin",
        "content": content,
    });
    let payload = upload_cmd.to_string();
    assert!(payload.len() > 1024 * 1024, "test payload must exceed the old 1 MiB limit");

    ws.send(ClientMessage::Text(payload.into())).await.expect("send");

    let frame = timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("should get response within timeout")
        .expect("stream should not be closed")
        .expect("frame should be valid");

    match frame {
        ClientMessage::Text(t) => {
            let v: serde_json::Value =
                serde_json::from_str(&t).expect("response should be valid JSON");
            assert_eq!(v["cmd"], "agent.upload", "response must echo the command");
            // The agent doesn't exist, so we expect an error, but the important
            // thing is that the frame was accepted and dispatched (not dropped).
            assert!(v.get("ok").is_some(), "response must contain an `ok` field, got: {v}");
        }
        other => panic!("expected text frame response, got {other:?}"),
    }
}

#[tokio::test]
async fn session_ws_accepts_frame_within_limit() {
    let server =
        common::spawn_test_server(profile_with_api_key()).await.expect("server should start");

    let mut ws = connect_session_ws(server.addr, "test-secret").await;

    let valid_cmd = serde_json::json!({"cmd": "agents"}).to_string();
    ws.send(ClientMessage::Text(valid_cmd.into())).await.expect("send");

    let frame = timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("should get response within timeout")
        .expect("stream should not be closed")
        .expect("frame should be valid");

    match frame {
        ClientMessage::Text(t) => {
            let v: serde_json::Value =
                serde_json::from_str(&t).expect("response should be valid JSON");
            assert!(v.get("cmd").is_some() || v.get("ok").is_some(), "unexpected response: {v}");
        }
        other => panic!("expected text frame, got {other:?}"),
    }
}
