use std::net::IpAddr;
use std::time::Duration;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use red_cell_common::crypto::hash_password_sha3;
use serde_json::Value;
use tracing::warn;
use uuid::Uuid;

use crate::LoginRateLimiter;
use crate::auth::password_hashes_match;

use super::{HEAD_REGISTER, ServiceBridgeError};

/// Delay applied before responding to a failed service auth attempt.
const FAILED_AUTH_DELAY: Duration = Duration::from_secs(2);

/// Maximum time a service client has to send the initial Register frame before
/// the connection is closed. Mirrors `AUTHENTICATION_FRAME_TIMEOUT` on the
/// operator WebSocket path.
pub(super) const SERVICE_AUTH_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Authenticate a service client by verifying its Register message.
///
/// Returns a unique client ID on success, or a [`ServiceBridgeError`] on failure.
pub(super) async fn authenticate(
    socket: &mut WebSocket,
    server_verifier: &str,
    rate_limiter: &LoginRateLimiter,
    client_ip: IpAddr,
) -> Result<Uuid, ServiceBridgeError> {
    if !rate_limiter.try_acquire(client_ip).await {
        warn!(%client_ip, "service auth rate limited");
        return Err(ServiceBridgeError::RateLimited);
    }

    let message = match tokio::time::timeout(SERVICE_AUTH_FRAME_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(WsMessage::Text(text)))) => text,
        Err(_) => {
            warn!(%client_ip, "service auth timed out waiting for Register frame");
            let _ = socket.send(WsMessage::Close(None)).await;
            return Err(ServiceBridgeError::AuthenticationTimeout);
        }
        _ => return Err(ServiceBridgeError::AuthenticationFailed),
    };

    let parsed: Value = serde_json::from_str(&message)?;

    let head_type =
        parsed.get("Head").and_then(|h| h.get("Type")).and_then(Value::as_str).unwrap_or_default();

    if head_type != HEAD_REGISTER {
        return Err(ServiceBridgeError::AuthenticationFailed);
    }

    let client_password = parsed
        .get("Body")
        .and_then(|b| b.get("Password"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    let client_hash = hash_password_sha3(client_password);
    let success = password_hashes_match(&client_hash, server_verifier);

    let response = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER },
        "Body": { "Success": success },
    });

    let response_text = serde_json::to_string(&response)?;
    socket
        .send(WsMessage::Text(response_text.into()))
        .await
        .map_err(ServiceBridgeError::WebSocket)?;

    if success {
        rate_limiter.record_success(client_ip).await;
        Ok(Uuid::new_v4())
    } else {
        tokio::time::sleep(FAILED_AUTH_DELAY).await;
        Err(ServiceBridgeError::AuthenticationFailed)
    }
}
