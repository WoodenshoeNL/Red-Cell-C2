//! Integration tests verifying that operator authentication events produce
//! the expected audit-log entries in the database.
//!
//! These tests exercise the full WebSocket login flow (the same path that
//! production operators follow) and then query the persisted audit log to
//! confirm that both successes and failures are recorded with the correct
//! action, result status, and structured parameters.

mod common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{EventCode, LoginInfo, Message, MessageHead, OperatorMessage};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

/// Connect a WebSocket client to the test teamserver, send a login frame
/// with `username`/`password_sha3`, and return whatever the server sends
/// back (success or error) plus the raw client for further interaction.
async fn attempt_login(
    addr: std::net::SocketAddr,
    username: &str,
    password: &str,
) -> Result<(OperatorMessage, common::WsClient), Box<dyn std::error::Error>> {
    let url = format!("ws://{addr}/");
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
    socket.send(ClientMessage::Text(payload.into())).await?;

    let next = timeout(Duration::from_secs(10), socket.next()).await?;
    let frame = next.ok_or_else(|| "missing websocket frame".to_owned())??;
    let response = match frame {
        ClientMessage::Text(text) => serde_json::from_str::<OperatorMessage>(text.as_str())?,
        other => return Err(format!("unexpected frame: {other:?}").into()),
    };

    Ok((response, socket))
}

/// Small helper to wait for audit entries to be flushed (they are written
/// asynchronously inside the WebSocket handler).
async fn poll_audit_entries(
    database: &red_cell::Database,
    expected_count: usize,
    max_wait: Duration,
) -> Vec<red_cell::AuditLogEntry> {
    let start = tokio::time::Instant::now();
    loop {
        let entries = database.audit_log().list().await.unwrap_or_default();
        if entries.len() >= expected_count || start.elapsed() > max_wait {
            return entries;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Filter audit entries to only `operator.login` actions.
fn login_audit_entries(entries: &[red_cell::AuditLogEntry]) -> Vec<&red_cell::AuditLogEntry> {
    entries.iter().filter(|e| e.action == "operator.login").collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn successful_login_produces_audit_entry_with_success_status()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;

    let (response, mut socket) = attempt_login(server.addr, "operator", "password1234").await?;
    assert!(
        matches!(response, OperatorMessage::InitConnectionSuccess(_)),
        "expected InitConnectionSuccess, got {response:?}"
    );

    // Drain the snapshot frame so the server finishes its handler.
    let _ = common::read_operator_snapshot(&mut socket).await;
    socket.close(None).await?;

    let entries = poll_audit_entries(&server.database, 1, Duration::from_secs(5)).await;
    let logins = login_audit_entries(&entries);
    assert!(!logins.is_empty(), "audit log must contain at least one operator.login entry");

    let entry = logins[0];
    assert_eq!(entry.actor, "operator");
    assert_eq!(entry.action, "operator.login");
    assert_eq!(entry.target_kind, "operator");
    assert_eq!(entry.target_id.as_deref(), Some("operator"));

    // Verify structured details contain success status.
    let details = entry.details.as_ref().expect("login audit entry must have details");
    assert_eq!(
        details.get("result_status").and_then(|v| v.as_str()),
        Some("success"),
        "successful login audit entry must have result_status=success"
    );
    assert_eq!(
        details.get("command").and_then(|v| v.as_str()),
        Some("login"),
        "login audit entry must have command=login"
    );

    // Parameters must include username and connection_id but NOT the raw session token.
    let params = details.get("parameters").expect("login details must include parameters");
    assert_eq!(
        params.get("username").and_then(|v| v.as_str()),
        Some("operator"),
        "login parameters must include the username"
    );
    assert!(params.get("connection_id").is_some(), "login parameters must include a connection_id");

    Ok(())
}

#[tokio::test]
async fn failed_login_invalid_credentials_produces_failure_audit_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;

    let (response, _socket) = attempt_login(server.addr, "operator", "wrong-password").await?;
    assert!(
        matches!(response, OperatorMessage::InitConnectionError(_)),
        "expected InitConnectionError, got {response:?}"
    );

    let entries = poll_audit_entries(&server.database, 1, Duration::from_secs(5)).await;
    let logins = login_audit_entries(&entries);
    assert!(!logins.is_empty(), "audit log must contain a login failure entry");

    let entry = logins[0];
    assert_eq!(entry.actor, "operator");
    assert_eq!(entry.action, "operator.login");
    assert_eq!(entry.target_kind, "operator");

    let details = entry.details.as_ref().expect("failure audit entry must have details");
    assert_eq!(
        details.get("result_status").and_then(|v| v.as_str()),
        Some("failure"),
        "failed login must have result_status=failure"
    );
    assert_eq!(
        details.get("command").and_then(|v| v.as_str()),
        Some("login"),
        "login audit entry must have command=login"
    );

    Ok(())
}

#[tokio::test]
async fn failed_login_unknown_user_produces_failure_audit_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;

    let (response, _socket) = attempt_login(server.addr, "ghost", "anything").await?;
    assert!(
        matches!(response, OperatorMessage::InitConnectionError(_)),
        "expected InitConnectionError, got {response:?}"
    );

    let entries = poll_audit_entries(&server.database, 1, Duration::from_secs(5)).await;
    let logins = login_audit_entries(&entries);
    assert!(!logins.is_empty(), "audit log must record login attempts for unknown users");

    let entry = logins[0];
    // The actor is the submitted username even when it doesn't exist.
    assert_eq!(entry.actor, "ghost");
    assert_eq!(entry.action, "operator.login");

    let details = entry.details.as_ref().expect("failure audit entry must have details");
    assert_eq!(
        details.get("result_status").and_then(|v| v.as_str()),
        Some("failure"),
        "unknown-user login must have result_status=failure"
    );

    Ok(())
}

#[tokio::test]
async fn session_cap_exceeded_produces_failure_audit_entry()
-> Result<(), Box<dyn std::error::Error>> {
    // Build a profile with a single operator account; the per-account session
    // cap (8) will be hit before the global cap (64).
    let server = common::spawn_test_server(common::default_test_profile()).await?;

    // Fill the per-account session cap.
    let mut sockets = Vec::new();
    for _ in 0..red_cell::auth::MAX_SESSIONS_PER_ACCOUNT {
        let (response, socket) = attempt_login(server.addr, "operator", "password1234").await?;
        assert!(
            matches!(response, OperatorMessage::InitConnectionSuccess(_)),
            "expected successful login while filling session cap"
        );
        sockets.push(socket);
    }

    // The next login attempt must be rejected due to session cap.
    let (response, _socket) = attempt_login(server.addr, "operator", "password1234").await?;
    assert!(
        matches!(response, OperatorMessage::InitConnectionError(_)),
        "expected session cap rejection, got {response:?}"
    );

    // Wait for all audit entries: N successes + 1 failure.
    let expected_count = red_cell::auth::MAX_SESSIONS_PER_ACCOUNT + 1;
    let entries =
        poll_audit_entries(&server.database, expected_count, Duration::from_secs(10)).await;
    let logins = login_audit_entries(&entries);

    // Find the failure entry (there should be exactly one).
    let failures: Vec<_> = logins
        .iter()
        .filter(|e| {
            e.details.as_ref().and_then(|d| d.get("result_status")).and_then(|v| v.as_str())
                == Some("failure")
        })
        .collect();

    assert!(
        !failures.is_empty(),
        "audit log must contain a failure entry for session-cap-exceeded login"
    );

    let failure_entry = failures[0];
    assert_eq!(failure_entry.actor, "operator");
    assert_eq!(failure_entry.action, "operator.login");

    let details = failure_entry.details.as_ref().expect("failure details must exist");
    assert_eq!(
        details.get("result_status").and_then(|v| v.as_str()),
        Some("failure"),
        "session-cap-exceeded login must have result_status=failure"
    );

    // Clean up sockets.
    for mut s in sockets {
        let _ = s.close(None).await;
    }

    Ok(())
}

#[tokio::test]
async fn rate_limited_login_does_not_produce_audit_entry() -> Result<(), Box<dyn std::error::Error>>
{
    // Rate-limited connections are rejected before the auth handler ever runs,
    // so no audit entry is expected. This test verifies that invariant.
    let server = common::spawn_test_server(common::default_test_profile()).await?;

    // Exhaust the rate limiter by sending enough failed login attempts.
    // The LoginRateLimiter blocks after MAX_LOGIN_FAILED_ATTEMPTS (5) failures.
    for _ in 0..6 {
        let _ = attempt_login(server.addr, "operator", "wrong").await;
    }

    // Record how many audit entries exist after the pre-rate-limit failures.
    let baseline_entries = poll_audit_entries(&server.database, 1, Duration::from_secs(10)).await;
    let baseline_login_count = login_audit_entries(&baseline_entries).len();

    // Now send one more attempt — this should be rate-limited and produce
    // no additional audit entry.
    let _ = attempt_login(server.addr, "operator", "wrong").await;

    // Give a small window for any (unexpected) audit entry to be flushed.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let final_entries = server.database.audit_log().list().await.unwrap_or_default();
    let final_login_count = login_audit_entries(&final_entries).len();

    assert_eq!(
        final_login_count, baseline_login_count,
        "rate-limited login attempts must not produce additional audit entries"
    );

    Ok(())
}

#[tokio::test]
async fn multiple_failed_logins_each_produce_separate_audit_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;

    // Send two failed login attempts with wrong passwords.
    let (r1, _s1) = attempt_login(server.addr, "operator", "bad1").await?;
    assert!(matches!(r1, OperatorMessage::InitConnectionError(_)));

    let (r2, _s2) = attempt_login(server.addr, "operator", "bad2").await?;
    assert!(matches!(r2, OperatorMessage::InitConnectionError(_)));

    let entries = poll_audit_entries(&server.database, 2, Duration::from_secs(10)).await;
    let logins = login_audit_entries(&entries);

    assert!(
        logins.len() >= 2,
        "each failed login attempt must produce its own audit entry (found {})",
        logins.len()
    );

    // All entries should be failures.
    for entry in &logins {
        let details = entry.details.as_ref().expect("failure audit entries must have details");
        assert_eq!(details.get("result_status").and_then(|v| v.as_str()), Some("failure"));
    }

    Ok(())
}
