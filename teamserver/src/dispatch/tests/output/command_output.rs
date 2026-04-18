//! Tests for the command_output callback handler (generic output, exit codes).

use super::*;

/// Build a length-prefixed string payload suitable for `CallbackParser::read_string`.
fn output_payload(text: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, text.len() as u32);
    buf.extend_from_slice(text.as_bytes());
    buf
}

/// Build a payload with a trailing i32 LE exit code appended after the
/// length-prefixed output string (Specter agent extended format).
fn output_payload_with_exit_code(text: &str, exit_code: i32) -> Vec<u8> {
    let mut buf = output_payload(text);
    buf.extend_from_slice(&exit_code.to_le_bytes());
    buf
}

/// Build registry + database + event bus with a pre-registered sample agent.
async fn setup_with_db() -> (AgentRegistry, Database, EventBus) {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let db_clone = db.clone();
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(16);
    registry.insert(sample_agent()).await.expect("insert sample agent");
    (registry, db_clone, events)
}

#[tokio::test]
async fn command_output_happy_path_broadcasts_and_persists() {
    let (registry, database, events) = setup_with_db().await;
    let mut rx = events.subscribe();
    let text = "whoami\nlab\\operator";
    let payload = output_payload(text);

    let result = handle_command_output_callback(
        &registry, &database, &events, None, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);

    // First broadcast: AgentResponse with correct message format.
    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains(&format!("{} bytes", text.len())),
        "expected message to contain byte count, got {message:?}"
    );
    assert!(
        message.contains("Received Output"),
        "expected 'Received Output' prefix, got {message:?}"
    );
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
}

#[tokio::test]
async fn command_output_empty_output_returns_ok_none_without_broadcast() {
    let (registry, database, events) = setup_with_db().await;
    let mut rx = events.subscribe();
    // Build a payload whose string content is empty (length-prefix = 0).
    let payload = output_payload("");

    let result = handle_command_output_callback(
        &registry, &database, &events, None, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);

    // No broadcast should have occurred.
    drop(events);
    assert!(rx.recv().await.is_none(), "no events should be broadcast for empty output");
}

#[tokio::test]
async fn command_output_truncated_payload_returns_error() {
    let (registry, database, events) = setup_with_db().await;
    // Empty payload — cannot even read the length-prefix u32.
    let payload: Vec<u8> = Vec::new();

    let result = handle_command_output_callback(
        &registry, &database, &events, None, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    let err = result.expect_err("truncated payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn command_output_stores_exit_code_from_extended_payload() {
    let (registry, database, events) = setup_with_db().await;
    let text = "error output";
    let payload = output_payload_with_exit_code(text, 42);

    let result = handle_command_output_callback(
        &registry, &database, &events, None, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    assert!(result.is_ok());

    let records = database.agent_responses().list_for_agent(AGENT_ID).await.expect("list records");
    assert_eq!(records.len(), 1);
    let extra = records[0].extra.as_ref().expect("extra must be present");
    let stored_exit_code =
        extra.get("ExitCode").and_then(Value::as_i64).expect("ExitCode key must exist");
    assert_eq!(stored_exit_code, 42, "exit code must be 42");
}

#[tokio::test]
async fn command_output_without_exit_code_stores_no_exit_code_in_extra() {
    let (registry, database, events) = setup_with_db().await;
    let text = "normal output";
    // Payload without trailing exit code — simulates legacy Havoc demon.
    let payload = output_payload(text);

    let result = handle_command_output_callback(
        &registry, &database, &events, None, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    assert!(result.is_ok());

    let records = database.agent_responses().list_for_agent(AGENT_ID).await.expect("list records");
    assert_eq!(records.len(), 1);
    // extra may be present (carries Type/Message/RequestID) but must not have ExitCode.
    if let Some(extra) = &records[0].extra {
        assert!(
            extra.get("ExitCode").is_none(),
            "ExitCode must not be present when payload has no trailing exit code"
        );
    }
}
