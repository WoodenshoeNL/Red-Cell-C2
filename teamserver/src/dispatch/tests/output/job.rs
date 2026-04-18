//! Tests for the job callback handler (suspend, resume, kill/remove, died).

use super::*;

fn job_payload_subcommand(subcommand: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, subcommand);
    buf
}

fn job_payload_action(subcommand: u32, job_id: u32, success: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, subcommand);
    push_u32(&mut buf, job_id);
    push_u32(&mut buf, success);
    buf
}

#[tokio::test]
async fn job_callback_died_returns_ok_none_and_broadcasts_nothing() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();

    // DemonJobCommand::Died = 5
    let payload = job_payload_subcommand(5);
    let result = handle_job_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("Died must succeed"), None);

    // Drop the event bus so recv returns None when the queue is empty.
    drop(events);
    let recv_result = rx.recv().await;
    assert!(recv_result.is_none(), "Died should not broadcast anything, but got {recv_result:?}");
}

#[tokio::test]
async fn job_callback_empty_payload_returns_error() {
    let (_registry, events) = setup().await;
    let payload: Vec<u8> = Vec::new();

    let err = handle_job_callback(&events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect_err("empty payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn job_callback_unknown_subcommand_returns_error() {
    let (_registry, events) = setup().await;
    // Use a value outside the known enum range (0, 99, 255, etc.)
    let payload = job_payload_subcommand(255);

    let err = handle_job_callback(&events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect_err("unknown subcommand must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn job_callback_suspend_truncated_payload_returns_error() {
    let (_registry, events) = setup().await;
    // DemonJobCommand::Suspend = 2, but no job_id or success fields
    let payload = job_payload_subcommand(2);

    let err = handle_job_callback(&events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect_err("truncated Suspend payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn job_callback_resume_truncated_payload_returns_error() {
    let (_registry, events) = setup().await;
    // DemonJobCommand::Resume = 3, but no job_id or success fields
    let payload = job_payload_subcommand(3);

    let err = handle_job_callback(&events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect_err("truncated Resume payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn job_callback_kill_remove_truncated_payload_returns_error() {
    let (_registry, events) = setup().await;
    // DemonJobCommand::KillRemove = 4, but no job_id or success fields
    let payload = job_payload_subcommand(4);

    let err = handle_job_callback(&events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect_err("truncated KillRemove payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn job_callback_suspend_success_broadcasts_response() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();
    // DemonJobCommand::Suspend = 2, job_id = 42, success = 1
    let payload = job_payload_action(2, 42, 1);

    let result = handle_job_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive broadcast");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("suspended") && message.contains("42"),
        "expected suspend success message with job_id 42, got {message:?}"
    );
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
}
