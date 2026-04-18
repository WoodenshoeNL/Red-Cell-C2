//! Tests for output, error, sleep, exit, kill_date, config, demon_info, and job callbacks.

use super::common::*;

use super::super::output::{
    handle_command_error_callback, handle_command_output_callback, handle_config_callback,
    handle_demon_info_callback, handle_exit_callback, handle_job_callback,
    handle_kill_date_callback, handle_sleep_callback,
};
use super::super::{
    CommandDispatchError, CommandDispatcher, LootContext, extract_credentials,
    looks_like_credential_line, looks_like_inline_secret, looks_like_pwdump_hash, loot_context,
};
use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager, TeamserverError};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{
    DemonCallback, DemonCallbackError, DemonCommand, DemonConfigKey, DemonInfoClass,
};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use zeroize::Zeroizing;

#[tokio::test]
async fn builtin_command_output_handler_captures_credentials_and_broadcasts_loot()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EE01, test_key(0x11), test_iv(0x22))).await?;
    registry
        .enqueue_job(
            0xABCD_EE01,
            Job {
                command: u32::from(DemonCommand::CommandOutput),
                request_id: 0x66,
                payload: Vec::new(),
                command_line: "sekurlsa::logonpasswords".to_owned(),
                task_id: "66".to_owned(),
                created_at: "2026-03-10T10:00:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let mut payload = Vec::new();
    add_bytes(&mut payload, b"Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB");
    dispatcher
        .dispatch(0xABCD_EE01, u32::from(DemonCommand::CommandOutput), 0x66, &payload)
        .await?;

    let first = receiver.recv().await.ok_or("missing output event")?;
    let second = receiver.recv().await.ok_or("missing loot event")?;
    let third = receiver.recv().await.ok_or("missing credential event")?;

    let OperatorMessage::AgentResponse(output_message) = first else {
        panic!("expected command output response");
    };
    assert_eq!(output_message.info.command_line.as_deref(), Some("sekurlsa::logonpasswords"));
    assert_eq!(
        output_message.info.extra.get("Message"),
        Some(&Value::String("Received Output [55 bytes]:".to_owned()))
    );
    assert_eq!(output_message.info.extra.get("RequestID"), Some(&Value::String("66".to_owned())));
    assert_eq!(output_message.info.extra.get("TaskID"), Some(&Value::String("66".to_owned())));

    let OperatorMessage::AgentResponse(loot_message) = second else {
        panic!("expected loot-new response");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );
    assert_eq!(
        loot_message.info.extra.get("Operator"),
        Some(&Value::String("operator".to_owned()))
    );

    let OperatorMessage::CredentialsAdd(credentials) = third else {
        panic!("expected credentials event");
    };
    assert_eq!(
        credentials.info.fields.get("CommandLine"),
        Some(&Value::String("sekurlsa::logonpasswords".to_owned()))
    );

    let loot = database.loot().list_for_agent(0xABCD_EE01).await?;
    assert_eq!(loot.len(), 1);
    assert!(loot.iter().all(|entry| entry.kind == "credential"));
    assert!(loot.iter().any(|entry| {
        entry.data.as_deref()
            == Some(b"Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB".as_slice())
    }));
    assert!(loot.iter().all(|entry| {
        entry.metadata.as_ref().and_then(|value| value.get("operator"))
            == Some(&Value::String("operator".to_owned()))
    }));
    let responses = database.agent_responses().list_for_agent(0xABCD_EE01).await?;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].request_id, 0x66);
    assert_eq!(responses[0].response_type, "Good");
    assert_eq!(responses[0].command_line.as_deref(), Some("sekurlsa::logonpasswords"));
    assert_eq!(responses[0].task_id.as_deref(), Some("66"));
    assert_eq!(responses[0].operator.as_deref(), Some("operator"));
    assert_eq!(responses[0].output, "Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB");
    Ok(())
}

#[test]
fn looks_like_credential_line_matches_expected_patterns() {
    let cases = [
        ("Password : Sup3rSecret!", true),
        ("username=alice", true),
        ("NTLM:0123456789ABCDEF0123456789ABCDEF", true),
        (
            "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
            false,
        ),
        ("status: password reset not required", false),
        ("operator message: secret rotation completed", false),
        ("https://example.test/password/reset", false),
        ("C:\\Windows\\Temp\\password.txt", false),
    ];

    for (line, expected) in cases {
        assert_eq!(
            looks_like_credential_line(line),
            expected,
            "unexpected classification for {line:?}"
        );
    }
}

#[test]
fn looks_like_inline_secret_handles_expected_and_edge_cases() {
    let cases = [
        ("alice@example.com:Sup3rSecret!", true),
        ("LAB\\alice:Sup3rSecret!", true),
        ("operator:Password123", true),
        ("https://alice:Password123@example.test", false),
        ("status: password rotation completed", false),
        ("C:\\Temp\\secret.txt", false),
        ("LAB\\alice:short", true),
    ];

    for (line, expected) in cases {
        assert_eq!(
            looks_like_inline_secret(line),
            expected,
            "unexpected inline-secret classification for {line:?}"
        );
    }
}

#[test]
fn looks_like_pwdump_hash_matches_pwdump_format_only() {
    let cases = [
        (
            "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
            true,
        ),
        ("alice:1001:0123456789ABCDEFFEDCBA9876543210:00112233445566778899AABBCCDDEEFF:::", true),
        ("NTLM:0123456789ABCDEF0123456789ABCDEF", false),
        ("Administrator:500:nothex:32ED87BDB5FDC5E9CBA88547376818D4:::", false),
        ("status: hash sync completed", false),
    ];

    for (line, expected) in cases {
        assert_eq!(
            looks_like_pwdump_hash(line),
            expected,
            "unexpected pwdump classification for {line:?}"
        );
    }
}

#[test]
fn extract_credentials_captures_blocks_inline_secrets_and_hashes() {
    let output = [
        "status: password reset not required",
        "message: domain join succeeded",
        "Username : alice",
        "Password : Sup3rSecret!",
        "Domain   : LAB",
        "",
        "alice@example.com:InlinePass123",
        "C:\\Windows\\Temp\\password.txt",
        "https://example.test/password/reset",
        "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
        "operator message: secret rotation completed",
    ]
    .join("\n");

    let captures = extract_credentials(&output);
    let actual = captures
        .iter()
        .map(|capture| (capture.label.as_str(), capture.pattern, capture.content.as_str()))
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            (
                "credential-block",
                "keyword-block",
                "Username : alice\nPassword : Sup3rSecret!\nDomain   : LAB",
            ),
            ("inline-credential", "inline-secret", "alice@example.com:InlinePass123",),
            (
                "password-hash",
                "pwdump-hash",
                "Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:32ED87BDB5FDC5E9CBA88547376818D4:::",
            ),
        ]
    );
}

#[tokio::test]
async fn builtin_beacon_output_and_error_callbacks_persist_response_history()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EE02, test_key(0x11), test_iv(0x22))).await?;
    registry
        .enqueue_job(
            0xABCD_EE02,
            Job {
                command: u32::from(DemonCommand::BeaconOutput),
                request_id: 0x67,
                payload: Vec::new(),
                command_line: "inline-execute seatbelt".to_owned(),
                task_id: "67".to_owned(),
                created_at: "2026-03-10T10:05:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let mut output = Vec::new();
    add_u32(&mut output, u32::from(DemonCallback::Output));
    add_bytes(&mut output, b"Seatbelt complete");
    dispatcher.dispatch(0xABCD_EE02, u32::from(DemonCommand::BeaconOutput), 0x67, &output).await?;

    let mut error = Vec::new();
    add_u32(&mut error, u32::from(DemonCallback::ErrorMessage));
    add_bytes(&mut error, b"access denied");
    dispatcher.dispatch(0xABCD_EE02, u32::from(DemonCommand::BeaconOutput), 0x67, &error).await?;

    let first = receiver.recv().await.ok_or("missing beacon output event")?;
    let second = receiver.recv().await.ok_or("missing beacon error event")?;

    let OperatorMessage::AgentResponse(first_message) = first else {
        panic!("expected beacon output response");
    };
    assert_eq!(first_message.info.command_line.as_deref(), Some("inline-execute seatbelt"));
    assert_eq!(first_message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));

    let OperatorMessage::AgentResponse(second_message) = second else {
        panic!("expected beacon error response");
    };
    assert_eq!(second_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(second_message.info.extra.get("TaskID"), Some(&Value::String("67".to_owned())));

    let responses = database.agent_responses().list_for_agent(0xABCD_EE02).await?;
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].output, "Seatbelt complete");
    assert_eq!(responses[0].response_type, "Good");
    assert_eq!(responses[1].output, "access denied");
    assert_eq!(responses[1].response_type, "Error");
    assert!(responses.iter().all(|response| response.request_id == 0x67));
    assert!(
        responses.iter().all(|response| {
            response.command_line.as_deref() == Some("inline-execute seatbelt")
        })
    );
    Ok(())
}

#[tokio::test]
async fn builtin_screenshot_handler_persists_loot_and_broadcasts_misc_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF01, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let png = vec![0x89, b'P', b'N', b'G'];
    let payload = [1_u32.to_le_bytes().to_vec(), {
        let mut data = Vec::new();
        add_bytes(&mut data, &png);
        data
    }]
    .concat();

    dispatcher
        .dispatch(0xABCD_EF01, u32::from(DemonCommand::CommandScreenshot), 0x44, &payload)
        .await?;

    let loot = database.loot().list_for_agent(0xABCD_EF01).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].kind, "screenshot");
    assert_eq!(loot[0].data.as_deref(), Some(png.as_slice()));

    let loot_event = receiver.recv().await.ok_or_else(|| "loot event missing".to_owned())?;
    let event = receiver.recv().await.ok_or_else(|| "screenshot response missing".to_owned())?;
    let OperatorMessage::AgentResponse(loot_message) = loot_event else {
        panic!("expected screenshot loot event");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected screenshot agent response event");
    };
    assert_eq!(message.info.extra.get("MiscType"), Some(&Value::String("screenshot".to_owned())));
    assert_eq!(
        message.info.extra.get("MiscData"),
        Some(&Value::String(BASE64_STANDARD.encode(&png)))
    );
    Ok(())
}

// ---- loot_context tests ----

#[tokio::test]
async fn loot_context_unknown_agent_returns_default() -> anyhow::Result<()> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    let unknown_agent_id = 0xDEAD_0001;
    let request_id = 42;

    let ctx = loot_context(&registry, unknown_agent_id, request_id).await;

    assert_eq!(ctx, LootContext::default());
    assert!(ctx.operator.is_empty());
    assert!(ctx.command_line.is_empty());
    assert!(ctx.task_id.is_empty());
    assert!(ctx.queued_at.is_empty());
    Ok(())
}

#[tokio::test]
async fn loot_context_known_agent_unknown_request_id_returns_default() -> anyhow::Result<()> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);

    // Register an agent so the agent_id is known.
    let agent_id = 0x1234_5678;
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let info = sample_agent_info(agent_id, key, iv);
    registry.insert(info).await?;

    // Use a request_id that was never enqueued.
    let unknown_request_id = 0xFFFF;
    let ctx = loot_context(&registry, agent_id, unknown_request_id).await;

    assert_eq!(ctx, LootContext::default());
    assert!(ctx.operator.is_empty());
    assert!(ctx.command_line.is_empty());
    assert!(ctx.task_id.is_empty());
    assert!(ctx.queued_at.is_empty());
    Ok(())
}

// ---- sleep / exit / kill_date / config / demon_info / job / command_output callbacks ----

const AGENT_ID: u32 = 0xBEEF_0001;
const REQUEST_ID: u32 = 99;

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn sample_agent() -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id: AGENT_ID,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0u8; 32]),
            aes_iv: Zeroizing::new(vec![0u8; 16]),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "lab".to_owned(),
        external_ip: "127.0.0.1".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x1000,
        process_pid: 1337,
        process_tid: 7331,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 10,
        sleep_jitter: 25,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-09T20:00:00Z".to_owned(),
        last_call_in: "2026-03-09T20:00:00Z".to_owned(),
    }
}

/// Build registry + event bus with a pre-registered sample agent.
async fn setup() -> (AgentRegistry, EventBus) {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(16);
    registry.insert(sample_agent()).await.expect("insert sample agent");
    (registry, events)
}

fn sleep_payload(delay: u32, jitter: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, delay);
    push_u32(&mut buf, jitter);
    buf
}

#[tokio::test]
async fn sleep_callback_updates_agent_state() {
    let (registry, events) = setup().await;
    let payload = sleep_payload(60, 20);

    let result = handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert_eq!(agent.sleep_delay, 60);
    assert_eq!(agent.sleep_jitter, 20);
}

#[tokio::test]
async fn sleep_callback_broadcasts_agent_update_and_response() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload = sleep_payload(30, 10);

    handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // First broadcast: AgentUpdate (mark event)
    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    // Second broadcast: AgentResponse
    // Drop the event bus so recv returns None after the last queued message.
    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    assert_eq!(resp.info.demon_id, format!("{AGENT_ID:08X}"));
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("30") && message.contains("10"),
        "expected message to contain delay=30 and jitter=10, got {message:?}"
    );
}

#[tokio::test]
async fn sleep_callback_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // Only 4 bytes — missing the jitter field.
    let mut payload = Vec::new();
    push_u32(&mut payload, 60);

    let result = handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn sleep_callback_empty_payload_returns_error() {
    let (registry, events) = setup().await;
    let payload = Vec::new();

    let result = handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("empty payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn sleep_callback_agent_not_found_returns_error() {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(8);
    let payload = sleep_payload(60, 20);
    let nonexistent_id = 0xDEAD_FFFF;

    let result =
        handle_sleep_callback(&registry, &events, nonexistent_id, REQUEST_ID, &payload).await;
    let err = result.expect_err("nonexistent agent must fail");
    assert!(
        matches!(err, CommandDispatchError::Registry(TeamserverError::AgentNotFound { .. })),
        "expected AgentNotFound, got {err:?}"
    );
}

// -- helpers for exit / kill-date callback tests --

/// Build registry + event bus + socket relay manager with a pre-registered sample agent.
async fn setup_with_sockets() -> (AgentRegistry, EventBus, SocketRelayManager) {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(16);
    registry.insert(sample_agent()).await.expect("insert sample agent");
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    (registry, events, sockets)
}

fn exit_payload(exit_method: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, exit_method);
    buf
}

// -- handle_exit_callback tests --

#[tokio::test]
async fn exit_callback_thread_exit_marks_agent_dead() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = exit_payload(1);

    let result =
        handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert!(
        agent.reason.contains("exit thread"),
        "reason should mention thread exit, got {:?}",
        agent.reason
    );
}

#[tokio::test]
async fn exit_callback_process_exit_marks_agent_dead() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = exit_payload(2);

    handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert!(
        agent.reason.contains("exit process"),
        "reason should mention process exit, got {:?}",
        agent.reason
    );
}

#[tokio::test]
async fn exit_callback_unknown_method_marks_agent_dead_generic() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = exit_payload(99);

    handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert_eq!(agent.reason, "Agent exited");
}

#[tokio::test]
async fn exit_callback_broadcasts_mark_and_response() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let mut rx = events.subscribe();
    let payload = exit_payload(1);

    handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // First broadcast: AgentUpdate (mark event)
    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    // Second broadcast: AgentResponse
    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("exit thread"), "expected message about thread exit, got {message:?}");
}

#[tokio::test]
async fn exit_callback_empty_payload_returns_error() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = Vec::new();

    let result =
        handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await;
    let err = result.expect_err("empty payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

// -- handle_kill_date_callback tests --

#[tokio::test]
async fn kill_date_callback_marks_agent_dead() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = Vec::new(); // kill date callback ignores payload

    handle_kill_date_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert!(
        agent.reason.contains("kill date"),
        "reason should mention kill date, got {:?}",
        agent.reason
    );
}

#[tokio::test]
async fn kill_date_callback_broadcasts_mark_and_response() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let mut rx = events.subscribe();
    let payload = Vec::new();

    handle_kill_date_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // First broadcast: AgentUpdate (mark event)
    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    // Second broadcast: AgentResponse
    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("kill date"), "expected message about kill date, got {message:?}");
}

// -- error path tests for non-existent agent --

#[tokio::test]
async fn exit_callback_nonexistent_agent_returns_error() {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let mut rx = events.subscribe();
    let nonexistent_id = 0xDEAD_FFFF;
    let payload = exit_payload(1);

    let result = handle_exit_callback(
        &registry,
        &sockets,
        &events,
        None,
        nonexistent_id,
        REQUEST_ID,
        &payload,
    )
    .await;
    let err = result.expect_err("nonexistent agent must fail");
    assert!(
        matches!(err, CommandDispatchError::Registry(TeamserverError::AgentNotFound { .. })),
        "expected AgentNotFound, got {err:?}"
    );

    // Drop all senders so the receiver closes, then verify no events were queued.
    drop(sockets);
    drop(events);
    assert!(rx.recv().await.is_none(), "no events should be broadcast for a nonexistent agent");
}

#[tokio::test]
async fn kill_date_callback_nonexistent_agent_returns_error() {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let mut rx = events.subscribe();
    let nonexistent_id = 0xDEAD_FFFF;
    let payload = Vec::new();

    let result = handle_kill_date_callback(
        &registry,
        &sockets,
        &events,
        None,
        nonexistent_id,
        REQUEST_ID,
        &payload,
    )
    .await;
    let err = result.expect_err("nonexistent agent must fail");
    assert!(
        matches!(err, CommandDispatchError::Registry(TeamserverError::AgentNotFound { .. })),
        "expected AgentNotFound, got {err:?}"
    );

    // Drop all senders so the receiver closes, then verify no events were queued.
    drop(sockets);
    drop(events);
    assert!(rx.recv().await.is_none(), "no events should be broadcast for a nonexistent agent");
}

// -- helpers for config callback tests --

/// Build a config callback payload: config key (u32) + extra fields.
fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, key);
    buf.extend_from_slice(extra);
    buf
}

// -- KillDate tests --

#[tokio::test]
async fn config_kill_date_nonzero_sets_agent_kill_date() {
    let (registry, events) = setup().await;
    let kill_date_raw: u64 = 1_700_000_000;
    let mut extra = Vec::new();
    push_u64(&mut extra, kill_date_raw);
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert_eq!(agent.kill_date, Some(kill_date_raw as i64));
}

#[tokio::test]
async fn config_kill_date_zero_disables_kill_date() {
    let (registry, events) = setup().await;

    // First set a non-zero kill date.
    let mut extra = Vec::new();
    push_u64(&mut extra, 1_700_000_000);
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
    handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("set kill date must succeed");

    // Now disable it with raw=0.
    let mut extra_zero = Vec::new();
    push_u64(&mut extra_zero, 0);
    let payload_zero = config_payload(u32::from(DemonConfigKey::KillDate), &extra_zero);
    handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload_zero)
        .await
        .expect("disable kill date must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert_eq!(agent.kill_date, None, "kill_date should be None when raw=0");
}

#[tokio::test]
async fn config_kill_date_broadcasts_mark_and_response() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u64(&mut extra, 1_700_000_000);
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);

    handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // First broadcast: AgentUpdate (mark event)
    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    // Second broadcast: AgentResponse
    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("KillDate"), "expected KillDate message, got {message:?}");
}

// -- WorkingHours tests --

#[tokio::test]
async fn config_working_hours_nonzero_sets_agent_working_hours() {
    let (registry, events) = setup().await;
    let raw: u32 = 0b101010;
    let mut extra = Vec::new();
    push_u32(&mut extra, raw);
    let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert_eq!(agent.working_hours, Some(42i32));
}

#[tokio::test]
async fn config_working_hours_zero_disables_working_hours() {
    let (registry, events) = setup().await;

    // First set a non-zero value.
    let mut extra = Vec::new();
    push_u32(&mut extra, 0b101010);
    let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);
    handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("set working hours must succeed");

    // Now disable with raw=0.
    let mut extra_zero = Vec::new();
    push_u32(&mut extra_zero, 0);
    let payload_zero = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra_zero);
    handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload_zero)
        .await
        .expect("disable working hours must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert_eq!(agent.working_hours, None, "working_hours should be None when raw=0");
}

#[tokio::test]
async fn config_working_hours_broadcasts_mark_and_response() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 0b101010);
    let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);

    handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("WorkingHours"), "expected WorkingHours message, got {message:?}");
}

// -- Simple key (MemoryAlloc) test --

#[tokio::test]
async fn config_memory_alloc_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 42);
    let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &extra);

    handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // MemoryAlloc only broadcasts a response, no AgentUpdate.
    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("42"),
        "expected message to contain the alloc value 42, got {message:?}"
    );
}

// -- Unknown config key test --

#[tokio::test]
async fn config_unknown_key_returns_error() {
    let (registry, events) = setup().await;
    let payload = config_payload(0xFFFF, &[]);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("unknown config key must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

// -- Truncated payload tests --

#[tokio::test]
async fn config_kill_date_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // KillDate needs 8 bytes (u64) after the key, provide only 4.
    let mut extra = Vec::new();
    push_u32(&mut extra, 123);
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated kill date payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn config_working_hours_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // WorkingHours needs 4 bytes (u32) after the key, provide none.
    let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &[]);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated working hours payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn config_empty_payload_returns_error() {
    let (registry, events) = setup().await;
    let payload = Vec::new();

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("empty payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

// -- helpers for encoding length-prefixed fields --

/// Encode a UTF-8 string as a length-prefixed byte blob (u32 LE length + raw bytes).
fn push_length_prefixed_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    push_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

/// Encode a string as a length-prefixed UTF-16 LE byte blob.
fn push_length_prefixed_utf16(buf: &mut Vec<u8>, s: &str) {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = words.len() * 2;
    push_u32(buf, byte_len as u32);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

// -- MemoryExecute tests --

#[tokio::test]
async fn config_memory_execute_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 64);
    let payload = config_payload(u32::from(DemonConfigKey::MemoryExecute), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("64"),
        "expected message to contain the execute value 64, got {message:?}"
    );
}

// -- InjectSpawn64 tests --

#[tokio::test]
async fn config_inject_spawn64_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_length_prefixed_utf16(&mut extra, "C:\\Windows\\System32\\notepad.exe");
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("notepad.exe"), "expected message to contain path, got {message:?}");
}

// -- InjectSpawn32 tests --

#[tokio::test]
async fn config_inject_spawn32_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_length_prefixed_utf16(&mut extra, "C:\\Windows\\SysWOW64\\cmd.exe");
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn32), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("cmd.exe"), "expected message to contain path, got {message:?}");
}

// -- ImplantSpfThreadStart tests --

#[tokio::test]
async fn config_spf_thread_start_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_length_prefixed_string(&mut extra, "ntdll.dll");
    push_length_prefixed_string(&mut extra, "RtlUserThreadStart");
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("ntdll.dll!RtlUserThreadStart"),
        "expected module!symbol format, got {message:?}"
    );
}

// -- ImplantSleepTechnique tests --

#[tokio::test]
async fn config_sleep_technique_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 3);
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSleepTechnique), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("3"), "expected message to contain technique id, got {message:?}");
}

// -- ImplantCoffeeVeh tests --

#[tokio::test]
async fn config_coffee_veh_true_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 1); // true
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeVeh), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("true"), "expected message to contain 'true', got {message:?}");
}

#[tokio::test]
async fn config_coffee_veh_false_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 0); // false
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeVeh), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("false"), "expected message to contain 'false', got {message:?}");
}

// -- ImplantCoffeeThreaded tests --

#[tokio::test]
async fn config_coffee_threaded_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 1); // true
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeThreaded), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("true"), "expected message to contain 'true', got {message:?}");
}

// -- InjectTechnique tests --

#[tokio::test]
async fn config_inject_technique_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 7);
    let payload = config_payload(u32::from(DemonConfigKey::InjectTechnique), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("7"), "expected message to contain technique id, got {message:?}");
}

// -- InjectSpoofAddr tests --

#[tokio::test]
async fn config_inject_spoof_addr_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_length_prefixed_string(&mut extra, "kernel32.dll");
    push_length_prefixed_string(&mut extra, "CreateThread");
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpoofAddr), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("kernel32.dll!CreateThread"),
        "expected module!symbol format, got {message:?}"
    );
}

// -- ImplantVerbose tests --

#[tokio::test]
async fn config_implant_verbose_true_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 1); // true
    let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("true"), "expected message to contain 'true', got {message:?}");
}

#[tokio::test]
async fn config_implant_verbose_false_formats_message_correctly() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();

    let mut extra = Vec::new();
    push_u32(&mut extra, 0); // false
    let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("false"), "expected message to contain 'false', got {message:?}");
}

// -- Truncated payload tests for newly-covered read types --

#[tokio::test]
async fn config_memory_execute_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // MemoryExecute needs u32 after the key, provide none.
    let payload = config_payload(u32::from(DemonConfigKey::MemoryExecute), &[]);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn config_inject_spawn64_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // InjectSpawn64 calls read_utf16 which needs at least a u32 length prefix.
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &[]);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated utf16 payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn config_spf_thread_start_truncated_second_string_returns_error() {
    let (registry, events) = setup().await;
    // Provide one valid string but truncate before the second.
    let mut extra = Vec::new();
    push_length_prefixed_string(&mut extra, "ntdll.dll");
    // No second string — parser should fail on read_string for symbol.
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated second string must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn config_coffee_veh_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // read_bool needs u32 (4 bytes), provide none.
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeVeh), &[]);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated bool payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn config_inject_spoof_addr_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // Provide first string, omit second.
    let mut extra = Vec::new();
    push_length_prefixed_string(&mut extra, "kernel32.dll");
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpoofAddr), &extra);

    let result = handle_config_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated second string must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

// -- handle_demon_info_callback tests ────────────────────────────────────

fn demon_info_payload_mem_alloc(pointer: u64, size: u32, protection: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, u32::from(DemonInfoClass::MemAlloc));
    push_u64(&mut buf, pointer);
    push_u32(&mut buf, size);
    push_u32(&mut buf, protection);
    buf
}

fn demon_info_payload_mem_exec(function: u64, thread_id: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, u32::from(DemonInfoClass::MemExec));
    push_u64(&mut buf, function);
    push_u32(&mut buf, thread_id);
    buf
}

fn demon_info_payload_mem_protect(memory: u64, size: u32, old: u32, new: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, u32::from(DemonInfoClass::MemProtect));
    push_u64(&mut buf, memory);
    push_u32(&mut buf, size);
    push_u32(&mut buf, old);
    push_u32(&mut buf, new);
    buf
}

// -- handle_command_error_callback truncated payload tests --

#[tokio::test]
async fn command_error_win32_truncated_second_field_returns_error() {
    let (_registry, events) = setup().await;
    // Win32 error class present, but no subsequent error_code u32.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonCallbackError::Win32));

    let result = handle_command_error_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated Win32 payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn command_error_token_truncated_second_field_returns_error() {
    let (_registry, events) = setup().await;
    // Token error class present, but no subsequent status u32.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonCallbackError::Token));

    let result = handle_command_error_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated Token payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn command_error_truncated_before_error_class_returns_error() {
    let (_registry, events) = setup().await;
    // Only 2 bytes — not enough to read the error class u32.
    let payload = vec![0x01, 0x00];

    let result = handle_command_error_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("payload too short for error class must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

// -- handle_demon_info_callback tests ────────────────────────────────────

#[tokio::test]
async fn demon_info_mem_alloc_formats_message() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload = demon_info_payload_mem_alloc(0x7FFE_0000_1000, 4096, 0x04);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive broadcast");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("0x7ffe00001000"), "expected pointer in message, got {message:?}");
    assert!(message.contains("4096"), "expected size in message, got {message:?}");
    assert!(
        message.contains("PAGE_READWRITE"),
        "expected protection name in message, got {message:?}"
    );
}

#[tokio::test]
async fn demon_info_mem_exec_formats_message() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload = demon_info_payload_mem_exec(0xDEAD_BEEF_CAFE, 42);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive broadcast");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("0xdeadbeefcafe"),
        "expected function pointer in message, got {message:?}"
    );
    assert!(message.contains("42"), "expected thread id in message, got {message:?}");
}

#[tokio::test]
async fn demon_info_mem_protect_formats_both_protections() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload = demon_info_payload_mem_protect(0x1000_2000, 8192, 0x02, 0x40);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive broadcast");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("0x10002000"), "expected memory address in message, got {message:?}");
    assert!(message.contains("8192"), "expected size in message, got {message:?}");
    assert!(
        message.contains("PAGE_READONLY"),
        "expected old protection in message, got {message:?}"
    );
    assert!(
        message.contains("PAGE_EXECUTE_READWRITE"),
        "expected new protection in message, got {message:?}"
    );
}

#[tokio::test]
async fn demon_info_unknown_class_returns_ok_none() {
    let (_registry, events) = setup().await;
    // Use a class value that doesn't map to any DemonInfoClass variant.
    let mut payload = Vec::new();
    push_u32(&mut payload, 0xFF);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("unknown class must not error"), None);
}

#[tokio::test]
async fn demon_info_mem_alloc_truncated_returns_error() {
    let (_registry, events) = setup().await;
    // Only info class, missing pointer/size/protection.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonInfoClass::MemAlloc));

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated MemAlloc payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn demon_info_mem_exec_truncated_returns_error() {
    let (_registry, events) = setup().await;
    // Only info class, missing function/thread_id.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonInfoClass::MemExec));

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated MemExec payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn demon_info_mem_protect_truncated_returns_error() {
    let (_registry, events) = setup().await;
    // Only info class + memory address, missing size/old/new.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonInfoClass::MemProtect));
    push_u64(&mut payload, 0x1000);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated MemProtect payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn demon_info_proc_create_truncated_after_class_returns_error() {
    let (_registry, events) = setup().await;
    // Only info class tag, no path length or any other field.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonInfoClass::ProcCreate));

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated ProcCreate payload (no path) must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn demon_info_proc_create_truncated_mid_path_returns_error() {
    let (_registry, events) = setup().await;
    // Class tag + path length that claims 20 bytes, but only 4 bytes of path data.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonInfoClass::ProcCreate));
    push_u32(&mut payload, 20_u32); // path length: 20 bytes
    payload.extend_from_slice(&[0x41, 0x00, 0x42, 0x00]); // only 4 bytes of UTF-16

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated ProcCreate payload (mid-path) must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn demon_info_proc_create_truncated_after_path_returns_error() {
    let (_registry, events) = setup().await;
    // Class tag + complete path, but missing pid/success/piped/verbose.
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonInfoClass::ProcCreate));
    let path = "C:\\a";
    let utf16: Vec<u16> = path.encode_utf16().collect();
    let byte_len = utf16.len() * 2;
    push_u32(&mut payload, byte_len as u32);
    for code_unit in &utf16 {
        payload.extend_from_slice(&code_unit.to_le_bytes());
    }
    // No pid, success, piped, or verbose fields.

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated ProcCreate payload (after path) must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

// -- ProcCreate branch tests ────────────────────────────────────────────

/// Build a ProcCreate payload with given (path, pid, success, piped, verbose).
fn demon_info_payload_proc_create(
    path: &str,
    pid: u32,
    success: bool,
    piped: bool,
    verbose: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, u32::from(DemonInfoClass::ProcCreate));
    // UTF-16 LE encoded path (read_utf16 reads length-prefixed bytes)
    let utf16: Vec<u16> = path.encode_utf16().collect();
    let byte_len = utf16.len() * 2;
    push_u32(&mut buf, byte_len as u32);
    for code_unit in &utf16 {
        buf.extend_from_slice(&code_unit.to_le_bytes());
    }
    push_u32(&mut buf, pid);
    push_u32(&mut buf, u32::from(success));
    push_u32(&mut buf, u32::from(piped));
    push_u32(&mut buf, u32::from(verbose));
    buf
}

#[tokio::test]
async fn demon_info_proc_create_not_verbose_returns_ok_none() {
    let (_registry, events) = setup().await;
    let payload = demon_info_payload_proc_create("C:\\Windows\\cmd.exe", 1234, true, false, false);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);
}

#[tokio::test]
async fn demon_info_proc_create_verbose_success_broadcasts_started() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload = demon_info_payload_proc_create("C:\\Windows\\cmd.exe", 5678, true, false, true);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive broadcast");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("Process started"),
        "expected 'Process started' in message, got {message:?}"
    );
    assert!(message.contains("cmd.exe"), "expected path in message, got {message:?}");
    assert!(message.contains("5678"), "expected ProcessID in message, got {message:?}");
}

#[tokio::test]
async fn demon_info_proc_create_verbose_fail_not_piped_broadcasts_could_not_start() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload =
        demon_info_payload_proc_create("C:\\Windows\\notepad.exe", 9999, false, false, true);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive broadcast");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("could not be started"),
        "expected 'could not be started' in message, got {message:?}"
    );
    assert!(message.contains("notepad.exe"), "expected path in message, got {message:?}");
    // ProcessID should NOT be present in the failure message.
    assert!(
        !message.contains("ProcessID"),
        "failure message should not contain ProcessID, got {message:?}"
    );
}

#[tokio::test]
async fn demon_info_proc_create_verbose_fail_piped_broadcasts_without_output_pipe() {
    let (_registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload =
        demon_info_payload_proc_create("C:\\Windows\\powershell.exe", 4321, false, true, true);

    let result = handle_demon_info_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert_eq!(result.expect("must succeed"), None);

    let msg = rx.recv().await.expect("should receive broadcast");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("without output pipe"),
        "expected 'without output pipe' in message, got {message:?}"
    );
    assert!(message.contains("powershell.exe"), "expected path in message, got {message:?}");
    assert!(message.contains("4321"), "expected ProcessID in message, got {message:?}");
}

// -- handle_job_callback tests --

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

// -- handle_command_output_callback tests --

/// Build a length-prefixed string payload suitable for `CallbackParser::read_string`.
fn output_payload(text: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, text.len() as u32);
    buf.extend_from_slice(text.as_bytes());
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

/// Build a payload with a trailing i32 LE exit code appended after the
/// length-prefixed output string (Specter agent extended format).
fn output_payload_with_exit_code(text: &str, exit_code: i32) -> Vec<u8> {
    let mut buf = output_payload(text);
    buf.extend_from_slice(&exit_code.to_le_bytes());
    buf
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
