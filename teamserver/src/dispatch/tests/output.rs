//! Tests for generic output, error callbacks, credential extraction, and screenshot handling.

use super::common::*;

use super::super::{
    CommandDispatcher, LootContext, extract_credentials, looks_like_credential_line,
    looks_like_inline_secret, looks_like_pwdump_hash, loot_context,
};
use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{DemonCallback, DemonCommand};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;

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
