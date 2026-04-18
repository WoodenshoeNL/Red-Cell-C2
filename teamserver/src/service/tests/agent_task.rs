use super::*;

#[tokio::test]
async fn handle_agent_task_add_enqueues_job() {
    use base64::Engine as _;
    let (db, wh) = test_audit_deps().await;

    let registry = test_registry().await;
    let agent_id: u32 = 0xAABB_CCDD;
    registry.insert(test_agent_record(agent_id)).await.expect("insert agent");

    let events = EventBus::default();
    let mut rx = events.subscribe();

    let payload = vec![0x41, 0x42, 0x43];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "AABBCCDD" },
            "Task": "Add",
            "Command": encoded,
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("task add should succeed");

    let jobs = registry.queued_jobs(agent_id).await.expect("queued jobs");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].payload, payload);
    assert_eq!(jobs[0].operator, "service");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(matches!(event, OperatorMessage::TeamserverLog(_)), "expected teamserver log event");
}

#[tokio::test]
async fn handle_agent_task_get_returns_queued_payloads() {
    use base64::Engine as _;
    use futures_util::StreamExt as _;
    let (db, wh) = test_audit_deps().await;

    let registry = test_registry().await;
    let agent_id: u32 = 0x1122_3344;
    registry.insert(test_agent_record(agent_id)).await.expect("insert agent");

    let job1 = crate::agents::Job {
        payload: vec![0x01, 0x02],
        task_id: "t1".to_owned(),
        created_at: "0".to_owned(),
        operator: "op".to_owned(),
        ..Default::default()
    };
    let job2 = crate::agents::Job {
        payload: vec![0x03, 0x04],
        task_id: "t2".to_owned(),
        created_at: "0".to_owned(),
        operator: "op".to_owned(),
        ..Default::default()
    };
    registry.enqueue_job(agent_id, job1).await.expect("enqueue job1");
    registry.enqueue_job(agent_id, job2).await.expect("enqueue job2");

    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "11223344" },
            "Task": "Get",
        },
    });

    let (mut server_ws, mut client_ws) = ws_pair().await;

    handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("task get should succeed");

    // Read the response from the client side
    let resp = client_ws.next().await.expect("should receive").expect("not error");
    let text = resp.into_text().expect("text message");
    let parsed: Value = serde_json::from_str(&text).expect("valid json");
    let tasks_queue = parsed["Body"]["TasksQueue"].as_str().expect("TasksQueue");
    let decoded =
        base64::engine::general_purpose::STANDARD.decode(tasks_queue).expect("valid base64");
    assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);

    // Queue should be drained
    let remaining = registry.queued_jobs(agent_id).await.expect("queued");
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn handle_agent_task_missing_body_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect_err("should fail");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

#[tokio::test]
async fn handle_agent_task_add_invalid_base64_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let agent_id: u32 = 0xDEAD_BEEF;
    registry.insert(test_agent_record(agent_id)).await.expect("insert agent");
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "DEADBEEF" },
            "Task": "Add",
            "Command": "!!!not-base64!!!",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect_err("should fail");
    assert!(matches!(err, ServiceBridgeError::Base64Decode(_)));
}

#[tokio::test]
async fn handle_agent_task_add_unknown_agent_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "99999999" },
            "Task": "Add",
            "Command": "AAAA",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect_err("should fail for unknown agent");
    assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
}

#[tokio::test]
async fn handle_agent_instance_register_inserts_and_broadcasts() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "256",
                "MagicValue": "deadbeef",
                "AgentID": "AABB0011",
            },
            "RegisterInfo": {
                "Hostname": "SRV01",
                "Username": "admin",
                "DomainName": "CORP",
                "ExternalIP": "10.0.0.5",
                "InternalIP": "192.168.1.5",
                "ProcessName": "agent.exe",
                "ProcessArch": "x64",
                "OSVersion": "Windows 11",
                "OSArch": "x64",
                "SleepDelay": 10,
                "SleepJitter": 20,
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("registration should succeed");

    let agent = registry.get(0xAABB_0011).await.expect("agent should exist");
    assert_eq!(agent.hostname, "SRV01");
    assert_eq!(agent.username, "admin");
    assert_eq!(agent.domain_name, "CORP");
    assert_eq!(agent.sleep_delay, 10);
    assert!(agent.active);

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(matches!(event, OperatorMessage::AgentNew(_)), "expected AgentNew event");
}

#[tokio::test]
async fn handle_agent_instance_register_duplicate_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "0",
                "MagicValue": "DEADBEEF",
                "AgentID": "11223344",
            },
            "RegisterInfo": {
                "Hostname": "H1",
                "Username": "u1",
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("first registration should succeed");

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("duplicate should fail");
    assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
}

#[tokio::test]
async fn handle_agent_instance_register_missing_header_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail without AgentHeader");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

#[tokio::test]
async fn handle_agent_response_broadcasts_event() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_RESPONSE,
            "Agent": { "NameID": "DEAD0001" },
            "Response": "SGVsbG8gV29ybGQ=",
            "RandID": "abc123",
        },
    });

    handle_agent_response(&message, &events).await.expect("response handling should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "DEAD0001");
            assert_eq!(msg.info.command_id, "abc123");
            assert_eq!(msg.info.output, "SGVsbG8gV29ybGQ=");
            assert!(msg.info.command_line.is_none());
            assert_eq!(msg.head.event, EventCode::Session);
            assert_eq!(msg.head.user, "service");
        }
        _ => panic!("expected AgentResponse event"),
    }
}

#[tokio::test]
async fn handle_agent_response_missing_body_returns_error() {
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
    });

    let err = handle_agent_response(&message, &events).await.expect_err("should fail without Body");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

#[tokio::test]
async fn handle_agent_response_missing_optional_fields_uses_defaults() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_RESPONSE,
        },
    });

    handle_agent_response(&message, &events).await.expect("should succeed with defaults");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "unknown");
            assert_eq!(msg.info.command_id, "");
            assert_eq!(msg.info.output, "");
        }
        _ => panic!("expected AgentResponse event"),
    }
}

#[tokio::test]
async fn handle_agent_instance_register_invalid_hex_id_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "ZZZZZZ",
                "MagicValue": "0",
            },
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail with invalid hex");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

#[tokio::test]
async fn handle_agent_instance_register_rejects_wrong_magic_value() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "AABB0011",
                "MagicValue": "CAFEBABE",
            },
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail with wrong magic value");
    assert!(
        matches!(
            err,
            ServiceBridgeError::InvalidMagicValue { expected: 0xDEAD_BEEF, actual: 0xCAFE_BABE }
        ),
        "expected InvalidMagicValue, got {err:?}"
    );
}

#[tokio::test]
async fn handle_agent_instance_register_rejects_missing_magic_value() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "AABB0011",
            },
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail with missing magic value");
    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("MagicValue")),
        "expected MissingField for MagicValue, got {err:?}"
    );
}

#[tokio::test]
async fn handle_agent_instance_register_clamps_overflowing_u32_fields_to_zero() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let over_u32_max: u64 = u32::MAX as u64 + 1;
    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "0",
                "MagicValue": "DEADBEEF",
                "AgentID": "DEAD0001",
            },
            "RegisterInfo": {
                "Hostname": "H1",
                "Username": "u1",
                "ProcessPID": over_u32_max,
                "SleepDelay": over_u32_max,
                "SleepJitter": over_u32_max,
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("registration should succeed");

    let agent = registry.get(0xDEAD_0001).await.expect("agent should exist");
    assert_eq!(agent.process_pid, 0, "ProcessPID should clamp to 0 on overflow");
    assert_eq!(agent.sleep_delay, 0, "SleepDelay should clamp to 0 on overflow");
    assert_eq!(agent.sleep_jitter, 0, "SleepJitter should clamp to 0 on overflow");
}

#[tokio::test]
async fn handle_agent_instance_register_accepts_u32_max_values() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "0",
                "MagicValue": "DEADBEEF",
                "AgentID": "DEAD0002",
            },
            "RegisterInfo": {
                "Hostname": "H2",
                "Username": "u2",
                "ProcessPID": u32::MAX as u64,
                "SleepDelay": u32::MAX as u64,
                "SleepJitter": u32::MAX as u64,
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("registration should succeed");

    let agent = registry.get(0xDEAD_0002).await.expect("agent should exist");
    assert_eq!(agent.process_pid, u32::MAX, "ProcessPID at u32::MAX should be accepted");
    assert_eq!(agent.sleep_delay, u32::MAX, "SleepDelay at u32::MAX should be accepted");
    assert_eq!(agent.sleep_jitter, u32::MAX, "SleepJitter at u32::MAX should be accepted");
}
