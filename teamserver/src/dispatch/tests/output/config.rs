//! Tests for the config callback handler (DemonConfigKey variants).

use super::*;

/// Build a config callback payload: config key (u32) + extra fields.
fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, key);
    buf.extend_from_slice(extra);
    buf
}

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
