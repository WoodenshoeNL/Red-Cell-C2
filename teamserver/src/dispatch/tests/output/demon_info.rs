//! Tests for the demon_info callback handler and command_error truncation paths.

use super::*;

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

async fn setup_error_handler() -> (AgentRegistry, Database, EventBus) {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let db_clone = db.clone();
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(16);
    registry.insert(sample_agent()).await.expect("insert sample agent");
    (registry, db_clone, events)
}

#[tokio::test]
async fn command_error_win32_truncated_second_field_returns_error() {
    let (registry, database, events) = setup_error_handler().await;
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonCallbackError::Win32));

    let result = handle_command_error_callback(
        &registry, &database, &events, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    let err = result.expect_err("truncated Win32 payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn command_error_token_truncated_second_field_returns_error() {
    let (registry, database, events) = setup_error_handler().await;
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonCallbackError::Token));

    let result = handle_command_error_callback(
        &registry, &database, &events, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    let err = result.expect_err("truncated Token payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn command_error_truncated_before_error_class_returns_error() {
    let (registry, database, events) = setup_error_handler().await;
    let payload = vec![0x01, 0x00];

    let result = handle_command_error_callback(
        &registry, &database, &events, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    let err = result.expect_err("payload too short for error class must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn command_error_generic_persists_to_agent_responses() {
    let (registry, database, events) = setup_error_handler().await;
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::from(DemonCallbackError::Generic));
    let error_text = b"command CommandJob is not supported on Linux";
    payload.extend_from_slice(&(error_text.len() as u32).to_le_bytes());
    payload.extend_from_slice(error_text);

    let result = handle_command_error_callback(
        &registry, &database, &events, AGENT_ID, REQUEST_ID, &payload,
    )
    .await;
    assert!(result.is_ok(), "generic error should succeed: {result:?}");

    let records =
        database.agent_responses().list_for_agent(AGENT_ID).await.expect("list agent responses");
    assert_eq!(records.len(), 1, "expected one persisted response");
    assert_eq!(records[0].response_type, "Error");
    assert!(records[0].output.contains("not supported on Linux"));
}

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
