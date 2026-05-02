//! Low-level integration tests that build binary payloads and call handler
//! functions directly: ppid-spoof, process-list, inject-shellcode/dll/spawn-dll,
//! process-kill, process-modules, process-grep, and process-memory.

use super::*;

// ── payload builder helpers ─────────────────────────────────────────────

/// Build a binary payload for `handle_proc_ppid_spoof_callback`.
fn build_ppid_spoof_payload(ppid: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, ppid);
    buf
}

/// Build a binary payload for `handle_process_list_callback`.
fn build_process_list_payload(
    from_process_manager: u32,
    rows: &[(&str, u32, u32, u32, u32, u32, &str)], // name, pid, is_wow, ppid, session, threads, user
) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, from_process_manager);
    for &(name, pid, is_wow, ppid, session, threads, user) in rows {
        add_utf16(&mut buf, name);
        add_u32(&mut buf, pid);
        add_u32(&mut buf, is_wow);
        add_u32(&mut buf, ppid);
        add_u32(&mut buf, session);
        add_u32(&mut buf, threads);
        add_utf16(&mut buf, user);
    }
    buf
}

/// Build a payload containing a single u32 status code (for inject/spawn handlers).
fn build_status_payload(status: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, status);
    buf
}

// ── handle_proc_ppid_spoof_callback ─────────────────────────────────────

fn temp_db_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("red-cell-dispatch-process-{}.sqlite", uuid::Uuid::new_v4()))
}

fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
    use red_cell_common::AgentEncryptionInfo;
    use zeroize::Zeroizing;
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"0123456789abcdef0123456789abcdef".to_vec()),
            aes_iv: Zeroizing::new(b"0123456789abcdef".to_vec()),
            monotonic_ctr: false,
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "LAB".to_owned(),
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
        archon_magic: None,
    }
}

async fn process_callback_test_harness(agent_id: u32) -> (AgentRegistry, Database, EventBus) {
    let database = Database::connect(temp_db_path()).await.expect("connect db");
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent(agent_id)).await.expect("insert agent");
    let events = EventBus::default();
    (registry, database, events)
}

async fn process_callback_stub_harness() -> (AgentRegistry, Database, EventBus) {
    let database = Database::connect(temp_db_path()).await.expect("connect db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    (registry, database, events)
}

#[tokio::test]
async fn ppid_spoof_updates_registry_and_broadcasts() {
    let agent_id = 0xABCD_0001;
    let (registry, database, events) = process_callback_test_harness(agent_id).await;
    let mut rx = events.subscribe();

    let payload = build_ppid_spoof_payload(9999);
    handle_proc_ppid_spoof_callback(&registry, &database, &events, agent_id, 1, &payload)
        .await
        .expect("handler should succeed");

    // Agent's process_ppid should be updated in the registry.
    let updated = registry.get(agent_id).await.expect("agent should exist");
    assert_eq!(updated.process_ppid, 9999);

    // Two events: agent_mark_event + agent_response_event
    let _mark_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive mark event")
        .expect("mark event");

    let response_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive response event")
        .expect("response event");

    let (kind, message) = extract_response_kind_and_message(&response_event);
    assert_eq!(kind, "Good");
    assert!(message.contains("9999"), "expected ppid in message, got: {message}");
}

#[tokio::test]
async fn ppid_spoof_missing_agent_still_broadcasts_response() {
    let (registry, database, events) = process_callback_stub_harness().await;
    let mut rx = events.subscribe();
    let agent_id = 0xDEAD_BEEF;

    let payload = build_ppid_spoof_payload(42);
    let result =
        handle_proc_ppid_spoof_callback(&registry, &database, &events, agent_id, 5, &payload).await;

    assert!(result.is_ok(), "handler should not panic for missing agent");

    // Only the response event should be broadcast (no mark event).
    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive response event")
        .expect("response event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("42"), "expected ppid in message, got: {message}");
}

#[tokio::test]
async fn inject_shellcode_missing_agent_still_broadcasts_response() {
    let (registry, database, events) = process_callback_stub_harness().await;
    let mut rx = events.subscribe();
    let agent_id = 0xDEAD_BEEF;

    let payload = build_status_payload(u32::from(DemonInjectError::Success));
    let result =
        handle_inject_shellcode_callback(&registry, &database, &events, agent_id, 9, &payload)
            .await;

    assert!(result.is_ok(), "handler should not fail for missing agent (FK-safe path)");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive response event")
        .expect("response event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("Successfully injected shellcode"), "got: {message}");
}

#[tokio::test]
async fn ppid_spoof_truncated_payload_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    // Payload too short — only 2 bytes instead of 4.
    let result =
        handle_proc_ppid_spoof_callback(&registry, &database, &events, 1, 1, &[0x01, 0x02]).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload, got: {result:?}"
    );
}

// ── handle_process_list_callback ────────────────────────────────────────

#[tokio::test]
async fn process_list_happy_path_broadcasts_table_and_json() {
    let (registry, database, events) = process_callback_test_harness(0xAA).await;
    let mut rx = events.subscribe();
    let payload = build_process_list_payload(
        0, // from_process_manager
        &[
            ("svchost.exe", 800, 0, 4, 0, 12, "SYSTEM"),
            ("explorer.exe", 1200, 1, 800, 1, 32, "user1"),
        ],
    );

    let result =
        handle_process_list_callback(&registry, &database, &events, 0xAA, 1, &payload).await;
    assert!(result.is_ok());
    assert!(result.expect("unwrap").is_none());

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event")
        .expect("broadcast event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    // Check structured JSON extra
    let rows_json = msg.info.extra.get("ProcessListRows").expect("missing ProcessListRows");
    let arr = rows_json.as_array().expect("ProcessListRows should be array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["Name"], "svchost.exe");
    assert_eq!(arr[0]["PID"], 800);
    assert_eq!(arr[0]["Arch"], "x64"); // is_wow=0 → x64
    assert_eq!(arr[1]["Name"], "explorer.exe");
    assert_eq!(arr[1]["Arch"], "x86"); // is_wow=1 → x86
    assert_eq!(arr[1]["User"], "user1");

    // Check the message type
    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");
}

#[tokio::test]
async fn process_list_empty_returns_none_without_broadcasting() {
    let (registry, database, events) = process_callback_stub_harness().await;
    let mut rx = events.subscribe();
    // No rows, just the from_process_manager flag.
    let payload = build_process_list_payload(0, &[]);

    let result =
        handle_process_list_callback(&registry, &database, &events, 0xBB, 2, &payload).await;
    assert!(result.is_ok());
    assert!(result.expect("unwrap").is_none());

    let timeout_result =
        tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
    assert!(timeout_result.is_err(), "expected no broadcast for empty process list");
}

#[tokio::test]
async fn process_list_truncated_row_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    // Payload with the flag but a truncated row (just 2 bytes of garbage).
    let mut payload = Vec::new();
    add_u32(&mut payload, 0); // from_process_manager
    payload.extend_from_slice(&[0x01, 0x02]); // truncated — not enough for a utf16 length

    let result =
        handle_process_list_callback(&registry, &database, &events, 0xCC, 3, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated row, got: {result:?}"
    );
}

// ── handle_inject_shellcode_callback ────────────────────────────────────

#[tokio::test]
async fn inject_shellcode_success_broadcasts_good() {
    let (registry, database, events) = process_callback_test_harness(0xAA).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Success));

    handle_inject_shellcode_callback(&registry, &database, &events, 0xAA, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("Successfully"), "got: {message}");
}

#[tokio::test]
async fn inject_shellcode_failed_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xAA).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Failed));

    handle_inject_shellcode_callback(&registry, &database, &events, 0xAA, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, _) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
}

#[tokio::test]
async fn inject_shellcode_invalid_param_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xAA).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

    handle_inject_shellcode_callback(&registry, &database, &events, 0xAA, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("Invalid parameter"), "got: {message}");
}

#[tokio::test]
async fn inject_shellcode_arch_mismatch_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xAA).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

    handle_inject_shellcode_callback(&registry, &database, &events, 0xAA, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("architecture mismatch"), "got: {message}");
}

#[tokio::test]
async fn inject_shellcode_unknown_status_returns_error() {
    let (registry, database, events) = process_callback_test_harness(0xAA).await;
    let payload = build_status_payload(0xFFFF);

    let result =
        handle_inject_shellcode_callback(&registry, &database, &events, 0xAA, 1, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for unknown status, got: {result:?}"
    );
}

// ── handle_inject_dll_callback ──────────────────────────────────────────

#[tokio::test]
async fn inject_dll_success_broadcasts_good() {
    let (registry, database, events) = process_callback_test_harness(0xBB).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Success));

    handle_inject_dll_callback(&registry, &database, &events, 0xBB, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("Successfully"), "got: {message}");
}

#[tokio::test]
async fn inject_dll_failed_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xBB).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Failed));

    handle_inject_dll_callback(&registry, &database, &events, 0xBB, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, _) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
}

#[tokio::test]
async fn inject_dll_invalid_param_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xBB).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

    handle_inject_dll_callback(&registry, &database, &events, 0xBB, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("invalid parameter"), "got: {message}");
}

#[tokio::test]
async fn inject_dll_arch_mismatch_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xBB).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

    handle_inject_dll_callback(&registry, &database, &events, 0xBB, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("architecture mismatch"), "got: {message}");
}

#[tokio::test]
async fn inject_dll_unknown_status_returns_error() {
    let (registry, database, events) = process_callback_test_harness(0xBB).await;
    let payload = build_status_payload(0xFFFF);

    let result = handle_inject_dll_callback(&registry, &database, &events, 0xBB, 1, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload, got: {result:?}"
    );
}

// ── handle_spawn_dll_callback ───────────────────────────────────────────

#[tokio::test]
async fn spawn_dll_success_broadcasts_good() {
    let (registry, database, events) = process_callback_test_harness(0xCC).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Success));

    handle_spawn_dll_callback(&registry, &database, &events, 0xCC, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("Successfully"), "got: {message}");
}

#[tokio::test]
async fn spawn_dll_failed_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xCC).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Failed));

    handle_spawn_dll_callback(&registry, &database, &events, 0xCC, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, _) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
}

#[tokio::test]
async fn spawn_dll_invalid_param_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xCC).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

    handle_spawn_dll_callback(&registry, &database, &events, 0xCC, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("invalid parameter"), "got: {message}");
}

#[tokio::test]
async fn spawn_dll_arch_mismatch_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xCC).await;
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

    handle_spawn_dll_callback(&registry, &database, &events, 0xCC, 1, &payload)
        .await
        .expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("architecture mismatch"), "got: {message}");
}

#[tokio::test]
async fn spawn_dll_unknown_status_returns_error() {
    let (registry, database, events) = process_callback_test_harness(0xCC).await;
    let payload = build_status_payload(0xFFFF);

    let result = handle_spawn_dll_callback(&registry, &database, &events, 0xCC, 1, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload, got: {result:?}"
    );
}

// ── handle_process_command_callback — Kill branch ──────────────────────

fn build_process_kill_payload(success: u32, pid: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Kill));
    add_u32(&mut buf, success);
    add_u32(&mut buf, pid);
    buf
}

#[tokio::test]
async fn process_kill_success_broadcasts_good_with_pid() {
    let (registry, database, events) = process_callback_test_harness(0xA1).await;
    let mut rx = events.subscribe();
    let payload = build_process_kill_payload(1, 4200);

    handle_process_command_callback(&registry, &database, &events, 0xA1, 10, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("4200"), "expected pid in message, got: {message}");
}

#[tokio::test]
async fn process_kill_failure_broadcasts_error() {
    let (registry, database, events) = process_callback_test_harness(0xA2).await;
    let mut rx = events.subscribe();
    let payload = build_process_kill_payload(0, 4200);

    handle_process_command_callback(&registry, &database, &events, 0xA2, 11, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("Failed"), "expected failure message, got: {message}");
}

// ── handle_process_command_callback — Kill branch (truncated payloads) ─

#[tokio::test]
async fn process_kill_empty_payload_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    // Payload: only the subcommand u32 (Kill), no success or pid fields.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Kill));

    let result =
        handle_process_command_callback(&registry, &database, &events, 0xA3, 12, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for empty kill body, got: {result:?}"
    );
}

#[tokio::test]
async fn process_kill_truncated_pid_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    // Payload: subcommand u32 (Kill) + success u32, but NO pid field.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Kill));
    add_u32(&mut payload, 1); // success field only

    let result =
        handle_process_command_callback(&registry, &database, &events, 0xA4, 13, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated kill pid, got: {result:?}"
    );
}

#[tokio::test]
async fn process_kill_full_payload_success_returns_ok() {
    // Regression guard: a well-formed 8-byte body (success=1, pid) must still succeed.
    let (registry, database, events) = process_callback_test_harness(0xA5).await;
    let payload = build_process_kill_payload(1, 9999);

    let result =
        handle_process_command_callback(&registry, &database, &events, 0xA5, 14, &payload).await;
    assert!(result.is_ok(), "expected Ok for full kill payload, got: {result:?}");
}

// ── handle_process_command_callback — Modules branch ────────────────────

fn add_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    add_u32(buf, u32::try_from(bytes.len()).expect("unwrap"));
    buf.extend_from_slice(bytes);
}

fn build_process_modules_payload(pid: u32, modules: &[(&str, u64)]) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Modules));
    add_u32(&mut buf, pid);
    for &(name, base) in modules {
        add_string(&mut buf, name);
        add_u64(&mut buf, base);
    }
    buf
}

#[tokio::test]
async fn process_modules_broadcasts_info_with_table_and_json() {
    let (registry, database, events) = process_callback_test_harness(0xB1).await;
    let mut rx = events.subscribe();
    let payload = build_process_modules_payload(
        1234,
        &[("ntdll.dll", 0x7FFE_0000_0000), ("kernel32.dll", 0x7FFE_0001_0000)],
    );

    handle_process_command_callback(&registry, &database, &events, 0xB1, 20, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("1234"), "expected PID in message, got: {message}");

    let rows_json = msg.info.extra.get("ModuleRows").expect("missing ModuleRows");
    let arr = rows_json.as_array().expect("ModuleRows should be array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["Name"], "ntdll.dll");
    assert_eq!(arr[1]["Name"], "kernel32.dll");
}

#[tokio::test]
async fn process_modules_empty_list_still_broadcasts() {
    let (registry, database, events) = process_callback_test_harness(0xB2).await;
    let mut rx = events.subscribe();
    let payload = build_process_modules_payload(999, &[]);

    handle_process_command_callback(&registry, &database, &events, 0xB2, 21, &payload)
        .await
        .expect("handler should succeed");

    // Empty module table → format_module_table returns "" but handler still broadcasts
    // because the Modules branch always broadcasts (unlike process list which checks is_empty)
    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let rows_json = msg.info.extra.get("ModuleRows").expect("missing ModuleRows");
    let arr = rows_json.as_array().expect("ModuleRows should be array");
    assert!(arr.is_empty());
}

// ── handle_process_command_callback — Grep branch ───────────────────────

fn add_bytes_raw(buf: &mut Vec<u8>, data: &[u8]) {
    add_u32(buf, u32::try_from(data.len()).expect("unwrap"));
    buf.extend_from_slice(data);
}

fn build_process_grep_payload(rows: &[(&str, u32, u32, &[u8], u32)]) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Grep));
    for &(name, pid, ppid, user_bytes, arch) in rows {
        add_utf16(&mut buf, name);
        add_u32(&mut buf, pid);
        add_u32(&mut buf, ppid);
        add_bytes_raw(&mut buf, user_bytes);
        add_u32(&mut buf, arch);
    }
    buf
}

#[tokio::test]
async fn process_grep_broadcasts_info_with_table_and_json() {
    let (registry, database, events) = process_callback_test_harness(0xC1).await;
    let mut rx = events.subscribe();
    let payload = build_process_grep_payload(&[
        ("lsass.exe", 700, 4, b"SYSTEM\0", 64),
        ("cmd.exe", 1200, 700, b"user1\0", 86),
    ]);

    handle_process_command_callback(&registry, &database, &events, 0xC1, 30, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");

    let rows_json = msg.info.extra.get("GrepRows").expect("missing GrepRows");
    let arr = rows_json.as_array().expect("GrepRows should be array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["Name"], "lsass.exe");
    assert_eq!(arr[0]["PID"], 700);
    assert_eq!(arr[0]["User"], "SYSTEM");
    assert_eq!(arr[0]["Arch"], "x64"); // arch != 86 → x64
    assert_eq!(arr[1]["Name"], "cmd.exe");
    assert_eq!(arr[1]["Arch"], "x86"); // arch == 86 → x86
}

#[tokio::test]
async fn process_grep_user_bytes_null_terminator_edge_cases() {
    let (registry, database, events) = process_callback_test_harness(0xC2).await;
    let mut rx = events.subscribe();
    let payload = build_process_grep_payload(&[
        // No null terminator — raw string should be preserved as-is
        ("notepad.exe", 100, 4, b"admin", 64),
        // Multiple trailing null bytes — all should be stripped
        ("svchost.exe", 200, 4, b"user\0\0\0", 64),
        // Entirely null bytes — should produce an empty string
        ("idle.exe", 300, 4, b"\0", 86),
    ]);

    handle_process_command_callback(&registry, &database, &events, 0xC2, 31, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let rows_json = msg.info.extra.get("GrepRows").expect("missing GrepRows");
    let arr = rows_json.as_array().expect("GrepRows should be array");
    assert_eq!(arr.len(), 3);

    // No null terminator — user string preserved
    assert_eq!(arr[0]["Name"], "notepad.exe");
    assert_eq!(arr[0]["User"], "admin");

    // Multiple trailing nulls — all stripped
    assert_eq!(arr[1]["Name"], "svchost.exe");
    assert_eq!(arr[1]["User"], "user");

    // Entirely null — empty string
    assert_eq!(arr[2]["Name"], "idle.exe");
    assert_eq!(arr[2]["User"], "");
}

// ── handle_process_command_callback — Memory branch ─────────────────────

fn build_process_memory_payload(
    pid: u32,
    query_protect: u32,
    regions: &[(u64, u32, u32, u32, u32)],
) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Memory));
    add_u32(&mut buf, pid);
    add_u32(&mut buf, query_protect);
    for &(base, size, protect, state, mem_type) in regions {
        add_u64(&mut buf, base);
        add_u32(&mut buf, size);
        add_u32(&mut buf, protect);
        add_u32(&mut buf, state);
        add_u32(&mut buf, mem_type);
    }
    buf
}

#[tokio::test]
async fn process_memory_broadcasts_info_with_table_and_json() {
    let (registry, database, events) = process_callback_test_harness(0xD1).await;
    let mut rx = events.subscribe();
    let payload = build_process_memory_payload(
        500,
        0, // query_protect=0 → "All"
        &[(0x7FF0_0000_0000, 0x1000, 0x20, 0x1000, 0x20000)],
    );

    handle_process_command_callback(&registry, &database, &events, 0xD1, 40, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("500"), "expected PID in message, got: {message}");
    assert!(message.contains("All"), "expected 'All' filter, got: {message}");

    let rows_json = msg.info.extra.get("MemoryRows").expect("missing MemoryRows");
    let arr = rows_json.as_array().expect("MemoryRows should be array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["Protect"], "PAGE_EXECUTE_READ");
    assert_eq!(arr[0]["State"], "MEM_COMMIT");
    assert_eq!(arr[0]["Type"], "MEM_PRIVATE");
}

#[tokio::test]
async fn process_memory_with_protect_filter_shows_protect_name() {
    let (registry, database, events) = process_callback_test_harness(0xD2).await;
    let mut rx = events.subscribe();
    let payload = build_process_memory_payload(
        600,
        0x40, // PAGE_EXECUTE_READWRITE
        &[(0x1000, 0x100, 0x40, 0x1000, 0x1000000)],
    );

    handle_process_command_callback(&registry, &database, &events, 0xD2, 41, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("PAGE_EXECUTE_READWRITE"),
        "expected protect name in filter, got: {message}"
    );
}

// ── handle_process_command_callback — invalid subcommand ────────────────

#[tokio::test]
async fn process_command_invalid_subcommand_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    let mut buf = Vec::new();
    add_u32(&mut buf, 0xFF); // invalid subcommand

    let result =
        handle_process_command_callback(&registry, &database, &events, 0xE1, 50, &buf).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for invalid subcommand, got: {result:?}"
    );
}

// ── handle_process_command_callback — truncated multi-row payload ───────

#[tokio::test]
async fn process_modules_truncated_second_row_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    // Build a valid first module row, then a truncated second row
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Modules));
    add_u32(&mut buf, 1234); // pid
    // First complete module row
    add_string(&mut buf, "ntdll.dll");
    add_u64(&mut buf, 0x7FFE_0000_0000);
    // Second row: name length says 10 bytes, but only provide 3
    buf.extend_from_slice(&10u32.to_le_bytes());
    buf.extend_from_slice(&[0x41, 0x42, 0x43]); // only 3 of the promised 10 bytes

    let result =
        handle_process_command_callback(&registry, &database, &events, 0xF1, 60, &buf).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated module row, got: {result:?}"
    );
}

#[tokio::test]
async fn inject_shellcode_truncated_payload_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    let result =
        handle_inject_shellcode_callback(&registry, &database, &events, 0xAA, 1, &[0x01]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
    );
}

#[tokio::test]
async fn inject_dll_truncated_payload_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    let result = handle_inject_dll_callback(&registry, &database, &events, 0xBB, 1, &[]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
    );
}

#[tokio::test]
async fn spawn_dll_truncated_payload_returns_error() {
    let (registry, database, events) = process_callback_stub_harness().await;
    let result =
        handle_spawn_dll_callback(&registry, &database, &events, 0xCC, 1, &[0xFF, 0xFF]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
    );
}
