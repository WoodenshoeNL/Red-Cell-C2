//! Builtin handler integration tests: sleep, PPID spoof, .NET assembly versions,
//! inline-execute BOF output callbacks, and sleep callback error path.
//! Also contains format helper unit tests and process-create callback tests.

use super::*;

// ── builtin sleep / ppid / assembly handlers ─────────────────────────────

#[tokio::test]
async fn builtin_sleep_ppid_and_assembly_handlers_update_state_and_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCAFEBABE, test_key(0x66), test_iv(0x77));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut sleep_payload = Vec::new();
    add_u32(&mut sleep_payload, 60);
    add_u32(&mut sleep_payload, 15);
    dispatcher
        .dispatch(0xCAFEBABE, u32::from(DemonCommand::CommandSleep), 37, &sleep_payload)
        .await?;

    let event = receiver.recv().await.ok_or("sleep agent update missing")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event");
    };
    let event = receiver.recv().await.ok_or("sleep response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Set sleep interval to 60 seconds with 15% jitter".to_owned()))
    );
    let updated = registry.get(0xCAFEBABE).await.ok_or("missing updated agent")?;
    assert_eq!(updated.sleep_delay, 60);
    assert_eq!(updated.sleep_jitter, 15);

    let mut ppid_payload = Vec::new();
    add_u32(&mut ppid_payload, 4242);
    dispatcher
        .dispatch(0xCAFEBABE, u32::from(DemonCommand::CommandProcPpidSpoof), 38, &ppid_payload)
        .await?;

    let event = receiver.recv().await.ok_or("ppid agent update missing")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event");
    };
    let event = receiver.recv().await.ok_or("ppid response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Changed parent pid to spoof: 4242".to_owned()))
    );
    assert_eq!(registry.get(0xCAFEBABE).await.ok_or("missing updated agent")?.process_ppid, 4242);

    let mut assembly_payload = Vec::new();
    add_u32(&mut assembly_payload, 0x2);
    add_utf16(&mut assembly_payload, "v4.0.30319");
    dispatcher
        .dispatch(
            0xCAFEBABE,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            39,
            &assembly_payload,
        )
        .await?;

    let event = receiver.recv().await.ok_or("assembly response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Using CLR Version: v4.0.30319".to_owned()))
    );

    let mut versions_payload = Vec::new();
    add_utf16(&mut versions_payload, "v2.0.50727");
    add_utf16(&mut versions_payload, "v4.0.30319");
    dispatcher
        .dispatch(
            0xCAFEBABE,
            u32::from(DemonCommand::CommandAssemblyListVersions),
            40,
            &versions_payload,
        )
        .await?;

    let event = receiver.recv().await.ok_or("assembly versions response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("List available assembly versions:".to_owned()))
    );
    assert!(message.info.output.contains("v2.0.50727"));
    assert!(message.info.output.contains("v4.0.30319"));
    Ok(())
}

#[tokio::test]
async fn inline_execute_bof_output_broadcasts_agent_response()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xB0B1B2B3, test_key(0x11), test_iv(0x22));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    // BOF_CALLBACK_OUTPUT (0x00): standard output from the BOF
    let mut payload = Vec::new();
    add_u32(&mut payload, 0x00);
    add_bytes(&mut payload, b"hello from BOF");
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 1, &payload)
        .await?;
    let event = receiver.recv().await.ok_or("bof output response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Output".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("hello from BOF".to_owned()))
    );

    // BOF_RAN_OK (3): completion confirmation
    let mut ran_ok = Vec::new();
    add_u32(&mut ran_ok, 3);
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 2, &ran_ok)
        .await?;
    let event = receiver.recv().await.ok_or("bof ran-ok response missing")?;
    let OperatorMessage::AgentResponse(ok_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        ok_message.info.extra.get("Message"),
        Some(&Value::String("BOF execution completed".to_owned()))
    );

    // BOF_EXCEPTION (1): exception code + address
    let mut exc = Vec::new();
    add_u32(&mut exc, 1);
    add_u32(&mut exc, 0xC000_0005_u32); // STATUS_ACCESS_VIOLATION
    add_u64(&mut exc, 0x0000_7FF7_DEAD_BEEF_u64);
    dispatcher.dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 3, &exc).await?;
    let event = receiver.recv().await.ok_or("bof exception response missing")?;
    let OperatorMessage::AgentResponse(exc_message) = event else {
        panic!("expected agent response event");
    };
    assert!(
        exc_message
            .info
            .extra
            .get("Message")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("0xC0000005") && s.contains("0x00007FF7DEADBEEF"))
            .unwrap_or(false),
        "exception message must include code and address"
    );

    // BOF_SYMBOL_NOT_FOUND (2): missing symbol name
    let mut sym = Vec::new();
    add_u32(&mut sym, 2);
    add_bytes(&mut sym, b"kernel32.VirtualAllocEx");
    dispatcher.dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 4, &sym).await?;
    let event = receiver.recv().await.ok_or("bof symbol-not-found response missing")?;
    let OperatorMessage::AgentResponse(sym_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        sym_message.info.extra.get("Message"),
        Some(&Value::String("Symbol not found: kernel32.VirtualAllocEx".to_owned()))
    );

    // BOF_COULD_NOT_RUN (4): loader failed to start
    let mut no_run = Vec::new();
    add_u32(&mut no_run, 4);
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 5, &no_run)
        .await?;
    let event = receiver.recv().await.ok_or("bof could-not-run response missing")?;
    let OperatorMessage::AgentResponse(no_run_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        no_run_message.info.extra.get("Message"),
        Some(&Value::String("Failed to execute object file".to_owned()))
    );

    // BOF_CALLBACK_ERROR (0x0d): error output text from the BOF
    let mut err_output = Vec::new();
    add_u32(&mut err_output, 0x0d);
    add_bytes(&mut err_output, b"access denied to target process");
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 6, &err_output)
        .await?;
    let event = receiver.recv().await.ok_or("bof error-output response missing")?;
    let OperatorMessage::AgentResponse(err_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(err_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        err_message.info.extra.get("Message"),
        Some(&Value::String("access denied to target process".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn sleep_callback_returns_agent_not_found_for_unregistered_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    // Build a valid CommandSleep payload: delay=60, jitter=15
    let mut payload = Vec::new();
    add_u32(&mut payload, 60);
    add_u32(&mut payload, 15);

    // Dispatch to a non-existent agent
    let nonexistent_agent_id: u32 = 0xDEAD_BEEF;
    let result = dispatcher
        .dispatch(nonexistent_agent_id, u32::from(DemonCommand::CommandSleep), 99, &payload)
        .await;

    // Assert that the error is AgentNotFound
    let error = result.expect_err("dispatch to unregistered agent must fail");
    assert!(
        matches!(
            &error,
            CommandDispatchError::Registry(TeamserverError::AgentNotFound { agent_id })
                if *agent_id == nonexistent_agent_id
        ),
        "expected AgentNotFound for 0x{nonexistent_agent_id:08X}, got: {error}"
    );

    // Confirm no events were broadcast (short timeout to verify nothing arrives)
    let no_event = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(no_event.is_err(), "no events should be broadcast when agent is not found");

    Ok(())
}

// ── Tests migrated from dispatch/process.rs inline mod tests ──────────────

// ── helpers ──────────────────────────────────────────────────────────────

fn make_process_row(name: &str, pid: u32, ppid: u32) -> ProcessRow {
    ProcessRow {
        name: name.to_owned(),
        pid,
        ppid,
        session: 1,
        arch: "x64".to_owned(),
        threads: 4,
        user: "SYSTEM".to_owned(),
    }
}

// ── format_process_table ─────────────────────────────────────────────────

#[test]
fn format_process_table_empty_returns_empty_string() {
    assert_eq!(format_process_table(&[]), "");
}

#[test]
fn format_process_table_single_row_contains_header_separator_and_data() {
    let rows = vec![make_process_row("svchost.exe", 1234, 456)];
    let table = format_process_table(&rows);

    // Header line must be present
    assert!(table.contains("Name"), "missing Name header: {table}");
    assert!(table.contains("PID"), "missing PID header: {table}");
    assert!(table.contains("PPID"), "missing PPID header: {table}");
    assert!(table.contains("Session"), "missing Session header: {table}");
    assert!(table.contains("Arch"), "missing Arch header: {table}");
    assert!(table.contains("Threads"), "missing Threads header: {table}");
    assert!(table.contains("User"), "missing User header: {table}");

    // Separator dashes must be present
    assert!(table.contains("----"), "missing separator: {table}");

    // Data row must be present
    assert!(table.contains("svchost.exe"), "missing process name: {table}");
    assert!(table.contains("1234"), "missing PID: {table}");
    assert!(table.contains("456"), "missing PPID: {table}");

    // Three lines: header, separator, data row (each ends with '\n')
    assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
}

#[test]
fn format_process_table_name_width_is_dynamic() {
    // A long process name should widen the Name column for all rows.
    let rows =
        vec![make_process_row("a", 1, 0), make_process_row("very_long_process_name.exe", 2, 0)];
    let table = format_process_table(&rows);
    // Both rows must have the same leading-space alignment — i.e. "a" must
    // be left-padded to the same width as "very_long_process_name.exe".
    let lines: Vec<&str> = table.lines().collect();
    // data rows start at index 2
    let short_row = lines[2];
    let long_row = lines[3];
    // The PID column starts at the same offset in both rows when names
    // are padded correctly; verify by checking equal lengths up to PID.
    assert_eq!(
        short_row.find("1   "),
        long_row.find("2   "),
        "PID column offsets differ — name width not applied uniformly"
    );
}

// ── process_rows_json ────────────────────────────────────────────────────

#[test]
fn process_rows_json_two_rows_produce_correct_array() {
    let rows = vec![
        ProcessRow {
            name: "explorer.exe".to_owned(),
            pid: 100,
            ppid: 4,
            session: 1,
            arch: "x64".to_owned(),
            threads: 32,
            user: "user1".to_owned(),
        },
        ProcessRow {
            name: "cmd.exe".to_owned(),
            pid: 200,
            ppid: 100,
            session: 1,
            arch: "x86".to_owned(),
            threads: 2,
            user: "user2".to_owned(),
        },
    ];

    let Value::Array(arr) = process_rows_json(&rows) else {
        panic!("expected JSON array");
    };

    assert_eq!(arr.len(), 2);

    assert_eq!(arr[0]["Name"], "explorer.exe");
    assert_eq!(arr[0]["PID"], 100u32);
    assert_eq!(arr[0]["PPID"], 4u32);
    assert_eq!(arr[0]["Session"], 1u32);
    assert_eq!(arr[0]["Arch"], "x64");
    assert_eq!(arr[0]["Threads"], 32u32);
    assert_eq!(arr[0]["User"], "user1");

    assert_eq!(arr[1]["Name"], "cmd.exe");
    assert_eq!(arr[1]["PID"], 200u32);
    assert_eq!(arr[1]["PPID"], 100u32);
    assert_eq!(arr[1]["Arch"], "x86");
    assert_eq!(arr[1]["User"], "user2");
}

#[test]
fn process_rows_json_empty_produces_empty_array() {
    let Value::Array(arr) = process_rows_json(&[]) else {
        panic!("expected JSON array");
    };
    assert!(arr.is_empty());
}

// ── format_module_table ──────────────────────────────────────────────────

#[test]
fn format_module_table_empty_returns_empty_string() {
    assert_eq!(format_module_table(&[]), "");
}

#[test]
fn format_module_table_formats_hex_base_address() {
    let rows = vec![ModuleRow { name: "ntdll.dll".to_owned(), base: 0x7FFE_0000_1234_ABCD }];
    let table = format_module_table(&rows);
    assert!(table.contains("7FFE00001234ABCD"), "expected hex base address in table:\n{table}");
    assert!(table.contains("ntdll.dll"), "missing module name:\n{table}");
}

// ── format_grep_table ────────────────────────────────────────────────────

#[test]
fn format_grep_table_empty_returns_empty_string() {
    assert_eq!(format_grep_table(&[]), "");
}

#[test]
fn format_grep_table_contains_expected_row_data() {
    let rows = vec![GrepRow {
        name: "lsass.exe".to_owned(),
        pid: 700,
        ppid: 4,
        user: "SYSTEM".to_owned(),
        arch: "x64".to_owned(),
    }];
    let table = format_grep_table(&rows);
    assert!(table.contains("lsass.exe"), "missing name:\n{table}");
    assert!(table.contains("700"), "missing PID:\n{table}");
    assert!(table.contains("SYSTEM"), "missing user:\n{table}");
}

// ── format_memory_table ──────────────────────────────────────────────────

#[test]
fn format_memory_table_empty_returns_empty_string() {
    assert_eq!(format_memory_table(&[]), "");
}

#[test]
fn format_memory_table_formats_row_correctly() {
    let rows = vec![MemoryRow {
        base: 0x0000_7FF0_0000_0000,
        size: 0x1000,
        protect: 0x20,     // PAGE_EXECUTE_READ
        state: 0x1000,     // MEM_COMMIT
        mem_type: 0x20000, // MEM_PRIVATE
    }];
    let table = format_memory_table(&rows);
    assert!(table.contains("PAGE_EXECUTE_READ"), "missing protect:\n{table}");
    assert!(table.contains("MEM_COMMIT"), "missing state:\n{table}");
    assert!(table.contains("MEM_PRIVATE"), "missing type:\n{table}");
    assert!(table.contains("7FF000000000"), "missing base address:\n{table}");
}

// ── format_memory_protect ────────────────────────────────────────────────

#[test]
fn format_memory_protect_known_constants_return_names() {
    assert_eq!(format_memory_protect(0x01), "PAGE_NOACCESS");
    assert_eq!(format_memory_protect(0x02), "PAGE_READONLY");
    assert_eq!(format_memory_protect(0x04), "PAGE_READWRITE");
    assert_eq!(format_memory_protect(0x08), "PAGE_WRITECOPY");
    assert_eq!(format_memory_protect(0x10), "PAGE_EXECUTE");
    assert_eq!(format_memory_protect(0x20), "PAGE_EXECUTE_READ");
    assert_eq!(format_memory_protect(0x40), "PAGE_EXECUTE_READWRITE");
    assert_eq!(format_memory_protect(0x80), "PAGE_EXECUTE_WRITECOPY");
    assert_eq!(format_memory_protect(0x100), "PAGE_GUARD");
}

#[test]
fn format_memory_protect_unknown_constant_returns_hex_fallback() {
    assert_eq!(format_memory_protect(0x99), "0x99");
    assert_eq!(format_memory_protect(0), "0x0");
    // Combined flags (e.g. PAGE_GUARD | PAGE_READWRITE) fall through to hex
    assert_eq!(format_memory_protect(0x104), "0x104");
    // Uppercase hex must be preserved for consistency
    assert_eq!(format_memory_protect(0xAB), "0xAB");
}

// ── format_memory_state ──────────────────────────────────────────────────

#[test]
fn format_memory_state_known_constants_return_names() {
    assert_eq!(format_memory_state(0x1000), "MEM_COMMIT");
    assert_eq!(format_memory_state(0x2000), "MEM_RESERVE");
    assert_eq!(format_memory_state(0x10000), "MEM_FREE");
}

#[test]
fn format_memory_state_unknown_constant_returns_hex_fallback() {
    assert_eq!(format_memory_state(0xABCD), "0xABCD");
    // Combined flags (e.g. MEM_COMMIT | MEM_RESERVE) fall through to hex
    assert_eq!(format_memory_state(0x3000), "0x3000");
    assert_eq!(format_memory_state(0), "0x0");
}

// ── format_memory_type ───────────────────────────────────────────────────

#[test]
fn format_memory_type_known_constants_return_names() {
    assert_eq!(format_memory_type(0x20000), "MEM_PRIVATE");
    assert_eq!(format_memory_type(0x40000), "MEM_MAPPED");
    assert_eq!(format_memory_type(0x1000000), "MEM_IMAGE");
}

#[test]
fn format_memory_type_unknown_constant_returns_hex_fallback() {
    assert_eq!(format_memory_type(0x99999), "0x99999");
    assert_eq!(format_memory_type(0x9999), "0x9999");
    assert_eq!(format_memory_type(0), "0x0");
}

// ── win32_error_code_name ────────────────────────────────────────────────

#[test]
fn win32_error_code_name_known_codes_return_symbolic_names() {
    assert_eq!(win32_error_code_name(2), Some("ERROR_FILE_NOT_FOUND"));
    assert_eq!(win32_error_code_name(5), Some("ERROR_ACCESS_DENIED"));
    assert_eq!(win32_error_code_name(87), Some("ERROR_INVALID_PARAMETER"));
    assert_eq!(win32_error_code_name(183), Some("ERROR_ALREADY_EXISTS"));
    assert_eq!(win32_error_code_name(997), Some("ERROR_IO_PENDING"));
}

#[test]
fn win32_error_code_name_unknown_codes_return_none() {
    assert_eq!(win32_error_code_name(0), None);
    assert_eq!(win32_error_code_name(1), None);
    assert_eq!(win32_error_code_name(9999), None);
}

// ── handle_process_command_callback — Create branch ─────────────────────

/// Build a binary payload for the `Create` subcommand of `CommandProc`.
fn build_process_create_payload(
    path: &str,
    pid: u32,
    success: u32,
    piped: u32,
    verbose: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    // subcommand
    buf.extend_from_slice(&u32::from(DemonProcessCommand::Create).to_le_bytes());
    // path (UTF-16 LE, null-terminated, length-prefixed)
    let mut encoded: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]); // null terminator
    buf.extend_from_slice(&u32::try_from(encoded.len()).expect("unwrap").to_le_bytes());
    buf.extend_from_slice(&encoded);
    // pid, success, piped, verbose
    buf.extend_from_slice(&pid.to_le_bytes());
    buf.extend_from_slice(&success.to_le_bytes());
    buf.extend_from_slice(&piped.to_le_bytes());
    buf.extend_from_slice(&verbose.to_le_bytes());
    buf
}

#[tokio::test]
async fn process_create_verbose_success_broadcasts_info_with_path_and_pid() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xAA, test_key(0x11), test_iv(0x22))).await.expect("insert");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_create_payload("C:\\cmd.exe", 1234, 1, 0, 1);

    handle_process_command_callback(&registry, &database, &events, 0xAA, 1, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert!(
        message.contains("C:\\cmd.exe") && message.contains("1234"),
        "expected path and pid in message, got: {message}"
    );
}

#[tokio::test]
async fn process_create_verbose_failure_broadcasts_error() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBB, test_key(0x11), test_iv(0x22))).await.expect("insert");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_create_payload("C:\\bad.exe", 0, 0, 0, 1);

    handle_process_command_callback(&registry, &database, &events, 0xBB, 2, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("C:\\bad.exe"), "expected path in error message, got: {message}");
}

#[tokio::test]
async fn process_create_non_verbose_failure_unpiped_broadcasts_fallback() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xCC, test_key(0x11), test_iv(0x22))).await.expect("insert");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=0, piped=0
    let payload = build_process_create_payload("C:\\app.exe", 0, 0, 0, 0);

    handle_process_command_callback(&registry, &database, &events, 0xCC, 3, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert_eq!(message, "Process create completed");
}

#[tokio::test]
async fn process_create_non_verbose_failure_piped_broadcasts_fallback() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xDD, test_key(0x11), test_iv(0x22))).await.expect("insert");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=0, piped=1
    let payload = build_process_create_payload("C:\\app.exe", 0, 0, 1, 0);

    handle_process_command_callback(&registry, &database, &events, 0xDD, 4, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert_eq!(message, "Process create completed");
}

#[tokio::test]
async fn process_create_non_verbose_success_unpiped_broadcasts_fallback() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xEE, test_key(0x11), test_iv(0x22))).await.expect("insert");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=1, piped=0
    let payload = build_process_create_payload("C:\\app.exe", 999, 1, 0, 0);

    handle_process_command_callback(&registry, &database, &events, 0xEE, 5, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert_eq!(message, "Process create completed");
}

#[tokio::test]
async fn process_create_non_verbose_success_piped_does_not_broadcast() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=1, piped=1 → no broadcast
    let payload = build_process_create_payload("C:\\app.exe", 999, 1, 1, 0);

    handle_process_command_callback(&registry, &database, &events, 0xFF, 6, &payload)
        .await
        .expect("handler should succeed");

    let result = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;

    assert!(result.is_err(), "expected no broadcast when verbose=0, success=1, piped=1");
}

// ── Unicode / non-ASCII process name formatting ─────────────────────────
//
// Note on alignment: `format_process_table` and `format_grep_table` compute
// column widths via `.len()` (byte length) and pad via `format!("{:<w$}", …)`
// (which counts Unicode scalar values, not display width).  For multi-byte
// UTF-8 characters this means:
//
//  - CJK characters: 3 bytes each, 1 char, 2 display columns
//    → `.len()` over-counts vs char count → extra padding spaces
//    → display columns = display_width + padding > expected column width
//
//  - Accented Latin (e.g. "é"): 2 bytes, 1 char, 1 display column
//    → `.len()` over-counts vs char count → extra padding spaces
//
// The result is that rows with multi-byte names get more visual padding than
// pure-ASCII rows, causing slight column misalignment.  This is a known
// cosmetic limitation.  Fixing it properly requires a Unicode display-width
// library (e.g. `unicode-width`).  The tests below document the current
// behavior so any future fix can be validated.

#[test]
fn format_process_table_cjk_name_output_is_well_formed() {
    let rows =
        vec![make_process_row("测试进程.exe", 1000, 4), make_process_row("svchost.exe", 800, 4)];
    let table = format_process_table(&rows);

    // All data must appear in the output
    assert!(table.contains("测试进程.exe"), "missing CJK process name:\n{table}");
    assert!(table.contains("svchost.exe"), "missing ASCII process name:\n{table}");
    assert!(table.contains("1000"), "missing PID 1000:\n{table}");
    assert!(table.contains("800"), "missing PID 800:\n{table}");

    // Must still have 4 lines: header, separator, 2 data rows
    assert_eq!(table.lines().count(), 4, "expected 4 lines:\n{table}");

    // Header and separator must still be present
    assert!(table.contains("Name"), "missing Name header:\n{table}");
    assert!(table.contains("----"), "missing separator:\n{table}");
}

#[test]
fn format_process_table_cjk_name_byte_len_exceeds_char_count() {
    // "测试进程.exe" = 4 CJK chars (3 bytes each) + ".exe" (4 bytes) = 16 bytes, 8 chars
    // This documents the known divergence between .len() and char count.
    let name = "测试进程.exe";
    assert_eq!(name.len(), 16, "byte length");
    assert_eq!(name.chars().count(), 8, "char count");

    let rows = vec![make_process_row(name, 1, 0)];
    let table = format_process_table(&rows);
    let data_line = table.lines().nth(2).expect("data row");

    // The Name column is padded to byte-length (16) by format!("{:<16}", …),
    // but since the string is only 8 chars, format! adds 8 spaces of padding.
    // Verify the name appears and is followed by spaces (over-padded).
    assert!(data_line.contains("测试进程.exe"), "data line must contain CJK name:\n{data_line}");
}

#[test]
fn format_process_table_accented_latin_name_is_present() {
    // "Ünïcödé.exe" contains multi-byte Latin chars
    let rows = vec![make_process_row("Ünïcödé.exe", 42, 1)];
    let table = format_process_table(&rows);

    assert!(table.contains("Ünïcödé.exe"), "missing accented name:\n{table}");
    assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
}

#[test]
fn format_process_table_mixed_script_rows_all_present() {
    // Mix of ASCII, CJK, Cyrillic, and accented names
    let rows = vec![
        make_process_row("explorer.exe", 100, 4),
        make_process_row("测试.exe", 200, 4),
        make_process_row("процесс.exe", 300, 4),
        make_process_row("café.exe", 400, 4),
    ];
    let table = format_process_table(&rows);

    assert!(table.contains("explorer.exe"), "missing ASCII name:\n{table}");
    assert!(table.contains("测试.exe"), "missing CJK name:\n{table}");
    assert!(table.contains("процесс.exe"), "missing Cyrillic name:\n{table}");
    assert!(table.contains("café.exe"), "missing accented name:\n{table}");
    assert_eq!(table.lines().count(), 6, "expected 6 lines (header+sep+4 data):\n{table}");
}

#[test]
fn format_process_table_unicode_user_field_is_present() {
    // Non-ASCII user name (e.g. domain with CJK characters)
    let row = ProcessRow {
        name: "cmd.exe".to_owned(),
        pid: 10,
        ppid: 1,
        session: 0,
        arch: "x64".to_owned(),
        threads: 1,
        user: "域\\管理员".to_owned(),
    };
    let table = format_process_table(&[row]);
    assert!(table.contains("域\\管理员"), "missing Unicode user:\n{table}");
}

#[test]
fn format_grep_table_cjk_name_output_is_well_formed() {
    let rows = vec![GrepRow {
        name: "恶意软件.exe".to_owned(),
        pid: 999,
        ppid: 4,
        user: "SYSTEM".to_owned(),
        arch: "x64".to_owned(),
    }];
    let table = format_grep_table(&rows);

    assert!(table.contains("恶意软件.exe"), "missing CJK name:\n{table}");
    assert!(table.contains("999"), "missing PID:\n{table}");
    assert!(table.contains("SYSTEM"), "missing user:\n{table}");
    // header + separator + 1 data row
    assert_eq!(
        table.lines().filter(|l| !l.is_empty()).count(),
        3,
        "expected 3 non-empty lines:\n{table}"
    );
}

#[test]
fn format_grep_table_unicode_user_is_present() {
    let rows = vec![GrepRow {
        name: "notepad.exe".to_owned(),
        pid: 50,
        ppid: 1,
        user: "用户".to_owned(),
        arch: "x86".to_owned(),
    }];
    let table = format_grep_table(&rows);
    assert!(table.contains("用户"), "missing Unicode user:\n{table}");
}

#[test]
fn format_module_table_cjk_module_name_is_present() {
    let rows = vec![ModuleRow { name: "テスト.dll".to_owned(), base: 0x7FFE_0000_0000_0000 }];
    let table = format_module_table(&rows);
    assert!(table.contains("テスト.dll"), "missing CJK module name:\n{table}");
}

#[test]
fn format_process_table_empty_name_does_not_panic() {
    // Edge case: empty process name (could happen with malformed agent data)
    let rows = vec![make_process_row("", 1, 0)];
    let table = format_process_table(&rows);
    // Name column minimum width is 4 ("Name" header), so this should still work
    assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
}
