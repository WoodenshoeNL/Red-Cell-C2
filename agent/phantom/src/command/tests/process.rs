use super::*;

/// Build a UTF-16LE wstring payload whose code units include an explicit
/// null-terminator `U+0000` at the end — matching the wire format sent by the
/// Havoc C agent, which always appends `\x00\x00` after the string body.
///
/// `TaskParser::wstring()` must strip this terminator; if it does not, callers
/// receive a `String` ending with `'\0'` which poisons comparisons and path
/// lookups (bug 2g1nj).
fn utf16_payload_with_null(value: &str) -> Vec<u8> {
    let utf16: Vec<u8> =
        value.encode_utf16().chain(std::iter::once(0u16)).flat_map(u16::to_le_bytes).collect();
    let mut out = Vec::with_capacity(4 + utf16.len());
    out.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
    out.extend_from_slice(&utf16);
    out
}

/// Sending a process Create command whose name wstring carries an explicit
/// UTF-16LE null terminator `\x00\x00` must produce the same process-path in
/// the callback as sending the same name without the terminator (bug 2g1nj).
///
/// If `TaskParser::wstring()` does NOT strip the null, the spawned `binary`
/// variable would be `/bin/sh\0`, and the proc-create callback would encode
/// `/bin/sh\0` as the process path.  The assertion detects this by checking
/// that the encoded process path contains no null character.
#[tokio::test]
async fn proc_create_wstring_null_terminator_stripped_from_process_path_in_callback() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonProcessCommand::Create as i32).to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes()); // process_state = 0

    // Send "/bin/sh\0" — explicit null terminator matching the C agent wire format.
    payload.extend_from_slice(&utf16_payload_with_null("/bin/sh"));
    payload.extend_from_slice(&utf16_payload("printf null-term-test"));
    payload.extend_from_slice(&1_i32.to_le_bytes()); // piped = true
    payload.extend_from_slice(&0_i32.to_le_bytes()); // verbose = false

    let package = DemonPackage::new(DemonCommand::CommandProc, 77, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert!(!callbacks.is_empty(), "proc create must produce at least one structured callback");

    // The first callback is the proc-create structured result; it encodes the
    // process path via `encode_proc_create(&binary, ...)` where `binary` comes
    // from `parser.wstring()`.  If the null was not stripped, the encoded path
    // would end with '\0' and the assertion below would catch it.
    let PendingCallback::Structured { payload: cb_payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback, got {:?}", callbacks[0]);
    };

    let mut offset = 0_usize;
    // First field is the subcommand ID (Create).
    let _ = read_u32(cb_payload, &mut offset);
    // Second field is the process path as UTF-16LE wstring.
    let proc_path = read_utf16(cb_payload, &mut offset);

    assert!(
        !proc_path.contains('\0'),
        "proc create callback at offset {offset}: process path {:?} contains null char — \
         TaskParser::wstring() must strip the null terminator (bug 2g1nj); \
         got bytes: {:?}",
        proc_path,
        &cb_payload[4..offset],
    );
}

#[tokio::test]
async fn proc_create_with_pipe_returns_structured_and_output_callbacks() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonProcessCommand::Create as i32).to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    payload.extend_from_slice(&utf16_payload("/bin/sh"));
    payload.extend_from_slice(&utf16_payload("printf phantom-test"));
    payload.extend_from_slice(&1_i32.to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandProc, 2, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [
        PendingCallback::Structured { command_id, request_id, payload },
        PendingCallback::Structured {
            command_id: output_command_id,
            request_id: output_request_id,
            payload: output_payload,
        },
    ] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(*request_id, 2);
    assert_eq!(*output_command_id, u32::from(DemonCommand::CommandOutput));
    assert_eq!(*output_request_id, 2);

    // Verify the output payload contains the command text + trailing exit code.
    let mut out_offset = 0;
    let text_len = read_u32(output_payload, &mut out_offset) as usize;
    let text = std::str::from_utf8(&output_payload[out_offset..out_offset + text_len])
        .expect("valid utf8");
    out_offset += text_len;
    assert_eq!(text, "phantom-test");
    let exit_code =
        i32::from_le_bytes(output_payload[out_offset..out_offset + 4].try_into().expect("4 bytes"));
    assert_eq!(exit_code, 0);

    // Verify the proc create structured payload has verbose=false.
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonProcessCommand::Create));
    assert_eq!(read_utf16(payload, &mut offset), "/bin/sh");
    assert!(read_u32(payload, &mut offset) > 0);
    assert_eq!(read_u32(payload, &mut offset), 1);
    assert_eq!(read_u32(payload, &mut offset), 1);
    assert_eq!(read_u32(payload, &mut offset), 0);
}

/// Empty process path + `cmd.exe /c …` args is what the teamserver sends (see
/// `format_proc_create_args`).  Phantom must translate that to `/bin/sh -c <inner>` on
/// Linux (bead 1f7q1 / regression: `cmd.exe: not found`).
#[tokio::test]
async fn proc_create_havoc_empty_process_cmd_exe_c_wraps_to_sh() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonProcessCommand::Create as i32).to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    payload.extend_from_slice(&utf16_payload(""));
    payload.extend_from_slice(&utf16_payload("cmd.exe /c echo rc-havoc-wrap"));
    payload.extend_from_slice(&1_i32.to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandProc, 401, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [
        PendingCallback::Structured { payload, .. },
        PendingCallback::Structured { payload: output_payload, .. },
    ] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonProcessCommand::Create));
    assert_eq!(read_utf16(payload, &mut offset), "/bin/sh");

    let mut out_offset = 0;
    let text_len = read_u32(output_payload, &mut out_offset) as usize;
    let text = std::str::from_utf8(&output_payload[out_offset..out_offset + text_len])
        .expect("valid utf8");
    assert!(
        text.contains("rc-havoc-wrap"),
        "expected inner echo output in captured stdout, got {text:?}"
    );
    out_offset += text_len;
    let exit_code =
        i32::from_le_bytes(output_payload[out_offset..out_offset + 4].try_into().expect("4 bytes"));
    assert_eq!(exit_code, 0);
}

#[tokio::test]
#[cfg(unix)]
async fn proc_create_with_pipe_reports_minus_one_when_shell_sigkilled() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonProcessCommand::Create as i32).to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    payload.extend_from_slice(&utf16_payload("/bin/sh"));
    payload.extend_from_slice(&utf16_payload("kill -KILL $$"));
    payload.extend_from_slice(&1_i32.to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandProc, 3, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [
        PendingCallback::Structured { .. },
        PendingCallback::Structured { payload: output_payload, .. },
    ] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };

    let mut out_offset = 0;
    let text_len = read_u32(output_payload, &mut out_offset) as usize;
    out_offset += text_len;
    let exit_code =
        i32::from_le_bytes(output_payload[out_offset..out_offset + 4].try_into().expect("4 bytes"));
    assert_eq!(exit_code, -1, "SIGKILL'd process has no exit code — must not report 0 (success)");
}

#[tokio::test]
async fn proc_list_returns_structured_process_payload() {
    let package = DemonPackage::new(DemonCommand::CommandProcList, 7, 0_i32.to_le_bytes().to_vec());
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}")
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandProcList));
    assert_eq!(*request_id, 7);
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), 0);
    assert!(offset < payload.len());
}

#[tokio::test]
async fn proc_memory_returns_structured_payload_instead_of_stub_error() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonProcessCommand::Memory as i32).to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandProc, 11, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(*request_id, 11);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonProcessCommand::Memory));
    assert_eq!(read_u32(payload, &mut offset), 0);
    assert_eq!(read_u32(payload, &mut offset), 0);
    assert!(offset < payload.len(), "expected at least one memory region");
    let _base = read_u64(payload, &mut offset);
    let _size = read_u32(payload, &mut offset);
    let _protect = read_u32(payload, &mut offset);
    let _state = read_u32(payload, &mut offset);
    let _type = read_u32(payload, &mut offset);
}

#[test]
fn parse_logged_on_users_deduplicates_and_sorts() {
    let users = parse_logged_on_users(
        "alice pts/0 2026-03-23 10:00 (10.0.0.1)\n\
         bob pts/1 2026-03-23 10:05 (10.0.0.2)\n\
         alice pts/2 2026-03-23 10:10 (10.0.0.3)\n",
    );
    assert_eq!(users, vec!["alice".to_owned(), "bob".to_owned()]);
}

#[test]
fn parse_logged_on_sessions_prefers_remote_host_when_present() {
    let sessions = parse_logged_on_sessions(
        "alice pts/0 2026-03-23 10:00 (10.0.0.1)\n\
         bob pts/1 2026-03-23 10:05\n",
    );
    assert_eq!(
        sessions,
        vec![
            SessionEntry {
                client: "10.0.0.1".to_owned(),
                user: "alice".to_owned(),
                active: 0,
                idle: 0,
            },
            SessionEntry { client: "pts/1".to_owned(), user: "bob".to_owned(), active: 0, idle: 0 },
        ]
    );
}

#[test]
fn parse_user_entries_marks_uid_zero_as_admin() {
    let users = parse_user_entries(
        "root:x:0:0:root:/root:/bin/bash\n\
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    );
    assert_eq!(
        users,
        vec![
            UserEntry { name: "daemon".to_owned(), is_admin: false },
            UserEntry { name: "root".to_owned(), is_admin: true },
        ]
    );
}

#[test]
fn parse_group_entries_formats_gid_and_members() {
    let groups = parse_group_entries(
        "root:x:0:\n\
         wheel:x:10:alice,bob\n",
    );
    assert_eq!(
        groups,
        vec![
            GroupEntry { name: "root".to_owned(), description: "gid=0".to_owned() },
            GroupEntry {
                name: "wheel".to_owned(),
                description: "gid=10; members=alice,bob".to_owned(),
            },
        ]
    );
}

#[test]
fn parse_memory_region_maps_linux_permissions_to_windows_compatible_constants() {
    let image = parse_memory_region("00400000-00452000 r-xp 00000000 08:01 12345 /usr/bin/cat")
        .expect("image region");
    assert_eq!(image.base, 0x0040_0000);
    assert_eq!(image.size, 0x52_000);
    assert_eq!(image.protect, PAGE_EXECUTE_READ);
    assert_eq!(image.state, MEM_COMMIT);
    assert_eq!(image.mem_type, MEM_IMAGE);

    let mapped =
        parse_memory_region("7f0000000000-7f0000001000 rw-s 00000000 00:05 99 /dev/shm/demo")
            .expect("mapped region");
    assert_eq!(mapped.protect, PAGE_WRITECOPY);
    assert_eq!(mapped.mem_type, MEM_MAPPED);

    let private = parse_memory_region("7ffd5f1c4000-7ffd5f1e5000 rw-p 00000000 00:00 0 [stack]")
        .expect("private region");
    assert_eq!(private.protect, PAGE_READWRITE);
    assert_eq!(private.mem_type, MEM_PRIVATE);

    let writable_exec = parse_memory_region("7f0000002000-7f0000003000 rwxp 00000000 00:00 0")
        .expect("writable exec region");
    assert_eq!(writable_exec.protect, PAGE_EXECUTE_READWRITE);
}
