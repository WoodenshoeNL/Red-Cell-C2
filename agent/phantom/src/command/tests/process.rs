use super::*;

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
