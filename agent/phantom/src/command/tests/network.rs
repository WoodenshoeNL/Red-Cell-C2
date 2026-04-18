use super::*;

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

// ---- Pivot tests ----

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
        PivotConnection { pipe_name: "/tmp/test_pivot".to_owned(), stream: left },
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
    state
        .smb_pivots
        .insert(child_id, PivotConnection { pipe_name: "/tmp/test".to_owned(), stream: left });

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
    state
        .smb_pivots
        .insert(child_id, PivotConnection { pipe_name: "/tmp/poll_test".to_owned(), stream: left });

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
    state
        .smb_pivots
        .insert(child_id, PivotConnection { pipe_name: "/tmp/broken".to_owned(), stream: left });

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
