//! Listener lifecycle integration tests.
//!
//! These tests exercise the [`ListenerManager`] state machine via its public API
//! and verify that the persisted database state remains consistent with the actual
//! task state across start, stop, restart, crash recovery, and concurrent operations.

mod common;

use std::time::Duration;

use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerManagerError, ListenerStatus,
    SocketRelayManager,
};
use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, ListenerConfig,
    SmbListenerConfig,
};
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a minimal in-memory [`ListenerManager`] for testing.
async fn test_manager() -> Result<ListenerManager, Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    Ok(ListenerManager::new(database, registry, events, sockets, None))
}

/// Build a minimal HTTP listener config bound to `port`.
fn http_config(name: &str, port: u16) -> ListenerConfig {
    http_config_with_time(name, port, None, None)
}

/// Build an HTTP listener config with optional `kill_date` and `working_hours`.
fn http_config_with_time(
    name: &str,
    port: u16,
    kill_date: Option<&str>,
    working_hours: Option<&str>,
) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: kill_date.map(str::to_owned),
        working_hours: working_hours.map(str::to_owned),
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
    })
}

/// Build a minimal SMB listener config with the given `pipe_name`.
fn smb_config(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

/// Compute a unique pipe name for each test to avoid collisions.
fn unique_pipe_name(suffix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    format!("red-cell-lc-test-{suffix}-{ts}")
}

/// Build a minimal DNS listener config bound to `port`.
fn dns_config(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "test.c2.local".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    })
}

/// Build a minimal External listener config with the given `endpoint`.
fn external_config(name: &str, endpoint: &str) -> ListenerConfig {
    ListenerConfig::from(ExternalListenerConfig {
        name: name.to_owned(),
        endpoint: endpoint.to_owned(),
    })
}

/// Build a minimal DNS query packet for probing listener readiness.
fn build_dns_probe_query() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xFFFF_u16.to_be_bytes()); // ID
    buf.extend_from_slice(&0x0100_u16.to_be_bytes()); // flags: QR=0, RD=1
    buf.extend_from_slice(&1_u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // arcount
    for label in "probe.other.domain.com".split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // zero terminator
    buf.extend_from_slice(&16_u16.to_be_bytes()); // QTYPE TXT
    buf.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN
    buf
}

/// Poll until the DNS listener on `port` is ready to accept queries.
async fn wait_for_dns_listener(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::net::UdpSocket;
    use tokio::time::sleep;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{port}")).await?;
    let probe = build_dns_probe_query();

    for _ in 0..40 {
        let _ = client.send(&probe).await;
        let mut buf = vec![0u8; 512];
        if timeout(Duration::from_millis(50), client.recv(&mut buf)).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("DNS listener on port {port} did not become ready").into())
}

/// Poll until the SMB listener's named pipe is ready to accept connections.
#[cfg(unix)]
async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    use interprocess::local_socket::ToNsName as _;
    use interprocess::local_socket::tokio::Stream as LocalSocketStream;
    use interprocess::local_socket::traits::tokio::Stream as _;
    use interprocess::os::unix::local_socket::AbstractNsUdSocket;
    use tokio::time::sleep;

    let smb_prefix = r"\\.\pipe\";
    let trimmed = pipe_name.trim();
    let full = if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{smb_prefix}{trimmed}")
    };
    let socket_name = full.to_ns_name::<AbstractNsUdSocket>()?.into_owned();

    for _ in 0..40 {
        if LocalSocketStream::connect(socket_name.clone()).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("SMB listener on pipe `{pipe_name}` did not become ready within 1 s").into())
}

// ---------------------------------------------------------------------------
// State transition tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_persists_listener_in_created_state() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-create", port)).await?;

    let summary = manager.summary("lc-create").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);
    assert!(summary.state.last_error.is_none());
    Ok(())
}

#[tokio::test]
async fn start_transitions_to_running_state() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-start", port)).await?;
    drop(guard);
    let summary = manager.start("lc-start").await?;

    assert_eq!(summary.state.status, ListenerStatus::Running);

    // Verify the DB is consistent.
    let db_summary = manager.summary("lc-start").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    manager.stop("lc-start").await?;
    Ok(())
}

#[tokio::test]
async fn stop_transitions_running_listener_to_stopped_state()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-stop", port)).await?;
    drop(guard);
    manager.start("lc-stop").await?;
    let summary = manager.stop("lc-stop").await?;

    assert_eq!(summary.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-stop").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);
    Ok(())
}

#[tokio::test]
async fn restart_after_stop_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-restart", port)).await?;
    drop(guard);
    manager.start("lc-restart").await?;
    manager.stop("lc-restart").await?;

    // The port is now free; a restart should succeed.
    let summary = manager.start("lc-restart").await?;
    assert_eq!(summary.state.status, ListenerStatus::Running);

    let db_summary = manager.summary("lc-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    manager.stop("lc-restart").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Restart coverage tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_after_stop_rebinds_port_and_accepts_connections()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-restart-port", port)).await?;
    drop(guard);
    manager.start("lc-restart-port").await?;

    // Verify the listener is actually accepting connections before stopping.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-restart-port").await?;

    // Restart — the port should be re-bound.
    let summary = manager.start("lc-restart-port").await?;
    assert_eq!(summary.state.status, ListenerStatus::Running);

    // Verify port rebinding by actually connecting.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-restart-port").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-restart-port").await?;
    Ok(())
}

#[tokio::test]
async fn multiple_restart_cycles_succeed() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-multi-restart", port)).await?;
    drop(guard);

    // Perform three stop-then-restart cycles.
    for cycle in 0..3 {
        let started = manager.start("lc-multi-restart").await?;
        assert_eq!(
            started.state.status,
            ListenerStatus::Running,
            "cycle {cycle}: listener must be Running after start"
        );

        timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

        let stopped = manager.stop("lc-multi-restart").await?;
        assert_eq!(
            stopped.state.status,
            ListenerStatus::Stopped,
            "cycle {cycle}: listener must be Stopped after stop"
        );
    }

    // Final DB consistency check.
    let db_summary = manager.summary("lc-multi-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);
    Ok(())
}

#[tokio::test]
async fn agent_reconnects_after_listener_restart() -> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-agent-reconnect", port)).await?;
    drop(guard);
    manager.start("lc-agent-reconnect").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // Register an agent via DEMON_INIT.
    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_0001;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];

    let _ctr_offset = common::register_agent(&client, port, agent_id, key, iv).await?;

    // Stop and restart the listener.
    manager.stop("lc-agent-reconnect").await?;
    manager.start("lc-agent-reconnect").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // The agent should be able to reconnect after the listener restarts.
    let reconnect_body = common::valid_demon_reconnect_body(agent_id);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(reconnect_body).send().await?;

    // The server should accept the reconnect probe (200 OK with a body).
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "reconnect probe after restart must succeed"
    );
    let body = resp.bytes().await?;
    assert!(!body.is_empty(), "reconnect ACK must have a non-empty body");

    manager.stop("lc-agent-reconnect").await?;
    Ok(())
}

#[tokio::test]
async fn restart_preserves_config_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    let config = http_config("lc-restart-cfg", port);
    manager.create(config).await?;
    drop(guard);

    // Capture config before restart cycle.
    let before = manager.summary("lc-restart-cfg").await?;

    manager.start("lc-restart-cfg").await?;
    manager.stop("lc-restart-cfg").await?;
    manager.start("lc-restart-cfg").await?;

    // Config must be identical after the stop-start cycle.
    let after = manager.summary("lc-restart-cfg").await?;
    match (&before.config, &after.config) {
        (ListenerConfig::Http(before_http), ListenerConfig::Http(after_http)) => {
            assert_eq!(before_http.port_bind, after_http.port_bind, "port must be preserved");
            assert_eq!(before_http.host_bind, after_http.host_bind, "host must be preserved");
            assert_eq!(
                before_http.host_rotation, after_http.host_rotation,
                "host_rotation must be preserved"
            );
            assert_eq!(before_http.uris, after_http.uris, "URIs must be preserved");
            assert_eq!(before_http.method, after_http.method, "method must be preserved");
        }
        _ => panic!("expected Http config on both sides"),
    }

    manager.stop("lc-restart-cfg").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Error condition tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_already_running_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-double-start", port)).await?;
    drop(guard);
    manager.start("lc-double-start").await?;

    let result = manager.start("lc-double-start").await;
    assert!(result.is_err(), "starting an already-running listener must return an error");

    // Status should remain Running.
    let db_summary = manager.summary("lc-double-start").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    manager.stop("lc-double-start").await?;
    Ok(())
}

#[tokio::test]
async fn stop_non_running_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-double-stop", port)).await?;

    // Listener is in Created state — stop should fail.
    let result = manager.stop("lc-double-stop").await;
    assert!(result.is_err(), "stopping a non-running listener must return an error");

    // Status must still be Created.
    let db_summary = manager.summary("lc-double-stop").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Created);
    Ok(())
}

#[tokio::test]
async fn start_fails_when_port_is_already_in_use() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    // The guard returned by available_port() is already bound to the port, so it acts
    // as the external listener that prevents ListenerManager from claiming the same port.
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-port-in-use", port)).await?;
    let result = manager.start("lc-port-in-use").await;

    assert!(result.is_err(), "starting on a bound port must return an error");

    // The DB should record the error state.
    let db_summary = manager.summary("lc-port-in-use").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Error);
    assert!(db_summary.state.last_error.is_some(), "error state must record the failure message");
    Ok(())
}

#[tokio::test]
async fn start_nonexistent_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    let result = manager.start("no-such-listener").await;
    assert!(result.is_err(), "starting a listener that does not exist must return an error");
    Ok(())
}

#[tokio::test]
async fn create_duplicate_name_returns_error_and_preserves_original()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, _guard_a) = common::available_port()?;
    let (port_b, _guard_b) = common::available_port_excluding(port_a)?;

    // First create succeeds.
    manager.create(http_config("lc-dup", port_a)).await?;

    // Second create with the same name but different port must fail.
    let result = manager.create(http_config("lc-dup", port_b)).await;
    assert!(result.is_err(), "duplicate create must return an error");

    let err = result.unwrap_err();
    assert!(
        matches!(err, ListenerManagerError::DuplicateListener { .. }),
        "error must be DuplicateListener, got: {err}"
    );

    // The original config must be unchanged — still bound to port_a.
    let summary = manager.summary("lc-dup").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_bind, port_a, "original port must be preserved");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // Only one listener entry must exist.
    let all = manager.list().await?;
    let dup_count = all.iter().filter(|s| s.name == "lc-dup").count();
    assert_eq!(dup_count, 1, "exactly one listener with the name must exist");

    Ok(())
}

// ---------------------------------------------------------------------------
// Delete tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_running_listener_stops_then_removes() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-delete-running", port)).await?;
    drop(guard);
    manager.start("lc-delete-running").await?;
    common::wait_for_listener(port).await?;

    // Delete should stop the runtime and remove the persisted record.
    manager.delete("lc-delete-running").await?;

    let result = manager.summary("lc-delete-running").await;
    assert!(result.is_err(), "deleted listener must not be found");

    // The port should be released — a new listener can bind it.
    manager.create(http_config("lc-after-delete", port)).await?;
    manager.start("lc-after-delete").await?;
    manager.stop("lc-after-delete").await?;
    Ok(())
}

#[tokio::test]
async fn delete_stopped_listener_removes_record() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-delete-stopped", port)).await?;
    manager.delete("lc-delete-stopped").await?;

    let result = manager.summary("lc-delete-stopped").await;
    assert!(result.is_err(), "deleted listener must not be found");
    Ok(())
}

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_returns_all_persisted_listeners() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, _guard_a) = common::available_port()?;
    let (port_b, _guard_b) = common::available_port_excluding(port_a)?;

    manager.create(http_config("lc-list-a", port_a)).await?;
    manager.create(http_config("lc-list-b", port_b)).await?;

    let summaries = manager.list().await?;
    let names: Vec<&str> = summaries.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"lc-list-a"), "list must contain lc-list-a");
    assert!(names.contains(&"lc-list-b"), "list must contain lc-list-b");
    Ok(())
}

// ---------------------------------------------------------------------------
// Crash recovery / restore_running tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_running_restarts_persisted_running_listeners()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let (port, guard) = common::available_port()?;

    // Simulate a teamserver crash: create the listener config in the DB and manually
    // set its state to Running without actually spawning a runtime task.  This mimics
    // a teamserver that died while a listener was active and left a stale Running entry.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(http_config("lc-restore", port)).await?;
        // Force the DB state to Running without starting the actual runtime task.
        manager.repository().set_state("lc-restore", ListenerStatus::Running, None).await?;
        let summary = manager.summary("lc-restore").await?;
        assert_eq!(summary.state.status, ListenerStatus::Running);
        // manager is dropped — no live runtime task, DB still says Running.
    }

    // A new manager over the same DB should call restore_running and actually start it.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    // Release the port reservation so restore_running() can bind it.
    drop(guard);
    restored.restore_running().await?;

    let summary = restored.summary("lc-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the listener back to Running"
    );

    // Verify the runtime is actually accepting connections.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    restored.stop("lc-restore").await?;
    Ok(())
}

#[tokio::test]
async fn restore_running_with_port_in_use_transitions_to_error_state()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let (port, guard) = common::available_port()?;

    // Simulate a stale Running entry left behind by a crashed teamserver.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(http_config("lc-restore-err", port)).await?;
        manager.repository().set_state("lc-restore-err", ListenerStatus::Running, None).await?;
    }

    // Build a new manager over the same DB — keep the guard alive so the port
    // remains occupied and restore_running() cannot bind it.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let result = restored.restore_running().await;
    assert!(result.is_err(), "restore_running must propagate the bind failure");

    // Even though restore_running returned an error, the DB should have been
    // transitioned to Error with a descriptive message.
    let summary = restored.summary("lc-restore-err").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Error,
        "listener must be in Error state when port is occupied"
    );
    assert!(
        summary.state.last_error.is_some(),
        "Error state must include a non-empty last_error message"
    );

    // Ensure the guard kept the port occupied for the duration of the test.
    drop(guard);
    Ok(())
}

#[tokio::test]
async fn restore_running_failure_halts_before_remaining_listeners()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let (port_fail, guard_fail) = common::available_port()?;
    let (port_ok, guard_ok) = common::available_port_excluding(port_fail)?;

    // Seed two listeners as Running in the DB.  Names are chosen so that the
    // failing listener ("lc-restore-aa-fail") sorts before the healthy one
    // ("lc-restore-bb-ok") in the `ORDER BY name` iteration that
    // `restore_running` uses.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(http_config("lc-restore-aa-fail", port_fail)).await?;
        manager.create(http_config("lc-restore-bb-ok", port_ok)).await?;
        manager.repository().set_state("lc-restore-aa-fail", ListenerStatus::Running, None).await?;
        manager.repository().set_state("lc-restore-bb-ok", ListenerStatus::Running, None).await?;
    }

    // Build a new manager over the same DB.  Keep `guard_fail` alive so
    // "lc-restore-aa-fail" cannot bind, but release `guard_ok` so the other
    // port is free.
    drop(guard_ok);
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let result = restored.restore_running().await;
    assert!(result.is_err(), "restore_running must return an error when a listener cannot rebind");

    // The failing listener must have been transitioned to Error with a message.
    let fail_summary = restored.summary("lc-restore-aa-fail").await?;
    assert_eq!(
        fail_summary.state.status,
        ListenerStatus::Error,
        "the failing listener must be in Error state"
    );
    assert!(
        fail_summary.state.last_error.is_some(),
        "the failing listener must record an error message"
    );

    // Because restore_running returns early on the first bind failure, the
    // second listener is never attempted — it still has its stale Running
    // status from the previous session, with no live runtime behind it.
    let ok_summary = restored.summary("lc-restore-bb-ok").await?;
    assert_eq!(
        ok_summary.state.status,
        ListenerStatus::Running,
        "the second listener is left with stale Running state (early return)"
    );

    drop(guard_fail);
    Ok(())
}

// ---------------------------------------------------------------------------
// Concurrent operations test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_create_and_start_for_independent_listeners_do_not_interfere()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, guard_a) = common::available_port()?;
    let (port_b, guard_b) = common::available_port_excluding(port_a)?;
    let (port_c, guard_c) = common::available_port_excluding(port_b)?;

    // Create all three listeners.
    manager.create(http_config("lc-concurrent-a", port_a)).await?;
    manager.create(http_config("lc-concurrent-b", port_b)).await?;
    manager.create(http_config("lc-concurrent-c", port_c)).await?;

    // Release port reservations before the concurrent starts bind.
    drop(guard_a);
    drop(guard_b);
    drop(guard_c);

    // Start them concurrently.
    let (r_a, r_b, r_c) = tokio::join!(
        manager.start("lc-concurrent-a"),
        manager.start("lc-concurrent-b"),
        manager.start("lc-concurrent-c"),
    );
    r_a?;
    r_b?;
    r_c?;

    // All three should be Running.
    for name in ["lc-concurrent-a", "lc-concurrent-b", "lc-concurrent-c"] {
        let summary = manager.summary(name).await?;
        assert_eq!(
            summary.state.status,
            ListenerStatus::Running,
            "{name} should be Running after concurrent start"
        );
    }

    // Stop all.
    manager.stop("lc-concurrent-a").await?;
    manager.stop("lc-concurrent-b").await?;
    manager.stop("lc-concurrent-c").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Update tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_stopped_listener_replaces_config() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, _guard_a) = common::available_port()?;
    let (port_b, guard_b) = common::available_port_excluding(port_a)?;

    manager.create(http_config("lc-update-stopped", port_a)).await?;

    // Update the config to use a different port while still in Created state.
    let updated = manager.update(http_config("lc-update-stopped", port_b)).await?;

    // The listener should be in Stopped state after update (update sets Stopped).
    assert_eq!(updated.state.status, ListenerStatus::Stopped);

    // Verify the persisted config has the new port.
    let summary = manager.summary("lc-update-stopped").await?;
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_bind, port_b, "port must be updated to the new value");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // Start on the new port to confirm it actually works.
    drop(guard_b);
    let running = manager.start("lc-update-stopped").await?;
    assert_eq!(running.state.status, ListenerStatus::Running);

    timeout(Duration::from_secs(2), common::wait_for_listener(port_b)).await??;

    manager.stop("lc-update-stopped").await?;
    Ok(())
}

#[tokio::test]
async fn update_running_listener_restarts_with_new_config() -> Result<(), Box<dyn std::error::Error>>
{
    let manager = test_manager().await?;
    let (port_a, guard_a) = common::available_port()?;
    let (port_b, guard_b) = common::available_port_excluding(port_a)?;

    manager.create(http_config("lc-update-running", port_a)).await?;
    drop(guard_a);
    manager.start("lc-update-running").await?;
    common::wait_for_listener(port_a).await?;

    // Update with a new port while the listener is running — should stop, update, restart.
    drop(guard_b);
    let updated = manager.update(http_config("lc-update-running", port_b)).await?;
    assert_eq!(
        updated.state.status,
        ListenerStatus::Running,
        "a running listener must be restarted after update"
    );

    // The new port should be reachable.
    timeout(Duration::from_secs(2), common::wait_for_listener(port_b)).await??;

    // Verify the persisted config reflects the new port.
    let summary = manager.summary("lc-update-running").await?;
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_bind, port_b, "port must be updated to the new value");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    manager.stop("lc-update-running").await?;
    Ok(())
}

#[tokio::test]
async fn update_running_listener_persists_non_port_config_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Create and start a listener with default host_rotation and no user_agent.
    manager.create(http_config("lc-update-cfg", port)).await?;
    drop(guard);
    manager.start("lc-update-cfg").await?;
    common::wait_for_listener(port).await?;

    // Build an updated config that keeps the same port but changes host_rotation
    // and sets a user_agent — these are non-port fields that should be persisted
    // without affecting the bind address.
    let updated_cfg = HttpListenerConfig {
        name: "lc-update-cfg".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "random".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("RedCell/1.0".to_owned()),
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
    };

    let updated = manager.update(ListenerConfig::from(updated_cfg.clone())).await?;

    // (1) The listener must still be Running after the update.
    assert_eq!(
        updated.state.status,
        ListenerStatus::Running,
        "listener must remain Running after config update"
    );

    // (2) summary() must reflect the new config values.
    let summary = manager.summary("lc-update-cfg").await?;
    assert_eq!(summary.state.status, ListenerStatus::Running, "persisted state must be Running");
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.host_rotation, "random", "host_rotation must be updated");
            assert_eq!(
                http.user_agent.as_deref(),
                Some("RedCell/1.0"),
                "user_agent must be updated"
            );
            assert_eq!(http.port_bind, port, "port must remain unchanged");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // (3) Verify the DB persisted the update by reading a fresh summary (which
    //     always reads from the database).
    let db_summary = manager.summary("lc-update-cfg").await?;
    match &db_summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.host_rotation, "random", "DB must persist host_rotation");
            assert_eq!(
                http.user_agent.as_deref(),
                Some("RedCell/1.0"),
                "DB must persist user_agent"
            );
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // The listener should still be accepting connections on the same port.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-update-cfg").await?;
    Ok(())
}

#[tokio::test]
async fn update_nonexistent_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    let result = manager.update(http_config("no-such-listener", port)).await;
    assert!(result.is_err(), "updating a listener that does not exist must return an error");
    Ok(())
}

// ---------------------------------------------------------------------------
// Delete nonexistent test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_nonexistent_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    let result = manager.delete("no-such-listener").await;
    assert!(result.is_err(), "deleting a listener that does not exist must return an error");
    Ok(())
}

// ---------------------------------------------------------------------------
// Error-state recovery tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_succeeds_after_error_state_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // 1. Create a listener and attempt to start it while the port is occupied.
    manager.create(http_config("lc-error-recovery", port)).await?;
    let result = manager.start("lc-error-recovery").await;
    assert!(result.is_err(), "start must fail when port is occupied");

    let summary = manager.summary("lc-error-recovery").await?;
    assert_eq!(summary.state.status, ListenerStatus::Error);
    assert!(summary.state.last_error.is_some(), "error state must record a failure message");

    // 2. Release the port so the listener can bind.
    drop(guard);

    // 3. Retry start — should transition from Error to Running.
    let running = manager.start("lc-error-recovery").await?;
    assert_eq!(
        running.state.status,
        ListenerStatus::Running,
        "listener must transition from Error to Running after port is freed"
    );

    // 4. Verify the DB is consistent.
    let db_summary = manager.summary("lc-error-recovery").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(
        db_summary.state.last_error.is_none(),
        "last_error must be cleared after successful restart"
    );

    // 5. Verify the listener is actually accepting connections.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-error-recovery").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Same-port conflict between managed listeners
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_second_listener_on_same_port_fails_and_preserves_first()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Create two listeners with different names but the same bind port.
    manager.create(http_config("lc-port-first", port)).await?;
    manager.create(http_config("lc-port-second", port)).await?;

    // Start the first listener — release the port guard so it can bind.
    drop(guard);
    manager.start("lc-port-first").await?;
    common::wait_for_listener(port).await?;

    // Starting the second listener on the same port must fail.
    let result = manager.start("lc-port-second").await;
    assert!(result.is_err(), "starting a second listener on an occupied port must fail");

    // The second listener must be in Error state with a recorded error message.
    let second_summary = manager.summary("lc-port-second").await?;
    assert_eq!(
        second_summary.state.status,
        ListenerStatus::Error,
        "the colliding listener must be in Error state"
    );
    assert!(
        second_summary.state.last_error.is_some(),
        "the colliding listener must record a last_error message"
    );

    // The first listener must still be Running.
    let first_summary = manager.summary("lc-port-first").await?;
    assert_eq!(
        first_summary.state.status,
        ListenerStatus::Running,
        "the original listener must remain Running"
    );

    // The first listener must still be reachable.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-port-first").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// kill_date and working_hours enforcement tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_with_past_kill_date_rejects_demon_init() -> Result<(), Box<dyn std::error::Error>>
{
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Set kill_date to 1 second in the past (unix timestamp).
    let past_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .saturating_sub(1);
    let kill_date_str = past_epoch.to_string();

    manager.create(http_config_with_time("lc-kill-past", port, Some(&kill_date_str), None)).await?;
    drop(guard);
    manager.start("lc-kill-past").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // Attempt a DEMON_INIT — should be rejected (fake 404).
    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_1001;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let body = common::valid_demon_init_body(agent_id, key, iv);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "DEMON_INIT must be rejected when kill_date is in the past"
    );

    manager.stop("lc-kill-past").await?;
    Ok(())
}

#[tokio::test]
async fn listener_with_future_kill_date_accepts_demon_init()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Set kill_date to 1 hour in the future.
    let future_epoch =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + 3600;
    let kill_date_str = future_epoch.to_string();

    manager
        .create(http_config_with_time("lc-kill-future", port, Some(&kill_date_str), None))
        .await?;
    drop(guard);
    manager.start("lc-kill-future").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // DEMON_INIT should succeed (200 OK with a body).
    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_1002;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let body =
        common::valid_demon_init_body_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "DEMON_INIT must succeed when kill_date is in the future"
    );
    let resp_body = resp.bytes().await?;
    assert!(!resp_body.is_empty(), "init ACK must have a non-empty body");

    manager.stop("lc-kill-future").await?;
    Ok(())
}

/// WorkingHours is enforced agent-side (victim's local clock), not server-side.
/// Verify that a listener with working_hours configured still accepts callbacks
/// regardless of the server's current time.
#[tokio::test]
async fn listener_working_hours_does_not_gate_server_side() -> Result<(), Box<dyn std::error::Error>>
{
    use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Pick a working_hours window that definitely excludes the current UTC time.
    // The server must still accept the callback because enforcement is agent-side.
    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let utc_hour = ((now_secs % 86400) / 3600) as u8;
    let excluded_start = (utc_hour + 12) % 24;
    let excluded_end = (excluded_start + 1) % 24;
    let (start, end) =
        if excluded_end > excluded_start { (excluded_start, excluded_end) } else { (5_u8, 6_u8) };
    let working_hours = format!("{start:02}:00-{end:02}:00");

    manager
        .create(http_config_with_time("lc-wh-no-gate", port, None, Some(&working_hours)))
        .await?;
    drop(guard);
    manager.start("lc-wh-no-gate").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_2001;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let body =
        common::valid_demon_init_body_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(body).send().await?;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "DEMON_INIT must succeed even outside working hours ({working_hours}, UTC hour {utc_hour}) — enforcement is agent-side"
    );
    let resp_body = resp.bytes().await?;
    assert!(!resp_body.is_empty(), "init ACK must have a non-empty body");

    manager.stop("lc-wh-no-gate").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SMB listener lifecycle tests
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn smb_listener_create_start_stop_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let pipe = unique_pipe_name("lifecycle");

    // Create — persisted in Created state.
    manager.create(smb_config("lc-smb-lifecycle", &pipe)).await?;
    let summary = manager.summary("lc-smb-lifecycle").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start — transitions to Running.
    let started = manager.start("lc-smb-lifecycle").await?;
    assert_eq!(started.state.status, ListenerStatus::Running);

    // Verify the pipe is actually accepting connections.
    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-smb-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    // Stop — transitions to Stopped.
    let stopped = manager.stop("lc-smb-lifecycle").await?;
    assert_eq!(stopped.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-smb-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);

    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn smb_listener_restart_after_stop_rebinds_pipe() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let pipe = unique_pipe_name("restart");

    manager.create(smb_config("lc-smb-restart", &pipe)).await?;
    manager.start("lc-smb-restart").await?;

    // Verify the pipe is reachable.
    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    // Stop — pipe should be cleaned up.
    manager.stop("lc-smb-restart").await?;

    // Restart — pipe must be re-created and accepting connections again.
    let restarted = manager.start("lc-smb-restart").await?;
    assert_eq!(restarted.state.status, ListenerStatus::Running);

    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-smb-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-smb-restart").await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn smb_listener_multiple_restart_cycles_succeed() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let pipe = unique_pipe_name("multi-restart");

    manager.create(smb_config("lc-smb-multi-restart", &pipe)).await?;

    for cycle in 0..3 {
        let started = manager.start("lc-smb-multi-restart").await?;
        assert_eq!(
            started.state.status,
            ListenerStatus::Running,
            "cycle {cycle}: listener must be Running after start"
        );

        timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

        let stopped = manager.stop("lc-smb-multi-restart").await?;
        assert_eq!(
            stopped.state.status,
            ListenerStatus::Stopped,
            "cycle {cycle}: listener must be Stopped after stop"
        );
    }

    let db_summary = manager.summary("lc-smb-multi-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS listener lifecycle tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dns_listener_create_start_stop_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Create — persisted in Created state.
    manager.create(dns_config("lc-dns-lifecycle", port)).await?;
    let summary = manager.summary("lc-dns-lifecycle").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start — transitions to Running.
    drop(guard);
    let started = manager.start("lc-dns-lifecycle").await?;
    assert_eq!(started.state.status, ListenerStatus::Running);

    // Verify the UDP socket is accepting queries.
    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-dns-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    // Stop — transitions to Stopped.
    let stopped = manager.stop("lc-dns-lifecycle").await?;
    assert_eq!(stopped.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-dns-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);

    Ok(())
}

#[tokio::test]
async fn dns_listener_restart_after_stop_rebinds_port() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(dns_config("lc-dns-restart", port)).await?;
    drop(guard);
    manager.start("lc-dns-restart").await?;
    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    manager.stop("lc-dns-restart").await?;

    // Restart — UDP port must be re-bound.
    let restarted = manager.start("lc-dns-restart").await?;
    assert_eq!(restarted.state.status, ListenerStatus::Running);

    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    let db_summary = manager.summary("lc-dns-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-dns-restart").await?;
    Ok(())
}

#[tokio::test]
async fn restore_running_restarts_persisted_dns_listener() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let (port, guard) = common::available_port()?;

    // Simulate a teamserver crash: create the DNS listener in the DB and manually
    // set its state to Running without actually spawning a runtime task.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(dns_config("lc-dns-restore", port)).await?;
        manager.repository().set_state("lc-dns-restore", ListenerStatus::Running, None).await?;
        let summary = manager.summary("lc-dns-restore").await?;
        assert_eq!(summary.state.status, ListenerStatus::Running);
        // manager is dropped — no live runtime task, DB still says Running.
    }

    // A new manager over the same DB should call restore_running and actually start it.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    // Release the port reservation so restore_running() can bind it.
    drop(guard);
    restored.restore_running().await?;

    let summary = restored.summary("lc-dns-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the DNS listener back to Running"
    );

    // Verify the runtime is actually accepting queries.
    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    restored.stop("lc-dns-restore").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SMB crash recovery tests
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn restore_running_restarts_persisted_smb_listener() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let pipe = unique_pipe_name("restore");

    // Simulate a teamserver crash with a stale Running SMB listener.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(smb_config("lc-smb-restore", &pipe)).await?;
        manager.repository().set_state("lc-smb-restore", ListenerStatus::Running, None).await?;
    }

    // A new manager should restore the SMB listener.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    restored.restore_running().await?;

    let summary = restored.summary("lc-smb-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the SMB listener back to Running"
    );

    // Verify the pipe is actually accepting connections.
    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    restored.stop("lc-smb-restore").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// External listener lifecycle tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn external_listener_create_start_stop_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    // Create — persisted in Created state.
    manager.create(external_config("lc-ext-lifecycle", "/bridge-lc")).await?;
    let summary = manager.summary("lc-ext-lifecycle").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start — transitions to Running (no socket owned, just registration).
    let started = manager.start("lc-ext-lifecycle").await?;
    assert_eq!(started.state.status, ListenerStatus::Running);

    let db_summary = manager.summary("lc-ext-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    // Stop — transitions to Stopped.
    let stopped = manager.stop("lc-ext-lifecycle").await?;
    assert_eq!(stopped.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-ext-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);

    Ok(())
}

#[tokio::test]
async fn external_listener_restart_after_stop() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    manager.create(external_config("lc-ext-restart", "/bridge-restart")).await?;
    manager.start("lc-ext-restart").await?;
    manager.stop("lc-ext-restart").await?;

    // Restart — should succeed (external listeners have no socket to rebind).
    let restarted = manager.start("lc-ext-restart").await?;
    assert_eq!(restarted.state.status, ListenerStatus::Running);

    let db_summary = manager.summary("lc-ext-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-ext-restart").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// External crash recovery tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_running_restarts_persisted_external_listener()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;

    // Simulate a teamserver crash: create the External listener in the DB and manually
    // set its state to Running without actually spawning a runtime task.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(external_config("lc-ext-restore", "/bridge-restore")).await?;
        manager.repository().set_state("lc-ext-restore", ListenerStatus::Running, None).await?;
        let summary = manager.summary("lc-ext-restore").await?;
        assert_eq!(summary.state.status, ListenerStatus::Running);
        // manager is dropped — no live runtime task, DB still says Running,
        // but external_endpoints map is empty (simulates crash).
    }

    // A new manager over the same DB should call restore_running and re-register
    // the external listener endpoint.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    restored.restore_running().await?;

    let summary = restored.summary("lc-ext-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the external listener back to Running"
    );

    // Yield to let the spawned task register the endpoint in external_endpoints.
    tokio::task::yield_now().await;

    // The key assertion: the endpoint map must be repopulated so the Axum
    // fallback handler can route bridge requests to this listener.
    let state = restored.external_state_for_path("/bridge-restore").await.expect(
        "restore_running must re-register external listener endpoint in external_endpoints",
    );
    assert_eq!(state.listener_name(), "lc-ext-restore");
    assert_eq!(state.endpoint(), "/bridge-restore");

    restored.stop("lc-ext-restore").await?;
    Ok(())
}

#[tokio::test]
async fn external_listener_delete_while_running() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    manager.create(external_config("lc-ext-delete", "/bridge-delete")).await?;
    manager.start("lc-ext-delete").await?;

    // Delete should stop and remove.
    manager.delete("lc-ext-delete").await?;

    let result = manager.summary("lc-ext-delete").await;
    assert!(result.is_err(), "deleted external listener must not be found");

    // The endpoint should be freed — a new listener can claim it.
    manager.create(external_config("lc-ext-delete-2", "/bridge-delete")).await?;
    Ok(())
}
