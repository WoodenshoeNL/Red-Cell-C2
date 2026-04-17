//! Agent-dispatch WebSocket tests: AgentTask enqueue/broadcast, AgentNote
//! registry updates, AgentRemove behaviour (including audit trail and ACL
//! enforcement), missing-agent dispatch reporting, and plugin TaskCreated
//! event firing through `execute_agent_task`.

use std::time::Duration;

use red_cell_common::{
    demon::DemonCommand,
    operator::{AgentTaskInfo, OperatorMessage},
};
use serde_json::Value;
use tokio::time::timeout;

use super::super::execute_agent_task;
use super::{
    TestState, agent_remove_message, agent_task_message, login, read_operator_message,
    sample_agent, sample_http_listener, spawn_server,
};
use crate::{AuditQuery, AuditResultStatus, query_audit_log};

#[tokio::test]
async fn websocket_agent_task_enqueues_job_and_broadcasts_event() {
    let state = TestState::new().await;
    let registry = state.registry.clone();
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    // Login each socket immediately after connecting to avoid the 5-second
    // unauthenticated-connection timeout firing under heavy parallel-test load.
    let (mut sender, server) = spawn_server(state.clone()).await;
    login(&mut sender, "operator", "password1234").await;
    let (mut observer, _) = spawn_server(state).await;
    login(&mut observer, "operator", "password1234").await;
    let snapshot = read_operator_message(&mut sender).await;
    assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));
    let snapshot = read_operator_message(&mut observer).await;
    assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));

    sender
        .send_text(agent_task_message(
            "operator",
            AgentTaskInfo {
                task_id: "2A".to_owned(),
                command_line: "checkin".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                ..AgentTaskInfo::default()
            },
        ))
        .await;

    let event = read_operator_message(&mut observer).await;
    let OperatorMessage::AgentTask(message) = event else {
        panic!("expected agent task broadcast");
    };
    assert_eq!(message.head.user, "operator");
    assert_eq!(message.info.demon_id, "DEADBEEF");

    let queued = registry.queued_jobs(0xDEAD_BEEF).await.expect("queue should load");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].command, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(queued[0].request_id, 0x2A);
    assert_eq!(queued[0].command_line, "checkin");

    sender.close().await;
    observer.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_agent_note_updates_registry() {
    let state = TestState::new().await;
    let registry = state.registry.clone();
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket
        .send_text(agent_task_message(
            "operator",
            AgentTaskInfo {
                task_id: "2B".to_owned(),
                command_line: "note tracked through vpn".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: "Teamserver".to_owned(),
                command: Some("note".to_owned()),
                arguments: Some("tracked through vpn".to_owned()),
                ..AgentTaskInfo::default()
            },
        ))
        .await;

    timeout(Duration::from_secs(2), async {
        loop {
            let updated = registry.get(0xDEAD_BEEF).await.expect("agent should exist");
            if updated.note == "tracked through vpn" {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("agent note should update");

    let updated = registry.get(0xDEAD_BEEF).await.expect("agent should exist");
    assert_eq!(updated.note, "tracked through vpn");

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_agent_remove_deletes_agent_for_admins() {
    let state = TestState::new().await;
    let registry = state.registry.clone();
    let sockets = state.sockets.clone();
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    sockets.add_socks_server(0xDEAD_BEEF, "0").await.expect("SOCKS server should start");
    assert!(sockets.list_socks_servers(0xDEAD_BEEF).await.contains("SOCKS5 servers"));
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "admin", "adminpass").await;
    let snapshot = read_operator_message(&mut socket).await;
    assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));

    socket.send_text(agent_remove_message("admin", "DEADBEEF")).await;

    let event = read_operator_message(&mut socket).await;
    assert!(matches!(event, OperatorMessage::AgentRemove(_)));
    assert!(registry.get(0xDEAD_BEEF).await.is_none());
    assert_eq!(sockets.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_agent_remove_records_success_audit_trail() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let registry = state.registry.clone();
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "admin", "adminpass").await;
    let _snapshot = read_operator_message(&mut socket).await;

    socket.send_text(agent_remove_message("admin", "DEADBEEF")).await;

    let _event = read_operator_message(&mut socket).await;

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.delete".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one agent.delete audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.action, "agent.delete");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.agent_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.command.as_deref(), Some("delete"));
    assert_eq!(entry.result_status, AuditResultStatus::Success);

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_agent_remove_missing_agent_records_failure_audit() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "admin", "adminpass").await;

    socket.send_text(agent_remove_message("admin", "DEADBEEF")).await;

    let _error = read_operator_message(&mut socket).await;

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.delete".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one agent.delete audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.action, "agent.delete");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.agent_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.command.as_deref(), Some("delete"));
    assert_eq!(entry.result_status, AuditResultStatus::Failure);
    let parameters = entry.parameters.as_ref().expect("failure audit should include parameters");
    assert_eq!(parameters.get("agent_id"), Some(&Value::String("DEADBEEF".to_owned())));
    assert!(parameters.get("error").is_some(), "failure audit should include error details");

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_agent_remove_enforces_operator_acl() {
    // Two operators with disjoint scopes: `admin` is restricted to
    // `admin-group` / `alpha-admin`, while a second agent owned by
    // `beta-public` belongs to an operator on `public-group`. AgentRemove
    // requires Admin role, so this test narrows `admin`'s agent-group and
    // listener allow-lists to simulate "operator A" whose ACL does not cover
    // the target agent, then asserts the sibling agent owned by "operator B"
    // survives the denied remove.
    let state = TestState::new().await;
    let registry = state.registry.clone();
    let listeners = state.listeners.clone();
    let database = state.database.clone();

    listeners
        .create(sample_http_listener("alpha-admin", 0))
        .await
        .expect("admin listener should persist");
    listeners
        .create(sample_http_listener("beta-public", 0))
        .await
        .expect("public listener should persist");

    // Restrict each listener to its owning operator so the remove command
    // would still be blocked even if group ACLs were misconfigured.
    database
        .listener_access()
        .set_allowed_operators("alpha-admin", &["admin".to_owned()])
        .await
        .expect("seed alpha listener access");
    database
        .listener_access()
        .set_allowed_operators("beta-public", &["operator".to_owned()])
        .await
        .expect("seed beta listener access");

    registry
        .insert_with_listener(sample_agent(0xAAAA_1111), "alpha-admin")
        .await
        .expect("admin agent should insert");
    registry
        .insert_with_listener(sample_agent(0xBBBB_2222), "beta-public")
        .await
        .expect("public agent should insert");

    database
        .agent_groups()
        .set_agent_groups(0xAAAA_1111, &["admin-group".to_owned()])
        .await
        .expect("seed admin agent group");
    database
        .agent_groups()
        .set_agent_groups(0xBBBB_2222, &["public-group".to_owned()])
        .await
        .expect("seed public agent group");
    database
        .agent_groups()
        .set_operator_allowed_groups("admin", &["admin-group".to_owned()])
        .await
        .expect("seed admin agent-group scope");

    let (mut socket, server) = spawn_server(state).await;
    login(&mut socket, "admin", "adminpass").await;

    // Drain the snapshot so the only frame that arrives after sending the
    // AgentRemove is the authorization-denied teamserver log.
    while (timeout(Duration::from_millis(200), socket.recv_msg()).await).is_ok() {}

    // `admin` dispatches an AgentRemove for the agent that belongs to
    // operator B's listener — outside admin's agent-group and listener ACL.
    socket.send_text(agent_remove_message("admin", "BBBB2222")).await;

    let event = read_operator_message(&mut socket).await;
    let OperatorMessage::TeamserverLog(message) = event else {
        panic!("expected teamserver log for denied remove, got {event:?}");
    };
    assert!(
        message.info.text.contains("not permitted"),
        "expected authorization error, got: {}",
        message.info.text
    );

    // The other operator's agent must still be registered — the denial must
    // block the remove before it reaches the registry.
    assert!(
        registry.get(0xBBBB_2222).await.is_some(),
        "public agent must survive a denied remove from a disjoint admin"
    );
    // The admin's own agent must be untouched.
    assert!(registry.get(0xAAAA_1111).await.is_some(), "admin agent must remain untouched");

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_reports_missing_agents_for_agent_commands() {
    let state = TestState::new().await;
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket
        .send_text(agent_task_message(
            "operator",
            AgentTaskInfo {
                task_id: "2C".to_owned(),
                command_line: "checkin".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                ..AgentTaskInfo::default()
            },
        ))
        .await;

    let event = read_operator_message(&mut socket).await;
    let OperatorMessage::TeamserverLog(message) = event else {
        panic!("expected teamserver log");
    };
    assert!(message.info.text.contains("not found"));

    socket.close().await;
    server.abort();
}

#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn execute_agent_task_fires_plugin_task_created_event()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{
        AgentRegistry, Database, EventBus, PluginEvent, PluginRuntime, SocketRelayManager,
    };
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList};

    let _guard = crate::plugins::PLUGIN_RUNTIME_TEST_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Build a PluginRuntime and install it as the active runtime.
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    )
    .await?;

    struct RuntimeGuard(Option<PluginRuntime>);
    impl Drop for RuntimeGuard {
        fn drop(&mut self) {
            let _ = PluginRuntime::swap_active(self.0.take());
        }
    }
    let previous = PluginRuntime::swap_active(Some(runtime.clone()))?;
    let _reset = RuntimeGuard(previous);

    // Register a TaskCreated callback that records the command_line for each event.
    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                runtime.install_api_module_for_test(py)?;
                let tracker = PyList::empty(py);
                let locals = PyDict::new(py);
                locals.set_item("_tracker", tracker.clone())?;
                let cb = py.eval(
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.data['command_line']))(_tracker)"
                    ),
                    None,
                    Some(&locals),
                )?;
                Ok::<_, PyErr>((tracker.unbind(), cb.unbind()))
            })
        }
    })
    .await??;

    runtime.register_callback_for_test(PluginEvent::TaskCreated, callback).await?;

    // Insert an agent so execute_agent_task can find it.
    let agent_id: u32 = 0xABCD_1234;
    registry.insert(sample_agent(agent_id)).await?;

    // Build a task message that produces exactly one job (a checkin command).
    let message = red_cell_common::operator::Message {
        head: red_cell_common::operator::MessageHead {
            event: red_cell_common::operator::EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "FF".to_owned(), // task_id must parse as hex
            command_line: "checkin".to_owned(),
            demon_id: format!("{agent_id:08X}"),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        },
    };

    let queued = execute_agent_task(
        &registry,
        &sockets,
        &events,
        "operator",
        red_cell_common::config::OperatorRole::Admin,
        message,
    )
    .await?;
    assert_eq!(queued, 1, "checkin command should queue exactly one job");

    // Poll until the spawn_blocking inside invoke_callbacks appends to the
    // tracker list, or until 10 s elapse.  A fixed sleep is racy under
    // cargo test --workspace concurrency (Argon2id in parallel tests causes
    // CPU contention that can push the callback well past 100 ms).
    //
    // Py<T> does not implement Clone without a GIL token, so wrap it in
    // Arc to share across poll iterations.
    let tracker = std::sync::Arc::new(tracker);
    let deadline = std::time::Duration::from_secs(10);
    let (count, cmd_line) = tokio::time::timeout(deadline, async {
        loop {
            let tracker_ref = tracker.clone();
            let result = tokio::task::spawn_blocking(move || {
                Python::with_gil(|py| -> PyResult<Option<(usize, String)>> {
                    let list = tracker_ref.bind(py);
                    if list.is_empty() {
                        return Ok(None);
                    }
                    let count = list.len();
                    let first = list.get_item(0)?.extract::<String>()?;
                    Ok(Some((count, first)))
                })
            })
            .await
            .expect("spawn_blocking panicked")
            .expect("Python GIL error");

            if let Some(pair) = result {
                break pair;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for task_created callback after 10 s");

    assert_eq!(count, 1, "exactly one task_created callback should have fired");
    assert_eq!(cmd_line, "checkin");
    Ok(())
}
