//! Session-snapshot and live-broadcast ACL filtering WebSocket tests:
//! verifies what frames an operator receives after login and that live
//! broadcasts respect operator ACLs for listeners and agents.

use std::time::Duration;

use red_cell_common::{OperatorInfo, operator::OperatorMessage};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

use super::{
    TestState, login, login_message, read_operator_message, read_operator_snapshot, sample_agent,
    sample_http_listener, spawn_server, teamserver_log_event,
};

#[tokio::test]
async fn websocket_sends_session_snapshot_after_login() {
    let state = TestState::new().await;
    let registry = state.registry.clone();
    let listeners = state.listeners.clone();
    let events = state.events.clone();
    registry
        .insert_with_listener(sample_agent(0xDEAD_BEEF), "alpha")
        .await
        .expect("agent should insert");
    listeners.create(sample_http_listener("alpha", 0)).await.expect("listener should persist");
    listeners.start("alpha").await.expect("listener should start");
    let expected_log = teamserver_log_event("teamserver", "snapshot entry");
    assert_eq!(events.broadcast(expected_log.clone()), 0);
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    let listener_event = read_operator_message(&mut socket).await;
    let OperatorMessage::ListenerNew(message) = listener_event else {
        panic!("expected listener snapshot event");
    };
    assert_eq!(message.info.name.as_deref(), Some("alpha"));
    assert_eq!(message.info.status.as_deref(), Some("Online"));

    assert_eq!(read_operator_message(&mut socket).await, expected_log);

    let agent_event = read_operator_message(&mut socket).await;
    let OperatorMessage::AgentNew(message) = agent_event else {
        panic!("expected agent snapshot event");
    };
    assert_eq!(message.info.name_id, "DEADBEEF");
    assert_eq!(message.info.listener, "alpha");
    assert_eq!(message.info.magic_value, "deadbeef");
    let encoded = serde_json::to_value(&message.info).expect("agent snapshot should serialize");
    assert!(encoded.get("Encryption").is_none());

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_session_snapshot_includes_configured_and_runtime_operators() {
    let state = TestState::new().await;
    state
        .auth
        .create_operator("trinity", "zion", red_cell_common::config::OperatorRole::Operator)
        .await
        .expect("runtime operator should be created");
    let (mut socket, server) = spawn_server(state).await;

    socket.send_frame(ClientMessage::Text(login_message("operator", "password1234").into())).await;
    let response = read_operator_message(&mut socket).await;
    assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));

    let operators = read_operator_snapshot(&mut socket).await;
    assert_eq!(
        operators,
        vec![
            OperatorInfo {
                username: "admin".to_owned(),
                password_hash: None,
                role: Some("Admin".to_owned()),
                online: false,
                last_seen: None,
            },
            OperatorInfo {
                username: "analyst".to_owned(),
                password_hash: None,
                role: Some("Analyst".to_owned()),
                online: false,
                last_seen: None,
            },
            OperatorInfo {
                username: "operator".to_owned(),
                password_hash: None,
                role: Some("Operator".to_owned()),
                online: true,
                last_seen: None,
            },
            OperatorInfo {
                username: "trinity".to_owned(),
                password_hash: None,
                role: Some("Operator".to_owned()),
                online: false,
                last_seen: None,
            },
        ]
    );

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_session_snapshot_includes_agent_pivot_chain() {
    let state = TestState::new().await;
    let registry = state.registry.clone();
    registry.insert(sample_agent(0x0102_0304)).await.expect("parent should insert");
    registry.insert(sample_agent(0x1112_1314)).await.expect("child should insert");
    registry.add_link(0x0102_0304, 0x1112_1314).await.expect("pivot link should insert");
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    let parent_event = read_operator_message(&mut socket).await;
    let OperatorMessage::AgentNew(parent_message) = parent_event else {
        panic!("expected parent snapshot event");
    };
    assert_eq!(parent_message.info.name_id, "01020304");
    assert!(parent_message.info.pivots.parent.is_none());
    assert_eq!(parent_message.info.pivots.links, vec!["11121314".to_owned()]);

    let child_event = read_operator_message(&mut socket).await;
    let OperatorMessage::AgentNew(child_message) = child_event else {
        panic!("expected child snapshot event");
    };
    assert_eq!(child_message.info.name_id, "11121314");
    assert_eq!(child_message.info.pivots.parent.as_deref(), Some("01020304"));
    assert_eq!(child_message.info.pivot_parent, "01020304");

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_snapshot_includes_persisted_offline_listeners() {
    let state = TestState::new().await;
    let listeners = state.listeners.clone();
    listeners
        .create(sample_http_listener("offline-alpha", 0))
        .await
        .expect("listener should persist");
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    let listener_event = read_operator_message(&mut socket).await;
    let OperatorMessage::ListenerNew(message) = listener_event else {
        panic!("expected listener snapshot event");
    };
    assert_eq!(message.info.name.as_deref(), Some("offline-alpha"));
    assert_eq!(message.info.status.as_deref(), Some("Offline"));

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_session_snapshot_filters_listeners_and_agents_by_operator_acl() {
    let state = TestState::new().await;
    let registry = state.registry.clone();
    let listeners = state.listeners.clone();
    let database = state.database.clone();

    listeners
        .create(sample_http_listener("alpha-public", 0))
        .await
        .expect("public listener should persist");
    listeners
        .create(sample_http_listener("beta-admin", 0))
        .await
        .expect("admin listener should persist");

    // beta-admin has an allow-list scoped to `admin` only, so the `operator`
    // account must not learn of it via the WebSocket snapshot.
    database
        .listener_access()
        .set_allowed_operators("beta-admin", &["admin".to_owned()])
        .await
        .expect("seed listener access");

    registry
        .insert_with_listener(sample_agent(0xAAAA_1111), "alpha-public")
        .await
        .expect("public agent should insert");
    registry
        .insert_with_listener(sample_agent(0xBBBB_2222), "beta-admin")
        .await
        .expect("admin agent should insert");

    database
        .agent_groups()
        .set_agent_groups(0xAAAA_1111, &["public-group".to_owned()])
        .await
        .expect("seed public agent group");
    database
        .agent_groups()
        .set_agent_groups(0xBBBB_2222, &["admin-group".to_owned()])
        .await
        .expect("seed admin agent group");
    database
        .agent_groups()
        .set_operator_allowed_groups("operator", &["public-group".to_owned()])
        .await
        .expect("seed operator agent-group scope");

    let (mut socket, server) = spawn_server(state).await;
    login(&mut socket, "operator", "password1234").await;

    // Drain all snapshot frames with a short per-frame timeout; the filtered
    // snapshot must contain only the listener/agent the operator is entitled
    // to see.
    let mut events = Vec::new();
    while let Ok(msg) = timeout(Duration::from_millis(500), socket.recv_msg()).await {
        events.push(msg);
    }

    let listener_names: Vec<String> = events
        .iter()
        .filter_map(|msg| match msg {
            OperatorMessage::ListenerNew(m) => m.info.name.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(listener_names, vec!["alpha-public".to_owned()]);

    let agent_ids: Vec<String> = events
        .iter()
        .filter_map(|msg| match msg {
            OperatorMessage::AgentNew(m) => Some(m.info.name_id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(agent_ids, vec!["AAAA1111".to_owned()]);

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_live_broadcast_filters_events_outside_operator_acl() {
    use crate::PivotInfo;
    use crate::agent_events::{agent_mark_event, agent_new_event};
    use crate::{ListenerEventAction, listener_event_for_action};

    let state = TestState::new().await;
    let registry = state.registry.clone();
    let listeners = state.listeners.clone();
    let database = state.database.clone();
    let events = state.events.clone();

    listeners
        .create(sample_http_listener("alpha-public", 0))
        .await
        .expect("public listener should persist");
    listeners
        .create(sample_http_listener("beta-admin", 0))
        .await
        .expect("admin listener should persist");

    // beta-admin is scoped to `admin`; the `operator` account must not see
    // live events carrying that listener's name or any agent attached to it.
    database
        .listener_access()
        .set_allowed_operators("beta-admin", &["admin".to_owned()])
        .await
        .expect("seed listener access");

    let admin_agent = sample_agent(0xBBBB_2222);
    let public_agent = sample_agent(0xAAAA_1111);
    registry
        .insert_with_listener(admin_agent.clone(), "beta-admin")
        .await
        .expect("admin agent should insert");
    registry
        .insert_with_listener(public_agent.clone(), "alpha-public")
        .await
        .expect("public agent should insert");

    database
        .agent_groups()
        .set_agent_groups(0xBBBB_2222, &["admin-group".to_owned()])
        .await
        .expect("seed admin agent group");
    database
        .agent_groups()
        .set_agent_groups(0xAAAA_1111, &["public-group".to_owned()])
        .await
        .expect("seed public agent group");
    database
        .agent_groups()
        .set_operator_allowed_groups("operator", &["public-group".to_owned()])
        .await
        .expect("seed operator agent-group scope");

    let (mut operator_socket, server) = spawn_server(state.clone()).await;
    login(&mut operator_socket, "operator", "password1234").await;

    // Drain snapshot frames so the assertions below observe only live
    // broadcasts that arrive after this point.
    while (timeout(Duration::from_millis(200), operator_socket.recv_msg()).await).is_ok() {}

    let beta_summary = listeners.summary("beta-admin").await.expect("beta listener");
    let alpha_summary = listeners.summary("alpha-public").await.expect("alpha listener");
    let pivots = PivotInfo::default();

    // Broadcasts for the restricted listener / agent must be filtered out.
    events.broadcast(listener_event_for_action(
        "admin",
        &beta_summary,
        ListenerEventAction::Updated,
    ));
    events.broadcast(agent_new_event(
        "beta-admin",
        red_cell_common::demon::DEMON_MAGIC_VALUE,
        &admin_agent,
        &pivots,
    ));
    events.broadcast(agent_mark_event(&admin_agent));

    // A visible broadcast for the public listener proves the filter lets
    // authorized events through and serves as a synchronization barrier.
    events.broadcast(listener_event_for_action(
        "admin",
        &alpha_summary,
        ListenerEventAction::Updated,
    ));
    events.broadcast(agent_new_event(
        "alpha-public",
        red_cell_common::demon::DEMON_MAGIC_VALUE,
        &public_agent,
        &pivots,
    ));

    // Collect whatever arrives during a short window after the broadcasts.
    let mut received = Vec::new();
    while let Ok(msg) = timeout(Duration::from_millis(300), operator_socket.recv_msg()).await {
        received.push(msg);
    }

    for msg in &received {
        match msg {
            OperatorMessage::ListenerEdit(m) => {
                assert_ne!(
                    m.info.name.as_deref(),
                    Some("beta-admin"),
                    "operator must not receive ListenerEdit for restricted listener"
                );
            }
            OperatorMessage::AgentNew(m) => {
                assert_ne!(
                    m.info.name_id, "BBBB2222",
                    "operator must not receive AgentNew for restricted agent"
                );
            }
            OperatorMessage::AgentUpdate(m) => {
                assert_ne!(
                    m.info.agent_id, "BBBB2222",
                    "operator must not receive AgentUpdate for restricted agent"
                );
            }
            _ => {}
        }
    }

    let saw_alpha_listener = received.iter().any(|msg| {
        matches!(msg, OperatorMessage::ListenerEdit(m) if m.info.name.as_deref() == Some("alpha-public"))
    });
    assert!(saw_alpha_listener, "operator must receive ListenerEdit for the public listener");

    let saw_alpha_agent = received
        .iter()
        .any(|msg| matches!(msg, OperatorMessage::AgentNew(m) if m.info.name_id == "AAAA1111"));
    assert!(saw_alpha_agent, "operator must receive AgentNew for the public agent");

    operator_socket.close().await;
    server.abort();
}
