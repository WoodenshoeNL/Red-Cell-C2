use super::*;

#[test]
fn authenticate_response_format_matches_havoc() {
    let response = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER },
        "Body": { "Success": true },
    });
    let head_type = response["Head"]["Type"].as_str().expect("unwrap");
    assert_eq!(head_type, "Register");
    assert!(response["Body"]["Success"].as_bool().expect("unwrap"));
}

#[tokio::test]
async fn dispatch_returns_ok_for_unknown_listener_subtype() {
    // `dispatch_message` requires a `WebSocket` (not constructable in unit
    // tests), so we test the equivalent "unknown type → Ok" path via
    // `handle_listener_message`, which `dispatch_message` delegates to for
    // HEAD_LISTENER messages and which has the same unknown-type branch.
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let (db, wh) = test_audit_deps().await;
    let mut client_listeners = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": { "Type": "CompletelyUnknownBodyType" },
    });

    let result =
        handle_listener_message(&message, &bridge, &events, &db, &wh, &mut client_listeners).await;
    assert!(result.is_ok(), "unknown listener sub-type should be silently ignored");
    assert!(client_listeners.is_empty(), "no listener should be registered");
}

#[tokio::test]
async fn handle_register_agent_broadcasts_event() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let mut client_agents = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER_AGENT },
        "Body": {
            "Agent": {
                "Name": "TestAgent",
                "Author": "test",
                "Description": "A test agent",
            }
        },
    });

    handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect("registration should succeed");

    assert!(bridge.agent_exists("TestAgent").await);
    assert_eq!(client_agents, vec!["TestAgent".to_owned()]);

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ServiceAgentRegister(msg) => {
            assert!(msg.info.agent.contains("TestAgent"));
        }
        _ => panic!("expected ServiceAgentRegister event"),
    }
}

#[tokio::test]
async fn handle_listener_add_broadcasts_event() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let mut client_listeners = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": {
            "Type": BODY_LISTENER_ADD,
            "Listener": {
                "Name": "custom-listener",
                "Agent": "TestAgent",
            },
        },
    });

    handle_listener_add(&message, &bridge, &events, &db, &wh, &mut client_listeners)
        .await
        .expect("listener add should succeed");

    assert_eq!(client_listeners, vec!["custom-listener".to_owned()]);

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ServiceListenerRegister(msg) => {
            assert!(msg.info.listener.contains("custom-listener"));
        }
        _ => panic!("expected ServiceListenerRegister event"),
    }
}

#[tokio::test]
async fn handle_register_agent_rejects_duplicate() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut client_agents = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER_AGENT },
        "Body": {
            "Agent": { "Name": "DupAgent" }
        },
    });

    handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect("first registration should succeed");

    let mut client_agents2 = Vec::new();
    let err = handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents2)
        .await
        .expect_err("duplicate should fail");

    assert!(
        matches!(err, ServiceBridgeError::DuplicateAgent { .. }),
        "expected DuplicateAgent error"
    );
}

#[tokio::test]
async fn missing_agent_name_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut client_agents = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER_AGENT },
        "Body": {
            "Agent": {}
        },
    });

    let err = handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect_err("missing Name should fail");

    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Name")),
        "expected MissingField error mentioning Name, got: {err:?}"
    );
}
