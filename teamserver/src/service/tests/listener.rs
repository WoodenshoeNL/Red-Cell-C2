use super::*;

fn listener_start_message(status: &str, error: &str) -> Value {
    serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": {
            "Type": BODY_LISTENER_START,
            "Listener": {
                "Name": "https-listener",
                "Protocol": "HTTPS",
                "Host": "0.0.0.0",
                "PortBind": "443",
                "Status": status,
                "Error": error,
                "Info": { "CertPath": "/tmp/cert.pem" },
            },
        },
    })
}

#[tokio::test]
async fn listener_start_broadcasts_online_mark() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = listener_start_message("online", "");

    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ListenerMark(msg) => {
            assert_eq!(msg.info.name, "https-listener");
            assert_eq!(msg.info.mark, "Online");
        }
        other => panic!("expected ListenerMark, got: {other:?}"),
    }
}

#[tokio::test]
async fn listener_start_broadcasts_error_on_failure() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = listener_start_message("error", "bind: address already in use");

    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed even on error status");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ListenerError(msg) => {
            assert_eq!(msg.info.name, "https-listener");
            assert_eq!(msg.info.error, "bind: address already in use");
        }
        other => panic!("expected ListenerError, got: {other:?}"),
    }
}

#[tokio::test]
async fn listener_start_error_text_nonempty_overrides_status() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    // Status is "online" but error text is non-empty — should still treat as error.
    let message = listener_start_message("online", "partial failure");

    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(
        matches!(event, OperatorMessage::ListenerError(_)),
        "non-empty error text should produce ListenerError"
    );
}

#[tokio::test]
async fn listener_start_rejects_missing_name() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Body": {
            "Type": BODY_LISTENER_START,
            "Listener": {
                "Protocol": "HTTPS",
                "Host": "0.0.0.0",
                "PortBind": "443",
                "Status": "online",
                "Error": "",
            },
        },
    });

    let err = handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect_err("missing Name should fail");
    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Name")),
        "expected MissingField mentioning Name, got: {err:?}"
    );
}

#[tokio::test]
async fn listener_start_rejects_missing_body() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let message = serde_json::json!({ "Head": { "Type": HEAD_LISTENER } });

    let err = handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect_err("missing Body should fail");
    assert!(matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Body")));
}

#[tokio::test]
async fn listener_start_rejects_missing_status() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Body": {
            "Type": BODY_LISTENER_START,
            "Listener": {
                "Name": "test",
                "Protocol": "HTTPS",
                "Host": "0.0.0.0",
                "PortBind": "443",
                "Error": "",
            },
        },
    });

    let err = handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect_err("missing Status should fail");
    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Status")),
        "expected MissingField mentioning Status, got: {err:?}"
    );
}

#[tokio::test]
async fn listener_message_dispatches_start() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let mut client_listeners = Vec::new();

    let message = listener_start_message("online", "");

    handle_listener_message(&message, &bridge, &events, &db, &wh, &mut client_listeners)
        .await
        .expect("dispatch to listener start should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(
        matches!(event, OperatorMessage::ListenerMark(_)),
        "expected ListenerMark from dispatched handler"
    );
}
