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
async fn register_agent_creates_audit_entry() {
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
        "Body": { "Agent": { "Name": "AuditTestAgent" } },
    });

    handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect("registration should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.register_agent".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for agent registration");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].target_kind, "agent_type");
    assert_eq!(page.items[0].target_id.as_deref(), Some("AuditTestAgent"));
}

#[tokio::test]
async fn listener_add_creates_audit_entry() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut client_listeners = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": {
            "Type": BODY_LISTENER_ADD,
            "Listener": { "Name": "audit-listener" },
        },
    });

    handle_listener_add(&message, &bridge, &events, &db, &wh, &mut client_listeners)
        .await
        .expect("listener add should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.listener_add".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for listener add");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].target_id.as_deref(), Some("audit-listener"));
}

#[tokio::test]
async fn listener_start_creates_audit_entry() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = listener_start_message("online", "");
    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.listener_start".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for listener start");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].result_status, AuditResultStatus::Success,);
}

#[tokio::test]
async fn listener_start_failure_creates_audit_entry_with_failure_status() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = listener_start_message("error", "bind failed");
    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start (error) should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.listener_start".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].result_status, AuditResultStatus::Failure,);
}

#[tokio::test]
async fn agent_instance_register_creates_audit_entry() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": { "AgentID": "ABCD1234", "MagicValue": "DEADBEEF" },
            "RegisterInfo": {
                "Hostname": "HOST",
                "Username": "user",
                "DomainName": "DOMAIN",
                "ExternalIP": "10.0.0.1",
                "InternalIP": "192.168.1.1",
                "ProcessName": "svc.exe",
                "ProcessPID": 100,
                "ProcessArch": "x64",
                "OSVersion": "Windows 10",
                "OSArch": "x64",
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("agent registration should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.agent_register".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for agent instance register");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].target_kind, "agent");
    assert_eq!(page.items[0].agent_id.as_deref(), Some("ABCD1234"));
}
