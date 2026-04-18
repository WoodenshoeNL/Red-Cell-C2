use super::*;

#[test]
fn service_bridge_creates_with_config() {
    let config =
        ServiceConfig { endpoint: "svc-endpoint".to_owned(), password: "secret".to_owned() };
    let bridge = ServiceBridge::new(config).expect("service bridge");
    assert_eq!(bridge.endpoint(), "svc-endpoint");
}

#[tokio::test]
async fn service_bridge_tracks_clients() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let id = Uuid::new_v4();
    bridge.add_client(id).await;
    assert_eq!(bridge.connected_client_count().await, 1);

    bridge.remove_client(id, &[], &[]).await;
    assert_eq!(bridge.connected_client_count().await, 0);
}

#[tokio::test]
async fn service_bridge_registers_agent() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    bridge
        .register_agent("custom-agent".to_owned())
        .await
        .expect("first registration should succeed");

    assert!(bridge.agent_exists("custom-agent").await);

    let err = bridge.register_agent("custom-agent".to_owned()).await;
    assert!(err.is_err(), "duplicate registration should fail");
}

#[tokio::test]
async fn service_bridge_registers_listener() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    bridge.register_listener("my-listener".to_owned()).await;
    // Registering same name again is idempotent.
    bridge.register_listener("my-listener".to_owned()).await;

    let inner = bridge.inner.read().await;
    assert_eq!(inner.registered_listeners.len(), 1);
}

#[tokio::test]
async fn client_cleanup_removes_agents_and_listeners() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let client_id = Uuid::new_v4();
    bridge.add_client(client_id).await;
    bridge.register_agent("agent-a".to_owned()).await.ok();
    bridge.register_listener("listener-b".to_owned()).await;

    bridge.remove_client(client_id, &["agent-a".to_owned()], &["listener-b".to_owned()]).await;

    assert_eq!(bridge.connected_client_count().await, 0);
    assert!(!bridge.agent_exists("agent-a").await);
    let inner = bridge.inner.read().await;
    assert!(inner.registered_listeners.is_empty());
}
