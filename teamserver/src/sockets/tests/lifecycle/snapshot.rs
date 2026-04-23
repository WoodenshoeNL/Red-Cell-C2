use super::super::test_manager;

#[tokio::test]
async fn agent_socket_snapshot_empty_for_unknown_agent() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");

    let snap = manager.agent_socket_snapshot(0xDEAD_BEEF).await;
    assert!(snap.port_fwds.is_empty(), "unknown agent must have no port fwds");
    assert!(snap.socks_svr.is_empty(), "unknown agent must have no SOCKS servers");
    assert!(snap.socks_cli.is_empty(), "unknown agent must have no SOCKS clients");
}

#[tokio::test]
async fn agent_socket_snapshot_includes_port_fwd() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0x1234_5678_u32;

    manager.add_port_fwd(agent_id, 1, "127.0.0.1:8080 -> 10.0.0.1:80".to_owned()).await;
    manager.add_port_fwd(agent_id, 2, "127.0.0.1:9090 -> 10.0.0.2:443".to_owned()).await;

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert_eq!(snap.port_fwds.len(), 2, "snapshot must include 2 port forwards");
    assert!(
        snap.port_fwds.contains(&"127.0.0.1:8080 -> 10.0.0.1:80".to_owned()),
        "snapshot must contain first port fwd"
    );
}

#[tokio::test]
async fn remove_port_fwd_removes_entry_from_snapshot() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0x1234_5678_u32;

    manager.add_port_fwd(agent_id, 1, "127.0.0.1:8080 -> 10.0.0.1:80".to_owned()).await;
    manager.add_port_fwd(agent_id, 2, "127.0.0.1:9090 -> 10.0.0.2:443".to_owned()).await;
    manager.remove_port_fwd(agent_id, 1).await;

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert_eq!(snap.port_fwds.len(), 1, "one port fwd must remain after removal");
    assert!(
        !snap.port_fwds.contains(&"127.0.0.1:8080 -> 10.0.0.1:80".to_owned()),
        "removed port fwd must not appear in snapshot"
    );
    assert!(
        snap.port_fwds.contains(&"127.0.0.1:9090 -> 10.0.0.2:443".to_owned()),
        "remaining port fwd must appear in snapshot"
    );
}

#[tokio::test]
async fn clear_port_fwds_empties_snapshot() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0x1234_5678_u32;

    manager.add_port_fwd(agent_id, 1, "127.0.0.1:8080 -> 10.0.0.1:80".to_owned()).await;
    manager.add_port_fwd(agent_id, 2, "127.0.0.1:9090 -> 10.0.0.2:443".to_owned()).await;
    manager.clear_port_fwds(agent_id).await;

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert!(snap.port_fwds.is_empty(), "all port fwds must be gone after clear");
}

#[tokio::test]
async fn agent_socket_snapshot_socks_svr_reflects_active_listeners() {
    let (_db, _registry, manager) = test_manager().await.expect("manager");
    let agent_id = 0xABCD_1234_u32;

    let _result = manager.add_socks_server(agent_id, "0").await.expect("started socks server");

    let snap = manager.agent_socket_snapshot(agent_id).await;
    assert_eq!(snap.socks_svr.len(), 1, "snapshot must include 1 SOCKS server");
    assert!(
        snap.socks_svr[0].starts_with("127.0.0.1:"),
        "socks_svr entry must be a 127.0.0.1 bind address"
    );
    assert!(snap.socks_cli.is_empty(), "no clients connected yet");
}
