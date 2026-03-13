use red_cell_common::{
    CommonError, HttpListenerConfig, HttpListenerProxyConfig, HttpListenerResponseConfig,
    ListenerConfig, ListenerProtocol, ListenerTlsConfig,
};

#[test]
fn crate_root_exports_round_trip_listener_config() -> Result<(), Box<dyn std::error::Error>> {
    let original = ListenerConfig::from(HttpListenerConfig {
        name: "edge".to_string(),
        kill_date: Some("2026-03-31 23:59:59".to_string()),
        working_hours: Some("08:00-17:00".to_string()),
        hosts: vec!["c2.example".to_string(), "cdn.example".to_string()],
        host_bind: "0.0.0.0".to_string(),
        host_rotation: "round-robin".to_string(),
        port_bind: 8443,
        port_conn: Some(443),
        method: Some("POST".to_string()),
        behind_redirector: true,
        trusted_proxy_peers: vec!["127.0.0.1/32".to_string()],
        user_agent: Some("Mozilla/5.0".to_string()),
        headers: vec!["X-Test: 1".to_string()],
        uris: vec!["/index".to_string(), "/health".to_string()],
        host_header: Some("front.example".to_string()),
        secure: true,
        cert: Some(ListenerTlsConfig {
            cert: "server.crt".to_string(),
            key: "server.key".to_string(),
        }),
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: nginx".to_string()],
            body: Some("{\"status\":\"ok\"}".to_string()),
        }),
        proxy: Some(HttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("http".to_string()),
            host: "127.0.0.1".to_string(),
            port: 8080,
            username: Some("operator".to_string()),
            password: Some("secret".to_string()),
        }),
    });

    let encoded = serde_json::to_value(&original)?;
    let decoded: ListenerConfig = serde_json::from_value(encoded)?;

    assert_eq!(decoded, original);
    assert_eq!(decoded.protocol(), ListenerProtocol::Http);
    assert_eq!(decoded.name(), "edge");

    Ok(())
}

#[test]
fn crate_root_exports_surface_common_error_variants() {
    let error = ListenerProtocol::try_from_str("quic").expect_err("unknown protocol should fail");

    assert_eq!(error, CommonError::UnsupportedListenerProtocol { protocol: "quic".to_string() });

    match error {
        CommonError::UnsupportedListenerProtocol { protocol } => assert_eq!(protocol, "quic"),
        CommonError::InvalidAgentId { .. } => panic!("expected unsupported listener protocol"),
    }
}

#[test]
fn crate_root_exports_compile_without_private_module_paths() {
    fn uses_public_api(config: HttpListenerConfig) -> ListenerConfig {
        ListenerConfig::from(config)
    }

    let config = HttpListenerConfig {
        name: "edge-compile".to_string(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["c2.example".to_string()],
        host_bind: "127.0.0.1".to_string(),
        host_rotation: "random".to_string(),
        port_bind: 443,
        port_conn: None,
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_string()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
    };

    let listener = uses_public_api(config);

    assert_eq!(listener.protocol(), ListenerProtocol::Http);
    assert_eq!(listener.name(), "edge-compile");
}
