use red_cell_common::{
    AgentEncryptionInfo, AgentRecord, CommonError, DnsListenerConfig, HttpListenerConfig,
    HttpListenerProxyConfig, HttpListenerResponseConfig, ListenerConfig, ListenerProtocol,
    ListenerTlsConfig, OperatorInfo, SmbListenerConfig,
};
use serde_json::json;
use zeroize::Zeroizing;

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
            password: Some(Zeroizing::new("secret".to_string())),
        }),
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
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
        other => panic!("expected unsupported listener protocol, got {other:?}"),
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
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    };

    let listener = uses_public_api(config);

    assert_eq!(listener.protocol(), ListenerProtocol::Http);
    assert_eq!(listener.name(), "edge-compile");
}

#[test]
fn crate_root_exports_round_trip_dns_and_smb_listener_configs()
-> Result<(), Box<dyn std::error::Error>> {
    let smb = SmbListenerConfig {
        name: "pivot".to_string(),
        pipe_name: r"\\.\pipe\red-cell".to_string(),
        kill_date: Some("2026-04-01 00:00:00".to_string()),
        working_hours: Some("09:00-17:00".to_string()),
    };
    let dns = DnsListenerConfig {
        name: "beacon-dns".to_string(),
        host_bind: "0.0.0.0".to_string(),
        port_bind: 53,
        domain: "c2.example.com".to_string(),
        record_types: vec!["TXT".to_string(), "A".to_string()],
        kill_date: Some("2026-04-01 00:00:00".to_string()),
        working_hours: Some("09:00-17:00".to_string()),
    };

    let smb_listener = ListenerConfig::from(smb.clone());
    let dns_listener = ListenerConfig::from(dns.clone());

    assert_eq!(
        serde_json::from_value::<ListenerConfig>(serde_json::to_value(&smb_listener)?)?,
        smb_listener
    );
    assert_eq!(
        serde_json::from_value::<ListenerConfig>(serde_json::to_value(&dns_listener)?)?,
        dns_listener
    );
    assert_eq!(smb_listener.protocol(), ListenerProtocol::Smb);
    assert_eq!(dns_listener.protocol(), ListenerProtocol::Dns);
    assert_eq!(smb_listener.name(), smb.name);
    assert_eq!(dns_listener.name(), dns.name);

    Ok(())
}

#[test]
fn crate_root_exports_deserialize_agent_record_and_operator_info()
-> Result<(), Box<dyn std::error::Error>> {
    let record: AgentRecord = serde_json::from_value(json!({
        "AgentID": "ABCD1234",
        "Active": true,
        "Reason": "checkin",
        "Note": "external-api-smoke",
        "Encryption": {
            "AESKey": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
            "AESIv": "u7u7u7u7u7u7u7u7u7u7uw=="
        },
        "Hostname": "wkstn-1",
        "Username": "operator",
        "DomainName": "LAB",
        "ExternalIP": "203.0.113.10",
        "InternalIP": "10.0.0.10",
        "ProcessName": "explorer.exe",
        "ProcessPath": "C:\\Windows\\explorer.exe",
        "BaseAddress": 1,
        "ProcessPID": 1234,
        "ProcessTID": 5678,
        "ProcessPPID": 4321,
        "ProcessArch": "x64",
        "Elevated": false,
        "OSVersion": "Windows 11",
        "OSBuild": 22631,
        "OSArch": "x64",
        "SleepDelay": 5,
        "SleepJitter": 10,
        "KillDate": null,
        "WorkingHours": null,
        "FirstCallIn": "09/03/2026 19:04:00",
        "LastCallIn": "09/03/2026 19:05:00"
    }))?;
    let operator: OperatorInfo = serde_json::from_value(json!({
        "User": "michel",
        "PasswordHash": "abc123",
        "Role": "admin",
        "Online": true,
        "LastSeen": "09/03/2026 19:05:00"
    }))?;

    assert_eq!(record.name_id(), "ABCD1234");
    assert_eq!(*record.encryption.aes_key, vec![0xAA; 32]);
    assert_eq!(*record.encryption.aes_iv, vec![0xBB; 16]);
    assert_eq!(operator.username, "michel");
    assert_eq!(operator.role.as_deref(), Some("admin"));
    assert!(operator.online);

    Ok(())
}

#[test]
fn crate_root_exports_round_trip_agent_encryption_info() -> Result<(), Box<dyn std::error::Error>> {
    let original = AgentEncryptionInfo {
        aes_key: Zeroizing::new(vec![0x11; 32]),
        aes_iv: Zeroizing::new(vec![0x22; 16]),
    };

    let encoded = serde_json::to_value(&original)?;
    let decoded: AgentEncryptionInfo = serde_json::from_value(encoded)?;

    assert_eq!(decoded, original);

    Ok(())
}
