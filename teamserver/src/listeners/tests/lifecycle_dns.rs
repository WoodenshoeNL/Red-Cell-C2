use super::super::listener_config_from_operator;
use super::*;
use red_cell_common::DnsListenerConfig;

#[tokio::test]
async fn create_accepts_dns_listener_config() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let summary =
        manager.create(dns_listener_config("dns-managed", 5300, "c2.example.com")).await?;

    assert_eq!(summary.name, "dns-managed");
    assert_eq!(summary.protocol, ListenerProtocol::Dns);
    assert_eq!(summary.state.status, ListenerStatus::Created);
    assert_eq!(summary.config, dns_listener_config("dns-managed", 5300, "c2.example.com"));

    Ok(())
}

#[tokio::test]
async fn update_accepts_dns_listener_config() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let port = free_udp_port();
    manager.create(dns_listener_config("dns-update", port, "c2.example.com")).await?;
    let updated_port = free_udp_port();

    let summary =
        manager.update(dns_listener_config("dns-update", updated_port, "ops.example.com")).await?;

    assert_eq!(summary.state.status, ListenerStatus::Stopped);
    assert_eq!(summary.config, dns_listener_config("dns-update", updated_port, "ops.example.com"));

    Ok(())
}

#[tokio::test]
async fn start_persisted_dns_listener_uses_dns_runtime() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let repository = manager.repository();
    let port = free_udp_port();
    repository.create(&dns_listener_config("dns-runtime", port, "c2.example.com")).await?;

    let summary = manager.start("dns-runtime").await?;

    assert_eq!(summary.state.status, ListenerStatus::Running);
    assert!(manager.active_handles.read().await.contains_key("dns-runtime"));

    manager.stop("dns-runtime").await?;
    let summary = manager.summary("dns-runtime").await?;

    assert_eq!(summary.state.status, ListenerStatus::Stopped);
    assert!(!manager.active_handles.read().await.contains_key("dns-runtime"));

    Ok(())
}

#[tokio::test]
async fn restore_running_restarts_dns_listener() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let repository = manager.repository();
    let port = free_udp_port();
    repository.create(&dns_listener_config("dns-restore", port, "c2.example.com")).await?;
    repository.set_state("dns-restore", ListenerStatus::Running, None).await?;

    manager.restore_running().await?;
    let summary = manager.summary("dns-restore").await?;

    assert_eq!(summary.state.status, ListenerStatus::Running);
    assert!(manager.active_handles.read().await.contains_key("dns-restore"));

    manager.stop("dns-restore").await?;

    Ok(())
}

// ── to_operator_info isolated field assertions for DNS ───────────────────

#[test]
fn dns_to_operator_info_includes_domain_and_record_types() {
    let summary = ListenerSummary {
        name: "dns-edge".to_owned(),
        protocol: ListenerProtocol::Dns,
        state: PersistedListenerState { status: ListenerStatus::Running, last_error: None },
        config: ListenerConfig::from(DnsListenerConfig {
            name: "dns-edge".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.example".to_owned(),
            record_types: vec!["A".to_owned(), "TXT".to_owned()],
            kill_date: None,
            working_hours: None,
            suppress_opsec_warnings: true,
        }),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.name.as_deref(), Some("dns-edge"));
    assert_eq!(info.protocol.as_deref(), Some("Dns"));
    assert_eq!(info.status.as_deref(), Some("Online"));
    assert_eq!(info.extra.get("Domain").and_then(|v| v.as_str()), Some("c2.example"),);
    assert_eq!(info.extra.get("RecordTypes").and_then(|v| v.as_str()), Some("A,TXT"),);
    assert_eq!(info.extra.get("Host").and_then(|v| v.as_str()), Some("0.0.0.0"),);
    assert_eq!(info.extra.get("Port").and_then(|v| v.as_str()), Some("53"),);
    assert_eq!(info.extra.get("Info").and_then(|v| v.as_str()), Some("c2.example"),);
    assert_eq!(info.host_bind.as_deref(), Some("0.0.0.0"));
    assert_eq!(info.port_bind.as_deref(), Some("53"));
}

// ── listener_config_from_operator DNS tests ──────────────────────────────

#[test]
fn listener_config_from_operator_parses_dns() -> Result<(), ListenerManagerError> {
    let mut info = ListenerInfo {
        name: Some("dns-test".to_owned()),
        protocol: Some("Dns".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        port_bind: Some("5353".to_owned()),
        ..ListenerInfo::default()
    };
    info.extra.insert("Domain".to_owned(), serde_json::Value::String("c2.example".to_owned()));
    info.extra.insert("RecordTypes".to_owned(), serde_json::Value::String("A,TXT".to_owned()));

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Dns(dns) => {
            assert_eq!(dns.name, "dns-test");
            assert_eq!(dns.host_bind, "0.0.0.0");
            assert_eq!(dns.port_bind, 5353);
            assert_eq!(dns.domain, "c2.example");
            assert_eq!(dns.record_types, vec!["A", "TXT"]);
        }
        other => panic!("expected Dns config, got {other:?}"),
    }

    Ok(())
}

#[test]
fn listener_config_from_operator_dns_defaults_host_bind() -> Result<(), ListenerManagerError> {
    let mut info = ListenerInfo {
        name: Some("dns-default".to_owned()),
        protocol: Some("Dns".to_owned()),
        host_bind: None,
        port_bind: Some("53".to_owned()),
        ..ListenerInfo::default()
    };
    info.extra.insert("Domain".to_owned(), serde_json::Value::String("c2.test".to_owned()));

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Dns(dns) => {
            assert_eq!(dns.host_bind, "0.0.0.0", "DNS should default host_bind to 0.0.0.0");
        }
        other => panic!("expected Dns config, got {other:?}"),
    }

    Ok(())
}

#[test]
fn listener_config_from_operator_rejects_dns_without_domain() {
    let info = ListenerInfo {
        name: Some("dns-no-domain".to_owned()),
        protocol: Some("Dns".to_owned()),
        port_bind: Some("53".to_owned()),
        ..ListenerInfo::default()
    };

    let error = listener_config_from_operator(&info).expect_err("missing Domain should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}
