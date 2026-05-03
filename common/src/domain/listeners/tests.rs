use serde_json::json;
use zeroize::Zeroizing;

use super::*;
use crate::error::CommonError;

#[test]
fn listener_protocol_accepts_havoc_labels() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(ListenerProtocol::try_from_str("Http")?, ListenerProtocol::Http);
    assert_eq!(ListenerProtocol::try_from_str("Https")?, ListenerProtocol::Http);
    assert_eq!(ListenerProtocol::try_from_str("SMB")?, ListenerProtocol::Smb);
    Ok(())
}

#[test]
fn listener_protocol_accepts_dns() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(ListenerProtocol::try_from_str("dns")?, ListenerProtocol::Dns);
    assert_eq!(ListenerProtocol::try_from_str("DNS")?, ListenerProtocol::Dns);
    Ok(())
}

#[test]
fn listener_protocol_as_str_returns_canonical_labels() {
    assert_eq!(ListenerProtocol::Http.as_str(), "http");
    assert_eq!(ListenerProtocol::Smb.as_str(), "smb");
    assert_eq!(ListenerProtocol::Dns.as_str(), "dns");
}

#[test]
fn listener_protocol_display_uses_canonical_label() {
    assert_eq!(ListenerProtocol::Http.to_string(), "http");
}

#[test]
fn listener_protocol_rejects_unknown_labels() {
    let error = ListenerProtocol::try_from_str("quic").expect_err("unknown protocol should fail");
    assert_eq!(error, CommonError::UnsupportedListenerProtocol { protocol: "quic".to_string() });
}

#[test]
fn listener_protocol_accepts_external() {
    assert_eq!(
        ListenerProtocol::try_from_str("external").expect("external should be supported"),
        ListenerProtocol::External,
    );
    assert_eq!(ListenerProtocol::External.as_str(), "external");
    assert_eq!(ListenerProtocol::External.to_string(), "external");
}

#[test]
fn listener_config_reports_name_and_protocol() {
    let config = ListenerConfig::from(HttpListenerConfig {
        name: "edge".to_string(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["team.example".to_string()],
        host_bind: "0.0.0.0".to_string(),
        host_rotation: "round-robin".to_string(),
        port_bind: 443,
        port_conn: Some(443),
        method: Some("POST".to_string()),
        behind_redirector: true,
        trusted_proxy_peers: vec!["127.0.0.1/32".to_string()],
        user_agent: Some("Mozilla/5.0".to_string()),
        headers: vec!["X-Test: 1".to_string()],
        uris: vec!["/index".to_string()],
        host_header: Some("team.example".to_string()),
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
            username: Some("user".to_string()),
            password: Some(Zeroizing::new("pass".to_string())),
        }),
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: false,
        suppress_opsec_warnings: false,
    });

    assert_eq!(config.name(), "edge");
    assert_eq!(config.protocol(), ListenerProtocol::Http);
}

#[test]
fn proxy_password_round_trips_through_serde() -> Result<(), Box<dyn std::error::Error>> {
    let proxy = HttpListenerProxyConfig {
        enabled: true,
        proxy_type: Some("http".to_string()),
        host: "127.0.0.1".to_string(),
        port: 8080,
        username: Some("user".to_string()),
        password: Some(Zeroizing::new("secret".to_string())),
    };
    let json = serde_json::to_value(&proxy)?;
    assert_eq!(json["password"], "secret");
    let decoded: HttpListenerProxyConfig = serde_json::from_value(json)?;
    assert_eq!(decoded.password.as_ref().map(|s| s.as_str()), Some("secret"));
    Ok(())
}

#[test]
fn proxy_password_none_round_trips_through_serde() -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::json!({
        "enabled": false,
        "host": "proxy.local",
        "port": 3128
    });
    let decoded: HttpListenerProxyConfig = serde_json::from_value(json)?;
    assert!(decoded.password.is_none());
    Ok(())
}

#[test]
fn response_body_round_trips_with_http_listener_config() -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "protocol": "http",
        "config": {
            "name": "edge",
            "kill_date": null,
            "working_hours": null,
            "hosts": ["c2.local"],
            "host_bind": "127.0.0.1",
            "host_rotation": "round-robin",
            "port_bind": 8080,
            "port_conn": null,
            "method": "POST",
            "behind_redirector": false,
            "user_agent": null,
            "headers": [],
            "uris": ["/submit"],
            "host_header": null,
            "secure": false,
            "cert": null,
            "response": {
                "headers": ["Server: nginx"],
                "body": "hello"
            },
            "proxy": null
        }
    });

    let config: ListenerConfig = serde_json::from_value(payload.clone())?;
    let encoded = serde_json::to_value(&config)?;

    assert_eq!(encoded["protocol"], payload["protocol"]);
    assert_eq!(encoded["config"]["response"]["body"], payload["config"]["response"]["body"]);
    assert_eq!(encoded["config"]["response"]["headers"], payload["config"]["response"]["headers"]);
    Ok(())
}

#[test]
fn dns_listener_config_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let original = ListenerConfig::from(DnsListenerConfig {
        name: "dns-c2".to_string(),
        host_bind: "0.0.0.0".to_string(),
        port_bind: 53,
        domain: "c2.example.com".to_string(),
        record_types: vec!["TXT".to_string(), "A".to_string()],
        kill_date: Some("1798761599".to_string()),
        working_hours: Some("08:00-18:00".to_string()),
        suppress_opsec_warnings: false,
    });

    let encoded = serde_json::to_value(&original)?;
    let decoded: ListenerConfig = serde_json::from_value(encoded)?;
    assert_eq!(decoded, original);
    Ok(())
}

#[test]
fn external_listener_config_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let original = ListenerConfig::from(ExternalListenerConfig {
        name: "bridge".to_string(),
        endpoint: "/svc".to_string(),
    });

    let encoded = serde_json::to_value(&original)?;
    let decoded: ListenerConfig = serde_json::from_value(encoded)?;
    assert_eq!(decoded, original);
    Ok(())
}

#[test]
fn dns_listener_config_record_types_defaults_to_txt_when_absent()
-> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({
        "protocol": "dns",
        "config": {
            "name": "dns-c2",
            "host_bind": "0.0.0.0",
            "port_bind": 53,
            "domain": "c2.example.com"
        }
    });

    let config: ListenerConfig = serde_json::from_value(payload)?;
    let ListenerConfig::Dns(dns) = config else {
        panic!("expected Dns variant");
    };
    assert_eq!(dns.record_types, vec!["TXT".to_string()]);
    Ok(())
}

#[test]
fn port_bind_rejects_value_above_u16_max() {
    let payload = json!({
        "name": "edge",
        "kill_date": null,
        "working_hours": null,
        "hosts": [],
        "host_bind": "0.0.0.0",
        "host_rotation": "round-robin",
        "port_bind": 70000,
        "port_conn": null,
        "method": null,
        "behind_redirector": false,
        "user_agent": null,
        "headers": [],
        "uris": [],
        "host_header": null,
        "secure": false,
        "cert": null,
        "response": null,
        "proxy": null
    });

    let error = serde_json::from_value::<HttpListenerConfig>(payload)
        .expect_err("port_bind 70000 must be rejected");
    assert!(error.to_string().contains("does not fit in u16"), "unexpected error message: {error}");
}

#[test]
fn port_conn_rejects_string_value_above_u16_max() {
    let payload = json!({
        "name": "edge",
        "kill_date": null,
        "working_hours": null,
        "hosts": [],
        "host_bind": "0.0.0.0",
        "host_rotation": "round-robin",
        "port_bind": 443,
        "port_conn": "99999",
        "method": null,
        "behind_redirector": false,
        "user_agent": null,
        "headers": [],
        "uris": [],
        "host_header": null,
        "secure": false,
        "cert": null,
        "response": null,
        "proxy": null
    });

    let error = serde_json::from_value::<HttpListenerConfig>(payload)
        .expect_err("port_conn 99999 must be rejected");
    assert!(error.to_string().contains("does not fit in u16"), "unexpected error message: {error}");
}

#[test]
fn proxy_port_rejects_string_value_above_u16_max() {
    let payload = json!({
        "name": "edge",
        "kill_date": null,
        "working_hours": null,
        "hosts": [],
        "host_bind": "0.0.0.0",
        "host_rotation": "round-robin",
        "port_bind": 443,
        "port_conn": null,
        "method": null,
        "behind_redirector": false,
        "user_agent": null,
        "headers": [],
        "uris": [],
        "host_header": null,
        "secure": false,
        "cert": null,
        "response": null,
        "proxy": {
            "enabled": true,
            "host": "127.0.0.1",
            "port": "99999"
        }
    });

    let error = serde_json::from_value::<HttpListenerConfig>(payload)
        .expect_err("proxy port 99999 must be rejected");
    assert!(error.to_string().contains("does not fit in u16"), "unexpected error message: {error}");
}

/// Helper: builds a minimal valid `HttpListenerConfig` JSON, then applies overrides.
fn http_listener_json(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "name": "edge",
        "hosts": [],
        "host_bind": "0.0.0.0",
        "host_rotation": "round-robin",
        "port_bind": 443,
        "behind_redirector": false,
        "headers": [],
        "uris": [],
        "secure": false
    });
    if let (Some(base_map), Some(over_map)) = (base.as_object_mut(), overrides.as_object()) {
        for (k, v) in over_map {
            base_map.insert(k.clone(), v.clone());
        }
    }
    base
}

#[test]
fn port_bind_rejects_string_value_above_u16_max() {
    let payload = http_listener_json(json!({ "port_bind": "70000" }));
    let error = serde_json::from_value::<HttpListenerConfig>(payload)
        .expect_err("string port_bind \"70000\" must be rejected");
    assert!(error.to_string().contains("does not fit in u16"), "unexpected error message: {error}");
}

#[test]
fn port_bind_rejects_value_99999_above_u16_max() {
    let payload = http_listener_json(json!({ "port_bind": 99999 }));
    let error = serde_json::from_value::<HttpListenerConfig>(payload)
        .expect_err("port_bind 99999 must be rejected");
    assert!(error.to_string().contains("does not fit in u16"), "unexpected error message: {error}");
}

#[test]
fn port_bind_accepts_zero() {
    let payload = http_listener_json(json!({ "port_bind": 0 }));
    let config: HttpListenerConfig =
        serde_json::from_value(payload).expect("port_bind 0 must be accepted");
    assert_eq!(config.port_bind, 0);
}

#[test]
fn port_bind_accepts_string_zero() {
    let payload = http_listener_json(json!({ "port_bind": "0" }));
    let config: HttpListenerConfig =
        serde_json::from_value(payload).expect("string port_bind \"0\" must be accepted");
    assert_eq!(config.port_bind, 0);
}

#[test]
fn port_bind_trims_whitespace_from_string() {
    let payload = http_listener_json(json!({ "port_bind": " 443 " }));
    let config: HttpListenerConfig =
        serde_json::from_value(payload).expect("whitespace-padded port_bind must be accepted");
    assert_eq!(config.port_bind, 443);
}

// ── parse_kill_date_to_epoch tests ──────────────────────────────────────

#[test]
fn parse_kill_date_to_epoch_accepts_unix_timestamp() {
    assert_eq!(parse_kill_date_to_epoch("1773086400").expect("unwrap"), 1773086400);
}

#[test]
fn parse_kill_date_to_epoch_accepts_zero() {
    assert_eq!(parse_kill_date_to_epoch("0").expect("unwrap"), 0);
}

#[test]
fn parse_kill_date_to_epoch_accepts_negative() {
    assert_eq!(parse_kill_date_to_epoch("-1").expect("unwrap"), -1);
}

#[test]
fn parse_kill_date_to_epoch_accepts_human_readable_datetime() {
    // "2026-03-09 20:00:00" UTC
    assert_eq!(parse_kill_date_to_epoch("2026-03-09 20:00:00").expect("unwrap"), 1773086400);
}

#[test]
fn parse_kill_date_to_epoch_rejects_empty() {
    assert!(parse_kill_date_to_epoch("").is_err());
    assert!(parse_kill_date_to_epoch("   ").is_err());
}

#[test]
fn parse_kill_date_to_epoch_rejects_garbage() {
    let err = parse_kill_date_to_epoch("not-a-date");
    assert!(matches!(err, Err(CommonError::InvalidKillDate { .. })));
}

#[test]
fn parse_kill_date_to_epoch_rejects_wrong_datetime_format() {
    // Missing seconds
    assert!(parse_kill_date_to_epoch("2026-03-09 20:00").is_err());
    // ISO 8601 with T separator
    assert!(parse_kill_date_to_epoch("2026-03-09T20:00:00").is_err());
}

#[test]
fn listener_config_http_json_preserves_doh_fields() -> Result<(), Box<dyn std::error::Error>> {
    // Matches red-cell-cli `listener create --config-json` envelope + autotest scenario 20 shape.
    let j = r#"{"protocol":"http","config":{"name":"t","host_bind":"0.0.0.0","port_bind":19182,"host_rotation":"round-robin","secure":false,"hosts":["192.168.1.1"],"uris":["/"],"doh_domain":"c2.test.local","doh_provider":"cloudflare"}}"#;
    let c: ListenerConfig = serde_json::from_str(j)?;
    let ListenerConfig::Http(h) = c else {
        panic!("expected http listener");
    };
    assert_eq!(h.doh_domain.as_deref(), Some("c2.test.local"));
    assert_eq!(h.doh_provider.as_deref(), Some("cloudflare"));
    Ok(())
}

// ── validate_kill_date tests ────────────────────────────────────────────

#[test]
fn validate_kill_date_returns_none_for_absent() {
    assert_eq!(validate_kill_date(None).expect("unwrap"), None);
}

#[test]
fn validate_kill_date_returns_none_for_empty() {
    assert_eq!(validate_kill_date(Some("")).expect("unwrap"), None);
    assert_eq!(validate_kill_date(Some("   ")).expect("unwrap"), None);
}

#[test]
fn validate_kill_date_normalises_to_timestamp_string() {
    assert_eq!(
        validate_kill_date(Some("2026-03-09 20:00:00")).expect("unwrap"),
        Some("1773086400".to_string())
    );
    assert_eq!(
        validate_kill_date(Some("1773086400")).expect("unwrap"),
        Some("1773086400".to_string())
    );
}

#[test]
fn validate_kill_date_rejects_garbage() {
    assert!(validate_kill_date(Some("garbage")).is_err());
}
