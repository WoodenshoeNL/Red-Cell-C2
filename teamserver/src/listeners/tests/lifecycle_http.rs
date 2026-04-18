use super::super::{
    listener_config_from_operator, operator_requests_start, profile_listener_configs,
};
use super::*;
use red_cell_common::config::Profile;
use red_cell_common::{HttpListenerProxyConfig, HttpListenerResponseConfig, ListenerTlsConfig};

#[test]
fn operator_payload_maps_to_http_listener_config() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("alpha".to_owned()),
        protocol: Some("Https".to_owned()),
        status: Some("Online".to_owned()),
        hosts: Some("a.example, b.example".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("8443".to_owned()),
        port_conn: Some("443".to_owned()),
        headers: Some("X-Test: true".to_owned()),
        uris: Some("/one, /two".to_owned()),
        user_agent: Some("Mozilla/5.0".to_owned()),
        secure: Some("true".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;

    assert!(operator_requests_start(&info));
    match config {
        ListenerConfig::Http(config) => {
            assert_eq!(config.name, "alpha");
            assert!(config.secure);
            assert_eq!(config.hosts, vec!["a.example".to_owned(), "b.example".to_owned()]);
        }
        other => panic!("unexpected config: {other:?}"),
    }

    Ok(())
}

#[test]
fn http_listener_operator_round_trip_preserves_advanced_settings()
-> Result<(), ListenerManagerError> {
    let original = ListenerConfig::from(HttpListenerConfig {
        name: "edge".to_owned(),
        kill_date: Some("1773086400".to_owned()),
        working_hours: Some("08:00-17:00".to_owned()),
        hosts: vec!["a.example".to_owned(), "b.example".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: Some("POST".to_owned()),
        behind_redirector: true,
        trusted_proxy_peers: vec!["127.0.0.1/32".to_owned(), "10.0.0.0/8".to_owned()],
        user_agent: Some("Mozilla/5.0".to_owned()),
        headers: vec!["X-Test: true".to_owned()],
        uris: vec!["/one".to_owned(), "/two".to_owned()],
        host_header: Some("team.example".to_owned()),
        secure: true,
        cert: Some(ListenerTlsConfig {
            cert: "/tmp/server.crt".to_owned(),
            key: "/tmp/server.key".to_owned(),
        }),
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: nginx".to_owned()],
            body: Some("{\"status\":\"ok\"}".to_owned()),
        }),
        proxy: Some(HttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("http".to_owned()),
            host: "127.0.0.1".to_owned(),
            port: 8080,
            username: Some("user".to_owned()),
            password: Some(Zeroizing::new("pass".to_owned())),
        }),
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    });
    let summary = ListenerSummary {
        name: "edge".to_owned(),
        protocol: original.protocol(),
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: original.clone(),
    };

    let info = summary.to_operator_info_with_secrets();
    let round_tripped = listener_config_from_operator(&info)?;

    assert_eq!(round_tripped, original);
    Ok(())
}

#[test]
fn operator_payload_redacts_http_proxy_password() {
    let summary = ListenerSummary {
        name: "edge".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: ListenerConfig::from(HttpListenerConfig {
            name: "edge".to_owned(),
            hosts: vec!["edge.example".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8443,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: true,
            cert: None,
            kill_date: None,
            working_hours: None,
            response: None,
            proxy: Some(HttpListenerProxyConfig {
                enabled: true,
                proxy_type: Some("http".to_owned()),
                host: "127.0.0.1".to_owned(),
                port: 8080,
                username: Some("user".to_owned()),
                password: Some(Zeroizing::new("pass".to_owned())),
            }),
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        }),
    };

    let info = summary.to_operator_info();

    assert_eq!(info.proxy_enabled.as_deref(), Some("true"));
    assert_eq!(info.proxy_username.as_deref(), Some("user"));
    assert_eq!(info.proxy_password, None);
}

#[test]
fn profile_listener_configs_preserve_http_host_header() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "neo" {
            Password = "password1234"
          }
        }

        Listeners {
          Http {
            Name = "edge"
            Hosts = ["listener.local"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = 8080
            HostHeader = "front.example"
          }
        }

        Demon {
          TrustXForwardedFor = true
          TrustedProxyPeers = ["127.0.0.1/32"]
        }
        "#,
    )
    .expect("profile should parse");

    let listeners = profile_listener_configs(&profile).expect("configs should be valid");

    assert_eq!(listeners.len(), 1);
    let ListenerConfig::Http(config) = &listeners[0] else {
        panic!("expected http listener");
    };
    assert_eq!(config.host_header.as_deref(), Some("front.example"));
    assert!(config.behind_redirector);
    assert_eq!(config.trusted_proxy_peers, vec!["127.0.0.1/32".to_owned()]);
}

// ── operator_requests_start tests ────────────────────────────────────────

#[test]
fn operator_requests_start_accepts_online_and_start_case_insensitive() {
    for status in ["Online", "ONLINE", "online", "start", "Start", "START"] {
        let info = ListenerInfo { status: Some(status.to_owned()), ..ListenerInfo::default() };
        assert!(operator_requests_start(&info), "expected true for status {status:?}",);
    }
}

#[test]
fn operator_requests_start_rejects_stop_and_unknown_statuses() {
    for status in ["Offline", "stop", "stopped", "running", "unknown", ""] {
        let info = ListenerInfo { status: Some(status.to_owned()), ..ListenerInfo::default() };
        assert!(!operator_requests_start(&info), "expected false for status {status:?}",);
    }
}

#[test]
fn operator_requests_start_returns_false_when_status_absent() {
    let info = ListenerInfo { status: None, ..ListenerInfo::default() };
    assert!(!operator_requests_start(&info));
}

// ── listener_config_from_operator validation tests (HTTP) ────────────────

#[test]
fn listener_config_from_operator_rejects_http_without_name() {
    let info = ListenerInfo { name: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing Name should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_protocol() {
    let info = ListenerInfo { protocol: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing Protocol should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_unrecognised_protocol() {
    let info = ListenerInfo { protocol: Some("Telnet".to_owned()), ..valid_http_listener_info() };
    let error =
        listener_config_from_operator(&info).expect_err("unrecognised protocol should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_host_bind() {
    let info = ListenerInfo { host_bind: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing HostBind should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_host_rotation() {
    let info = ListenerInfo { host_rotation: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing HostRotation should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_port_bind() {
    let info = ListenerInfo { port_bind: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing PortBind should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_with_non_numeric_port_bind() {
    let info =
        ListenerInfo { port_bind: Some("not-a-number".to_owned()), ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("non-numeric PortBind should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

// ── http to_operator_info tests ──────────────────────────────────────────

#[test]
fn http_to_operator_info_running_status_maps_to_online() {
    let summary = ListenerSummary {
        name: "http-run".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Running, last_error: None },
        config: http_listener("http-run", 8080),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.status.as_deref(), Some("Online"));
}

#[test]
fn http_to_operator_info_stopped_status_maps_to_offline() {
    let summary = ListenerSummary {
        name: "http-stop".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Stopped, last_error: None },
        config: http_listener("http-stop", 8080),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.status.as_deref(), Some("Offline"));
}

#[test]
fn http_to_operator_info_without_proxy_has_disabled_proxy() {
    let summary = ListenerSummary {
        name: "no-proxy".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: http_listener("no-proxy", 8080),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.proxy_enabled.as_deref(), Some("false"));
    assert!(info.proxy_host.is_none());
    assert!(info.proxy_port.is_none());
    assert!(info.proxy_username.is_none());
    assert!(info.proxy_password.is_none());
}

// ── listener_config_from_operator port_conn tests ────────────────────────

#[test]
fn listener_config_from_operator_parses_optional_port_conn() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("port-conn-test".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("8443".to_owned()),
        port_conn: Some("443".to_owned()),
        secure: Some("false".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_conn, Some(443));
        }
        other => panic!("expected Http config, got {other:?}"),
    }

    Ok(())
}

#[test]
fn listener_config_from_operator_accepts_absent_port_conn() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("no-port-conn".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("8080".to_owned()),
        port_conn: None,
        secure: Some("false".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert!(http.port_conn.is_none());
        }
        other => panic!("expected Http config, got {other:?}"),
    }

    Ok(())
}

// ── ja3_randomize wiring tests ───────────────────────────────────────────

#[test]
fn listener_config_from_operator_wires_ja3_randomize_false() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("true".to_owned()),
        extra: [("Ja3Randomize".to_owned(), serde_json::Value::String("false".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.ja3_randomize, Some(false), "ja3_randomize should be Some(false)");
        }
        other => panic!("expected Http config, got {other:?}"),
    }
    Ok(())
}

/// `listener_config_from_operator` honours an explicit `Ja3Randomize = true`.
#[test]
fn listener_config_from_operator_wires_ja3_randomize_true() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("80".to_owned()),
        secure: Some("false".to_owned()),
        extra: [("Ja3Randomize".to_owned(), serde_json::Value::String("true".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.ja3_randomize, Some(true), "ja3_randomize should be Some(true)");
        }
        other => panic!("expected Http config, got {other:?}"),
    }
    Ok(())
}

/// When `Ja3Randomize` is absent from the operator message the field is `None`, which
/// lets the payload builder apply its default (enabled for HTTPS, disabled for HTTP).
#[test]
fn listener_config_from_operator_ja3_randomize_absent_yields_none()
-> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("true".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert!(http.ja3_randomize.is_none(), "absent Ja3Randomize should yield None");
        }
        other => panic!("expected Http config, got {other:?}"),
    }
    Ok(())
}

/// An invalid value for `Ja3Randomize` in the operator message must be rejected.
#[test]
fn listener_config_from_operator_rejects_invalid_ja3_randomize() {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("true".to_owned()),
        extra: [("Ja3Randomize".to_owned(), serde_json::Value::String("yes".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let err = listener_config_from_operator(&info).expect_err("invalid Ja3Randomize should fail");
    assert!(err.to_string().contains("Ja3Randomize"), "error should mention the field name: {err}");
}

/// `profile_listener_configs` wires `Ja3Randomize = false` from the HCL profile.
#[test]
fn profile_listener_configs_wires_ja3_randomize_false() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }
        Operators {
          user "neo" {
            Password = "password1234"
          }
        }
        Listeners {
          Http {
            Name         = "edge"
            Hosts        = ["listener.local"]
            HostBind     = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind     = 443
            Secure       = true
            Ja3Randomize = false
          }
        }
        Demon {
          TrustXForwardedFor = false
        }
        "#,
    )
    .expect("profile should parse");

    let listeners = profile_listener_configs(&profile).expect("configs should be valid");
    assert_eq!(listeners.len(), 1);
    let ListenerConfig::Http(config) = &listeners[0] else {
        panic!("expected http listener");
    };
    assert_eq!(config.ja3_randomize, Some(false));
}

/// When `Ja3Randomize` is omitted from the HCL profile the field is `None`.
#[test]
fn profile_listener_configs_ja3_randomize_absent_yields_none() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }
        Operators {
          user "neo" {
            Password = "password1234"
          }
        }
        Listeners {
          Http {
            Name         = "edge"
            Hosts        = ["listener.local"]
            HostBind     = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind     = 443
            Secure       = true
          }
        }
        Demon {
          TrustXForwardedFor = false
        }
        "#,
    )
    .expect("profile should parse");

    let listeners = profile_listener_configs(&profile).expect("configs should be valid");
    assert_eq!(listeners.len(), 1);
    let ListenerConfig::Http(config) = &listeners[0] else {
        panic!("expected http listener");
    };
    assert!(config.ja3_randomize.is_none());
}
