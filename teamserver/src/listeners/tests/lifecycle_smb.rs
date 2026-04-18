use super::super::listener_config_from_operator;
use super::*;
use red_cell_common::DnsListenerConfig;

#[test]
fn smb_and_dns_listener_operator_round_trip_preserves_profile_timing()
-> Result<(), ListenerManagerError> {
    let smb = ListenerConfig::from(SmbListenerConfig {
        name: "pivot".to_owned(),
        pipe_name: r"pivot-01".to_owned(),
        kill_date: Some("1773086400".to_owned()),
        working_hours: Some("08:00-17:00".to_owned()),
    });
    let dns = ListenerConfig::from(DnsListenerConfig {
        name: "dns-edge".to_owned(),
        host_bind: "0.0.0.0".to_owned(),
        port_bind: 53,
        domain: "c2.example".to_owned(),
        record_types: vec!["A".to_owned(), "TXT".to_owned()],
        kill_date: Some("1773086400".to_owned()),
        working_hours: Some("08:00-17:00".to_owned()),
    });

    for config in [smb, dns] {
        let summary = ListenerSummary {
            name: config.name().to_owned(),
            protocol: config.protocol(),
            state: PersistedListenerState { status: ListenerStatus::Stopped, last_error: None },
            config: config.clone(),
        };

        let info = summary.to_operator_info();
        let round_tripped = listener_config_from_operator(&info)?;
        assert_eq!(round_tripped, config);
    }

    Ok(())
}

#[test]
fn operator_payload_maps_to_smb_listener_config() -> Result<(), ListenerManagerError> {
    let mut info = ListenerInfo {
        name: Some("pivot".to_owned()),
        protocol: Some("SMB".to_owned()),
        ..ListenerInfo::default()
    };
    info.extra.insert("PipeName".to_owned(), serde_json::json!(r"pivot-01"));

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Smb(config) => {
            assert_eq!(config.name, "pivot");
            assert_eq!(config.pipe_name, "pivot-01");
        }
        other => panic!("unexpected config: {other:?}"),
    }

    Ok(())
}

// ── to_operator_info isolated field assertions for SMB ───────────────────

#[test]
fn smb_to_operator_info_includes_pipe_name_and_protocol() {
    let summary = ListenerSummary {
        name: "pivot".to_owned(),
        protocol: ListenerProtocol::Smb,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: smb_listener("pivot", "pivot-pipe"),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.name.as_deref(), Some("pivot"));
    assert_eq!(info.protocol.as_deref(), Some("Smb"));
    assert_eq!(info.status.as_deref(), Some("Offline"));
    assert_eq!(info.extra.get("PipeName").and_then(|v| v.as_str()), Some("pivot-pipe"),);
    assert_eq!(info.extra.get("Info").and_then(|v| v.as_str()), Some("pivot-pipe"),);
    // SMB has no real host/port — should be empty strings.
    assert_eq!(info.extra.get("Host").and_then(|v| v.as_str()), Some(""));
    assert_eq!(info.extra.get("Port").and_then(|v| v.as_str()), Some(""));
}

#[test]
fn smb_to_operator_info_with_last_error() {
    let summary = ListenerSummary {
        name: "smb-err".to_owned(),
        protocol: ListenerProtocol::Smb,
        state: PersistedListenerState {
            status: ListenerStatus::Error,
            last_error: Some("pipe busy".to_owned()),
        },
        config: smb_listener("smb-err", "pipe1"),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.status.as_deref(), Some("Offline"));
    assert_eq!(info.extra.get("Error").and_then(|v| v.as_str()), Some("pipe busy"),);
}
