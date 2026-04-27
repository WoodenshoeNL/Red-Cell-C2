use super::*;

/// `disabled_for_tests` uses empty `DemonConfig` defaults, so the merge step does
/// not fill `Sleep` / `Jitter`.  Phantom and Specter builds run `demon_config_for_rust_agent_build`
/// before the source-tree check; the request must include these keys or the build
/// fails with `InvalidRequest` first.
const MIN_RUST_AGENT_BUILD_CONFIG: &str = r#"{"Sleep":"5","Jitter":"0"}"#;

#[tokio::test]
async fn build_payload_archon_rejects_missing_source_tree() -> Result<(), Box<dyn std::error::Error>>
{
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Archon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Exe".to_owned(),
        config: r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#.to_owned(),
    };
    let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["listener.local".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 443,
        port_conn: Some(443),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: Vec::new(),
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("missing archon source tree should be rejected");
    assert!(
        matches!(error, PayloadBuildError::ToolchainUnavailable { .. }),
        "expected ToolchainUnavailable, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_phantom_rejects_missing_source_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Phantom".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Linux ELF".to_owned(),
        config: MIN_RUST_AGENT_BUILD_CONFIG.to_owned(),
    };
    let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["listener.local".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 443,
        port_conn: Some(443),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: Vec::new(),
        host_header: None,
        secure: true,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("missing phantom source tree should be rejected");
    assert!(
        matches!(error, PayloadBuildError::ToolchainUnavailable { .. }),
        "expected ToolchainUnavailable, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_specter_rejects_missing_source_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Specter".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Exe".to_owned(),
        config: MIN_RUST_AGENT_BUILD_CONFIG.to_owned(),
    };
    let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["listener.local".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 443,
        port_conn: Some(443),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: Vec::new(),
        host_header: None,
        secure: true,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("missing specter source tree should be rejected");
    assert!(
        matches!(error, PayloadBuildError::ToolchainUnavailable { .. }),
        "expected ToolchainUnavailable, got {error:?}"
    );
    Ok(())
}
