use super::super::*;

#[tokio::test]
async fn build_payload_rejects_unsupported_listener_protocol()
-> Result<(), Box<dyn std::error::Error>> {
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "dns".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Exe".to_owned(),
        config: r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#.to_owned(),
    };
    let listener = ListenerConfig::Dns(red_cell_common::DnsListenerConfig {
        name: "dns".to_owned(),
        host_bind: "0.0.0.0".to_owned(),
        port_bind: 53,
        domain: "c2.local".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
        suppress_opsec_warnings: true,
    });

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("invalid request should be rejected");
    assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
    Ok(())
}

#[tokio::test]
async fn build_payload_rejects_unsupported_agent_type() -> Result<(), Box<dyn std::error::Error>> {
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Shellcode".to_owned(),
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
        .expect_err("invalid request should be rejected");
    match error {
        PayloadBuildError::InvalidRequest { message } => {
            assert!(message.contains("unsupported agent type `Shellcode`"));
        }
        other => panic!("expected invalid request, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn build_payload_rejects_unsupported_architecture() -> Result<(), Box<dyn std::error::Error>>
{
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "arm64".to_owned(),
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
        .expect_err("invalid request should be rejected");
    match error {
        PayloadBuildError::InvalidRequest { message } => {
            assert!(message.contains("unsupported architecture `arm64`"));
        }
        other => panic!("expected invalid request, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn build_payload_rejects_unsupported_output_format() -> Result<(), Box<dyn std::error::Error>>
{
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Linux Elf".to_owned(),
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
        .expect_err("invalid request should be rejected");
    match error {
        PayloadBuildError::InvalidRequest { message } => {
            assert!(message.contains("unsupported output format `Linux Elf`"));
        }
        other => panic!("expected invalid request, got {other:?}"),
    }
    Ok(())
}
