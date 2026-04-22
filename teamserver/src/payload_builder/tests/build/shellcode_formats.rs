use super::*;

#[tokio::test]
async fn build_payload_raw_shellcode_rejects_x86() -> Result<(), Box<dyn std::error::Error>> {
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x86".to_owned(),
        format: "Windows Raw Shellcode".to_owned(),
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

    let err = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("x86 raw shellcode must be rejected");
    assert!(
        matches!(&err, PayloadBuildError::InvalidRequest { message }
            if message.contains("x64")),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_staged_shellcode_rejects_non_http() -> Result<(), Box<dyn std::error::Error>>
{
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "smb".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Shellcode Staged".to_owned(),
        config: "{}".to_owned(),
    };
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });

    let err = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("staged shellcode with SMB listener must be rejected");
    assert!(
        matches!(&err, PayloadBuildError::InvalidRequest { message }
            if message.contains("HTTP listener")),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_staged_shellcode_uses_stager_template()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager' > \"$1\"; break; fi; shift; done\necho gcc-stager-ok\n";
    let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Shellcode Staged".to_owned(),
        config: "{}".to_owned(),
    };

    let mut messages = Vec::new();
    let artifact = service
        .build_payload(&listener, &request, None, |m| messages.push(m.message.clone()))
        .await?;

    assert_eq!(artifact.bytes, b"stager");
    assert_eq!(artifact.file_name, "demon.x64.exe");
    assert_eq!(artifact.format, "Windows Shellcode Staged");
    assert!(
        messages.iter().any(|m| m.contains("gcc-stager-ok")),
        "expected gcc output in messages: {messages:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_raw_shellcode_prepends_dllldr_template()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'dll' > \"$1\"; break; fi; shift; done\necho gcc-raw-ok\n";
    let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Raw Shellcode".to_owned(),
        config: r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#.to_owned(),
    };

    let artifact = service.build_payload(&listener, &request, None, |_| {}).await?;

    assert_eq!(&artifact.bytes[..2], &[0x55, 0x48], "DllLdr header not prepended");
    assert_eq!(&artifact.bytes[2..], b"dll", "DLL bytes not appended after DllLdr header");
    assert_eq!(artifact.file_name, "demon.x64.bin");
    assert_eq!(artifact.format, "Windows Raw Shellcode");
    Ok(())
}

#[tokio::test]
async fn build_payload_staged_shellcode_cache_hit_skips_compilation()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager' > \"$1\"; break; fi; shift; done\n";
    let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Shellcode Staged".to_owned(),
        config: "{}".to_owned(),
    };

    let first = service.build_payload(&listener, &request, None, |_| {}).await?;

    let mut messages = Vec::new();
    let second = service
        .build_payload(&listener, &request, None, |m| messages.push(m.message.clone()))
        .await?;

    assert_eq!(first.bytes, second.bytes, "cached bytes must match compiled bytes");
    assert!(
        messages.iter().any(|m| m.contains("cache hit")),
        "second request should be a cache hit: {messages:?}"
    );
    Ok(())
}
