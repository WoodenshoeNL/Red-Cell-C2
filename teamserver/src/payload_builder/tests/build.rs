use super::*;
use red_cell_common::config::DemonConfig;

/// Build a minimal source tree and return (service, listener, request).
///
/// `nasm_script` and `gcc_script` are the shell script bodies written to the
/// respective stub executables. Both must be `#!/bin/sh` scripts.
fn setup_build_fixture(
    temp: &TempDir,
    nasm_script: &str,
    gcc_script: &str,
) -> Result<
    (PayloadBuilderService, ListenerConfig, BuildPayloadRequestInfo),
    Box<dyn std::error::Error>,
> {
    let bin_dir = temp.path().join("bin");
    let cache_dir = temp.path().join("payload-cache");
    let source_root = temp.path().join("agent/demon");
    let shellcode_root = temp.path().join("agent/demon/payloads");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(source_root.join("src/core"))?;
    std::fs::create_dir_all(source_root.join("src/crypt"))?;
    std::fs::create_dir_all(source_root.join("src/inject"))?;
    std::fs::create_dir_all(source_root.join("src/asm"))?;
    std::fs::create_dir_all(source_root.join("src/main"))?;
    std::fs::create_dir_all(source_root.join("include"))?;
    std::fs::create_dir_all(&shellcode_root)?;
    std::fs::write(source_root.join("src/core/a.c"), "int x = 1;")?;
    std::fs::write(source_root.join("src/asm/test.x64.asm"), "bits 64")?;
    std::fs::write(source_root.join("src/main/MainExe.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainSvc.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainDll.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/Demon.c"), "int demo = 1;")?;
    std::fs::write(shellcode_root.join("Shellcode.x64.bin"), [0x90_u8, 0x90])?;
    std::fs::write(shellcode_root.join("Shellcode.x86.bin"), [0x90_u8, 0x90])?;
    std::fs::write(shellcode_root.join("DllLdr.x64.bin"), [0x55_u8, 0x48])?;
    let templates_dir = temp.path().join("payloads/templates");
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(templates_dir.join("MainStager.c"), "int main(void){return 0;}")?;

    let nasm = bin_dir.join("nasm");
    let gcc = bin_dir.join("x86_64-w64-mingw32-gcc");
    std::fs::write(&nasm, nasm_script)?;
    std::fs::write(&gcc, gcc_script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nasm, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&gcc, std::fs::Permissions::from_mode(0o755))?;
    }

    let unknown_version =
        ToolchainVersion { major: 0, minor: 0, patch: 0, raw: "0.0.0".to_owned() };
    let service = PayloadBuilderService::with_paths_for_tests(
        Toolchain {
            compiler_x64: gcc.clone(),
            compiler_x64_version: unknown_version.clone(),
            compiler_x86: gcc,
            compiler_x86_version: unknown_version.clone(),
            nasm,
            nasm_version: unknown_version,
        },
        source_root,
        temp.path().join("agent/archon"),
        shellcode_root.join("Shellcode.x64.bin"),
        shellcode_root.join("Shellcode.x86.bin"),
        shellcode_root.join("DllLdr.x64.bin"),
        templates_dir.join("MainStager.c"),
        DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: "thread".to_owned(),
            stomp_dll: None,
        },
        None,
        cache_dir,
    );

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
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
    }));

    Ok((service, listener, request))
}

// ── Build validation tests ──────────────────────────────────────────

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
async fn build_payload_archon_rejects_missing_source_tree() -> Result<(), Box<dyn std::error::Error>>
{
    // `disabled_for_tests` points archon_source_root at a non-existent path.
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

#[tokio::test]
async fn build_payload_uses_toolchain_and_returns_compiled_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let bin_dir = temp.path().join("bin");
    let source_root = temp.path().join("agent/demon");
    let shellcode_root = temp.path().join("agent/demon/payloads");
    let cache_dir = temp.path().join("payload-cache");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(source_root.join("src/core"))?;
    std::fs::create_dir_all(source_root.join("src/crypt"))?;
    std::fs::create_dir_all(source_root.join("src/inject"))?;
    std::fs::create_dir_all(source_root.join("src/asm"))?;
    std::fs::create_dir_all(source_root.join("src/main"))?;
    std::fs::create_dir_all(source_root.join("include"))?;
    std::fs::create_dir_all(&shellcode_root)?;
    std::fs::write(source_root.join("src/core/a.c"), "int x = 1;")?;
    std::fs::write(source_root.join("src/asm/test.x64.asm"), "bits 64")?;
    std::fs::write(source_root.join("src/main/MainExe.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainSvc.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainDll.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/Demon.c"), "int demo = 1;")?;
    std::fs::write(shellcode_root.join("Shellcode.x64.bin"), [0x90, 0x90])?;
    std::fs::write(shellcode_root.join("Shellcode.x86.bin"), [0x90, 0x90])?;
    std::fs::write(shellcode_root.join("DllLdr.x64.bin"), [0x55, 0x48])?;
    let templates_dir = temp.path().join("payloads/templates");
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(templates_dir.join("MainStager.c"), "int main(void){return 0;}")?;

    let nasm = bin_dir.join("nasm");
    let gcc = bin_dir.join("x86_64-w64-mingw32-gcc");
    std::fs::write(
        &nasm,
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\necho nasm-ok\n",
    )?;
    std::fs::write(
        &gcc,
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\necho gcc-ok\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nasm, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&gcc, std::fs::Permissions::from_mode(0o755))?;
    }

    let unknown_version =
        ToolchainVersion { major: 0, minor: 0, patch: 0, raw: "0.0.0".to_owned() };
    let service = PayloadBuilderService::with_paths_for_tests(
        Toolchain {
            compiler_x64: gcc.clone(),
            compiler_x64_version: unknown_version.clone(),
            compiler_x86: gcc,
            compiler_x86_version: unknown_version.clone(),
            nasm,
            nasm_version: unknown_version,
        },
        source_root,
        temp.path().join("agent/archon"),
        shellcode_root.join("Shellcode.x64.bin"),
        shellcode_root.join("Shellcode.x86.bin"),
        shellcode_root.join("DllLdr.x64.bin"),
        templates_dir.join("MainStager.c"),
        DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: "thread".to_owned(),
            stomp_dll: None,
        },
        None,
        cache_dir,
    );
    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
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
    }));

    let mut messages = Vec::new();
    let artifact = service
        .build_payload(&listener, &request, None, |message| messages.push(message.message))
        .await?;
    assert_eq!(artifact.bytes, b"payload");
    assert_eq!(artifact.file_name, "demon.x64.exe");
    assert!(messages.iter().any(|line| line.contains("nasm-ok")));
    assert!(messages.iter().any(|line| line.contains("gcc-ok")));
    Ok(())
}

#[tokio::test]
async fn build_payload_x86_uses_x86_compiler_and_win32_nasm_format()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let bin_dir = temp.path().join("bin");
    let cache_dir = temp.path().join("payload-cache");
    let source_root = temp.path().join("agent/demon");
    let shellcode_root = temp.path().join("agent/demon/payloads");
    let nasm_args = temp.path().join("nasm.args");
    let gcc_x64_args = temp.path().join("gcc-x64.args");
    let gcc_x86_args = temp.path().join("gcc-x86.args");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(source_root.join("src/core"))?;
    std::fs::create_dir_all(source_root.join("src/crypt"))?;
    std::fs::create_dir_all(source_root.join("src/inject"))?;
    std::fs::create_dir_all(source_root.join("src/asm"))?;
    std::fs::create_dir_all(source_root.join("src/main"))?;
    std::fs::create_dir_all(source_root.join("include"))?;
    std::fs::create_dir_all(&shellcode_root)?;
    std::fs::write(source_root.join("src/core/a.c"), "int x = 1;")?;
    std::fs::write(source_root.join("src/asm/test.x86.asm"), "bits 32")?;
    std::fs::write(source_root.join("src/main/MainExe.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainSvc.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainDll.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/Demon.c"), "int demo = 1;")?;
    std::fs::write(shellcode_root.join("Shellcode.x64.bin"), [0x90, 0x90])?;
    std::fs::write(shellcode_root.join("Shellcode.x86.bin"), [0x90, 0x90])?;
    std::fs::write(shellcode_root.join("DllLdr.x64.bin"), [0x55, 0x48])?;
    let templates_dir = temp.path().join("payloads/templates");
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(templates_dir.join("MainStager.c"), "int main(void){return 0;}")?;

    let nasm = bin_dir.join("nasm");
    let gcc_x64 = bin_dir.join("x86_64-w64-mingw32-gcc");
    let gcc_x86 = bin_dir.join("i686-w64-mingw32-gcc");
    std::fs::write(
        &nasm,
        format!(
            "#!/bin/sh\nprintf '%s\n' \"$@\" > '{}'\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\necho nasm-x86-ok\n",
            nasm_args.display()
        ),
    )?;
    std::fs::write(
        &gcc_x64,
        format!(
            "#!/bin/sh\nprintf '%s\n' \"$@\" > '{}'\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload-x64' > \"$1\"; break; fi; shift; done\necho gcc-x64-ok\n",
            gcc_x64_args.display()
        ),
    )?;
    std::fs::write(
        &gcc_x86,
        format!(
            "#!/bin/sh\nprintf '%s\n' \"$@\" > '{}'\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload-x86' > \"$1\"; break; fi; shift; done\necho gcc-x86-ok\n",
            gcc_x86_args.display()
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nasm, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&gcc_x64, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&gcc_x86, std::fs::Permissions::from_mode(0o755))?;
    }

    let unknown_version =
        ToolchainVersion { major: 0, minor: 0, patch: 0, raw: "0.0.0".to_owned() };
    let service = PayloadBuilderService::with_paths_for_tests(
        Toolchain {
            compiler_x64: gcc_x64,
            compiler_x64_version: unknown_version.clone(),
            compiler_x86: gcc_x86,
            compiler_x86_version: unknown_version.clone(),
            nasm,
            nasm_version: unknown_version,
        },
        source_root,
        temp.path().join("agent/archon"),
        shellcode_root.join("Shellcode.x64.bin"),
        shellcode_root.join("Shellcode.x86.bin"),
        shellcode_root.join("DllLdr.x64.bin"),
        templates_dir.join("MainStager.c"),
        DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: "thread".to_owned(),
            stomp_dll: None,
        },
        None,
        cache_dir,
    );
    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x86".to_owned(),
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
    }));

    let artifact = service.build_payload(&listener, &request, None, |_| {}).await?;

    assert_eq!(artifact.bytes, b"payload-x86");
    assert_eq!(artifact.file_name, "demon.x86.exe");
    assert!(std::fs::read_to_string(&gcc_x64_args).is_err());
    let gcc_x86_args = std::fs::read_to_string(&gcc_x86_args)?;
    assert!(gcc_x86_args.contains("src/main/MainExe.c"));
    let nasm_args = std::fs::read_to_string(&nasm_args)?;
    assert!(nasm_args.contains("win32"));
    Ok(())
}

// ── Compiler failure tests ──────────────────────────────────────────

#[tokio::test]
async fn build_payload_compiler_exits_nonzero_returns_command_failed()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    // nasm succeeds and writes its output file; gcc always exits 1
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_fail = "#!/bin/sh\necho 'stub compiler error' >&2\nexit 1\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("a compiler that exits non-zero must produce an error");

    assert!(
        matches!(error, PayloadBuildError::CommandFailed { .. }),
        "expected CommandFailed, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_assembler_exits_nonzero_returns_command_failed()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    // nasm always exits 1; gcc is never reached
    let nasm_fail = "#!/bin/sh\necho 'stub assembler error' >&2\nexit 1\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_fail, gcc_ok)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("an assembler that exits non-zero must produce an error");

    assert!(
        matches!(error, PayloadBuildError::CommandFailed { .. }),
        "expected CommandFailed, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_compiler_failure_populates_diagnostics()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    // Emit a structured GCC diagnostic to stderr then exit 1.
    let gcc_fail = "#!/bin/sh\necho \"src/Demon.c:42:8: error: 'foo' undeclared\" >&2\nexit 1\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("compiler failure must yield an error");

    match error {
        PayloadBuildError::CommandFailed { ref diagnostics, .. } => {
            assert_eq!(diagnostics.len(), 1, "one GCC diagnostic should be parsed");
            let d = &diagnostics[0];
            assert_eq!(d.filename, "src/Demon.c");
            assert_eq!(d.line, 42);
            assert_eq!(d.column, Some(8));
            assert_eq!(d.severity, "error");
            assert!(d.message.contains("'foo' undeclared"));
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
    Ok(())
}

// ── Cache integration tests ─────────────────────────────────────────

#[tokio::test]
async fn build_payload_returns_cached_artifact_on_second_request()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    // The compiler writes "payload" the first time; we can detect a cache
    // hit if the artifact is returned without re-invoking the compiler.
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

    // First build — cache miss, runs the compiler.
    let first = service.build_payload(&listener, &request, None, |_| {}).await?;
    assert_eq!(first.bytes, b"payload");

    // Second build with identical inputs — cache hit, no recompilation.
    let mut hit_messages = Vec::new();
    let second = service
        .build_payload(&listener, &request, None, |m| hit_messages.push(m.message.clone()))
        .await?;
    assert_eq!(second.bytes, b"payload");
    assert!(
        hit_messages.iter().any(|m| m.contains("cache hit")),
        "expected a cache-hit progress message, got: {hit_messages:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_cache_miss_on_different_architecture()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    // Different architectures use different compilers but the important
    // thing is that they must not share a cache entry.
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
    let (service, listener, request_x64) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;
    let request_x86 = BuildPayloadRequestInfo { arch: "x86".to_owned(), ..request_x64.clone() };

    let first = service.build_payload(&listener, &request_x64, None, |_| {}).await?;
    assert_eq!(first.bytes, b"payload");

    // x86 build should NOT return the x64 cached artifact.
    let mut hit_messages = Vec::new();
    service
        .build_payload(&listener, &request_x86, None, |m| hit_messages.push(m.message.clone()))
        .await
        .ok(); // may fail due to stub compiler, but we just need to check messages
    assert!(
        !hit_messages.iter().any(|m| m.contains("cache hit")),
        "x86 build should not hit the x64 cache entry, got: {hit_messages:?}"
    );
    Ok(())
}

/// Regression test: Demon and Archon builds with identical listener/config/arch/format
/// must not share a cache entry.  Before the fix, `compute_cache_key` omitted the agent
/// variant from the hash, so the second build would return the first build's bytes.
#[tokio::test]
async fn build_payload_demon_and_archon_do_not_share_cache()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    // Compiler writes "demon-bytes" when building Demon and "archon-bytes" when building
    // Archon.  We detect a collision if the Archon request returns "demon-bytes".
    let gcc_demon = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'demon-bytes' > \"$1\"; break; fi; shift; done\n";

    let (service, listener, demon_request) = setup_build_fixture(&temp, nasm_ok, gcc_demon)?;

    // First build: Demon — cache miss, compiler writes "demon-bytes".
    let demon_artifact = service.build_payload(&listener, &demon_request, None, |_| {}).await?;
    assert_eq!(demon_artifact.bytes, b"demon-bytes");

    // Create a minimal Archon source tree so the existence check passes.
    let archon_root = temp.path().join("agent/archon");
    for dir in ["src/core", "src/crypt", "src/inject", "src/asm", "src/main", "include"] {
        std::fs::create_dir_all(archon_root.join(dir))?;
    }
    std::fs::write(archon_root.join("src/core/a.c"), "int x = 1;")?;
    std::fs::write(archon_root.join("src/asm/test.x64.asm"), "bits 64")?;
    std::fs::write(archon_root.join("src/main/MainExe.c"), "int main(void){return 0;}")?;
    std::fs::write(archon_root.join("src/main/MainSvc.c"), "int main(void){return 0;}")?;
    std::fs::write(archon_root.join("src/main/MainDll.c"), "int main(void){return 0;}")?;
    std::fs::write(archon_root.join("src/Demon.c"), "int demo = 1;")?;

    let archon_request =
        BuildPayloadRequestInfo { agent_type: "Archon".to_owned(), ..demon_request.clone() };

    // Second build: Archon with identical listener/config/arch/format.
    // The cache key must differ from Demon's, so we get a cache miss (full build).
    let mut hit_messages = Vec::new();
    // The build may succeed or fail depending on stub output — we only care about
    // whether a cache hit was reported.
    let _ = service
        .build_payload(&listener, &archon_request, None, |m| hit_messages.push(m.message.clone()))
        .await;

    assert!(
        !hit_messages.iter().any(|m| m.contains("cache hit")),
        "Archon build must not hit the Demon cache entry; messages: {hit_messages:?}"
    );
    Ok(())
}

// ── OutputFormat parsing tests ──────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────
// OutputFormat: new variants
// ──────────────────────────────────────────────────────────────────────

#[test]
fn output_format_parses_staged_shellcode() {
    let fmt = OutputFormat::parse("Windows Shellcode Staged")
        .expect("should parse Windows Shellcode Staged");
    assert_eq!(fmt, OutputFormat::StagedShellcode);
    assert_eq!(fmt.file_extension(), ".exe");
}

#[test]
fn output_format_parses_raw_shellcode() {
    let fmt =
        OutputFormat::parse("Windows Raw Shellcode").expect("should parse Windows Raw Shellcode");
    assert_eq!(fmt, OutputFormat::RawShellcode);
    assert_eq!(fmt.file_extension(), ".bin");
}

#[test]
fn output_format_parse_rejects_unknown_format() {
    let err = OutputFormat::parse("Windows Invalid Format")
        .expect_err("unknown format should be rejected");
    assert!(
        matches!(&err, PayloadBuildError::InvalidRequest { message }
            if message.contains("Windows Invalid Format")),
        "unexpected error: {err}"
    );
}

// ──────────────────────────────────────────────────────────────────────

// ── Shellcode format integration tests ──────────────────────────────

// ──────────────────────────────────────────────────────────────────────
// build_payload: new formats (integration with fake toolchain)
// ──────────────────────────────────────────────────────────────────────

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
    // Compiler writes exactly "dll" as the output DLL bytes.
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

    // DllLdr.x64.bin stub is [0x55, 0x48]; the fake gcc writes "dll".
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

    // First build — compiles and caches.
    let first = service.build_payload(&listener, &request, None, |_| {}).await?;

    // Second build — must return cache hit.
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

// ── Stager generation tests ─────────────────────────────────────────

// ── Stager generation integration tests ────────────────────────────

#[tokio::test]
async fn build_stager_passes_correct_defines_to_compiler() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = TempDir::new()?;
    let args_file = temp.path().join("gcc.args");
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager-exe' > \"$1\"; break; fi; shift; done\n",
        args_file.display()
    );
    let (service, _, _) = setup_build_fixture(&temp, nasm_ok, &gcc_ok)?;

    let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http-staging".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["c2.example.com".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/stage".to_owned()],
        host_header: None,
        secure: true,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
    }));

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http-staging".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Shellcode Staged".to_owned(),
        config: "{}".to_owned(),
    };

    let mut messages = Vec::new();
    let artifact = service
        .build_payload(&listener, &request, None, |m| messages.push(m.message.clone()))
        .await?;

    // Validate artifact metadata.
    assert_eq!(artifact.file_name, "demon.x64.exe");
    assert_eq!(artifact.format, "Windows Shellcode Staged");
    assert!(!artifact.bytes.is_empty(), "stager artifact must not be empty");

    // Validate that the correct -D defines were passed to the compiler.
    let gcc_args = std::fs::read_to_string(&args_file)?;
    assert!(
        gcc_args.contains("-DSTAGER_PORT=443"),
        "expected port_conn=443 in defines: {gcc_args}"
    );
    assert!(gcc_args.contains("-DSTAGER_SECURE=1"), "expected secure=1 in defines: {gcc_args}");
    // Host and URI are embedded as C byte-array initialisers.
    assert!(gcc_args.contains("-DSTAGER_HOST="), "expected STAGER_HOST define: {gcc_args}");
    assert!(gcc_args.contains("-DSTAGER_URI="), "expected STAGER_URI define: {gcc_args}");
    // Verify the entry point flag.
    assert!(
        gcc_args.contains("-e") && gcc_args.contains("WinMain"),
        "expected -e WinMain in args: {gcc_args}"
    );
    // Verify linking flags.
    assert!(gcc_args.contains("-lwininet"), "stager must link wininet: {gcc_args}");
    // Verify the stager template source was passed.
    assert!(gcc_args.contains("MainStager.c"), "stager must compile MainStager.c: {gcc_args}");

    // Validate progress messages include expected stages.
    assert!(
        messages.iter().any(|m| m.contains("starting stager build")),
        "expected 'starting stager build' in messages: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("payload generated")),
        "expected 'payload generated' in messages: {messages:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_stager_x86_uses_underscore_entry_point() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let bin_dir = temp.path().join("bin");
    let cache_dir = temp.path().join("payload-cache");
    let source_root = temp.path().join("agent/demon");
    let shellcode_root = temp.path().join("agent/demon/payloads");
    let gcc_x86_args = temp.path().join("gcc-x86.args");

    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(source_root.join("src/core"))?;
    std::fs::create_dir_all(source_root.join("src/crypt"))?;
    std::fs::create_dir_all(source_root.join("src/inject"))?;
    std::fs::create_dir_all(source_root.join("src/asm"))?;
    std::fs::create_dir_all(source_root.join("src/main"))?;
    std::fs::create_dir_all(source_root.join("include"))?;
    std::fs::create_dir_all(&shellcode_root)?;
    std::fs::write(source_root.join("src/core/a.c"), "int x = 1;")?;
    std::fs::write(source_root.join("src/asm/test.x86.asm"), "bits 32")?;
    std::fs::write(source_root.join("src/main/MainExe.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainSvc.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/main/MainDll.c"), "int main(void){return 0;}")?;
    std::fs::write(source_root.join("src/Demon.c"), "int demo = 1;")?;
    std::fs::write(shellcode_root.join("Shellcode.x64.bin"), [0x90, 0x90])?;
    std::fs::write(shellcode_root.join("Shellcode.x86.bin"), [0x90, 0x90])?;
    std::fs::write(shellcode_root.join("DllLdr.x64.bin"), [0x55, 0x48])?;
    let templates_dir = temp.path().join("payloads/templates");
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(templates_dir.join("MainStager.c"), "int main(void){return 0;}")?;

    let nasm = bin_dir.join("nasm");
    let gcc_x64 = bin_dir.join("x86_64-w64-mingw32-gcc");
    let gcc_x86 = bin_dir.join("i686-w64-mingw32-gcc");
    std::fs::write(
        &nasm,
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n",
    )?;
    std::fs::write(
        &gcc_x64,
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager-x64' > \"$1\"; break; fi; shift; done\n",
    )?;
    std::fs::write(
        &gcc_x86,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager-x86' > \"$1\"; break; fi; shift; done\n",
            gcc_x86_args.display()
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nasm, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&gcc_x64, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&gcc_x86, std::fs::Permissions::from_mode(0o755))?;
    }

    let unknown_version =
        ToolchainVersion { major: 0, minor: 0, patch: 0, raw: "0.0.0".to_owned() };
    let service = PayloadBuilderService::with_paths_for_tests(
        Toolchain {
            compiler_x64: gcc_x64,
            compiler_x64_version: unknown_version.clone(),
            compiler_x86: gcc_x86,
            compiler_x86_version: unknown_version.clone(),
            nasm,
            nasm_version: unknown_version,
        },
        source_root,
        temp.path().join("agent/archon"),
        shellcode_root.join("Shellcode.x64.bin"),
        shellcode_root.join("Shellcode.x86.bin"),
        shellcode_root.join("DllLdr.x64.bin"),
        templates_dir.join("MainStager.c"),
        DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: "thread".to_owned(),
            stomp_dll: None,
        },
        None,
        cache_dir,
    );

    let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["stager.local".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 80,
        port_conn: None,
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
    }));

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x86".to_owned(),
        format: "Windows Shellcode Staged".to_owned(),
        config: "{}".to_owned(),
    };

    let artifact = service.build_payload(&listener, &request, None, |_| {}).await?;

    // Validate x86 stager output.
    assert_eq!(artifact.bytes, b"stager-x86");
    assert_eq!(artifact.file_name, "demon.x86.exe");

    // The x86 stager must use the _WinMain entry point (leading underscore).
    let args = std::fs::read_to_string(&gcc_x86_args)?;
    assert!(args.contains("_WinMain"), "x86 stager must use _WinMain entry point: {args}");

    // port_conn is None so port_bind (80) should be used.
    assert!(
        args.contains("-DSTAGER_PORT=80"),
        "expected port_bind=80 when port_conn is None: {args}"
    );
    // secure=false ⇒ STAGER_SECURE=0
    assert!(args.contains("-DSTAGER_SECURE=0"), "expected secure=0 in defines: {args}");
    // Default URI is "/" when uris list is empty.
    assert!(args.contains("-DSTAGER_URI="), "expected STAGER_URI define: {args}");

    // The x64 compiler must NOT have been invoked for an x86 build.
    assert!(
        !std::path::Path::new(&temp.path().join("gcc-x64.args")).exists(),
        "x64 compiler should not be invoked for x86 stager build"
    );
    Ok(())
}

#[tokio::test]
async fn build_stager_copies_template_to_compile_dir() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    // A gcc stub that writes the contents of MainStager.c (its first arg)
    // into a sidecar file so we can verify the template was copied.
    let template_check = temp.path().join("template_found");
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = format!(
        "#!/bin/sh\n# Check that MainStager.c exists in cwd\nif [ -f MainStager.c ]; then cp MainStager.c '{}'; fi\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager-bin' > \"$1\"; break; fi; shift; done\n",
        template_check.display()
    );
    let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, &gcc_ok)?;

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Shellcode Staged".to_owned(),
        config: "{}".to_owned(),
    };

    let artifact = service.build_payload(&listener, &request, None, |_| {}).await?;

    assert_eq!(artifact.bytes, b"stager-bin");
    // The gcc stub copies MainStager.c from the compile dir if it exists.
    assert!(
        template_check.exists(),
        "stager template (MainStager.c) must be copied into the compile directory"
    );
    let template_content = std::fs::read_to_string(&template_check)?;
    assert_eq!(
        template_content, "int main(void){return 0;}",
        "stager template content must match the source template"
    );
    Ok(())
}

// ── Phantom / Specter source tree tests ─────────────────────────────

#[tokio::test]
async fn build_payload_phantom_rejects_missing_source_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let service = PayloadBuilderService::disabled_for_tests();
    let request = BuildPayloadRequestInfo {
        agent_type: "Phantom".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Linux ELF".to_owned(),
        config: "{}".to_owned(),
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
        config: "{}".to_owned(),
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

// ── ECDH pub-key injection tests ───────────────────────────────────────────

/// Helper: create a minimal Archon source tree under `root`.
fn create_archon_source_tree(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    for dir in ["src/core", "src/crypt", "src/inject", "src/asm", "src/main", "include"] {
        std::fs::create_dir_all(root.join(dir))?;
    }
    std::fs::write(root.join("src/core/a.c"), "int x = 1;")?;
    std::fs::write(root.join("src/asm/test.x64.asm"), "bits 64")?;
    std::fs::write(root.join("src/main/MainExe.c"), "int main(void){return 0;}")?;
    std::fs::write(root.join("src/main/MainSvc.c"), "int main(void){return 0;}")?;
    std::fs::write(root.join("src/main/MainDll.c"), "int main(void){return 0;}")?;
    std::fs::write(root.join("src/Demon.c"), "int demo = 1;")?;
    Ok(())
}

/// GCC stub that records every argument on a separate line in `args_file` and
/// then writes "archon-ecdh-payload" to the `-o` output path.
fn gcc_args_capture_script(args_file: &std::path::Path) -> String {
    format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'archon-ecdh-payload' > \"$1\"; break; fi; shift; done\n",
        args_file.display()
    )
}

/// Archon build with `ecdh_pub_key = Some(key)` must pass `-DARCHON_ECDH_MODE`
/// and `-DARCHON_LISTENER_PUBKEY=` to the compiler.
#[tokio::test]
async fn build_payload_archon_with_ecdh_key_injects_ecdh_defines()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let args_file = temp.path().join("gcc_args.txt");
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_script = gcc_args_capture_script(&args_file);

    let (service, listener_template, _) = setup_build_fixture(&temp, nasm_ok, &gcc_script)?;

    let archon_root = temp.path().join("agent/archon");
    create_archon_source_tree(&archon_root)?;

    let listener = match listener_template {
        ListenerConfig::Http(mut http) => {
            http.legacy_mode = false;
            ListenerConfig::Http(http)
        }
        other => other,
    };

    let request = BuildPayloadRequestInfo {
        agent_type: "Archon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Exe".to_owned(),
        config: r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#.to_owned(),
    };

    let ecdh_key = [0xABu8; 32];
    let _ = service.build_payload(&listener, &request, Some(ecdh_key), |_| {}).await;

    let captured = std::fs::read_to_string(&args_file).unwrap_or_default();
    assert!(
        captured.contains("ARCHON_ECDH_MODE"),
        "ARCHON_ECDH_MODE not found in compiler args; captured: {captured}"
    );
    assert!(
        captured.contains("ARCHON_LISTENER_PUBKEY"),
        "ARCHON_LISTENER_PUBKEY not found in compiler args; captured: {captured}"
    );
    assert!(
        captured.contains("0xab"),
        "expected 0xab key bytes in compiler args; captured: {captured}"
    );
    Ok(())
}

/// Archon build with `ecdh_pub_key = None` must NOT emit ECDH defines.
#[tokio::test]
async fn build_payload_archon_without_ecdh_key_omits_ecdh_defines()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let args_file = temp.path().join("gcc_args.txt");
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_script = gcc_args_capture_script(&args_file);

    let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, &gcc_script)?;

    let archon_root = temp.path().join("agent/archon");
    create_archon_source_tree(&archon_root)?;

    let request = BuildPayloadRequestInfo {
        agent_type: "Archon".to_owned(),
        listener: "http".to_owned(),
        arch: "x64".to_owned(),
        format: "Windows Exe".to_owned(),
        config: r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#.to_owned(),
    };

    let _ = service.build_payload(&listener, &request, None, |_| {}).await;

    let captured = std::fs::read_to_string(&args_file).unwrap_or_default();
    assert!(
        !captured.contains("ARCHON_ECDH_MODE"),
        "ARCHON_ECDH_MODE should not appear without ECDH key; captured: {captured}"
    );
    assert!(
        !captured.contains("ARCHON_LISTENER_PUBKEY"),
        "ARCHON_LISTENER_PUBKEY should not appear without ECDH key; captured: {captured}"
    );
    Ok(())
}
