use super::super::*;

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
            job_execution: JobExecutionMode::Thread,
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
        suppress_opsec_warnings: true,
    }));

    let mut messages = Vec::new();
    let artifact = service
        .build_payload(&listener, &request, None, |message| messages.push(message.message))
        .await?;
    assert!(artifact.bytes.starts_with(b"payload"), "artifact must start with compiled payload");
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
            job_execution: JobExecutionMode::Thread,
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
        suppress_opsec_warnings: true,
    }));

    let artifact = service.build_payload(&listener, &request, None, |_| {}).await?;

    assert!(artifact.bytes.starts_with(b"payload-x86"), "artifact must start with compiled payload");
    assert_eq!(artifact.file_name, "demon.x86.exe");
    assert!(std::fs::read_to_string(&gcc_x64_args).is_err());
    let gcc_x86_args = std::fs::read_to_string(&gcc_x86_args)?;
    assert!(gcc_x86_args.contains("src/main/MainExe.c"));
    let nasm_args = std::fs::read_to_string(&nasm_args)?;
    assert!(nasm_args.contains("win32"));
    Ok(())
}
