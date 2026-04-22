use super::*;
use red_cell_common::config::{DemonConfig, JobExecutionMode};

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
        suppress_opsec_warnings: true,
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

    assert_eq!(artifact.file_name, "demon.x64.exe");
    assert_eq!(artifact.format, "Windows Shellcode Staged");
    assert!(!artifact.bytes.is_empty(), "stager artifact must not be empty");

    let gcc_args = std::fs::read_to_string(&args_file)?;
    assert!(
        gcc_args.contains("-DSTAGER_PORT=443"),
        "expected port_conn=443 in defines: {gcc_args}"
    );
    assert!(gcc_args.contains("-DSTAGER_SECURE=1"), "expected secure=1 in defines: {gcc_args}");
    assert!(gcc_args.contains("-DSTAGER_HOST="), "expected STAGER_HOST define: {gcc_args}");
    assert!(gcc_args.contains("-DSTAGER_URI="), "expected STAGER_URI define: {gcc_args}");
    assert!(
        gcc_args.contains("-e") && gcc_args.contains("WinMain"),
        "expected -e WinMain in args: {gcc_args}"
    );
    assert!(gcc_args.contains("-lwininet"), "stager must link wininet: {gcc_args}");
    assert!(gcc_args.contains("MainStager.c"), "stager must compile MainStager.c: {gcc_args}");

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
            job_execution: JobExecutionMode::Thread,
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
        suppress_opsec_warnings: true,
    }));

    let request = BuildPayloadRequestInfo {
        agent_type: "Demon".to_owned(),
        listener: "http".to_owned(),
        arch: "x86".to_owned(),
        format: "Windows Shellcode Staged".to_owned(),
        config: "{}".to_owned(),
    };

    let artifact = service.build_payload(&listener, &request, None, |_| {}).await?;

    assert_eq!(artifact.bytes, b"stager-x86");
    assert_eq!(artifact.file_name, "demon.x86.exe");

    let args = std::fs::read_to_string(&gcc_x86_args)?;
    assert!(args.contains("_WinMain"), "x86 stager must use _WinMain entry point: {args}");
    assert!(
        args.contains("-DSTAGER_PORT=80"),
        "expected port_bind=80 when port_conn is None: {args}"
    );
    assert!(args.contains("-DSTAGER_SECURE=0"), "expected secure=0 in defines: {args}");
    assert!(args.contains("-DSTAGER_URI="), "expected STAGER_URI define: {args}");
    assert!(
        !std::path::Path::new(&temp.path().join("gcc-x64.args")).exists(),
        "x64 compiler should not be invoked for x86 stager build"
    );
    Ok(())
}

#[tokio::test]
async fn build_stager_copies_template_to_compile_dir() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let template_check = temp.path().join("template_found");
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = format!(
        "#!/bin/sh\nif [ -f MainStager.c ]; then cp MainStager.c '{}'; fi\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager-bin' > \"$1\"; break; fi; shift; done\n",
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
