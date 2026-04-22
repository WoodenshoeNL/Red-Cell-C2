use super::*;
use red_cell_common::config::{DemonConfig, JobExecutionMode};

mod archon_ecdh;
mod cache_behavior;
mod compiler_failures;
mod format_parsing;
mod shellcode_formats;
mod source_trees;
mod stager_generation;
mod validation;

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

    Ok((service, listener, request))
}

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
