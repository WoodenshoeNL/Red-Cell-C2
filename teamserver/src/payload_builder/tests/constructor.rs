use std::collections::BTreeMap;
use std::path::Path;

use super::*;
use red_cell_common::config::{DemonConfig, Profile};

fn constructor_test_profile(compiler_x64: &Path, compiler_x86: &Path, nasm: &Path) -> Profile {
    Profile {
        teamserver: red_cell_common::config::TeamserverConfig {
            host: "127.0.0.1".to_owned(),
            port: 40056,
            plugins_dir: None,
            max_download_bytes: None,
            max_concurrent_downloads_per_agent: None,
            max_aggregate_download_bytes: None,
            max_registered_agents: None,
            max_pivot_chain_depth: None,
            drain_timeout_secs: None,
            agent_timeout_secs: None,
            logging: None,
            cert: None,
            database: None,
            observability: None,
            build: Some(red_cell_common::config::BuildConfig {
                compiler64: Some(compiler_x64.display().to_string()),
                compiler86: Some(compiler_x86.display().to_string()),
                nasm: Some(nasm.display().to_string()),
            }),
        },
        operators: red_cell_common::config::OperatorsConfig {
            users: BTreeMap::from([(
                "operator".to_owned(),
                red_cell_common::config::OperatorConfig {
                    password: "password".to_owned(),
                    role: red_cell_common::config::OperatorRole::Admin,
                },
            )]),
            ..Default::default()
        },
        listeners: red_cell_common::config::ListenersConfig::default(),
        demon: DemonConfig {
            sleep: Some(5),
            jitter: Some(10),
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
        service: None,
        api: None,
        webhook: None,
    }
}

#[test]
fn from_profile_resolves_workspace_root_and_toolchain() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
    let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
    let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
    let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);
    let repo_root = workspace_root()?;

    let service = PayloadBuilderService::from_profile_with_repo_root_impl(
        &profile,
        &repo_root,
        read_fake_script_output,
    )?;

    assert_eq!(service.inner.toolchain.compiler_x64, compiler_x64.canonicalize()?);
    assert_eq!(service.inner.toolchain.compiler_x86, compiler_x86.canonicalize()?);
    assert_eq!(service.inner.toolchain.nasm, nasm.canonicalize()?);
    assert_eq!(service.inner.toolchain.compiler_x64_version.major, 12);
    assert_eq!(service.inner.toolchain.nasm_version.major, 2);
    assert_eq!(service.inner.source_root, repo_root.join("agent/demon"));
    assert_eq!(
        service.inner.shellcode_x64_template,
        repo_root.join("agent/demon/payloads/Shellcode.x64.bin")
    );
    assert_eq!(
        service.inner.shellcode_x86_template,
        repo_root.join("agent/demon/payloads/Shellcode.x86.bin")
    );
    assert_eq!(service.inner.default_demon, profile.demon);
    Ok(())
}

#[test]
fn from_profile_with_repo_root_resolves_toolchain_and_havoc_assets()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
    let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
    let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
    create_payload_assets(temp.path())?;
    let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);

    let service = PayloadBuilderService::from_profile_with_repo_root_impl(
        &profile,
        temp.path(),
        read_fake_script_output,
    )?;

    assert_eq!(service.inner.toolchain.compiler_x64, compiler_x64.canonicalize()?);
    assert_eq!(service.inner.toolchain.compiler_x86, compiler_x86.canonicalize()?);
    assert_eq!(service.inner.toolchain.nasm, nasm.canonicalize()?);
    assert_eq!(
        service.inner.toolchain.compiler_x64_version,
        ToolchainVersion { major: 12, minor: 2, patch: 0, raw: "12.2.0".to_owned() }
    );
    assert_eq!(
        service.inner.toolchain.compiler_x86_version,
        ToolchainVersion { major: 12, minor: 2, patch: 0, raw: "12.2.0".to_owned() }
    );
    assert_eq!(
        service.inner.toolchain.nasm_version,
        ToolchainVersion { major: 2, minor: 16, patch: 1, raw: "2.16.01".to_owned() }
    );
    assert_eq!(service.inner.source_root, temp.path().join("agent/demon"));
    assert_eq!(
        service.inner.shellcode_x64_template,
        temp.path().join("agent/demon/payloads/Shellcode.x64.bin")
    );
    assert_eq!(
        service.inner.shellcode_x86_template,
        temp.path().join("agent/demon/payloads/Shellcode.x86.bin")
    );
    assert_eq!(
        service.inner.dllldr_x64_template,
        temp.path().join("agent/demon/payloads/DllLdr.x64.bin")
    );
    assert_eq!(service.inner.stager_template, temp.path().join("payloads/templates/MainStager.c"));
    assert_eq!(service.inner.default_demon, profile.demon);
    Ok(())
}

#[test]
fn from_profile_rejects_missing_toolchain_binary() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x64 = temp.path().join("bin/missing-x64-gcc");
    let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
    let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
    create_payload_assets(temp.path())?;
    let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);

    let error = PayloadBuilderService::from_profile_with_repo_root(&profile, temp.path())
        .expect_err("missing compiler should be rejected");

    assert!(matches!(
        error,
        PayloadBuildError::ToolchainUnavailable { message }
            if message.contains("executable does not exist")
                && message.contains("missing-x64-gcc")
    ));
    Ok(())
}

#[test]
fn from_profile_with_repo_root_resolves_relative_toolchain_paths_against_repo_root()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x64 = write_fake_gcc(
        &temp.path().join("data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"),
    )?;
    let compiler_x86 =
        write_fake_gcc(&temp.path().join("data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"))?;
    let nasm = write_fake_nasm(&temp.path().join("data/nasm/bin/nasm"))?;
    create_payload_assets(temp.path())?;
    let profile = constructor_test_profile(
        Path::new("data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"),
        Path::new("data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"),
        Path::new("data/nasm/bin/nasm"),
    );

    let service = PayloadBuilderService::from_profile_with_repo_root_impl(
        &profile,
        temp.path(),
        read_fake_script_output,
    )?;

    assert_eq!(service.inner.toolchain.compiler_x64, compiler_x64.canonicalize()?);
    assert_eq!(service.inner.toolchain.compiler_x86, compiler_x86.canonicalize()?);
    assert_eq!(service.inner.toolchain.nasm, nasm.canonicalize()?);
    Ok(())
}

#[test]
fn from_profile_with_repo_root_reports_missing_relative_toolchain_from_repo_root()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x86 =
        write_fake_gcc(&temp.path().join("data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"))?;
    let nasm = write_fake_nasm(&temp.path().join("data/nasm/bin/nasm"))?;
    create_payload_assets(temp.path())?;
    let missing_relative = Path::new("data/x86_64-w64-mingw32-cross/bin/missing-gcc");
    let profile = constructor_test_profile(missing_relative, &compiler_x86, &nasm);

    let error = PayloadBuilderService::from_profile_with_repo_root(&profile, temp.path())
        .expect_err("missing relative compiler should be rejected");

    let expected = temp.path().join(missing_relative);
    assert!(matches!(
        error,
        PayloadBuildError::ToolchainUnavailable { message }
            if message.contains("executable does not exist")
                && message.contains(&expected.display().to_string())
    ));
    Ok(())
}

#[test]
fn from_profile_rejects_missing_payload_assets() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
    let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
    let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
    create_payload_assets(temp.path())?;
    std::fs::remove_file(temp.path().join("agent/demon/payloads/Shellcode.x86.bin"))?;
    let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);

    let error = PayloadBuilderService::from_profile_with_repo_root_impl(
        &profile,
        temp.path(),
        read_fake_script_output,
    )
    .expect_err("missing asset should be rejected");

    assert!(matches!(
        error,
        PayloadBuildError::ToolchainUnavailable { message }
            if message.contains("required payload asset missing")
                && message.contains("Shellcode.x86.bin")
    ));
    Ok(())
}

#[test]
fn from_profile_rejects_outdated_gcc() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x64 = write_fake_executable_with_output(
        &temp.path().join("bin/x64-gcc"),
        "x86_64-w64-mingw32-gcc (GCC) 8.3.0 (Release)",
    )?;
    let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
    let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
    create_payload_assets(temp.path())?;
    let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);

    let error = PayloadBuilderService::from_profile_with_repo_root_impl(
        &profile,
        temp.path(),
        read_fake_script_output,
    )
    .expect_err("outdated gcc should be rejected");

    assert!(matches!(
        error,
        PayloadBuildError::ToolchainUnavailable { message }
            if message.contains("below the minimum required")
                && message.contains("8.3.0")
    ));
    Ok(())
}

#[test]
fn from_profile_rejects_outdated_nasm() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
    let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
    let nasm = write_fake_executable_with_output(
        &temp.path().join("bin/nasm"),
        "NASM version 2.10.07 compiled on Jan  1 2015",
    )?;
    create_payload_assets(temp.path())?;
    let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);

    let error = PayloadBuilderService::from_profile_with_repo_root_impl(
        &profile,
        temp.path(),
        read_fake_script_output,
    )
    .expect_err("outdated nasm should be rejected");

    assert!(matches!(
        error,
        PayloadBuildError::ToolchainUnavailable { message }
            if message.contains("below the minimum required")
                && message.contains("2.10.07")
    ));
    Ok(())
}
