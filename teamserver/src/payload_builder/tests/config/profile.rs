use super::*;

// ── merged_request_config profile default tests ──────────────────────

#[test]
fn merged_request_config_applies_profile_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Injection":{"Alloc":"Win32","Execute":"Win32"}}"#,
        "demon",
        &DemonConfig {
            sleep: Some(10),
            jitter: Some(25),
            indirect_syscall: true,
            stack_duplication: true,
            sleep_technique: Some("Ekko".to_owned()),
            proxy_loading: Some("RtlCreateTimer".to_owned()),
            amsi_etw_patching: Some("Hardware breakpoints".to_owned()),
            injection: Some(red_cell_common::config::ProcessInjectionConfig {
                spawn64: Some("C:\\Windows\\System32\\notepad.exe".to_owned()),
                spawn32: Some("C:\\Windows\\SysWOW64\\notepad.exe".to_owned()),
            }),
            dotnet_name_pipe: Some(r"\\.\pipe\red-cell-dotnet".to_owned()),
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
    )?;

    assert_eq!(config.get("Sleep"), Some(&Value::String("10".to_owned())));
    assert_eq!(config.get("Jitter"), Some(&Value::String("25".to_owned())));
    assert_eq!(config.get("Indirect Syscall"), Some(&Value::Bool(true)));
    assert_eq!(config.get("Stack Duplication"), Some(&Value::Bool(true)));
    assert_eq!(config.get("Sleep Technique"), Some(&Value::String("Ekko".to_owned())));
    assert_eq!(config.get("DotNetNamePipe"), None);
    assert_eq!(
        config["Injection"]["Spawn64"],
        Value::String("C:\\Windows\\System32\\notepad.exe".to_owned())
    );
    assert_eq!(
        config["Injection"]["Spawn32"],
        Value::String("C:\\Windows\\SysWOW64\\notepad.exe".to_owned())
    );
    Ok(())
}

// ── merged_request_config AMSI/ETW tests ────────────────────────────

#[test]
fn merged_request_config_archon_defaults_amsi_to_patch() -> Result<(), Box<dyn std::error::Error>> {
    // When AmsiEtw is absent from both request and profile, Archon
    // should default to "patch" (AMSIETW_PATCH_MEMORY = 2).
    let config = merged_request_config(
        r#"{}"#,
        "archon",
        &DemonConfig {
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
    )?;
    assert_eq!(
        config.get("Amsi/Etw Patch"),
        Some(&Value::String("patch".to_owned())),
        "Archon without an explicit AmsiEtw key should default to 'patch'"
    );
    Ok(())
}

#[test]
fn merged_request_config_archon_profile_amsi_overrides_default()
-> Result<(), Box<dyn std::error::Error>> {
    // An explicit profile value must take precedence over the Archon default.
    let config = merged_request_config(
        r#"{}"#,
        "archon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: Some("hwbp".to_owned()),
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
    )?;
    assert_eq!(
        config.get("Amsi/Etw Patch"),
        Some(&Value::String("hwbp".to_owned())),
        "explicit profile AmsiEtw must win over the Archon default"
    );
    Ok(())
}

#[test]
fn merged_request_config_demon_amsi_stays_none_by_default() -> Result<(), Box<dyn std::error::Error>>
{
    // For Demon, absence of AmsiEtw in the profile should leave it unset
    // (serialises to 0 = AMSIETW_PATCH_NONE in the agent config bytes).
    let config = merged_request_config(
        r#"{}"#,
        "demon",
        &DemonConfig {
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
    )?;
    assert_eq!(
        config.get("Amsi/Etw Patch"),
        None,
        "Demon without an explicit AmsiEtw key should leave the field absent"
    );
    Ok(())
}

// ── merged_request_config HeapEnc propagation ───────────────────────

#[test]
fn merged_request_config_propagates_heap_enc_false_from_profile_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "demon",
        &DemonConfig {
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
            heap_enc: false,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    assert_eq!(config.get("HeapEnc"), Some(&Value::Bool(false)));
    Ok(())
}

// ── merged_request_config Archon-only field propagation ─────────────

#[test]
fn merged_request_config_propagates_job_execution_from_archon_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "archon",
        &DemonConfig {
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
            job_execution: JobExecutionMode::Threadpool,
            stomp_dll: None,
        },
    )?;
    assert_eq!(config.get("JobExecution"), Some(&Value::String("threadpool".to_owned())));
    Ok(())
}

#[test]
fn merged_request_config_propagates_stomp_dll_from_archon_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "archon",
        &DemonConfig {
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
            stomp_dll: Some("WINMM.DLL".to_owned()),
        },
    )?;
    assert_eq!(config.get("StompDll"), Some(&Value::String("WINMM.DLL".to_owned())));
    Ok(())
}

#[test]
fn merged_request_config_does_not_propagate_archon_keys_for_demon()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "demon",
        &DemonConfig {
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
            job_execution: JobExecutionMode::Threadpool,
            stomp_dll: Some("WINMM.DLL".to_owned()),
        },
    )?;
    assert_eq!(config.get("JobExecution"), None);
    assert_eq!(config.get("StompDll"), None);
    Ok(())
}

// ── merged_request_config override tests ────────────────────────────

#[test]
fn merged_request_config_request_overrides_profile_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"20","Jitter":"50","Injection":{"Alloc":"Win32","Execute":"Win32"}}"#,
        "demon",
        &DemonConfig {
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
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    // Request values should override profile defaults.
    assert_eq!(config.get("Sleep"), Some(&Value::String("20".to_owned())));
    assert_eq!(config.get("Jitter"), Some(&Value::String("50".to_owned())));
    Ok(())
}

#[test]
fn merged_request_config_injection_spawn_overrides_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"custom64.exe","Spawn32":"custom32.exe"}}"#,
        "demon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: Some(red_cell_common::config::ProcessInjectionConfig {
                spawn64: Some("default64.exe".to_owned()),
                spawn32: Some("default32.exe".to_owned()),
            }),
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
    )?;
    assert_eq!(config["Injection"]["Spawn64"], Value::String("custom64.exe".to_owned()));
    assert_eq!(config["Injection"]["Spawn32"], Value::String("custom32.exe".to_owned()));
    Ok(())
}

// ── merged_request_config rejection tests ───────────────────────────

#[test]
fn merged_request_config_rejects_non_object_input() {
    let err = merged_request_config(
        r#""just a string""#,
        "demon",
        &DemonConfig {
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
    )
    .expect_err("non-object JSON should be rejected");
    assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
        if message.contains("JSON object")));
}
