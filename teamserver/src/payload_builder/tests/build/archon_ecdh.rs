use super::*;

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
