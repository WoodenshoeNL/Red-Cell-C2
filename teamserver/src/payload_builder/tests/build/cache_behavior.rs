use super::*;

#[tokio::test]
async fn build_payload_returns_cached_artifact_on_second_request()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

    let first = service.build_payload(&listener, &request, None, |_| {}).await?;
    assert!(first.bytes.starts_with(b"payload"), "artifact must start with compiled payload");

    let mut hit_messages = Vec::new();
    let second = service
        .build_payload(&listener, &request, None, |m| hit_messages.push(m.message.clone()))
        .await?;
    assert!(
        second.bytes.starts_with(b"payload"),
        "cached artifact must start with compiled payload"
    );
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
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
    let (service, listener, request_x64) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;
    let request_x86 = BuildPayloadRequestInfo { arch: "x86".to_owned(), ..request_x64.clone() };

    let first = service.build_payload(&listener, &request_x64, None, |_| {}).await?;
    assert!(first.bytes.starts_with(b"payload"), "artifact must start with compiled payload");

    let mut hit_messages = Vec::new();
    service
        .build_payload(&listener, &request_x86, None, |m| hit_messages.push(m.message.clone()))
        .await
        .ok();
    assert!(
        !hit_messages.iter().any(|m| m.contains("cache hit")),
        "x86 build should not hit the x64 cache entry, got: {hit_messages:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_demon_and_archon_do_not_share_cache()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_demon = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'demon-bytes' > \"$1\"; break; fi; shift; done\n";

    let (service, listener, demon_request) = setup_build_fixture(&temp, nasm_ok, gcc_demon)?;

    let demon_artifact = service.build_payload(&listener, &demon_request, None, |_| {}).await?;
    assert!(
        demon_artifact.bytes.starts_with(b"demon-bytes"),
        "artifact must start with compiled payload"
    );

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

    let mut hit_messages = Vec::new();
    let _ = service
        .build_payload(&listener, &archon_request, None, |m| hit_messages.push(m.message.clone()))
        .await;

    assert!(
        !hit_messages.iter().any(|m| m.contains("cache hit")),
        "Archon build must not hit the Demon cache entry; messages: {hit_messages:?}"
    );
    Ok(())
}
