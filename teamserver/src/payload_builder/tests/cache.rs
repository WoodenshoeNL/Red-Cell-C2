use std::path::PathBuf;

use super::*;

fn test_cache_key(hex: &str, ext: &'static str) -> CacheKey {
    CacheKey { hex: hex.to_owned(), ext }
}

#[test]
fn cache_accessor_returns_consistent_handle() {
    let svc = PayloadBuilderService::disabled_for_tests();
    let c1 = svc.cache();
    let c2 = svc.cache();
    // Both references must point to the same underlying cache (same
    // cache_dir). This catches accidental reconstructions or field swaps.
    assert_eq!(c1.cache_dir, c2.cache_dir);
    assert!(std::ptr::eq(c1, c2), "cache() should return the same reference each call");
}

#[test]
fn cache_accessor_safe_before_any_build() {
    // Calling cache() on a freshly constructed service must not panic,
    // even though no payload has ever been built.
    let svc = PayloadBuilderService::disabled_for_tests();
    let cache = svc.cache();
    // The cache dir should be the one configured by disabled_for_tests().
    assert_eq!(cache.cache_dir, PathBuf::from("/nonexistent/payload-cache"));
}

#[tokio::test]
async fn cache_accessor_observes_external_mutations() {
    let temp = TempDir::new().expect("unwrap");
    let cache_dir = temp.path().join("payload-cache");
    let svc = PayloadBuilderService::with_paths_for_tests(
        Toolchain {
            compiler_x64: PathBuf::from("/nonexistent/x64-gcc"),
            compiler_x64_version: ToolchainVersion {
                major: 0,
                minor: 0,
                patch: 0,
                raw: "0.0.0".to_owned(),
            },
            compiler_x86: PathBuf::from("/nonexistent/x86-gcc"),
            compiler_x86_version: ToolchainVersion {
                major: 0,
                minor: 0,
                patch: 0,
                raw: "0.0.0".to_owned(),
            },
            nasm: PathBuf::from("/nonexistent/nasm"),
            nasm_version: ToolchainVersion {
                major: 0,
                minor: 0,
                patch: 0,
                raw: "0.0.0".to_owned(),
            },
        },
        PathBuf::from("/nonexistent/src"),
        PathBuf::from("/nonexistent/archon"),
        PathBuf::from("/nonexistent/sc64"),
        PathBuf::from("/nonexistent/sc86"),
        PathBuf::from("/nonexistent/dllldr"),
        PathBuf::from("/nonexistent/stager"),
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
        cache_dir.clone(),
    );

    // Populate the cache through the accessor-returned handle.
    let key = test_cache_key("aabbccdd", ".bin");
    svc.cache().put(&key, b"test-payload").await;

    // Read back through the same accessor — proves mutations are visible.
    let got = svc.cache().get(&key).await.expect("should read back cached artifact");
    assert_eq!(got, b"test-payload");

    // Flush through the accessor and verify the cache is empty.
    let removed = svc.cache().flush().await.expect("flush should succeed");
    assert_eq!(removed, 1);
    assert!(svc.cache().get(&key).await.is_none(), "cache should be empty after flush");
}
