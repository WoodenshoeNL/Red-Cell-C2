//! Content-addressed on-disk cache for compiled payload artifacts.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use red_cell_common::config::BinaryConfig;

use super::formats::{Architecture, OutputFormat};

/// Content-addressed on-disk cache for compiled Demon payload artifacts.
///
/// Cache entries live at `<cache_dir>/<sha256_hex>.<ext>` and are keyed by a
/// SHA-256 hash that covers the teamserver version, target architecture, output
/// format, packed binary config, and binary-patch configuration.
///
/// All cache errors are non-fatal: a miss or a write failure is logged and the
/// builder falls through to a full compilation.
#[derive(Clone, Debug)]
pub struct PayloadCache {
    pub(super) cache_dir: PathBuf,
}

impl PayloadCache {
    pub(super) fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    pub(super) fn artifact_path(&self, key: &CacheKey) -> PathBuf {
        self.cache_dir.join(format!("{}{}", key.hex, key.ext))
    }

    /// Look up a cache entry. Returns `None` on miss or any I/O error.
    pub(super) async fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let path = self.artifact_path(key);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                tracing::debug!(path = %path.display(), "payload cache hit");
                Some(bytes)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "payload cache read failed; treating as cache miss"
                );
                None
            }
        }
    }

    /// Persist bytes in the cache. Errors are logged but not propagated.
    ///
    /// Uses atomic write (write to temporary file, then rename) so that
    /// concurrent readers never observe a partially-written or truncated file.
    pub(super) async fn put(&self, key: &CacheKey, bytes: &[u8]) {
        if let Err(err) = tokio::fs::create_dir_all(&self.cache_dir).await {
            tracing::warn!(
                dir = %self.cache_dir.display(),
                error = %err,
                "could not create payload cache directory; skipping cache write"
            );
            return;
        }
        let path = self.artifact_path(key);
        let dir = self.cache_dir.clone();
        let num_bytes = bytes.len();
        let bytes = bytes.to_vec();
        let dest = path.clone();

        // Perform the blocking tempfile + write + persist on the blocking pool
        // so we get atomic rename semantics without blocking the async runtime.
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write;
            let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
            tmp.write_all(&bytes)?;
            tmp.persist(&dest)?;
            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => tracing::debug!(
                path = %path.display(),
                bytes = num_bytes,
                "payload artifact cached"
            ),
            Ok(Err(err)) => tracing::warn!(
                path = %path.display(),
                error = %err,
                "failed to write payload cache entry"
            ),
            Err(err) => tracing::warn!(
                path = %path.display(),
                error = %err,
                "payload cache write task panicked"
            ),
        }
    }

    /// Remove every file in the cache directory and return the count removed.
    ///
    /// Returns `Ok(0)` if the cache directory does not exist.
    /// Per-entry removal errors are logged but do not stop the flush.
    pub async fn flush(&self) -> std::io::Result<u64> {
        let mut dir = match tokio::fs::read_dir(&self.cache_dir).await {
            Ok(dir) => dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(err),
        };
        let mut count = 0u64;
        while let Some(entry) = dir.next_entry().await? {
            match tokio::fs::remove_file(entry.path()).await {
                Ok(()) => count += 1,
                Err(err) => tracing::warn!(
                    path = %entry.path().display(),
                    error = %err,
                    "failed to remove payload cache entry during flush"
                ),
            }
        }
        Ok(count)
    }
}

/// Internal cache key used to address a compiled artifact.
pub(super) struct CacheKey {
    /// Lower-case hex SHA-256 digest of all build inputs.
    pub(super) hex: String,
    /// File extension for this artifact type (e.g. `.exe`).
    pub(super) ext: &'static str,
}

/// Compute a content-addressed cache key for a payload build.
///
/// The hash covers every input that determines the compiled output:
/// - Teamserver version (from `CARGO_PKG_VERSION`)
/// - Agent variant name (e.g. `"demon"`, `"archon"`) — ensures that builds
///   for different agent types never collide even when all other inputs match
/// - Target architecture
/// - Output format
/// - Packed binary config bytes embedded in the PE
/// - Binary-patch configuration applied after compilation
pub(super) fn compute_cache_key(
    agent_name: &str,
    arch: Architecture,
    format: OutputFormat,
    config_bytes: &[u8],
    binary_patch: Option<&BinaryConfig>,
) -> Result<CacheKey, serde_json::Error> {
    let mut hasher = Sha256::new();
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(b"\x00");
    hasher.update(agent_name.as_bytes());
    hasher.update(b"\x00");
    hasher.update(arch.suffix().as_bytes());
    hasher.update(b"\x00");
    hasher.update(format.cache_tag().as_bytes());
    hasher.update(b"\x00");
    hasher.update(config_bytes);
    hasher.update(b"\x00");
    if let Some(patch) = binary_patch {
        // serde_json serialization is deterministic for the same data.
        let patch_json = serde_json::to_string(patch)?;
        hasher.update(patch_json.as_bytes());
    }
    let hex = format!("{:x}", hasher.finalize());
    Ok(CacheKey { hex, ext: format.file_extension() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::config::HeaderConfig;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn test_cache_key(hex: &str, ext: &'static str) -> CacheKey {
        CacheKey { hex: hex.to_owned(), ext }
    }

    // ── compute_cache_key tests ──────────────────────────────────────────

    #[test]
    fn compute_cache_key_differs_by_architecture() {
        let config_bytes = b"config";
        let key_x64 =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config_bytes, None)
                .expect("unwrap");
        let key_x86 =
            compute_cache_key("demon", Architecture::X86, OutputFormat::Exe, config_bytes, None)
                .expect("unwrap");
        assert_ne!(key_x64.hex, key_x86.hex, "x64 and x86 must produce different cache keys");
    }

    #[test]
    fn compute_cache_key_differs_by_format() {
        let config_bytes = b"config";
        let key_exe =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config_bytes, None)
                .expect("unwrap");
        let key_dll =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Dll, config_bytes, None)
                .expect("unwrap");
        assert_ne!(key_exe.hex, key_dll.hex, "Exe and Dll must produce different cache keys");
    }

    #[test]
    fn compute_cache_key_differs_by_config_bytes() {
        let key_a =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"config-a", None)
                .expect("unwrap");
        let key_b =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"config-b", None)
                .expect("unwrap");
        assert_ne!(
            key_a.hex, key_b.hex,
            "different config bytes must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_ext_matches_format() {
        let key_exe = compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"c", None)
            .expect("unwrap");
        let key_bin =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Shellcode, b"c", None)
                .expect("unwrap");
        assert_eq!(key_exe.ext, ".exe");
        assert_eq!(key_bin.ext, ".bin");
    }

    #[test]
    fn compute_cache_key_deterministic() {
        let a = compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"same", None)
            .expect("unwrap");
        let b = compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"same", None)
            .expect("unwrap");
        assert_eq!(a.hex, b.hex, "identical inputs must produce the same cache key");
    }

    #[test]
    fn compute_cache_key_differs_by_binary_patch_presence() {
        let patch = BinaryConfig {
            header: None,
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let key_none =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"cfg", None)
                .expect("unwrap");
        let key_some =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"cfg", Some(&patch))
                .expect("unwrap");
        assert_ne!(
            key_none.hex, key_some.hex,
            "present vs absent binary_patch must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_differs_by_binary_patch_content() {
        let patch_a = BinaryConfig {
            header: None,
            replace_strings_x64: [("old".into(), "new-a".into())].into_iter().collect(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let patch_b = BinaryConfig {
            header: None,
            replace_strings_x64: [("old".into(), "new-b".into())].into_iter().collect(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let key_a = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_a),
        )
        .expect("unwrap");
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .expect("unwrap");
        assert_ne!(
            key_a.hex, key_b.hex,
            "different binary_patch content must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_differs_by_header_fields() {
        let patch_a = BinaryConfig {
            header: Some(HeaderConfig {
                magic_mz_x64: Some("MZ-A".into()),
                magic_mz_x86: None,
                compile_time: None,
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let patch_b = BinaryConfig {
            header: Some(HeaderConfig {
                magic_mz_x64: Some("MZ-B".into()),
                magic_mz_x86: None,
                compile_time: None,
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let key_a = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_a),
        )
        .expect("unwrap");
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .expect("unwrap");
        assert_ne!(
            key_a.hex, key_b.hex,
            "different header magic_mz_x64 must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_differs_by_header_compile_time() {
        let patch_a = BinaryConfig {
            header: Some(HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: Some("2024-01-01".into()),
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let patch_b = BinaryConfig {
            header: Some(HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: Some("2025-06-15".into()),
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let key_a = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_a),
        )
        .expect("unwrap");
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .expect("unwrap");
        assert_ne!(
            key_a.hex, key_b.hex,
            "different header compile_time must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_differs_by_header_image_size() {
        let patch_a = BinaryConfig {
            header: Some(HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: None,
                image_size_x64: Some(0x1000),
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let patch_b = BinaryConfig {
            header: Some(HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: None,
                image_size_x64: Some(0x2000),
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let key_a = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_a),
        )
        .expect("unwrap");
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .expect("unwrap");
        assert_ne!(
            key_a.hex, key_b.hex,
            "different header image_size_x64 must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_differs_by_replace_strings_x86() {
        let patch_a = BinaryConfig {
            header: None,
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: [("old".into(), "new-a".into())].into_iter().collect(),
        };
        let patch_b = BinaryConfig {
            header: None,
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: [("old".into(), "new-b".into())].into_iter().collect(),
        };
        let key_a = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_a),
        )
        .expect("unwrap");
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .expect("unwrap");
        assert_ne!(
            key_a.hex, key_b.hex,
            "different replace_strings_x86 must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_stable_for_identical_binary_patch() {
        let patch = BinaryConfig {
            header: Some(HeaderConfig {
                magic_mz_x64: Some("MZ".into()),
                magic_mz_x86: Some("MZ86".into()),
                compile_time: Some("2025-01-01".into()),
                image_size_x64: Some(0x1000),
                image_size_x86: Some(0x800),
            }),
            replace_strings_x64: [("a".into(), "b".into()), ("c".into(), "d".into())]
                .into_iter()
                .collect(),
            replace_strings_x86: [("e".into(), "f".into())].into_iter().collect(),
        };
        let key_1 =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"cfg", Some(&patch))
                .expect("unwrap");
        let key_2 =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"cfg", Some(&patch))
                .expect("unwrap");
        assert_eq!(
            key_1.hex, key_2.hex,
            "identical binary_patch configs must produce identical cache keys"
        );
    }

    #[test]
    fn compute_cache_key_all_dimensions_distinct() {
        use std::collections::HashSet;

        let patch = BinaryConfig {
            header: None,
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        };
        let config = b"cfg";

        // Generate keys varying exactly one dimension at a time from a baseline.
        let keys: Vec<String> = vec![
            // baseline
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config, None)
                .expect("unwrap")
                .hex,
            // vary arch
            compute_cache_key("demon", Architecture::X86, OutputFormat::Exe, config, None)
                .expect("unwrap")
                .hex,
            // vary format
            compute_cache_key("demon", Architecture::X64, OutputFormat::Dll, config, None)
                .expect("unwrap")
                .hex,
            compute_cache_key("demon", Architecture::X64, OutputFormat::ServiceExe, config, None)
                .expect("unwrap")
                .hex,
            compute_cache_key(
                "demon",
                Architecture::X64,
                OutputFormat::ReflectiveDll,
                config,
                None,
            )
            .expect("unwrap")
            .hex,
            compute_cache_key("demon", Architecture::X64, OutputFormat::Shellcode, config, None)
                .expect("unwrap")
                .hex,
            compute_cache_key(
                "demon",
                Architecture::X64,
                OutputFormat::StagedShellcode,
                config,
                None,
            )
            .expect("unwrap")
            .hex,
            compute_cache_key("demon", Architecture::X64, OutputFormat::RawShellcode, config, None)
                .expect("unwrap")
                .hex,
            // vary config bytes
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"other", None)
                .expect("unwrap")
                .hex,
            // vary binary_patch
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config, Some(&patch))
                .expect("unwrap")
                .hex,
        ];

        let unique: HashSet<&str> = keys.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            unique.len(),
            keys.len(),
            "all cache keys must be distinct; got {} unique out of {}",
            unique.len(),
            keys.len()
        );
    }

    #[test]
    fn compute_cache_key_differs_by_agent_name() {
        let config_bytes = b"config";
        let key_demon =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config_bytes, None)
                .expect("unwrap");
        let key_archon =
            compute_cache_key("archon", Architecture::X64, OutputFormat::Exe, config_bytes, None)
                .expect("unwrap");
        assert_ne!(
            key_demon.hex, key_archon.hex,
            "demon and archon must produce different cache keys for identical other inputs"
        );
    }

    // ── PayloadCache isolated unit tests ────────────────────────────────

    #[test]
    fn artifact_path_concatenates_hex_and_extension() {
        let cache = PayloadCache::new(PathBuf::from("/tmp/cache"));
        let key = test_cache_key("abcdef01", ".exe");
        assert_eq!(cache.artifact_path(&key), PathBuf::from("/tmp/cache/abcdef01.exe"));
    }

    #[test]
    fn artifact_path_bin_extension() {
        let cache = PayloadCache::new(PathBuf::from("/tmp/cache"));
        let key = test_cache_key("0123456789abcdef", ".bin");
        assert_eq!(cache.artifact_path(&key), PathBuf::from("/tmp/cache/0123456789abcdef.bin"));
    }

    #[test]
    fn artifact_path_dll_extension() {
        let cache = PayloadCache::new(PathBuf::from("/tmp/cache"));
        let key = test_cache_key("ff", ".dll");
        assert_eq!(cache.artifact_path(&key), PathBuf::from("/tmp/cache/ff.dll"));
    }

    #[tokio::test]
    async fn get_returns_none_for_absent_key() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("nonexistent", ".exe");
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn put_then_get_round_trips_bytes() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("deadbeef", ".dll");
        let payload = b"MZ\x90\x00payload-bytes";

        cache.put(&key, payload).await;

        let got = cache.get(&key).await.expect("cache hit expected after put");
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn get_returns_none_when_cache_dir_missing() {
        let temp = TempDir::new().expect("unwrap");
        // Point at a sub-directory that does not exist.
        let cache = PayloadCache::new(temp.path().join("does-not-exist"));
        let key = test_cache_key("abc", ".bin");
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn flush_then_get_returns_none() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("flushme", ".exe");

        cache.put(&key, b"data").await;
        assert!(cache.get(&key).await.is_some(), "should be present before flush");

        cache.flush().await.expect("flush should succeed");
        assert!(cache.get(&key).await.is_none(), "should be gone after flush");
    }

    #[tokio::test]
    async fn put_creates_cache_dir_if_absent() {
        let temp = TempDir::new().expect("unwrap");
        let nested = temp.path().join("sub/dir");
        let cache = PayloadCache::new(nested.clone());
        let key = test_cache_key("cafebabe", ".bin");

        cache.put(&key, b"shellcode").await;

        assert!(nested.exists(), "put should create the cache directory");
        let got = cache.get(&key).await.expect("should read back after put");
        assert_eq!(got, b"shellcode");
    }

    #[tokio::test]
    async fn distinct_keys_do_not_collide() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let k1 = test_cache_key("samehex", ".exe");
        let k2 = test_cache_key("samehex", ".dll");

        cache.put(&k1, b"exe-bytes").await;
        cache.put(&k2, b"dll-bytes").await;

        assert_eq!(cache.get(&k1).await.expect("unwrap"), b"exe-bytes");
        assert_eq!(cache.get(&k2).await.expect("unwrap"), b"dll-bytes");
    }

    // ── PayloadCache edge-case & concurrency tests ─────────────────────

    #[tokio::test]
    async fn get_returns_truncated_bytes_from_corrupted_cache_entry() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("corrupt01", ".exe");

        // Simulate a full artifact write followed by on-disk truncation
        // (e.g. disk full during a previous `put`).
        let original = b"MZ\x90\x00FULL-PAYLOAD-CONTENT-HERE";
        cache.put(&key, original).await;

        // Manually truncate the cached file to simulate corruption.
        let path = cache.artifact_path(&key);
        let truncated = &original[..4]; // only the MZ header stub
        tokio::fs::write(&path, truncated).await.expect("unwrap");

        // `get` performs no integrity validation — it returns whatever bytes
        // are on disk, even if they are shorter than the original artifact.
        let got = cache.get(&key).await.expect("file exists, so get returns Some");
        assert_eq!(got, truncated, "get should return the truncated bytes verbatim");
        assert_ne!(got.len(), original.len(), "truncated content differs from original");
    }

    #[tokio::test]
    async fn get_returns_empty_bytes_for_zero_length_cache_file() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("empty01", ".bin");

        // Create a zero-length file (worst-case truncation).
        tokio::fs::create_dir_all(temp.path()).await.expect("unwrap");
        tokio::fs::write(cache.artifact_path(&key), b"").await.expect("unwrap");

        let got = cache.get(&key).await.expect("file exists, so get returns Some");
        assert!(got.is_empty(), "zero-length cached file should return empty bytes");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn put_succeeds_gracefully_when_cache_dir_is_read_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("unwrap");
        let cache_dir = temp.path().join("readonly-cache");
        std::fs::create_dir_all(&cache_dir).expect("unwrap");

        // Pre-populate one entry so we can verify reads still work.
        let pre_key = test_cache_key("preexist", ".exe");
        let cache = PayloadCache::new(cache_dir.clone());
        cache.put(&pre_key, b"existing-data").await;

        // Make the directory read-only.
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o555))
            .expect("unwrap");

        // Writing to a read-only directory should fail gracefully (no panic).
        let key = test_cache_key("readonly01", ".bin");
        cache.put(&key, b"should-not-persist").await; // must not panic

        // The failed write should not have created the file.
        assert!(
            cache.get(&key).await.is_none(),
            "put to read-only dir should not create a cache entry"
        );

        // Pre-existing entries should still be readable.
        let got = cache.get(&pre_key).await.expect("pre-existing entry should still be readable");
        assert_eq!(got, b"existing-data");

        // Restore permissions so TempDir cleanup succeeds.
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o755))
            .expect("unwrap");
    }

    #[tokio::test]
    async fn concurrent_puts_with_same_key_both_succeed() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key_hex = "racekey01";
        let ext = ".dll";

        let payload_a = vec![0xAAu8; 1024];
        let payload_b = vec![0xBBu8; 1024];

        // Spawn two concurrent puts with the same cache key.
        let cache_a = cache.clone();
        let cache_b = cache.clone();
        let pa = payload_a.clone();
        let pb = payload_b.clone();

        let ((), ()) = tokio::join!(
            async move {
                let k = test_cache_key(key_hex, ext);
                cache_a.put(&k, &pa).await;
            },
            async move {
                let k = test_cache_key(key_hex, ext);
                cache_b.put(&k, &pb).await;
            },
        );

        // Neither put should panic or error.
        // The file should contain one of the two payloads (last-writer-wins).
        let key = test_cache_key(key_hex, ext);
        let got = cache.get(&key).await.expect("cache entry should exist after concurrent puts");
        assert!(
            got == payload_a || got == payload_b,
            "cached bytes must be one of the two payloads, not a mix"
        );
        assert_eq!(got.len(), 1024, "cached artifact must not be partially written");
    }

    #[tokio::test]
    async fn concurrent_put_and_get_does_not_panic() {
        let temp = TempDir::new().expect("unwrap");
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key_hex = "racerw01";
        let ext = ".exe";
        let payload = vec![0xCCu8; 2048];

        // Pre-populate so the reader has something to find.
        let pre_key = test_cache_key(key_hex, ext);
        cache.put(&pre_key, &payload).await;

        let cache_w = cache.clone();
        let cache_r = cache.clone();
        let pw = payload.clone();

        // Run a put and a get concurrently against the same key.
        let ((), read_result) = tokio::join!(
            async move {
                let k = test_cache_key(key_hex, ext);
                cache_w.put(&k, &pw).await;
            },
            async move {
                let k = test_cache_key(key_hex, ext);
                cache_r.get(&k).await
            },
        );

        // The get may return the old or new data — either is acceptable.
        // The critical property is that neither operation panics and the
        // file is not left in an invalid intermediate state.
        if let Some(bytes) = read_result {
            assert_eq!(bytes.len(), 2048, "read bytes must be complete, not partially written");
        }
        // If read_result is None, the file was briefly absent during the write — also acceptable.
    }

    // ── PayloadCache flush tests ─────────────────────────────────────────

    #[tokio::test]
    async fn payload_cache_flush_removes_all_entries() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let cache_dir = temp.path().join("payload-cache");
        tokio::fs::create_dir_all(&cache_dir).await?;

        // Write a few fake entries.
        tokio::fs::write(cache_dir.join("aabbcc.exe"), b"artifact-1").await?;
        tokio::fs::write(cache_dir.join("ddeeff.dll"), b"artifact-2").await?;
        tokio::fs::write(cache_dir.join("112233.bin"), b"artifact-3").await?;

        let cache = PayloadCache::new(cache_dir.clone());
        let removed = cache.flush().await?;
        assert_eq!(removed, 3, "flush should remove all three entries");

        let mut dir = tokio::fs::read_dir(&cache_dir).await?;
        assert!(dir.next_entry().await?.is_none(), "cache directory should be empty after flush");
        Ok(())
    }

    #[tokio::test]
    async fn payload_cache_flush_returns_zero_for_nonexistent_dir()
    -> Result<(), Box<dyn std::error::Error>> {
        let cache = PayloadCache::new(PathBuf::from("/nonexistent/no/such/cache-dir"));
        let removed = cache.flush().await?;
        assert_eq!(removed, 0);
        Ok(())
    }
}
