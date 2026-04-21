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
mod tests;
