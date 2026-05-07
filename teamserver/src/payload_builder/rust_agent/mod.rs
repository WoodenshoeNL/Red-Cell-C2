//! Rust-based agent build pipeline (Phantom, Specter).
//!
//! Extracted from `payload_builder/mod.rs` to keep the module focused on the
//! Demon C/ASM build pipeline while isolating the `cargo build`-based flow for
//! Rust agents.

use std::path::Path;
use std::process::Stdio;

use sha2::{Digest, Sha256};
use tokio::process::Command;

use red_cell_common::ListenerConfig;
use red_cell_common::config::DemonConfig;
use red_cell_common::operator::CompilerDiagnostic;

use super::cache::CacheKey;
use super::{
    BuildProgress, MAX_STDERR_TAIL_LINES, PayloadArtifact, PayloadBuildError,
    PayloadBuilderService, append_manifest, build_manifest, workspace_root,
};

mod env;
mod url;

use env::{
    clear_inherited_rust_agent_bake_env, pinned_cert_pem_for_rust_listener, rust_agent_env_vars,
};

impl PayloadBuilderService {
    /// Compile a Rust-based agent (Phantom / Specter) via `cargo build --release`.
    ///
    /// The listener configuration is passed to the agent binary via environment
    /// variables so it can be embedded at compile time (`option_env!`) or read
    /// at runtime.  The resulting release binary is read from the cargo target
    /// directory and returned as the payload artifact.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn build_rust_agent<F>(
        &self,
        listener: &ListenerConfig,
        agent_name: &str,
        source_root: &Path,
        target_triple: &str,
        file_extension: &'static str,
        listener_pub_key: Option<[u8; 32]>,
        demon: &DemonConfig,
        progress: &mut F,
    ) -> Result<PayloadArtifact, PayloadBuildError>
    where
        F: FnMut(BuildProgress),
    {
        if !source_root.exists() {
            return Err(PayloadBuildError::ToolchainUnavailable {
                message: format!(
                    "{} source tree not found at {}",
                    agent_name,
                    source_root.display()
                ),
            });
        }

        // Derive the environment variable prefix from the agent name
        // (e.g. "phantom" → "PHANTOM", "specter" → "SPECTER").
        let env_prefix = agent_name.to_ascii_uppercase();

        // The TLS cert PEM is the only env-var input that requires async I/O.
        // Read it here so rust_agent_env_vars() stays pure/sync and trivially
        // unit-testable. A configured PEM path must be readable — otherwise the
        // build fails instead of succeeding with pinning silently omitted.
        let pinned_cert_pem = pinned_cert_pem_for_rust_listener(listener).await?;

        let env_vars =
            rust_agent_env_vars(listener, &env_prefix, demon, listener_pub_key, pinned_cert_pem)?;

        // Compute a cache key covering the agent type, target, and listener config.
        let cache_input =
            env_vars.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n");
        let cache_key = CacheKey {
            hex: {
                let mut hasher = Sha256::new();
                hasher.update(agent_name.as_bytes());
                hasher.update(b"\0");
                hasher.update(target_triple.as_bytes());
                hasher.update(b"\0");
                hasher.update(cache_input.as_bytes());
                format!("{:x}", hasher.finalize())
            },
            ext: file_extension,
        };

        if let Some(cached) = self.inner.cache.get(&cache_key).await {
            progress(BuildProgress {
                level: "Info".to_owned(),
                message: "cache hit — returning cached artifact".to_owned(),
            });
            return Ok(PayloadArtifact {
                bytes: cached,
                file_name: format!("{agent_name}{file_extension}"),
                format: format!("{agent_name} release"),
                export_name: None,
            });
        }

        progress(BuildProgress {
            level: "Info".to_owned(),
            message: format!("building {agent_name} ({target_triple})"),
        });

        let mut cmd = Command::new("cargo");
        cmd.arg("build")
            .arg("--release")
            .arg("--target")
            .arg(target_triple)
            .current_dir(source_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // `option_env!` / `parse_compile_env` in Phantom/Specter read rustc's
        // environment.  Cargo forwards the parent process env; any stray
        // `PHANTOM_*` / `SPECTER_*` in the teamserver's environment (or a stale
        // shell export) would be baked in even when this build path omits
        // that key from `env_vars` — e.g. wrong kill date or sleep from a
        // previous operator session.  Clear known bake keys, then set exactly
        // what this listener/demon build requires.
        clear_inherited_rust_agent_bake_env(&mut cmd, &env_prefix);

        for (key, value) in &env_vars {
            cmd.env(key, value);
        }

        let child = cmd.spawn().map_err(|err| PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to spawn cargo build for {agent_name}: {err}"),
        })?;

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let diagnostics: Vec<CompilerDiagnostic> = stderr
                .lines()
                .filter_map(|line| {
                    if line.contains("error") || line.contains("warning") {
                        Some(CompilerDiagnostic {
                            severity: if line.contains("error") {
                                "error".to_owned()
                            } else {
                                "warning".to_owned()
                            },
                            filename: String::new(),
                            line: 0,
                            column: None,
                            error_code: None,
                            message: line.to_owned(),
                        })
                    } else {
                        None
                    }
                })
                .collect();

            for diag in &diagnostics {
                progress(BuildProgress {
                    level: "Error".to_owned(),
                    message: diag.message.clone(),
                });
            }

            let stderr_tail: Vec<String> = stderr
                .lines()
                .filter(|line| !line.trim().is_empty())
                .take(MAX_STDERR_TAIL_LINES)
                .map(str::to_owned)
                .collect();

            return Err(PayloadBuildError::CommandFailed {
                command: format!("cargo build --release --target {target_triple}"),
                diagnostics,
                stderr_tail,
            });
        }

        // The binary is produced at <workspace_root>/target/<triple>/release/<name>[.exe]
        let binary_name = if file_extension.is_empty() {
            agent_name.to_owned()
        } else {
            format!("{agent_name}{file_extension}")
        };
        let ws_root = workspace_root()?;
        let artifact_path =
            ws_root.join("target").join(target_triple).join("release").join(&binary_name);

        let mut bytes = tokio::fs::read(&artifact_path).await.map_err(|err| {
            PayloadBuildError::Io(std::io::Error::new(
                err.kind(),
                format!(
                    "failed to read compiled {} artifact at {}: {err}",
                    agent_name,
                    artifact_path.display()
                ),
            ))
        })?;

        progress(BuildProgress {
            level: "Info".to_owned(),
            message: format!("{agent_name} binary [{} bytes]", bytes.len()),
        });

        let agent_type_pascal = {
            let mut chars = agent_name.chars();
            match chars.next() {
                Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        };
        let format_label = if file_extension == ".exe" {
            "exe"
        } else if file_extension.is_empty() {
            "elf"
        } else {
            file_extension.trim_start_matches('.')
        };
        let manifest =
            build_manifest(listener, &agent_type_pascal, "x64", format_label, demon, None);
        append_manifest(&mut bytes, &manifest)?;

        progress(BuildProgress {
            level: "Good".to_owned(),
            message: "payload generated".to_owned(),
        });

        self.inner.cache.put(&cache_key, &bytes).await;

        Ok(PayloadArtifact {
            bytes,
            file_name: binary_name,
            format: format!("{agent_name} release"),
            export_name: None,
        })
    }
}

#[cfg(test)]
mod tests {
    // Mirrors the pascal-case conversion embedded in build_rust_agent so the
    // logic stays tested even though it is not a named function.
    fn to_pascal(name: &str) -> String {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
            None => String::new(),
        }
    }

    #[test]
    fn pascal_case_known_agents() {
        assert_eq!(to_pascal("phantom"), "Phantom");
        assert_eq!(to_pascal("specter"), "Specter");
        assert_eq!(to_pascal("archon"), "Archon");
    }

    #[test]
    fn pascal_case_empty_string() {
        assert_eq!(to_pascal(""), "");
    }

    #[test]
    fn pascal_case_single_char() {
        assert_eq!(to_pascal("a"), "A");
    }

    #[test]
    fn pascal_case_multibyte_first_char() {
        assert_eq!(to_pascal("\u{00e9}agent"), "\u{00e9}agent");
    }
}
