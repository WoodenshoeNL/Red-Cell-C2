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
use red_cell_common::operator::CompilerDiagnostic;

use super::cache::CacheKey;
use super::{
    BuildProgress, PayloadArtifact, PayloadBuildError, PayloadBuilderService, workspace_root,
};

impl PayloadBuilderService {
    /// Compile a Rust-based agent (Phantom / Specter) via `cargo build --release`.
    ///
    /// The listener configuration is passed to the agent binary via environment
    /// variables so it can be embedded at compile time (`option_env!`) or read
    /// at runtime.  The resulting release binary is read from the cargo target
    /// directory and returned as the payload artifact.
    pub(super) async fn build_rust_agent<F>(
        &self,
        listener: &ListenerConfig,
        agent_name: &str,
        source_root: &Path,
        target_triple: &str,
        file_extension: &'static str,
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

        let callback_url = rust_agent_callback_url(listener)?;

        // Derive the environment variable prefix from the agent name
        // (e.g. "phantom" → "PHANTOM", "specter" → "SPECTER").
        let env_prefix = agent_name.to_ascii_uppercase();

        // Build environment variables to pass listener config to the agent.
        let mut env_vars: Vec<(String, String)> = Vec::new();
        env_vars.push((format!("{env_prefix}_CALLBACK_URL"), callback_url));

        if let ListenerConfig::Http(http) = listener {
            if let Some(ua) = &http.user_agent {
                env_vars.push((format!("{env_prefix}_USER_AGENT"), ua.clone()));
            }
            // Read the TLS certificate PEM for compile-time pinning if available.
            if let Some(tls) = &http.cert {
                if let Ok(pem) = tokio::fs::read_to_string(&tls.cert).await {
                    env_vars.push((format!("{env_prefix}_PINNED_CERT_PEM"), pem));
                }
            }
        }

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

            return Err(PayloadBuildError::CommandFailed {
                command: format!("cargo build --release --target {target_triple}"),
                diagnostics,
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

        let bytes = tokio::fs::read(&artifact_path).await.map_err(|err| {
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

/// Build the callback URL that a Rust agent should use from the listener config.
fn rust_agent_callback_url(listener: &ListenerConfig) -> Result<String, PayloadBuildError> {
    match listener {
        ListenerConfig::Http(http) => {
            let scheme = if http.secure { "https" } else { "http" };
            let port = http.port_conn.unwrap_or(http.port_bind);
            let host = http.hosts.first().map(|h| h.as_str()).unwrap_or("127.0.0.1");
            // Strip an existing port suffix if the host entry already includes one.
            let host_name = host
                .rsplit_once(':')
                .and_then(|(name, p)| p.parse::<u16>().ok().map(|_| name))
                .unwrap_or(host);
            Ok(format!("{scheme}://{host_name}:{port}/"))
        }
        other => Err(PayloadBuildError::InvalidRequest {
            message: format!(
                "{} listeners are not supported for Rust agent payload builds",
                other.protocol()
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::HttpListenerConfig;

    #[test]
    fn rust_agent_callback_url_builds_https_url() -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "https-listener".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.example.com:8443".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 443,
            port_conn: Some(8443),
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
            legacy_mode: false,
        }));
        let url = rust_agent_callback_url(&listener)?;
        assert_eq!(url, "https://c2.example.com:8443/");
        Ok(())
    }

    #[test]
    fn rust_agent_callback_url_builds_http_url_with_default_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http-listener".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["10.0.0.1".to_owned()],
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
            legacy_mode: false,
        }));
        let url = rust_agent_callback_url(&listener)?;
        assert_eq!(url, "http://10.0.0.1:80/");
        Ok(())
    }

    #[test]
    fn rust_agent_callback_url_falls_back_to_localhost_when_no_hosts()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "empty-hosts".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: Vec::new(),
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
            legacy_mode: false,
        }));
        let url = rust_agent_callback_url(&listener)?;
        assert_eq!(url, "https://127.0.0.1:443/");
        Ok(())
    }

    #[test]
    fn rust_agent_callback_url_rejects_smb_listener() {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pipe".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let err = rust_agent_callback_url(&listener).expect_err("SMB listener should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
    }
}
