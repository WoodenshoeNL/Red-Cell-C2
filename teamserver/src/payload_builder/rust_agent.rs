//! Rust-based agent build pipeline (Phantom, Specter).
//!
//! Extracted from `payload_builder/mod.rs` to keep the module focused on the
//! Demon C/ASM build pipeline while isolating the `cargo build`-based flow for
//! Rust agents.

use std::path::Path;
use std::process::Stdio;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::process::Command;

use red_cell_common::ListenerConfig;
use red_cell_common::config::DemonConfig;
use red_cell_common::operator::CompilerDiagnostic;

use super::cache::CacheKey;
use super::config_values::{parse_kill_date, parse_working_hours};
use super::{
    BuildProgress, MAX_STDERR_TAIL_LINES, PayloadArtifact, PayloadBuildError,
    PayloadBuilderService, append_manifest, build_manifest, workspace_root,
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
        // unit-testable.
        let pinned_cert_pem = match listener {
            ListenerConfig::Http(http) => match &http.cert {
                Some(tls) => tokio::fs::read_to_string(&tls.cert).await.ok(),
                None => None,
            },
            _ => None,
        };

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

/// Build the full set of `cargo build` environment variables that configure a
/// Phantom/Specter binary for `listener` and `demon`.
///
/// Each entry becomes a `{PREFIX}_{FIELD}` variable baked into the agent at
/// compile time via `option_env!()` in the agent's `Config::default()` impl.
/// Companion to the agent-side work in commit `ed425a37`.
fn rust_agent_env_vars(
    listener: &ListenerConfig,
    env_prefix: &str,
    demon: &DemonConfig,
    listener_pub_key: Option<[u8; 32]>,
    pinned_cert_pem: Option<String>,
) -> Result<Vec<(String, String)>, PayloadBuildError> {
    let mut env_vars: Vec<(String, String)> = Vec::new();

    env_vars.push((format!("{env_prefix}_CALLBACK_URL"), rust_agent_callback_url(listener)?));

    if let ListenerConfig::Http(http) = listener {
        if let Some(ua) = &http.user_agent {
            env_vars.push((format!("{env_prefix}_USER_AGENT"), ua.clone()));
        }
        if let Some(pem) = pinned_cert_pem {
            env_vars.push((format!("{env_prefix}_PINNED_CERT_PEM"), pem));
        }
    }

    // Listener ECDH public key.  Encoded as standard base64 (no padding) to
    // match the format expected by `decode_listener_pub_key` in the agent.
    if let Some(pub_key) = listener_pub_key {
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(pub_key);
        env_vars.push((format!("{env_prefix}_LISTENER_PUB_KEY"), encoded));
    }

    // Teamserver-wide HKDF init secret.  `InitSecrets` (versioned) takes
    // precedence over the deprecated single `InitSecret` field, mirroring the
    // precedence established in `teamserver/src/main.rs`.  When multiple
    // versions are configured we bake in the highest version number, since by
    // operator convention new versions are appended.
    if !demon.init_secrets.is_empty() {
        if let Some(entry) = demon.init_secrets.iter().max_by_key(|v| v.version) {
            env_vars.push((format!("{env_prefix}_INIT_SECRET"), entry.secret.to_string()));
            env_vars.push((format!("{env_prefix}_INIT_SECRET_VERSION"), entry.version.to_string()));
        }
    } else if let Some(secret) = demon.init_secret.as_deref() {
        env_vars.push((format!("{env_prefix}_INIT_SECRET"), secret.to_owned()));
    }

    if let Some(sleep_s) = demon.sleep {
        let ms = sleep_s.saturating_mul(1000);
        env_vars.push((format!("{env_prefix}_SLEEP_DELAY_MS"), ms.to_string()));
    }
    if let Some(jitter) = demon.jitter {
        env_vars.push((format!("{env_prefix}_SLEEP_JITTER"), jitter.to_string()));
    }

    let (kill_date_str, working_hours_str) = match listener {
        ListenerConfig::Http(http) => (http.kill_date.as_deref(), http.working_hours.as_deref()),
        ListenerConfig::Dns(dns) => (dns.kill_date.as_deref(), dns.working_hours.as_deref()),
        ListenerConfig::Smb(smb) => (smb.kill_date.as_deref(), smb.working_hours.as_deref()),
        ListenerConfig::External(_) => (None, None),
    };
    let kill_date_epoch = parse_kill_date(kill_date_str)?;
    if kill_date_epoch > 0 {
        env_vars.push((format!("{env_prefix}_KILL_DATE"), kill_date_epoch.to_string()));
    }
    let working_hours_packed = parse_working_hours(working_hours_str)?;
    if working_hours_packed != 0 {
        env_vars.push((format!("{env_prefix}_WORKING_HOURS"), working_hours_packed.to_string()));
    }

    Ok(env_vars)
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
            suppress_opsec_warnings: true,
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
            suppress_opsec_warnings: true,
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
            suppress_opsec_warnings: true,
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

    // ── rust_agent_env_vars tests ────────────────────────────────────

    fn http_listener(user_agent: Option<&str>) -> ListenerConfig {
        ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "hardened".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.example.com".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 443,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: user_agent.map(str::to_owned),
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
            suppress_opsec_warnings: true,
        }))
    }

    fn default_demon_config() -> DemonConfig {
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
            job_execution: red_cell_common::config::JobExecutionMode::Thread,
            stomp_dll: None,
        }
    }

    fn find(env: &[(String, String)], key: &str) -> Option<String> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn rust_agent_env_vars_bakes_listener_pub_key_when_provided()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let demon = default_demon_config();
        let pub_key: [u8; 32] = [7u8; 32];

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, Some(pub_key), None)?;

        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(pub_key);
        assert_eq!(find(&env, "PHANTOM_LISTENER_PUB_KEY"), Some(encoded));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_omits_listener_pub_key_when_absent()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "SPECTER", &demon, None, None)?;

        assert_eq!(find(&env, "SPECTER_LISTENER_PUB_KEY"), None);
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_bakes_unversioned_init_secret() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = http_listener(None);
        let mut demon = default_demon_config();
        demon.init_secret = Some(zeroize::Zeroizing::new("unit-test-secret-16b".to_owned()));

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(find(&env, "PHANTOM_INIT_SECRET"), Some("unit-test-secret-16b".to_owned()));
        // Unversioned mode must not emit a version byte.
        assert_eq!(find(&env, "PHANTOM_INIT_SECRET_VERSION"), None);
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_bakes_highest_versioned_init_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let mut demon = default_demon_config();
        demon.init_secrets = vec![
            red_cell_common::config::VersionedInitSecret {
                version: 1,
                secret: zeroize::Zeroizing::new("old-rotation-secret".to_owned()),
            },
            red_cell_common::config::VersionedInitSecret {
                version: 3,
                secret: zeroize::Zeroizing::new("new-rotation-secret".to_owned()),
            },
            red_cell_common::config::VersionedInitSecret {
                version: 2,
                secret: zeroize::Zeroizing::new("mid-rotation-secret".to_owned()),
            },
        ];

        let env = rust_agent_env_vars(&listener, "SPECTER", &demon, None, None)?;

        assert_eq!(find(&env, "SPECTER_INIT_SECRET"), Some("new-rotation-secret".to_owned()));
        assert_eq!(find(&env, "SPECTER_INIT_SECRET_VERSION"), Some("3".to_owned()));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_versioned_takes_precedence_over_unversioned()
    -> Result<(), Box<dyn std::error::Error>> {
        // If an operator mis-configures both fields (profile validation is
        // supposed to reject this, but we should still be defensive in the
        // build step), InitSecrets wins — matching the precedence applied in
        // teamserver/src/main.rs.
        let listener = http_listener(None);
        let mut demon = default_demon_config();
        demon.init_secret = Some(zeroize::Zeroizing::new("deprecated-single-secret".to_owned()));
        demon.init_secrets = vec![red_cell_common::config::VersionedInitSecret {
            version: 5,
            secret: zeroize::Zeroizing::new("preferred-versioned-secret".to_owned()),
        }];

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(
            find(&env, "PHANTOM_INIT_SECRET"),
            Some("preferred-versioned-secret".to_owned())
        );
        assert_eq!(find(&env, "PHANTOM_INIT_SECRET_VERSION"), Some("5".to_owned()));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_omits_init_secret_when_unset() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = http_listener(None);
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(find(&env, "PHANTOM_INIT_SECRET"), None);
        assert_eq!(find(&env, "PHANTOM_INIT_SECRET_VERSION"), None);
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_includes_callback_url_and_user_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(Some("Mozilla/5.0 test"));
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(
            find(&env, "PHANTOM_CALLBACK_URL"),
            Some("https://c2.example.com:443/".to_owned())
        );
        assert_eq!(find(&env, "PHANTOM_USER_AGENT"), Some("Mozilla/5.0 test".to_owned()));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_threads_pinned_cert_pem() -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let demon = default_demon_config();
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBAg==\n-----END CERTIFICATE-----\n";

        let env = rust_agent_env_vars(&listener, "SPECTER", &demon, None, Some(pem.to_owned()))?;

        assert_eq!(find(&env, "SPECTER_PINNED_CERT_PEM"), Some(pem.to_owned()));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_bakes_sleep_and_jitter() -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let mut demon = default_demon_config();
        demon.sleep = Some(10);
        demon.jitter = Some(25);

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(find(&env, "PHANTOM_SLEEP_DELAY_MS"), Some("10000".to_owned()));
        assert_eq!(find(&env, "PHANTOM_SLEEP_JITTER"), Some("25".to_owned()));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_omits_sleep_when_unset() -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(find(&env, "PHANTOM_SLEEP_DELAY_MS"), None);
        assert_eq!(find(&env, "PHANTOM_SLEEP_JITTER"), None);
        Ok(())
    }

    fn http_listener_with_kill_date_and_working_hours(
        kill_date: Option<&str>,
        working_hours: Option<&str>,
    ) -> ListenerConfig {
        ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "timed".to_owned(),
            kill_date: kill_date.map(str::to_owned),
            working_hours: working_hours.map(str::to_owned),
            hosts: vec!["c2.example.com".to_owned()],
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
            suppress_opsec_warnings: true,
        }))
    }

    #[test]
    fn rust_agent_env_vars_bakes_kill_date() -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_with_kill_date_and_working_hours(Some("1893456000"), None);
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(find(&env, "PHANTOM_KILL_DATE"), Some("1893456000".to_owned()));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_bakes_working_hours() -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_with_kill_date_and_working_hours(None, Some("09:00-17:00"));
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        let packed = find(&env, "PHANTOM_WORKING_HOURS");
        assert!(packed.is_some(), "PHANTOM_WORKING_HOURS should be set");
        let packed: i32 = packed.as_deref().map(str::parse).transpose()?.unwrap_or(0);
        assert_ne!(packed, 0);
        assert_eq!((packed >> 22) & 1, 1, "enable bit should be set");
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_omits_kill_date_and_working_hours_when_unset()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "PHANTOM", &demon, None, None)?;

        assert_eq!(find(&env, "PHANTOM_KILL_DATE"), None);
        assert_eq!(find(&env, "PHANTOM_WORKING_HOURS"), None);
        Ok(())
    }

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
