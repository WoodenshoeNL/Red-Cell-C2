//! Bake-time environment variable construction and inherited-env scrubbing
//! for Rust-based agents (Phantom, Specter).

use base64::Engine as _;
use tokio::process::Command;

use red_cell_common::ListenerConfig;
use red_cell_common::config::DemonConfig;

use super::super::{
    PayloadBuildError,
    config_values::{parse_kill_date, parse_working_hours},
};
use super::url::rust_agent_callback_url;

/// Suffixes after `PHANTOM_` / `SPECTER_` that are read via `option_env!` or
/// `parse_compile_env` in `agent/phantom` and `agent/specter` `config.rs`
/// (keep in sync with those crates when adding new bake-time env vars).
pub(super) const RUST_AGENT_BAKE_ENV_SUFFIXES: &[&str] = &[
    "CALLBACK_URL",
    "DOH_DOMAIN",
    "DOH_PROVIDER",
    "INIT_SECRET",
    "INIT_SECRET_VERSION",
    "KILL_DATE",
    "LISTENER_PUB_KEY",
    "PINNED_CERT_PEM",
    "SLEEP_DELAY_MS",
    "SLEEP_JITTER",
    "USER_AGENT",
    "WORKING_HOURS",
];

/// Remove compile-time bake variables for `env_prefix` from a `cargo` command
/// so the parent (teamserver) process cannot leak `PHANTOM_*` / `SPECTER_*`
/// into `rustc` when this build does not set them in [`rust_agent_env_vars`].
pub(super) fn clear_inherited_rust_agent_bake_env(cmd: &mut Command, env_prefix: &str) {
    for suffix in RUST_AGENT_BAKE_ENV_SUFFIXES {
        cmd.env_remove(format!("{env_prefix}_{suffix}"));
    }
}

/// Read the pinned TLS certificate PEM when an HTTP listener has TLS paths configured.
///
/// Returns `Ok(None)` when there is no cert to load (non-HTTP listener, or HTTP without TLS).
/// If a cert path is configured and cannot be read, returns [`PayloadBuildError::Io`]
/// so Phantom/Specter builds never degrade to "no pinning" due to filesystem errors.
pub(super) async fn pinned_cert_pem_for_rust_listener(
    listener: &ListenerConfig,
) -> Result<Option<String>, PayloadBuildError> {
    match listener {
        ListenerConfig::Http(http) => match &http.cert {
            Some(tls) => Ok(Some(
                tokio::fs::read_to_string(&tls.cert).await.map_err(|err| {
                    PayloadBuildError::Io(std::io::Error::new(
                        err.kind(),
                        format!(
                            "failed to read listener TLS cert PEM at {} for Rust-agent payload build: {err}",
                            tls.cert
                        ),
                    ))
                })?,
            )),
            None => Ok(None),
        },
        _ => Ok(None),
    }
}

/// Build the full set of `cargo build` environment variables that configure a
/// Phantom/Specter binary for `listener` and `demon`.
///
/// Each entry becomes a `{PREFIX}_{FIELD}` variable baked into the agent at
/// compile time via `option_env!()` in the agent's `Config::default()` impl.
/// Companion to the agent-side work in commit `ed425a37`.
pub(super) fn rust_agent_env_vars(
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
        if let Some(domain) = &http.doh_domain {
            env_vars.push((format!("{env_prefix}_DOH_DOMAIN"), domain.clone()));
        }
        if let Some(provider) = &http.doh_provider {
            env_vars.push((format!("{env_prefix}_DOH_PROVIDER"), provider.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::{HttpListenerConfig, ListenerConfig, ListenerTlsConfig};

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

    // ── RUST_AGENT_BAKE_ENV_SUFFIXES ────────────────────────────────────

    #[test]
    fn rust_agent_bake_env_suffixes_includes_sleep_kill_and_working_hours() {
        let joined = RUST_AGENT_BAKE_ENV_SUFFIXES.join(",");
        assert!(joined.contains("SLEEP_DELAY_MS"));
        assert!(joined.contains("KILL_DATE"));
        assert!(joined.contains("WORKING_HOURS"));
    }

    // ── rust_agent_env_vars ────────────────────────────────────

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

    fn http_listener_with_doh(
        doh_domain: Option<&str>,
        doh_provider: Option<&str>,
    ) -> ListenerConfig {
        ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "doh-listener".to_owned(),
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
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(),
            host_header: None,
            secure: true,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: doh_domain.map(str::to_owned),
            doh_provider: doh_provider.map(str::to_owned),
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }))
    }

    #[test]
    fn rust_agent_env_vars_bakes_doh_domain_and_provider() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = http_listener_with_doh(Some("c2.test.local"), Some("cloudflare"));
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "SPECTER", &demon, None, None)?;

        assert_eq!(find(&env, "SPECTER_DOH_DOMAIN"), Some("c2.test.local".to_owned()));
        assert_eq!(find(&env, "SPECTER_DOH_PROVIDER"), Some("cloudflare".to_owned()));
        Ok(())
    }

    #[test]
    fn rust_agent_env_vars_omits_doh_vars_when_unset() -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener(None);
        let demon = default_demon_config();

        let env = rust_agent_env_vars(&listener, "SPECTER", &demon, None, None)?;

        assert_eq!(find(&env, "SPECTER_DOH_DOMAIN"), None);
        assert_eq!(find(&env, "SPECTER_DOH_PROVIDER"), None);
        Ok(())
    }

    // ── pinned_cert_pem_for_rust_listener ────────────────────────────────────

    #[tokio::test]
    async fn pinned_cert_pem_for_http_listener_reads_configured_pem_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pem_path = dir.path().join("listener.pem");
        let pem_body = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----";
        tokio::fs::write(&pem_path, pem_body.as_bytes()).await.expect("write pem");

        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "tls-listener".to_owned(),
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
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(),
            host_header: None,
            secure: true,
            cert: Some(ListenerTlsConfig {
                cert: pem_path.display().to_string(),
                key: dir.path().join("key.pem").display().to_string(),
            }),
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }));

        let got = pinned_cert_pem_for_rust_listener(&listener).await.expect("read pinned pem");
        assert_eq!(got.as_deref(), Some(pem_body));
    }

    #[tokio::test]
    async fn pinned_cert_pem_for_http_listener_errors_when_pem_missing() {
        let missing = tempfile::tempdir().expect("tempdir").path().join("nope.pem");
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "tls-listener".to_owned(),
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
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(),
            host_header: None,
            secure: true,
            cert: Some(ListenerTlsConfig {
                cert: missing.display().to_string(),
                key: "/tmp/key-does-not-matter.pem".to_owned(),
            }),
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }));

        let err = pinned_cert_pem_for_rust_listener(&listener)
            .await
            .expect_err("missing pem should fail");
        assert!(matches!(err, PayloadBuildError::Io(_)), "expected Io error, got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains(missing.display().to_string().as_str()),
            "error should cite cert path: {msg}"
        );
    }

    #[tokio::test]
    async fn pinned_cert_pem_is_none_when_http_listener_has_no_tls() {
        let listener = http_listener(None);
        let got = pinned_cert_pem_for_rust_listener(&listener).await.expect("listener without tls");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn pinned_cert_pem_is_none_for_non_http_listener() {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pipe".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let got =
            pinned_cert_pem_for_rust_listener(&listener).await.expect("non-http has no pinning");
        assert!(got.is_none());
    }
}
