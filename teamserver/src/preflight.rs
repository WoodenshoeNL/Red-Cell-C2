/// Startup preflight checks that run before the Axum server binds its port.
///
/// On failure the teamserver logs a clear error and exits non-zero rather than
/// starting in a broken state.
use std::path::Path;

use thiserror::Error;
use tracing::info;

use red_cell_common::config::Profile;

use red_cell::{DbMasterKey, database::crypto::DbCryptoError};

/// Errors that can occur during preflight checks.
#[derive(Debug, Error)]
pub enum PreflightError {
    #[error("preflight: master key encrypt failed: {0}")]
    MasterKeyEncrypt(#[source] DbCryptoError),

    #[error("preflight: master key decrypt failed — key file may be corrupt: {0}")]
    MasterKeyDecrypt(#[source] DbCryptoError),

    #[error("preflight: master key roundtrip produced mismatched plaintext — key file is corrupt")]
    MasterKeyMismatch,

    #[error(
        "preflight: no listeners defined — the teamserver needs at least one \
         Http, Smb, External, or Dns listener to accept agent callbacks"
    )]
    NoListeners,

    #[error("preflight: listener '{listener}': TLS certificate file not found: {path}")]
    TlsCertNotFound { listener: String, path: String },

    #[error("preflight: listener '{listener}': TLS private key file not found: {path}")]
    TlsKeyNotFound { listener: String, path: String },
}

/// Run all preflight checks and log the startup banner on success.
pub fn run(
    profile: &Profile,
    master_key: &DbMasterKey,
    database_path: &Path,
) -> Result<(), PreflightError> {
    verify_master_key(master_key)?;
    let listener_count = verify_listeners(profile)?;
    verify_listener_tls_certs(profile)?;

    let operator_count = profile.operators.users.len();

    log_startup_banner(listener_count, operator_count, database_path);
    Ok(())
}

/// Encrypt and decrypt a test value to verify the master key is usable.
fn verify_master_key(master_key: &DbMasterKey) -> Result<(), PreflightError> {
    let test_value = b"preflight-roundtrip-check";
    let encrypted = master_key.encrypt(test_value).map_err(PreflightError::MasterKeyEncrypt)?;
    let decrypted = master_key.decrypt(&encrypted).map_err(PreflightError::MasterKeyDecrypt)?;
    if decrypted.as_slice() != test_value {
        return Err(PreflightError::MasterKeyMismatch);
    }
    info!("master key encrypt/decrypt roundtrip verified");
    Ok(())
}

/// Verify at least one listener is defined in the profile.
fn verify_listeners(profile: &Profile) -> Result<usize, PreflightError> {
    let listeners = &profile.listeners;
    let count =
        listeners.http.len() + listeners.smb.len() + listeners.external.len() + listeners.dns.len();
    if count == 0 {
        return Err(PreflightError::NoListeners);
    }
    info!(count, "listener profiles verified");
    Ok(count)
}

/// Verify that TLS certificate files exist and are readable for HTTPS listeners.
fn verify_listener_tls_certs(profile: &Profile) -> Result<(), PreflightError> {
    for listener in &profile.listeners.http {
        if !listener.secure {
            continue;
        }
        let Some(ref cert_config) = listener.cert else {
            continue;
        };
        let cert_path = Path::new(&cert_config.cert);
        let key_path = Path::new(&cert_config.key);

        if !cert_path.is_file() {
            return Err(PreflightError::TlsCertNotFound {
                listener: listener.name.clone(),
                path: cert_config.cert.clone(),
            });
        }
        if !key_path.is_file() {
            return Err(PreflightError::TlsKeyNotFound {
                listener: listener.name.clone(),
                path: cert_config.key.clone(),
            });
        }
        info!(listener = %listener.name, cert = %cert_config.cert, "listener TLS certificate verified");
    }
    Ok(())
}

/// Log a startup banner summarizing the runtime configuration.
fn log_startup_banner(listener_count: usize, operator_count: usize, database_path: &Path) {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        listeners = listener_count,
        operators = operator_count,
        database = %database_path.display(),
        "red-cell teamserver starting"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> DbMasterKey {
        DbMasterKey::random().expect("rng")
    }

    #[test]
    fn verify_master_key_succeeds_with_valid_key() {
        let key = test_master_key();
        verify_master_key(&key).expect("should succeed");
    }

    #[test]
    fn verify_listeners_fails_when_none_defined() {
        let profile = minimal_profile_no_listeners();
        let err = verify_listeners(&profile).unwrap_err();
        assert!(matches!(err, PreflightError::NoListeners), "unexpected error: {err}");
        assert!(err.to_string().contains("no listeners defined"), "unexpected message: {err}");
    }

    #[test]
    fn verify_listeners_succeeds_with_http_listener() {
        let profile = minimal_profile_with_http_listener(false, None);
        let count = verify_listeners(&profile).expect("should succeed");
        assert_eq!(count, 1);
    }

    #[test]
    fn verify_tls_certs_skips_non_secure_listeners() {
        let profile = minimal_profile_with_http_listener(false, None);
        verify_listener_tls_certs(&profile).expect("should succeed for non-secure listener");
    }

    #[test]
    fn verify_tls_certs_skips_secure_listener_without_custom_cert() {
        let profile = minimal_profile_with_http_listener(true, None);
        verify_listener_tls_certs(&profile).expect("should succeed without custom cert");
    }

    #[test]
    fn verify_tls_certs_fails_for_missing_cert_file() {
        let cert_config = red_cell_common::config::HttpListenerCertConfig {
            cert: "/nonexistent/cert.pem".to_owned(),
            key: "/nonexistent/key.pem".to_owned(),
        };
        let profile = minimal_profile_with_http_listener(true, Some(cert_config));
        let err = verify_listener_tls_certs(&profile).unwrap_err();
        assert!(matches!(err, PreflightError::TlsCertNotFound { .. }), "unexpected error: {err}");
        assert!(
            err.to_string().contains("TLS certificate file not found"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn verify_tls_certs_fails_for_missing_key_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, b"fake-cert").expect("write cert");

        let cert_config = red_cell_common::config::HttpListenerCertConfig {
            cert: cert_path.display().to_string(),
            key: "/nonexistent/key.pem".to_owned(),
        };
        let profile = minimal_profile_with_http_listener(true, Some(cert_config));
        let err = verify_listener_tls_certs(&profile).unwrap_err();
        assert!(matches!(err, PreflightError::TlsKeyNotFound { .. }), "unexpected error: {err}");
        assert!(
            err.to_string().contains("TLS private key file not found"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn verify_tls_certs_succeeds_when_both_files_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"fake-cert").expect("write cert");
        std::fs::write(&key_path, b"fake-key").expect("write key");

        let cert_config = red_cell_common::config::HttpListenerCertConfig {
            cert: cert_path.display().to_string(),
            key: key_path.display().to_string(),
        };
        let profile = minimal_profile_with_http_listener(true, Some(cert_config));
        verify_listener_tls_certs(&profile).expect("should succeed");
    }

    #[test]
    fn run_succeeds_with_valid_config() {
        let key = test_master_key();
        let profile = minimal_profile_with_http_listener(false, None);
        let db_path = std::path::PathBuf::from("/tmp/test.sqlite");
        run(&profile, &key, &db_path).expect("preflight should pass");
    }

    #[test]
    fn run_fails_with_no_listeners() {
        let key = test_master_key();
        let profile = minimal_profile_no_listeners();
        let db_path = std::path::PathBuf::from("/tmp/test.sqlite");
        let err = run(&profile, &key, &db_path).unwrap_err();
        assert!(matches!(err, PreflightError::NoListeners), "unexpected error: {err:?}");
    }

    // -- test helpers --

    fn minimal_profile_no_listeners() -> Profile {
        use red_cell_common::config::{DemonConfig, OperatorsConfig, TeamserverConfig};

        Profile {
            teamserver: TeamserverConfig {
                host: "0.0.0.0".to_owned(),
                port: 40056,
                plugins_dir: None,
                max_download_bytes: None,
                max_concurrent_downloads_per_agent: None,
                max_aggregate_download_bytes: None,
                max_pivot_chain_depth: None,
                max_registered_agents: None,
                drain_timeout_secs: None,
                agent_timeout_secs: None,
                logging: None,
                build: None,
                cert: None,
                database: None,
                observability: None,
            },
            operators: OperatorsConfig {
                users: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            listeners: red_cell_common::config::ListenersConfig::default(),
            demon: DemonConfig {
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
                trusted_proxy_peers: vec![],
                heap_enc: true,
                allow_legacy_ctr: false,
                job_execution: "thread".to_owned(),
                stomp_dll: None,
            },
            service: None,
            api: None,
            webhook: None,
        }
    }

    fn minimal_profile_with_http_listener(
        secure: bool,
        cert: Option<red_cell_common::config::HttpListenerCertConfig>,
    ) -> Profile {
        let mut profile = minimal_profile_no_listeners();
        profile.listeners.http.push(red_cell_common::config::ProfileHttpListenerConfig {
            name: "test-listener".to_owned(),
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 443,
            port_conn: None,
            kill_date: None,
            working_hours: None,
            method: None,
            user_agent: None,
            host_header: None,
            headers: vec![],
            uris: vec!["/".to_owned()],
            secure,
            cert,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
        });
        profile
    }
}
