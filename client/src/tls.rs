//! TLS certificate validation and verification-mode resolution.

use crate::ClientError;
use crate::known_servers::{KnownServersStore, host_port_from_url};
use crate::local_config::LocalConfig;
use crate::transport::TlsVerification;

/// Validate that a certificate fingerprint is a well-formed SHA-256 hex digest.
///
/// Returns the fingerprint unchanged if valid, or an error describing why it is malformed.
pub(crate) fn validate_fingerprint(fingerprint: &str, source: &str) -> Result<String, ClientError> {
    if fingerprint.len() != 64 {
        return Err(ClientError::InvalidFingerprintLength {
            fingerprint_source: source.to_owned(),
            got: fingerprint.len(),
        });
    }
    if !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ClientError::InvalidFingerprintNonHex {
            fingerprint_source: source.to_owned(),
        });
    }
    Ok(fingerprint.to_owned())
}

/// Determine the TLS verification mode from CLI flags, falling back to known-servers
/// TOFU store, then local config.
///
/// Precedence: CLI `--accept-invalid-certs` > CLI `--cert-fingerprint` > CLI `--ca-cert`
///           > known-servers TOFU store > config `cert_fingerprint` > config `ca_cert`
///           > system root CAs (with fingerprint capture for TOFU prompts).
///
/// Returns an error if a provided fingerprint is not a valid SHA-256 hex digest.
pub(crate) fn resolve_tls_verification(
    cli: &super::Cli,
    config: &LocalConfig,
    known_servers: &KnownServersStore,
    server_url: &str,
) -> Result<TlsVerification, ClientError> {
    if cli.accept_invalid_certs {
        tracing::warn!("--accept-invalid-certs is deprecated; TOFU is now the default TLS mode");
        return Ok(TlsVerification::DangerousSkipVerify);
    }
    if let Some(fingerprint) = &cli.cert_fingerprint {
        let validated = validate_fingerprint(fingerprint, "--cert-fingerprint")?;
        return Ok(TlsVerification::Fingerprint(validated));
    }
    if let Some(ca_path) = &cli.ca_cert {
        return Ok(TlsVerification::CustomCa(ca_path.clone()));
    }
    // TOFU: check the known-servers store for a previously trusted fingerprint.
    if let Some(host_port) = host_port_from_url(server_url) {
        if let Some(entry) = known_servers.lookup(&host_port) {
            return Ok(TlsVerification::Fingerprint(entry.fingerprint.clone()));
        }
    }
    if let Some(fingerprint) = &config.cert_fingerprint {
        let validated = validate_fingerprint(fingerprint, "config file")?;
        return Ok(TlsVerification::Fingerprint(validated));
    }
    if let Some(ca_path) = &config.ca_cert {
        return Ok(TlsVerification::CustomCa(ca_path.clone()));
    }
    // Default: standard CA verification with fingerprint capture.
    // For self-signed teamservers this will fail with UnknownIssuer,
    // triggering the TOFU prompt in the login UI.
    Ok(TlsVerification::CertificateAuthority)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{resolve_tls_verification, validate_fingerprint};
    use crate::known_servers::KnownServersStore;
    use crate::local_config::LocalConfig;
    use crate::transport::TlsVerification;
    use crate::{Cli, DEFAULT_SERVER_URL};

    #[test]
    fn resolve_tls_prefers_cli_accept_invalid_certs() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some("abcd".to_owned()),
            accept_invalid_certs: true,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::DangerousSkipVerify
        ));
    }

    #[test]
    fn resolve_tls_prefers_cli_fingerprint_over_ca() {
        let valid_fp = "a".repeat(64);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
            cert_fingerprint: Some(valid_fp.clone()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref fp) if fp == &valid_fp
        ));
    }

    #[test]
    fn resolve_tls_falls_back_to_config_fingerprint() {
        let valid_fp = "b".repeat(64);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config =
            LocalConfig { cert_fingerprint: Some(valid_fp.clone()), ..LocalConfig::default() };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref fp) if fp == &valid_fp
        ));
    }

    #[test]
    fn resolve_tls_uses_custom_ca_when_cli_ca_cert_is_set() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/cli-ca.pem")),
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/cli-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_prefers_cli_custom_ca_over_config_custom_ca() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: Some(PathBuf::from("/tmp/cli-ca.pem")),
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig {
            ca_cert: Some(PathBuf::from("/tmp/config-ca.pem")),
            ..LocalConfig::default()
        };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/cli-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_falls_back_to_config_custom_ca() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig {
            ca_cert: Some(PathBuf::from("/tmp/config-ca.pem")),
            ..LocalConfig::default()
        };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server).unwrap(),
            TlsVerification::CustomCa(ref path) if path == &PathBuf::from("/tmp/config-ca.pem")
        ));
    }

    #[test]
    fn resolve_tls_defaults_to_certificate_authority() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::CertificateAuthority
        ));
    }

    #[test]
    fn validate_fingerprint_accepts_valid_sha256_hex() {
        let valid_lower = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(validate_fingerprint(valid_lower, "test").is_ok());

        let valid_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(validate_fingerprint(valid_upper, "test").is_ok());

        let valid_mixed = "AbCdEf0123456789abcDEF0123456789ABCDEF0123456789abcdef0123456789";
        assert!(validate_fingerprint(valid_mixed, "test").is_ok());
    }

    #[test]
    fn validate_fingerprint_rejects_wrong_length() {
        let too_short = "abcdef";
        let err = validate_fingerprint(too_short, "test").unwrap_err();
        assert!(err.to_string().contains("6 characters"), "error: {err}");

        let too_long = "a".repeat(65);
        let err = validate_fingerprint(&too_long, "test").unwrap_err();
        assert!(err.to_string().contains("65 characters"), "error: {err}");

        let empty = "";
        let err = validate_fingerprint(empty, "test").unwrap_err();
        assert!(err.to_string().contains("0 characters"), "error: {err}");
    }

    #[test]
    fn validate_fingerprint_rejects_non_hex_chars() {
        // 64 chars but contains spaces (non-hex)
        let with_spaces = format!("{}    ", "a".repeat(60));
        assert_eq!(with_spaces.len(), 64);
        let err = validate_fingerprint(&with_spaces, "test").unwrap_err();
        assert!(err.to_string().contains("non-hex"), "error: {err}");

        // 64 chars but contains 'g'
        let with_invalid = "g".repeat(64);
        let err = validate_fingerprint(&with_invalid, "test").unwrap_err();
        assert!(err.to_string().contains("non-hex"), "error: {err}");
    }

    #[test]
    fn resolve_tls_rejects_malformed_cli_fingerprint() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some("not-a-valid-fingerprint".to_owned()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        let err =
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap_err();
        assert!(err.to_string().contains("--cert-fingerprint"), "error: {err}");
    }

    #[test]
    fn resolve_tls_rejects_malformed_config_fingerprint() {
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config =
            LocalConfig { cert_fingerprint: Some("zzzz".to_owned()), ..LocalConfig::default() };
        let err =
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap_err();
        assert!(err.to_string().contains("config file"), "error: {err}");
    }

    #[test]
    fn resolve_tls_accept_invalid_certs_skips_fingerprint_validation() {
        // Even with an invalid fingerprint, --accept-invalid-certs takes precedence
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some("bad".to_owned()),
            accept_invalid_certs: true,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &KnownServersStore::default(), &cli.server)
                .unwrap(),
            TlsVerification::DangerousSkipVerify
        ));
    }

    #[test]
    fn resolve_tls_uses_known_servers_fingerprint() {
        let fp = "c".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &fp
        ));
    }

    #[test]
    fn resolve_tls_cli_fingerprint_overrides_known_servers() {
        let known_fp = "d".repeat(64);
        let cli_fp = "e".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &known_fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: Some(cli_fp.clone()),
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig::default();
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &cli_fp
        ));
    }

    #[test]
    fn resolve_tls_known_servers_overrides_config_fingerprint() {
        let known_fp = "f".repeat(64);
        let config_fp = "0".repeat(64);
        let mut known = KnownServersStore::default();
        known.trust("127.0.0.1:40056", &known_fp, None);
        let cli = Cli {
            server: DEFAULT_SERVER_URL.to_owned(),
            scripts_dir: None,
            ca_cert: None,
            cert_fingerprint: None,
            accept_invalid_certs: false,
            purge_known_server: None,
        };
        let config = LocalConfig { cert_fingerprint: Some(config_fp), ..LocalConfig::default() };
        assert!(matches!(
            resolve_tls_verification(&cli, &config, &known, &cli.server).unwrap(),
            TlsVerification::Fingerprint(ref f) if f == &known_fp
        ));
    }
}
