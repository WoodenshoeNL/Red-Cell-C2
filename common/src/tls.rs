//! TLS certificate generation and loading helpers for teamserver services.

use std::fs;
use std::io::BufReader;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::FromDer as _;
use zeroize::Zeroizing;

use crate::config::HttpListenerCertConfig;

/// Supported key algorithms for runtime-generated self-signed certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsKeyAlgorithm {
    /// Generate a P-256 ECDSA key pair and certificate.
    EcdsaP256,
    /// Generate a 2048-bit RSA key pair and certificate.
    Rsa2048,
}

/// Parsed TLS identity material backed by PEM and rustls-compatible DER types.
#[derive(Debug)]
pub struct TlsIdentity {
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    certificate_pem: Vec<u8>,
    /// PEM-encoded private key bytes. Wrapped in [`Zeroizing`] so the key
    /// material is wiped from heap memory when the identity is dropped.
    private_key_pem: Zeroizing<Vec<u8>>,
}

impl TlsIdentity {
    /// Return the certificate chain in PEM encoding.
    pub fn certificate_pem(&self) -> &[u8] {
        &self.certificate_pem
    }

    /// Return the private key in PEM encoding.
    pub fn private_key_pem(&self) -> &[u8] {
        &self.private_key_pem
    }

    /// Build a rustls server configuration for Axum or raw Tokio listeners.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError> {
        let config = ServerConfig::builder_with_provider(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?
        .with_no_client_auth()
        .with_single_cert(self.certificate_chain.clone(), self.private_key.clone_key())
        .map_err(TlsError::Rustls)?;

        Ok(Arc::new(config))
    }

    /// Build a Tokio TLS acceptor from this identity.
    pub fn tls_acceptor(&self) -> Result<TlsAcceptor, TlsError> {
        Ok(TlsAcceptor::from(self.server_config()?))
    }
}

/// Errors returned while generating, loading, or configuring TLS identities.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Runtime-generated certificates need at least one SAN entry.
    #[error("at least one subject alternative name is required")]
    MissingSubjectAltNames,
    /// Certificate PEM data could not be read or parsed from disk.
    #[error("failed to read TLS material from {path}: {source}")]
    ReadFile {
        /// Path that could not be read.
        path: String,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// PEM parsing failed while decoding a certificate or private key.
    #[error("failed to parse PEM-encoded TLS material: {0}")]
    Pem(#[from] std::io::Error),
    /// No certificate blocks were found in the provided PEM data.
    #[error("no X.509 certificates were found in the PEM data")]
    MissingCertificates,
    /// No private key was found in the provided PEM data.
    #[error("no private key was found in the PEM data")]
    MissingPrivateKey,
    /// rcgen failed to create or serialize the certificate or key pair.
    #[error("failed to generate self-signed TLS material: {0}")]
    Generate(#[from] rcgen::Error),
    /// rustls rejected the certificate/key combination.
    #[error("failed to build rustls server configuration: {0}")]
    Rustls(#[source] tokio_rustls::rustls::Error),
    /// Certificate has passed its `notAfter` validity bound.
    #[error("certificate expired at {not_after}")]
    CertificateExpired {
        /// RFC 3339-formatted expiry timestamp.
        not_after: String,
    },
    /// Certificate `notBefore` is in the future.
    #[error("certificate is not yet valid (valid from {not_before})")]
    CertificateNotYetValid {
        /// RFC 3339-formatted validity-start timestamp.
        not_before: String,
    },
    /// The certificate DER could not be parsed for validity checking.
    #[error("failed to parse certificate for validity check: {0}")]
    CertificateParse(String),
}

/// Validate that the leaf certificate in `cert_pem` is currently within its validity window.
///
/// Parses the first DER certificate in the PEM block and compares its `notBefore` and
/// `notAfter` fields against the current UTC clock.  Returns an error if:
///
/// - The certificate has already expired ([`TlsError::CertificateExpired`]).
/// - The certificate is not yet valid ([`TlsError::CertificateNotYetValid`]).
/// - The PEM could not be parsed ([`TlsError::MissingCertificates`] or
///   [`TlsError::CertificateParse`]).
pub fn validate_tls_not_expired(cert_pem: &[u8]) -> Result<(), TlsError> {
    let mut reader = BufReader::new(cert_pem);
    let certs: Vec<CertificateDer<'_>> =
        rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    let cert_der = certs.first().ok_or(TlsError::MissingCertificates)?;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::CertificateParse(e.to_string()))?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();

    if now < not_before_ts {
        let not_before_str = OffsetDateTime::from_unix_timestamp(not_before_ts)
            .map(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| not_before_ts.to_string())
            })
            .unwrap_or_else(|_| not_before_ts.to_string());
        return Err(TlsError::CertificateNotYetValid { not_before: not_before_str });
    }

    if now > not_after_ts {
        let not_after_str = OffsetDateTime::from_unix_timestamp(not_after_ts)
            .map(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| not_after_ts.to_string())
            })
            .unwrap_or_else(|_| not_after_ts.to_string());
        return Err(TlsError::CertificateExpired { not_after: not_after_str });
    }

    Ok(())
}

/// Install the default rustls crypto provider once for the current process.
pub fn install_default_crypto_provider() {
    static PROVIDER: OnceLock<()> = OnceLock::new();

    if PROVIDER.set(()).is_ok() {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

/// Generate a self-signed certificate for the provided DNS names and/or IP addresses.
pub fn generate_self_signed_tls_identity(
    subject_alt_names: &[String],
    algorithm: TlsKeyAlgorithm,
) -> Result<TlsIdentity, TlsError> {
    let Some(common_name) = subject_alt_names.first() else {
        return Err(TlsError::MissingSubjectAltNames);
    };

    let mut params = CertificateParams::new(subject_alt_names.to_vec())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name.as_str());
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);

    let signing_key = match algorithm {
        TlsKeyAlgorithm::EcdsaP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?,
        TlsKeyAlgorithm::Rsa2048 => KeyPair::generate_for(&PKCS_RSA_SHA256)?,
    };

    let certificate = params.self_signed(&signing_key)?;
    let certificate_pem = certificate.pem().into_bytes();
    let private_key_pem = signing_key.serialize_pem().into_bytes();

    load_tls_identity(&certificate_pem, &private_key_pem)
}

/// Load an existing PEM certificate chain and private key into a rustls-compatible identity.
pub fn load_tls_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsIdentity, TlsError> {
    let mut cert_reader = BufReader::new(cert_pem);
    let certificate_chain =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, std::io::Error>>()?;

    if certificate_chain.is_empty() {
        if !cert_pem.is_empty() {
            let mut cert_item_reader = BufReader::new(cert_pem);
            match rustls_pemfile::read_one(&mut cert_item_reader)? {
                Some(_) => {}
                None => {
                    return Err(TlsError::Pem(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "certificate PEM did not contain any valid PEM sections",
                    )));
                }
            }
        }

        return Err(TlsError::MissingCertificates);
    }

    let mut key_reader = BufReader::new(key_pem);
    let Some(private_key) = rustls_pemfile::private_key(&mut key_reader)? else {
        return Err(TlsError::MissingPrivateKey);
    };

    Ok(TlsIdentity {
        certificate_chain,
        private_key,
        certificate_pem: cert_pem.to_vec(),
        private_key_pem: Zeroizing::new(key_pem.to_vec()),
    })
}

/// Load an existing PEM certificate chain and private key from disk.
pub fn load_tls_identity_from_files(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<TlsIdentity, TlsError> {
    let cert_path = cert_path.as_ref();
    let key_path = key_path.as_ref();
    let certificate_pem = fs::read(cert_path)
        .map_err(|source| TlsError::ReadFile { path: cert_path.display().to_string(), source })?;
    let private_key_pem = fs::read(key_path)
        .map_err(|source| TlsError::ReadFile { path: key_path.display().to_string(), source })?;

    load_tls_identity(&certificate_pem, &private_key_pem)
}

/// Resolve TLS identity material from profile PEM paths or runtime self-signed generation.
pub fn resolve_tls_identity(
    subject_alt_names: &[String],
    cert_config: Option<&HttpListenerCertConfig>,
    algorithm: TlsKeyAlgorithm,
) -> Result<TlsIdentity, TlsError> {
    match cert_config {
        Some(cert_config) => load_tls_identity_from_files(&cert_config.cert, &cert_config.key),
        None => generate_self_signed_tls_identity(subject_alt_names, algorithm),
    }
}

/// Errors that can occur while persisting generated TLS material to disk.
#[derive(Debug, Error)]
pub enum PersistTlsError {
    /// The underlying TLS generation or loading failed.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// Writing the generated PEM files to disk failed.
    #[error("failed to persist TLS material to {path}: {source}")]
    WriteFile {
        /// Path that could not be written.
        path: String,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// Tightening permissions on an existing key file to 0600 failed.
    #[error("failed to harden permissions on {path}: {source}")]
    HardenPermissions {
        /// Path whose permissions could not be updated.
        path: String,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
}

/// Resolve a durable TLS identity for a long-running service.
///
/// Resolution order:
/// 1. If `cert_config` is [`Some`], load from the configured PEM paths.
/// 2. If `cert_path` and `key_path` already exist on disk, load them.
/// 3. Otherwise generate a fresh self-signed certificate, write it to
///    `cert_path` / `key_path`, and return it.
///
/// This ensures that the identity survives process restarts without requiring
/// explicit TLS configuration in the profile: on the first boot a certificate
/// is generated and saved; every subsequent boot reloads that same material.
pub fn resolve_or_persist_tls_identity(
    subject_alt_names: &[String],
    cert_config: Option<&HttpListenerCertConfig>,
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    algorithm: TlsKeyAlgorithm,
) -> Result<TlsIdentity, PersistTlsError> {
    let cert_path = cert_path.as_ref();
    let key_path = key_path.as_ref();

    if let Some(cfg) = cert_config {
        return load_tls_identity_from_files(&cfg.cert, &cfg.key).map_err(PersistTlsError::Tls);
    }

    if cert_path.exists() && key_path.exists() {
        // Re-apply 0600 so keys written by older builds with a permissive umask
        // are hardened on every subsequent boot, not just on first generation.
        harden_private_key_permissions(key_path)?;
        return load_tls_identity_from_files(cert_path, key_path).map_err(PersistTlsError::Tls);
    }

    let identity = generate_self_signed_tls_identity(subject_alt_names, algorithm)?;

    fs::write(cert_path, identity.certificate_pem()).map_err(|source| {
        PersistTlsError::WriteFile { path: cert_path.display().to_string(), source }
    })?;

    // Private key must be owner-only readable (0600) to prevent exposure.
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(key_path)
        .and_then(|mut f| f.write_all(identity.private_key_pem()))
        .map_err(|source| PersistTlsError::WriteFile {
            path: key_path.display().to_string(),
            source,
        })?;

    // `OpenOptions::mode` applies only when the file is created; truncation of an
    // existing permissive key (partial state: cert missing) leaves stale mode bits.
    harden_private_key_permissions(key_path)?;

    Ok(identity)
}

// Ensure PEM private key material on disk is not group/world readable (Unix mode 0600).
fn harden_private_key_permissions(key_path: &Path) -> Result<(), PersistTlsError> {
    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        PersistTlsError::HardenPermissions { path: key_path.display().to_string(), source }
    })
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use tempfile::TempDir;
    use x509_parser::prelude::FromDer;

    use super::{
        PersistTlsError, TlsError, TlsIdentity, TlsKeyAlgorithm, generate_self_signed_tls_identity,
        install_default_crypto_provider, load_tls_identity, load_tls_identity_from_files,
        resolve_or_persist_tls_identity, resolve_tls_identity, validate_tls_not_expired,
    };
    use crate::config::HttpListenerCertConfig;

    #[test]
    fn generate_self_signed_tls_identity_rejects_empty_subject_alt_names() {
        let error = generate_self_signed_tls_identity(&[], TlsKeyAlgorithm::EcdsaP256)
            .expect_err("empty SAN list must be rejected");

        assert!(matches!(error, TlsError::MissingSubjectAltNames));
    }

    #[test]
    fn generate_self_signed_tls_identity_supports_ecdsa() {
        let subject_alt_names = vec!["teamserver.local".to_owned(), "127.0.0.1".to_owned()];
        let identity =
            generate_self_signed_tls_identity(&subject_alt_names, TlsKeyAlgorithm::EcdsaP256)
                .expect("ECDSA identity generation should succeed");

        assert!(identity.certificate_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(identity.private_key_pem().starts_with(b"-----BEGIN PRIVATE KEY-----"));
        assert_eq!(public_key_algorithm_oid(&identity), "1.2.840.10045.2.1");

        let sans = subject_alt_names_from_identity(&identity);
        assert!(sans.iter().any(|name| name == "DNS:teamserver.local"));
        assert!(sans.iter().any(|name| name == "IP:127.0.0.1"));

        let _ = identity.server_config().expect("generated identity should build a rustls config");
    }

    #[test]
    fn generate_self_signed_tls_identity_supports_rsa() {
        let subject_alt_names = vec!["127.0.0.1".to_owned()];
        let identity =
            generate_self_signed_tls_identity(&subject_alt_names, TlsKeyAlgorithm::Rsa2048)
                .expect("RSA identity generation should succeed");

        assert!(identity.private_key_pem().starts_with(b"-----BEGIN PRIVATE KEY-----"));
        assert_eq!(public_key_algorithm_oid(&identity), "1.2.840.113549.1.1.1");

        let _ =
            identity.server_config().expect("generated RSA identity should build a rustls config");
    }

    #[test]
    fn load_tls_identity_round_trips_generated_pem_material() {
        let original = generate_self_signed_tls_identity(
            &["localhost".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");

        let loaded = load_tls_identity(original.certificate_pem(), original.private_key_pem())
            .expect("generated PEM material should round-trip");

        assert_eq!(loaded.certificate_pem(), original.certificate_pem());
        assert_eq!(loaded.private_key_pem(), original.private_key_pem());
    }

    #[test]
    fn load_tls_identity_rejects_missing_certificates() {
        let error = load_tls_identity(b"", b"")
            .expect_err("empty PEM inputs must be rejected as missing certificates");

        assert!(matches!(error, TlsError::MissingCertificates));
    }

    #[test]
    fn load_tls_identity_rejects_missing_private_key() {
        let identity = generate_self_signed_tls_identity(
            &["localhost".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");

        let error = load_tls_identity(identity.certificate_pem(), b"")
            .expect_err("missing private key must be rejected");

        assert!(matches!(error, TlsError::MissingPrivateKey));
    }

    #[test]
    fn load_tls_identity_rejects_non_pem_input() {
        let error =
            load_tls_identity(b"garbage", b"garbage").expect_err("non-PEM input must be rejected");

        assert!(matches!(error, TlsError::Pem(_)));
    }

    #[test]
    fn load_tls_identity_from_files_reads_existing_pem_material() {
        let temp_dir = TempDir::new().expect("temporary directory should be created");
        let identity = generate_self_signed_tls_identity(
            &["localhost".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("server.key");

        std::fs::write(&cert_path, identity.certificate_pem())
            .expect("certificate should be written");
        std::fs::write(&key_path, identity.private_key_pem())
            .expect("private key should be written");

        let loaded = load_tls_identity_from_files(&cert_path, &key_path)
            .expect("PEM files should load successfully");

        assert_eq!(loaded.certificate_pem(), identity.certificate_pem());
        assert_eq!(loaded.private_key_pem(), identity.private_key_pem());
    }

    #[test]
    fn load_tls_identity_from_files_rejects_missing_paths() {
        let temp_dir = TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("missing.crt");
        let key_path = temp_dir.path().join("missing.key");

        let error = load_tls_identity_from_files(&cert_path, &key_path)
            .expect_err("missing PEM files must be rejected");

        match error {
            TlsError::ReadFile { path, .. } => {
                assert_eq!(path, cert_path.display().to_string());
            }
            other => panic!("expected ReadFile error, got {other:?}"),
        }
    }

    #[test]
    fn load_tls_identity_from_files_rejects_missing_key_when_cert_exists() {
        let temp_dir = TempDir::new().expect("temporary directory should be created");
        let identity = generate_self_signed_tls_identity(
            &["localhost".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("missing.key");

        std::fs::write(&cert_path, identity.certificate_pem())
            .expect("certificate should be written");
        // key file is intentionally not written

        let error = load_tls_identity_from_files(&cert_path, &key_path)
            .expect_err("missing key file must be rejected");

        match error {
            TlsError::ReadFile { path, .. } => {
                assert_eq!(path, key_path.display().to_string());
            }
            other => panic!("expected ReadFile error for key path, got {other:?}"),
        }
    }

    #[test]
    fn resolve_tls_identity_uses_profile_cert_paths_when_present() {
        let temp_dir = TempDir::new().expect("temporary directory should be created");
        let identity = generate_self_signed_tls_identity(
            &["listener.local".to_owned()],
            TlsKeyAlgorithm::Rsa2048,
        )
        .expect("identity generation should succeed");
        let cert_path = temp_dir.path().join("listener.crt");
        let key_path = temp_dir.path().join("listener.key");

        std::fs::write(&cert_path, identity.certificate_pem())
            .expect("certificate should be written");
        std::fs::write(&key_path, identity.private_key_pem())
            .expect("private key should be written");

        let cert_config = HttpListenerCertConfig {
            cert: cert_path.display().to_string(),
            key: key_path.display().to_string(),
        };

        let resolved = resolve_tls_identity(
            &["ignored.local".to_owned()],
            Some(&cert_config),
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("existing profile PEMs should be preferred");

        assert_eq!(resolved.certificate_pem(), identity.certificate_pem());
        assert_eq!(resolved.private_key_pem(), identity.private_key_pem());
    }

    #[test]
    fn resolve_tls_identity_fails_when_configured_pem_files_are_corrupt() {
        let temp_dir = TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("listener.crt");
        let key_path = temp_dir.path().join("listener.key");

        std::fs::write(
            &cert_path,
            b"-----BEGIN CERTIFICATE-----\n%%%invalid-base64%%%\n-----END CERTIFICATE-----\n",
        )
        .expect("certificate fixture should write");
        std::fs::write(
            &key_path,
            b"-----BEGIN PRIVATE KEY-----\n%%%invalid-base64%%%\n-----END PRIVATE KEY-----\n",
        )
        .expect("key fixture should write");

        let cert_config = HttpListenerCertConfig {
            cert: cert_path.display().to_string(),
            key: key_path.display().to_string(),
        };

        let error = resolve_tls_identity(
            &["ignored.local".to_owned()],
            Some(&cert_config),
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect_err("corrupt configured PEM should fail without fallback generation");

        assert!(matches!(error, TlsError::Pem(_)), "expected PEM parse error, got: {error:?}");
    }

    #[test]
    fn resolve_tls_identity_generates_material_when_profile_cert_paths_are_absent() {
        let resolved =
            resolve_tls_identity(&["ws.local".to_owned()], None, TlsKeyAlgorithm::EcdsaP256)
                .expect("missing profile PEMs should trigger generation");

        assert!(resolved.certificate_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(resolved.tls_acceptor().is_ok());
    }

    #[test]
    fn install_default_crypto_provider_allows_tls_identity_creation_after_first_call() {
        install_default_crypto_provider();

        let identity = generate_self_signed_tls_identity(
            &["localhost".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed after provider installation");

        assert!(identity.server_config().is_ok());
    }

    #[test]
    fn install_default_crypto_provider_is_idempotent_on_repeated_calls() {
        install_default_crypto_provider();
        install_default_crypto_provider();
        install_default_crypto_provider();

        let identity =
            generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::Rsa2048)
                .expect("identity generation should succeed after repeated provider installation");

        assert!(identity.server_config().is_ok());
    }

    #[test]
    fn install_default_crypto_provider_before_server_config_keeps_rustls_setup_working() {
        let identity = generate_self_signed_tls_identity(
            &["listener.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");

        install_default_crypto_provider();

        assert!(identity.server_config().is_ok());
    }

    fn public_key_algorithm_oid(identity: &TlsIdentity) -> String {
        let mut reader = BufReader::new(identity.certificate_pem());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, std::io::Error>>()
            .expect("certificate PEM should parse");
        let certificate =
            certificates.first().expect("certificate PEM should contain at least one certificate");
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
            .expect("certificate DER should parse");

        parsed.tbs_certificate.subject_pki.algorithm.algorithm.to_id_string()
    }

    fn subject_alt_names_from_identity(identity: &TlsIdentity) -> Vec<String> {
        let mut reader = BufReader::new(identity.certificate_pem());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, std::io::Error>>()
            .expect("certificate PEM should parse");
        let certificate =
            certificates.first().expect("certificate PEM should contain at least one certificate");
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
            .expect("certificate DER should parse");

        parsed
            .subject_alternative_name()
            .expect("certificate extensions should parse")
            .expect("generated certificate should include SANs")
            .value
            .general_names
            .iter()
            .map(|name| match name {
                x509_parser::extensions::GeneralName::DNSName(value) => format!("DNS:{value}"),
                x509_parser::extensions::GeneralName::IPAddress([a, b, c, d]) => {
                    format!("IP:{a}.{b}.{c}.{d}")
                }
                other => other.to_string(),
            })
            .collect()
    }

    #[test]
    fn generate_self_signed_tls_identity_has_reasonable_validity_period() {
        let identity = generate_self_signed_tls_identity(
            &["validity-test.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");

        let mut reader = BufReader::new(identity.certificate_pem());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, std::io::Error>>()
            .expect("certificate PEM should parse");
        let cert_der =
            certificates.first().expect("certificate PEM should contain at least one certificate");
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
            .expect("certificate DER should parse");

        let validity = &parsed.tbs_certificate.validity;
        let now = x509_parser::time::ASN1Time::now();

        assert!(
            validity.not_before <= now,
            "certificate not_before ({:?}) should be in the past or present",
            validity.not_before,
        );
        assert!(
            now <= validity.not_after,
            "certificate not_after ({:?}) should be in the future",
            validity.not_after,
        );

        // Validity span must be between 1 day and 10 years (reasonable for self-signed certs).
        let not_before_secs = validity.not_before.timestamp();
        let not_after_secs = validity.not_after.timestamp();
        let span_secs = not_after_secs - not_before_secs;

        let one_day_secs: i64 = 24 * 60 * 60;
        let ten_years_secs: i64 = 10 * 365 * 24 * 60 * 60;

        assert!(
            span_secs >= one_day_secs,
            "certificate validity span ({span_secs}s) should be at least 1 day ({one_day_secs}s)",
        );
        assert!(
            span_secs <= ten_years_secs,
            "certificate validity span ({span_secs}s) should be at most 10 years ({ten_years_secs}s)",
        );
    }

    #[test]
    fn mismatched_cert_and_key_fails_server_config() {
        let identity_a = generate_self_signed_tls_identity(
            &["identity-a.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity A generation should succeed");

        let identity_b = generate_self_signed_tls_identity(
            &["identity-b.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity B generation should succeed");

        // Combine cert from A with key from B — a realistic misconfiguration.
        let mismatched =
            load_tls_identity(identity_a.certificate_pem(), identity_b.private_key_pem())
                .expect("PEM parsing should succeed even with mismatched material");

        let error =
            mismatched.server_config().expect_err("mismatched cert/key must be rejected by rustls");

        assert!(
            matches!(error, TlsError::Rustls(_)),
            "expected TlsError::Rustls for mismatched cert/key, got: {error:?}"
        );
    }

    #[test]
    fn mismatched_cert_and_key_fails_tls_acceptor() {
        let identity_a = generate_self_signed_tls_identity(
            &["acceptor-a.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity A generation should succeed");

        let identity_b = generate_self_signed_tls_identity(
            &["acceptor-b.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity B generation should succeed");

        let mismatched =
            load_tls_identity(identity_a.certificate_pem(), identity_b.private_key_pem())
                .expect("PEM parsing should succeed even with mismatched material");

        let error = match mismatched.tls_acceptor() {
            Err(e) => e,
            Ok(_) => panic!("mismatched cert/key must be rejected by tls_acceptor"),
        };

        assert!(
            matches!(error, TlsError::Rustls(_)),
            "expected TlsError::Rustls for mismatched cert/key via tls_acceptor, got: {error:?}"
        );
    }

    #[test]
    fn mismatched_rsa_cert_and_ecdsa_key_fails_server_config() {
        let rsa_identity =
            generate_self_signed_tls_identity(&["rsa.local".to_owned()], TlsKeyAlgorithm::Rsa2048)
                .expect("RSA identity generation should succeed");

        let ecdsa_identity = generate_self_signed_tls_identity(
            &["ecdsa.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("ECDSA identity generation should succeed");

        // Cross-algorithm mismatch: RSA cert with ECDSA key.
        let mismatched =
            load_tls_identity(rsa_identity.certificate_pem(), ecdsa_identity.private_key_pem())
                .expect("PEM parsing should succeed even with cross-algorithm material");

        let error = mismatched
            .server_config()
            .expect_err("cross-algorithm cert/key must be rejected by rustls");

        assert!(
            matches!(error, TlsError::Rustls(_)),
            "expected TlsError::Rustls for cross-algorithm mismatch, got: {error:?}"
        );
    }

    #[test]
    fn resolve_or_persist_generates_and_writes_pem_files_on_first_boot() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("teamserver.tls.crt");
        let key_path = temp_dir.path().join("teamserver.tls.key");

        let identity = resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("first-boot generation should succeed");

        assert!(cert_path.exists(), "certificate file should be written to disk");
        assert!(key_path.exists(), "private key file should be written to disk");
        assert!(identity.certificate_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(identity.private_key_pem().starts_with(b"-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn resolve_or_persist_sets_private_key_permissions_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("teamserver.tls.crt");
        let key_path = temp_dir.path().join("teamserver.tls.key");

        resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("first-boot generation should succeed");

        let key_mode = std::fs::metadata(&key_path)
            .expect("key file metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600, "private key file must be owner-only (0600), got {key_mode:o}");
    }

    #[test]
    fn resolve_or_persist_hardens_pre_existing_0644_key_on_reload() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("teamserver.tls.crt");
        let key_path = temp_dir.path().join("teamserver.tls.key");

        // Simulate an older build that wrote the key with permissive 0644 mode.
        let identity = generate_self_signed_tls_identity(
            &["teamserver.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");
        std::fs::write(&cert_path, identity.certificate_pem())
            .expect("certificate should be written");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&key_path)
                .and_then(|mut f: std::fs::File| f.write_all(identity.private_key_pem()))
                .expect("key should be written with 0644");
        }

        let mode_before = std::fs::metadata(&key_path)
            .expect("key metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_before, 0o644, "precondition: key file must start with 0644");

        resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("reload of pre-existing files should succeed");

        let mode_after = std::fs::metadata(&key_path)
            .expect("key metadata should be readable after reload")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode_after, 0o600,
            "private key must be hardened to 0600 on reload, was {mode_before:o}"
        );
    }

    #[test]
    fn resolve_or_persist_reloads_existing_pem_files_on_subsequent_boots() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("teamserver.tls.crt");
        let key_path = temp_dir.path().join("teamserver.tls.key");

        // First boot — generates and persists.
        let first = resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("first-boot generation should succeed");

        // Second boot — must reload from disk, not generate a new certificate.
        let second = resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("second-boot reload should succeed");

        assert_eq!(
            first.certificate_pem(),
            second.certificate_pem(),
            "certificate material must be identical across restarts"
        );
        assert_eq!(
            first.private_key_pem(),
            second.private_key_pem(),
            "private key material must be identical across restarts"
        );
    }

    #[test]
    fn resolve_or_persist_prefers_configured_cert_paths_over_persisted_files() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");

        // Write one cert as the "configured" cert.
        let configured_identity = generate_self_signed_tls_identity(
            &["configured.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");
        let configured_cert_path = temp_dir.path().join("configured.crt");
        let configured_key_path = temp_dir.path().join("configured.key");
        std::fs::write(&configured_cert_path, configured_identity.certificate_pem())
            .expect("configured cert should be written");
        std::fs::write(&configured_key_path, configured_identity.private_key_pem())
            .expect("configured key should be written");

        // Auto-persist paths (different files).
        let auto_cert_path = temp_dir.path().join("teamserver.tls.crt");
        let auto_key_path = temp_dir.path().join("teamserver.tls.key");

        let cert_config = HttpListenerCertConfig {
            cert: configured_cert_path.display().to_string(),
            key: configured_key_path.display().to_string(),
        };

        let resolved = resolve_or_persist_tls_identity(
            &["ignored.local".to_owned()],
            Some(&cert_config),
            &auto_cert_path,
            &auto_key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("configured cert should be preferred");

        assert_eq!(
            resolved.certificate_pem(),
            configured_identity.certificate_pem(),
            "configured cert must be used instead of auto-generated one"
        );
        assert!(
            !auto_cert_path.exists(),
            "auto-persist paths should not be written when explicit cert is configured"
        );
    }

    #[test]
    fn resolve_or_persist_fails_when_configured_pem_files_are_corrupt() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let configured_cert_path = temp_dir.path().join("configured.crt");
        let configured_key_path = temp_dir.path().join("configured.key");
        std::fs::write(
            &configured_cert_path,
            b"-----BEGIN CERTIFICATE-----\n%%%invalid-base64%%%\n-----END CERTIFICATE-----\n",
        )
        .expect("certificate fixture should be written");
        std::fs::write(
            &configured_key_path,
            b"-----BEGIN PRIVATE KEY-----\n%%%invalid-base64%%%\n-----END PRIVATE KEY-----\n",
        )
        .expect("key fixture should be written");

        let auto_cert_path = temp_dir.path().join("teamserver.tls.crt");
        let auto_key_path = temp_dir.path().join("teamserver.tls.key");

        let cert_config = HttpListenerCertConfig {
            cert: configured_cert_path.display().to_string(),
            key: configured_key_path.display().to_string(),
        };

        let error = resolve_or_persist_tls_identity(
            &["ignored.local".to_owned()],
            Some(&cert_config),
            &auto_cert_path,
            &auto_key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect_err("corrupt configured PEM should fail without writing fallback material");

        assert!(
            matches!(error, PersistTlsError::Tls(TlsError::Pem(_))),
            "expected PersistTlsError::Tls(TlsError::Pem(_)), got: {error:?}"
        );
        assert!(
            !auto_cert_path.exists(),
            "fallback certificate path should remain untouched on PEM parse failure"
        );
        assert!(
            !auto_key_path.exists(),
            "fallback key path should remain untouched on PEM parse failure"
        );
    }

    #[test]
    fn resolve_or_persist_regenerates_both_files_when_only_cert_exists() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("teamserver.tls.crt");
        let key_path = temp_dir.path().join("teamserver.tls.key");

        // Simulate partial state: only the certificate was persisted (e.g. interrupted write).
        let stale_identity = generate_self_signed_tls_identity(
            &["stale.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("stale identity generation should succeed");
        std::fs::write(&cert_path, stale_identity.certificate_pem())
            .expect("stale certificate should be written");

        assert!(cert_path.exists(), "precondition: cert file should exist");
        assert!(!key_path.exists(), "precondition: key file should not exist");

        let identity = resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("cert-only partial state should trigger regeneration");

        // Both files must be written and match the returned identity.
        assert!(cert_path.exists(), "certificate file should be written");
        assert!(key_path.exists(), "private key file should be written");
        assert_eq!(
            std::fs::read(&cert_path).expect("cert should be readable"),
            identity.certificate_pem(),
            "on-disk cert must match returned identity"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("key should be readable"),
            identity.private_key_pem(),
            "on-disk key must match returned identity"
        );

        // The stale cert must be overwritten — the new cert/key pair must be consistent.
        assert_ne!(
            identity.certificate_pem(),
            stale_identity.certificate_pem(),
            "stale certificate should be replaced by a fresh one"
        );
        identity.server_config().expect("regenerated identity must produce a valid rustls config");
    }

    #[test]
    fn resolve_or_persist_regenerates_both_files_when_only_key_exists() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let cert_path = temp_dir.path().join("teamserver.tls.crt");
        let key_path = temp_dir.path().join("teamserver.tls.key");

        // Simulate partial state: only the key was persisted (e.g. cert deleted manually).
        let stale_identity = generate_self_signed_tls_identity(
            &["stale.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("stale identity generation should succeed");
        std::fs::write(&key_path, stale_identity.private_key_pem())
            .expect("stale private key should be written");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path).expect("key metadata").permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&key_path, perms)
                .expect("world-readable key simulates unsafe partial state");
        }

        assert!(!cert_path.exists(), "precondition: cert file should not exist");
        assert!(key_path.exists(), "precondition: key file should exist");

        let identity = resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("key-only partial state should trigger regeneration");

        // Both files must be written and match the returned identity.
        assert!(cert_path.exists(), "certificate file should be written");
        assert!(key_path.exists(), "private key file should be written");
        assert_eq!(
            std::fs::read(&cert_path).expect("cert should be readable"),
            identity.certificate_pem(),
            "on-disk cert must match returned identity"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("key should be readable"),
            identity.private_key_pem(),
            "on-disk key must match returned identity"
        );

        // The stale key must be overwritten — the new cert/key pair must be consistent.
        assert_ne!(
            identity.private_key_pem(),
            stale_identity.private_key_pem(),
            "stale private key should be replaced by a fresh one"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                std::fs::metadata(&key_path).expect("key metadata").permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "regenerated key must be chmod 0600 even when truncating a permissive file"
            );
        }

        identity.server_config().expect("regenerated identity must produce a valid rustls config");
    }

    #[test]
    fn resolve_or_persist_fails_when_write_directory_is_read_only() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");

        // Make the directory read-only so writes fail.
        let mut perms =
            std::fs::metadata(temp_dir.path()).expect("metadata should read").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o555);
        std::fs::set_permissions(temp_dir.path(), perms).expect("permissions should update");

        let cert_path = temp_dir.path().join("teamserver.tls.crt");
        let key_path = temp_dir.path().join("teamserver.tls.key");

        let result = resolve_or_persist_tls_identity(
            &["teamserver.local".to_owned()],
            None,
            &cert_path,
            &key_path,
            TlsKeyAlgorithm::EcdsaP256,
        );

        // Restore permissions so the temp dir can be cleaned up.
        let mut perms =
            std::fs::metadata(temp_dir.path()).expect("metadata should read").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(temp_dir.path(), perms).expect("permissions should restore");

        assert!(
            matches!(result, Err(PersistTlsError::WriteFile { .. })),
            "write failure should surface as PersistTlsError::WriteFile, got: {result:?}"
        );
    }

    #[test]
    fn validate_tls_not_expired_accepts_fresh_self_signed_cert() {
        install_default_crypto_provider();
        let identity = generate_self_signed_tls_identity(
            &["test.local".to_owned()],
            TlsKeyAlgorithm::EcdsaP256,
        )
        .expect("identity generation should succeed");

        let result = validate_tls_not_expired(identity.certificate_pem());
        assert!(result.is_ok(), "fresh self-signed cert should be valid, got: {result:?}");
    }

    #[test]
    fn validate_tls_not_expired_rejects_missing_certificate() {
        let result = validate_tls_not_expired(b"not a pem at all");
        assert!(
            matches!(result, Err(TlsError::MissingCertificates)),
            "missing cert should return MissingCertificates, got: {result:?}"
        );
    }

    #[test]
    fn validate_tls_not_expired_rejects_expired_cert() {
        use rcgen::{CertificateParams, DistinguishedName, KeyPair};
        use time::Duration;

        install_default_crypto_provider();
        let not_before = time::OffsetDateTime::now_utc() - Duration::days(30);
        let not_after = time::OffsetDateTime::now_utc() - Duration::days(2);

        let key_pair = KeyPair::generate().expect("key pair generation should succeed");
        let mut params = CertificateParams::new(vec!["expired.local".to_owned()])
            .expect("params should be created");
        params.not_before = not_before;
        params.not_after = not_after;
        params.distinguished_name = DistinguishedName::new();

        let cert = params.self_signed(&key_pair).expect("self-signed cert should be generated");
        let cert_pem = cert.pem();

        let result = validate_tls_not_expired(cert_pem.as_bytes());
        assert!(
            matches!(result, Err(TlsError::CertificateExpired { .. })),
            "expired cert should return CertificateExpired, got: {result:?}"
        );
    }

    #[test]
    fn validate_tls_not_expired_rejects_not_yet_valid_cert() {
        use rcgen::{CertificateParams, DistinguishedName, KeyPair};
        use time::Duration;

        install_default_crypto_provider();
        let not_before = time::OffsetDateTime::now_utc() + Duration::days(1);
        let not_after = time::OffsetDateTime::now_utc() + Duration::days(365);

        let key_pair = KeyPair::generate().expect("key pair generation should succeed");
        let mut params = CertificateParams::new(vec!["future.local".to_owned()])
            .expect("params should be created");
        params.not_before = not_before;
        params.not_after = not_after;
        params.distinguished_name = DistinguishedName::new();

        let cert = params.self_signed(&key_pair).expect("self-signed cert should be generated");
        let cert_pem = cert.pem();

        let result = validate_tls_not_expired(cert_pem.as_bytes());
        assert!(
            matches!(result, Err(TlsError::CertificateNotYetValid { .. })),
            "future cert should return CertificateNotYetValid, got: {result:?}"
        );
    }
}
