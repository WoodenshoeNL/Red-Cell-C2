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
    /// OS entropy source failed while generating random TLS validity period.
    #[error("failed to read random bytes from OS entropy source")]
    CertGeneration,
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
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    // Randomize validity between 60 and 120 days to avoid the static 365-day fingerprint
    // that certificate scanners (Censys, Shodan) flag as a C2 indicator.
    let validity_days = {
        let mut buf = [0u8; 1];
        getrandom::fill(&mut buf).map_err(|_| TlsError::CertGeneration)?;
        i64::from(60 + (buf[0] % 61))
    };
    params.not_after = now + time::Duration::days(validity_days);

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
