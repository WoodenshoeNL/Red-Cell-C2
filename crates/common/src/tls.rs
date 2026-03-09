//! TLS certificate generation and loading helpers for teamserver services.

use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256};
use thiserror::Error;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
    private_key_pem: Vec<u8>,
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
        private_key_pem: key_pem.to_vec(),
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

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use tempfile::TempDir;
    use x509_parser::prelude::FromDer;

    use super::{
        TlsError, TlsIdentity, TlsKeyAlgorithm, generate_self_signed_tls_identity,
        load_tls_identity, load_tls_identity_from_files, resolve_tls_identity,
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
    fn resolve_tls_identity_generates_material_when_profile_cert_paths_are_absent() {
        let resolved =
            resolve_tls_identity(&["ws.local".to_owned()], None, TlsKeyAlgorithm::EcdsaP256)
                .expect("missing profile PEMs should trigger generation");

        assert!(resolved.certificate_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(resolved.tls_acceptor().is_ok());
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
}
