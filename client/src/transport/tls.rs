use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{self, aws_lc_rs};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_tungstenite::Connector;
use tracing::warn;
use url::Url;

use crate::login::TlsFailureKind;

use super::TransportError;

/// Controls how the client verifies the teamserver's TLS certificate.
#[derive(Debug, Clone)]
pub(crate) enum TlsVerification {
    /// Verify against system/webpki root CA certificates (default, secure).
    CertificateAuthority,
    /// Verify against a custom CA certificate loaded from a PEM file.
    CustomCa(PathBuf),
    /// Pin against a specific SHA-256 certificate fingerprint (hex-encoded).
    Fingerprint(String),
    /// Skip all certificate verification. Requires explicit opt-in via
    /// `--accept-invalid-certs`. Logs a prominent warning on every connection.
    DangerousSkipVerify,
}

/// Normalise the raw server URL string to a canonical WebSocket URL.
///
/// Accepts `ws://` and `wss://` schemes. Rejects `http://`, `https://`, and
/// any unrecognised scheme. Appends the `/havoc` path suffix when the path is
/// absent or root-only so callers do not need to include it explicitly.
pub(super) fn normalize_server_url(server_url: &str) -> Result<String, TransportError> {
    let mut url = Url::parse(server_url)
        .map_err(|source| TransportError::InvalidUrl { url: server_url.to_owned(), source })?;

    match url.scheme() {
        "ws" | "wss" => {}
        other => {
            return Err(TransportError::UnsupportedScheme { scheme: other.to_owned() });
        }
    }

    if url.host().is_none() {
        return Err(TransportError::MissingHost);
    }

    let normalized_path = match url.path() {
        "" | "/" | "/havoc" | "/havoc/" => "/havoc/".to_owned(),
        other => other.to_owned(),
    };
    url.set_path(&normalized_path);

    Ok(url.to_string())
}

/// Returns true when the error string indicates a TLS *certificate* problem that will not
/// self-heal on retry (e.g. expired cert, hostname mismatch, untrusted CA).
pub(super) fn is_tls_cert_error(err: &str) -> bool {
    err.contains("invalid peer certificate:") || err.contains("certificate fingerprint mismatch")
}

/// Translate a raw connection error into an actionable message for the UI.
/// Falls back to the raw error string when no specific pattern matches.
pub(crate) fn classify_tls_error(err: &str) -> String {
    if err.contains("invalid peer certificate:") {
        if err.contains("certificate expired") || err.contains("Expired") {
            return "The server's TLS certificate has expired. \
                     Contact your teamserver administrator to renew it."
                .to_owned();
        }
        if err.contains("not valid for name") || err.contains("NotValidForName") {
            return "TLS hostname mismatch: the server URL's hostname does not match \
                     the certificate. Verify the server address."
                .to_owned();
        }
        if err.contains("UnknownIssuer") || err.contains("unknown issuer") {
            return "The server's TLS certificate is signed by an unknown authority. \
                     Use --ca-cert to specify the CA certificate, or trust the \
                     certificate by its fingerprint."
                .to_owned();
        }
        return format!("TLS certificate error: {err}");
    }
    if err.contains("certificate fingerprint mismatch") {
        return "The server's certificate fingerprint does not match the pinned value. \
                 The certificate may have been renewed — verify with your administrator."
            .to_owned();
    }
    if err.contains("Connection refused")
        || err.contains("connection refused")
        || err.contains("os error 111")
    {
        return "Connection refused: check that the teamserver is running \
                 and the address is correct."
            .to_owned();
    }
    err.to_owned()
}

/// Classify the TLS failure into a [`TlsFailureKind`] for UI rendering.
///
/// Fingerprint mismatches (from TOFU pinned certs) map to [`TlsFailureKind::CertificateChanged`].
/// Unknown-issuer errors (self-signed, first connect) map to [`TlsFailureKind::UnknownServer`].
/// Everything else is a generic [`TlsFailureKind::CertificateError`].
pub(crate) fn classify_tls_failure_kind(err: &str) -> TlsFailureKind {
    if err.contains("certificate fingerprint mismatch") {
        // Extract the stored (expected) fingerprint from the error message.
        // Format: "certificate fingerprint mismatch: expected <hex64>, got <hex64>"
        let stored = err
            .strip_suffix(|_: char| false)
            .unwrap_or(err)
            .split("expected ")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .unwrap_or("")
            .trim()
            .to_owned();
        return TlsFailureKind::CertificateChanged { stored_fingerprint: stored };
    }
    if err.contains("UnknownIssuer") || err.contains("unknown issuer") {
        return TlsFailureKind::UnknownServer;
    }
    TlsFailureKind::CertificateError
}

/// Build a [`Connector`] from the given [`TlsVerification`] policy.
///
/// Captures the server certificate fingerprint into `fingerprint_sink` on every
/// connection attempt so callers can display or pin it regardless of whether
/// verification succeeds.
pub(super) fn build_tls_connector(
    verification: &TlsVerification,
    fingerprint_sink: Arc<std::sync::Mutex<Option<String>>>,
) -> Result<Connector, TransportError> {
    let provider = aws_lc_rs::default_provider();

    let mut client_config = match verification {
        TlsVerification::CertificateAuthority => {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let inner: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store),
                provider.clone().into(),
            )
            .build()
            .map_err(|e| TransportError::RustlsVerifier(e.to_string()))?;
            let verifier = Arc::new(CapturingCertVerifier { inner, fingerprint_sink });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        TlsVerification::CustomCa(path) => {
            let ca_pem = std::fs::read(path).map_err(|source| TransportError::CustomCaRead {
                path: path.display().to_string(),
                source,
            })?;
            let mut reader = BufReader::new(ca_pem.as_slice());
            let mut root_store = RootCertStore::empty();
            let mut found_any = false;
            for cert_result in rustls_pemfile::certs(&mut reader) {
                let cert = cert_result.map_err(TransportError::CustomCaParse)?;
                root_store
                    .add(cert)
                    .map_err(|error| TransportError::CustomCaInvalid(error.to_string()))?;
                found_any = true;
            }
            if !found_any {
                return Err(TransportError::CustomCaEmpty(path.display().to_string()));
            }
            let inner: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store),
                provider.clone().into(),
            )
            .build()
            .map_err(|e| TransportError::RustlsVerifier(e.to_string()))?;
            let verifier = Arc::new(CapturingCertVerifier { inner, fingerprint_sink });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        TlsVerification::Fingerprint(expected) => {
            let verifier = Arc::new(FingerprintCertificateVerifier {
                expected_fingerprint: expected.to_ascii_lowercase(),
                provider: provider.clone(),
                fingerprint_sink,
            });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        TlsVerification::DangerousSkipVerify => {
            warn!(
                "TLS certificate verification is DISABLED — connections are vulnerable to MITM attacks"
            );
            let verifier = Arc::new(DangerousCertificateVerifier { provider: provider.clone() });
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|error| TransportError::Rustls(Box::new(error)))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };

    // Advertise HTTP/1.1 via ALPN so the server does not default to HTTP/2,
    // which does not support the WebSocket upgrade mechanism.
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Connector::Rustls(Arc::new(client_config)))
}

/// Wraps an inner [`ServerCertVerifier`], capturing the end-entity certificate's SHA-256
/// fingerprint before delegating. This lets the caller display or pin the server's certificate
/// even when CA verification fails.
#[derive(Debug)]
struct CapturingCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    fingerprint_sink: Arc<std::sync::Mutex<Option<String>>>,
}

impl ServerCertVerifier for CapturingCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        // Capture the fingerprint before verification so it's available even on failure.
        let fp = certificate_fingerprint(end_entity.as_ref());
        if let Ok(mut sink) = self.fingerprint_sink.lock() {
            *sink = Some(fp);
        }
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Compute the lowercase hex-encoded SHA-256 fingerprint of a DER-encoded certificate.
pub(crate) fn certificate_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Verifies the server certificate by comparing its SHA-256 fingerprint against
/// a pinned value. Signature verification still uses the real crypto provider.
#[derive(Debug)]
pub(super) struct FingerprintCertificateVerifier {
    pub(super) expected_fingerprint: String,
    pub(super) provider: crypto::CryptoProvider,
    /// Captures the server's actual certificate fingerprint (may differ from expected).
    pub(super) fingerprint_sink: Arc<std::sync::Mutex<Option<String>>>,
}

impl ServerCertVerifier for FingerprintCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let actual = certificate_fingerprint(end_entity.as_ref());
        // Always capture the actual fingerprint so the caller can show it on mismatch.
        if let Ok(mut sink) = self.fingerprint_sink.lock() {
            *sink = Some(actual.clone());
        }
        if actual == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(tokio_rustls::rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected {}, got {actual}",
                self.expected_fingerprint
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Accepts any server certificate without verification. Only used when the operator
/// explicitly passes `--accept-invalid-certs`.
#[derive(Debug)]
struct DangerousCertificateVerifier {
    provider: crypto::CryptoProvider,
}

impl ServerCertVerifier for DangerousCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
