//! Shared TLS helpers for the CLI's HTTP and WebSocket clients.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::config::FingerprintPinMode;
use crate::error::CliError;

/// Computes the SHA-256 fingerprint of a DER-encoded certificate as lowercase
/// hexadecimal.
pub(crate) fn certificate_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Builds a rustls client configuration that verifies a pinned SHA-256
/// fingerprint per [`FingerprintPinMode`].
pub(crate) fn build_fingerprint_client_config(
    expected_fingerprint: &str,
    pin_mode: FingerprintPinMode,
) -> Result<ClientConfig, CliError> {
    let provider = rustls::crypto::ring::default_provider();
    let verifier =
        Arc::new(FingerprintCertVerifier::new(expected_fingerprint, pin_mode, provider.clone()));

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| CliError::General(format!("TLS protocol configuration failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(config)
}

#[derive(Debug)]
struct FingerprintCertVerifier {
    expected_fingerprint: String,
    pin_mode: FingerprintPinMode,
    provider: rustls::crypto::CryptoProvider,
}

impl FingerprintCertVerifier {
    fn new(
        expected_fingerprint: &str,
        pin_mode: FingerprintPinMode,
        provider: rustls::crypto::CryptoProvider,
    ) -> Self {
        Self { expected_fingerprint: expected_fingerprint.to_ascii_lowercase(), pin_mode, provider }
    }
}

impl ServerCertVerifier for FingerprintCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let matches = match self.pin_mode {
            FingerprintPinMode::Leaf => {
                certificate_fingerprint(end_entity.as_ref()) == self.expected_fingerprint
            }
            FingerprintPinMode::Chain => std::iter::once(end_entity.as_ref())
                .chain(intermediates.iter().map(|c| c.as_ref()))
                .any(|der| certificate_fingerprint(der) == self.expected_fingerprint),
        };

        if matches {
            Ok(ServerCertVerified::assertion())
        } else {
            let leaf_fp = certificate_fingerprint(end_entity.as_ref());
            warn!(
                expected = %self.expected_fingerprint,
                pin_mode = ?self.pin_mode,
                leaf = %leaf_fp,
                "TLS certificate fingerprint mismatch"
            );
            let scope = match self.pin_mode {
                FingerprintPinMode::Leaf => "leaf certificate",
                FingerprintPinMode::Chain => "presented certificate chain",
            };
            Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch ({scope}): expected {}, leaf fingerprint was {leaf_fp}",
                self.expected_fingerprint
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
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
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
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

#[cfg(test)]
mod tests {
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use crate::config::FingerprintPinMode;

    use super::{FingerprintCertVerifier, certificate_fingerprint};

    fn dummy_leaf_der() -> Vec<u8> {
        vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]
    }

    fn dummy_intermediate_der() -> Vec<u8> {
        vec![0xca, 0xfe, 0xba, 0xbe, 0x10, 0x20, 0x30, 0x40]
    }

    #[test]
    fn certificate_fingerprint_produces_lowercase_hex_sha256() {
        let input = [0u8; 32];
        let fingerprint = certificate_fingerprint(&input);
        assert_eq!(fingerprint.len(), 64, "fingerprint must be 64 hex chars");
        assert!(fingerprint.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(fingerprint, fingerprint.to_ascii_lowercase());
    }

    #[test]
    fn fingerprint_verifier_accepts_matching_cert() {
        let cert_bytes = dummy_leaf_der();
        let verifier = FingerprintCertVerifier::new(
            &certificate_fingerprint(&cert_bytes),
            FingerprintPinMode::Leaf,
            rustls::crypto::ring::default_provider(),
        );
        let cert = CertificateDer::from(cert_bytes);
        let server_name = ServerName::try_from("teamserver.example.com").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok(), "matching fingerprint must be accepted");
    }

    #[test]
    fn fingerprint_verifier_rejects_mismatched_cert() {
        let cert_bytes = dummy_leaf_der();
        let verifier = FingerprintCertVerifier::new(
            &certificate_fingerprint(&cert_bytes),
            FingerprintPinMode::Leaf,
            rustls::crypto::ring::default_provider(),
        );
        let cert = CertificateDer::from(vec![0xca, 0xfe, 0xba, 0xbe]);
        let server_name = ServerName::try_from("teamserver.example.com").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_err(), "mismatched fingerprint must be rejected");
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("fingerprint mismatch"),
            "error message must mention fingerprint mismatch, got: {error_message}"
        );
    }

    #[test]
    fn fingerprint_verifier_normalises_uppercase_input() {
        let cert_bytes = dummy_leaf_der();
        let verifier = FingerprintCertVerifier::new(
            &certificate_fingerprint(&cert_bytes).to_ascii_uppercase(),
            FingerprintPinMode::Leaf,
            rustls::crypto::ring::default_provider(),
        );
        let cert = CertificateDer::from(cert_bytes);
        let server_name = ServerName::try_from("ts.example.com").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok(), "lowercased fingerprint must be accepted");
    }

    #[test]
    fn chain_mode_accepts_intermediate_when_leaf_differs() {
        let leaf = dummy_leaf_der();
        let intermediate = dummy_intermediate_der();
        let verifier = FingerprintCertVerifier::new(
            &certificate_fingerprint(&intermediate),
            FingerprintPinMode::Chain,
            rustls::crypto::ring::default_provider(),
        );
        let leaf_cert = CertificateDer::from(leaf);
        let im_cert = CertificateDer::from(intermediate);
        let server_name = ServerName::try_from("ts.example.com").unwrap();
        let result =
            verifier.verify_server_cert(&leaf_cert, &[im_cert], &server_name, &[], UnixTime::now());
        assert!(result.is_ok(), "intermediate fingerprint must match in chain mode");
    }

    #[test]
    fn chain_mode_rejects_when_no_cert_matches() {
        let leaf = dummy_leaf_der();
        let intermediate = dummy_intermediate_der();
        let verifier = FingerprintCertVerifier::new(
            "00".repeat(32).as_str(),
            FingerprintPinMode::Chain,
            rustls::crypto::ring::default_provider(),
        );
        let leaf_cert = CertificateDer::from(leaf);
        let im_cert = CertificateDer::from(intermediate);
        let server_name = ServerName::try_from("ts.example.com").unwrap();
        let result =
            verifier.verify_server_cert(&leaf_cert, &[im_cert], &server_name, &[], UnixTime::now());
        assert!(result.is_err(), "must reject when chain has no matching fingerprint");
    }

    #[test]
    fn leaf_mode_ignores_matching_intermediate() {
        let leaf = dummy_leaf_der();
        let intermediate = dummy_intermediate_der();
        let verifier = FingerprintCertVerifier::new(
            &certificate_fingerprint(&intermediate),
            FingerprintPinMode::Leaf,
            rustls::crypto::ring::default_provider(),
        );
        let leaf_cert = CertificateDer::from(leaf);
        let im_cert = CertificateDer::from(intermediate);
        let server_name = ServerName::try_from("ts.example.com").unwrap();
        let result =
            verifier.verify_server_cert(&leaf_cert, &[im_cert], &server_name, &[], UnixTime::now());
        assert!(
            result.is_err(),
            "leaf mode must not accept a pin that matches only an intermediate"
        );
    }
}
