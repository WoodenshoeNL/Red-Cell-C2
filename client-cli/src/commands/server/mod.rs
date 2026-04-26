//! `red-cell-cli server cert` — fetch the teamserver's TLS certificate
//! fingerprint and metadata without requiring authentication or `openssl`.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{self, OutputFormat, TextRender};
use crate::tls::certificate_fingerprint;

/// Metadata for a single certificate in the chain.
#[derive(Debug, Serialize)]
pub struct CertInfo {
    /// Position in the chain: 0 = leaf, 1+ = intermediates.
    pub position: usize,
    /// SHA-256 fingerprint as lowercase hex (64 chars).
    pub fingerprint: String,
    /// Subject distinguished name (e.g. "CN=teamserver").
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Not-valid-after timestamp (RFC 3339).
    pub not_after: String,
    /// Not-valid-before timestamp (RFC 3339).
    pub not_before: String,
    /// PEM-encoded certificate (only present when `--pem` is used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pem: Option<String>,
}

/// Output for `red-cell-cli server cert`.
#[derive(Debug, Serialize)]
pub struct ServerCertOutput {
    /// Server URL that was connected to.
    pub server: String,
    /// Certificate chain (leaf first).
    pub certificates: Vec<CertInfo>,
}

impl TextRender for ServerCertOutput {
    fn render_text(&self) -> String {
        let mut lines = Vec::new();
        for cert in &self.certificates {
            if cert.position == 0 {
                lines.push(cert.fingerprint.clone());
            } else {
                lines.push(format!("[{}] {}", cert.position, cert.fingerprint));
            }
            if let Some(ref pem_data) = cert.pem {
                lines.push(pem_data.clone());
            }
        }
        lines.join("\n")
    }
}

/// Execute `red-cell-cli server cert`.
pub async fn run_cert(server_url: &str, chain: bool, include_pem: bool, fmt: &OutputFormat) -> i32 {
    match fetch_certs(server_url, chain, include_pem).await {
        Ok(data) => match output::print_success(fmt, &data) {
            Ok(()) => EXIT_SUCCESS,
            Err(e) => {
                output::print_error(&e).ok();
                e.exit_code()
            }
        },
        Err(e) => {
            output::print_error(&e).ok();
            e.exit_code()
        }
    }
}

/// Connect to the server via TLS, capture the certificate chain, and return
/// structured metadata.
async fn fetch_certs(
    server_url: &str,
    chain: bool,
    include_pem: bool,
) -> Result<ServerCertOutput, CliError> {
    let url = server_url.trim_end_matches('/');

    let (host, port) = parse_https_url(url)?;

    let captured = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(CertCaptureVerifier {
        captured: Arc::clone(&captured),
        provider: provider.clone(),
    });

    let tls_config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| CliError::General(format!("TLS protocol configuration failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| CliError::InvalidArgs(format!("invalid server name '{host}': {e}")))?;

    let tcp = TcpStream::connect((host.as_str(), port)).await.map_err(|e| {
        CliError::ServerUnreachable(format!("cannot connect to {host}:{port}: {e}"))
    })?;

    // SECURITY: stream is dropped immediately — CertCaptureVerifier does not
    // validate the peer, so this connection must never carry traffic.
    let _tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
        CliError::ServerUnreachable(format!("TLS handshake with {host}:{port} failed: {e}"))
    })?;
    drop(_tls_stream);

    let certs_der = captured
        .lock()
        .map_err(|_| CliError::General("failed to read captured certificates".to_owned()))?;

    if certs_der.is_empty() {
        return Err(CliError::General(
            "server presented no certificates during TLS handshake".to_owned(),
        ));
    }

    let limit = if chain { certs_der.len() } else { 1 };

    let mut certificates = Vec::with_capacity(limit);
    for (i, der) in certs_der.iter().take(limit).enumerate() {
        let fingerprint = certificate_fingerprint(der);
        let (subject, issuer, not_before, not_after) = parse_x509_metadata(der);

        let pem = if include_pem { Some(der_to_pem(der)) } else { None };

        certificates.push(CertInfo {
            position: i,
            fingerprint,
            subject,
            issuer,
            not_after,
            not_before,
            pem,
        });
    }

    Ok(ServerCertOutput { server: url.to_owned(), certificates })
}

/// Parse subject, issuer, and validity from DER-encoded certificate bytes.
fn parse_x509_metadata(der: &[u8]) -> (String, String, String, String) {
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let not_before =
                cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "(unknown)".to_owned());
            let not_after =
                cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "(unknown)".to_owned());
            (subject, issuer, not_before, not_after)
        }
        Err(_) => {
            let unknown = "(parse error)".to_owned();
            (unknown.clone(), unknown.clone(), unknown.clone(), unknown)
        }
    }
}

/// Encode DER bytes as a PEM CERTIFICATE block.
fn der_to_pem(der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for start in (0..b64.len()).step_by(64) {
        let end = (start + 64).min(b64.len());
        pem.push_str(&b64[start..end]);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----");
    pem
}

/// Parse an `https://host:port` URL into `(host, port)`.
fn parse_https_url(url: &str) -> Result<(String, u16), CliError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        CliError::InvalidArgs(
            "server cert requires an https:// URL (no TLS on plain HTTP)".to_owned(),
        )
    })?;

    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(CliError::InvalidArgs("server URL has no host".to_owned()));
    }

    let (host, port) = if authority.starts_with('[') {
        // IPv6 literal: [host]:port or [host]
        let bracket_end = authority.find(']').ok_or_else(|| {
            CliError::InvalidArgs(format!("unclosed bracket in IPv6 URL: {authority}"))
        })?;
        let h = &authority[1..bracket_end];
        let rest = &authority[bracket_end + 1..];
        let p = if let Some(port_str) = rest.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| CliError::InvalidArgs(format!("invalid port in URL: {authority}")))?
        } else {
            443
        };
        (h.to_owned(), p)
    } else if let Some(colon_pos) = authority.rfind(':') {
        let h = &authority[..colon_pos];
        let p: u16 = authority[colon_pos + 1..]
            .parse()
            .map_err(|_| CliError::InvalidArgs(format!("invalid port in URL: {authority}")))?;
        (h.to_owned(), p)
    } else {
        (authority.to_owned(), 443)
    };

    if host.is_empty() {
        return Err(CliError::InvalidArgs("server URL has no host".to_owned()));
    }

    Ok((host, port))
}

// ── Certificate-capturing TLS verifier ──────────────────────────────────────

/// SECURITY: This verifier accepts ANY server certificate without validation.
///
/// It exists solely to capture the raw DER bytes of the certificate chain
/// during the TLS handshake.  The resulting TLS stream **must be dropped
/// immediately** after the handshake completes — it must never be used to
/// send or receive application data, because the peer's identity has not
/// been verified.
///
/// This struct is intentionally `pub(self)` (file-private) to prevent use
/// outside `fetch_certs`.
#[derive(Debug)]
struct CertCaptureVerifier {
    captured: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    provider: rustls::crypto::CryptoProvider,
}

impl ServerCertVerifier for CertCaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut certs) = self.captured.lock() {
            certs.push(end_entity.to_vec());
            for im in intermediates {
                certs.push(im.to_vec());
            }
        }
        Ok(ServerCertVerified::assertion())
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
    use super::*;

    #[test]
    fn der_to_pem_wraps_at_64_chars() {
        let der = vec![0u8; 100];
        let pem = der_to_pem(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
        for line in pem.lines() {
            if line.starts_with("-----") {
                continue;
            }
            assert!(line.len() <= 64, "PEM line exceeds 64 chars: {} (len={})", line, line.len());
        }
    }

    #[test]
    fn der_to_pem_roundtrips() {
        let der = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let pem = der_to_pem(&der);
        let parsed = pem.lines().filter(|l| !l.starts_with("-----")).collect::<String>();
        use base64::Engine as _;
        let decoded =
            base64::engine::general_purpose::STANDARD.decode(&parsed).expect("valid base64");
        assert_eq!(decoded, der);
    }

    #[test]
    fn parse_x509_metadata_returns_parse_error_for_invalid_der() {
        let garbage = vec![0xFF, 0x00, 0x01];
        let (subject, issuer, not_before, not_after) = parse_x509_metadata(&garbage);
        assert_eq!(subject, "(parse error)");
        assert_eq!(issuer, "(parse error)");
        assert_eq!(not_before, "(parse error)");
        assert_eq!(not_after, "(parse error)");
    }

    #[test]
    fn cert_info_skips_pem_when_none() {
        let info = CertInfo {
            position: 0,
            fingerprint: "aa".repeat(32),
            subject: "CN=test".to_owned(),
            issuer: "CN=ca".to_owned(),
            not_after: "2030-01-01T00:00:00Z".to_owned(),
            not_before: "2020-01-01T00:00:00Z".to_owned(),
            pem: None,
        };
        let json = serde_json::to_value(&info).expect("serialize");
        assert!(!json.as_object().expect("object").contains_key("pem"));
    }

    #[test]
    fn cert_info_includes_pem_when_some() {
        let info = CertInfo {
            position: 0,
            fingerprint: "aa".repeat(32),
            subject: "CN=test".to_owned(),
            issuer: "CN=ca".to_owned(),
            not_after: "2030-01-01T00:00:00Z".to_owned(),
            not_before: "2020-01-01T00:00:00Z".to_owned(),
            pem: Some("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----".to_owned()),
        };
        let json = serde_json::to_value(&info).expect("serialize");
        assert!(json.as_object().expect("object").contains_key("pem"));
    }

    #[test]
    fn text_render_leaf_only() {
        let output = ServerCertOutput {
            server: "https://ts:40056".to_owned(),
            certificates: vec![CertInfo {
                position: 0,
                fingerprint: "ab".repeat(32),
                subject: "CN=test".to_owned(),
                issuer: "CN=ca".to_owned(),
                not_after: "2030-01-01".to_owned(),
                not_before: "2020-01-01".to_owned(),
                pem: None,
            }],
        };
        let text = output.render_text();
        assert_eq!(text, "ab".repeat(32));
    }

    #[test]
    fn text_render_chain_shows_positions() {
        let output = ServerCertOutput {
            server: "https://ts:40056".to_owned(),
            certificates: vec![
                CertInfo {
                    position: 0,
                    fingerprint: "aa".repeat(32),
                    subject: "CN=leaf".to_owned(),
                    issuer: "CN=intermediate".to_owned(),
                    not_after: "2030-01-01".to_owned(),
                    not_before: "2020-01-01".to_owned(),
                    pem: None,
                },
                CertInfo {
                    position: 1,
                    fingerprint: "bb".repeat(32),
                    subject: "CN=intermediate".to_owned(),
                    issuer: "CN=root".to_owned(),
                    not_after: "2035-01-01".to_owned(),
                    not_before: "2020-01-01".to_owned(),
                    pem: None,
                },
            ],
        };
        let text = output.render_text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "aa".repeat(32));
        assert!(lines[1].starts_with("[1] "));
        assert!(lines[1].contains(&"bb".repeat(32)));
    }

    #[test]
    fn server_cert_output_json_shape() {
        let output = ServerCertOutput {
            server: "https://ts:40056".to_owned(),
            certificates: vec![CertInfo {
                position: 0,
                fingerprint: "cc".repeat(32),
                subject: "CN=test".to_owned(),
                issuer: "CN=ca".to_owned(),
                not_after: "2030-01-01".to_owned(),
                not_before: "2020-01-01".to_owned(),
                pem: None,
            }],
        };
        let json = serde_json::to_value(&output).expect("serialize");
        assert_eq!(json["server"], "https://ts:40056");
        assert!(json["certificates"].is_array());
        assert_eq!(json["certificates"][0]["fingerprint"], "cc".repeat(32));
        assert_eq!(json["certificates"][0]["subject"], "CN=test");
    }

    #[test]
    fn parse_ipv6_with_port() {
        let (host, port) = parse_https_url("https://[::1]:40056").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 40056);
    }

    #[test]
    fn parse_ipv6_default_port() {
        let (host, port) = parse_https_url("https://[::1]").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_ipv6_full_address_with_port() {
        let (host, port) = parse_https_url("https://[2001:db8::1]:8443").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_ipv6_with_path() {
        let (host, port) = parse_https_url("https://[::1]:9090/api").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 9090);
    }

    #[test]
    fn parse_ipv6_unclosed_bracket() {
        let result = parse_https_url("https://[::1:40056");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unclosed bracket"), "got: {msg}");
    }

    #[test]
    fn parse_ipv4_with_port_unchanged() {
        let (host, port) = parse_https_url("https://10.0.0.1:40056").unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 40056);
    }

    #[test]
    fn parse_hostname_default_port() {
        let (host, port) = parse_https_url("https://ts.example.com").unwrap();
        assert_eq!(host, "ts.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn rejects_http_url() {
        let rt =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        let result = rt.block_on(fetch_certs("http://ts:40056", false, false));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("https://"), "should suggest https, got: {msg}");
    }

    #[test]
    fn rejects_invalid_url() {
        let rt =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        let result = rt.block_on(fetch_certs("not a url", false, false));
        assert!(result.is_err());
    }

    #[test]
    fn cert_capture_verifier_accepts_any_cert() {
        let captured = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let provider = rustls::crypto::ring::default_provider();
        let verifier = CertCaptureVerifier { captured: Arc::clone(&captured), provider };

        // Fabricate DER bytes that are NOT a valid certificate — the verifier
        // must still store them and return Ok, proving it does no validation.
        let fake_leaf = CertificateDer::from(vec![0xDE, 0xAD, 0x01]);
        let fake_intermediate = CertificateDer::from(vec![0xBE, 0xEF, 0x02]);
        let server_name = ServerName::try_from("example.com").unwrap();

        let result = verifier.verify_server_cert(
            &fake_leaf,
            &[fake_intermediate],
            &server_name,
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok(), "verifier must accept any certificate");

        let certs = captured.lock().unwrap();
        assert_eq!(certs.len(), 2, "should capture leaf + 1 intermediate");
        assert_eq!(certs[0], vec![0xDE, 0xAD, 0x01]);
        assert_eq!(certs[1], vec![0xBE, 0xEF, 0x02]);
    }
}
