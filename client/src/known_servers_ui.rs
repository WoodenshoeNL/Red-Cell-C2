//! TOFU / certificate trust actions for the known-servers store.

use crate::app::{AppPhase, ClientApp};
use crate::known_servers::host_port_from_url;
use crate::transport::TlsVerification;

impl ClientApp {
    /// Handle the user trusting (or re-trusting) a server certificate.
    ///
    /// Stores the fingerprint in the known-servers file keyed by host:port,
    /// updates the TLS verification mode to pin against that fingerprint, and
    /// also persists the fingerprint in the legacy per-client config for
    /// backwards compatibility.
    pub(crate) fn handle_trust_certificate(&mut self, fingerprint: String) {
        let server_url = match &self.phase {
            AppPhase::Login(login_state) => login_state.server_url.trim().to_owned(),
            _ => self.cli_server_url.clone(),
        };
        if let Some(host_port) = host_port_from_url(&server_url) {
            self.known_servers.trust(&host_port, &fingerprint, None);
            if let Err(error) = self.known_servers.save() {
                tracing::warn!(
                    %error,
                    "failed to persist certificate trust — \
                     TOFU decision will be lost on next launch",
                );
            }
        }
        // Also keep the legacy global fingerprint for backwards compat.
        self.local_config.cert_fingerprint = Some(fingerprint.clone());
        self.tls_verification = TlsVerification::Fingerprint(fingerprint);
        if let Err(error) = self.local_config.save() {
            tracing::warn!(
                %error,
                "failed to persist pinned certificate fingerprint — \
                 TLS trust decision will be lost on next launch",
            );
        }
    }
}
