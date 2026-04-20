use base64::Engine as _;
use red_cell_common::ListenerConfig;

use crate::database::Database;

/// Returns the ECDH public key that must be embedded in an Archon build, or
/// `None` when the build does not require one (non-Archon agent type or legacy
/// HTTP listener).
///
/// Logs a debug message on success and an error message on failure.
pub(crate) async fn ecdh_pub_key_for_archon_build(
    agent_type: &str,
    listener_config: &ListenerConfig,
    listener_name: &str,
    database: &Database,
) -> Result<Option<[u8; 32]>, String> {
    let is_archon = agent_type.eq_ignore_ascii_case("Archon");
    let is_non_legacy_http = matches!(
        listener_config,
        ListenerConfig::Http(http) if !http.legacy_mode
    );

    if !is_archon || !is_non_legacy_http {
        return Ok(None);
    }

    match database.ecdh().get_or_create_keypair(listener_name).await {
        Ok(kp) => {
            tracing::debug!(
                listener = listener_name,
                public_key = %base64::engine::general_purpose::STANDARD.encode(kp.public_bytes),
                "injecting ECDH public key into Archon build"
            );
            Ok(Some(kp.public_bytes))
        }
        Err(err) => {
            tracing::error!(
                listener = listener_name,
                error = %err,
                "failed to load ECDH keypair for Archon build — refusing to build without ECDH"
            );
            Err(format!("failed to load ECDH keypair for listener '{}': {err}", listener_name))
        }
    }
}
