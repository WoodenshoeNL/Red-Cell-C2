//! Shared error types used by teamserver and client domain models.

use thiserror::Error;

/// Errors returned by common-domain parsing and validation helpers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommonError {
    /// A listener protocol string did not match a supported variant.
    #[error("unsupported listener protocol `{protocol}`")]
    UnsupportedListenerProtocol { protocol: String },
    /// An agent identifier could not be parsed from a decimal or hex string.
    #[error("invalid agent identifier `{value}`")]
    InvalidAgentId { value: String },
}

#[cfg(test)]
mod tests {
    use super::CommonError;

    #[test]
    fn variants_format_expected_user_facing_messages() {
        let unsupported_protocol =
            CommonError::UnsupportedListenerProtocol { protocol: "smtp".to_string() };
        let invalid_agent_id = CommonError::InvalidAgentId { value: "0xnothex".to_string() };

        assert_eq!(unsupported_protocol.to_string(), "unsupported listener protocol `smtp`");
        assert_eq!(invalid_agent_id.to_string(), "invalid agent identifier `0xnothex`");
    }

    #[test]
    fn variants_preserve_offending_input_values() {
        let protocol = "ws+tls".to_string();
        let invalid_value = "agent-007".to_string();

        let unsupported_protocol =
            CommonError::UnsupportedListenerProtocol { protocol: protocol.clone() };
        let invalid_agent_id = CommonError::InvalidAgentId { value: invalid_value.clone() };

        match unsupported_protocol {
            CommonError::UnsupportedListenerProtocol { protocol: actual } => {
                assert_eq!(actual, protocol);
            }
            CommonError::InvalidAgentId { .. } => {
                panic!("expected unsupported listener protocol variant")
            }
        }

        match invalid_agent_id {
            CommonError::InvalidAgentId { value } => {
                assert_eq!(value, invalid_value);
            }
            CommonError::UnsupportedListenerProtocol { .. } => {
                panic!("expected invalid agent identifier variant")
            }
        }
    }

    #[test]
    fn variants_support_stable_clone_and_equality_checks() {
        let original = CommonError::UnsupportedListenerProtocol { protocol: "http".to_string() };
        let clone = original.clone();
        let same = CommonError::UnsupportedListenerProtocol { protocol: "http".to_string() };
        let different = CommonError::UnsupportedListenerProtocol { protocol: "https".to_string() };

        assert_eq!(original, clone);
        assert_eq!(original, same);
        assert_ne!(original, different);
        assert_eq!(clone, same);
        assert_ne!(
            CommonError::InvalidAgentId { value: "42".to_string() },
            CommonError::InvalidAgentId { value: "0x2a".to_string() }
        );
    }
}
