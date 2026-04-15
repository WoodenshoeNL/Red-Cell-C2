//! Login response message builders and small operator protocol helpers.

use red_cell_common::OperatorInfo;
use red_cell_common::config::OperatorRole;
use red_cell_common::operator::{EventCode, Message, MessageHead, MessageInfo, OperatorMessage};

use super::AuthenticationFailure;

/// Operator account inventory entry with current presence metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorPresence {
    /// Operator username.
    pub username: String,
    /// RBAC role assigned to the operator account.
    pub role: OperatorRole,
    /// Whether the operator currently has an authenticated session.
    pub online: bool,
    /// Most recent persisted operator activity timestamp.
    pub last_seen: Option<String>,
}

impl OperatorPresence {
    /// Convert the operator-presence entry into the shared wire/domain representation.
    #[must_use]
    pub fn as_operator_info(&self) -> OperatorInfo {
        OperatorInfo {
            username: self.username.clone(),
            password_hash: None,
            role: Some(operator_role_name(self.role).to_owned()),
            online: self.online,
            last_seen: self.last_seen.clone(),
        }
    }
}

/// Build a success response for an authenticated login handshake.
#[must_use]
pub fn login_success_message(user: &str, token: &str) -> OperatorMessage {
    OperatorMessage::InitConnectionSuccess(Message {
        head: login_response_head(user),
        info: MessageInfo { message: format!("Successful Authenticated; SessionToken={token}") },
    })
}

/// Build an error response for a rejected login handshake.
#[must_use]
pub fn login_failure_message(user: &str, failure: &AuthenticationFailure) -> OperatorMessage {
    OperatorMessage::InitConnectionError(Message {
        head: login_response_head(user),
        info: MessageInfo { message: failure.message().to_owned() },
    })
}

fn login_response_head(user: &str) -> MessageHead {
    MessageHead {
        event: EventCode::InitConnection,
        user: user.to_owned(),
        timestamp: String::new(),
        one_time: String::new(),
    }
}

const fn operator_role_name(role: OperatorRole) -> &'static str {
    match role {
        OperatorRole::Admin => "Admin",
        OperatorRole::Operator => "Operator",
        OperatorRole::Analyst => "Analyst",
    }
}

#[cfg(test)]
mod tests {
    use red_cell_common::config::OperatorRole;
    use red_cell_common::operator::{EventCode, InitConnectionCode};
    use serde_json::json;

    use super::*;

    #[test]
    fn operator_presence_as_operator_info_preserves_wire_fields() {
        let presence = OperatorPresence {
            username: "operator".to_owned(),
            role: OperatorRole::Admin,
            online: true,
            last_seen: Some("2026-03-11T08:00:00Z".to_owned()),
        };

        let info = presence.as_operator_info();

        assert_eq!(info.username, "operator");
        assert_eq!(info.password_hash, None);
        assert_eq!(info.role.as_deref(), Some("Admin"));
        assert!(info.online);
        assert_eq!(info.last_seen.as_deref(), Some("2026-03-11T08:00:00Z"));
    }

    #[test]
    fn operator_presence_as_operator_info_keeps_unusual_username_without_password_material() {
        let presence = OperatorPresence {
            username: "MiXeD-Case_99@example.local".to_owned(),
            role: OperatorRole::Operator,
            online: true,
            last_seen: Some("2026-03-12T09:30:00Z".to_owned()),
        };

        let info = presence.as_operator_info();
        let payload = serde_json::to_value(&info).expect("operator info should serialize");

        assert_eq!(info.username, "MiXeD-Case_99@example.local");
        assert_eq!(info.role.as_deref(), Some("Operator"));
        assert_eq!(info.last_seen.as_deref(), Some("2026-03-12T09:30:00Z"));
        assert_eq!(payload["Username"], json!("MiXeD-Case_99@example.local"));
        assert_eq!(payload["Role"], json!("Operator"));
        assert_eq!(payload["Online"], json!(true));
        assert_eq!(payload["LastSeen"], json!("2026-03-12T09:30:00Z"));
        assert!(payload.get("PasswordHash").is_none());
    }

    #[test]
    fn operator_presence_as_operator_info_supports_offline_operator_without_last_seen() {
        let presence = OperatorPresence {
            username: "analyst".to_owned(),
            role: OperatorRole::Analyst,
            online: false,
            last_seen: None,
        };

        let info = presence.as_operator_info();
        let payload = serde_json::to_value(&info).expect("operator info should serialize");

        assert_eq!(info.username, "analyst");
        assert_eq!(info.role.as_deref(), Some("Analyst"));
        assert!(!info.online);
        assert_eq!(info.last_seen, None);
        assert_eq!(payload["Username"], json!("analyst"));
        assert_eq!(payload["Role"], json!("Analyst"));
        assert_eq!(payload["Online"], json!(false));
        assert!(payload.get("LastSeen").is_none());
        assert!(payload.get("PasswordHash").is_none());
    }

    #[test]
    fn login_success_message_uses_init_connection_success_wire_shape() {
        let message = login_success_message("operator", "token-123");
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Head"]["Event"], json!(EventCode::InitConnection.as_u32()));
        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Success.as_u32()));
        assert_eq!(
            value["Body"]["Info"]["Message"],
            json!("Successful Authenticated; SessionToken=token-123")
        );
    }

    #[test]
    fn authentication_failure_invalid_credentials_message_returns_expected_string() {
        assert_eq!(AuthenticationFailure::InvalidCredentials.message(), "Authentication failed");
    }

    #[test]
    fn login_failure_message_embeds_variant_message_unchanged() {
        let variants =
            [AuthenticationFailure::InvalidCredentials, AuthenticationFailure::SessionCapExceeded];
        for variant in &variants {
            let msg = login_failure_message("user", variant);
            let value = serde_json::to_value(&msg).expect("message should serialize");
            assert_eq!(
                value["Body"]["Info"]["Message"],
                json!(variant.message()),
                "login_failure_message must embed {variant:?}.message() unchanged"
            );
        }
    }

    #[test]
    fn login_failure_message_uses_generic_authentication_error_text() {
        let message = login_failure_message("ghost", &AuthenticationFailure::InvalidCredentials);
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Error.as_u32()));
        assert_eq!(value["Body"]["Info"]["Message"], json!("Authentication failed"));
    }

    #[test]
    fn authentication_failure_session_cap_exceeded_message_returns_expected_string() {
        assert_eq!(
            AuthenticationFailure::SessionCapExceeded.message(),
            "Too many active sessions; try again later"
        );
    }

    #[test]
    fn login_failure_message_session_cap_exceeded_uses_init_connection_error_wire_shape() {
        let message =
            login_failure_message("overloaded", &AuthenticationFailure::SessionCapExceeded);
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Error.as_u32()));
        assert_eq!(
            value["Body"]["Info"]["Message"],
            json!("Too many active sessions; try again later")
        );
    }

    #[test]
    fn all_authentication_failure_variants_have_non_empty_messages() {
        let variants =
            [AuthenticationFailure::InvalidCredentials, AuthenticationFailure::SessionCapExceeded];
        for variant in &variants {
            assert!(
                !variant.message().is_empty(),
                "AuthenticationFailure::{variant:?} must have a non-empty message"
            );
        }
    }
}
