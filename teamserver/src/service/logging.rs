use red_cell_common::operator::{
    EventCode, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
};
use time::OffsetDateTime;
use tracing::warn;

use crate::audit::AuditDetails;
use crate::{AuditWebhookNotifier, Database, record_operator_action_with_notifications};

/// Persist a structured audit-log entry for a service bridge action.
///
/// This mirrors `log_operator_action` in `websocket.rs` but uses the actor
/// `"service"` to distinguish service bridge actions from operator actions.
pub(super) async fn log_service_action(
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: AuditDetails,
) {
    if let Err(error) = record_operator_action_with_notifications(
        database,
        webhooks,
        "service",
        action,
        target_kind,
        target_id,
        details,
    )
    .await
    {
        warn!(action, %error, "failed to persist service audit log entry");
    }
}

/// Build a teamserver log event attributed to the service bridge.
pub(super) fn service_log_event(text: &str) -> OperatorMessage {
    OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: "service".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: text.to_owned() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_log_event_creates_valid_operator_message() {
        let event = service_log_event("hello");
        match event {
            OperatorMessage::TeamserverLog(msg) => {
                assert_eq!(msg.info.text, "hello");
                assert_eq!(msg.head.user, "service");
                assert_eq!(msg.head.event, EventCode::Teamserver);
            }
            _ => panic!("expected TeamserverLog variant"),
        }
    }
}
