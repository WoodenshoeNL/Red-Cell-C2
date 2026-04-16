//! Webhook notification dispatch for audit events.

use super::types::AuditDetails;
use crate::{AuditWebhookNotifier, Database, TeamserverError};

/// Persist a structured audit-log entry and emit outbound notifications when configured.
pub async fn record_operator_action_with_notifications(
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: AuditDetails,
) -> Result<i64, TeamserverError> {
    let (id, record) =
        super::persist_operator_action(database, actor, action, target_kind, target_id, details)
            .await?;

    webhooks.notify_audit_record_detached(record);

    Ok(id)
}
