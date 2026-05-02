//! Structured operator audit logging helpers and REST-facing models.

mod types;
mod webhook;

pub use types::*;
pub use webhook::*;

use std::collections::BTreeSet;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::database::AuditLogFilter;
use crate::{AuditLogEntry, Database, TeamserverError};

use types::normalize_timestamp_utc;

/// Persist a structured audit-log entry for an operator action.
pub async fn record_operator_action(
    database: &Database,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: AuditDetails,
) -> Result<i64, TeamserverError> {
    let (id, _) =
        persist_operator_action(database, actor, action, target_kind, target_id, details).await?;
    Ok(id)
}

pub(crate) async fn persist_operator_action(
    database: &Database,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: AuditDetails,
) -> Result<(i64, AuditRecord), TeamserverError> {
    let occurred_at = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|error| {
        TeamserverError::InvalidPersistedValue { field: "occurred_at", message: error.to_string() }
    })?;
    let serialized_details = serde_json::to_value(&details)?;

    let id = database
        .audit_log()
        .create(&AuditLogEntry {
            id: None,
            actor: actor.to_owned(),
            action: action.to_owned(),
            target_kind: target_kind.to_owned(),
            target_id: target_id.clone(),
            details: Some(serialized_details),
            occurred_at: occurred_at.clone(),
        })
        .await?;

    Ok((
        id,
        AuditRecord {
            id,
            actor: actor.to_owned(),
            action: action.to_owned(),
            target_kind: target_kind.to_owned(),
            target_id,
            agent_id: details.agent_id,
            command: details.command,
            parameters: details.parameters,
            result_status: details.result_status,
            occurred_at,
        },
    ))
}

/// Return a filtered and paginated view of the audit log.
///
/// Filtering and pagination are pushed into SQL so only the requested page of
/// rows is transferred from the database.
pub async fn query_audit_log(
    database: &Database,
    query: &AuditQuery,
) -> Result<AuditPage, TeamserverError> {
    let limit = query.limit();
    let offset = query.offset();

    let filter = AuditLogFilter {
        actor_contains: query.actor_filter().map(ToOwned::to_owned),
        action_contains: query.action.clone(),
        target_kind_contains: query.target_kind.clone(),
        target_id_contains: query.target_id.clone(),
        agent_id: query.normalized_agent_id(),
        command_contains: query.command.clone(),
        result_status: query.result_status.map(|s| s.as_str().to_owned()),
        since: normalize_timestamp_utc(query.since_timestamp())?
            .map(|s| types::audit_since_sql_lower_bound(&s)),
        until: normalize_timestamp_utc(query.until_timestamp())?,
        action_in: None,
    };

    let sql_limit = i64::try_from(limit).map_err(|_| TeamserverError::InvalidPersistedValue {
        field: "limit",
        message: "limit exceeds i64 range".to_owned(),
    })?;
    let sql_offset = i64::try_from(offset).map_err(|_| TeamserverError::InvalidPersistedValue {
        field: "offset",
        message: "offset exceeds i64 range".to_owned(),
    })?;

    let repo = database.audit_log();
    let total = repo.count_filtered(&filter).await?;
    let entries = repo.query_filtered(&filter, sql_limit, sql_offset).await?;
    let items =
        entries.into_iter().map(TryInto::try_into).collect::<Result<Vec<AuditRecord>, _>>()?;

    let total = usize::try_from(total).map_err(|_| TeamserverError::InvalidPersistedValue {
        field: "total",
        message: "row count exceeds usize range".to_owned(),
    })?;

    Ok(AuditPage { total, limit, offset, items })
}

/// Return a filtered and paginated view of persisted operator session activity.
pub async fn query_session_activity(
    database: &Database,
    query: &SessionActivityQuery,
) -> Result<SessionActivityPage, TeamserverError> {
    let limit = query.limit();
    let offset = query.offset();
    let mut actions =
        BTreeSet::from(["operator.connect".to_owned(), "operator.disconnect".to_owned()]);
    actions.insert("operator.chat".to_owned());
    actions.insert("operator.session_timeout".to_owned());
    actions.insert("operator.permission_denied".to_owned());

    if let Some(ref action) =
        query.activity.as_deref().map(|activity| format!("operator.{activity}"))
    {
        actions.retain(|value| value == action);
    }

    if actions.is_empty() {
        return Ok(SessionActivityPage { total: 0, limit, offset, items: Vec::new() });
    }

    let filter = AuditLogFilter {
        actor_contains: query.operator.clone(),
        action_in: Some(actions.iter().cloned().collect()),
        since: normalize_timestamp_utc(query.since_timestamp())?
            .map(|s| types::audit_since_sql_lower_bound(&s)),
        until: normalize_timestamp_utc(query.until_timestamp())?,
        ..AuditLogFilter::default()
    };

    let sql_limit = i64::try_from(limit).map_err(|_| TeamserverError::InvalidPersistedValue {
        field: "limit",
        message: "limit exceeds i64 range".to_owned(),
    })?;
    let sql_offset = i64::try_from(offset).map_err(|_| TeamserverError::InvalidPersistedValue {
        field: "offset",
        message: "offset exceeds i64 range".to_owned(),
    })?;

    let repo = database.audit_log();
    let total = usize::try_from(repo.count_filtered(&filter).await?).map_err(|_| {
        TeamserverError::InvalidPersistedValue {
            field: "total",
            message: "row count exceeds usize range".to_owned(),
        }
    })?;
    let entries = repo.query_filtered(&filter, sql_limit, sql_offset).await?;
    let items = entries
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<SessionActivityRecord>, _>>()?;

    Ok(SessionActivityPage { total, limit, offset, items })
}

#[cfg(test)]
mod tests;
