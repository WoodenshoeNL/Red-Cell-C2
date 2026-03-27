//! Structured operator audit logging helpers and REST-facing models.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{IntoParams, ToSchema};

use crate::database::AuditLogFilter;
use crate::{AuditLogEntry, AuditWebhookNotifier, Database, TeamserverError};

/// Result status recorded for an audited action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditResultStatus {
    /// The action completed successfully.
    Success,
    /// The action failed or was rejected.
    Failure,
}

impl AuditResultStatus {
    /// Return the stable serialized status label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Structured audit fields embedded in the persisted `details` JSON payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AuditDetails {
    /// Optional related agent identifier rendered as uppercase hex.
    pub agent_id: Option<String>,
    /// Optional command or sub-action label.
    pub command: Option<String>,
    /// Optional structured parameters associated with the action.
    pub parameters: Option<Value>,
    /// Outcome recorded for the action.
    pub result_status: AuditResultStatus,
}

/// REST-facing audit record with extracted structured fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AuditRecord {
    /// Database-assigned primary key.
    pub id: i64,
    /// Operator username or API key identifier.
    pub actor: String,
    /// Stable action label.
    pub action: String,
    /// Entity category acted upon.
    pub target_kind: String,
    /// Optional target identifier.
    pub target_id: Option<String>,
    /// Optional related agent identifier rendered as uppercase hex.
    pub agent_id: Option<String>,
    /// Optional command or sub-action label.
    pub command: Option<String>,
    /// Optional structured parameters associated with the action.
    pub parameters: Option<Value>,
    /// Outcome recorded for the action.
    pub result_status: AuditResultStatus,
    /// RFC 3339 timestamp recorded for the action.
    pub occurred_at: String,
}

impl TryFrom<AuditLogEntry> for AuditRecord {
    type Error = TeamserverError;

    fn try_from(entry: AuditLogEntry) -> Result<Self, Self::Error> {
        let details =
            entry.details.map(serde_json::from_value::<AuditDetails>).transpose()?.unwrap_or(
                AuditDetails {
                    agent_id: None,
                    command: None,
                    parameters: None,
                    result_status: AuditResultStatus::Success,
                },
            );

        Ok(Self {
            id: entry.id.ok_or_else(|| TeamserverError::InvalidPersistedValue {
                field: "id",
                message: "audit log row was missing an id".to_owned(),
            })?,
            actor: entry.actor,
            action: entry.action,
            target_kind: entry.target_kind,
            target_id: entry.target_id,
            agent_id: details.agent_id,
            command: details.command,
            parameters: details.parameters,
            result_status: details.result_status,
            occurred_at: entry.occurred_at,
        })
    }
}

/// Query parameters supported by `GET /audit`.
#[derive(Clone, Debug, Default, Deserialize, IntoParams)]
pub struct AuditQuery {
    /// Filter by operator username or API key id.
    pub operator: Option<String>,
    /// Filter by actor username or API key id.
    pub actor: Option<String>,
    /// Filter by stable action label.
    pub action: Option<String>,
    /// Filter by target entity category.
    pub target_kind: Option<String>,
    /// Filter by target identifier.
    pub target_id: Option<String>,
    /// Filter by related agent id in hexadecimal (with optional `0x` prefix).
    /// Purely numeric strings like `"256"` are interpreted as hex `0x256`, not
    /// decimal. Values that are not valid hex are silently ignored.
    pub agent_id: Option<String>,
    /// Filter by command label.
    pub command: Option<String>,
    /// Filter by action result.
    pub result_status: Option<AuditResultStatus>,
    /// Include records at or after this RFC 3339 timestamp.
    pub since: Option<String>,
    /// Include records at or before this RFC 3339 timestamp.
    pub until: Option<String>,
    /// Maximum number of records to return. Defaults to `50`.
    pub limit: Option<usize>,
    /// Number of matching records to skip. Defaults to `0`.
    pub offset: Option<usize>,
}

impl AuditQuery {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    /// Return the validated page size.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT).clamp(1, Self::MAX_LIMIT)
    }

    /// Return the validated page offset.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }

    fn normalized_agent_id(&self) -> Option<String> {
        self.agent_id.as_deref().and_then(parse_agent_id_filter)
    }

    fn actor_filter(&self) -> Option<&str> {
        self.operator.as_deref().or(self.actor.as_deref())
    }

    fn since_timestamp(&self) -> Option<OffsetDateTime> {
        self.since.as_deref().and_then(parse_timestamp_filter)
    }

    fn until_timestamp(&self) -> Option<OffsetDateTime> {
        self.until.as_deref().and_then(parse_timestamp_filter)
    }
}

/// Paginated audit query response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AuditPage {
    /// Total number of records matching the supplied filters.
    pub total: usize,
    /// Maximum number of records returned in this page.
    pub limit: usize,
    /// Number of matching records skipped before this page.
    pub offset: usize,
    /// Matching audit records ordered from newest to oldest.
    pub items: Vec<AuditRecord>,
}

/// Query parameters supported by `GET /session-activity`.
#[derive(Clone, Debug, Default, Deserialize, IntoParams)]
pub struct SessionActivityQuery {
    /// Filter by operator username.
    pub operator: Option<String>,
    /// Filter by session activity label such as `connect`, `disconnect`, or `chat`.
    pub activity: Option<String>,
    /// Include records at or after this RFC 3339 timestamp.
    pub since: Option<String>,
    /// Include records at or before this RFC 3339 timestamp.
    pub until: Option<String>,
    /// Maximum number of records to return. Defaults to `50`.
    pub limit: Option<usize>,
    /// Number of matching records to skip. Defaults to `0`.
    pub offset: Option<usize>,
}

impl SessionActivityQuery {
    /// Return the validated page size.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(AuditQuery::DEFAULT_LIMIT).clamp(1, AuditQuery::MAX_LIMIT)
    }

    /// Return the validated page offset.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset.unwrap_or_default()
    }

    fn since_timestamp(&self) -> Option<OffsetDateTime> {
        self.since.as_deref().and_then(parse_timestamp_filter)
    }

    fn until_timestamp(&self) -> Option<OffsetDateTime> {
        self.until.as_deref().and_then(parse_timestamp_filter)
    }
}

/// REST-facing operator session activity record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SessionActivityRecord {
    /// Database-assigned primary key.
    pub id: i64,
    /// Operator username associated with the activity.
    pub operator: String,
    /// Stable session activity label.
    pub activity: String,
    /// Optional structured session metadata.
    pub parameters: Option<Value>,
    /// Outcome recorded for the activity.
    pub result_status: AuditResultStatus,
    /// RFC 3339 timestamp recorded for the activity.
    pub occurred_at: String,
}

impl TryFrom<AuditLogEntry> for SessionActivityRecord {
    type Error = TeamserverError;

    fn try_from(entry: AuditLogEntry) -> Result<Self, Self::Error> {
        let details =
            entry.details.map(serde_json::from_value::<AuditDetails>).transpose()?.unwrap_or(
                AuditDetails {
                    agent_id: None,
                    command: None,
                    parameters: None,
                    result_status: AuditResultStatus::Success,
                },
            );

        let activity = entry.action.strip_prefix("operator.").ok_or_else(|| {
            TeamserverError::InvalidPersistedValue {
                field: "action",
                message: format!("audit row `{}` is not operator session activity", entry.action),
            }
        })?;

        Ok(Self {
            id: entry.id.ok_or_else(|| TeamserverError::InvalidPersistedValue {
                field: "id",
                message: "audit log row was missing an id".to_owned(),
            })?,
            operator: entry.actor,
            activity: activity.to_owned(),
            parameters: details.parameters,
            result_status: details.result_status,
            occurred_at: entry.occurred_at,
        })
    }
}

/// Paginated operator session activity response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SessionActivityPage {
    /// Total number of records matching the supplied filters.
    pub total: usize,
    /// Maximum number of records returned in this page.
    pub limit: usize,
    /// Number of matching records skipped before this page.
    pub offset: usize,
    /// Matching activity records ordered from newest to oldest.
    pub items: Vec<SessionActivityRecord>,
}

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
        persist_operator_action(database, actor, action, target_kind, target_id, details).await?;

    webhooks.notify_audit_record_detached(record);

    Ok(id)
}

async fn persist_operator_action(
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
        since: normalize_timestamp_utc(query.since_timestamp())?,
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
        since: normalize_timestamp_utc(query.since_timestamp())?,
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

/// Format an optional timestamp as a UTC RFC 3339 string for SQL comparison.
fn normalize_timestamp_utc(ts: Option<OffsetDateTime>) -> Result<Option<String>, TeamserverError> {
    ts.map(|t| {
        t.to_offset(time::UtcOffset::UTC).format(&Rfc3339).map_err(|error| {
            TeamserverError::InvalidPersistedValue {
                field: "timestamp",
                message: error.to_string(),
            }
        })
    })
    .transpose()
}

/// Build common structured details for an operator audit record.
#[must_use]
pub fn audit_details(
    result_status: AuditResultStatus,
    agent_id: Option<u32>,
    command: Option<&str>,
    parameters: Option<Value>,
) -> AuditDetails {
    AuditDetails {
        agent_id: agent_id.map(|value| format!("{value:08X}")),
        command: command.map(ToOwned::to_owned),
        parameters,
        result_status,
    }
}

/// Build a minimal JSON object from simple key/value pairs.
#[must_use]
pub fn parameter_object(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut object = serde_json::Map::new();
    for (key, value) in pairs {
        object.insert(key.to_owned(), value);
    }
    Value::Object(object)
}

fn parse_timestamp_filter(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

/// Parse a query-string agent-id value as **hexadecimal** and normalise it to
/// an 8-digit uppercase hex string (e.g. `"0xCAFE"` → `"0000CAFE"`).
///
/// Input is always interpreted as hex — an optional `0x`/`0X` prefix is
/// stripped but does not change the radix.  A purely numeric string like
/// `"256"` therefore maps to hex `0x0256` (decimal 598), **not** decimal 256.
/// Returns `None` for empty or non-hex input.
fn parse_agent_id_filter(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    let agent_id = u32::from_str_radix(hex_digits, 16).ok()?;
    Some(format!("{agent_id:08X}"))
}

/// Build an audit payload for a login attempt without persisting sensitive fields.
#[must_use]
pub fn login_parameters(username: &str, connection_id: &uuid::Uuid) -> Value {
    json!({
        "username": username,
        "connection_id": connection_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::{future::pending, net::SocketAddr, time::Duration};

    use axum::{Json, Router, routing::post};
    use red_cell_common::config::Profile;
    use serde_json::Value;
    use sqlx::Row as _;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::{
        AuditQuery, AuditRecord, AuditResultStatus, SessionActivityQuery, SessionActivityRecord,
        audit_details, login_parameters, parameter_object, parse_agent_id_filter, query_audit_log,
        query_session_activity,
    };
    use crate::{
        AuditLogEntry, AuditWebhookNotifier, Database, TeamserverError, record_operator_action,
        record_operator_action_with_notifications,
    };
    use serde_json::json;

    #[test]
    fn session_activity_query_default_limit_and_offset() {
        let q = SessionActivityQuery { limit: None, offset: None, ..Default::default() };
        assert_eq!(q.limit(), 50);
        assert_eq!(q.offset(), 0);
    }

    #[test]
    fn session_activity_query_oversized_limit_is_clamped() {
        let q = SessionActivityQuery { limit: Some(9999), ..Default::default() };
        assert_eq!(q.limit(), 200);
    }

    #[test]
    fn session_activity_query_explicit_small_limit_and_nonzero_offset_are_preserved() {
        let q = SessionActivityQuery { limit: Some(10), offset: Some(25), ..Default::default() };
        assert_eq!(q.limit(), 10);
        assert_eq!(q.offset(), 25);
    }

    #[test]
    fn audit_result_status_as_str_success() {
        assert_eq!(AuditResultStatus::Success.as_str(), "success");
    }

    #[test]
    fn audit_result_status_as_str_failure() {
        assert_eq!(AuditResultStatus::Failure.as_str(), "failure");
    }

    #[test]
    fn audit_result_status_as_str_is_lowercase_and_stable() {
        let success = AuditResultStatus::Success.as_str();
        let failure = AuditResultStatus::Failure.as_str();

        assert_eq!(success, success.to_lowercase(), "Success label must be lowercase");
        assert_eq!(failure, failure.to_lowercase(), "Failure label must be lowercase");
        assert_ne!(success, failure, "Status labels must be distinct");
        assert_eq!(success, "success");
        assert_eq!(failure, "failure");
    }

    #[test]
    fn audit_record_extracts_structured_details() {
        let record = AuditRecord::try_from(AuditLogEntry {
            id: Some(7),
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: Some("DEADBEEF".to_owned()),
            details: Some(
                serde_json::to_value(audit_details(
                    AuditResultStatus::Success,
                    Some(0xDEAD_BEEF),
                    Some("checkin"),
                    Some(json!({"arg":"value"})),
                ))
                .expect("details should serialize"),
            ),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect("record should decode");

        assert_eq!(record.id, 7);
        assert_eq!(record.agent_id.as_deref(), Some("DEADBEEF"));
        assert_eq!(record.command.as_deref(), Some("checkin"));
        assert_eq!(record.result_status, AuditResultStatus::Success);
    }

    #[test]
    fn audit_record_requires_id() {
        let error = AuditRecord::try_from(AuditLogEntry {
            id: None,
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: Some("DEADBEEF".to_owned()),
            details: None,
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("missing id should fail");

        match error {
            TeamserverError::InvalidPersistedValue { field, message } => {
                assert_eq!(field, "id");
                assert_eq!(message, "audit log row was missing an id");
            }
            other => panic!("expected invalid persisted value error, got {other}"),
        }
    }

    #[test]
    fn session_activity_record_rejects_non_operator_actions() {
        let error = SessionActivityRecord::try_from(AuditLogEntry {
            id: Some(7),
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: Some("DEADBEEF".to_owned()),
            details: None,
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("non-operator action should fail");

        match error {
            TeamserverError::InvalidPersistedValue { field, message } => {
                assert_eq!(field, "action");
                assert!(message.contains("agent.task"));
            }
            other => panic!("expected invalid persisted value error, got {other}"),
        }
    }

    #[test]
    fn session_activity_record_requires_id() {
        let error = SessionActivityRecord::try_from(AuditLogEntry {
            id: None,
            actor: "operator".to_owned(),
            action: "operator.chat".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: None,
            details: None,
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("missing id should fail");

        match error {
            TeamserverError::InvalidPersistedValue { field, message } => {
                assert_eq!(field, "id");
                assert_eq!(message, "audit log row was missing an id");
            }
            other => panic!("expected invalid persisted value error, got {other}"),
        }
    }

    #[test]
    fn parameter_object_builds_json_object() {
        let value = parameter_object([("listener", json!("http")), ("port", json!(443))]);
        assert_eq!(value, json!({"listener":"http","port":443}));
    }

    #[test]
    fn login_parameters_only_include_username_and_connection_id() {
        let connection_id = uuid::Uuid::parse_str("12345678-1234-5678-9abc-1234567890ab")
            .expect("connection id should parse");

        let payload = login_parameters("operator", &connection_id);

        assert_eq!(
            payload,
            json!({
                "username": "operator",
                "connection_id": "12345678-1234-5678-9abc-1234567890ab",
            })
        );

        let object = payload.as_object().expect("payload should be a JSON object");
        assert_eq!(object.len(), 2);
        assert!(!object.contains_key("password"));
        assert!(!object.contains_key("Password"));
        assert!(!object.contains_key("password_hash"));
        assert!(!object.contains_key("PasswordHash"));
    }

    #[test]
    fn login_parameters_preserve_mixed_case_and_unusual_usernames_without_password_material() {
        let connection_id = uuid::Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            .expect("connection id should parse");
        let username = "Op-Erator_42@example.local";

        let payload = login_parameters(username, &connection_id);

        assert_eq!(payload["username"], json!(username));
        assert_eq!(payload["connection_id"], json!(connection_id.to_string()));
        assert!(payload.get("password").is_none());
        assert!(payload.get("password_hash").is_none());
    }

    #[test]
    fn agent_id_filter_always_parses_hex() {
        assert_eq!(parse_agent_id_filter("DEADBEEF").as_deref(), Some("DEADBEEF"));
        assert_eq!(parse_agent_id_filter("0x10").as_deref(), Some("00000010"));
        assert_eq!(parse_agent_id_filter("00000010").as_deref(), Some("00000010"));
        assert_eq!(parse_agent_id_filter("16").as_deref(), Some("00000016"));
        assert!(parse_agent_id_filter("").is_none());
        assert!(parse_agent_id_filter("ZZZZ").is_none());
    }

    /// Ambiguous all-digit strings are treated as hex, not decimal.
    /// `"256"` → hex 0x0256 (=598 decimal) → `"00000256"`, NOT decimal 256 (=0x100) → `"00000100"`.
    #[test]
    fn parse_agent_id_filter_treats_ambiguous_numeric_input_as_hex_not_decimal() {
        // "256" as hex is 0x256 = 598; as decimal it would be 0x100.
        assert_eq!(parse_agent_id_filter("256").as_deref(), Some("00000256"));
        assert_ne!(parse_agent_id_filter("256").as_deref(), Some("00000100"));

        // "10" as hex is 0x10 = 16; as decimal it would be 0x0A.
        assert_eq!(parse_agent_id_filter("10").as_deref(), Some("00000010"));
        assert_ne!(parse_agent_id_filter("10").as_deref(), Some("0000000A"));

        // "100" as hex is 0x100 = 256; as decimal it would be 0x64.
        assert_eq!(parse_agent_id_filter("100").as_deref(), Some("00000100"));
        assert_ne!(parse_agent_id_filter("100").as_deref(), Some("00000064"));
    }

    #[test]
    fn query_validates_limit_and_offset_defaults() {
        let query = AuditQuery::default();
        assert_eq!(query.limit(), 50);
        assert_eq!(query.offset(), 0);

        let clamped = AuditQuery { limit: Some(500), offset: Some(4), ..AuditQuery::default() };
        assert_eq!(clamped.limit(), 200);
        assert_eq!(clamped.offset(), 4);
    }

    #[test]
    fn session_activity_query_validates_limit_and_offset_defaults() {
        let query = SessionActivityQuery::default();
        assert_eq!(query.limit(), 50);
        assert_eq!(query.offset(), 0);

        let clamped = SessionActivityQuery {
            limit: Some(500),
            offset: Some(7),
            ..SessionActivityQuery::default()
        };
        assert_eq!(clamped.limit(), 200);
        assert_eq!(clamped.offset(), 7);
    }

    #[tokio::test]
    async fn query_session_activity_returns_empty_page_for_unknown_activity() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        // Populate the DB with known-good session activity rows so that a
        // missing early-return (issuing `action_in = []` to SQL) would
        // silently return these rows instead of an empty page.
        for action in ["operator.connect", "operator.disconnect", "operator.chat"] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "operator".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let query = SessionActivityQuery {
            activity: Some("hack".to_owned()),
            ..SessionActivityQuery::default()
        };

        let page = query_session_activity(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 0, "unrecognized activity should yield zero total");
        assert!(page.items.is_empty(), "unrecognized activity should yield no items");
    }

    #[tokio::test]
    async fn query_session_activity_includes_session_timeout_and_permission_denied_events() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in [
            "operator.connect",
            "operator.disconnect",
            "operator.chat",
            "operator.session_timeout",
            "operator.permission_denied",
        ] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "operator".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        // Querying without an activity filter should return all five event types.
        let page = query_session_activity(&database, &SessionActivityQuery::default())
            .await
            .expect("query should succeed");
        assert_eq!(page.total, 5, "all five session activity types should be returned");

        // Filtering by the new activity types should return exactly one record each.
        for activity in ["session_timeout", "permission_denied"] {
            let q = SessionActivityQuery {
                activity: Some(activity.to_owned()),
                ..SessionActivityQuery::default()
            };
            let p = query_session_activity(&database, &q).await.expect("query should succeed");
            assert_eq!(p.total, 1, "filtering by `{activity}` should return exactly one record");
            assert_eq!(p.items[0].activity, activity);
        }
    }

    #[tokio::test]
    async fn query_session_activity_connect_filter_returns_only_connect_entries() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in ["operator.connect", "operator.connect", "operator.chat"] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "operator".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let query = SessionActivityQuery {
            activity: Some("connect".to_owned()),
            ..SessionActivityQuery::default()
        };
        let page = query_session_activity(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 2, "only operator.connect entries should be counted");
        assert_eq!(page.items.len(), 2, "only operator.connect items should be returned");
        assert!(
            page.items.iter().all(|r| r.activity == "connect"),
            "all returned items must have activity=connect"
        );
    }

    #[tokio::test]
    async fn query_session_activity_chat_filter_excludes_connect_entries() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in ["operator.connect", "operator.chat", "operator.chat"] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "operator".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let query = SessionActivityQuery {
            activity: Some("chat".to_owned()),
            ..SessionActivityQuery::default()
        };
        let page = query_session_activity(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 2, "only operator.chat entries should be counted");
        assert_eq!(page.items.len(), 2, "only operator.chat items should be returned");
        assert!(
            page.items.iter().all(|r| r.activity == "chat"),
            "all returned items must have activity=chat"
        );
    }

    #[tokio::test]
    async fn query_session_activity_nonexistent_action_triggers_empty_set_guard() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in ["operator.connect", "operator.chat"] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "operator".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let query = SessionActivityQuery {
            activity: Some("nonexistent_action_xyz".to_owned()),
            ..SessionActivityQuery::default()
        };
        let page = query_session_activity(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 0, "empty-set guard must return total=0 for unknown activity");
        assert!(page.items.is_empty(), "empty-set guard must return no items for unknown activity");
    }

    #[tokio::test]
    async fn query_session_activity_no_filter_includes_all_five_event_types() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in [
            "operator.connect",
            "operator.disconnect",
            "operator.chat",
            "operator.session_timeout",
            "operator.permission_denied",
        ] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "operator".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let page = query_session_activity(&database, &SessionActivityQuery::default())
            .await
            .expect("query should succeed");

        assert_eq!(page.total, 5, "unfiltered query must return all five session event types");
        let mut activities: Vec<_> = page.items.iter().map(|r| r.activity.as_str()).collect();
        activities.sort_unstable();
        assert_eq!(
            activities,
            ["chat", "connect", "disconnect", "permission_denied", "session_timeout"],
            "all five activity types must appear in results"
        );
    }

    #[tokio::test]
    async fn record_operator_action_persists_entry_and_returns_valid_id() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        let id = record_operator_action(
            &database,
            "test-operator",
            "agent.task",
            "agent",
            Some("CAFE0001".to_owned()),
            audit_details(
                AuditResultStatus::Success,
                Some(0xCAFE_0001),
                Some("checkin"),
                Some(json!({"key": "value"})),
            ),
        )
        .await
        .expect("record_operator_action should succeed");

        assert!(id > 0, "returned ID should be positive");

        let entry = database
            .audit_log()
            .get(id)
            .await
            .expect("database read should succeed")
            .expect("audit row should exist for the returned ID");

        assert_eq!(entry.actor, "test-operator");
        assert_eq!(entry.action, "agent.task");
        assert_eq!(entry.target_kind, "agent");
        assert_eq!(entry.target_id.as_deref(), Some("CAFE0001"));

        let details = entry.details.expect("details should be present");
        assert_eq!(details["agent_id"], "CAFE0001");
        assert_eq!(details["command"], "checkin");
        assert_eq!(details["parameters"]["key"], "value");
        assert_eq!(details["result_status"], "success");
    }

    #[tokio::test]
    async fn record_operator_action_with_none_target_id_persists_null() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        let id = record_operator_action(
            &database,
            "admin",
            "config.update",
            "config",
            None,
            audit_details(AuditResultStatus::Success, None, None, None),
        )
        .await
        .expect("record_operator_action should succeed");

        let entry = database
            .audit_log()
            .get(id)
            .await
            .expect("database read should succeed")
            .expect("audit row should exist");

        assert_eq!(entry.actor, "admin");
        assert_eq!(entry.action, "config.update");
        assert_eq!(entry.target_kind, "config");
        assert!(entry.target_id.is_none(), "target_id should be None");
    }

    #[tokio::test]
    async fn notifying_audit_helper_posts_to_configured_discord_webhook() {
        let (address, mut receiver, server) = webhook_server().await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
                User = "Red Cell"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);
        let database = Database::connect_in_memory().await.expect("database should initialize");

        let id = record_operator_action_with_notifications(
            &database,
            &notifier,
            "operator",
            "listener.create",
            "listener",
            Some("http-1".to_owned()),
            audit_details(
                AuditResultStatus::Success,
                None,
                Some("create"),
                Some(json!({"listener":"http-1"})),
            ),
        )
        .await
        .expect("audit record should persist");

        let payload = receiver.recv().await.expect("payload should arrive");
        server.abort();

        assert_eq!(id, 1);
        assert_eq!(payload["username"], "Red Cell");
        assert_eq!(payload["embeds"][0]["fields"][1]["value"], "listener.create");
        assert_eq!(payload["embeds"][0]["fields"][4]["value"], "http-1");
    }

    #[tokio::test]
    async fn notifying_audit_helper_does_not_block_on_stalled_webhook() {
        let (address, server) = stalled_webhook_server().await;
        let profile = Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "operator" {{
                Password = "password1234"
              }}
            }}

            WebHook {{
              Discord {{
                Url = "http://{address}/"
              }}
            }}

            Demon {{}}
            "#
        ))
        .expect("profile should parse");
        let notifier = AuditWebhookNotifier::from_profile(&profile);
        let database = Database::connect_in_memory().await.expect("database should initialize");

        let result = timeout(
            Duration::from_millis(250),
            record_operator_action_with_notifications(
                &database,
                &notifier,
                "operator",
                "listener.delete",
                "listener",
                Some("http-1".to_owned()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("delete"),
                    Some(json!({"listener":"http-1"})),
                ),
            ),
        )
        .await;

        server.abort();

        let id =
            result.expect("audit helper should not block").expect("audit record should persist");
        let stored = database.audit_log().list().await.expect("audit log should query");

        assert_eq!(id, 1);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].action, "listener.delete");
    }

    async fn webhook_server()
    -> (SocketAddr, mpsc::UnboundedReceiver<Value>, tokio::task::JoinHandle<()>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/",
            post(move |Json(payload): Json<Value>| {
                let sender = sender.clone();
                async move {
                    let _ = sender.send(payload);
                    Json(json!({"ok": true}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener address should resolve");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test webhook server should not fail");
        });

        (address, receiver, server)
    }

    async fn stalled_webhook_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/",
            post(|| async {
                pending::<()>().await;
                Json(json!({"ok": true}))
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let address = listener.local_addr().expect("listener address should resolve");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test stalled webhook server should not fail");
        });

        (address, server)
    }

    /// Collect the names of all indexes on `ts_audit_log` via SQLite PRAGMA.
    async fn audit_log_index_names(database: &Database) -> Vec<String> {
        let rows = sqlx::query("PRAGMA index_list(ts_audit_log)")
            .fetch_all(database.pool())
            .await
            .expect("PRAGMA index_list should succeed");
        rows.into_iter().map(|row| row.get::<String, _>("name")).collect()
    }

    #[tokio::test]
    async fn audit_log_actor_timestamp_composite_index_exists() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let names = audit_log_index_names(&database).await;
        assert!(
            names.iter().any(|n| n == "idx_ts_audit_log_actor_ts"),
            "expected idx_ts_audit_log_actor_ts, found: {names:?}"
        );
    }

    #[tokio::test]
    async fn audit_log_action_timestamp_composite_index_exists() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let names = audit_log_index_names(&database).await;
        assert!(
            names.iter().any(|n| n == "idx_ts_audit_log_action_ts"),
            "expected idx_ts_audit_log_action_ts, found: {names:?}"
        );
    }

    #[tokio::test]
    async fn audit_log_agent_id_timestamp_expression_index_exists() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let names = audit_log_index_names(&database).await;
        assert!(
            names.iter().any(|n| n == "idx_ts_audit_log_agent_id_ts"),
            "expected idx_ts_audit_log_agent_id_ts, found: {names:?}"
        );
    }

    /// Seed `count` audit rows across two actors, two actions, and one agent id.
    async fn seed_audit_rows(database: &Database, count: usize) {
        let repo = database.audit_log();
        for i in 0..count {
            let actor = if i % 2 == 0 { "alice" } else { "bob" };
            let action = if i % 3 == 0 { "agent.task" } else { "listener.create" };
            let agent_id = if i % 5 == 0 { Some(0xDEAD_BEEFu32) } else { None };
            let occurred_at = format!("2026-01-{:02}T{:02}:00:00Z", (i % 28) + 1, i % 24);
            let details = audit_details(AuditResultStatus::Success, agent_id, Some("test"), None);
            repo.create(&AuditLogEntry {
                id: None,
                actor: actor.to_owned(),
                action: action.to_owned(),
                target_kind: "agent".to_owned(),
                target_id: None,
                details: Some(serde_json::to_value(&details).expect("details should serialize")),
                occurred_at,
            })
            .await
            .expect("seed row should insert");
        }
    }

    #[tokio::test]
    async fn filtered_query_by_actor_returns_correct_subset_at_scale() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_audit_rows(&database, 500).await;

        let query = AuditQuery { actor: Some("alice".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert!(page.total > 0, "alice rows should be present");
        assert!(
            page.items.iter().all(|r| r.actor == "alice"),
            "only alice rows should be returned"
        );
    }

    #[tokio::test]
    async fn filtered_query_by_action_returns_correct_subset_at_scale() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_audit_rows(&database, 500).await;

        let query = AuditQuery { action: Some("agent.task".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert!(page.total > 0, "agent.task rows should be present");
        assert!(
            page.items.iter().all(|r| r.action.contains("agent.task")),
            "only agent.task rows should be returned"
        );
    }

    #[tokio::test]
    async fn filtered_query_by_agent_id_returns_correct_subset_at_scale() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_audit_rows(&database, 500).await;

        let query = AuditQuery { agent_id: Some("DEADBEEF".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert!(page.total > 0, "DEADBEEF rows should be present");
        assert!(
            page.items.iter().all(|r| r.agent_id.as_deref() == Some("DEADBEEF")),
            "only DEADBEEF rows should be returned"
        );
    }

    /// Seed audit rows with specific timestamps for time-range filter testing.
    async fn seed_timestamped_audit_rows(database: &Database) {
        let repo = database.audit_log();
        let timestamps = [
            "2026-01-10T08:00:00Z",
            "2026-01-15T12:00:00Z",
            "2026-01-20T16:00:00Z",
            "2026-01-25T20:00:00Z",
            "2026-01-30T23:59:59Z",
        ];
        for (i, ts) in timestamps.iter().enumerate() {
            let details = audit_details(AuditResultStatus::Success, None, Some("test"), None);
            repo.create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: format!("action.{i}"),
                target_kind: "agent".to_owned(),
                target_id: None,
                details: Some(serde_json::to_value(&details).expect("details should serialize")),
                occurred_at: (*ts).to_owned(),
            })
            .await
            .expect("seed row should insert");
        }
    }

    #[tokio::test]
    async fn query_audit_log_since_filter_excludes_older_rows() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // since = Jan 20 at 16:00 UTC — should include rows at Jan 20, Jan 25, Jan 30
        let query =
            AuditQuery { since: Some("2026-01-20T16:00:00Z".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 3, "since filter should include 3 rows at or after the cutoff");
        assert!(
            page.items.iter().all(|r| r.occurred_at.as_str() >= "2026-01-20T16:00:00Z"),
            "all returned rows must be at or after the since timestamp"
        );
    }

    #[tokio::test]
    async fn query_audit_log_until_filter_excludes_newer_rows() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // until = Jan 15 at 12:00 UTC — should include rows at Jan 10 and Jan 15
        let query =
            AuditQuery { until: Some("2026-01-15T12:00:00Z".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 2, "until filter should include 2 rows at or before the cutoff");
        assert!(
            page.items.iter().all(|r| r.occurred_at.as_str() <= "2026-01-15T12:00:00Z"),
            "all returned rows must be at or before the until timestamp"
        );
    }

    #[tokio::test]
    async fn query_audit_log_since_and_until_combined_returns_window() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // Window: Jan 15 through Jan 25 — should include rows at Jan 15, Jan 20, Jan 25
        let query = AuditQuery {
            since: Some("2026-01-15T12:00:00Z".to_owned()),
            until: Some("2026-01-25T20:00:00Z".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 3, "combined since/until should return 3 rows in window");
        assert!(
            page.items.iter().all(|r| {
                r.occurred_at.as_str() >= "2026-01-15T12:00:00Z"
                    && r.occurred_at.as_str() <= "2026-01-25T20:00:00Z"
            }),
            "all returned rows must fall within the since/until window"
        );
    }

    #[tokio::test]
    async fn query_audit_log_since_filter_normalizes_non_utc_offset() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // 2026-01-20T21:30:00+05:30 == 2026-01-20T16:00:00Z
        // So this should produce the same results as since=2026-01-20T16:00:00Z
        let query = AuditQuery {
            since: Some("2026-01-20T21:30:00+05:30".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(
            page.total, 3,
            "non-UTC offset should be normalized to UTC; 3 rows at or after 2026-01-20T16:00:00Z"
        );
    }

    #[tokio::test]
    async fn query_audit_log_until_filter_normalizes_non_utc_offset() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // 2026-01-15T17:30:00+05:30 == 2026-01-15T12:00:00Z
        // So this should produce the same results as until=2026-01-15T12:00:00Z
        let query = AuditQuery {
            until: Some("2026-01-15T17:30:00+05:30".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(
            page.total, 2,
            "non-UTC offset should be normalized to UTC; 2 rows at or before 2026-01-15T12:00:00Z"
        );
    }

    #[tokio::test]
    async fn query_audit_log_since_after_all_rows_returns_empty() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        let query =
            AuditQuery { since: Some("2026-12-01T00:00:00Z".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 0, "since after all rows should return nothing");
        assert!(page.items.is_empty());
    }

    #[tokio::test]
    async fn query_audit_log_until_before_all_rows_returns_empty() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        let query =
            AuditQuery { until: Some("2025-01-01T00:00:00Z".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 0, "until before all rows should return nothing");
        assert!(page.items.is_empty());
    }

    #[tokio::test]
    async fn actor_filter_operator_takes_precedence_over_actor() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_audit_rows(&database, 100).await;

        // Both `operator` and `actor` are set — `operator` must win.
        let query = AuditQuery {
            operator: Some("alice".to_owned()),
            actor: Some("bob".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert!(page.total > 0, "alice rows should be present");
        assert!(
            page.items.iter().all(|r| r.actor == "alice"),
            "operator field should take precedence — only alice rows expected, \
             but found: {:?}",
            page.items.iter().map(|r| &r.actor).collect::<Vec<_>>()
        );
        assert!(
            page.items.iter().all(|r| r.actor != "bob"),
            "bob rows must not appear when operator=alice takes precedence"
        );
    }

    // ---- malformed details coverage ----

    #[test]
    fn audit_record_rejects_malformed_details_json() {
        // `result_status` is required but set to an invalid enum variant.
        let malformed = json!({"result_status": "bogus", "agent_id": null});
        let error = AuditRecord::try_from(AuditLogEntry {
            id: Some(1),
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: None,
            details: Some(malformed),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("malformed details should fail conversion");

        assert!(
            matches!(error, TeamserverError::Json(_)),
            "expected Json error variant, got {error}"
        );
    }

    #[test]
    fn audit_record_rejects_details_with_wrong_type() {
        // details is a JSON string instead of an object.
        let error = AuditRecord::try_from(AuditLogEntry {
            id: Some(1),
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: None,
            details: Some(json!("not-an-object")),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("string details should fail conversion");

        assert!(
            matches!(error, TeamserverError::Json(_)),
            "expected Json error variant, got {error}"
        );
    }

    #[test]
    fn audit_record_rejects_details_missing_required_field() {
        // Object present but missing `result_status` entirely.
        let error = AuditRecord::try_from(AuditLogEntry {
            id: Some(1),
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: None,
            details: Some(json!({"agent_id": "DEADBEEF"})),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("missing result_status should fail conversion");

        assert!(
            matches!(error, TeamserverError::Json(_)),
            "expected Json error variant, got {error}"
        );
    }

    #[test]
    fn session_activity_record_rejects_malformed_details_json() {
        let malformed = json!({"result_status": "bogus"});
        let error = SessionActivityRecord::try_from(AuditLogEntry {
            id: Some(1),
            actor: "operator".to_owned(),
            action: "operator.connect".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: None,
            details: Some(malformed),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("malformed details should fail conversion");

        assert!(
            matches!(error, TeamserverError::Json(_)),
            "expected Json error variant, got {error}"
        );
    }

    #[test]
    fn session_activity_record_rejects_details_with_wrong_type() {
        let error = SessionActivityRecord::try_from(AuditLogEntry {
            id: Some(1),
            actor: "operator".to_owned(),
            action: "operator.chat".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: None,
            details: Some(json!(42)),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .expect_err("numeric details should fail conversion");

        assert!(
            matches!(error, TeamserverError::Json(_)),
            "expected Json error variant, got {error}"
        );
    }

    #[tokio::test]
    async fn query_audit_log_fails_deterministically_on_malformed_details_row() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        // Insert a well-formed row followed by a malformed one.
        let repo = database.audit_log();
        let good_details =
            serde_json::to_value(audit_details(AuditResultStatus::Success, None, None, None))
                .expect("details should serialize");
        repo.create(&AuditLogEntry {
            id: None,
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: None,
            details: Some(good_details),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .await
        .expect("good row should insert");

        // Malformed: result_status has an invalid enum value.
        repo.create(&AuditLogEntry {
            id: None,
            actor: "operator".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: None,
            details: Some(json!({"result_status": "bogus"})),
            occurred_at: "2026-03-10T13:00:00Z".to_owned(),
        })
        .await
        .expect("malformed row should insert into DB");

        let result = query_audit_log(&database, &AuditQuery::default()).await;
        assert!(
            result.is_err(),
            "query_audit_log must fail when a row has malformed details, not return partial results"
        );
    }

    #[tokio::test]
    async fn query_session_activity_fails_deterministically_on_malformed_details_row() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        let repo = database.audit_log();
        // Well-formed session activity row.
        repo.create(&AuditLogEntry {
            id: None,
            actor: "operator".to_owned(),
            action: "operator.connect".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: None,
            details: Some(
                serde_json::to_value(audit_details(AuditResultStatus::Success, None, None, None))
                    .expect("details should serialize"),
            ),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .await
        .expect("good row should insert");

        // Malformed session activity row.
        repo.create(&AuditLogEntry {
            id: None,
            actor: "operator".to_owned(),
            action: "operator.chat".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: None,
            details: Some(json!({"result_status": "invalid_enum_value"})),
            occurred_at: "2026-03-10T13:00:00Z".to_owned(),
        })
        .await
        .expect("malformed row should insert into DB");

        let result = query_session_activity(&database, &SessionActivityQuery::default()).await;
        assert!(
            result.is_err(),
            "query_session_activity must fail when a row has malformed details, \
             not return partial results"
        );
    }

    #[tokio::test]
    async fn query_audit_log_succeeds_when_details_is_null() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: "agent.task".to_owned(),
                target_kind: "agent".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("row should insert");

        let page = query_audit_log(&database, &AuditQuery::default())
            .await
            .expect("null details should not prevent query");
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].result_status, AuditResultStatus::Success);
    }

    #[tokio::test]
    async fn query_session_activity_succeeds_when_details_is_null() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: "operator.connect".to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("row should insert");

        let page = query_session_activity(&database, &SessionActivityQuery::default())
            .await
            .expect("null details should not prevent query");
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].result_status, AuditResultStatus::Success);
    }

    /// Seed audit rows with varied fields for filter and pagination testing.
    ///
    /// Creates 10 rows with distinct timestamps, result statuses, target kinds,
    /// target ids, and commands so each filter dimension can be tested in isolation.
    async fn seed_diverse_audit_rows(database: &Database) {
        let repo = database.audit_log();
        let rows: Vec<(&str, &str, &str, &str, Option<&str>, Option<&str>, AuditResultStatus)> = vec![
            // (actor, action, target_kind, occurred_at, target_id, command, result_status)
            (
                "alice",
                "agent.task",
                "agent",
                "2026-02-01T01:00:00Z",
                Some("A1"),
                Some("shell"),
                AuditResultStatus::Success,
            ),
            (
                "bob",
                "listener.create",
                "listener",
                "2026-02-02T02:00:00Z",
                Some("L1"),
                Some("create"),
                AuditResultStatus::Success,
            ),
            (
                "alice",
                "agent.task",
                "agent",
                "2026-02-03T03:00:00Z",
                Some("A2"),
                Some("upload"),
                AuditResultStatus::Failure,
            ),
            (
                "bob",
                "agent.task",
                "agent",
                "2026-02-04T04:00:00Z",
                Some("A1"),
                Some("shell"),
                AuditResultStatus::Success,
            ),
            (
                "alice",
                "listener.delete",
                "listener",
                "2026-02-05T05:00:00Z",
                Some("L1"),
                Some("delete"),
                AuditResultStatus::Failure,
            ),
            (
                "bob",
                "agent.task",
                "agent",
                "2026-02-06T06:00:00Z",
                Some("A3"),
                Some("upload"),
                AuditResultStatus::Success,
            ),
            (
                "alice",
                "config.update",
                "config",
                "2026-02-07T07:00:00Z",
                None,
                Some("profile"),
                AuditResultStatus::Success,
            ),
            (
                "bob",
                "agent.task",
                "agent",
                "2026-02-08T08:00:00Z",
                Some("A1"),
                Some("shell"),
                AuditResultStatus::Failure,
            ),
            (
                "alice",
                "listener.create",
                "listener",
                "2026-02-09T09:00:00Z",
                Some("L2"),
                Some("create"),
                AuditResultStatus::Success,
            ),
            (
                "bob",
                "config.update",
                "config",
                "2026-02-10T10:00:00Z",
                None,
                Some("profile"),
                AuditResultStatus::Failure,
            ),
        ];
        for (actor, action, target_kind, occurred_at, target_id, command, result_status) in rows {
            let details = audit_details(result_status, None, command, None);
            repo.create(&AuditLogEntry {
                id: None,
                actor: actor.to_owned(),
                action: action.to_owned(),
                target_kind: target_kind.to_owned(),
                target_id: target_id.map(ToOwned::to_owned),
                details: Some(serde_json::to_value(&details).expect("details should serialize")),
                occurred_at: occurred_at.to_owned(),
            })
            .await
            .expect("seed row should insert");
        }
    }

    #[tokio::test]
    async fn query_audit_log_result_status_filter_narrows_correctly() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query =
            AuditQuery { result_status: Some(AuditResultStatus::Failure), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        // Rows 3, 5, 8, 10 are failures = 4 total
        assert_eq!(page.total, 4, "exactly 4 failure rows should match");
        assert!(
            page.items.iter().all(|r| r.result_status == AuditResultStatus::Failure),
            "only failure rows should be returned"
        );
    }

    #[tokio::test]
    async fn query_audit_log_target_kind_filter_narrows_correctly() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query =
            AuditQuery { target_kind: Some("listener".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        // Rows 2, 5, 9 have target_kind=listener
        assert_eq!(page.total, 3, "exactly 3 listener rows should match");
        assert!(
            page.items.iter().all(|r| r.target_kind == "listener"),
            "only listener rows should be returned"
        );
    }

    #[tokio::test]
    async fn query_audit_log_target_id_filter_narrows_correctly() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query = AuditQuery { target_id: Some("A1".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        // Rows 1, 4, 8 have target_id=A1
        assert_eq!(page.total, 3, "exactly 3 rows with target_id=A1 should match");
        assert!(
            page.items.iter().all(|r| r.target_id.as_deref() == Some("A1")),
            "only rows with target_id=A1 should be returned"
        );
    }

    #[tokio::test]
    async fn query_audit_log_command_filter_narrows_correctly() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query = AuditQuery { command: Some("shell".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        // Rows 1, 4, 8 have command=shell
        assert_eq!(page.total, 3, "exactly 3 rows with command=shell should match");
        assert!(
            page.items.iter().all(|r| r.command.as_deref() == Some("shell")),
            "only rows with command=shell should be returned"
        );
    }

    #[tokio::test]
    async fn query_audit_log_newest_first_ordering() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query = AuditQuery::default();
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 10);
        // Verify strict descending order by occurred_at
        for window in page.items.windows(2) {
            assert!(
                window[0].occurred_at >= window[1].occurred_at,
                "results must be ordered newest-to-oldest, but {} came before {}",
                window[0].occurred_at,
                window[1].occurred_at
            );
        }
    }

    #[tokio::test]
    async fn query_audit_log_pagination_preserves_newest_first_across_pages() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // Page 1: first 3 rows
        let page1_query = AuditQuery { limit: Some(3), offset: Some(0), ..AuditQuery::default() };
        let page1 = query_audit_log(&database, &page1_query).await.expect("page 1 should succeed");

        // Page 2: next 3 rows
        let page2_query = AuditQuery { limit: Some(3), offset: Some(3), ..AuditQuery::default() };
        let page2 = query_audit_log(&database, &page2_query).await.expect("page 2 should succeed");

        // Page 3: next 3 rows
        let page3_query = AuditQuery { limit: Some(3), offset: Some(6), ..AuditQuery::default() };
        let page3 = query_audit_log(&database, &page3_query).await.expect("page 3 should succeed");

        // Page 4: last row
        let page4_query = AuditQuery { limit: Some(3), offset: Some(9), ..AuditQuery::default() };
        let page4 = query_audit_log(&database, &page4_query).await.expect("page 4 should succeed");

        // All pages report the same total
        assert_eq!(page1.total, 10);
        assert_eq!(page2.total, 10);
        assert_eq!(page3.total, 10);
        assert_eq!(page4.total, 10);

        // Page sizes correct
        assert_eq!(page1.items.len(), 3);
        assert_eq!(page2.items.len(), 3);
        assert_eq!(page3.items.len(), 3);
        assert_eq!(page4.items.len(), 1);

        // Concatenate all pages and verify global ordering
        let mut all_timestamps: Vec<String> = Vec::new();
        for page in [&page1, &page2, &page3, &page4] {
            for item in &page.items {
                all_timestamps.push(item.occurred_at.clone());
            }
        }
        for window in all_timestamps.windows(2) {
            assert!(
                window[0] >= window[1],
                "cross-page ordering must be newest-to-oldest, but {} came before {}",
                window[0],
                window[1]
            );
        }

        // The last item on page 1 must be newer-or-equal to the first item on page 2
        assert!(
            page1.items.last().expect("page1 non-empty").occurred_at
                >= page2.items.first().expect("page2 non-empty").occurred_at,
            "page boundary must preserve newest-first ordering"
        );
    }

    #[tokio::test]
    async fn query_audit_log_operator_alias_behaves_like_actor() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // Query using `operator` field alone — should filter by actor.
        let by_operator =
            AuditQuery { operator: Some("alice".to_owned()), ..AuditQuery::default() };
        let page_op = query_audit_log(&database, &by_operator).await.expect("query should succeed");

        // Query using `actor` field alone — should produce identical results.
        let by_actor = AuditQuery { actor: Some("alice".to_owned()), ..AuditQuery::default() };
        let page_act = query_audit_log(&database, &by_actor).await.expect("query should succeed");

        assert_eq!(page_op.total, page_act.total, "operator and actor must produce the same total");
        assert_eq!(
            page_op.items.len(),
            page_act.items.len(),
            "operator and actor must return the same number of items"
        );
        assert!(
            page_op.items.iter().all(|r| r.actor == "alice"),
            "operator filter must narrow to alice"
        );
    }

    #[tokio::test]
    async fn query_audit_log_combined_filters_intersect() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // alice + agent.task + failure → only row 3
        let query = AuditQuery {
            actor: Some("alice".to_owned()),
            action: Some("agent.task".to_owned()),
            result_status: Some(AuditResultStatus::Failure),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 1, "combined filters should yield exactly 1 row");
        assert_eq!(page.items[0].actor, "alice");
        assert_eq!(page.items[0].action, "agent.task");
        assert_eq!(page.items[0].result_status, AuditResultStatus::Failure);
    }

    #[tokio::test]
    async fn query_audit_log_time_window_with_filter_intersects() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // Window Feb 3 through Feb 7 + target_kind=agent → rows 3, 4, 6
        let query = AuditQuery {
            since: Some("2026-02-03T00:00:00Z".to_owned()),
            until: Some("2026-02-07T00:00:00Z".to_owned()),
            target_kind: Some("agent".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 3, "time window + target_kind=agent should yield 3 rows");
        assert!(
            page.items.iter().all(|r| r.target_kind == "agent"),
            "all returned rows must have target_kind=agent"
        );
        assert!(
            page.items.iter().all(|r| {
                r.occurred_at.as_str() >= "2026-02-03T00:00:00Z"
                    && r.occurred_at.as_str() <= "2026-02-07T00:00:00Z"
            }),
            "all returned rows must fall within the time window"
        );
    }

    #[tokio::test]
    async fn query_audit_log_since_boundary_is_inclusive() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // Query where since == exact timestamp of the middle row (2026-01-20T16:00:00Z).
        // That row must be included in the results.
        let query =
            AuditQuery { since: Some("2026-01-20T16:00:00Z".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert!(
            page.items.iter().any(|r| r.occurred_at == "2026-01-20T16:00:00Z"),
            "row exactly at the since boundary must be included"
        );
    }

    #[tokio::test]
    async fn query_audit_log_until_boundary_is_inclusive() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // Query where until == exact timestamp of Jan 15 row.
        let query =
            AuditQuery { until: Some("2026-01-15T12:00:00Z".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert!(
            page.items.iter().any(|r| r.occurred_at == "2026-01-15T12:00:00Z"),
            "row exactly at the until boundary must be included"
        );
    }

    #[tokio::test]
    async fn query_audit_log_offset_timezone_returns_same_items_as_utc() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // UTC query
        let utc_query = AuditQuery {
            since: Some("2026-01-20T16:00:00Z".to_owned()),
            until: Some("2026-01-25T20:00:00Z".to_owned()),
            ..AuditQuery::default()
        };
        let utc_page =
            query_audit_log(&database, &utc_query).await.expect("utc query should succeed");

        // Equivalent query with +05:30 offset:
        //   2026-01-20T21:30:00+05:30 == 2026-01-20T16:00:00Z
        //   2026-01-26T01:30:00+05:30 == 2026-01-25T20:00:00Z
        let offset_query = AuditQuery {
            since: Some("2026-01-20T21:30:00+05:30".to_owned()),
            until: Some("2026-01-26T01:30:00+05:30".to_owned()),
            ..AuditQuery::default()
        };
        let offset_page =
            query_audit_log(&database, &offset_query).await.expect("offset query should succeed");

        assert_eq!(
            utc_page.total, offset_page.total,
            "UTC and offset queries must return same total"
        );
        let utc_ids: Vec<i64> = utc_page.items.iter().map(|r| r.id).collect();
        let offset_ids: Vec<i64> = offset_page.items.iter().map(|r| r.id).collect();
        assert_eq!(utc_ids, offset_ids, "UTC and offset queries must return the same rows");
    }

    #[tokio::test]
    async fn query_audit_log_negative_offset_timezone_normalizes_correctly() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // UTC reference: since 2026-01-15T12:00:00Z → 3 rows (Jan 15, 20, 25, 30 → wait, 4 rows)
        // Actually: Jan 15 12:00, Jan 20 16:00, Jan 25 20:00, Jan 30 23:59:59 → 4 rows
        let utc_query =
            AuditQuery { since: Some("2026-01-15T12:00:00Z".to_owned()), ..AuditQuery::default() };
        let utc_page =
            query_audit_log(&database, &utc_query).await.expect("utc query should succeed");

        // Equivalent with -08:00 offset:
        //   2026-01-15T04:00:00-08:00 == 2026-01-15T12:00:00Z
        let neg_offset_query = AuditQuery {
            since: Some("2026-01-15T04:00:00-08:00".to_owned()),
            ..AuditQuery::default()
        };
        let neg_page = query_audit_log(&database, &neg_offset_query)
            .await
            .expect("negative offset query should succeed");

        assert_eq!(
            utc_page.total, neg_page.total,
            "negative UTC offset must produce same total as equivalent UTC timestamp"
        );
        let utc_ids: Vec<i64> = utc_page.items.iter().map(|r| r.id).collect();
        let neg_ids: Vec<i64> = neg_page.items.iter().map(|r| r.id).collect();
        assert_eq!(utc_ids, neg_ids, "negative offset must return the same rows as UTC");
    }

    #[tokio::test]
    async fn query_audit_log_since_until_single_row_boundary() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_timestamped_audit_rows(&database).await;

        // Window exactly matching one row: since == until == row timestamp.
        let query = AuditQuery {
            since: Some("2026-01-20T16:00:00Z".to_owned()),
            until: Some("2026-01-20T16:00:00Z".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(
            page.total, 1,
            "since == until == row timestamp must return exactly that one row"
        );
        assert_eq!(page.items[0].occurred_at, "2026-01-20T16:00:00Z");
    }

    #[tokio::test]
    async fn actor_filter_falls_back_to_actor_when_operator_absent() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_audit_rows(&database, 100).await;

        // Only `actor` set, no `operator` — should fall back to actor value.
        let query = AuditQuery { actor: Some("bob".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert!(page.total > 0, "bob rows should be present");
        assert!(
            page.items.iter().all(|r| r.actor == "bob"),
            "actor fallback should filter to bob only, \
             but found: {:?}",
            page.items.iter().map(|r| &r.actor).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn query_audit_log_result_status_success_filter_narrows_correctly() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query =
            AuditQuery { result_status: Some(AuditResultStatus::Success), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        // Rows 1, 2, 4, 6, 7, 9 are successes = 6 total
        assert_eq!(page.total, 6, "exactly 6 success rows should match");
        assert!(
            page.items.iter().all(|r| r.result_status == AuditResultStatus::Success),
            "only success rows should be returned"
        );
    }

    #[tokio::test]
    async fn query_audit_log_target_kind_and_result_status_combined() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // agent + Failure → rows 3, 8
        let query = AuditQuery {
            target_kind: Some("agent".to_owned()),
            result_status: Some(AuditResultStatus::Failure),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 2, "agent + failure should yield 2 rows");
        assert!(
            page.items
                .iter()
                .all(|r| r.target_kind == "agent" && r.result_status == AuditResultStatus::Failure),
            "all rows must match both filters"
        );
    }

    #[tokio::test]
    async fn query_audit_log_target_id_and_actor_combined() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // actor=alice + target_id=A1 → only row 1
        let query = AuditQuery {
            actor: Some("alice".to_owned()),
            target_id: Some("A1".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 1, "alice + target_id=A1 should yield 1 row");
        assert_eq!(page.items[0].actor, "alice");
        assert_eq!(page.items[0].target_id.as_deref(), Some("A1"));
    }

    #[tokio::test]
    async fn query_audit_log_operator_and_target_kind_combined() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // operator=bob + target_kind=agent → rows 4, 6, 8
        let query = AuditQuery {
            operator: Some("bob".to_owned()),
            target_kind: Some("agent".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 3, "bob + agent should yield 3 rows");
        assert!(
            page.items.iter().all(|r| r.actor == "bob" && r.target_kind == "agent"),
            "all rows must match both operator and target_kind"
        );
    }

    #[tokio::test]
    async fn query_audit_log_target_id_and_result_status_combined() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // target_id=A1 + Success → rows 1, 4
        let query = AuditQuery {
            target_id: Some("A1".to_owned()),
            result_status: Some(AuditResultStatus::Success),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 2, "A1 + success should yield 2 rows");
        assert!(
            page.items.iter().all(|r| r.target_id.as_deref() == Some("A1")
                && r.result_status == AuditResultStatus::Success),
            "all rows must match both filters"
        );
    }

    #[tokio::test]
    async fn query_audit_log_nonexistent_target_kind_returns_empty() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query =
            AuditQuery { target_kind: Some("nonexistent".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 0, "no rows should match a nonexistent target_kind");
        assert!(page.items.is_empty());
    }

    #[tokio::test]
    async fn query_audit_log_nonexistent_target_id_returns_empty() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let query = AuditQuery { target_id: Some("ZZZZZ".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 0, "no rows should match a nonexistent target_id");
        assert!(page.items.is_empty());
    }

    #[tokio::test]
    async fn query_audit_log_target_id_substring_match() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // "L" should match both "L1" (rows 2, 5) and "L2" (row 9) via instr()
        let query = AuditQuery { target_id: Some("L".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 3, "substring 'L' should match L1 and L2 target_ids");
        assert!(
            page.items.iter().all(|r| r.target_id.as_deref().is_some_and(|id| id.contains('L'))),
            "all returned target_ids must contain 'L'"
        );
    }

    #[tokio::test]
    async fn query_audit_log_target_kind_substring_match() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // "lis" should match "listener" (rows 2, 5, 9) via instr()
        let query = AuditQuery { target_kind: Some("lis".to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 3, "substring 'lis' should match listener target_kind");
        assert!(
            page.items.iter().all(|r| r.target_kind.contains("lis")),
            "all returned target_kinds must contain 'lis'"
        );
    }

    #[tokio::test]
    async fn query_audit_log_triple_filter_target_kind_target_id_result_status() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        // listener + L1 + Failure → only row 5
        let query = AuditQuery {
            target_kind: Some("listener".to_owned()),
            target_id: Some("L1".to_owned()),
            result_status: Some(AuditResultStatus::Failure),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query).await.expect("query should succeed");

        assert_eq!(page.total, 1, "listener + L1 + failure should yield exactly 1 row");
        let item = &page.items[0];
        assert_eq!(item.target_kind, "listener");
        assert_eq!(item.target_id.as_deref(), Some("L1"));
        assert_eq!(item.result_status, AuditResultStatus::Failure);
    }

    // ---------------------------------------------------------------
    // Invalid filter normalization — query_audit_log
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn query_audit_log_invalid_agent_id_is_ignored() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let baseline = query_audit_log(&database, &AuditQuery::default())
            .await
            .expect("baseline query should succeed");
        assert!(baseline.total > 0, "seeded rows should exist");

        for bad_id in ["not-hex", "ZZZZ", "🦀", "  ", "0xGG", "0x-1"] {
            let query = AuditQuery { agent_id: Some(bad_id.to_owned()), ..AuditQuery::default() };
            let page = query_audit_log(&database, &query)
                .await
                .unwrap_or_else(|e| panic!("query with agent_id={bad_id:?} should not error: {e}"));
            assert_eq!(
                page.total, baseline.total,
                "invalid agent_id={bad_id:?} should be ignored, returning all rows"
            );
        }
    }

    #[tokio::test]
    async fn query_audit_log_invalid_since_is_ignored() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let baseline = query_audit_log(&database, &AuditQuery::default())
            .await
            .expect("baseline query should succeed");

        for bad_ts in ["not-a-date", "2026-13-01", "yesterday", ""] {
            let query = AuditQuery { since: Some(bad_ts.to_owned()), ..AuditQuery::default() };
            let page = query_audit_log(&database, &query)
                .await
                .unwrap_or_else(|e| panic!("query with since={bad_ts:?} should not error: {e}"));
            assert_eq!(
                page.total, baseline.total,
                "invalid since={bad_ts:?} should be ignored, returning all rows"
            );
        }
    }

    #[tokio::test]
    async fn query_audit_log_invalid_until_is_ignored() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let baseline = query_audit_log(&database, &AuditQuery::default())
            .await
            .expect("baseline query should succeed");

        for bad_ts in ["not-a-date", "32/01/2026", "∞", ""] {
            let query = AuditQuery { until: Some(bad_ts.to_owned()), ..AuditQuery::default() };
            let page = query_audit_log(&database, &query)
                .await
                .unwrap_or_else(|e| panic!("query with until={bad_ts:?} should not error: {e}"));
            assert_eq!(
                page.total, baseline.total,
                "invalid until={bad_ts:?} should be ignored, returning all rows"
            );
        }
    }

    #[tokio::test]
    async fn query_audit_log_all_invalid_filters_combined_returns_unfiltered() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        seed_diverse_audit_rows(&database).await;

        let baseline = query_audit_log(&database, &AuditQuery::default())
            .await
            .expect("baseline query should succeed");

        let query = AuditQuery {
            agent_id: Some("ZZZZ".to_owned()),
            since: Some("garbage".to_owned()),
            until: Some("also-garbage".to_owned()),
            ..AuditQuery::default()
        };
        let page = query_audit_log(&database, &query)
            .await
            .expect("query with all invalid filters should succeed");
        assert_eq!(
            page.total, baseline.total,
            "all-invalid filters should be ignored, returning full result set"
        );
    }

    // ---------------------------------------------------------------
    // Invalid filter normalization — query_session_activity
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn query_session_activity_invalid_since_is_ignored() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in ["operator.connect", "operator.disconnect", "operator.chat"] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "op".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let baseline = query_session_activity(&database, &SessionActivityQuery::default())
            .await
            .expect("baseline query should succeed");
        assert_eq!(baseline.total, 3, "three seeded session rows expected");

        for bad_ts in ["not-a-date", "yesterday", "2026-99-01", ""] {
            let query =
                SessionActivityQuery { since: Some(bad_ts.to_owned()), ..Default::default() };
            let page = query_session_activity(&database, &query).await.unwrap_or_else(|e| {
                panic!("session query with since={bad_ts:?} should not error: {e}")
            });
            assert_eq!(
                page.total, baseline.total,
                "invalid since={bad_ts:?} should be ignored for session activity"
            );
        }
    }

    #[tokio::test]
    async fn query_session_activity_invalid_until_is_ignored() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in ["operator.connect", "operator.disconnect"] {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "op".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let baseline = query_session_activity(&database, &SessionActivityQuery::default())
            .await
            .expect("baseline query should succeed");
        assert_eq!(baseline.total, 2, "two seeded session rows expected");

        for bad_ts in ["not-a-date", "∞", "32/01/2026", ""] {
            let query =
                SessionActivityQuery { until: Some(bad_ts.to_owned()), ..Default::default() };
            let page = query_session_activity(&database, &query).await.unwrap_or_else(|e| {
                panic!("session query with until={bad_ts:?} should not error: {e}")
            });
            assert_eq!(
                page.total, baseline.total,
                "invalid until={bad_ts:?} should be ignored for session activity"
            );
        }
    }

    #[tokio::test]
    async fn query_session_activity_invalid_since_and_until_combined_returns_unfiltered() {
        let database = Database::connect_in_memory().await.expect("database should initialize");

        for action in
            ["operator.connect", "operator.disconnect", "operator.chat", "operator.session_timeout"]
        {
            database
                .audit_log()
                .create(&AuditLogEntry {
                    id: None,
                    actor: "op".to_owned(),
                    action: action.to_owned(),
                    target_kind: "operator".to_owned(),
                    target_id: None,
                    details: None,
                    occurred_at: "2026-03-10T12:00:00Z".to_owned(),
                })
                .await
                .expect("seed row should insert");
        }

        let baseline = query_session_activity(&database, &SessionActivityQuery::default())
            .await
            .expect("baseline query should succeed");
        assert_eq!(baseline.total, 4, "four seeded session rows expected");

        let query = SessionActivityQuery {
            since: Some("garbage".to_owned()),
            until: Some("also-garbage".to_owned()),
            ..Default::default()
        };
        let page = query_session_activity(&database, &query)
            .await
            .expect("session query with all invalid timestamps should succeed");
        assert_eq!(
            page.total, baseline.total,
            "invalid since+until should be ignored, returning full session activity set"
        );
    }

    #[tokio::test]
    async fn query_audit_log_rejects_offset_exceeding_i64() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let overflowing_offset = (i64::MAX as usize).saturating_add(1);
        let query = AuditQuery { offset: Some(overflowing_offset), ..AuditQuery::default() };
        let error = query_audit_log(&database, &query)
            .await
            .expect_err("offset exceeding i64 should be rejected");
        match error {
            TeamserverError::InvalidPersistedValue { field, message } => {
                assert_eq!(field, "offset");
                assert!(
                    message.contains("i64"),
                    "error message should mention i64 range, got: {message}"
                );
            }
            other => panic!("expected InvalidPersistedValue for offset, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn query_session_activity_rejects_offset_exceeding_i64() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let overflowing_offset = (i64::MAX as usize).saturating_add(1);
        let query = SessionActivityQuery {
            offset: Some(overflowing_offset),
            ..SessionActivityQuery::default()
        };
        let error = query_session_activity(&database, &query)
            .await
            .expect_err("offset exceeding i64 should be rejected");
        match error {
            TeamserverError::InvalidPersistedValue { field, message } => {
                assert_eq!(field, "offset");
                assert!(
                    message.contains("i64"),
                    "error message should mention i64 range, got: {message}"
                );
            }
            other => panic!("expected InvalidPersistedValue for offset, got: {other:?}"),
        }
    }
}
