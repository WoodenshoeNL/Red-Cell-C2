//! Structured operator audit logging helpers and REST-facing models.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{IntoParams, ToSchema};

use crate::{AuditLogEntry, Database, TeamserverError};

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
    /// Filter by related agent id in hex or decimal form.
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

/// Persist a structured audit-log entry for an operator action.
pub async fn record_operator_action(
    database: &Database,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: AuditDetails,
) -> Result<i64, TeamserverError> {
    let occurred_at = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|error| {
        TeamserverError::InvalidPersistedValue { field: "occurred_at", message: error.to_string() }
    })?;

    database
        .audit_log()
        .create(&AuditLogEntry {
            id: None,
            actor: actor.to_owned(),
            action: action.to_owned(),
            target_kind: target_kind.to_owned(),
            target_id,
            details: Some(serde_json::to_value(details)?),
            occurred_at,
        })
        .await
}

/// Return a filtered and paginated view of the audit log.
pub async fn query_audit_log(
    database: &Database,
    query: &AuditQuery,
) -> Result<AuditPage, TeamserverError> {
    let normalized_agent_id = query.normalized_agent_id();
    let mut items = database
        .audit_log()
        .list()
        .await?
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<AuditRecord>, _>>()?;

    items.reverse();
    items.retain(|entry| matches_query(entry, query, normalized_agent_id.as_deref()));

    let total = items.len();
    let offset = query.offset();
    let limit = query.limit();
    let items = items.into_iter().skip(offset).take(limit).collect();

    Ok(AuditPage { total, limit, offset, items })
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

fn matches_query(
    entry: &AuditRecord,
    query: &AuditQuery,
    normalized_agent_id: Option<&str>,
) -> bool {
    contains_filter(&entry.actor, query.actor_filter())
        && contains_filter(&entry.action, query.action.as_deref())
        && contains_filter(&entry.target_kind, query.target_kind.as_deref())
        && optional_contains_filter(entry.target_id.as_deref(), query.target_id.as_deref())
        && optional_contains_filter(entry.command.as_deref(), query.command.as_deref())
        && matches_agent_id(entry.agent_id.as_deref(), normalized_agent_id)
        && query.result_status.is_none_or(|status| entry.result_status == status)
        && matches_timestamp(
            entry.occurred_at.as_str(),
            query.since_timestamp(),
            query.until_timestamp(),
        )
}

fn contains_filter(value: &str, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| value.contains(filter))
}

fn optional_contains_filter(value: Option<&str>, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| value.is_some_and(|value| value.contains(filter)))
}

fn matches_agent_id(value: Option<&str>, filter: Option<&str>) -> bool {
    filter.is_none_or(|filter| value == Some(filter))
}

fn matches_timestamp(
    occurred_at: &str,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
) -> bool {
    let Some(timestamp) = parse_timestamp_filter(occurred_at) else {
        return false;
    };

    since.is_none_or(|boundary| timestamp >= boundary)
        && until.is_none_or(|boundary| timestamp <= boundary)
}

fn parse_timestamp_filter(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn parse_agent_id_filter(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let maybe_prefixed =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    let parse_hex = trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        || maybe_prefixed.chars().any(|character| character.is_ascii_alphabetic());
    let radix = if parse_hex { 16 } else { 10 };
    let agent_id = u32::from_str_radix(maybe_prefixed, radix).ok()?;
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
    use super::{
        AuditQuery, AuditRecord, AuditResultStatus, audit_details, parameter_object,
        parse_agent_id_filter,
    };
    use crate::AuditLogEntry;
    use serde_json::json;

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
    fn parameter_object_builds_json_object() {
        let value = parameter_object([("listener", json!("http")), ("port", json!(443))]);
        assert_eq!(value, json!({"listener":"http","port":443}));
    }

    #[test]
    fn agent_id_filter_normalizes_hex_and_decimal_inputs() {
        assert_eq!(parse_agent_id_filter("DEADBEEF").as_deref(), Some("DEADBEEF"));
        assert_eq!(parse_agent_id_filter("0x10").as_deref(), Some("00000010"));
        assert_eq!(parse_agent_id_filter("16").as_deref(), Some("00000010"));
        assert!(parse_agent_id_filter("").is_none());
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
}
