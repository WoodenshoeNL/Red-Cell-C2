//! Audit log entry types, serialization helpers, and filter/query models.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{IntoParams, ToSchema};

use crate::{AuditLogEntry, TeamserverError};

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
    pub(crate) const DEFAULT_LIMIT: usize = 50;
    pub(crate) const MAX_LIMIT: usize = 200;

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

    pub(super) fn normalized_agent_id(&self) -> Option<String> {
        self.agent_id.as_deref().and_then(parse_agent_id_filter)
    }

    pub(super) fn actor_filter(&self) -> Option<&str> {
        self.operator.as_deref().or(self.actor.as_deref())
    }

    pub(super) fn since_timestamp(&self) -> Option<OffsetDateTime> {
        self.since.as_deref().and_then(parse_timestamp_filter)
    }

    pub(super) fn until_timestamp(&self) -> Option<OffsetDateTime> {
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

    pub(super) fn since_timestamp(&self) -> Option<OffsetDateTime> {
        self.since.as_deref().and_then(parse_timestamp_filter)
    }

    pub(super) fn until_timestamp(&self) -> Option<OffsetDateTime> {
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

/// Build an audit payload for a login attempt without persisting sensitive fields.
#[must_use]
pub fn login_parameters(username: &str, connection_id: &uuid::Uuid) -> Value {
    json!({
        "username": username,
        "connection_id": connection_id.to_string(),
    })
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
pub(super) fn parse_agent_id_filter(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    let agent_id = u32::from_str_radix(hex_digits, 16).ok()?;
    Some(format!("{agent_id:08X}"))
}

/// Format an optional timestamp as a UTC RFC 3339 string for SQL comparison.
pub(super) fn normalize_timestamp_utc(
    ts: Option<OffsetDateTime>,
) -> Result<Option<String>, TeamserverError> {
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
