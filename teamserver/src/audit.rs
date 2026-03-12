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
    let entries = repo.query_filtered(&filter, sql_limit, sql_offset).await?;
    let items = entries
        .into_iter()
        .filter(|entry| actions.contains(&entry.action))
        .map(TryInto::try_into)
        .collect::<Result<Vec<SessionActivityRecord>, _>>()?;

    let total = usize::try_from(repo.count_filtered(&filter).await?).map_err(|_| {
        TeamserverError::InvalidPersistedValue {
            field: "total",
            message: "row count exceeds usize range".to_owned(),
        }
    })?;

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
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::{
        AuditQuery, AuditRecord, AuditResultStatus, SessionActivityRecord, audit_details,
        parameter_object, parse_agent_id_filter,
    };
    use crate::{
        AuditLogEntry, AuditWebhookNotifier, Database, TeamserverError,
        record_operator_action_with_notifications,
    };
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
    fn agent_id_filter_always_parses_hex() {
        assert_eq!(parse_agent_id_filter("DEADBEEF").as_deref(), Some("DEADBEEF"));
        assert_eq!(parse_agent_id_filter("0x10").as_deref(), Some("00000010"));
        assert_eq!(parse_agent_id_filter("00000010").as_deref(), Some("00000010"));
        assert_eq!(parse_agent_id_filter("16").as_deref(), Some("00000016"));
        assert!(parse_agent_id_filter("").is_none());
        assert!(parse_agent_id_filter("ZZZZ").is_none());
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
            let _ = axum::serve(listener, app).await;
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
            let _ = axum::serve(listener, app).await;
        });

        (address, server)
    }
}
