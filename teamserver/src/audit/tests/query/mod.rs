mod filtering;
mod pagination;
mod session_activity;
mod time_range;

use serde_json::json;

use super::super::types::parse_agent_id_filter;
use super::super::{
    AuditQuery, AuditRecord, AuditResultStatus, SessionActivityQuery, SessionActivityRecord,
    audit_details, login_parameters, parameter_object, query_audit_log, query_session_activity,
};
use crate::{AuditLogEntry, Database, TeamserverError};

// ---- type unit tests ----

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

    let payload = login_parameters("operator", &connection_id, "rest");

    assert_eq!(
        payload,
        json!({
            "username": "operator",
            "connection_id": "12345678-1234-5678-9abc-1234567890ab",
            "auth_vector": "rest",
        })
    );

    let object = payload.as_object().expect("payload should be a JSON object");
    assert_eq!(object.len(), 3);
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

    let payload = login_parameters(username, &connection_id, "websocket");

    assert_eq!(payload["username"], json!(username));
    assert_eq!(payload["connection_id"], json!(connection_id.to_string()));
    assert_eq!(payload["auth_vector"], json!("websocket"));
    assert!(payload.get("password").is_none());
    assert!(payload.get("password_hash").is_none());
}

#[test]
fn login_parameters_auth_vector_distinguishes_rest_from_websocket() {
    let connection_id = uuid::Uuid::parse_str("12345678-1234-5678-9abc-1234567890ab")
        .expect("connection id should parse");

    let rest = login_parameters("operator", &connection_id, "rest");
    let ws = login_parameters("operator", &connection_id, "websocket");

    assert_eq!(rest["auth_vector"], json!("rest"));
    assert_eq!(ws["auth_vector"], json!("websocket"));
    assert_ne!(rest, ws);
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

    assert!(matches!(error, TeamserverError::Json(_)), "expected Json error variant, got {error}");
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

    assert!(matches!(error, TeamserverError::Json(_)), "expected Json error variant, got {error}");
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

    assert!(matches!(error, TeamserverError::Json(_)), "expected Json error variant, got {error}");
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

    assert!(matches!(error, TeamserverError::Json(_)), "expected Json error variant, got {error}");
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

    assert!(matches!(error, TeamserverError::Json(_)), "expected Json error variant, got {error}");
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

// ---- shared seed helpers used by submodules ----

/// Seed `count` audit rows across two actors, two actions, and one agent id.
pub(super) async fn seed_audit_rows(database: &Database, count: usize) {
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

/// Seed audit rows with specific timestamps for time-range filter testing.
pub(super) async fn seed_timestamped_audit_rows(database: &Database) {
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

/// Seed audit rows with varied fields for filter and pagination testing.
///
/// Creates 10 rows with distinct timestamps, result statuses, target kinds,
/// target ids, and commands so each filter dimension can be tested in isolation.
pub(super) async fn seed_diverse_audit_rows(database: &Database) {
    let repo = database.audit_log();
    #[allow(clippy::type_complexity)]
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
