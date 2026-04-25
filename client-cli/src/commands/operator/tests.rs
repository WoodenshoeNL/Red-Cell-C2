use super::handlers::operator_row_from_raw;
use super::types::*;
use super::validate_role;
use crate::error::CliError;
use crate::output::{TextRender, TextRow};

// ── validate_role ─────────────────────────────────────────────────────────

#[test]
fn validate_role_accepts_all_valid_roles() {
    for role in ["admin", "operator", "analyst"] {
        assert!(validate_role(role).is_ok(), "'{role}' should be accepted");
    }
}

#[test]
fn validate_role_rejects_unknown_role() {
    let err = validate_role("superuser").unwrap_err();
    assert!(matches!(err, CliError::InvalidArgs(_)));
}

#[test]
fn validate_role_rejects_empty_string() {
    assert!(matches!(validate_role(""), Err(CliError::InvalidArgs(_))));
}

#[test]
fn validate_role_is_case_sensitive() {
    assert!(matches!(validate_role("Admin"), Err(CliError::InvalidArgs(_))));
    assert!(matches!(validate_role("OPERATOR"), Err(CliError::InvalidArgs(_))));
}

// ── OperatorRow ───────────────────────────────────────────────────────────

#[test]
fn operator_row_headers_match_row_length() {
    let row = OperatorRow {
        username: "alice".to_owned(),
        role: "admin".to_owned(),
        online: true,
        last_seen: Some("2026-03-21T00:00:00Z".to_owned()),
    };
    assert_eq!(OperatorRow::headers().len(), row.row().len());
}

#[test]
fn operator_row_serialises_all_fields() {
    let row = OperatorRow {
        username: "bob".to_owned(),
        role: "operator".to_owned(),
        online: false,
        last_seen: Some("2026-03-21T12:00:00Z".to_owned()),
    };
    let v = serde_json::to_value(&row).expect("serialise");
    assert_eq!(v["username"], "bob");
    assert_eq!(v["role"], "operator");
    assert_eq!(v["online"], false);
    assert_eq!(v["last_seen"], "2026-03-21T12:00:00Z");
}

#[test]
fn operator_row_serialises_null_last_seen() {
    let row = OperatorRow {
        username: "carol".to_owned(),
        role: "analyst".to_owned(),
        online: false,
        last_seen: None,
    };
    let v = serde_json::to_value(&row).expect("serialise");
    assert!(v["last_seen"].is_null());
}

#[test]
fn operator_row_renders_online_as_yes_no() {
    let online_row = OperatorRow {
        username: "a".to_owned(),
        role: "admin".to_owned(),
        online: true,
        last_seen: None,
    };
    let offline_row = OperatorRow {
        username: "b".to_owned(),
        role: "admin".to_owned(),
        online: false,
        last_seen: None,
    };
    assert!(online_row.row().contains(&"yes".to_owned()));
    assert!(offline_row.row().contains(&"no".to_owned()));
}

#[test]
fn operator_row_renders_missing_last_seen_as_dash() {
    let row = OperatorRow {
        username: "a".to_owned(),
        role: "admin".to_owned(),
        online: false,
        last_seen: None,
    };
    assert!(row.row().contains(&"-".to_owned()));
}

#[test]
fn vec_operator_row_renders_table_with_data() {
    let rows = vec![OperatorRow {
        username: "alice".to_owned(),
        role: "admin".to_owned(),
        online: true,
        last_seen: Some("2026-03-21T00:00:00Z".to_owned()),
    }];
    let rendered = rows.render_text();
    assert!(rendered.contains("alice"));
    assert!(rendered.contains("admin"));
    assert!(rendered.contains("2026-03-21T00:00:00Z"));
}

#[test]
fn vec_operator_row_empty_renders_none() {
    let rows: Vec<OperatorRow> = vec![];
    assert_eq!(rows.render_text(), "(none)");
}

// ── CreateResult ──────────────────────────────────────────────────────────

#[test]
fn create_result_render_contains_username_and_role() {
    let r = CreateResult { username: "alice".to_owned(), role: "operator".to_owned() };
    let rendered = r.render_text();
    assert!(rendered.contains("alice"));
    assert!(rendered.contains("operator"));
}

#[test]
fn create_result_serialises_both_fields() {
    let r = CreateResult { username: "bob".to_owned(), role: "admin".to_owned() };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["username"], "bob");
    assert_eq!(v["role"], "admin");
}

#[test]
fn raw_create_response_deserialises_server_shape() {
    let json = r#"{"username":"carol","role":"analyst"}"#;
    let raw: RawCreateResponse = serde_json::from_str(json).expect("deserialise");
    assert_eq!(raw.username, "carol");
    assert_eq!(raw.role, "analyst");
}

#[test]
fn raw_create_response_rejects_missing_role() {
    let json = r#"{"username":"dave","token":"tok-xyz"}"#;
    assert!(serde_json::from_str::<RawCreateResponse>(json).is_err());
}

// ── DeleteResult ──────────────────────────────────────────────────────────

#[test]
fn delete_result_render_contains_username() {
    let r = DeleteResult { username: "alice".to_owned() };
    assert!(r.render_text().contains("alice"));
}

#[test]
fn delete_result_serialises_username() {
    let r = DeleteResult { username: "carol".to_owned() };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["username"], "carol");
}

// ── SetRoleResult ─────────────────────────────────────────────────────────

#[test]
fn set_role_result_render_contains_username_and_role() {
    let r = SetRoleResult { username: "dave".to_owned(), role: "analyst".to_owned() };
    let rendered = r.render_text();
    assert!(rendered.contains("dave"));
    assert!(rendered.contains("analyst"));
}

#[test]
fn set_role_result_serialises_both_fields() {
    let r = SetRoleResult { username: "eve".to_owned(), role: "admin".to_owned() };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["username"], "eve");
    assert_eq!(v["role"], "admin");
}

// ── operator_row_from_raw ─────────────────────────────────────────────────

#[test]
fn operator_row_from_raw_maps_all_fields() {
    let raw = RawOperatorSummary {
        username: "frank".to_owned(),
        role: "operator".to_owned(),
        online: true,
        last_seen: Some("2026-01-01T00:00:00Z".to_owned()),
    };
    let row = operator_row_from_raw(raw);
    assert_eq!(row.username, "frank");
    assert_eq!(row.role, "operator");
    assert!(row.online);
    assert_eq!(row.last_seen.as_deref(), Some("2026-01-01T00:00:00Z"));
}

#[test]
fn operator_row_from_raw_lowercases_role() {
    for (input, expected) in [("Analyst", "analyst"), ("Operator", "operator"), ("Admin", "admin")]
    {
        let raw = RawOperatorSummary {
            username: "x".to_owned(),
            role: input.to_owned(),
            online: false,
            last_seen: None,
        };
        assert_eq!(operator_row_from_raw(raw).role, expected);
    }
}

#[test]
fn raw_operator_summary_deserialises_server_shape() {
    let json =
        r#"{"username":"grace","role":"admin","online":true,"last_seen":"2026-03-22T10:00:00Z"}"#;
    let raw: RawOperatorSummary = serde_json::from_str(json).expect("deserialise");
    assert_eq!(raw.username, "grace");
    assert_eq!(raw.role, "admin");
    assert!(raw.online);
    assert_eq!(raw.last_seen.as_deref(), Some("2026-03-22T10:00:00Z"));
}

#[test]
fn raw_operator_summary_deserialises_null_last_seen() {
    let json = r#"{"username":"hal","role":"operator","online":false,"last_seen":null}"#;
    let raw: RawOperatorSummary = serde_json::from_str(json).expect("deserialise");
    assert!(!raw.online);
    assert!(raw.last_seen.is_none());
}

#[test]
fn raw_operator_summary_rejects_old_created_at_shape() {
    let json = r#"{"username":"ivan","role":"analyst","created_at":"2026-01-01T00:00:00Z"}"#;
    assert!(serde_json::from_str::<RawOperatorSummary>(json).is_err());
}

// ── network-independent role validation via create/set_role logic ─────────

#[test]
fn create_role_validation_rejects_bad_role_without_network() {
    let result = validate_role("superuser");
    assert!(matches!(result, Err(CliError::InvalidArgs(_))));
}

#[test]
fn set_role_validation_accepts_analyst() {
    assert!(validate_role("analyst").is_ok());
}

// ── help-surface drift prevention ────────────────────────────────────────

/// Ensure the `operator set-role` help text documents exactly the roles
/// accepted by [`VALID_ROLES`], preventing future drift between CLI docs
/// and validation logic.
#[test]
fn set_role_help_documents_only_valid_roles() {
    use clap::CommandFactory;
    let cmd = crate::cli::Cli::command();
    let operator = cmd
        .get_subcommands()
        .find(|c| c.get_name() == "operator")
        .expect("operator subcommand exists");
    let set_role = operator
        .get_subcommands()
        .find(|c| c.get_name() == "set-role")
        .expect("set-role subcommand exists");

    let mut buf = Vec::new();
    set_role.clone().write_help(&mut buf).expect("render help");
    let help = String::from_utf8(buf).expect("valid utf-8");

    for role in super::VALID_ROLES {
        assert!(help.contains(role), "help text must mention valid role '{role}' but was:\n{help}");
    }

    assert!(
        !help.contains("viewer"),
        "help text must NOT mention retired role 'viewer' but was:\n{help}"
    );
}

// ── OperatorGroupAccessInfo / RawOperatorGroupAccessResponse ──────────────

#[test]
fn raw_operator_group_access_response_deserialises_server_shape() {
    let json = r#"{"username":"alice","allowed_groups":["g1","g2"]}"#;
    let raw: RawOperatorGroupAccessResponse = serde_json::from_str(json).expect("parse");
    assert_eq!(raw.username, "alice");
    assert_eq!(raw.allowed_groups, vec!["g1", "g2"]);
}

#[test]
fn operator_group_access_info_renders_restricted_and_unrestricted() {
    let restricted = OperatorGroupAccessInfo {
        username: "bob".to_owned(),
        allowed_groups: vec!["corp".to_owned()],
    };
    assert!(restricted.render_text().contains("corp"));

    let open = OperatorGroupAccessInfo { username: "carol".to_owned(), allowed_groups: vec![] };
    assert!(open.render_text().contains("unrestricted"));
}

#[test]
fn operator_group_access_info_serialises() {
    let info = OperatorGroupAccessInfo {
        username: "dave".to_owned(),
        allowed_groups: vec!["a".to_owned()],
    };
    let v = serde_json::to_value(&info).expect("serialise");
    assert_eq!(v["username"], "dave");
    assert_eq!(v["allowed_groups"], serde_json::json!(["a"]));
}

// ── WhoamiResult ─────────────────────────────────────────────────────────

#[test]
fn whoami_result_serialises_all_fields() {
    let result = WhoamiResult {
        name: "test-operator".to_owned(),
        role: "operator".to_owned(),
        auth_method: "api_key".to_owned(),
    };
    let v = serde_json::to_value(&result).expect("serialise");
    assert_eq!(v["name"], "test-operator");
    assert_eq!(v["role"], "operator");
    assert_eq!(v["auth_method"], "api_key");
}

#[test]
fn whoami_result_renders_text() {
    let result = WhoamiResult {
        name: "alice".to_owned(),
        role: "admin".to_owned(),
        auth_method: "api_key".to_owned(),
    };
    let text = result.render_text();
    assert!(text.contains("alice"));
    assert!(text.contains("admin"));
    assert!(text.contains("api_key"));
}

#[test]
fn raw_whoami_response_deserialises_server_shape() {
    let json = r#"{"name":"ops","role":"Analyst","auth_method":"api_key"}"#;
    let raw: RawWhoamiResponse = serde_json::from_str(json).expect("parse");
    assert_eq!(raw.name, "ops");
    assert_eq!(raw.role, "Analyst");
    assert_eq!(raw.auth_method, "api_key");
}
