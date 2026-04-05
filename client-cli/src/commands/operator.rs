//! `red-cell-cli operator` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `operator list` | `GET /operators` | table of all operators |
//! | `operator create <name> --role <role>` | `POST /operators` | prints username and assigned role |
//! | `operator delete <name>` | `DELETE /operators/{username}` | hard delete |
//! | `operator set-role <name> <role>` | `PUT /operators/{username}/role` | role update |
//! | `operator show-agent-groups <name>` | `GET /operators/{username}/agent-groups` | allowed agent groups |
//! | `operator set-agent-groups <name>` | `PUT /operators/{username}/agent-groups` | replace group restrictions |

use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::OperatorCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};

// ── valid roles ───────────────────────────────────────────────────────────────

const VALID_ROLES: &[&str] = &["admin", "operator", "analyst"];

pub(crate) fn validate_role(role: &str) -> Result<(), CliError> {
    if VALID_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(CliError::InvalidArgs(format!(
            "unknown role '{role}': expected admin, operator, or analyst"
        )))
    }
}

// ── raw API response shapes ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawOperatorSummary {
    username: String,
    role: String,
    online: bool,
    last_seen: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCreateResponse {
    username: String,
    role: String,
}

/// Wire body for `GET`/`PUT /operators/{username}/agent-groups`.
#[derive(Debug, Deserialize)]
struct RawOperatorGroupAccessResponse {
    username: String,
    allowed_groups: Vec<String>,
}

// ── public output types ───────────────────────────────────────────────────────

/// Summary row returned by `operator list`.
#[derive(Debug, Clone, Serialize)]
pub struct OperatorRow {
    /// Operator username.
    pub username: String,
    /// Assigned role: `"admin"`, `"operator"`, or `"analyst"`.
    pub role: String,
    /// Whether the operator is currently connected.
    pub online: bool,
    /// RFC 3339 timestamp of the operator's last activity, if any.
    pub last_seen: Option<String>,
}

impl TextRow for OperatorRow {
    fn headers() -> Vec<&'static str> {
        vec!["Username", "Role", "Online", "Last Seen"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.username.clone(),
            self.role.clone(),
            if self.online { "yes".to_owned() } else { "no".to_owned() },
            self.last_seen.clone().unwrap_or_else(|| "-".to_owned()),
        ]
    }
}

/// Result returned by `operator create`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateResult {
    /// Operator username.
    pub username: String,
    /// Role assigned to the new operator.
    pub role: String,
}

impl TextRender for CreateResult {
    fn render_text(&self) -> String {
        format!("Operator '{}' created with role '{}'.", self.username, self.role)
    }
}

/// Result returned by `operator delete`.
#[derive(Debug, Clone, Serialize)]
pub struct DeleteResult {
    /// Username that was deleted.
    pub username: String,
}

impl TextRender for DeleteResult {
    fn render_text(&self) -> String {
        format!("Operator '{}' deleted.", self.username)
    }
}

/// Result returned by `operator set-role`.
#[derive(Debug, Clone, Serialize)]
pub struct SetRoleResult {
    /// Username whose role was updated.
    pub username: String,
    /// New role that was assigned.
    pub role: String,
}

impl TextRender for SetRoleResult {
    fn render_text(&self) -> String {
        format!("Operator '{}' role set to '{}'.", self.username, self.role)
    }
}

/// Agent-group restrictions for an operator (`show-agent-groups` / `set-agent-groups`).
#[derive(Debug, Clone, Serialize)]
pub struct OperatorGroupAccessInfo {
    /// Operator username.
    pub username: String,
    /// Group names this operator may task agents from (empty means unrestricted).
    pub allowed_groups: Vec<String>,
}

impl TextRender for OperatorGroupAccessInfo {
    fn render_text(&self) -> String {
        if self.allowed_groups.is_empty() {
            format!("Operator '{}' — unrestricted (no agent-group limits).", self.username)
        } else {
            format!(
                "Operator '{}' — allowed agent groups: {}",
                self.username,
                self.allowed_groups.join(", ")
            )
        }
    }
}

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch an [`OperatorCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: OperatorCommands) -> i32 {
    match action {
        OperatorCommands::List => match list(client).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        OperatorCommands::Create { username, password, role } => {
            match create(client, &username, &password, &role).await {
                Ok(result) => match print_success(fmt, &result) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        OperatorCommands::Delete { username } => match delete(client, &username).await {
            Ok(result) => match print_success(fmt, &result) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        OperatorCommands::SetRole { username, role } => {
            match set_role(client, &username, &role).await {
                Ok(result) => match print_success(fmt, &result) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        OperatorCommands::ShowAgentGroups { username } => {
            match get_operator_agent_groups(client, &username).await {
                Ok(data) => match print_success(fmt, &data) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        OperatorCommands::SetAgentGroups { username, group } => {
            match set_operator_agent_groups(client, &username, &group).await {
                Ok(data) => match print_success(fmt, &data) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }
    }
}

// ── command implementations ───────────────────────────────────────────────────

/// `operator list` — fetch all registered operators.
///
/// # Examples
/// ```text
/// red-cell-cli operator list
/// ```
#[instrument(skip(client))]
async fn list(client: &ApiClient) -> Result<Vec<OperatorRow>, CliError> {
    let raw: Vec<RawOperatorSummary> = client.get("/operators").await?;
    Ok(raw.into_iter().map(operator_row_from_raw).collect())
}

/// `operator create <username> --password <password> --role <role>` — create a new operator.
///
/// # Examples
/// ```text
/// red-cell-cli operator create alice --role operator --password s3cr3t!
/// red-cell-cli operator create bob   --role admin    --password hunter2
/// ```
#[instrument(skip(client, password))]
async fn create(
    client: &ApiClient,
    username: &str,
    password: &str,
    role: &str,
) -> Result<CreateResult, CliError> {
    validate_role(role)?;

    let body = serde_json::json!({ "username": username, "password": password, "role": role });
    let raw: RawCreateResponse = client.post("/operators", &body).await?;

    Ok(CreateResult { username: raw.username, role: raw.role })
}

/// `operator delete <username>` — permanently remove an operator account.
///
/// # Examples
/// ```text
/// red-cell-cli operator delete alice
/// ```
#[instrument(skip(client))]
async fn delete(client: &ApiClient, username: &str) -> Result<DeleteResult, CliError> {
    client.delete_no_body(&format!("/operators/{username}")).await?;
    Ok(DeleteResult { username: username.to_owned() })
}

/// `operator set-role <username> <role>` — change an operator's role.
///
/// # Examples
/// ```text
/// red-cell-cli operator set-role alice admin
/// red-cell-cli operator set-role bob   analyst
/// ```
#[instrument(skip(client))]
async fn set_role(
    client: &ApiClient,
    username: &str,
    role: &str,
) -> Result<SetRoleResult, CliError> {
    validate_role(role)?;

    let body = serde_json::json!({ "role": role });
    let raw: RawOperatorSummary = client.put(&format!("/operators/{username}/role"), &body).await?;

    Ok(SetRoleResult { username: raw.username, role: raw.role })
}

/// `operator show-agent-groups <username>` — fetch RBAC agent-group restrictions.
///
/// # Examples
/// ```text
/// red-cell-cli operator show-agent-groups alice
/// ```
#[instrument(skip(client))]
async fn get_operator_agent_groups(
    client: &ApiClient,
    username: &str,
) -> Result<OperatorGroupAccessInfo, CliError> {
    let raw: RawOperatorGroupAccessResponse =
        client.get(&format!("/operators/{username}/agent-groups")).await?;
    Ok(OperatorGroupAccessInfo { username: raw.username, allowed_groups: raw.allowed_groups })
}

/// `operator set-agent-groups <username>` — replace agent-group restrictions.
///
/// # Examples
/// ```text
/// red-cell-cli operator set-agent-groups alice --group tier1
/// red-cell-cli operator set-agent-groups alice
/// ```
#[instrument(skip(client, groups))]
async fn set_operator_agent_groups(
    client: &ApiClient,
    username: &str,
    groups: &[String],
) -> Result<OperatorGroupAccessInfo, CliError> {
    let body = serde_json::json!({ "allowed_groups": groups });
    let raw: RawOperatorGroupAccessResponse =
        client.put(&format!("/operators/{username}/agent-groups"), &body).await?;
    Ok(OperatorGroupAccessInfo { username: raw.username, allowed_groups: raw.allowed_groups })
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn operator_row_from_raw(raw: RawOperatorSummary) -> OperatorRow {
    OperatorRow {
        username: raw.username,
        role: raw.role,
        online: raw.online,
        last_seen: raw.last_seen,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        // The old buggy shape had `token` instead of `role`; ensure we reject it.
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
    fn raw_operator_summary_deserialises_server_shape() {
        let json = r#"{"username":"grace","role":"admin","online":true,"last_seen":"2026-03-22T10:00:00Z"}"#;
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
        // created_at was the old (wrong) shape — it should no longer deserialise
        // into RawOperatorSummary because the required `online` field is absent.
        let json = r#"{"username":"ivan","role":"analyst","created_at":"2026-01-01T00:00:00Z"}"#;
        assert!(serde_json::from_str::<RawOperatorSummary>(json).is_err());
    }

    // ── network-independent role validation via create/set_role logic ─────────

    #[test]
    fn create_role_validation_rejects_bad_role_without_network() {
        // Replicate the validation branch directly.
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
        let cmd = crate::Cli::command();
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

        // Every valid role must appear in the help text.
        for role in VALID_ROLES {
            assert!(
                help.contains(role),
                "help text must mention valid role '{role}' but was:\n{help}"
            );
        }

        // The retired `viewer` role must not appear.
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
}
