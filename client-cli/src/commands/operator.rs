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

use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::OperatorCommands;
use crate::client::ApiClient;
use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, TextRow, print_error, print_success};

// ── valid roles ───────────────────────────────────────────────────────────────

const VALID_ROLES: &[&str] = &["admin", "operator", "analyst"];

fn validate_role(role: &str) -> Result<(), CliError> {
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
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct RawCreateResponse {
    username: String,
    role: String,
}

/// Opaque server acknowledgement returned by delete / set-role.
#[derive(Debug, Deserialize)]
struct RawOk {
    #[allow(dead_code)]
    ok: bool,
}

// ── public output types ───────────────────────────────────────────────────────

/// Summary row returned by `operator list`.
#[derive(Debug, Clone, Serialize)]
pub struct OperatorRow {
    /// Operator username.
    pub username: String,
    /// Assigned role: `"admin"`, `"operator"`, or `"analyst"`.
    pub role: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

impl TextRow for OperatorRow {
    fn headers() -> Vec<&'static str> {
        vec!["Username", "Role", "Created At"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.username.clone(), self.role.clone(), self.created_at.clone()]
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

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch an [`OperatorCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: OperatorCommands) -> i32 {
    match action {
        OperatorCommands::List => match list(client).await {
            Ok(data) => {
                print_success(fmt, &data);
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
                e.exit_code()
            }
        },

        OperatorCommands::Create { username, role } => {
            match create(client, &username, &role).await {
                Ok(result) => {
                    print_success(fmt, &result);
                    EXIT_SUCCESS
                }
                Err(e) => {
                    print_error(&e);
                    e.exit_code()
                }
            }
        }

        OperatorCommands::Delete { username } => match delete(client, &username).await {
            Ok(result) => {
                print_success(fmt, &result);
                EXIT_SUCCESS
            }
            Err(e) => {
                print_error(&e);
                e.exit_code()
            }
        },

        OperatorCommands::SetRole { username, role } => {
            match set_role(client, &username, &role).await {
                Ok(result) => {
                    print_success(fmt, &result);
                    EXIT_SUCCESS
                }
                Err(e) => {
                    print_error(&e);
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

/// `operator create <username> --role <role>` — create a new operator.
///
/// Returns the username and one-time API token.  The token cannot be recovered
/// after this call.
///
/// # Examples
/// ```text
/// red-cell-cli operator create alice --role operator
/// red-cell-cli operator create bob   --role admin
/// ```
#[instrument(skip(client))]
async fn create(client: &ApiClient, username: &str, role: &str) -> Result<CreateResult, CliError> {
    validate_role(role)?;

    let body = serde_json::json!({ "username": username, "role": role });
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
    let _: RawOk = client.put(&format!("/operators/{username}/role"), &body).await?;

    Ok(SetRoleResult { username: username.to_owned(), role: role.to_owned() })
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn operator_row_from_raw(raw: RawOperatorSummary) -> OperatorRow {
    OperatorRow { username: raw.username, role: raw.role, created_at: raw.created_at }
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
            created_at: "2026-03-21T00:00:00Z".to_owned(),
        };
        assert_eq!(OperatorRow::headers().len(), row.row().len());
    }

    #[test]
    fn operator_row_serialises_all_fields() {
        let row = OperatorRow {
            username: "bob".to_owned(),
            role: "operator".to_owned(),
            created_at: "2026-03-21T12:00:00Z".to_owned(),
        };
        let v = serde_json::to_value(&row).expect("serialise");
        assert_eq!(v["username"], "bob");
        assert_eq!(v["role"], "operator");
        assert_eq!(v["created_at"], "2026-03-21T12:00:00Z");
    }

    #[test]
    fn vec_operator_row_renders_table_with_data() {
        let rows = vec![OperatorRow {
            username: "alice".to_owned(),
            role: "admin".to_owned(),
            created_at: "2026-03-21T00:00:00Z".to_owned(),
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
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let row = operator_row_from_raw(raw);
        assert_eq!(row.username, "frank");
        assert_eq!(row.role, "operator");
        assert_eq!(row.created_at, "2026-01-01T00:00:00Z");
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
}
