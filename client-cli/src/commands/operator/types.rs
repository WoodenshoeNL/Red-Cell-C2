//! Data types for `red-cell-cli operator` subcommands.
//!
//! Wire types (deserialized from teamserver JSON) are `pub(super)`.
//! Output types (serialised to stdout) are `pub`.

use serde::{Deserialize, Serialize};

use crate::output::{TextRender, TextRow};

// ── raw API response shapes ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct RawOperatorSummary {
    pub username: String,
    pub role: String,
    pub online: bool,
    pub last_seen: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawCreateResponse {
    pub username: String,
    pub role: String,
}

/// Wire body for `GET`/`PUT /operators/{username}/agent-groups`.
#[derive(Debug, Deserialize)]
pub(super) struct RawOperatorGroupAccessResponse {
    pub username: String,
    pub allowed_groups: Vec<String>,
}

/// Wire body for `GET /operators/active`.
#[derive(Debug, Deserialize)]
pub(super) struct RawActiveOperatorEntry {
    pub username: String,
    pub connect_time: String,
    pub remote_addr: String,
}

/// Wire body for `POST /operators/{username}/logout`.
#[derive(Debug, Deserialize)]
pub(super) struct RawLogoutResponse {
    pub username: String,
    pub revoked_sessions: usize,
}

/// Wire body for `GET /operators/whoami`.
#[derive(Debug, Deserialize)]
pub(super) struct RawWhoamiResponse {
    pub name: String,
    pub role: String,
    pub auth_method: String,
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

/// A currently connected operator returned by `operator active`.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveOperatorRow {
    /// Operator username.
    pub username: String,
    /// ISO 8601 timestamp when the session was established.
    pub connect_time: String,
    /// Remote address of the connected client.
    pub remote_addr: String,
}

impl TextRow for ActiveOperatorRow {
    fn headers() -> Vec<&'static str> {
        vec!["Username", "Connected At", "Remote Address"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.username.clone(), self.connect_time.clone(), self.remote_addr.clone()]
    }
}

/// Result returned by `operator logout`.
#[derive(Debug, Clone, Serialize)]
pub struct LogoutResult {
    /// Operator whose sessions were revoked.
    pub username: String,
    /// Number of sessions that were invalidated.
    pub revoked_sessions: usize,
}

impl TextRender for LogoutResult {
    fn render_text(&self) -> String {
        format!(
            "Revoked {} active session(s) for operator '{}'.",
            self.revoked_sessions, self.username
        )
    }
}

/// Result returned by `operator whoami`.
#[derive(Debug, Clone, Serialize)]
pub struct WhoamiResult {
    /// Operator name (API key identifier).
    pub name: String,
    /// RBAC role assigned to this API key.
    pub role: String,
    /// Authentication method used for this request.
    pub auth_method: String,
}

impl TextRender for WhoamiResult {
    fn render_text(&self) -> String {
        format!("{} (role: {}, auth: {})", self.name, self.role, self.auth_method)
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
