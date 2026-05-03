//! Public JSON/table types for `red-cell-cli agent` output.

use serde::{Deserialize, Serialize};

use crate::AgentId;
use crate::output::{TextRender, TextRow};

/// Summary row returned by `agent list`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentSummary {
    /// Unique agent identifier.
    pub id: AgentId,
    /// Hostname of the compromised host.
    pub hostname: String,
    /// Operating system (e.g. `"Windows 10 x64"`).
    pub os: String,
    /// RFC 3339 timestamp of the agent's last check-in.
    pub last_seen: String,
    /// Liveness status: `"alive"` or `"dead"`.
    pub status: String,
    /// Name of the listener that accepted this agent.
    pub listener: String,
}

impl TextRow for AgentSummary {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "Hostname", "OS", "Last Seen", "Status", "Listener"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.hostname.clone(),
            self.os.clone(),
            self.last_seen.clone(),
            self.status.clone(),
            self.listener.clone(),
        ]
    }
}

/// Full agent record returned by `agent show`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentDetail {
    pub id: AgentId,
    pub hostname: String,
    pub os: String,
    pub arch: Option<String>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub external_ip: Option<String>,
    pub internal_ip: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u64>,
    pub elevated: Option<bool>,
    pub first_seen: String,
    pub last_seen: String,
    pub status: String,
    pub sleep_interval: Option<u64>,
    pub jitter: Option<u64>,
    pub listener: String,
}

impl TextRender for AgentDetail {
    fn render_text(&self) -> String {
        use comfy_table::{Cell, ContentArrangement, Table};
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header([Cell::new("Field"), Cell::new("Value")]);
        let rows: &[(&str, String)] = &[
            ("id", self.id.to_string()),
            ("hostname", self.hostname.clone()),
            ("os", self.os.clone()),
            ("arch", self.arch.clone().unwrap_or_default()),
            ("username", self.username.clone().unwrap_or_default()),
            ("domain", self.domain.clone().unwrap_or_default()),
            ("external_ip", self.external_ip.clone().unwrap_or_default()),
            ("internal_ip", self.internal_ip.clone().unwrap_or_default()),
            ("process_name", self.process_name.clone().unwrap_or_default()),
            ("pid", self.pid.map_or_else(String::new, |p| p.to_string())),
            ("elevated", self.elevated.map_or_else(String::new, |e| e.to_string())),
            ("first_seen", self.first_seen.clone()),
            ("last_seen", self.last_seen.clone()),
            ("status", self.status.clone()),
            ("sleep_interval", self.sleep_interval.map_or_else(String::new, |s| s.to_string())),
            ("jitter", self.jitter.map_or_else(String::new, |j| j.to_string())),
            ("listener", self.listener.clone()),
        ];
        for (field, val) in rows {
            table.add_row([Cell::new(*field), Cell::new(val)]);
        }
        table.to_string()
    }
}

/// Result of `agent exec` without `--wait`.
#[derive(Debug, Clone, Serialize)]
pub struct JobSubmitted {
    /// Identifier for the queued job.
    pub job_id: String,
}

impl TextRender for JobSubmitted {
    fn render_text(&self) -> String {
        format!("Job submitted: {}", self.job_id)
    }
}

/// Result of `agent exec --wait`.
#[derive(Debug, Clone, Serialize)]
pub struct ExecResult {
    pub job_id: String,
    pub output: String,
    pub exit_code: Option<i32>,
}

impl TextRender for ExecResult {
    fn render_text(&self) -> String {
        let code = self.exit_code.map_or_else(|| "?".to_owned(), |c| c.to_string());
        format!("[job {}  exit {}]\n{}", self.job_id, code, self.output)
    }
}

/// Single output entry returned by `agent output`.
#[derive(Debug, Clone, Serialize)]
pub struct OutputEntry {
    /// Numeric database row id — used as the polling cursor for incremental
    /// fetches (`?since=<entry_id>`).  Matches the `id` field in the server's
    /// `AgentOutputEntry` and the `AgentOutputQuery::since: Option<i64>`
    /// parameter.
    pub entry_id: i64,
    /// Correlates with REST `TaskID` / Demon request id on the wire.
    pub request_id: u32,
    pub job_id: String,
    pub command: Option<String>,
    pub output: String,
    pub exit_code: Option<i32>,
    pub created_at: String,
}

impl TextRow for OutputEntry {
    fn headers() -> Vec<&'static str> {
        vec!["Job ID", "Command", "Exit", "Created At", "Output"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.job_id.clone(),
            self.command.clone().unwrap_or_default(),
            self.exit_code.map_or_else(String::new, |c| c.to_string()),
            self.created_at.clone(),
            // Truncate long output in table mode.
            self.output.chars().take(80).collect(),
        ]
    }
}

/// Result of `agent kill`.
#[derive(Debug, Clone, Serialize)]
pub struct KillResult {
    pub agent_id: AgentId,
    pub status: String,
}

impl TextRender for KillResult {
    fn render_text(&self) -> String {
        format!("Agent {}  status: {}", self.agent_id, self.status)
    }
}

/// Result of `agent upload` and `agent download`.
#[derive(Debug, Clone, Serialize)]
pub struct TransferResult {
    pub agent_id: AgentId,
    pub job_id: Option<String>,
    pub local_path: String,
    pub remote_path: String,
}

impl TextRender for TransferResult {
    fn render_text(&self) -> String {
        match &self.job_id {
            Some(jid) => format!(
                "Transfer job {jid}  agent: {}  remote: {}  local: {}",
                self.agent_id, self.remote_path, self.local_path
            ),
            None => format!(
                "Transfer complete  agent: {}  remote: {}  local: {}",
                self.agent_id, self.remote_path, self.local_path
            ),
        }
    }
}

/// Wire body for `GET`/`PUT /agents/{id}/groups`.
#[derive(Debug, Deserialize)]
pub(crate) struct RawAgentGroupsResponse {
    pub(crate) agent_id: String,
    pub(crate) groups: Vec<String>,
}

/// RBAC group membership for an agent (`agent groups` / `agent set-groups`).
#[derive(Debug, Clone, Serialize)]
pub struct AgentGroupsInfo {
    /// Hex agent id as returned by the server (e.g. `"DEADBEEF"`).
    pub agent_id: String,
    /// Group names assigned to the agent (empty means no tags).
    pub groups: Vec<String>,
}

impl TextRender for AgentGroupsInfo {
    fn render_text(&self) -> String {
        if self.groups.is_empty() {
            format!("Agent {} — no RBAC groups.", self.agent_id)
        } else {
            format!("Agent {} — groups: {}", self.agent_id, self.groups.join(", "))
        }
    }
}
