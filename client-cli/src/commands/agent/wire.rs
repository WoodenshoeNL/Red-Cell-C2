//! Raw API wire types for agent REST endpoints.

use serde::{Deserialize, Serialize};

use crate::AgentId;

/// Wire format returned by `GET /agents` and `GET /agents/{id}`.
///
/// Field names and types mirror `ApiAgentInfo` in the teamserver
/// (`teamserver/src/api.rs`) exactly so that serde can deserialise the
/// server response without loss of data.  All PascalCase renames match
/// the `#[serde(rename = "…")]` attributes on `ApiAgentInfo`.
///
/// Only the fields consumed by [`From<ApiAgentWire>`] are declared here.
/// The server sends additional fields (`Reason`, `Note`, `BaseAddress`,
/// `ProcessTID`, `ProcessPPID`, `OSBuild`, `KillDate`, `WorkingHours`) that
/// are silently ignored by serde — no `deny_unknown_fields` is set.
#[derive(Debug, Deserialize)]
struct ApiAgentWire {
    #[serde(rename = "AgentID")]
    agent_id: u32,
    #[serde(rename = "Active")]
    active: bool,
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "DomainName")]
    domain_name: String,
    #[serde(rename = "ExternalIP")]
    external_ip: String,
    #[serde(rename = "InternalIP")]
    internal_ip: String,
    #[serde(rename = "ProcessName")]
    process_name: String,
    #[serde(rename = "ProcessPID")]
    process_pid: u32,
    #[serde(rename = "ProcessArch")]
    process_arch: String,
    #[serde(rename = "Elevated")]
    elevated: bool,
    #[serde(rename = "OSVersion")]
    os_version: String,
    #[serde(rename = "OSArch")]
    os_arch: String,
    #[serde(rename = "SleepDelay")]
    sleep_delay: u32,
    #[serde(rename = "SleepJitter")]
    sleep_jitter: u32,
    #[serde(rename = "FirstCallIn")]
    first_call_in: String,
    #[serde(rename = "LastCallIn")]
    last_call_in: String,
    #[serde(rename = "Listener", default)]
    listener: String,
}

/// Normalised agent record used throughout the CLI.
///
/// The teamserver returns agent data as `ApiAgentInfo` (PascalCase fields).
/// `RawAgent` is populated from the wire format via `#[serde(from =
/// "ApiAgentWire")]` — all deserialization goes through `ApiAgentWire` and
/// the `From` impl below converts PascalCase fields and derives computed
/// values (`id` as hex string, `os` as combined version+arch, `status` from
/// the `Active` boolean).
#[derive(Debug, Deserialize, Serialize)]
#[serde(from = "ApiAgentWire")]
pub(crate) struct RawAgent {
    /// Agent identifier as an uppercase hex string, e.g. `"DEADBEEF"`.
    pub(crate) id: AgentId,
    pub(crate) hostname: String,
    /// Combined OS string, e.g. `"Windows 11 x64"`.
    pub(crate) os: String,
    /// RFC 3339 timestamp of the agent's last check-in (`LastCallIn`).
    pub(crate) last_seen: String,
    /// RFC 3339 timestamp of the agent's first check-in (`FirstCallIn`).
    pub(crate) first_seen: String,
    /// `"alive"` when `Active == true`, `"dead"` otherwise.
    pub(crate) status: String,
    pub(crate) arch: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) external_ip: Option<String>,
    pub(crate) internal_ip: Option<String>,
    pub(crate) process_name: Option<String>,
    pub(crate) pid: Option<u64>,
    pub(crate) elevated: Option<bool>,
    pub(crate) sleep_interval: Option<u64>,
    pub(crate) jitter: Option<u64>,
    pub(crate) listener: String,
}

impl From<ApiAgentWire> for RawAgent {
    fn from(w: ApiAgentWire) -> Self {
        Self {
            id: AgentId::from(w.agent_id),
            hostname: w.hostname,
            os: format!("{} {}", w.os_version, w.os_arch),
            last_seen: w.last_call_in,
            first_seen: w.first_call_in,
            status: if w.active { "alive".to_owned() } else { "dead".to_owned() },
            arch: Some(w.process_arch),
            username: Some(w.username),
            domain: Some(w.domain_name),
            external_ip: Some(w.external_ip),
            internal_ip: Some(w.internal_ip),
            process_name: Some(w.process_name),
            pid: Some(w.process_pid as u64),
            elevated: Some(w.elevated),
            sleep_interval: Some(w.sleep_delay as u64),
            jitter: Some(w.sleep_jitter as u64),
            listener: w.listener,
        }
    }
}

/// Response from `POST /agents/{id}/task` and `DELETE /agents/{id}`.
#[derive(Debug, Deserialize)]
pub(crate) struct TaskQueuedResponse {
    pub(crate) task_id: String,
}
