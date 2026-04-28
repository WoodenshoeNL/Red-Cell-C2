//! Agent, task, response, and update payload structs for the operator protocol.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Maximum byte length of an operator-authored agent note.
///
/// Enforced at every path that writes [`crate::AgentRecord::note`] so that a
/// single misbehaving operator cannot inflate the `agents` table or audit
/// parameters with a multi-megabyte note. The transport-frame caps
/// (1 MiB over WS, 100 MiB over REST) are defensive for transport and are
/// unrelated to what the data model should accept.
pub const MAX_AGENT_NOTE_LEN: usize = 4 * 1024;

/// Agent pivot metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPivotsInfo {
    /// Parent agent id, if present.
    #[serde(rename = "Parent", default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Child pivot links.
    #[serde(rename = "Links", default)]
    pub links: Vec<String>,
}

/// New agent/session payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    #[serde(rename = "Active")]
    pub active: String,
    #[serde(rename = "BackgroundCheck")]
    pub background_check: bool,
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "Elevated")]
    pub elevated: bool,
    #[serde(rename = "InternalIP")]
    pub internal_ip: String,
    #[serde(rename = "ExternalIP")]
    pub external_ip: String,
    #[serde(rename = "FirstCallIn")]
    pub first_call_in: String,
    #[serde(rename = "LastCallIn")]
    pub last_call_in: String,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "Listener")]
    pub listener: String,
    #[serde(rename = "MagicValue")]
    pub magic_value: String,
    #[serde(rename = "NameID")]
    pub name_id: String,
    #[serde(rename = "OSArch")]
    pub os_arch: String,
    #[serde(rename = "OSBuild")]
    pub os_build: String,
    #[serde(rename = "OSVersion")]
    pub os_version: String,
    #[serde(rename = "Pivots")]
    pub pivots: AgentPivotsInfo,
    #[serde(rename = "PortFwds", default)]
    pub port_fwds: Vec<String>,
    #[serde(rename = "ProcessArch")]
    pub process_arch: String,
    #[serde(rename = "ProcessName")]
    pub process_name: String,
    #[serde(rename = "ProcessPID")]
    pub process_pid: String,
    #[serde(rename = "ProcessPPID")]
    pub process_ppid: String,
    #[serde(rename = "ProcessPath")]
    pub process_path: String,
    #[serde(rename = "Reason")]
    pub reason: String,
    #[serde(rename = "Note", default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(rename = "SleepDelay")]
    pub sleep_delay: Value,
    #[serde(rename = "SleepJitter")]
    pub sleep_jitter: Value,
    #[serde(rename = "KillDate")]
    pub kill_date: Value,
    #[serde(rename = "WorkingHours")]
    pub working_hours: Value,
    #[serde(rename = "SocksCli", default)]
    pub socks_cli: Vec<String>,
    #[serde(rename = "SocksCliMtx", default, skip_serializing_if = "Option::is_none")]
    pub socks_cli_mtx: Option<Value>,
    #[serde(rename = "SocksSvr", default)]
    pub socks_svr: Vec<String>,
    #[serde(rename = "TaskedOnce")]
    pub tasked_once: bool,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "PivotParent")]
    pub pivot_parent: String,
}

/// Agent task request payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AgentTaskInfo {
    #[serde(rename = "TaskID")]
    pub task_id: String,
    #[serde(rename = "CommandLine")]
    pub command_line: String,
    #[serde(rename = "DemonID")]
    pub demon_id: String,
    #[serde(rename = "CommandID")]
    pub command_id: String,
    #[serde(rename = "AgentType", default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    #[serde(rename = "TaskMessage", default, skip_serializing_if = "Option::is_none")]
    pub task_message: Option<String>,
    #[serde(rename = "Command", default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(rename = "SubCommand", default, skip_serializing_if = "Option::is_none")]
    pub sub_command: Option<String>,
    #[serde(rename = "Arguments", default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Agent output payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentResponseInfo {
    /// Target agent id.
    #[serde(rename = "DemonID")]
    pub demon_id: String,
    /// Command id or callback id.
    #[serde(rename = "CommandID")]
    pub command_id: String,
    /// Base64-encoded or raw output blob.
    #[serde(rename = "Output")]
    pub output: String,
    #[serde(rename = "CommandLine", default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Agent update payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentUpdateInfo {
    /// Target agent id.
    #[serde(rename = "AgentID")]
    pub agent_id: String,
    /// Update marker, usually `Alive` or `Dead`.
    #[serde(rename = "Marked")]
    pub marked: String,
}
