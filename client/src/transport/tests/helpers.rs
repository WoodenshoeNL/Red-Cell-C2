use red_cell_common::operator::{
    AgentInfo as OperatorAgentInfo, AgentPivotsInfo, EventCode, FlatInfo, MessageHead,
};
use serde_json::Value;

/// Test fixture: minimal [`MessageHead`] for operator messages.
pub fn head(event: EventCode) -> MessageHead {
    MessageHead {
        event,
        user: "operator".to_owned(),
        timestamp: "10/03/2026 12:00:00".to_owned(),
        one_time: String::new(),
    }
}

/// Test fixture: [`FlatInfo`] from string key/value pairs.
pub fn flat_info(pairs: &[(&str, &str)]) -> FlatInfo {
    FlatInfo {
        fields: pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Value::String((*v).to_owned())))
            .collect(),
    }
}

/// Test fixture: [`FlatInfo`] with arbitrary JSON values per field.
pub fn make_flat_info(pairs: &[(&str, serde_json::Value)]) -> FlatInfo {
    let fields = pairs.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
    FlatInfo { fields }
}

/// Test fixture: [`OperatorAgentInfo`] with `hostname`, using sensible defaults for other fields.
pub fn make_agent_info(name_id: &str, hostname: &str) -> OperatorAgentInfo {
    OperatorAgentInfo {
        active: "true".to_owned(),
        background_check: false,
        domain_name: "LAB".to_owned(),
        elevated: false,
        internal_ip: "10.0.0.10".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        first_call_in: "10/03/2026 11:59:00".to_owned(),
        last_call_in: "10/03/2026 12:00:00".to_owned(),
        hostname: hostname.to_owned(),
        listener: "http".to_owned(),
        magic_value: "deadbeef".to_owned(),
        name_id: name_id.to_owned(),
        os_arch: "x64".to_owned(),
        os_build: "19045".to_owned(),
        os_version: "Windows 11".to_owned(),
        pivots: AgentPivotsInfo::default(),
        port_fwds: Vec::new(),
        process_arch: "x64".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_pid: "1234".to_owned(),
        process_ppid: "1111".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        reason: "manual".to_owned(),
        note: String::new(),
        sleep_delay: serde_json::Value::from(5),
        sleep_jitter: serde_json::Value::from(10),
        kill_date: serde_json::Value::Null,
        working_hours: serde_json::Value::Null,
        socks_cli: Vec::new(),
        socks_cli_mtx: None,
        socks_svr: Vec::new(),
        tasked_once: false,
        username: "operator".to_owned(),
        pivot_parent: String::new(),
    }
}
