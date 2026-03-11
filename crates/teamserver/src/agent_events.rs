//! Shared builders for Havoc-compatible operator agent events.

use red_cell_common::AgentInfo;
use red_cell_common::operator::{
    AgentEncryptionInfo as OperatorAgentEncryptionInfo, AgentInfo as OperatorAgentInfo,
    AgentPivotsInfo, EventCode, Message, MessageHead, OperatorMessage,
};
use serde_json::Value;

use crate::PivotInfo;

pub(crate) fn agent_new_event(
    listener_name: &str,
    magic_value: u32,
    agent: &AgentInfo,
    pivots: &PivotInfo,
) -> OperatorMessage {
    OperatorMessage::AgentNew(Box::new(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp: agent.last_call_in.clone(),
            one_time: "true".to_owned(),
        },
        info: operator_agent_info(listener_name, magic_value, agent, pivots),
    }))
}

pub(crate) fn operator_agent_info(
    listener_name: &str,
    magic_value: u32,
    agent: &AgentInfo,
    pivots: &PivotInfo,
) -> OperatorAgentInfo {
    let parent = pivots.parent.map(|agent_id| format!("{agent_id:08X}"));
    let links = pivots.children.iter().map(|agent_id| format!("{agent_id:08X}")).collect();

    OperatorAgentInfo {
        active: agent.active.to_string(),
        background_check: false,
        domain_name: agent.domain_name.clone(),
        elevated: agent.elevated,
        encryption: OperatorAgentEncryptionInfo {
            aes_key: agent.encryption.aes_key.clone(),
            aes_iv: agent.encryption.aes_iv.clone(),
        },
        internal_ip: agent.internal_ip.clone(),
        external_ip: agent.external_ip.clone(),
        first_call_in: agent.first_call_in.clone(),
        last_call_in: agent.last_call_in.clone(),
        hostname: agent.hostname.clone(),
        listener: listener_name.to_owned(),
        magic_value: format!("{magic_value:08x}"),
        name_id: agent.name_id(),
        os_arch: agent.os_arch.clone(),
        os_build: String::new(),
        os_version: agent.os_version.clone(),
        pivots: AgentPivotsInfo { parent: parent.clone(), links },
        port_fwds: Vec::new(),
        process_arch: agent.process_arch.clone(),
        process_name: agent.process_name.clone(),
        process_pid: agent.process_pid.to_string(),
        process_ppid: agent.process_ppid.to_string(),
        process_path: agent.process_name.clone(),
        reason: agent.reason.clone(),
        note: agent.note.clone(),
        sleep_delay: Value::from(agent.sleep_delay),
        sleep_jitter: Value::from(agent.sleep_jitter),
        kill_date: agent.kill_date.map_or(Value::Null, Value::from),
        working_hours: agent.working_hours.map_or(Value::Null, Value::from),
        socks_cli: Vec::new(),
        socks_cli_mtx: None,
        socks_svr: Vec::new(),
        tasked_once: false,
        username: agent.username.clone(),
        pivot_parent: parent.unwrap_or_default(),
    }
}
