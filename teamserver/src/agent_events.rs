//! Shared builders for Havoc-compatible operator agent events.

use red_cell_common::AgentRecord;
use red_cell_common::operator::{
    AgentInfo as OperatorAgentInfo, AgentPivotsInfo, AgentUpdateInfo, EventCode, Message,
    MessageHead, OperatorMessage,
};
use serde_json::Value;

use crate::PivotInfo;

pub(crate) fn agent_new_event(
    listener_name: &str,
    magic_value: u32,
    agent: &AgentRecord,
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

pub(crate) fn agent_mark_event(agent: &AgentRecord) -> OperatorMessage {
    let marked = if agent.active { "Alive" } else { "Dead" };
    OperatorMessage::AgentUpdate(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp: agent.last_call_in.clone(),
            one_time: String::new(),
        },
        info: AgentUpdateInfo { agent_id: agent.name_id(), marked: marked.to_owned() },
    })
}

pub(crate) fn operator_agent_info(
    listener_name: &str,
    magic_value: u32,
    agent: &AgentRecord,
    pivots: &PivotInfo,
) -> OperatorAgentInfo {
    let parent = pivots.parent.map(|agent_id| format!("{agent_id:08X}"));
    let links = pivots.children.iter().map(|agent_id| format!("{agent_id:08X}")).collect();

    OperatorAgentInfo {
        active: agent.active.to_string(),
        background_check: false,
        domain_name: agent.domain_name.clone(),
        elevated: agent.elevated,
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

#[cfg(test)]
mod tests {
    use super::{agent_mark_event, agent_new_event, operator_agent_info};
    use crate::PivotInfo;
    use red_cell_common::operator::OperatorMessage;
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use zeroize::Zeroizing;

    fn sample_agent(agent_id: u32) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(b"aes-key".to_vec()),
                aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 15,
            sleep_jitter: 20,
            kill_date: Some(1_893_456_000),
            working_hours: Some(0b101010),
            first_call_in: "2026-03-09T18:45:00Z".to_owned(),
            last_call_in: "2026-03-09T18:46:00Z".to_owned(),
        }
    }

    #[test]
    fn operator_agent_info_preserves_parent_and_child_pivots() {
        let agent = sample_agent(0x1112_1314);
        let pivots =
            PivotInfo { parent: Some(0x0102_0304), children: vec![0x2122_2324, 0x3132_3334] };

        let info = operator_agent_info("smb", 0xDEAD_BEEF, &agent, &pivots);

        assert_eq!(info.listener, "smb");
        assert_eq!(info.magic_value, "deadbeef");
        assert_eq!(info.pivots.parent.as_deref(), Some("01020304"));
        assert_eq!(info.pivots.links, vec!["21222324".to_owned(), "31323334".to_owned()]);
        assert_eq!(info.pivot_parent, "01020304");
    }

    #[test]
    fn operator_agent_info_with_no_parent_or_children_leaves_pivot_fields_empty() {
        let agent = sample_agent(0x1112_1314);
        let pivots = PivotInfo { parent: None, children: vec![] };

        let info = operator_agent_info("http", 0xDEAD_BEEF, &agent, &pivots);

        assert!(
            info.pivot_parent.is_empty(),
            "pivot_parent must be empty string when parent is None"
        );
        assert!(info.pivots.parent.is_none(), "pivots.parent must be None when no parent supplied");
        assert!(
            info.pivots.links.is_empty(),
            "pivots.links must be empty when no children supplied"
        );
    }

    #[test]
    fn agent_new_event_uses_shared_operator_agent_info() {
        let agent = sample_agent(0x1112_1314);
        let pivots = PivotInfo { parent: Some(0x0102_0304), children: vec![] };

        let event = agent_new_event("http-main", 0x1234_5678, &agent, &pivots);

        let OperatorMessage::AgentNew(message) = event else {
            panic!("expected AgentNew event");
        };
        assert_eq!(message.head.timestamp, agent.last_call_in);
        assert_eq!(message.info.listener, "http-main");
        assert_eq!(message.info.name_id, "11121314");
        assert_eq!(message.info.pivots.parent.as_deref(), Some("01020304"));
        assert_eq!(message.info.pivot_parent, "01020304");
    }

    #[test]
    fn agent_mark_event_uses_dead_status_for_inactive_agents() {
        let mut agent = sample_agent(0x1112_1314);
        agent.active = false;
        agent.reason = "timed out".to_owned();

        let event = agent_mark_event(&agent);

        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("expected AgentUpdate event");
        };
        assert_eq!(message.head.timestamp, agent.last_call_in);
        assert_eq!(message.info.agent_id, "11121314");
        assert_eq!(message.info.marked, "Dead");
    }

    #[test]
    fn agent_mark_event_uses_alive_status_for_active_agents() {
        let agent = sample_agent(0x1112_1314);

        let event = agent_mark_event(&agent);

        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("expected AgentUpdate event");
        };
        assert_eq!(message.head.timestamp, agent.last_call_in);
        assert_eq!(message.info.agent_id, "11121314");
        assert_eq!(message.info.marked, "Alive");
    }
}
