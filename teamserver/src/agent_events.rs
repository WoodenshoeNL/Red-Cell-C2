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
        os_build: agent.os_build.to_string(),
        os_version: agent.os_version.clone(),
        pivots: AgentPivotsInfo { parent: parent.clone(), links },
        port_fwds: Vec::new(),
        process_arch: agent.process_arch.clone(),
        process_name: agent.process_name.clone(),
        process_pid: agent.process_pid.to_string(),
        process_ppid: agent.process_ppid.to_string(),
        process_path: agent.process_path.clone(),
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
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 22000,
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
    fn operator_agent_info_with_inactive_agent_serializes_active_field_as_false() {
        let mut agent = sample_agent(0x1112_1314);
        agent.active = false;
        let pivots = PivotInfo { parent: None, children: vec![] };

        let info = operator_agent_info("http", 0xDEAD_BEEF, &agent, &pivots);

        assert_eq!(info.active, "false");
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

    #[test]
    fn operator_agent_info_os_build_is_populated_from_agent_record() {
        let mut agent = sample_agent(0x1112_1314);
        agent.os_build = 22000;
        let pivots = PivotInfo { parent: None, children: vec![] };

        let info = operator_agent_info("http", 0xDEAD_BEEF, &agent, &pivots);

        assert_eq!(info.os_build, "22000", "os_build must be the build number string");
    }

    #[test]
    fn operator_agent_info_os_build_zero_serializes_as_zero_string() {
        let mut agent = sample_agent(0x1112_1314);
        agent.os_build = 0;
        let pivots = PivotInfo { parent: None, children: vec![] };

        let info = operator_agent_info("http", 0xDEAD_BEEF, &agent, &pivots);

        assert_eq!(info.os_build, "0");
    }

    #[test]
    fn operator_agent_info_process_path_differs_from_process_name() {
        let agent = sample_agent(0x1112_1314);
        let pivots = PivotInfo { parent: None, children: vec![] };

        let info = operator_agent_info("http", 0xDEAD_BEEF, &agent, &pivots);

        assert_eq!(info.process_name, "explorer.exe");
        assert_eq!(info.process_path, "C:\\Windows\\explorer.exe");
        assert_ne!(
            info.process_path, info.process_name,
            "process_path must be the full path, not the basename"
        );
    }

    /// Verify that the serialized JSON field names match the Havoc wire protocol.
    ///
    /// A `#[serde(rename = "...")]` change or field rename in `AgentInfo` would
    /// silently break Havoc client compatibility — all Rust-level assertions would
    /// still pass but the operator client would receive unknown keys.
    #[test]
    fn operator_agent_info_serialized_json_keys_match_havoc_wire_protocol() {
        let agent = sample_agent(0x1112_1314);
        let pivots =
            PivotInfo { parent: Some(0x0102_0304), children: vec![0x2122_2324, 0x3132_3334] };

        let info = operator_agent_info("http-main", 0xDEAD_BEEF, &agent, &pivots);
        let json = serde_json::to_value(&info).expect("AgentInfo must serialize to JSON");
        let obj = json.as_object().expect("serialized AgentInfo must be a JSON object");

        // Assert every Havoc-expected key is present with the correct value.
        assert_eq!(obj["NameID"], "11121314");
        assert_eq!(obj["MagicValue"], "deadbeef");
        assert_eq!(obj["Active"], "true");
        assert_eq!(obj["Listener"], "http-main");

        // Identity / host fields
        assert_eq!(obj["Hostname"], "wkstn-01");
        assert_eq!(obj["Username"], "operator");
        assert_eq!(obj["DomainName"], "REDCELL");
        assert_eq!(obj["ExternalIP"], "203.0.113.10");
        assert_eq!(obj["InternalIP"], "10.0.0.25");

        // Process fields
        assert_eq!(obj["ProcessName"], "explorer.exe");
        assert_eq!(obj["ProcessPath"], "C:\\Windows\\explorer.exe");
        assert_eq!(obj["ProcessPID"], "1337");
        assert_eq!(obj["ProcessPPID"], "512");
        assert_eq!(obj["ProcessArch"], "x64");

        // OS fields
        assert_eq!(obj["OSVersion"], "Windows 11");
        assert_eq!(obj["OSBuild"], "22000");
        assert_eq!(obj["OSArch"], "x64");

        // Timing / sleep fields
        assert_eq!(obj["SleepDelay"], 15);
        assert_eq!(obj["SleepJitter"], 20);
        assert_eq!(obj["FirstCallIn"], "2026-03-09T18:45:00Z");
        assert_eq!(obj["LastCallIn"], "2026-03-09T18:46:00Z");
        assert_eq!(obj["KillDate"], 1_893_456_000);
        assert_eq!(obj["WorkingHours"], 0b101010);

        // Pivot fields
        assert_eq!(obj["PivotParent"], "01020304");
        let pivots_obj = obj["Pivots"].as_object().expect("Pivots must be a JSON object");
        assert_eq!(pivots_obj["Parent"], "01020304");
        assert_eq!(pivots_obj["Links"], serde_json::json!(["21222324", "31323334"]));

        // Boolean / state fields
        assert_eq!(obj["BackgroundCheck"], false);
        assert_eq!(obj["TaskedOnce"], false);
        assert_eq!(obj["Elevated"], true);

        // Collection fields
        assert_eq!(obj["PortFwds"], serde_json::json!([]));
        assert_eq!(obj["SocksCli"], serde_json::json!([]));
        assert_eq!(obj["SocksSvr"], serde_json::json!([]));

        // Verify no unexpected keys are present — the full set of required keys.
        let expected_keys: std::collections::BTreeSet<&str> = [
            "Active",
            "BackgroundCheck",
            "DomainName",
            "Elevated",
            "InternalIP",
            "ExternalIP",
            "FirstCallIn",
            "LastCallIn",
            "Hostname",
            "Listener",
            "MagicValue",
            "NameID",
            "OSArch",
            "OSBuild",
            "OSVersion",
            "Pivots",
            "PortFwds",
            "ProcessArch",
            "ProcessName",
            "ProcessPID",
            "ProcessPPID",
            "ProcessPath",
            "Reason",
            "SleepDelay",
            "SleepJitter",
            "KillDate",
            "WorkingHours",
            "SocksCli",
            "SocksSvr",
            "TaskedOnce",
            "Username",
            "PivotParent",
        ]
        .iter()
        .copied()
        .collect();

        let actual_keys: std::collections::BTreeSet<&str> =
            obj.keys().map(String::as_str).collect();

        assert_eq!(
            expected_keys, actual_keys,
            "serialized AgentInfo keys must exactly match the Havoc wire protocol"
        );
    }

    #[test]
    fn agent_new_event_message_head_has_session_event_teamserver_user_and_one_time_true() {
        let agent = sample_agent(0x1112_1314);
        let pivots = PivotInfo { parent: None, children: vec![] };

        let event = agent_new_event("http", 0xDEAD_BEEF, &agent, &pivots);

        let OperatorMessage::AgentNew(message) = event else {
            panic!("expected AgentNew event");
        };
        assert_eq!(
            message.head.event,
            red_cell_common::operator::EventCode::Session,
            "agent_new_event must use EventCode::Session"
        );
        assert_eq!(
            message.head.user, "teamserver",
            "agent_new_event must set user to 'teamserver'"
        );
        assert_eq!(message.head.one_time, "true", "agent_new_event must set one_time to 'true'");
        assert_eq!(message.head.timestamp, agent.last_call_in);
    }

    #[test]
    fn agent_mark_event_message_head_has_session_event_teamserver_user_and_empty_one_time() {
        let agent = sample_agent(0x1112_1314);

        let event = agent_mark_event(&agent);

        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("expected AgentUpdate event");
        };
        assert_eq!(
            message.head.event,
            red_cell_common::operator::EventCode::Session,
            "agent_mark_event must use EventCode::Session"
        );
        assert_eq!(
            message.head.user, "teamserver",
            "agent_mark_event must set user to 'teamserver'"
        );
        assert!(
            message.head.one_time.is_empty(),
            "agent_mark_event must leave one_time empty, got: {:?}",
            message.head.one_time
        );
        assert_eq!(message.head.timestamp, agent.last_call_in);
    }

    #[test]
    fn agent_new_event_includes_kill_date_and_working_hours_when_present() {
        let agent = sample_agent(0x1112_1314);
        let pivots = PivotInfo { parent: None, children: vec![] };

        let event = agent_new_event("http", 0xDEAD_BEEF, &agent, &pivots);

        let OperatorMessage::AgentNew(message) = event else {
            panic!("expected AgentNew event");
        };
        assert_eq!(
            message.info.kill_date,
            serde_json::Value::from(1_893_456_000_i64),
            "kill_date must be present when agent has a kill_date"
        );
        assert_eq!(
            message.info.working_hours,
            serde_json::Value::from(0b101010),
            "working_hours must be present when agent has working_hours"
        );
    }

    #[test]
    fn agent_new_event_emits_null_kill_date_and_working_hours_when_absent() {
        let mut agent = sample_agent(0x1112_1314);
        agent.kill_date = None;
        agent.working_hours = None;
        let pivots = PivotInfo { parent: None, children: vec![] };

        let event = agent_new_event("http", 0xDEAD_BEEF, &agent, &pivots);

        let OperatorMessage::AgentNew(message) = event else {
            panic!("expected AgentNew event");
        };
        assert_eq!(
            message.info.kill_date,
            serde_json::Value::Null,
            "kill_date must be null when agent has no kill_date"
        );
        assert_eq!(
            message.info.working_hours,
            serde_json::Value::Null,
            "working_hours must be null when agent has no working_hours"
        );
    }

    /// When `note` is non-empty, the `Note` key must appear in the serialized JSON.
    /// When `SocksCliMtx` is `Some`, it must also appear. These fields use
    /// `skip_serializing_if` and could silently vanish if the condition is wrong.
    #[test]
    fn operator_agent_info_conditional_fields_appear_when_populated() {
        let mut agent = sample_agent(0x1112_1314);
        agent.note = "high-value target".to_owned();
        let pivots = PivotInfo { parent: None, children: vec![] };

        let mut info = operator_agent_info("http", 0xDEAD_BEEF, &agent, &pivots);
        info.socks_cli_mtx = Some(serde_json::Value::String("mutex-1".to_owned()));

        let json = serde_json::to_value(&info).expect("AgentInfo must serialize to JSON");
        let obj = json.as_object().expect("serialized AgentInfo must be a JSON object");

        assert_eq!(obj["Note"], "high-value target", "Note must appear when non-empty");
        assert_eq!(obj["SocksCliMtx"], "mutex-1", "SocksCliMtx must appear when Some");
    }

    /// Verify that `AgentUpdateInfo` serialized JSON keys match the Havoc wire protocol.
    ///
    /// Mirrors `operator_agent_info_serialized_json_keys_match_havoc_wire_protocol` but
    /// for the `agent_mark_event` path.  A `#[serde(rename = "...")]` change on
    /// `AgentUpdateInfo` would break the Havoc operator client silently.
    #[test]
    fn agent_update_info_serialized_json_keys_match_havoc_wire_protocol() {
        let agent = sample_agent(0x1112_1314);

        let event = agent_mark_event(&agent);

        let OperatorMessage::AgentUpdate(message) = event else {
            panic!("expected AgentUpdate event");
        };

        let json =
            serde_json::to_value(&message.info).expect("AgentUpdateInfo must serialize to JSON");
        let obj = json.as_object().expect("serialized AgentUpdateInfo must be a JSON object");

        // Assert every Havoc-expected key is present with the correct wire name and value.
        assert_eq!(obj["AgentID"], "11121314", "wire key must be 'AgentID', not 'agent_id'");
        assert_eq!(obj["Marked"], "Alive", "wire key must be 'Marked', not 'marked'");

        // Verify no unexpected keys are present — the full set of required keys.
        let expected_keys: std::collections::BTreeSet<&str> =
            ["AgentID", "Marked"].iter().copied().collect();

        let actual_keys: std::collections::BTreeSet<&str> =
            obj.keys().map(String::as_str).collect();

        assert_eq!(
            expected_keys, actual_keys,
            "serialized AgentUpdateInfo keys must exactly match the Havoc wire protocol"
        );
    }

    #[test]
    fn operator_agent_info_none_kill_date_and_working_hours_emit_null() {
        let mut agent = sample_agent(0x1112_1314);
        agent.kill_date = None;
        agent.working_hours = None;
        let pivots = PivotInfo { parent: None, children: vec![] };

        let info = operator_agent_info("http", 0xDEAD_BEEF, &agent, &pivots);

        assert_eq!(
            info.kill_date,
            serde_json::Value::Null,
            "kill_date must be Value::Null when None"
        );
        assert_eq!(
            info.working_hours,
            serde_json::Value::Null,
            "working_hours must be Value::Null when None"
        );
    }
}
