//! Agent session messages (`Agent*`, `Session` wire family).

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::test_support::head;
    use super::super::{
        AgentInfo, AgentResponseInfo, AgentTaskInfo, EventCode, Message, MessageHead,
        OperatorMessage, SessionCode,
    };
    use crate::operator::agents::AgentPivotsInfo;
    use serde_json::{Value, json};

    #[test]
    fn agent_task_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::AgentTask(Message {
            head: head(EventCode::Session),
            info: AgentTaskInfo {
                task_id: "task-1".to_string(),
                command_line: "sleep 5".to_string(),
                demon_id: "ABCD1234".to_string(),
                command_id: "11".to_string(),
                arguments: Some("5".to_string()),
                extra: BTreeMap::from([(String::from("FromProcessManager"), json!("false"))]),
                ..AgentTaskInfo::default()
            },
        });

        let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn agent_new_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::AgentNew(Box::new(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: String::new(),
                timestamp: "09/03/2026 19:05:00".to_string(),
                one_time: "true".to_string(),
            },
            info: AgentInfo {
                active: "true".to_string(),
                background_check: false,
                domain_name: "LAB".to_string(),
                elevated: true,
                internal_ip: "10.0.0.10".to_string(),
                external_ip: "203.0.113.10".to_string(),
                first_call_in: "09/03/2026 19:04:00".to_string(),
                last_call_in: "09/03/2026 19:05:00".to_string(),
                hostname: "wkstn-1".to_string(),
                listener: "null".to_string(),
                magic_value: "deadbeef".to_string(),
                name_id: "ABCD1234".to_string(),
                os_arch: "x64".to_string(),
                os_build: "19045".to_string(),
                os_version: "Windows 10".to_string(),
                pivots: AgentPivotsInfo { parent: None, links: Vec::new() },
                port_fwds: Vec::new(),
                process_arch: "x64".to_string(),
                process_name: "explorer.exe".to_string(),
                process_pid: "1234".to_string(),
                process_ppid: "1000".to_string(),
                process_path: "C:\\Windows\\explorer.exe".to_string(),
                reason: "manual".to_string(),
                note: "vpn foothold".to_string(),
                sleep_delay: json!(5),
                sleep_jitter: json!(10),
                kill_date: Value::Null,
                working_hours: Value::Null,
                socks_cli: Vec::new(),
                socks_cli_mtx: None,
                socks_svr: Vec::new(),
                tasked_once: false,
                username: "operator".to_string(),
                pivot_parent: String::new(),
            },
        }));

        let encoded = serde_json::to_value(&message)?;
        assert!(encoded.pointer("/Body/Info/Encryption").is_none());

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn agent_reregistered_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::AgentReregistered(Box::new(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: String::new(),
                timestamp: "09/03/2026 19:05:00".to_string(),
                one_time: "true".to_string(),
            },
            info: AgentInfo {
                active: "true".to_string(),
                background_check: false,
                domain_name: "LAB".to_string(),
                elevated: true,
                internal_ip: "10.0.0.10".to_string(),
                external_ip: "203.0.113.10".to_string(),
                first_call_in: "09/03/2026 19:04:00".to_string(),
                last_call_in: "09/03/2026 19:05:00".to_string(),
                hostname: "wkstn-1".to_string(),
                listener: "null".to_string(),
                magic_value: "deadbeef".to_string(),
                name_id: "ABCD1234".to_string(),
                os_arch: "x64".to_string(),
                os_build: "19045".to_string(),
                os_version: "Windows 10".to_string(),
                pivots: AgentPivotsInfo { parent: None, links: Vec::new() },
                port_fwds: Vec::new(),
                process_arch: "x64".to_string(),
                process_name: "explorer.exe".to_string(),
                process_pid: "1234".to_string(),
                process_ppid: "1000".to_string(),
                process_path: "C:\\Windows\\explorer.exe".to_string(),
                reason: "manual".to_string(),
                note: String::new(),
                sleep_delay: json!(5),
                sleep_jitter: json!(10),
                kill_date: Value::Null,
                working_hours: Value::Null,
                socks_cli: Vec::new(),
                socks_cli_mtx: None,
                socks_svr: Vec::new(),
                tasked_once: false,
                username: "operator".to_string(),
                pivot_parent: String::new(),
            },
        }));

        let encoded = serde_json::to_value(&message)?;
        let sub_event = encoded.pointer("/Body/SubEvent").and_then(|v| v.as_u64());
        assert_eq!(
            sub_event,
            Some(SessionCode::AgentReregistered.as_u32() as u64),
            "AgentReregistered must serialize with SubEvent 0x6"
        );

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    /// An `AgentNew` message whose `Info` object is completely empty must fail
    /// deserialization — all non-`#[serde(default)]` fields are required.
    #[test]
    fn agent_info_empty_info_object_fails_deserialization() {
        let value = json!({
            "Head": { "Event": 7, "Time": "09/03/2026 19:05:00" },
            "Body": { "SubEvent": 1, "Info": {} }
        });

        serde_json::from_value::<OperatorMessage>(value)
            .expect_err("empty Info object must fail: all AgentInfo fields are required");
    }

    /// `SleepDelay: null` and `KillDate: null` (both `serde_json::Value`) must
    /// survive a serialize → deserialize round-trip as `Value::Null`.
    #[test]
    fn agent_info_null_value_fields_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::AgentNew(Box::new(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: String::new(),
                timestamp: "09/03/2026 19:05:00".to_string(),
                one_time: "true".to_string(),
            },
            info: AgentInfo {
                active: "true".to_string(),
                background_check: false,
                domain_name: "LAB".to_string(),
                elevated: false,
                internal_ip: "10.0.0.1".to_string(),
                external_ip: "203.0.113.1".to_string(),
                first_call_in: "09/03/2026 19:04:00".to_string(),
                last_call_in: "09/03/2026 19:05:00".to_string(),
                hostname: "host".to_string(),
                listener: "http".to_string(),
                magic_value: "deadbeef".to_string(),
                name_id: "ABCD1234".to_string(),
                os_arch: "x64".to_string(),
                os_build: "19045".to_string(),
                os_version: "Windows 10".to_string(),
                pivots: AgentPivotsInfo { parent: None, links: Vec::new() },
                port_fwds: Vec::new(),
                process_arch: "x64".to_string(),
                process_name: "explorer.exe".to_string(),
                process_pid: "1234".to_string(),
                process_ppid: "1000".to_string(),
                process_path: "C:\\Windows\\explorer.exe".to_string(),
                reason: String::new(),
                note: String::new(),
                sleep_delay: Value::Null,
                sleep_jitter: Value::Null,
                kill_date: Value::Null,
                working_hours: Value::Null,
                socks_cli: Vec::new(),
                socks_cli_mtx: None,
                socks_svr: Vec::new(),
                tasked_once: false,
                username: "operator".to_string(),
                pivot_parent: String::new(),
            },
        }));

        let encoded = serde_json::to_value(&message)?;

        // All four Value::Null fields must appear as JSON null on the wire.
        assert_eq!(encoded.pointer("/Body/Info/SleepDelay"), Some(&Value::Null));
        assert_eq!(encoded.pointer("/Body/Info/SleepJitter"), Some(&Value::Null));
        assert_eq!(encoded.pointer("/Body/Info/KillDate"), Some(&Value::Null));
        assert_eq!(encoded.pointer("/Body/Info/WorkingHours"), Some(&Value::Null));

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    /// A minimal `AgentNew` JSON message that omits every `#[serde(default)]`
    /// field must deserialize successfully, with all omitted fields receiving
    /// their default values.
    #[test]
    fn agent_info_minimal_fields_defaults_optional() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 7, "Time": "09/03/2026 19:05:00" },
            "Body": {
                "SubEvent": 1,
                "Info": {
                    "Active": "",
                    "BackgroundCheck": false,
                    "DomainName": "",
                    "Elevated": false,
                    "InternalIP": "",
                    "ExternalIP": "",
                    "FirstCallIn": "",
                    "LastCallIn": "",
                    "Hostname": "",
                    "Listener": "",
                    "MagicValue": "",
                    "NameID": "",
                    "OSArch": "",
                    "OSBuild": "",
                    "OSVersion": "",
                    "Pivots": {},
                    "ProcessArch": "",
                    "ProcessName": "",
                    "ProcessPID": "",
                    "ProcessPPID": "",
                    "ProcessPath": "",
                    "Reason": "",
                    "SleepDelay": null,
                    "SleepJitter": null,
                    "KillDate": null,
                    "WorkingHours": null,
                    "TaskedOnce": false,
                    "Username": "",
                    "PivotParent": ""
                    // PortFwds, Note, SocksCli, SocksCliMtx, SocksSvr are intentionally absent.
                }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        let OperatorMessage::AgentNew(msg) = decoded else {
            panic!("expected AgentNew variant");
        };

        // Fields absent from the JSON must have their serde default values.
        assert_eq!(msg.info.port_fwds, Vec::<String>::new(), "PortFwds must default to []");
        assert_eq!(msg.info.note, "", "Note must default to empty string");
        assert_eq!(msg.info.socks_cli, Vec::<String>::new(), "SocksCli must default to []");
        assert_eq!(msg.info.socks_cli_mtx, None, "SocksCliMtx must default to None");
        assert_eq!(msg.info.socks_svr, Vec::<String>::new(), "SocksSvr must default to []");

        // Required fields must match exactly what was sent.
        assert_eq!(msg.info.active, "");
        assert_eq!(msg.info.magic_value, "");
        assert_eq!(msg.info.sleep_delay, Value::Null);
        assert_eq!(msg.info.kill_date, Value::Null);
        Ok(())
    }

    /// Verify that `AgentResponseInfo` with `command_line: None` omits the
    /// `CommandLine` key entirely (via `skip_serializing_if`) and round-trips
    /// correctly.
    #[test]
    fn agent_response_info_none_command_line_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let info = AgentResponseInfo {
            demon_id: "DEAD0001".to_string(),
            command_id: "10".to_string(),
            output: "data".to_string(),
            command_line: None,
            extra: BTreeMap::new(),
        };

        let json = serde_json::to_value(&info)?;
        let obj = json.as_object().expect("must be an object");

        // The key must be absent, not present-as-null.
        assert!(
            !obj.contains_key("CommandLine"),
            "CommandLine key must be omitted when command_line is None, got: {json}"
        );

        // Round-trip: deserializing back must yield the same value.
        let deserialized: AgentResponseInfo = serde_json::from_value(json)?;
        assert_eq!(deserialized.command_line, None);
        assert_eq!(deserialized, info);

        Ok(())
    }

    #[test]
    fn remaining_typed_agent_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [OperatorMessage::AgentResponse(Message {
            head: head(EventCode::Session),
            info: AgentResponseInfo {
                demon_id: "ABCD1234".to_string(),
                command_id: "94".to_string(),
                output: "hello".to_string(),
                command_line: Some("whoami".to_string()),
                extra: BTreeMap::from([(String::from("Type"), json!("stdout"))]),
            },
        })];

        for message in cases {
            let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
            assert_eq!(decoded, message);
        }

        Ok(())
    }
}
