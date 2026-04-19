//! Chat, gate (payload builder), host file, service, and teamserver messages.

#[cfg(test)]
mod tests {
    use super::super::test_support::head;
    use super::super::{
        BuildPayloadMessageInfo, BuildPayloadRequestInfo, BuildPayloadResponseInfo, ChatUserInfo,
        EventCode, Message, MessageHead, OperatorMessage, ServiceAgentRegistrationInfo,
        TeamserverLogInfo,
    };
    use base64::Engine as _;
    use serde_json::json;

    #[test]
    fn build_payload_variants_deserialize_by_shape() -> Result<(), Box<dyn std::error::Error>> {
        let request = json!({
            "Head": { "Event": 5, "User": "operator", "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "AgentType": "Demon",
                    "Listener": "http",
                    "Arch": "x64",
                    "Format": "Windows Exe",
                    "Config": "{\"Sleep\":5}"
                }
            }
        });
        let response = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "PayloadArray": "QUJD",
                    "Format": "Windows Exe",
                    "FileName": "payload.exe"
                }
            }
        });

        assert!(matches!(
            serde_json::from_value::<OperatorMessage>(request)?,
            OperatorMessage::BuildPayloadRequest(_)
        ));
        assert!(matches!(
            serde_json::from_value::<OperatorMessage>(response)?,
            OperatorMessage::BuildPayloadResponse(_)
        ));
        Ok(())
    }

    #[test]
    fn build_payload_request_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::BuildPayloadRequest(Message {
            head: MessageHead {
                event: EventCode::Gate,
                user: "operator".to_string(),
                timestamp: "09/03/2026 19:00:00".to_string(),
                one_time: String::new(),
            },
            info: BuildPayloadRequestInfo {
                agent_type: "Demon".to_string(),
                listener: "http-listener".to_string(),
                arch: "x64".to_string(),
                format: "Windows Exe".to_string(),
                config: r#"{"Sleep":5,"Jitter":10}"#.to_string(),
            },
        });

        let encoded = serde_json::to_value(&message)?;

        // All renamed fields must survive serialization.
        assert_eq!(encoded.pointer("/Body/Info/AgentType"), Some(&json!("Demon")));
        assert_eq!(encoded.pointer("/Body/Info/Listener"), Some(&json!("http-listener")));
        assert_eq!(encoded.pointer("/Body/Info/Arch"), Some(&json!("x64")));
        assert_eq!(encoded.pointer("/Body/Info/Format"), Some(&json!("Windows Exe")));
        assert_eq!(
            encoded.pointer("/Body/Info/Config"),
            Some(&json!(r#"{"Sleep":5,"Jitter":10}"#))
        );

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn build_payload_response_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let payload_bytes = b"binary payload data";
        let encoded_payload = base64::engine::general_purpose::STANDARD.encode(payload_bytes);

        let message = OperatorMessage::BuildPayloadResponse(Message {
            head: MessageHead {
                event: EventCode::Gate,
                user: String::new(),
                timestamp: "09/03/2026 19:00:00".to_string(),
                one_time: String::new(),
            },
            info: BuildPayloadResponseInfo {
                payload_array: encoded_payload.clone(),
                format: "Windows Exe".to_string(),
                file_name: "demon.exe".to_string(),
                export_name: None,
            },
        });

        let encoded = serde_json::to_value(&message)?;

        // All renamed fields must survive serialization.
        assert_eq!(encoded.pointer("/Body/Info/PayloadArray"), Some(&json!(encoded_payload)));
        assert_eq!(encoded.pointer("/Body/Info/Format"), Some(&json!("Windows Exe")));
        assert_eq!(encoded.pointer("/Body/Info/FileName"), Some(&json!("demon.exe")));

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn build_payload_response_partial_fields() -> Result<(), Box<dyn std::error::Error>> {
        // All three fields are required; a message with only them (no extras) must decode cleanly.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "PayloadArray": "QUJD",
                    "Format": "shellcode",
                    "FileName": "payload.bin"
                }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        let OperatorMessage::BuildPayloadResponse(msg) = decoded else {
            panic!("expected BuildPayloadResponse");
        };
        assert_eq!(msg.info.payload_array, "QUJD");
        assert_eq!(msg.info.format, "shellcode");
        assert_eq!(msg.info.file_name, "payload.bin");
        Ok(())
    }

    #[test]
    fn build_payload_missing_request_fields_falls_through_to_message()
    -> Result<(), Box<dyn std::error::Error>> {
        // Info has neither request nor response fields — should fall through
        // to BuildPayloadMessage.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "MessageType": "Info",
                    "Message": "building payload..."
                }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert!(
            matches!(decoded, OperatorMessage::BuildPayloadMessage(_)),
            "payload with only message fields should decode as BuildPayloadMessage, got {decoded:?}"
        );
        Ok(())
    }

    #[test]
    fn build_payload_wrong_type_in_response_fields_rejects_cleanly() {
        // PayloadArray is a number instead of string — response parsing fails,
        // request parsing fails (missing required fields), and fallback message
        // parsing also fails (missing MessageType/Message). The entire
        // deserialization must fail rather than silently accepting the wrong variant.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "PayloadArray": 12345,
                    "Format": "shellcode",
                    "FileName": "payload.bin"
                }
            }
        });

        let result = serde_json::from_value::<OperatorMessage>(value);
        assert!(
            result.is_err(),
            "wrong-typed fields matching no variant must fail deserialization"
        );
    }

    #[test]
    fn build_payload_empty_info_rejects_cleanly() {
        // Empty Info object — neither request, response, nor message fields present.
        // All three try-parses fail, returning a clean deserialization error.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {}
            }
        });

        let result = serde_json::from_value::<OperatorMessage>(value);
        assert!(
            result.is_err(),
            "empty Info matching no BuildPayload variant must fail deserialization"
        );
    }

    #[test]
    fn build_payload_request_rejects_wrong_type_for_required_field() {
        // AgentType as a number instead of string — should fail direct deserialization.
        let value = json!({
            "AgentType": 42,
            "Listener": "http",
            "Arch": "x64",
            "Format": "Windows Exe",
            "Config": "{}"
        });

        let result = serde_json::from_value::<BuildPayloadRequestInfo>(value);
        assert!(result.is_err(), "BuildPayloadRequestInfo must reject non-string AgentType");
    }

    #[test]
    fn build_payload_response_rejects_missing_required_field() {
        // Missing FileName — should fail deserialization.
        let value = json!({
            "PayloadArray": "QUJD",
            "Format": "shellcode"
        });

        let result = serde_json::from_value::<BuildPayloadResponseInfo>(value);
        assert!(result.is_err(), "BuildPayloadResponseInfo must reject missing FileName");
    }

    #[test]
    fn accepts_legacy_teamserver_profile_shape() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 16, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 1,
                "Info": { "profile": "profile-data" }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert!(matches!(decoded, OperatorMessage::TeamserverProfile(_)));
        Ok(())
    }

    #[test]
    fn accepts_timestamp_alias() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 4, "User": "operator", "Timestamp": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 4,
                "Info": { "User": "alice" }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert!(matches!(decoded, OperatorMessage::ChatUserConnected(_)));
        Ok(())
    }

    #[test]
    fn remaining_typed_non_agent_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            OperatorMessage::ChatUserDisconnected(Message {
                head: head(EventCode::Chat),
                info: ChatUserInfo { user: "alice".to_string() },
            }),
            OperatorMessage::BuildPayloadMessage(Message {
                head: head(EventCode::Gate),
                info: BuildPayloadMessageInfo {
                    message_type: "Info".to_string(),
                    message: "staging".to_string(),
                },
            }),
            OperatorMessage::ServiceAgentRegister(Message {
                head: head(EventCode::Service),
                info: ServiceAgentRegistrationInfo { agent: "{}".to_string() },
            }),
            OperatorMessage::TeamserverLog(Message {
                head: head(EventCode::Teamserver),
                info: TeamserverLogInfo { text: "started".to_string() },
            }),
        ];

        for message in cases {
            let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
            assert_eq!(decoded, message);
        }

        Ok(())
    }
}
