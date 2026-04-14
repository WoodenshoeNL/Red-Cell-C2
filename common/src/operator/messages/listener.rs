//! Listener lifecycle messages (`Listener*` variants).

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::test_support::head;
    use super::super::{
        EventCode, ListenerErrorInfo, ListenerInfo, ListenerMarkInfo, Message, NameInfo,
        OperatorMessage,
    };
    use serde_json::json;

    #[test]
    fn listener_message_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::ListenerNew(Message {
            head: head(EventCode::Listener),
            info: ListenerInfo {
                name: Some("http".to_string()),
                protocol: Some("Http".to_string()),
                status: Some("Online".to_string()),
                headers: Some("X-Test: 1".to_string()),
                host_bind: Some("0.0.0.0".to_string()),
                ..ListenerInfo::default()
            },
        });

        let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    /// Verifies that `ListenerInfo` extra fields (via `#[serde(flatten)]`) survive
    /// a JSON round-trip and appear at the top level alongside named fields.
    #[test]
    fn listener_info_extra_fields_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let info = ListenerInfo {
            name: Some("smb-pivot".to_string()),
            protocol: Some("Smb".to_string()),
            extra: BTreeMap::from([
                ("CustomField".to_string(), json!("custom_value")),
                ("PipeName".to_string(), json!("\\\\.\\pipe\\demon")),
            ]),
            ..ListenerInfo::default()
        };

        // Serialize and verify extra fields appear at the top level
        let json_value = serde_json::to_value(&info)?;
        let obj = json_value.as_object().expect("serialized ListenerInfo should be an object");
        assert_eq!(obj.get("CustomField"), Some(&json!("custom_value")));
        assert_eq!(obj.get("PipeName"), Some(&json!("\\\\.\\pipe\\demon")));
        assert_eq!(obj.get("Name"), Some(&json!("smb-pivot")));
        assert_eq!(obj.get("Protocol"), Some(&json!("Smb")));

        // Deserialize back and verify extra fields are preserved
        let decoded: ListenerInfo = serde_json::from_value(json_value)?;
        assert_eq!(decoded.name, Some("smb-pivot".to_string()));
        assert_eq!(decoded.protocol, Some("Smb".to_string()));
        assert_eq!(decoded.extra.get("CustomField"), Some(&json!("custom_value")));
        assert_eq!(decoded.extra.get("PipeName"), Some(&json!("\\\\.\\pipe\\demon")));
        // Named fields must not leak into extra
        assert!(!decoded.extra.contains_key("Name"));
        assert!(!decoded.extra.contains_key("Protocol"));

        Ok(())
    }

    #[test]
    fn remaining_typed_listener_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            OperatorMessage::ListenerRemove(Message {
                head: head(EventCode::Listener),
                info: NameInfo { name: "http".to_string() },
            }),
            OperatorMessage::ListenerError(Message {
                head: head(EventCode::Listener),
                info: ListenerErrorInfo {
                    error: "bind failed".to_string(),
                    name: "http".to_string(),
                },
            }),
            OperatorMessage::ListenerMark(Message {
                head: head(EventCode::Listener),
                info: ListenerMarkInfo { name: "http".to_string(), mark: "good".to_string() },
            }),
        ];

        for message in cases {
            let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
            assert_eq!(decoded, message);
        }

        Ok(())
    }
}
