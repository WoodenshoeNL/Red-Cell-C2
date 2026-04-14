//! Init / auth / connection messages (`InitConnection*` and `Login`).

#[cfg(test)]
mod tests {
    use super::super::test_support::head;
    use super::super::{
        EventCode, InitProfileInfo, LoginInfo, Message, MessageHead, MessageInfo, OperatorMessage,
    };
    use serde_json::json;

    #[test]
    fn login_message_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::Login(Message {
            head: head(EventCode::InitConnection),
            info: LoginInfo { user: "operator".to_string(), password: "deadbeef".to_string() },
        });

        let value = serde_json::to_value(&message)?;
        assert_eq!(value["Head"]["Event"], json!(1));
        assert_eq!(value["Body"]["SubEvent"], json!(3));

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn rejects_unknown_operator_event_code() {
        let value = json!({
            "Head": { "Event": 255, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 1, "Info": {} }
        });

        let error = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("unsupported event code must fail");

        assert!(error.to_string().contains("unsupported EventCode code"));
    }

    #[test]
    fn rejects_unknown_operator_sub_event() {
        let value = json!({
            "Head": { "Event": 1, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 255, "Info": {} }
        });

        let error = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("unsupported subevent must fail");

        assert!(error.to_string().contains("unsupported operator message"));
    }

    #[test]
    fn message_head_skips_empty_optional_fields() -> Result<(), Box<dyn std::error::Error>> {
        let value = serde_json::to_value(MessageHead {
            event: EventCode::Chat,
            user: String::new(),
            timestamp: String::new(),
            one_time: String::new(),
        })?;

        assert_eq!(value, json!({ "Event": 4 }));
        Ok(())
    }

    #[test]
    fn remaining_typed_init_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            OperatorMessage::InitConnectionError(Message {
                head: head(EventCode::InitConnection),
                info: MessageInfo { message: "denied".to_string() },
            }),
            OperatorMessage::InitConnectionProfile(Message {
                head: head(EventCode::InitConnection),
                info: InitProfileInfo {
                    demon: "{\"Sleep\":5}".to_string(),
                    teamserver_ips: "127.0.0.1".to_string(),
                },
            }),
        ];

        for message in cases {
            let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
            assert_eq!(decoded, message);
        }

        Ok(())
    }

    /// Deserialization must fail with a clear error when `Head` is missing.
    #[test]
    fn operator_message_rejects_missing_head() {
        let value = json!({
            "Body": { "SubEvent": 3, "Info": { "User": "operator", "Password": "secret" } }
        });

        let err = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("missing Head must fail deserialization");
        assert!(
            err.to_string().contains("Head"),
            "error should mention the missing field 'Head', got: {err}"
        );
    }

    /// Deserialization must fail with a clear error when `Body` is missing.
    #[test]
    fn operator_message_rejects_missing_body() {
        let value = json!({
            "Head": { "Event": 1, "User": "operator", "Time": "09/03/2026 19:00:00" }
        });

        let err = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("missing Body must fail deserialization");
        assert!(
            err.to_string().contains("Body"),
            "error should mention the missing field 'Body', got: {err}"
        );
    }

    /// Deserialization must fail when the JSON object is completely empty.
    #[test]
    fn operator_message_rejects_empty_object() {
        let value = json!({});

        let err = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("empty object must fail deserialization");
        // serde will complain about the first missing required field.
        let msg = err.to_string();
        assert!(
            msg.contains("Head") || msg.contains("Body"),
            "error should mention a missing top-level key, got: {err}"
        );
    }

    /// Extra unknown top-level JSON keys (beyond `Head` and `Body`) must be
    /// silently ignored for forward-compatibility with newer Havoc clients.
    #[test]
    fn extra_top_level_keys_are_silently_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 1, "User": "operator", "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 3,
                "Info": { "User": "operator", "Password": "deadbeef" }
            },
            "Debug": true,
            "Version": 42,
            "Extra": { "nested": "data" }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        let expected = OperatorMessage::Login(Message {
            head: head(EventCode::InitConnection),
            info: LoginInfo { user: "operator".to_string(), password: "deadbeef".to_string() },
        });
        assert_eq!(decoded, expected);
        Ok(())
    }
}
