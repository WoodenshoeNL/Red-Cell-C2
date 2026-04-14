//! Credential / loot messages (`Credentials*` variants).

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::test_support::head;
    use super::super::{EventCode, FlatInfo, Message, OperatorMessage};

    #[test]
    fn credentials_remove_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::CredentialsRemove(Message {
            head: head(EventCode::Credentials),
            info: FlatInfo { fields: BTreeMap::new() },
        });
        let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
        assert_eq!(decoded, message);
        Ok(())
    }
}
