//! Operator management request/response info structs for the Red Cell WebSocket protocol extension.

use serde::{Deserialize, Serialize};

/// Info payload for creating a new operator account (`OperatorManagement / Create`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOperatorInfo {
    /// Username for the new operator.
    #[serde(rename = "Username")]
    pub username: String,
    /// Plaintext password; the teamserver is responsible for hashing before storage.
    #[serde(rename = "Password")]
    pub password: String,
    /// RBAC role to assign (e.g. `"Admin"`, `"Operator"`, `"Analyst"`).
    #[serde(rename = "Role", default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// Info payload for removing an operator account (`OperatorManagement / Remove`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveOperatorInfo {
    /// Username of the operator to remove.
    #[serde(rename = "Username")]
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_operator_info_round_trip() {
        let info = CreateOperatorInfo {
            username: "alice".to_owned(),
            password: "s3cr3t".to_owned(),
            role: Some("Operator".to_owned()),
        };
        let encoded = serde_json::to_value(&info).expect("serialize");
        assert_eq!(encoded["Username"], json!("alice"));
        assert_eq!(encoded["Password"], json!("s3cr3t"));
        assert_eq!(encoded["Role"], json!("Operator"));
        let decoded: CreateOperatorInfo = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(decoded, info);
    }

    #[test]
    fn create_operator_info_omits_role_when_none() {
        let info = CreateOperatorInfo {
            username: "bob".to_owned(),
            password: "pw".to_owned(),
            role: None,
        };
        let encoded = serde_json::to_value(&info).expect("serialize");
        assert!(!encoded.as_object().unwrap().contains_key("Role"));
    }

    #[test]
    fn remove_operator_info_round_trip() {
        let info = RemoveOperatorInfo { username: "charlie".to_owned() };
        let encoded = serde_json::to_value(&info).expect("serialize");
        assert_eq!(encoded["Username"], json!("charlie"));
        let decoded: RemoveOperatorInfo = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(decoded, info);
    }
}
