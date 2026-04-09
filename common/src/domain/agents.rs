//! Agent record, encryption info, and operator types.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::error::CommonError;

use super::serde_helpers::{
    StringOrU64, deserialize_bool_from_any, deserialize_optional_i32_from_any,
    deserialize_optional_i64_from_any, deserialize_u32_from_any, deserialize_u64_from_any,
};

/// Agent transport crypto material persisted by the teamserver.
///
/// Key and IV are stored as raw bytes inside [`Zeroizing`] wrappers, which
/// guarantee that the heap memory is overwritten with zeros when the value is
/// dropped.  Serialisation encodes them as standard base64 strings to keep
/// wire and database formats unchanged.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AgentEncryptionInfo {
    /// AES-256 key (raw bytes, zeroized on drop).
    #[serde(
        rename = "AESKey",
        serialize_with = "serialize_zeroizing_bytes_as_base64",
        deserialize_with = "deserialize_base64_to_zeroizing_bytes"
    )]
    #[schema(value_type = String)]
    pub aes_key: Zeroizing<Vec<u8>>,
    /// AES-CTR counter block / IV (raw bytes, zeroized on drop).
    #[serde(
        rename = "AESIv",
        serialize_with = "serialize_zeroizing_bytes_as_base64",
        deserialize_with = "deserialize_base64_to_zeroizing_bytes"
    )]
    #[schema(value_type = String)]
    pub aes_iv: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AgentEncryptionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentEncryptionInfo")
            .field("aes_key", &"[redacted]")
            .field("aes_iv", &"[redacted]")
            .finish()
    }
}

fn serialize_zeroizing_bytes_as_base64<S: Serializer>(
    bytes: &Zeroizing<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64_STANDARD.encode(bytes.as_slice()))
}

fn deserialize_base64_to_zeroizing_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<Vec<u8>>, D::Error> {
    // Deserialize directly into Zeroizing<String> so the base64-encoded key
    // material is zeroed on drop, not left in a plain String on the heap.
    let encoded = Zeroizing::<String>::deserialize(deserializer)?;
    let bytes = BASE64_STANDARD.decode(encoded.as_bytes()).map_err(de::Error::custom)?;
    Ok(Zeroizing::new(bytes))
}

/// Shared persisted agent/session metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AgentRecord {
    /// Numeric agent identifier.
    #[serde(rename = "AgentID", alias = "NameID", deserialize_with = "deserialize_agent_id")]
    pub agent_id: u32,
    /// Whether the agent is still marked active.
    #[serde(rename = "Active", deserialize_with = "deserialize_bool_from_any")]
    pub active: bool,
    /// Optional inactive reason or registration source.
    #[serde(rename = "Reason", default)]
    pub reason: String,
    /// Optional operator-authored note attached to the agent.
    #[serde(rename = "Note", default)]
    pub note: String,
    /// Per-agent transport keys.
    /// Serialisation is intentionally suppressed so that key material is never included in
    /// operator-facing JSON responses (REST API, WebSocket broadcasts).  The field is still
    /// deserialisable for any path that loads a full record from a trusted source.
    #[serde(rename = "Encryption", default, skip_serializing)]
    pub encryption: AgentEncryptionInfo,
    /// Computer hostname.
    #[serde(rename = "Hostname")]
    pub hostname: String,
    /// Logon username.
    #[serde(rename = "Username")]
    pub username: String,
    /// Logon domain.
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    /// External callback IP.
    #[serde(rename = "ExternalIP")]
    pub external_ip: String,
    /// Internal workstation IP.
    #[serde(rename = "InternalIP")]
    pub internal_ip: String,
    /// Process executable name (basename only).
    #[serde(rename = "ProcessName")]
    pub process_name: String,
    /// Full path to the process executable.
    #[serde(rename = "ProcessPath", default)]
    pub process_path: String,
    /// Remote process base address.
    #[serde(rename = "BaseAddress", deserialize_with = "deserialize_u64_from_any")]
    pub base_address: u64,
    /// Remote process id.
    #[serde(rename = "ProcessPID", deserialize_with = "deserialize_u32_from_any")]
    pub process_pid: u32,
    /// Remote thread id.
    #[serde(rename = "ProcessTID", deserialize_with = "deserialize_u32_from_any")]
    pub process_tid: u32,
    /// Remote parent process id.
    #[serde(rename = "ProcessPPID", deserialize_with = "deserialize_u32_from_any")]
    pub process_ppid: u32,
    /// Process architecture label.
    #[serde(rename = "ProcessArch")]
    pub process_arch: String,
    /// Whether the current token is elevated.
    #[serde(rename = "Elevated", deserialize_with = "deserialize_bool_from_any")]
    pub elevated: bool,
    /// Operating system version string.
    #[serde(rename = "OSVersion")]
    pub os_version: String,
    /// Operating system build number (e.g. 22000 for Windows 11 21H2).
    #[serde(rename = "OSBuild", deserialize_with = "deserialize_u32_from_any", default)]
    pub os_build: u32,
    /// Operating system architecture label.
    #[serde(rename = "OSArch")]
    pub os_arch: String,
    /// Sleep interval in seconds.
    #[serde(rename = "SleepDelay", deserialize_with = "deserialize_u32_from_any")]
    pub sleep_delay: u32,
    /// Sleep jitter percentage.
    #[serde(
        rename = "SleepJitter",
        alias = "Jitter",
        deserialize_with = "deserialize_u32_from_any"
    )]
    pub sleep_jitter: u32,
    /// Optional kill-date value.
    #[serde(default, rename = "KillDate", deserialize_with = "deserialize_optional_i64_from_any")]
    pub kill_date: Option<i64>,
    /// Optional working-hours bitmask.
    #[serde(
        default,
        rename = "WorkingHours",
        deserialize_with = "deserialize_optional_i32_from_any"
    )]
    pub working_hours: Option<i32>,
    /// Registration timestamp.
    #[serde(rename = "FirstCallIn")]
    pub first_call_in: String,
    /// Last callback timestamp.
    #[serde(rename = "LastCallIn")]
    pub last_call_in: String,
}

impl AgentRecord {
    /// Return the canonical eight-character upper-hex agent id string.
    #[must_use]
    pub fn name_id(&self) -> String {
        format!("{:08X}", self.agent_id)
    }
}

/// Shared operator account and presence metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorInfo {
    /// Operator username.
    #[serde(rename = "Username", alias = "User")]
    pub username: String,
    /// Optional password hash or profile-secret representation.
    #[serde(rename = "PasswordHash", default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// Optional RBAC role name.
    #[serde(rename = "Role", default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Whether the operator is currently connected.
    #[serde(rename = "Online", default)]
    pub online: bool,
    /// Optional last-seen timestamp string.
    #[serde(rename = "LastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

fn deserialize_agent_id<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = StringOrU64::deserialize(deserializer)?;

    match raw {
        StringOrU64::String(value) => parse_agent_id(&value).map_err(de::Error::custom),
        StringOrU64::Number(value) => u32::try_from(value).map_err(|_| {
            de::Error::custom(format!("agent identifier `{value}` does not fit in u32"))
        }),
    }
}

fn parse_agent_id(value: &str) -> Result<u32, CommonError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CommonError::InvalidAgentId { value: value.to_string() });
    }

    let maybe_hex =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);

    u32::from_str_radix(maybe_hex, 16)
        .map_err(|_| CommonError::InvalidAgentId { value: value.to_string() })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::*;
    use crate::error::CommonError;

    fn minimal_agent_record() -> AgentRecord {
        AgentRecord {
            agent_id: 0xABCD1234,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0xAA; 32]),
                aes_iv: Zeroizing::new(vec![0xBB; 16]),
            },
            hostname: "wkstn-1".to_string(),
            username: "operator".to_string(),
            domain_name: "LAB".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "10.0.0.10".to_string(),
            process_name: "explorer.exe".to_string(),
            process_path: String::new(),
            base_address: 1,
            process_pid: 1,
            process_tid: 1,
            process_ppid: 1,
            process_arch: "x64".to_string(),
            elevated: false,
            os_version: "Windows 10".to_string(),
            os_build: 0,
            os_arch: "x64".to_string(),
            sleep_delay: 5,
            sleep_jitter: 10,
            kill_date: None,
            working_hours: None,
            first_call_in: "09/03/2026 19:04:00".to_string(),
            last_call_in: "09/03/2026 19:05:00".to_string(),
        }
    }

    #[test]
    fn deserialize_bool_from_any_rejects_unrecognized_string_active() {
        let payload = json!({
            "AgentID": "ABCD1234",
            "Active": "yes",
            "Hostname": "wkstn-1",
            "Username": "operator",
            "DomainName": "LAB",
            "ExternalIP": "203.0.113.10",
            "InternalIP": "10.0.0.10",
            "ProcessName": "explorer.exe",
            "BaseAddress": 1,
            "ProcessPID": 1,
            "ProcessTID": 1,
            "ProcessPPID": 1,
            "ProcessArch": "x64",
            "Elevated": false,
            "OSVersion": "Windows 10",
            "OSArch": "x64",
            "SleepDelay": 5,
            "SleepJitter": 10,
            "FirstCallIn": "09/03/2026 19:04:00",
            "LastCallIn": "09/03/2026 19:05:00"
        });

        let error = serde_json::from_value::<AgentRecord>(payload)
            .expect_err("string \"yes\" for Active must be rejected");
        assert!(
            error.to_string().contains("invalid boolean value"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn deserialize_bool_from_any_rejects_unrecognized_string_elevated() {
        let payload = json!({
            "AgentID": "ABCD1234",
            "Active": true,
            "Hostname": "wkstn-1",
            "Username": "operator",
            "DomainName": "LAB",
            "ExternalIP": "203.0.113.10",
            "InternalIP": "10.0.0.10",
            "ProcessName": "explorer.exe",
            "BaseAddress": 1,
            "ProcessPID": 1,
            "ProcessTID": 1,
            "ProcessPPID": 1,
            "ProcessArch": "x64",
            "Elevated": "maybe",
            "OSVersion": "Windows 10",
            "OSArch": "x64",
            "SleepDelay": 5,
            "SleepJitter": 10,
            "FirstCallIn": "09/03/2026 19:04:00",
            "LastCallIn": "09/03/2026 19:05:00"
        });

        let error = serde_json::from_value::<AgentRecord>(payload)
            .expect_err("string \"maybe\" for Elevated must be rejected");
        assert!(
            error.to_string().contains("invalid boolean value"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn deserialize_agent_id_rejects_numeric_id_that_does_not_fit_in_u32() {
        for overflow_value in [4_294_967_296_u64, u64::MAX] {
            let payload = json!({
                "AgentID": overflow_value,
                "Active": true,
                "Hostname": "wkstn-1",
                "Username": "operator",
                "DomainName": "LAB",
                "ExternalIP": "203.0.113.10",
                "InternalIP": "10.0.0.10",
                "ProcessName": "explorer.exe",
                "BaseAddress": 1,
                "ProcessPID": 1,
                "ProcessTID": 1,
                "ProcessPPID": 1,
                "ProcessArch": "x64",
                "Elevated": false,
                "OSVersion": "Windows 10",
                "OSArch": "x64",
                "SleepDelay": 5,
                "SleepJitter": 10,
                "FirstCallIn": "09/03/2026 19:04:00",
                "LastCallIn": "09/03/2026 19:05:00"
            });

            let error = serde_json::from_value::<AgentRecord>(payload)
                .expect_err("numeric agent id exceeding u32::MAX must be rejected");
            assert!(
                error.to_string().contains("does not fit in u32"),
                "unexpected error message for value {overflow_value}: {error}"
            );
        }
    }

    #[test]
    fn parse_agent_id_accepts_lowercase_0x_prefix() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_agent_id("0xABCD1234")?, 0xABCD_1234);
        Ok(())
    }

    #[test]
    fn parse_agent_id_accepts_uppercase_0x_prefix() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_agent_id("0XABCD1234")?, 0xABCD_1234);
        Ok(())
    }

    #[test]
    fn parse_agent_id_accepts_lowercase_hex_without_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_agent_id("abcd1234")?, 0xABCD_1234);
        Ok(())
    }

    #[test]
    fn parse_agent_id_rejects_empty_string() {
        assert_eq!(
            parse_agent_id("").expect_err("empty agent id must be rejected"),
            CommonError::InvalidAgentId { value: String::new() }
        );
    }

    #[test]
    fn parse_agent_id_rejects_non_hex_string() {
        assert_eq!(
            parse_agent_id("not-hex").expect_err("non-hex agent id must be rejected"),
            CommonError::InvalidAgentId { value: "not-hex".to_string() }
        );
    }

    #[test]
    fn parse_agent_id_rejects_invalid_hex_after_prefix() {
        assert_eq!(
            parse_agent_id("0xGGGGGGGG").expect_err("invalid hex digits must be rejected"),
            CommonError::InvalidAgentId { value: "0xGGGGGGGG".to_string() }
        );
    }

    #[test]
    fn deserialize_bool_from_any_rejects_integer_outside_zero_one() {
        let payload = json!({
            "AgentID": "ABCD1234",
            "Active": 2,
            "Hostname": "wkstn-1",
            "Username": "operator",
            "DomainName": "LAB",
            "ExternalIP": "203.0.113.10",
            "InternalIP": "10.0.0.10",
            "ProcessName": "explorer.exe",
            "BaseAddress": 1,
            "ProcessPID": 1,
            "ProcessTID": 1,
            "ProcessPPID": 1,
            "ProcessArch": "x64",
            "Elevated": false,
            "OSVersion": "Windows 10",
            "OSArch": "x64",
            "SleepDelay": 5,
            "SleepJitter": 10,
            "FirstCallIn": "09/03/2026 19:04:00",
            "LastCallIn": "09/03/2026 19:05:00"
        });

        let error = serde_json::from_value::<AgentRecord>(payload)
            .expect_err("integer 2 for Active must be rejected");
        assert!(
            error.to_string().contains("invalid boolean number"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn deserialize_bool_from_any_rejects_integer_outside_zero_one_for_elevated() {
        let payload = json!({
            "AgentID": "ABCD1234",
            "Active": true,
            "Hostname": "wkstn-1",
            "Username": "operator",
            "DomainName": "LAB",
            "ExternalIP": "203.0.113.10",
            "InternalIP": "10.0.0.10",
            "ProcessName": "explorer.exe",
            "BaseAddress": 1,
            "ProcessPID": 1,
            "ProcessTID": 1,
            "ProcessPPID": 1,
            "ProcessArch": "x64",
            "Elevated": 2,
            "OSVersion": "Windows 10",
            "OSArch": "x64",
            "SleepDelay": 5,
            "SleepJitter": 10,
            "FirstCallIn": "09/03/2026 19:04:00",
            "LastCallIn": "09/03/2026 19:05:00"
        });

        let error = serde_json::from_value::<AgentRecord>(payload)
            .expect_err("integer 2 for Elevated must be rejected");
        assert!(
            error.to_string().contains("invalid boolean number"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn agent_record_serialize_omits_encryption_field() {
        let record = minimal_agent_record();
        let json = serde_json::to_string(&record).expect("serialisation must succeed");
        assert!(
            !json.contains("Encryption"),
            "serialised AgentRecord must not contain the Encryption key: {json}"
        );
        assert!(!json.contains("AESKey"), "serialised AgentRecord must not contain AESKey: {json}");
        assert!(!json.contains("AESIv"), "serialised AgentRecord must not contain AESIv: {json}");
    }

    #[test]
    fn agent_record_deserialize_restores_encryption_field() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64;

        let mut record = minimal_agent_record();
        let serialised = serde_json::to_value(&record).expect("serialisation must succeed");
        let mut map = serialised.as_object().expect("top-level value must be an object").clone();
        map.insert(
            "Encryption".to_string(),
            serde_json::json!({
                "AESKey": BASE64.encode(&*record.encryption.aes_key),
                "AESIv":  BASE64.encode(&*record.encryption.aes_iv),
            }),
        );
        let round_tripped: AgentRecord = serde_json::from_value(serde_json::Value::Object(map))
            .expect("deserialisation with Encryption blob must succeed");
        assert_eq!(
            *round_tripped.encryption.aes_key, *record.encryption.aes_key,
            "aes_key must survive the round-trip"
        );
        assert_eq!(
            *round_tripped.encryption.aes_iv, *record.encryption.aes_iv,
            "aes_iv must survive the round-trip"
        );
        // Also verify that a record without the Encryption key deserialises with defaults.
        record.encryption = AgentEncryptionInfo::default();
        let no_enc = serde_json::to_value(&record).expect("serialisation must succeed");
        let without_enc: AgentRecord = serde_json::from_value(no_enc)
            .expect("deserialisation without Encryption blob must succeed");
        assert!(
            without_enc.encryption.aes_key.is_empty(),
            "missing Encryption field must produce empty aes_key"
        );
    }

    #[test]
    fn agent_record_rejects_malformed_base64_aes_key() {
        let record = minimal_agent_record();
        let serialised = serde_json::to_value(&record).expect("serialisation must succeed");
        let mut map = serialised.as_object().expect("top-level value must be an object").clone();
        map.insert(
            "Encryption".to_string(),
            serde_json::json!({
                "AESKey": "NOT-VALID-BASE64!!!@@@",
                "AESIv": "AAAAAAAAAAAAAAAAAAAAAA==",
            }),
        );

        let result: Result<AgentRecord, _> = serde_json::from_value(serde_json::Value::Object(map));
        assert!(result.is_err(), "malformed base64 in AESKey must fail deserialization");
    }

    #[test]
    fn agent_record_serialization_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = minimal_agent_record();
        record.agent_id = 0xDEAD_BEEF;
        record.active = true;
        record.elevated = true;
        record.sleep_delay = 60;
        record.sleep_jitter = 25;
        record.base_address = 0x7FFE_0000_0000;
        record.process_pid = 4096;
        record.process_tid = 8192;
        record.process_ppid = 2048;
        record.os_build = 22000;
        record.kill_date = Some(1_700_000_000);
        record.working_hours = Some(255);
        record.reason = "callback".to_string();
        record.note = "test agent".to_string();
        record.process_path = r"C:\Windows\explorer.exe".to_string();

        let serialized = serde_json::to_value(&record)?;
        let deserialized: AgentRecord = serde_json::from_value(serialized)?;

        // Encryption is skip_serializing, so it defaults to empty after round-trip.
        let mut expected = record;
        expected.encryption = AgentEncryptionInfo::default();

        assert_eq!(deserialized, expected);
        Ok(())
    }

    #[test]
    fn agent_record_round_trip_with_none_optional_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut record = minimal_agent_record();
        record.encryption = AgentEncryptionInfo::default();
        record.kill_date = None;
        record.working_hours = None;

        let serialized = serde_json::to_value(&record)?;
        let deserialized: AgentRecord = serde_json::from_value(serialized)?;

        assert_eq!(deserialized, record);
        Ok(())
    }

    #[test]
    fn agent_record_round_trip_preserves_false_booleans() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut record = minimal_agent_record();
        record.encryption = AgentEncryptionInfo::default();
        record.active = false;
        record.elevated = false;

        let serialized = serde_json::to_value(&record)?;
        let deserialized: AgentRecord = serde_json::from_value(serialized)?;

        assert!(!deserialized.active);
        assert!(!deserialized.elevated);
        assert_eq!(deserialized, record);
        Ok(())
    }

    #[test]
    fn agent_record_round_trip_preserves_zero_numeric_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut record = minimal_agent_record();
        record.encryption = AgentEncryptionInfo::default();
        record.agent_id = 0;
        record.base_address = 0;
        record.process_pid = 0;
        record.process_tid = 0;
        record.process_ppid = 0;
        record.os_build = 0;
        record.sleep_delay = 0;
        record.sleep_jitter = 0;

        let serialized = serde_json::to_value(&record)?;
        let deserialized: AgentRecord = serde_json::from_value(serialized)?;

        assert_eq!(deserialized, record);
        Ok(())
    }

    #[test]
    fn agent_record_round_trip_preserves_max_u32_agent_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut record = minimal_agent_record();
        record.encryption = AgentEncryptionInfo::default();
        record.agent_id = u32::MAX;

        let serialized = serde_json::to_value(&record)?;
        let deserialized: AgentRecord = serde_json::from_value(serialized)?;

        assert_eq!(deserialized.agent_id, u32::MAX);
        assert_eq!(deserialized, record);
        Ok(())
    }

    #[test]
    fn agent_record_rejects_malformed_base64_aes_iv() {
        let record = minimal_agent_record();
        let serialised = serde_json::to_value(&record).expect("serialisation must succeed");
        let mut map = serialised.as_object().expect("top-level value must be an object").clone();
        map.insert(
            "Encryption".to_string(),
            serde_json::json!({
                "AESKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "AESIv": "~~~INVALID~~~",
            }),
        );

        let result: Result<AgentRecord, _> = serde_json::from_value(serde_json::Value::Object(map));
        assert!(result.is_err(), "malformed base64 in AESIv must fail deserialization");
    }
}
