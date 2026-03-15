//! Shared domain types used across the Red Cell teamserver and client.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::de::{self};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::error::CommonError;

/// Supported listener transport families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    /// HTTP or HTTPS transport.
    Http,
    /// SMB pivot transport.
    Smb,
    /// DNS C2 transport.
    Dns,
}

impl ListenerProtocol {
    /// Parse a listener protocol string using Havoc-compatible names.
    pub fn try_from_str(protocol: &str) -> Result<Self, CommonError> {
        match protocol {
            value if value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https") => {
                Ok(Self::Http)
            }
            value if value.eq_ignore_ascii_case("smb") => Ok(Self::Smb),
            value if value.eq_ignore_ascii_case("dns") => Ok(Self::Dns),
            _ => Err(CommonError::UnsupportedListenerProtocol { protocol: protocol.to_string() }),
        }
    }

    /// Return the canonical protocol label used by Red Cell.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Smb => "smb",
            Self::Dns => "dns",
        }
    }
}

impl fmt::Display for ListenerProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// TLS certificate and key file paths for an HTTP listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ListenerTlsConfig {
    /// PEM certificate path.
    pub cert: String,
    /// PEM private key path.
    pub key: String,
}

/// Static response headers returned by an HTTP listener.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HttpListenerResponseConfig {
    /// Headers added to every listener response.
    pub headers: Vec<String>,
    /// Optional static response body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Upstream proxy configuration for an HTTP listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HttpListenerProxyConfig {
    /// Whether the proxy is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Proxy type label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_type: Option<String>,
    /// Proxy hostname or IP address.
    pub host: String,
    /// Proxy port.
    #[serde(deserialize_with = "deserialize_u16_from_any")]
    pub port: u16,
    /// Optional proxy username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional proxy password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Shared HTTP listener configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HttpListenerConfig {
    /// Listener display name.
    pub name: String,
    /// Optional kill-date restriction from the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_date: Option<String>,
    /// Optional working-hours restriction from the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_hours: Option<String>,
    /// Callback hosts advertised to agents.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Local interface to bind.
    pub host_bind: String,
    /// Host rotation mode.
    pub host_rotation: String,
    /// Teamserver bind port.
    #[serde(deserialize_with = "deserialize_u16_from_any")]
    pub port_bind: u16,
    /// Agent-facing connect port, if different from the bind port.
    #[serde(default, deserialize_with = "deserialize_optional_u16_from_any")]
    pub port_conn: Option<u16>,
    /// HTTP method override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Trust redirector forwarding headers.
    #[serde(default)]
    pub behind_redirector: bool,
    /// Explicit redirector peers or networks allowed to supply forwarded client IP headers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxy_peers: Vec<String>,
    /// User-Agent gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Required request headers.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Allowed request paths.
    #[serde(default)]
    pub uris: Vec<String>,
    /// Optional override for the HTTP host header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_header: Option<String>,
    /// Whether TLS is enabled.
    #[serde(default)]
    pub secure: bool,
    /// TLS certificate paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<ListenerTlsConfig>,
    /// Static response header overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpListenerResponseConfig>,
    /// Upstream proxy settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<HttpListenerProxyConfig>,
}

/// Shared SMB listener configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SmbListenerConfig {
    /// Listener display name.
    pub name: String,
    /// Named pipe used for pivot traffic.
    pub pipe_name: String,
    /// Optional kill-date restriction from the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_date: Option<String>,
    /// Optional working-hours restriction from the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_hours: Option<String>,
}

/// Shared DNS C2 listener configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnsListenerConfig {
    /// Listener display name.
    pub name: String,
    /// Local interface to bind (e.g., `0.0.0.0`).
    pub host_bind: String,
    /// UDP port to listen on (default 53).
    #[serde(deserialize_with = "deserialize_u16_from_any")]
    pub port_bind: u16,
    /// C2 domain suffix handled by this listener (e.g., `c2.example.com`).
    pub domain: String,
    /// Enabled DNS record types for C2 (e.g., `["TXT", "A"]`).
    #[serde(default = "default_dns_record_types")]
    pub record_types: Vec<String>,
    /// Optional kill-date restriction from the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_date: Option<String>,
    /// Optional working-hours restriction from the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_hours: Option<String>,
}

fn default_dns_record_types() -> Vec<String> {
    vec!["TXT".to_owned()]
}

/// Shared listener configuration enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "protocol", content = "config", rename_all = "snake_case")]
pub enum ListenerConfig {
    /// HTTP or HTTPS listener settings.
    Http(Box<HttpListenerConfig>),
    /// SMB pivot listener settings.
    Smb(SmbListenerConfig),
    /// DNS C2 listener settings.
    Dns(DnsListenerConfig),
}

impl ListenerConfig {
    /// Return the listener display name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Http(config) => &config.name,
            Self::Smb(config) => &config.name,
            Self::Dns(config) => &config.name,
        }
    }

    /// Return the listener protocol family.
    #[must_use]
    pub const fn protocol(&self) -> ListenerProtocol {
        match self {
            Self::Http(_) => ListenerProtocol::Http,
            Self::Smb(_) => ListenerProtocol::Smb,
            Self::Dns(_) => ListenerProtocol::Dns,
        }
    }
}

impl From<HttpListenerConfig> for ListenerConfig {
    fn from(config: HttpListenerConfig) -> Self {
        Self::Http(Box::new(config))
    }
}

impl From<SmbListenerConfig> for ListenerConfig {
    fn from(config: SmbListenerConfig) -> Self {
        Self::Smb(config)
    }
}

impl From<DnsListenerConfig> for ListenerConfig {
    fn from(config: DnsListenerConfig) -> Self {
        Self::Dns(config)
    }
}

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
    let encoded = Zeroizing::new(String::deserialize(deserializer)?);
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
    #[serde(rename = "Encryption", default)]
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
    /// Process executable name.
    #[serde(rename = "ProcessName")]
    pub process_name: String,
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

fn deserialize_bool_from_any<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = StringOrBoolOrU64::deserialize(deserializer)?;

    match raw {
        StringOrBoolOrU64::Bool(value) => Ok(value),
        StringOrBoolOrU64::Number(value) => match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(de::Error::custom(format!("invalid boolean number `{value}`"))),
        },
        StringOrBoolOrU64::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" | "" => Ok(false),
            other => Err(de::Error::custom(format!("invalid boolean value `{other}`"))),
        },
    }
}

fn deserialize_u16_from_any<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_u64_from_any(deserializer)?;
    u16::try_from(value)
        .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in u16")))
}

fn deserialize_optional_u16_from_any<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_optional_u64_from_any(deserializer)?;
    value
        .map(|value| {
            u16::try_from(value)
                .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in u16")))
        })
        .transpose()
}

fn deserialize_u32_from_any<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_u64_from_any(deserializer)?;
    u32::try_from(value)
        .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in u32")))
}

fn deserialize_u64_from_any<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = StringOrU64::deserialize(deserializer)?;

    match raw {
        StringOrU64::String(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|_| de::Error::custom(format!("invalid unsigned integer value `{value}`"))),
        StringOrU64::Number(value) => Ok(value),
    }
}

fn deserialize_optional_u64_from_any<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<StringOrU64>::deserialize(deserializer)?;

    raw.map(|value| match value {
        StringOrU64::String(string) if string.trim().is_empty() => Ok(None),
        StringOrU64::String(string) => {
            string.trim().parse::<u64>().map(Some).map_err(|_| {
                de::Error::custom(format!("invalid unsigned integer value `{string}`"))
            })
        }
        StringOrU64::Number(value) => Ok(Some(value)),
    })
    .transpose()
    .map(Option::flatten)
}

fn deserialize_optional_i64_from_any<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<StringOrI64>::deserialize(deserializer)?;

    raw.map(|value| match value {
        StringOrI64::String(string) if string.trim().is_empty() => Ok(None),
        StringOrI64::String(string) => string
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| de::Error::custom(format!("invalid signed integer value `{string}`"))),
        StringOrI64::Number(value) => Ok(Some(value)),
    })
    .transpose()
    .map(Option::flatten)
}

fn deserialize_optional_i32_from_any<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_optional_i64_from_any(deserializer)?;
    value
        .map(|value| {
            i32::try_from(value)
                .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in i32")))
        })
        .transpose()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrU64 {
    String(String),
    Number(u64),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrI64 {
    String(String),
    Number(i64),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrBoolOrU64 {
    String(String),
    Bool(bool),
    Number(u64),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        AgentRecord, DnsListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
        HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, ListenerTlsConfig,
        OperatorInfo, SmbListenerConfig,
    };
    use crate::error::CommonError;

    #[test]
    fn listener_protocol_accepts_havoc_labels() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(ListenerProtocol::try_from_str("Http")?, ListenerProtocol::Http);
        assert_eq!(ListenerProtocol::try_from_str("Https")?, ListenerProtocol::Http);
        assert_eq!(ListenerProtocol::try_from_str("SMB")?, ListenerProtocol::Smb);
        Ok(())
    }

    #[test]
    fn listener_protocol_accepts_dns() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(ListenerProtocol::try_from_str("dns")?, ListenerProtocol::Dns);
        assert_eq!(ListenerProtocol::try_from_str("DNS")?, ListenerProtocol::Dns);
        Ok(())
    }

    #[test]
    fn listener_protocol_rejects_unknown_labels() {
        let error =
            ListenerProtocol::try_from_str("quic").expect_err("unknown protocol should fail");
        assert_eq!(
            error,
            CommonError::UnsupportedListenerProtocol { protocol: "quic".to_string() }
        );
    }

    #[test]
    fn listener_protocol_rejects_external_until_runtime_exists() {
        let error =
            ListenerProtocol::try_from_str("external").expect_err("external is not yet supported");
        assert_eq!(
            error,
            CommonError::UnsupportedListenerProtocol { protocol: "external".to_string() }
        );
    }

    #[test]
    fn listener_config_reports_name_and_protocol() {
        let config = ListenerConfig::from(HttpListenerConfig {
            name: "edge".to_string(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["team.example".to_string()],
            host_bind: "0.0.0.0".to_string(),
            host_rotation: "round-robin".to_string(),
            port_bind: 443,
            port_conn: Some(443),
            method: Some("POST".to_string()),
            behind_redirector: true,
            trusted_proxy_peers: vec!["127.0.0.1/32".to_string()],
            user_agent: Some("Mozilla/5.0".to_string()),
            headers: vec!["X-Test: 1".to_string()],
            uris: vec!["/index".to_string()],
            host_header: Some("team.example".to_string()),
            secure: true,
            cert: Some(ListenerTlsConfig {
                cert: "server.crt".to_string(),
                key: "server.key".to_string(),
            }),
            response: Some(HttpListenerResponseConfig {
                headers: vec!["Server: nginx".to_string()],
                body: Some("{\"status\":\"ok\"}".to_string()),
            }),
            proxy: Some(HttpListenerProxyConfig {
                enabled: true,
                proxy_type: Some("http".to_string()),
                host: "127.0.0.1".to_string(),
                port: 8080,
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
            }),
        });

        assert_eq!(config.name(), "edge");
        assert_eq!(config.protocol(), ListenerProtocol::Http);
    }

    #[test]
    fn listener_config_round_trips_with_tagged_protocol() -> Result<(), Box<dyn std::error::Error>>
    {
        let original = ListenerConfig::from(SmbListenerConfig {
            name: "pivot".to_string(),
            pipe_name: r"\\.\pipe\pivot".to_string(),
            kill_date: Some("2026-03-09 20:00:00".to_string()),
            working_hours: Some("08:00-17:00".to_string()),
        });

        let encoded = serde_json::to_value(&original)?;
        let decoded: ListenerConfig = serde_json::from_value(encoded)?;
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn agent_info_deserializes_mixed_havoc_shapes() -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "NameID": "ABCD1234",
            "Active": "true",
            "Reason": "manual",
            "Encryption": {
                "AESKey": "YWVzLWtleQ==",
                "AESIv": "aXY="
            },
            "Hostname": "wkstn-1",
            "Username": "operator",
            "DomainName": "LAB",
            "ExternalIP": "203.0.113.10",
            "InternalIP": "10.0.0.10",
            "ProcessName": "explorer.exe",
            "BaseAddress": "140702646099968",
            "ProcessPID": "1234",
            "ProcessTID": 5678,
            "ProcessPPID": "1000",
            "ProcessArch": "x64",
            "Elevated": "true",
            "OSVersion": "Windows 10",
            "OSArch": "x64",
            "SleepDelay": 5,
            "Jitter": "10",
            "KillDate": "",
            "WorkingHours": "0",
            "FirstCallIn": "09/03/2026 19:04:00",
            "LastCallIn": "09/03/2026 19:05:00"
        });

        let info: AgentRecord = serde_json::from_value(payload)?;
        assert_eq!(info.agent_id, 0xABCD_1234);
        assert!(info.active);
        assert!(info.elevated);
        assert_eq!(info.sleep_jitter, 10);
        assert_eq!(info.kill_date, None);
        assert_eq!(info.working_hours, Some(0));
        assert_eq!(info.name_id(), "ABCD1234");
        Ok(())
    }

    #[test]
    fn agent_info_rejects_invalid_identifier() {
        let payload = json!({
            "AgentID": "not-a-valid-id",
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

        let error =
            serde_json::from_value::<AgentRecord>(payload).expect_err("invalid agent id must fail");
        assert!(error.to_string().contains("invalid agent identifier"));
    }

    #[test]
    fn agent_info_parses_digit_only_string_identifier_as_hex()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "AgentID": "00000010",
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

        let info: AgentRecord = serde_json::from_value(payload)?;
        assert_eq!(info.agent_id, 0x10);
        assert_eq!(info.name_id(), "00000010");
        Ok(())
    }

    #[test]
    fn agent_info_parses_digit_only_identifier_without_prefix_as_hex()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "AgentID": "12345678",
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

        let info: AgentRecord = serde_json::from_value(payload)?;
        assert_eq!(info.agent_id, 0x1234_5678);
        assert_eq!(info.name_id(), "12345678");
        Ok(())
    }

    #[test]
    fn agent_info_parses_prefixed_identifier_as_hex() -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "AgentID": "0X00000010",
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

        let info: AgentRecord = serde_json::from_value(payload)?;
        assert_eq!(info.agent_id, 0x10);
        assert_eq!(info.name_id(), "00000010");
        Ok(())
    }

    #[test]
    fn operator_info_supports_profile_and_presence_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let payload = json!({
            "User": "michel",
            "PasswordHash": "abc123",
            "Role": "admin",
            "Online": true,
            "LastSeen": "09/03/2026 19:05:00"
        });

        let info: OperatorInfo = serde_json::from_value(payload)?;
        assert_eq!(info.username, "michel");
        assert_eq!(info.password_hash.as_deref(), Some("abc123"));
        assert_eq!(info.role.as_deref(), Some("admin"));
        assert!(info.online);
        Ok(())
    }

    #[test]
    fn proxy_port_accepts_string_values() -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "name": "edge",
            "kill_date": null,
            "working_hours": null,
            "hosts": [],
            "host_bind": "0.0.0.0",
            "host_rotation": "round-robin",
            "port_bind": "443",
            "port_conn": "8443",
            "method": "POST",
            "behind_redirector": false,
            "user_agent": null,
            "headers": [],
            "uris": [],
            "host_header": null,
            "secure": true,
            "cert": null,
            "response": null,
            "proxy": {
                "enabled": true,
                "proxy_type": "http",
                "host": "127.0.0.1",
                "port": "8080",
                "username": null,
                "password": null
            }
        });

        let info: HttpListenerConfig = serde_json::from_value(payload)?;
        assert_eq!(info.port_bind, 443);
        assert_eq!(info.port_conn, Some(8443));
        assert_eq!(info.proxy.as_ref().map(|proxy| proxy.port), Some(8080));
        Ok(())
    }

    #[test]
    fn response_body_round_trips_with_http_listener_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "protocol": "http",
            "config": {
                "name": "edge",
                "kill_date": null,
                "working_hours": null,
                "hosts": ["c2.local"],
                "host_bind": "127.0.0.1",
                "host_rotation": "round-robin",
                "port_bind": 8080,
                "port_conn": null,
                "method": "POST",
                "behind_redirector": false,
                "user_agent": null,
                "headers": [],
                "uris": ["/submit"],
                "host_header": null,
                "secure": false,
                "cert": null,
                "response": {
                    "headers": ["Server: nginx"],
                    "body": "hello"
                },
                "proxy": null
            }
        });

        let config: ListenerConfig = serde_json::from_value(payload.clone())?;
        let encoded = serde_json::to_value(&config)?;

        assert_eq!(encoded["protocol"], payload["protocol"]);
        assert_eq!(encoded["config"]["response"]["body"], payload["config"]["response"]["body"]);
        assert_eq!(
            encoded["config"]["response"]["headers"],
            payload["config"]["response"]["headers"]
        );
        Ok(())
    }

    #[test]
    fn dns_listener_config_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let original = ListenerConfig::from(DnsListenerConfig {
            name: "dns-c2".to_string(),
            host_bind: "0.0.0.0".to_string(),
            port_bind: 53,
            domain: "c2.example.com".to_string(),
            record_types: vec!["TXT".to_string(), "A".to_string()],
            kill_date: Some("2026-12-31 23:59:59".to_string()),
            working_hours: Some("08:00-18:00".to_string()),
        });

        let encoded = serde_json::to_value(&original)?;
        let decoded: ListenerConfig = serde_json::from_value(encoded)?;
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn dns_listener_config_record_types_defaults_to_txt_when_absent()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = serde_json::json!({
            "protocol": "dns",
            "config": {
                "name": "dns-c2",
                "host_bind": "0.0.0.0",
                "port_bind": 53,
                "domain": "c2.example.com"
            }
        });

        let config: ListenerConfig = serde_json::from_value(payload)?;
        let ListenerConfig::Dns(dns) = config else {
            panic!("expected Dns variant");
        };
        assert_eq!(dns.record_types, vec!["TXT".to_string()]);
        Ok(())
    }

    #[test]
    fn port_bind_rejects_value_above_u16_max() {
        let payload = json!({
            "name": "edge",
            "kill_date": null,
            "working_hours": null,
            "hosts": [],
            "host_bind": "0.0.0.0",
            "host_rotation": "round-robin",
            "port_bind": 70000,
            "port_conn": null,
            "method": null,
            "behind_redirector": false,
            "user_agent": null,
            "headers": [],
            "uris": [],
            "host_header": null,
            "secure": false,
            "cert": null,
            "response": null,
            "proxy": null
        });

        let error = serde_json::from_value::<HttpListenerConfig>(payload)
            .expect_err("port_bind 70000 must be rejected");
        assert!(
            error.to_string().contains("does not fit in u16"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn port_conn_rejects_string_value_above_u16_max() {
        let payload = json!({
            "name": "edge",
            "kill_date": null,
            "working_hours": null,
            "hosts": [],
            "host_bind": "0.0.0.0",
            "host_rotation": "round-robin",
            "port_bind": 443,
            "port_conn": "99999",
            "method": null,
            "behind_redirector": false,
            "user_agent": null,
            "headers": [],
            "uris": [],
            "host_header": null,
            "secure": false,
            "cert": null,
            "response": null,
            "proxy": null
        });

        let error = serde_json::from_value::<HttpListenerConfig>(payload)
            .expect_err("port_conn 99999 must be rejected");
        assert!(
            error.to_string().contains("does not fit in u16"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn proxy_port_rejects_string_value_above_u16_max() {
        let payload = json!({
            "name": "edge",
            "kill_date": null,
            "working_hours": null,
            "hosts": [],
            "host_bind": "0.0.0.0",
            "host_rotation": "round-robin",
            "port_bind": 443,
            "port_conn": null,
            "method": null,
            "behind_redirector": false,
            "user_agent": null,
            "headers": [],
            "uris": [],
            "host_header": null,
            "secure": false,
            "cert": null,
            "response": null,
            "proxy": {
                "enabled": true,
                "host": "127.0.0.1",
                "port": "99999"
            }
        });

        let error = serde_json::from_value::<HttpListenerConfig>(payload)
            .expect_err("proxy port 99999 must be rejected");
        assert!(
            error.to_string().contains("does not fit in u16"),
            "unexpected error message: {error}"
        );
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
}
