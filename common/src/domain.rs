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
    /// External C2 bridge transport.
    External,
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
            value if value.eq_ignore_ascii_case("external") => Ok(Self::External),
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
            Self::External => "external",
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
///
/// The proxy password is wrapped in [`Zeroizing`] so that heap memory is
/// overwritten with zeros when the value is dropped, and the custom [`Debug`]
/// implementation redacts it from log output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
    /// Optional proxy password (zeroized on drop).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_zeroizing_string",
        deserialize_with = "deserialize_optional_zeroizing_string"
    )]
    #[schema(value_type = Option<String>)]
    pub password: Option<Zeroizing<String>>,
}

impl fmt::Debug for HttpListenerProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpListenerProxyConfig")
            .field("enabled", &self.enabled)
            .field("proxy_type", &self.proxy_type)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .finish()
    }
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

/// External C2 bridge listener configuration.
///
/// External listeners register a path on the teamserver's main HTTP port.
/// Third-party C2 transports relay agent traffic through this endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExternalListenerConfig {
    /// Listener display name.
    pub name: String,
    /// HTTP path registered on the teamserver (e.g., `"/bridge"`).
    pub endpoint: String,
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
    /// External C2 bridge listener settings.
    External(ExternalListenerConfig),
}

impl ListenerConfig {
    /// Return the listener display name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Http(config) => &config.name,
            Self::Smb(config) => &config.name,
            Self::Dns(config) => &config.name,
            Self::External(config) => &config.name,
        }
    }

    /// Return the listener protocol family.
    #[must_use]
    pub const fn protocol(&self) -> ListenerProtocol {
        match self {
            Self::Http(_) => ListenerProtocol::Http,
            Self::Smb(_) => ListenerProtocol::Smb,
            Self::Dns(_) => ListenerProtocol::Dns,
            Self::External(_) => ListenerProtocol::External,
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

impl From<ExternalListenerConfig> for ListenerConfig {
    fn from(config: ExternalListenerConfig) -> Self {
        Self::External(config)
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

fn serialize_optional_zeroizing_string<S: Serializer>(
    value: &Option<Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(s) => serializer.serialize_some(s.as_str()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_zeroizing_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.map(Zeroizing::new))
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

    use zeroize::Zeroizing;

    use super::{
        AgentEncryptionInfo, AgentRecord, BASE64_STANDARD, DnsListenerConfig,
        ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
        HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, ListenerTlsConfig,
        OperatorInfo, SmbListenerConfig, parse_agent_id,
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
    fn listener_protocol_as_str_returns_canonical_labels() {
        assert_eq!(ListenerProtocol::Http.as_str(), "http");
        assert_eq!(ListenerProtocol::Smb.as_str(), "smb");
        assert_eq!(ListenerProtocol::Dns.as_str(), "dns");
    }

    #[test]
    fn listener_protocol_display_uses_canonical_label() {
        assert_eq!(ListenerProtocol::Http.to_string(), "http");
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
    fn listener_protocol_accepts_external() {
        assert_eq!(
            ListenerProtocol::try_from_str("external").expect("external should be supported"),
            ListenerProtocol::External,
        );
        assert_eq!(ListenerProtocol::External.as_str(), "external");
        assert_eq!(ListenerProtocol::External.to_string(), "external");
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
                password: Some(Zeroizing::new("pass".to_string())),
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
    fn name_id_returns_eight_zero_chars_for_agent_id_zero() {
        let mut record = minimal_agent_record();
        record.agent_id = 0;
        assert_eq!(record.name_id(), "00000000");
    }

    #[test]
    fn name_id_returns_ffffffff_for_agent_id_u32_max() {
        let mut record = minimal_agent_record();
        record.agent_id = u32::MAX;
        assert_eq!(record.name_id(), "FFFFFFFF");
    }

    #[test]
    fn name_id_returns_zero_padded_string_for_agent_id_one() {
        let mut record = minimal_agent_record();
        record.agent_id = 1;
        assert_eq!(record.name_id(), "00000001");
    }

    /// Helper: builds a valid `AgentRecord` JSON value, then applies overrides.
    fn agent_record_json(overrides: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
            "AgentID": "ABCD1234",
            "Active": true,
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
        if let (Some(base_map), Some(over_map)) = (base.as_object_mut(), overrides.as_object()) {
            for (k, v) in over_map {
                base_map.insert(k.clone(), v.clone());
            }
        }
        base
    }

    #[test]
    fn agent_encryption_rejects_invalid_base64_aes_key() {
        let payload = agent_record_json(json!({
            "Encryption": {
                "AESKey": "%%%not-base64%%%",
                "AESIv": "aXY="
            }
        }));

        let error = serde_json::from_value::<AgentRecord>(payload)
            .expect_err("invalid base64 AESKey must fail");
        let msg = error.to_string().to_lowercase();
        assert!(
            msg.contains("base64") || msg.contains("invalid"),
            "error should mention base64 or invalid, got: {msg}"
        );
    }

    #[test]
    fn agent_encryption_rejects_invalid_base64_aes_iv() {
        let payload = agent_record_json(json!({
            "Encryption": {
                "AESKey": "YWVzLWtleQ==",
                "AESIv": "%%%not-base64%%%"
            }
        }));

        let error = serde_json::from_value::<AgentRecord>(payload)
            .expect_err("invalid base64 AESIv must fail");
        let msg = error.to_string().to_lowercase();
        assert!(
            msg.contains("base64") || msg.contains("invalid"),
            "error should mention base64 or invalid, got: {msg}"
        );
    }

    #[test]
    fn agent_encryption_accepts_empty_base64_strings() -> Result<(), Box<dyn std::error::Error>> {
        let payload = agent_record_json(json!({
            "Encryption": {
                "AESKey": "",
                "AESIv": ""
            }
        }));

        let record: AgentRecord = serde_json::from_value(payload)?;
        assert!(record.encryption.aes_key.is_empty(), "empty base64 should decode to empty bytes");
        assert!(record.encryption.aes_iv.is_empty(), "empty base64 should decode to empty bytes");
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
    fn operator_info_serializes_canonical_username_and_round_trips()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = OperatorInfo {
            username: "michel".to_string(),
            password_hash: Some("abc123".to_string()),
            role: Some("admin".to_string()),
            online: true,
            last_seen: Some("09/03/2026 19:05:00".to_string()),
        };

        let serialized = serde_json::to_value(&original)?;
        assert_eq!(serialized.get("Username"), Some(&json!("michel")));
        assert_eq!(serialized.get("User"), None);

        let from_username: OperatorInfo = serde_json::from_value(json!({
            "Username": "michel",
            "PasswordHash": "abc123",
            "Role": "admin",
            "Online": true,
            "LastSeen": "09/03/2026 19:05:00"
        }))?;
        assert_eq!(from_username, original);

        let from_user_alias: OperatorInfo = serde_json::from_value(json!({
            "User": "michel",
            "PasswordHash": "abc123",
            "Role": "admin",
            "Online": true,
            "LastSeen": "09/03/2026 19:05:00"
        }))?;
        assert_eq!(from_user_alias, original);

        let round_trip: OperatorInfo = serde_json::from_value(serialized)?;
        assert_eq!(round_trip, original);
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
    fn proxy_password_debug_is_redacted() {
        let proxy = HttpListenerProxyConfig {
            enabled: true,
            proxy_type: None,
            host: "127.0.0.1".to_string(),
            port: 8080,
            username: None,
            password: Some(Zeroizing::new("super-secret".to_string())),
        };
        let debug_output = format!("{proxy:?}");
        assert!(
            !debug_output.contains("super-secret"),
            "proxy password must not appear in Debug output: {debug_output}"
        );
        assert!(
            debug_output.contains("[redacted]"),
            "Debug output must contain [redacted]: {debug_output}"
        );
    }

    #[test]
    fn agent_encryption_info_debug_redacts_key_material() {
        use base64::Engine as _;

        let key_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let iv_bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x05, 0x06, 0x07, 0x08];
        let key_b64 = BASE64_STANDARD.encode(&key_bytes);
        let iv_b64 = BASE64_STANDARD.encode(&iv_bytes);

        let info = AgentEncryptionInfo {
            aes_key: Zeroizing::new(key_bytes),
            aes_iv: Zeroizing::new(iv_bytes),
        };
        let debug_output = format!("{info:?}");

        assert!(
            debug_output.contains("[redacted]"),
            "Debug output must contain [redacted]: {debug_output}"
        );
        assert!(
            !debug_output.contains(&key_b64),
            "Debug output must not contain base64 key: {debug_output}"
        );
        assert!(
            !debug_output.contains(&iv_b64),
            "Debug output must not contain base64 IV: {debug_output}"
        );
        // Verify raw byte sequences don't leak either (e.g. as [222, 173, ...])
        assert!(
            !debug_output.contains("222"),
            "Debug output must not contain raw key bytes: {debug_output}"
        );
        assert!(
            !debug_output.contains("202"),
            "Debug output must not contain raw IV bytes: {debug_output}"
        );
    }

    #[test]
    fn proxy_password_round_trips_through_serde() -> Result<(), Box<dyn std::error::Error>> {
        let proxy = HttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("http".to_string()),
            host: "127.0.0.1".to_string(),
            port: 8080,
            username: Some("user".to_string()),
            password: Some(Zeroizing::new("secret".to_string())),
        };
        let json = serde_json::to_value(&proxy)?;
        assert_eq!(json["password"], "secret");
        let decoded: HttpListenerProxyConfig = serde_json::from_value(json)?;
        assert_eq!(decoded.password.as_ref().map(|s| s.as_str()), Some("secret"));
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
    fn external_listener_config_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let original = ListenerConfig::from(ExternalListenerConfig {
            name: "bridge".to_string(),
            endpoint: "/svc".to_string(),
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

    /// Helper: builds a minimal valid `HttpListenerConfig` JSON, then applies overrides.
    fn http_listener_json(overrides: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
            "name": "edge",
            "hosts": [],
            "host_bind": "0.0.0.0",
            "host_rotation": "round-robin",
            "port_bind": 443,
            "behind_redirector": false,
            "headers": [],
            "uris": [],
            "secure": false
        });
        if let (Some(base_map), Some(over_map)) = (base.as_object_mut(), overrides.as_object()) {
            for (k, v) in over_map {
                base_map.insert(k.clone(), v.clone());
            }
        }
        base
    }

    #[test]
    fn port_bind_rejects_string_value_above_u16_max() {
        let payload = http_listener_json(json!({ "port_bind": "70000" }));
        let error = serde_json::from_value::<HttpListenerConfig>(payload)
            .expect_err("string port_bind \"70000\" must be rejected");
        assert!(
            error.to_string().contains("does not fit in u16"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn port_bind_rejects_value_99999_above_u16_max() {
        let payload = http_listener_json(json!({ "port_bind": 99999 }));
        let error = serde_json::from_value::<HttpListenerConfig>(payload)
            .expect_err("port_bind 99999 must be rejected");
        assert!(
            error.to_string().contains("does not fit in u16"),
            "unexpected error message: {error}"
        );
    }

    #[test]
    fn port_bind_accepts_zero() {
        let payload = http_listener_json(json!({ "port_bind": 0 }));
        let config: HttpListenerConfig =
            serde_json::from_value(payload).expect("port_bind 0 must be accepted");
        assert_eq!(config.port_bind, 0);
    }

    #[test]
    fn port_bind_accepts_string_zero() {
        let payload = http_listener_json(json!({ "port_bind": "0" }));
        let config: HttpListenerConfig =
            serde_json::from_value(payload).expect("string port_bind \"0\" must be accepted");
        assert_eq!(config.port_bind, 0);
    }

    #[test]
    fn port_bind_trims_whitespace_from_string() {
        let payload = http_listener_json(json!({ "port_bind": " 443 " }));
        let config: HttpListenerConfig =
            serde_json::from_value(payload).expect("whitespace-padded port_bind must be accepted");
        assert_eq!(config.port_bind, 443);
    }

    fn minimal_agent_record() -> AgentRecord {
        use zeroize::Zeroizing;
        AgentRecord {
            agent_id: 0xABCD1234,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: crate::AgentEncryptionInfo {
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
        // Serialise then re-inject the encryption blob manually.
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
        record.encryption = crate::AgentEncryptionInfo::default();
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
        // Use non-default values for fields with custom serde logic.
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
        expected.encryption = crate::AgentEncryptionInfo::default();

        assert_eq!(deserialized, expected);
        Ok(())
    }

    #[test]
    fn agent_record_round_trip_with_none_optional_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut record = minimal_agent_record();
        record.encryption = crate::AgentEncryptionInfo::default();
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
        record.encryption = crate::AgentEncryptionInfo::default();
        record.active = false;
        record.elevated = false;

        let serialized = serde_json::to_value(&record)?;
        let deserialized: AgentRecord = serde_json::from_value(serialized)?;

        assert_eq!(deserialized.active, false);
        assert_eq!(deserialized.elevated, false);
        assert_eq!(deserialized, record);
        Ok(())
    }

    #[test]
    fn agent_record_round_trip_preserves_zero_numeric_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut record = minimal_agent_record();
        record.encryption = crate::AgentEncryptionInfo::default();
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
        record.encryption = crate::AgentEncryptionInfo::default();
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
