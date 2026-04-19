//! Listener blocks deserialised from the YAOTL profile (HTTP, SMB, DNS, external).

use std::fmt;

use serde::Deserialize;
use zeroize::Zeroizing;

/// Listener definitions grouped by transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct ListenersConfig {
    /// HTTP(S) listeners.
    #[serde(
        rename = "Http",
        default,
        deserialize_with = "crate::config::serde_helpers::deserialize_one_or_many"
    )]
    pub http: Vec<ProfileHttpListenerConfig>,
    /// SMB listeners.
    #[serde(
        rename = "Smb",
        default,
        deserialize_with = "crate::config::serde_helpers::deserialize_one_or_many"
    )]
    pub smb: Vec<SmbListenerConfig>,
    /// External connector listeners.
    #[serde(
        rename = "External",
        default,
        deserialize_with = "crate::config::serde_helpers::deserialize_one_or_many"
    )]
    pub external: Vec<ExternalListenerConfig>,
    /// DNS C2 listeners.
    #[serde(
        rename = "Dns",
        default,
        deserialize_with = "crate::config::serde_helpers::deserialize_one_or_many"
    )]
    pub dns: Vec<DnsListenerConfig>,
}

/// Havoc HTTP listener profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProfileHttpListenerConfig {
    /// Display name of the listener.
    #[serde(rename = "Name")]
    pub name: String,
    /// Callback hosts advertised to the agent.
    #[serde(rename = "Hosts")]
    pub hosts: Vec<String>,
    /// Address the server binds locally.
    #[serde(rename = "HostBind")]
    pub host_bind: String,
    /// Host rotation strategy.
    #[serde(rename = "HostRotation")]
    pub host_rotation: String,
    /// Local bind port.
    #[serde(rename = "PortBind")]
    pub port_bind: u16,
    /// Remote connect port used by agents.
    #[serde(rename = "PortConn", default)]
    pub port_conn: Option<u16>,
    /// Optional kill date.
    #[serde(rename = "KillDate", default)]
    pub kill_date: Option<String>,
    /// Optional working-hours restriction.
    #[serde(rename = "WorkingHours", default)]
    pub working_hours: Option<String>,
    /// Optional HTTP method override.
    #[serde(rename = "Method", default)]
    pub method: Option<String>,
    /// Optional user-agent string.
    #[serde(rename = "UserAgent", default)]
    pub user_agent: Option<String>,
    /// Optional override for the HTTP Host header.
    #[serde(rename = "HostHeader", default)]
    pub host_header: Option<String>,
    /// Optional additional request headers.
    #[serde(rename = "Headers", default)]
    pub headers: Vec<String>,
    /// Optional URI list.
    #[serde(rename = "Uris", default)]
    pub uris: Vec<String>,
    /// Whether TLS is enabled.
    #[serde(rename = "Secure", default)]
    pub secure: bool,
    /// Optional TLS certificate paths.
    #[serde(rename = "Cert", default)]
    pub cert: Option<HttpListenerCertConfig>,
    /// Optional response header customization.
    #[serde(rename = "Response", default)]
    pub response: Option<HclHttpListenerResponseConfig>,
    /// Optional upstream proxy settings.
    #[serde(rename = "Proxy", default)]
    pub proxy: Option<HclHttpListenerProxyConfig>,
    /// Whether to randomize the TLS JA3 fingerprint.
    ///
    /// Defaults to `true` for HTTPS listeners when absent.
    #[serde(rename = "Ja3Randomize", default)]
    pub ja3_randomize: Option<bool>,
    /// ARC-08: authoritative C2 domain for DNS-over-HTTPS fallback transport.
    #[serde(rename = "DoHDomain", default)]
    pub doh_domain: Option<String>,
    /// ARC-08: DoH provider — `"cloudflare"` (default) or `"google"`.
    #[serde(rename = "DoHProvider", default)]
    pub doh_provider: Option<String>,
    /// Legacy mode — accept Demon `0xDEADBEEF` packets (default `false`).
    #[serde(rename = "LegacyMode", default)]
    pub legacy_mode: bool,
}

/// SMB pivot listener configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SmbListenerConfig {
    /// Display name of the listener.
    #[serde(rename = "Name")]
    pub name: String,
    /// Named pipe used for peer traffic.
    #[serde(rename = "PipeName")]
    pub pipe_name: String,
    /// Optional kill date.
    #[serde(rename = "KillDate", default)]
    pub kill_date: Option<String>,
    /// Optional working-hours restriction.
    #[serde(rename = "WorkingHours", default)]
    pub working_hours: Option<String>,
}

/// External listener/service bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExternalListenerConfig {
    /// Display name of the listener.
    #[serde(rename = "Name")]
    pub name: String,
    /// External service endpoint.
    #[serde(rename = "Endpoint")]
    pub endpoint: String,
}

/// DNS C2 listener profile configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnsListenerConfig {
    /// Display name of the listener.
    #[serde(rename = "Name")]
    pub name: String,
    /// Local interface to bind (default `0.0.0.0`).
    #[serde(rename = "HostBind", default = "default_all_interfaces")]
    pub host_bind: String,
    /// UDP port to listen on (default 53).
    #[serde(rename = "PortBind")]
    pub port_bind: u16,
    /// C2 domain suffix handled by this listener (e.g., `c2.example.com`).
    #[serde(rename = "Domain")]
    pub domain: String,
    /// Enabled DNS record types for C2 (e.g., `["TXT", "A"]`).
    #[serde(rename = "RecordTypes", default)]
    pub record_types: Vec<String>,
    /// Optional kill date.
    #[serde(rename = "KillDate", default)]
    pub kill_date: Option<String>,
    /// Optional working-hours restriction.
    #[serde(rename = "WorkingHours", default)]
    pub working_hours: Option<String>,
}

fn default_all_interfaces() -> String {
    "0.0.0.0".to_owned()
}

/// TLS material for an HTTP listener.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HttpListenerCertConfig {
    /// PEM certificate path.
    #[serde(rename = "Cert")]
    pub cert: String,
    /// PEM private key path.
    #[serde(rename = "Key")]
    pub key: String,
}

/// Static headers applied to HTTP listener responses (HCL profile shape).
///
/// This type deserializes the PascalCase HCL profile format. Use
/// [`Into<crate::HttpListenerResponseConfig>`] to convert to the canonical
/// domain type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HclHttpListenerResponseConfig {
    /// HTTP response headers.
    #[serde(rename = "Headers", default)]
    pub headers: Vec<String>,
    /// Optional static response body.
    #[serde(rename = "Body", default)]
    pub body: Option<String>,
}

impl From<HclHttpListenerResponseConfig> for crate::HttpListenerResponseConfig {
    fn from(hcl: HclHttpListenerResponseConfig) -> Self {
        Self { headers: hcl.headers, body: hcl.body }
    }
}

/// Upstream proxy settings for HTTP listeners (HCL profile shape).
///
/// This type deserializes the PascalCase HCL profile format. Use
/// [`Into<crate::HttpListenerProxyConfig>`] to convert to the canonical domain
/// type. The conversion sets `enabled` to `true` and `proxy_type` to `"http"`
/// since presence in the HCL profile implies an enabled HTTP proxy.
///
/// The proxy password is wrapped in [`Zeroizing`] so that heap memory is
/// overwritten with zeros when the value is dropped.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct HclHttpListenerProxyConfig {
    /// Proxy hostname.
    #[serde(rename = "Host")]
    pub host: String,
    /// Proxy port.
    #[serde(rename = "Port")]
    pub port: u16,
    /// Optional proxy username.
    #[serde(rename = "Username", default)]
    pub username: Option<String>,
    /// Optional proxy password (zeroized on drop).
    #[serde(
        rename = "Password",
        default,
        deserialize_with = "crate::config::serde_helpers::deserialize_optional_zeroizing_string"
    )]
    pub password: Option<Zeroizing<String>>,
}

impl From<HclHttpListenerProxyConfig> for crate::HttpListenerProxyConfig {
    fn from(hcl: HclHttpListenerProxyConfig) -> Self {
        Self {
            enabled: true,
            proxy_type: Some("http".to_owned()),
            host: hcl.host,
            port: hcl.port,
            username: hcl.username,
            password: hcl.password,
        }
    }
}

impl fmt::Debug for HclHttpListenerProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HclHttpListenerProxyConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}
