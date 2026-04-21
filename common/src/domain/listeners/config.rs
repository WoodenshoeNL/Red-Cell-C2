//! Listener configuration structs for each transport family.

use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::domain::serde_helpers::{deserialize_optional_u16_from_any, deserialize_u16_from_any};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Whether to randomize the TLS JA3/JA3S fingerprint on each HTTPS
    /// connection (Archon ARC-06).  When `None` the payload builder defaults
    /// to `true` for HTTPS listeners and `false` for plain HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3_randomize: Option<bool>,
    /// Authoritative C2 domain for ARC-08 DNS-over-HTTPS fallback transport.
    /// When set, Archon will fall back to DoH if the primary HTTP transport
    /// fails.  `None` disables the DoH fallback entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_domain: Option<String>,
    /// DoH provider selection for ARC-08.  `"cloudflare"` (default) or
    /// `"google"`.  Ignored when `doh_domain` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_provider: Option<String>,
    /// Whether this listener runs in legacy (Demon-compatible) mode.
    ///
    /// When `true` the listener accepts packets bearing the `0xDEADBEEF` Havoc
    /// magic value and routes them through the Demon protocol path.  When
    /// `false` (the default) any packet whose bytes 4–7 equal `0xDEADBEEF` is
    /// silently rejected at the pre-filter stage, before any DB look-up, so
    /// that new-protocol listeners carry no plaintext fingerprint.
    #[serde(default)]
    pub legacy_mode: bool,
    /// Suppress opsec-risk warnings at listener startup.
    ///
    /// Set to `true` only for intentional test deployments where the default
    /// port, User-Agent, or self-signed certificate are known and acceptable.
    #[serde(default)]
    pub suppress_opsec_warnings: bool,
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
    /// Suppress opsec-risk warnings at listener startup.
    ///
    /// Set to `true` only for intentional test deployments where the default
    /// port is known and acceptable.
    #[serde(default)]
    pub suppress_opsec_warnings: bool,
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
