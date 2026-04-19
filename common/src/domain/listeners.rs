//! Listener protocol, configuration, and kill-date types.

use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::error::CommonError;

use super::serde_helpers::{deserialize_optional_u16_from_any, deserialize_u16_from_any};

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

/// Parse a KillDate string into a unix epoch (seconds).
///
/// Accepts two representations:
/// 1. A plain decimal integer (unix timestamp).
/// 2. A human-readable datetime `"YYYY-MM-DD HH:MM:SS"` (interpreted as UTC).
///
/// Returns [`CommonError::InvalidKillDate`] for any other format.
pub fn parse_kill_date_to_epoch(value: &str) -> Result<i64, CommonError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CommonError::InvalidKillDate { value: value.to_string() });
    }

    // Try plain integer first (fast path).
    if let Ok(ts) = value.parse::<i64>() {
        return Ok(ts);
    }

    // Try human-readable datetime "YYYY-MM-DD HH:MM:SS" (UTC).
    let format = time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]")
        .map_err(|_| CommonError::InvalidKillDate { value: value.to_string() })?;
    let dt = time::PrimitiveDateTime::parse(value, &format)
        .map_err(|_| CommonError::InvalidKillDate { value: value.to_string() })?;
    Ok(dt.assume_utc().unix_timestamp())
}

/// Validate and normalise an optional KillDate value.
///
/// If the input is `None` or an empty/whitespace-only string, returns `Ok(None)`.
/// Otherwise parses the value (accepting both formats described in
/// [`parse_kill_date_to_epoch`]) and returns the normalised unix-timestamp string.
///
/// This should be called at config ingress (profile parsing and operator
/// requests) so that downstream consumers always receive a numeric timestamp
/// string.
pub fn validate_kill_date(value: Option<&str>) -> Result<Option<String>, CommonError> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let epoch = parse_kill_date_to_epoch(raw)?;
    Ok(Some(epoch.to_string()))
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::*;
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
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
        });

        assert_eq!(config.name(), "edge");
        assert_eq!(config.protocol(), ListenerProtocol::Http);
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
    fn proxy_password_none_round_trips_through_serde() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::json!({
            "enabled": false,
            "host": "proxy.local",
            "port": 3128
        });
        let decoded: HttpListenerProxyConfig = serde_json::from_value(json)?;
        assert!(decoded.password.is_none());
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
            kill_date: Some("1798761599".to_string()),
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

    // ── parse_kill_date_to_epoch tests ──────────────────────────────────────

    #[test]
    fn parse_kill_date_to_epoch_accepts_unix_timestamp() {
        assert_eq!(parse_kill_date_to_epoch("1773086400").expect("unwrap"), 1773086400);
    }

    #[test]
    fn parse_kill_date_to_epoch_accepts_zero() {
        assert_eq!(parse_kill_date_to_epoch("0").expect("unwrap"), 0);
    }

    #[test]
    fn parse_kill_date_to_epoch_accepts_negative() {
        assert_eq!(parse_kill_date_to_epoch("-1").expect("unwrap"), -1);
    }

    #[test]
    fn parse_kill_date_to_epoch_accepts_human_readable_datetime() {
        // "2026-03-09 20:00:00" UTC
        assert_eq!(parse_kill_date_to_epoch("2026-03-09 20:00:00").expect("unwrap"), 1773086400);
    }

    #[test]
    fn parse_kill_date_to_epoch_rejects_empty() {
        assert!(parse_kill_date_to_epoch("").is_err());
        assert!(parse_kill_date_to_epoch("   ").is_err());
    }

    #[test]
    fn parse_kill_date_to_epoch_rejects_garbage() {
        let err = parse_kill_date_to_epoch("not-a-date");
        assert!(matches!(err, Err(CommonError::InvalidKillDate { .. })));
    }

    #[test]
    fn parse_kill_date_to_epoch_rejects_wrong_datetime_format() {
        // Missing seconds
        assert!(parse_kill_date_to_epoch("2026-03-09 20:00").is_err());
        // ISO 8601 with T separator
        assert!(parse_kill_date_to_epoch("2026-03-09T20:00:00").is_err());
    }

    // ── validate_kill_date tests ────────────────────────────────────────────

    #[test]
    fn validate_kill_date_returns_none_for_absent() {
        assert_eq!(validate_kill_date(None).expect("unwrap"), None);
    }

    #[test]
    fn validate_kill_date_returns_none_for_empty() {
        assert_eq!(validate_kill_date(Some("")).expect("unwrap"), None);
        assert_eq!(validate_kill_date(Some("   ")).expect("unwrap"), None);
    }

    #[test]
    fn validate_kill_date_normalises_to_timestamp_string() {
        assert_eq!(
            validate_kill_date(Some("2026-03-09 20:00:00")).expect("unwrap"),
            Some("1773086400".to_string())
        );
        assert_eq!(
            validate_kill_date(Some("1773086400")).expect("unwrap"),
            Some("1773086400".to_string())
        );
    }

    #[test]
    fn validate_kill_date_rejects_garbage() {
        assert!(validate_kill_date(Some("garbage")).is_err());
    }
}
