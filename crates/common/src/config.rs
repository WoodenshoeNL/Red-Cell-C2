//! Havoc-compatible teamserver profile parsing.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// A full Havoc/Red Cell YAOTL profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Profile {
    /// Teamserver network and build settings.
    #[serde(rename = "Teamserver")]
    pub teamserver: TeamserverConfig,
    /// Operator accounts keyed by username.
    #[serde(rename = "Operators")]
    pub operators: OperatorsConfig,
    /// Listener definitions grouped by transport type.
    #[serde(rename = "Listeners", default)]
    pub listeners: ListenersConfig,
    /// Demon default settings used during payload generation.
    #[serde(rename = "Demon")]
    pub demon: DemonConfig,
    /// Optional service API configuration.
    #[serde(rename = "Service", default)]
    pub service: Option<ServiceConfig>,
    /// Optional REST API configuration.
    #[serde(rename = "Api", default)]
    pub api: Option<ApiConfig>,
    /// Optional outbound webhook configuration.
    #[serde(rename = "WebHook", default)]
    pub webhook: Option<WebHookConfig>,
}

impl Profile {
    /// Parse a profile from HCL/YAOTL text.
    pub fn parse(input: &str) -> Result<Self, ProfileError> {
        hcl::from_str(input).map_err(ProfileError::from)
    }

    /// Parse a profile from any readable input stream.
    pub fn from_reader(reader: impl Read) -> Result<Self, ProfileError> {
        hcl::from_reader(reader).map_err(ProfileError::from)
    }

    /// Parse a profile from a filesystem path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let path = path.as_ref();
        let input = fs::read_to_string(path)
            .map_err(|source| ProfileError::Read { path: path.display().to_string(), source })?;

        Self::parse(&input)
    }

    /// Validate the parsed profile for required fields and structural consistency.
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        let mut errors = Vec::new();

        if self.teamserver.host.trim().is_empty() {
            errors.push("Teamserver.Host must not be empty".to_owned());
        }

        if self.teamserver.port == 0 {
            errors.push("Teamserver.Port must be greater than zero".to_owned());
        }

        if self
            .teamserver
            .plugins_dir
            .as_deref()
            .is_some_and(|plugins_dir| plugins_dir.trim().is_empty())
        {
            errors.push("Teamserver.PluginsDir must not be empty when specified".to_owned());
        }

        if self.operators.users.is_empty() {
            errors.push("Operators must define at least one user".to_owned());
        }

        for (username, operator) in &self.operators.users {
            if username.trim().is_empty() {
                errors.push("Operators.user labels must not be empty".to_owned());
            }

            if operator.password.trim().is_empty() {
                errors.push(format!(
                    "Operators.user \"{username}\" must define a non-empty Password"
                ));
            }
        }

        for listener in &self.listeners.http {
            if listener.name.trim().is_empty() {
                errors.push("Listeners.Http.Name must not be empty".to_owned());
            }

            if listener.host_bind.trim().is_empty() {
                errors.push(format!("Listeners.Http \"{}\" must define HostBind", listener.name));
            }

            if listener.hosts.is_empty() {
                errors.push(format!(
                    "Listeners.Http \"{}\" must define at least one Hosts entry",
                    listener.name
                ));
            }

            if listener.port_bind == 0 {
                errors.push(format!(
                    "Listeners.Http \"{}\" must define a PortBind greater than zero",
                    listener.name
                ));
            }

            if listener.host_rotation.trim().is_empty() {
                errors
                    .push(format!("Listeners.Http \"{}\" must define HostRotation", listener.name));
            }

            if let Some(cert) = &listener.cert {
                if cert.cert.trim().is_empty() || cert.key.trim().is_empty() {
                    errors.push(format!(
                        "Listeners.Http \"{}\" must define non-empty Cert and Key paths",
                        listener.name
                    ));
                }
            }
        }

        for listener in &self.listeners.smb {
            if listener.name.trim().is_empty() {
                errors.push("Listeners.Smb.Name must not be empty".to_owned());
            }

            if listener.pipe_name.trim().is_empty() {
                errors.push(format!("Listeners.Smb \"{}\" must define PipeName", listener.name));
            }
        }

        for listener in &self.listeners.external {
            if listener.name.trim().is_empty() {
                errors.push("Listeners.External.Name must not be empty".to_owned());
            }

            if listener.endpoint.trim().is_empty() {
                errors
                    .push(format!("Listeners.External \"{}\" must define Endpoint", listener.name));
            }
        }

        for listener in &self.listeners.dns {
            if listener.name.trim().is_empty() {
                errors.push("Listeners.Dns.Name must not be empty".to_owned());
            }

            if listener.domain.trim().is_empty() {
                errors.push(format!("Listeners.Dns \"{}\" must define Domain", listener.name));
            }

            if listener.port_bind == 0 {
                errors.push(format!(
                    "Listeners.Dns \"{}\" must define a PortBind greater than zero",
                    listener.name
                ));
            }
        }

        if let Some(service) = &self.service {
            if service.endpoint.trim().is_empty() {
                errors.push("Service.Endpoint must not be empty".to_owned());
            }

            if service.password.trim().is_empty() {
                errors.push("Service.Password must not be empty".to_owned());
            }
        }

        if let Some(api) = &self.api {
            if api.keys.is_empty() {
                errors.push("Api must define at least one key".to_owned());
            }

            if api.rate_limit_per_minute == 0 {
                errors.push("Api.RateLimitPerMinute must be greater than zero".to_owned());
            }

            for (name, key) in &api.keys {
                if name.trim().is_empty() {
                    errors.push("Api.key labels must not be empty".to_owned());
                }

                if key.value.trim().is_empty() {
                    errors.push(format!("Api.key \"{name}\" must define a non-empty Value"));
                }
            }
        }

        if let Some(webhook) = &self.webhook
            && let Some(discord) = &webhook.discord
            && discord.url.trim().is_empty()
        {
            errors.push("WebHook.Discord.Url must not be empty".to_owned());
        }

        if errors.is_empty() { Ok(()) } else { Err(ProfileValidationError { errors }) }
    }
}

/// Errors returned while parsing a YAOTL profile.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// The underlying HCL parser or deserializer rejected the input.
    #[error("failed to parse YAOTL profile: {0}")]
    Parse(#[from] hcl::Error),
    /// The profile file could not be read from disk.
    #[error("failed to read YAOTL profile from {path}: {source}")]
    Read {
        /// Filesystem path that could not be read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Validation failures reported for a parsed profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("profile validation failed: {0}", .errors.join("; "))]
pub struct ProfileValidationError {
    /// Human-readable validation failures.
    pub errors: Vec<String>,
}

/// Teamserver bind settings and payload build tooling.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TeamserverConfig {
    /// Host address to bind the teamserver to.
    #[serde(rename = "Host")]
    pub host: String,
    /// TCP port for the teamserver listener.
    #[serde(rename = "Port")]
    pub port: u16,
    /// Optional directory containing Python plugin modules.
    #[serde(rename = "PluginsDir", default)]
    pub plugins_dir: Option<String>,
    /// Optional build toolchain settings.
    #[serde(rename = "Build", default)]
    pub build: Option<BuildConfig>,
}

/// Cross-compilation toolchain settings used for Demon builds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BuildConfig {
    /// 64-bit MinGW compiler path.
    #[serde(rename = "Compiler64", default)]
    pub compiler64: Option<String>,
    /// 32-bit MinGW compiler path.
    #[serde(rename = "Compiler86", default)]
    pub compiler86: Option<String>,
    /// NASM executable path.
    #[serde(rename = "Nasm", default)]
    pub nasm: Option<String>,
}

/// Operator accounts defined in the profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OperatorsConfig {
    /// Operators keyed by their block label.
    #[serde(rename = "user", default)]
    pub users: BTreeMap<String, OperatorConfig>,
}

/// A single operator account definition.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OperatorConfig {
    /// Operator password.
    #[serde(rename = "Password")]
    pub password: String,
    /// Operator role used by the teamserver RBAC layer.
    #[serde(rename = "Role", default)]
    pub role: OperatorRole,
}

/// Role assigned to an operator account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum OperatorRole {
    /// Full teamserver access.
    #[default]
    #[serde(rename = "Admin", alias = "admin")]
    Admin,
    /// Can task agents and manage listeners.
    #[serde(rename = "Operator", alias = "operator")]
    Operator,
    /// Read-only access for agents, sessions, and loot.
    #[serde(rename = "Analyst", alias = "analyst")]
    Analyst,
}

/// Listener definitions grouped by transport.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct ListenersConfig {
    /// HTTP(S) listeners.
    #[serde(rename = "Http", default, deserialize_with = "deserialize_one_or_many")]
    pub http: Vec<HttpListenerConfig>,
    /// SMB listeners.
    #[serde(rename = "Smb", default, deserialize_with = "deserialize_one_or_many")]
    pub smb: Vec<SmbListenerConfig>,
    /// External connector listeners.
    #[serde(rename = "External", default, deserialize_with = "deserialize_one_or_many")]
    pub external: Vec<ExternalListenerConfig>,
    /// DNS C2 listeners.
    #[serde(rename = "Dns", default, deserialize_with = "deserialize_one_or_many")]
    pub dns: Vec<DnsListenerConfig>,
}

/// Havoc HTTP listener profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HttpListenerConfig {
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
    pub response: Option<HttpListenerResponseConfig>,
    /// Optional upstream proxy settings.
    #[serde(rename = "Proxy", default)]
    pub proxy: Option<HttpListenerProxyConfig>,
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

/// Static headers applied to HTTP listener responses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HttpListenerResponseConfig {
    /// HTTP response headers.
    #[serde(rename = "Headers", default)]
    pub headers: Vec<String>,
    /// Optional static response body.
    #[serde(rename = "Body", default)]
    pub body: Option<String>,
}

/// Upstream proxy settings for HTTP listeners.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HttpListenerProxyConfig {
    /// Proxy hostname.
    #[serde(rename = "Host")]
    pub host: String,
    /// Proxy port.
    #[serde(rename = "Port")]
    pub port: u16,
    /// Optional proxy username.
    #[serde(rename = "Username", default)]
    pub username: Option<String>,
    /// Optional proxy password.
    #[serde(rename = "Password", default)]
    pub password: Option<String>,
}

/// Demon build-time defaults and injection settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DemonConfig {
    /// Beacon sleep interval.
    #[serde(rename = "Sleep", default)]
    pub sleep: Option<u64>,
    /// Beacon jitter percentage.
    #[serde(rename = "Jitter", default)]
    pub jitter: Option<u8>,
    /// Enable indirect syscall dispatch.
    #[serde(rename = "IndirectSyscall", default)]
    pub indirect_syscall: bool,
    /// Enable stack duplication.
    #[serde(rename = "StackDuplication", default)]
    pub stack_duplication: bool,
    /// Sleep obfuscation technique name.
    #[serde(rename = "SleepTechnique", default)]
    pub sleep_technique: Option<String>,
    /// Proxy loading mode.
    #[serde(rename = "ProxyLoading", default)]
    pub proxy_loading: Option<String>,
    /// AMSI/ETW patching mode.
    #[serde(rename = "AmsiEtwPatching", default)]
    pub amsi_etw_patching: Option<String>,
    /// Process injection defaults.
    #[serde(rename = "Injection", default)]
    pub injection: Option<ProcessInjectionConfig>,
    /// Named pipe used for .NET output transport.
    #[serde(rename = "DotNetNamePipe", default)]
    pub dotnet_name_pipe: Option<String>,
    /// PE/loader binary customization.
    #[serde(rename = "Binary", default)]
    pub binary: Option<BinaryConfig>,
    /// Whether to trust `X-Forwarded-For`.
    #[serde(rename = "TrustXForwardedFor", default)]
    pub trust_x_forwarded_for: bool,
}

/// Spawn-to process defaults for injection.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProcessInjectionConfig {
    /// 64-bit spawn-to path.
    #[serde(rename = "Spawn64", default)]
    pub spawn64: Option<String>,
    /// 32-bit spawn-to path.
    #[serde(rename = "Spawn32", default)]
    pub spawn32: Option<String>,
}

/// Binary patching options for generated payloads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BinaryConfig {
    /// PE header overrides.
    #[serde(rename = "Header", default)]
    pub header: Option<HeaderConfig>,
    /// Replacement strings for x64 builds.
    #[serde(rename = "ReplaceStrings-x64", default)]
    pub replace_strings_x64: BTreeMap<String, String>,
    /// Replacement strings for x86 builds.
    #[serde(rename = "ReplaceStrings-x86", default)]
    pub replace_strings_x86: BTreeMap<String, String>,
}

/// PE header customization options.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HeaderConfig {
    /// DOS header magic for x64 payloads.
    #[serde(rename = "MagicMz-x64", default)]
    pub magic_mz_x64: Option<String>,
    /// DOS header magic for x86 payloads.
    #[serde(rename = "MagicMz-x86", default)]
    pub magic_mz_x86: Option<String>,
    /// Forced compile timestamp.
    #[serde(rename = "CompileTime", default)]
    pub compile_time: Option<String>,
    /// Image size override for x64 payloads.
    #[serde(rename = "ImageSize-x64", default)]
    pub image_size_x64: Option<u32>,
    /// Image size override for x86 payloads.
    #[serde(rename = "ImageSize-x86", default)]
    pub image_size_x86: Option<u32>,
}

/// Optional service bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServiceConfig {
    /// Service endpoint name or address.
    #[serde(rename = "Endpoint")]
    pub endpoint: String,
    /// Service shared secret.
    #[serde(rename = "Password")]
    pub password: String,
}

/// Optional REST API configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiConfig {
    /// API keys keyed by a stable identifier.
    #[serde(rename = "key", default)]
    pub keys: BTreeMap<String, ApiKeyConfig>,
    /// Maximum accepted requests per API key, per minute.
    #[serde(rename = "RateLimitPerMinute", default = "default_api_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self { keys: BTreeMap::new(), rate_limit_per_minute: default_api_rate_limit_per_minute() }
    }
}

/// A single REST API key definition.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiKeyConfig {
    /// The secret value accepted by the REST API.
    #[serde(rename = "Value")]
    pub value: String,
    /// RBAC role granted to requests using this key.
    #[serde(rename = "Role", default)]
    pub role: OperatorRole,
}

const fn default_api_rate_limit_per_minute() -> u32 {
    60
}

/// Outbound webhook settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WebHookConfig {
    /// Discord webhook integration.
    #[serde(rename = "Discord", default)]
    pub discord: Option<DiscordWebHookConfig>,
}

/// Discord webhook configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DiscordWebHookConfig {
    /// Webhook URL.
    #[serde(rename = "Url")]
    pub url: String,
    /// Optional avatar URL.
    #[serde(rename = "AvatarUrl", default)]
    pub avatar_url: Option<String>,
    /// Optional display name.
    #[serde(rename = "User", default)]
    pub user: Option<String>,
}

fn deserialize_one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }

    let Some(value) = Option::<OneOrMany<T>>::deserialize(deserializer)? else {
        return Ok(Vec::new());
    };

    Ok(match value {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base_havoc_profile() {
        let profile = Profile::parse(include_str!("../../../src/Havoc/profiles/havoc.yaotl"))
            .expect("sample profile should parse");

        assert_eq!(profile.teamserver.host, "0.0.0.0");
        assert_eq!(profile.teamserver.port, 40056);
        assert_eq!(
            profile.teamserver.build.as_ref().and_then(|build| build.nasm.as_deref()),
            Some("/usr/bin/nasm")
        );
        assert_eq!(profile.operators.users.len(), 2);
        assert_eq!(
            profile.operators.users.get("Neo").map(|operator| operator.password.as_str()),
            Some("password1234")
        );
        assert_eq!(
            profile.operators.users.get("Neo").map(|operator| operator.role),
            Some(OperatorRole::Admin)
        );
        assert_eq!(profile.demon.sleep, Some(2));
        assert_eq!(profile.demon.jitter, Some(15));
        assert!(!profile.demon.trust_x_forwarded_for);
        assert_eq!(
            profile.demon.injection.as_ref().and_then(|injection| injection.spawn64.as_deref()),
            Some("C:\\Windows\\System32\\notepad.exe")
        );
        assert!(profile.listeners.http.is_empty());
        assert!(profile.listeners.smb.is_empty());
        assert!(profile.listeners.external.is_empty());
        assert!(profile.service.is_some());
        assert!(profile.webhook.is_none());
    }

    #[test]
    fn parses_listener_profile() {
        let profile = Profile::parse(include_str!("../../../src/Havoc/profiles/http_smb.yaotl"))
            .expect("listener profile should parse");

        assert_eq!(profile.listeners.http.len(), 1);
        assert_eq!(profile.listeners.smb.len(), 1);

        let http_listener = &profile.listeners.http[0];
        assert_eq!(http_listener.name, "teams profile - http");
        assert_eq!(http_listener.hosts, vec!["5pider.net"]);
        assert_eq!(http_listener.host_bind, "0.0.0.0");
        assert_eq!(http_listener.host_rotation, "round-robin");
        assert_eq!(http_listener.port_bind, 443);
        assert_eq!(http_listener.port_conn, Some(443));
        assert!(!http_listener.secure);
        assert_eq!(http_listener.uris, vec!["/Collector/2.0/settings/"]);
        assert_eq!(http_listener.headers.len(), 7);
        assert_eq!(http_listener.response.as_ref().map(|response| response.headers.len()), Some(8));
        assert_eq!(
            http_listener.response.as_ref().and_then(|response| response.body.as_deref()),
            None
        );

        let smb_listener = &profile.listeners.smb[0];
        assert_eq!(smb_listener.name, "Pivot - Smb");
        assert_eq!(smb_listener.pipe_name, "demon_pipe");
    }

    #[test]
    fn parses_webhook_profile() {
        let profile =
            Profile::parse(include_str!("../../../src/Havoc/profiles/webhook_example.yaotl"))
                .expect("webhook profile should parse");

        let webhook = profile.webhook.and_then(|config| config.discord);
        assert_eq!(webhook.as_ref().map(|discord| discord.url.as_str()), Some("..."));
        assert_eq!(webhook.as_ref().and_then(|discord| discord.user.as_deref()), Some("Havoc"));
    }

    #[test]
    fn parses_listener_tls_certificate_paths() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "https listener"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                Secure = true

                Cert {
                  Cert = "/tmp/server.crt"
                  Key = "/tmp/server.key"
                }
              }
            }

            Demon {}
            "#,
        )
        .expect("inline HTTPS listener profile should parse");

        let listener = &profile.listeners.http[0];
        let cert = listener.cert.as_ref().expect("certificate block should be present");

        assert!(listener.secure);
        assert_eq!(cert.cert, "/tmp/server.crt");
        assert_eq!(cert.key, "/tmp/server.key");
    }

    #[test]
    fn parses_listener_response_body() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {
              Http {
                Name = "body listener"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080

                Response {
                  Headers = ["Server: nginx"]
                  Body = "{\"status\":\"ok\"}"
                }
              }
            }

            Demon {}
            "#,
        )
        .expect("inline listener profile should parse");

        let response =
            profile.listeners.http[0].response.as_ref().expect("response block should be present");

        assert_eq!(response.body.as_deref(), Some("{\"status\":\"ok\"}"));
    }

    #[test]
    fn parses_operator_roles_and_defaults_missing_roles_to_admin() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "admin" {
                Password = "adminpw"
              }

              user "operator" {
                Password = "operatorpw"
                Role = "Operator"
              }

              user "analyst" {
                Password = "analystpw"
                Role = "analyst"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile with roles should parse");

        assert_eq!(profile.operators.users["admin"].role, OperatorRole::Admin);
        assert_eq!(profile.operators.users["operator"].role, OperatorRole::Operator);
        assert_eq!(profile.operators.users["analyst"].role, OperatorRole::Analyst);
    }

    #[test]
    fn parses_from_reader() {
        let profile =
            Profile::from_reader(include_str!("../../../src/Havoc/data/havoc.yaotl").as_bytes())
                .expect("embedded data profile should parse");

        assert_eq!(profile.teamserver.port, 40056);
        assert_eq!(profile.demon.sleep, Some(2));
        assert!(profile.teamserver.build.is_none());
    }

    #[test]
    fn loads_profile_from_file() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let profile_path = temp_dir.path().join("profile.yaotl");

        std::fs::write(&profile_path, include_str!("../../../src/Havoc/profiles/havoc.yaotl"))
            .expect("profile fixture should be written");

        let profile = Profile::from_file(&profile_path).expect("profile should load from disk");

        assert_eq!(profile.teamserver.host, "0.0.0.0");
        assert_eq!(profile.teamserver.port, 40056);
    }

    #[test]
    fn validates_sample_profile() {
        let profile = Profile::parse(include_str!("../../../src/Havoc/profiles/havoc.yaotl"))
            .expect("sample profile should parse");

        assert!(profile.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_profile_configuration() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = ""
              Port = 0
            }

            Operators {}

            Listeners {
              Http {
                Name = ""
                Hosts = []
                HostBind = ""
                HostRotation = ""
                PortBind = 0
              }
            }

            Demon {}
            "#,
        )
        .expect("invalid profile should still parse");

        let error = profile.validate().expect_err("validation should fail");

        assert!(error.errors.iter().any(|entry| entry.contains("Teamserver.Host")));
        assert!(error.errors.iter().any(|entry| entry.contains("Teamserver.Port")));
        assert!(error.errors.iter().any(|entry| entry.contains("Operators must define")));
        assert!(error.errors.iter().any(|entry| entry.contains("PortBind")));
    }

    #[test]
    fn parses_rest_api_configuration() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Api {
              RateLimitPerMinute = 120
              key "automation" {
                Value = "secret-admin"
              }
              key "reporting" {
                Value = "secret-analyst"
                Role = "Analyst"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let api = profile.api.expect("api config should exist");
        assert_eq!(api.rate_limit_per_minute, 120);
        assert_eq!(api.keys["automation"].value, "secret-admin");
        assert_eq!(api.keys["automation"].role, OperatorRole::Admin);
        assert_eq!(api.keys["reporting"].role, OperatorRole::Analyst);
    }

    #[test]
    fn validates_rest_api_configuration() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Api {
              RateLimitPerMinute = 0
              key "automation" {
                Value = ""
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(error.errors.iter().any(|message| message.contains("RateLimitPerMinute")));
        assert!(error.errors.iter().any(|message| message.contains("non-empty Value")));
    }

    #[test]
    fn parses_teamserver_plugins_dir() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              PluginsDir = "plugins"
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        assert_eq!(profile.teamserver.plugins_dir.as_deref(), Some("plugins"));
    }

    #[test]
    fn rejects_empty_teamserver_plugins_dir() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              PluginsDir = "   "
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(error.errors.iter().any(|message| message.contains("PluginsDir")));
    }
}
