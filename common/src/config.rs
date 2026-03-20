//! Havoc-compatible teamserver profile parsing.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use utoipa::ToSchema;
use zeroize::Zeroizing;

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

        if self.teamserver.max_download_bytes == Some(0) {
            errors.push("Teamserver.MaxDownloadBytes must be greater than zero".to_owned());
        }

        if self.teamserver.max_registered_agents == Some(0) {
            errors.push("Teamserver.MaxRegisteredAgents must be greater than zero".to_owned());
        }

        if self.teamserver.drain_timeout_secs == Some(0) {
            errors.push("Teamserver.DrainTimeoutSecs must be greater than zero".to_owned());
        }

        if self.teamserver.agent_timeout_secs == Some(0) {
            errors.push("Teamserver.AgentTimeoutSecs must be greater than zero".to_owned());
        }

        if let Some(logging) = &self.teamserver.logging {
            if logging.level.as_deref().is_some_and(|level| level.trim().is_empty()) {
                errors.push("Teamserver.Logging.Level must not be empty when specified".to_owned());
            }

            if let Some(file) = &logging.file {
                if file.directory.trim().is_empty() {
                    errors.push("Teamserver.Logging.File.Directory must not be empty".to_owned());
                }

                if file.prefix.trim().is_empty() {
                    errors.push("Teamserver.Logging.File.Prefix must not be empty".to_owned());
                }
            }
        }

        if let Some(cert) = &self.teamserver.cert {
            if cert.cert.trim().is_empty() {
                errors
                    .push("Teamserver.Cert.Cert path must not be empty when specified".to_owned());
            }

            if cert.key.trim().is_empty() {
                errors.push("Teamserver.Cert.Key path must not be empty when specified".to_owned());
            }
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

            if listener
                .host_header
                .as_deref()
                .is_some_and(|host_header| host_header.trim().is_empty())
            {
                errors.push(format!(
                    "Listeners.Http \"{}\" HostHeader must not be empty when specified",
                    listener.name
                ));
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
            } else if !listener.endpoint.starts_with('/') {
                errors.push(format!(
                    "Listeners.External \"{}\" Endpoint must start with '/'",
                    listener.name
                ));
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
            if service.endpoint.is_empty() {
                errors.push("Service.Endpoint must not be empty".to_owned());
            }
            if service.password.is_empty() {
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
        {
            validate_discord_webhook_url(&discord.url, &mut errors);
        }

        for peer in &self.demon.trusted_proxy_peers {
            let trimmed = peer.trim();
            if trimmed.is_empty() {
                errors.push("Demon.TrustedProxyPeers entries must not be empty".to_owned());
                continue;
            }

            if trimmed.parse::<IpAddr>().is_ok() {
                continue;
            }

            let Some((network, prefix_len)) = trimmed.split_once('/') else {
                errors.push(format!(
                    "Demon.TrustedProxyPeers entry `{trimmed}` must be an IP address or CIDR"
                ));
                continue;
            };

            let Ok(network) = network.parse::<IpAddr>() else {
                errors.push(format!(
                    "Demon.TrustedProxyPeers entry `{trimmed}` must be an IP address or CIDR"
                ));
                continue;
            };

            let Ok(prefix_len) = prefix_len.parse::<u8>() else {
                errors.push(format!(
                    "Demon.TrustedProxyPeers entry `{trimmed}` has an invalid prefix length"
                ));
                continue;
            };

            let max_prefix_len = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix_len > max_prefix_len {
                errors.push(format!(
                    "Demon.TrustedProxyPeers entry `{trimmed}` has an invalid prefix length"
                ));
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(ProfileValidationError { errors }) }
    }
}

/// Permitted Discord webhook hostnames (scheme must always be `https`).
const DISCORD_WEBHOOK_HOSTS: &[&str] =
    &["discord.com", "discordapp.com", "hooks.discord.com", "hooks.discordapp.com"];

/// Validate a Discord webhook URL: must be `https://` and target a known Discord hostname.
///
/// Any HTTP URL or unknown host is rejected to prevent SSRF via the webhook HTTP client.
fn validate_discord_webhook_url(url: &str, errors: &mut Vec<String>) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        errors.push("WebHook.Discord.Url must not be empty".to_owned());
        return;
    }

    // Require the https scheme to prevent plaintext delivery and trivial SSRF.
    let Some(after_scheme) = trimmed.strip_prefix("https://") else {
        errors.push("WebHook.Discord.Url must use the https:// scheme to prevent SSRF".to_owned());
        return;
    };

    // Extract the host (stop at '/', '?', '#', or ':' for a port).
    let host = after_scheme.split(['/', '?', '#', ':']).next().unwrap_or("").to_ascii_lowercase();

    if !DISCORD_WEBHOOK_HOSTS.contains(&host.as_str()) {
        errors.push(format!(
            "WebHook.Discord.Url host `{host}` is not a permitted Discord hostname; \
             allowed: {}",
            DISCORD_WEBHOOK_HOSTS.join(", ")
        ));
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
    /// Maximum in-memory size of a single agent download before the server drops it.
    #[serde(rename = "MaxDownloadBytes", default)]
    pub max_download_bytes: Option<u64>,
    /// Maximum number of registered agents retained in memory and SQLite.
    #[serde(rename = "MaxRegisteredAgents", default)]
    pub max_registered_agents: Option<usize>,
    /// Graceful-shutdown drain timeout in seconds.
    #[serde(rename = "DrainTimeoutSecs", default)]
    pub drain_timeout_secs: Option<u64>,
    /// Optional agent inactivity timeout override in seconds.
    #[serde(rename = "AgentTimeoutSecs", default)]
    pub agent_timeout_secs: Option<u64>,
    /// Optional structured logging settings for the teamserver runtime.
    #[serde(rename = "Logging", default)]
    pub logging: Option<LoggingConfig>,
    /// Optional build toolchain settings.
    #[serde(rename = "Build", default)]
    pub build: Option<BuildConfig>,
    /// Optional TLS certificate and key paths for the control-plane listener.
    ///
    /// When set, the teamserver loads its TLS identity from these PEM files on every
    /// start instead of generating a fresh self-signed certificate. When absent, the
    /// teamserver generates a self-signed certificate on the first boot and persists it
    /// next to the profile file so that subsequent restarts reuse the same material.
    #[serde(rename = "Cert", default)]
    pub cert: Option<HttpListenerCertConfig>,
}

/// Teamserver tracing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LoggingConfig {
    /// Default log filter used when `RUST_LOG` is not set.
    #[serde(rename = "Level", default)]
    pub level: Option<String>,
    /// Formatter style used for stdout and optional file output.
    #[serde(rename = "Format", default)]
    pub format: Option<LogFormat>,
    /// Optional rolling-file output configuration.
    #[serde(rename = "File", default)]
    pub file: Option<LogFileConfig>,
}

/// Supported tracing output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum LogFormat {
    /// Human-readable, developer-oriented output.
    #[serde(rename = "Pretty", alias = "pretty")]
    Pretty,
    /// Structured JSON output for production ingestion.
    #[serde(rename = "Json", alias = "json")]
    Json,
}

/// Optional rolling-file tracing output configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LogFileConfig {
    /// Directory where rotated log files are written.
    #[serde(rename = "Directory")]
    pub directory: String,
    /// Stable filename prefix used by the rolling appender.
    #[serde(rename = "Prefix")]
    pub prefix: String,
    /// Rotation cadence for the log file.
    #[serde(rename = "Rotation", default)]
    pub rotation: Option<LogRotation>,
}

/// Supported file rotation cadences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum LogRotation {
    /// Never rotate the file.
    #[serde(rename = "Never", alias = "never")]
    Never,
    /// Rotate files hourly.
    #[serde(rename = "Hourly", alias = "hourly")]
    Hourly,
    /// Rotate files daily.
    #[serde(rename = "Daily", alias = "daily")]
    Daily,
    /// Rotate files minutely.
    #[serde(rename = "Minutely", alias = "minutely")]
    Minutely,
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
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct OperatorConfig {
    /// Operator password.
    #[serde(rename = "Password")]
    pub password: String,
    /// Operator role used by the teamserver RBAC layer.
    #[serde(rename = "Role", default)]
    pub role: OperatorRole,
}

impl fmt::Debug for OperatorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorConfig")
            .field("password", &"[redacted]")
            .field("role", &self.role)
            .finish()
    }
}

/// Role assigned to an operator account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
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
    pub http: Vec<ProfileHttpListenerConfig>,
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
        deserialize_with = "deserialize_optional_zeroizing_string"
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

fn deserialize_optional_zeroizing_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.map(Zeroizing::new))
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
    /// Explicit redirector peers or networks allowed to supply forwarded client IP headers.
    #[serde(rename = "TrustedProxyPeers", default, deserialize_with = "deserialize_one_or_many")]
    pub trusted_proxy_peers: Vec<String>,
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

    const HAVOC_PROFILE: &str = r#"
        Teamserver {
          Host = "0.0.0.0"
          Port = 40056

          Build {
            Nasm = "/usr/bin/nasm"
          }
        }

        Operators {
          user "Neo" {
            Password = "password1234"
            Role = "Admin"
          }

          user "Trinity" {
            Password = "followthewhiterabbit"
            Role = "Operator"
          }
        }

        Demon {
          Sleep = 2
          Jitter = 15
          TrustXForwardedFor = false
          TrustedProxyPeers = ["127.0.0.1/32"]

          Injection {
            Spawn64 = "C:\\Windows\\System32\\notepad.exe"
          }
        }

    "#;

    const HTTP_SMB_PROFILE: &str = r#"
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
            Name = "teams profile - http"
            Hosts = ["5pider.net"]
            HostBind = "0.0.0.0"
            HostRotation = "round-robin"
            PortBind = 443
            PortConn = 443
            Headers = [
              "A: 1", "B: 2", "C: 3", "D: 4", "E: 5", "F: 6", "G: 7"
            ]
            Uris = ["/Collector/2.0/settings/"]
            Secure = false

            Response {
              Headers = [
                "H1: 1", "H2: 2", "H3: 3", "H4: 4",
                "H5: 5", "H6: 6", "H7: 7", "H8: 8"
              ]
            }
          }

          Smb {
            Name = "Pivot - Smb"
            PipeName = "demon_pipe"
          }
        }

        Demon {}
    "#;

    const WEBHOOK_PROFILE: &str = r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "Neo" {
            Password = "password1234"
          }
        }

        Demon {}

        WebHook {
          Discord {
            Url = "https://discord.com/api/webhooks/000000000000000000/test-token"
            User = "Havoc"
          }
        }
    "#;

    const HAVOC_DATA_PROFILE: &str = r#"
        Teamserver {
          Host = "0.0.0.0"
          Port = 40056
        }

        Operators {
          user "Neo" {
            Password = "password1234"
          }
        }

        Demon {
          Sleep = 2
        }
    "#;

    #[test]
    fn parses_base_havoc_profile() {
        let profile = Profile::parse(HAVOC_PROFILE).expect("sample profile should parse");

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
        assert_eq!(profile.demon.trusted_proxy_peers, vec!["127.0.0.1/32"]);
        assert_eq!(
            profile.demon.injection.as_ref().and_then(|injection| injection.spawn64.as_deref()),
            Some("C:\\Windows\\System32\\notepad.exe")
        );
        assert!(profile.listeners.http.is_empty());
        assert!(profile.listeners.smb.is_empty());
        assert!(profile.listeners.external.is_empty());
        assert!(profile.service.is_none());
        assert!(profile.webhook.is_none());
    }

    #[test]
    fn parses_listener_profile() {
        let profile = Profile::parse(HTTP_SMB_PROFILE).expect("listener profile should parse");

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
        assert_eq!(http_listener.host_header, None);
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
        let profile = Profile::parse(WEBHOOK_PROFILE).expect("webhook profile should parse");

        let webhook = profile.webhook.and_then(|config| config.discord);
        assert_eq!(
            webhook.as_ref().map(|discord| discord.url.as_str()),
            Some("https://discord.com/api/webhooks/000000000000000000/test-token")
        );
        assert_eq!(webhook.as_ref().and_then(|discord| discord.user.as_deref()), Some("Havoc"));
    }

    #[test]
    fn parses_trusted_proxy_peers_from_single_value_or_list() {
        let single = Profile::parse(
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

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = "127.0.0.1/32"
            }
            "#,
        )
        .expect("profile with single trusted proxy peer should parse");
        assert_eq!(single.demon.trusted_proxy_peers, vec!["127.0.0.1/32"]);

        let list = Profile::parse(
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

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = ["127.0.0.1", "10.0.0.0/8"]
            }
            "#,
        )
        .expect("profile with trusted proxy peer list should parse");
        assert_eq!(list.demon.trusted_proxy_peers, vec!["127.0.0.1", "10.0.0.0/8"]);
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
    fn parses_http_listener_host_header() {
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
                Name = "redirected listener"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080
                HostHeader = "front.example"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        assert_eq!(profile.listeners.http[0].host_header.as_deref(), Some("front.example"));
    }

    #[test]
    fn parses_http_listener_with_proxy_block() {
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
                Name = "proxied listener"
                Hosts = ["proxy.local"]
                HostBind = "0.0.0.0"
                HostRotation = "round-robin"
                PortBind = 8443

                Proxy {
                  Host = "squid.internal"
                  Port = 3128
                  Username = "proxyuser"
                  Password = "proxysecret"
                }
              }
            }

            Demon {}
            "#,
        )
        .expect("profile with proxy block should parse");

        assert_eq!(profile.listeners.http.len(), 1);
        let listener = &profile.listeners.http[0];
        assert_eq!(listener.name, "proxied listener");

        let proxy = listener.proxy.as_ref().expect("proxy block should be present");
        assert_eq!(proxy.host, "squid.internal");
        assert_eq!(proxy.port, 3128);
        assert_eq!(proxy.username.as_deref(), Some("proxyuser"));
        assert_eq!(proxy.password.as_deref().map(String::as_str), Some("proxysecret"));

        // Verify the From conversion to the domain type sets expected defaults.
        let domain_proxy: crate::HttpListenerProxyConfig = proxy.clone().into();
        assert!(domain_proxy.enabled);
        assert_eq!(domain_proxy.proxy_type.as_deref(), Some("http"));
        assert_eq!(domain_proxy.host, "squid.internal");
        assert_eq!(domain_proxy.port, 3128);
        assert_eq!(domain_proxy.username.as_deref(), Some("proxyuser"));
        assert_eq!(domain_proxy.password.as_deref().map(String::as_str), Some("proxysecret"));
    }

    #[test]
    fn parses_http_listener_with_proxy_block_no_credentials() {
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
                Name = "anon proxy listener"
                Hosts = ["proxy.local"]
                HostBind = "0.0.0.0"
                HostRotation = "round-robin"
                PortBind = 9090

                Proxy {
                  Host = "transparent.internal"
                  Port = 8080
                }
              }
            }

            Demon {}
            "#,
        )
        .expect("profile with credential-less proxy block should parse");

        let proxy =
            profile.listeners.http[0].proxy.as_ref().expect("proxy block should be present");
        assert_eq!(proxy.host, "transparent.internal");
        assert_eq!(proxy.port, 8080);
        assert_eq!(proxy.username, None);
        assert_eq!(proxy.password, None);
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
        let profile = Profile::from_reader(HAVOC_DATA_PROFILE.as_bytes())
            .expect("embedded data profile should parse");

        assert_eq!(profile.teamserver.port, 40056);
        assert_eq!(profile.demon.sleep, Some(2));
        assert!(profile.teamserver.build.is_none());
    }

    #[test]
    fn loads_profile_from_file() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let profile_path = temp_dir.path().join("profile.yaotl");

        std::fs::write(&profile_path, HAVOC_PROFILE).expect("profile fixture should be written");

        let profile = Profile::from_file(&profile_path).expect("profile should load from disk");

        assert_eq!(profile.teamserver.host, "0.0.0.0");
        assert_eq!(profile.teamserver.port, 40056);
    }

    #[test]
    fn loads_all_embedded_profile_fixtures_from_disk() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let fixtures = [
            ("havoc.yaotl", HAVOC_PROFILE),
            ("http-smb.yaotl", HTTP_SMB_PROFILE),
            ("webhook.yaotl", WEBHOOK_PROFILE),
        ];

        for (name, fixture) in fixtures {
            let path = temp_dir.path().join(name);
            std::fs::write(&path, fixture).expect("profile fixture should be written");

            let profile = Profile::from_file(&path).expect("profile fixture should load");
            assert!(profile.validate().is_ok(), "fixture {name} should validate");
        }
    }

    #[test]
    fn validates_sample_profile() {
        let profile = Profile::parse(HAVOC_PROFILE).expect("sample profile should parse");

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
    fn rejects_empty_http_listener_host_header() {
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

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 8080
                HostHeader = "   "
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(error.errors.iter().any(|message| message.contains("HostHeader")));
    }

    #[test]
    fn rejects_http_listener_with_blank_certificate_path() {
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

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                Secure = true

                Cert {
                  Cert = "   "
                  Key = "/tmp/server.key"
                }
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(error.errors.iter().any(|message| {
            message.contains("Listeners.Http \"edge\"")
                && message.contains("non-empty Cert and Key paths")
        }));
    }

    #[test]
    fn rejects_http_listener_with_blank_certificate_key_path() {
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

            Listeners {
              Http {
                Name = "edge"
                Hosts = ["listener.local"]
                HostBind = "127.0.0.1"
                HostRotation = "round-robin"
                PortBind = 443
                Secure = true

                Cert {
                  Cert = "/tmp/server.crt"
                  Key = "   "
                }
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(error.errors.iter().any(|message| {
            message.contains("Listeners.Http \"edge\"")
                && message.contains("non-empty Cert and Key paths")
        }));
    }

    #[test]
    fn rejects_invalid_trusted_proxy_peer_configuration() {
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

            Demon {
              TrustedProxyPeers = ["bad-value", "10.0.0.0/33", "   "]
            }
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(error.errors.iter().any(|message| message.contains("TrustedProxyPeers")));
    }

    #[test]
    fn accepts_ipv6_trusted_proxy_peers() {
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

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = ["::1", "2001:db8::/128"]
            }
            "#,
        )
        .expect("profile should parse");

        profile.validate().expect("IPv6 trusted proxy peers should validate");
    }

    #[test]
    fn rejects_ipv6_trusted_proxy_peer_with_invalid_prefix_length() {
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

            Demon {
              TrustXForwardedFor = true
              TrustedProxyPeers = ["2001:db8::/129"]
            }
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(error.errors.iter().any(|message| {
            message.contains("TrustedProxyPeers")
                && message.contains("2001:db8::/129")
                && message.contains("invalid prefix length")
        }));
    }

    #[test]
    fn accepts_service_block_with_warning() {
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

            Service {
              Endpoint = "service-endpoint"
              Password = "service-password"
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        profile.validate().expect("profile with Service block should validate successfully");
        assert!(profile.service.is_some());
    }

    #[test]
    fn accepts_valid_external_listener_configuration() {
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

            Listeners {
              External {
                Name = "bridge"
                Endpoint = "/svc"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        profile.validate().expect("profile with External listener should validate successfully");
        assert_eq!(profile.listeners.external.len(), 1);
        assert_eq!(profile.listeners.external[0].name, "bridge");
        assert_eq!(profile.listeners.external[0].endpoint, "/svc");
    }

    #[test]
    fn rejects_external_listener_missing_endpoint_slash() {
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

            Listeners {
              External {
                Name = "bridge"
                Endpoint = "svc"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("endpoint without leading / should fail");
        assert!(error.to_string().contains("must start with '/'"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_invalid_dns_listener_configuration() {
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

            Listeners {
              Dns {
                Name = ""
                Domain = ""
                PortBind = 0
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|m| m.contains("Listeners.Dns.Name must not be empty")),
            "expected name-empty error; got: {:?}",
            error.errors
        );
        assert!(
            error.errors.iter().any(|m| m.contains("must define Domain")),
            "expected domain-empty error; got: {:?}",
            error.errors
        );
        assert!(
            error.errors.iter().any(|m| m.contains("must define a PortBind greater than zero")),
            "expected port-bind-zero error; got: {:?}",
            error.errors
        );
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
    fn rejects_rest_api_configuration_without_keys() {
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
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|message| message.contains("Api must define at least one key"))
        );
    }

    #[test]
    fn parses_teamserver_plugins_dir() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              PluginsDir = "plugins"
              MaxDownloadBytes = 1048576
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
        assert_eq!(profile.teamserver.max_download_bytes, Some(1_048_576));
        assert_eq!(profile.teamserver.max_registered_agents, None);
        assert_eq!(profile.teamserver.drain_timeout_secs, None);
    }

    #[test]
    fn parses_teamserver_max_registered_agents() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxRegisteredAgents = 2048
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

        assert_eq!(profile.teamserver.max_registered_agents, Some(2_048));
    }

    #[test]
    fn parses_teamserver_drain_timeout() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              DrainTimeoutSecs = 45
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

        assert_eq!(profile.teamserver.drain_timeout_secs, Some(45));
    }

    #[test]
    fn parses_teamserver_logging_configuration() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "red_cell=debug,tower_http=info"
                Format = "Json"

                File {
                  Directory = "logs"
                  Prefix = "teamserver.log"
                  Rotation = "Hourly"
                }
              }
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

        let logging = profile.teamserver.logging.expect("logging config should exist");
        assert_eq!(logging.level.as_deref(), Some("red_cell=debug,tower_http=info"));
        assert_eq!(logging.format, Some(LogFormat::Json));
        let file = logging.file.expect("file logging config should exist");
        assert_eq!(file.directory, "logs");
        assert_eq!(file.prefix, "teamserver.log");
        assert_eq!(file.rotation, Some(LogRotation::Hourly));
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

    #[test]
    fn rejects_zero_max_registered_agents() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxRegisteredAgents = 0
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
        assert!(error.errors.iter().any(|message| message.contains("MaxRegisteredAgents")));
    }

    #[test]
    fn rejects_zero_drain_timeout_secs() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              DrainTimeoutSecs = 0
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
        assert!(error.errors.iter().any(|message| message.contains("DrainTimeoutSecs")));
    }

    #[test]
    fn parses_agent_timeout_secs() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              AgentTimeoutSecs = 90
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {
              Sleep = 5
            }
            "#,
        )
        .expect("profile should parse");

        assert_eq!(profile.teamserver.agent_timeout_secs, Some(90));
    }

    #[test]
    fn rejects_zero_agent_timeout_secs() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              AgentTimeoutSecs = 0
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
        assert!(error.errors.iter().any(|message| message.contains("AgentTimeoutSecs")));
    }

    #[test]
    fn rejects_invalid_teamserver_logging_configuration() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "   "

                File {
                  Directory = " "
                  Prefix = ""
                }
              }
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
        assert!(error.errors.iter().any(|message| message.contains("Logging.Level")));
        assert!(error.errors.iter().any(|message| message.contains("Logging.File.Directory")));
        assert!(error.errors.iter().any(|message| message.contains("Logging.File.Prefix")));
    }

    #[test]
    fn rejects_zero_max_download_bytes() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              MaxDownloadBytes = 0
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
        assert!(error.errors.iter().any(|message| message.contains("MaxDownloadBytes")));
    }

    #[test]
    fn parse_rejects_malformed_hcl() {
        let result = Profile::parse("{completely invalid hcl]");
        assert!(result.is_err(), "malformed HCL must return an error");
        assert!(
            matches!(result.unwrap_err(), ProfileError::Parse(_)),
            "error must be the Parse variant"
        );
    }

    #[test]
    fn from_file_returns_error_for_nonexistent_path() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let missing_path = temp_dir.path().join("does_not_exist.yaotl");

        let result = Profile::from_file(&missing_path);
        assert!(result.is_err(), "missing file must return an error");

        match result.unwrap_err() {
            ProfileError::Read { path, .. } => {
                assert_eq!(
                    path,
                    missing_path.display().to_string(),
                    "error must carry the path that failed to open"
                );
            }
            other => panic!("expected ProfileError::Read, got {other:?}"),
        }
    }

    /// Build a minimal valid profile with the given Discord webhook URL for validation tests.
    fn profile_with_discord_url(url: &str) -> Profile {
        Profile::parse(&format!(
            r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}
            Operators {{
              user "neo" {{
                Password = "pw"
              }}
            }}
            Demon {{}}
            WebHook {{
              Discord {{
                Url = "{url}"
              }}
            }}
            "#
        ))
        .expect("profile should parse")
    }

    #[test]
    fn accepts_valid_discord_webhook_urls() {
        let valid = [
            "https://discord.com/api/webhooks/123/token",
            "https://discordapp.com/api/webhooks/123/token",
            "https://hooks.discord.com/services/T/B/x",
            "https://hooks.discordapp.com/services/T/B/x",
        ];
        for url in valid {
            let profile = profile_with_discord_url(url);
            assert!(
                profile.validate().is_ok(),
                "expected valid for {url}: {:?}",
                profile.validate().unwrap_err()
            );
        }
    }

    #[test]
    fn accepts_discord_webhook_url_with_port() {
        let profile = profile_with_discord_url("https://discord.com:443/api/webhooks/123/token");
        assert!(
            profile.validate().is_ok(),
            "discord.com with explicit port 443 should be accepted: {:?}",
            profile.validate().unwrap_err()
        );
    }

    #[test]
    fn rejects_discord_webhook_url_with_host_in_port() {
        // An attacker might try `evil.com:discord.com` hoping the validator
        // sees "discord.com" as the host. The colon-split must yield "evil.com".
        let profile = profile_with_discord_url("https://evil.com:discord.com/hook");
        let err =
            profile.validate().expect_err("evil.com disguised via port field must be rejected");
        assert!(
            err.errors.iter().any(|m| m.contains("permitted Discord hostname")),
            "error should mention hostname restriction: {err}"
        );
    }

    #[test]
    fn rejects_http_discord_webhook_url() {
        let profile = profile_with_discord_url("http://discord.com/api/webhooks/123/token");
        let err = profile.validate().expect_err("http webhook URL must be rejected");
        assert!(
            err.errors.iter().any(|m| m.contains("https://")),
            "error should mention https requirement: {err}"
        );
    }

    #[test]
    fn rejects_non_discord_webhook_url() {
        for url in [
            "https://evil.example.com/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://localhost/hook",
        ] {
            let profile = profile_with_discord_url(url);
            let err = profile.validate().expect_err(&format!("SSRF URL {url} must be rejected"));
            assert!(
                err.errors.iter().any(|m| m.contains("permitted Discord hostname")),
                "error should mention hostname restriction for {url}: {err}"
            );
        }
    }

    #[test]
    fn rejects_empty_discord_webhook_url() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }
            Operators {
              user "neo" {
                Password = "pw"
              }
            }
            Demon {}
            WebHook {
              Discord {
                Url = ""
              }
            }
            "#,
        )
        .expect("profile should parse");
        let err = profile.validate().expect_err("empty webhook URL must be rejected");
        assert!(err.errors.iter().any(|m| m.contains("must not be empty")));
    }

    #[test]
    fn rejects_smb_listener_with_empty_pipe_name() {
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

            Listeners {
              Smb {
                Name = "pivot"
                PipeName = "   "
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error
                .errors
                .iter()
                .any(|m| m.contains("Listeners.Smb \"pivot\"") && m.contains("PipeName")),
            "expected PipeName error; got: {:?}",
            error.errors
        );
    }

    #[test]
    fn rejects_smb_listener_with_empty_name() {
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

            Listeners {
              Smb {
                Name = ""
                PipeName = "demo_pipe"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|m| m.contains("Listeners.Smb.Name must not be empty")),
            "expected name-empty error; got: {:?}",
            error.errors
        );
    }

    #[test]
    fn rejects_service_block_with_empty_endpoint() {
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

            Service {
              Endpoint = ""
              Password = "service-password"
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|m| m.contains("Service.Endpoint must not be empty")),
            "expected endpoint error; got: {:?}",
            error.errors
        );
    }

    #[test]
    fn rejects_service_block_with_empty_password() {
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

            Service {
              Endpoint = "service-endpoint"
              Password = ""
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|m| m.contains("Service.Password must not be empty")),
            "expected password error; got: {:?}",
            error.errors
        );
    }

    #[test]
    fn accepts_valid_dns_listener_configuration() {
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

            Listeners {
              Dns {
                Name = "dns-c2"
                Domain = "c2.example.com"
                PortBind = 53
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        profile.validate().expect("valid DNS listener should pass validation");
        assert_eq!(profile.listeners.dns.len(), 1);
        assert_eq!(profile.listeners.dns[0].name, "dns-c2");
        assert_eq!(profile.listeners.dns[0].domain, "c2.example.com");
        assert_eq!(profile.listeners.dns[0].port_bind, 53);
    }

    #[test]
    fn parse_rejects_hcl_missing_teamserver_block() {
        // Valid HCL syntax but missing the required `Teamserver` block.
        let result = Profile::parse(
            r#"
            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        );
        assert!(result.is_err(), "HCL missing Teamserver block must return an error");
        assert!(
            matches!(result.unwrap_err(), ProfileError::Parse(_)),
            "error must be the Parse variant"
        );
    }

    #[test]
    fn profile_error_parse_display_format() {
        // Trigger a parse error by passing garbage HCL.
        let err = Profile::parse("{{{{not valid hcl@@@@").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.starts_with("failed to parse YAOTL profile:"),
            "unexpected Display output: {msg}"
        );
    }

    #[test]
    fn profile_error_read_display_contains_path() {
        let missing = "/tmp/red_cell_c2_nonexistent_profile_12345.hcl";
        let err = Profile::from_file(missing).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.starts_with("failed to read YAOTL profile from"),
            "unexpected Display prefix: {msg}"
        );
        assert!(msg.contains(missing), "Display output must contain the path; got: {msg}");
    }

    #[test]
    fn profile_validation_error_display_join_format() {
        let err = ProfileValidationError {
            errors: vec!["error one".to_owned(), "error two".to_owned(), "error three".to_owned()],
        };
        let msg = err.to_string();
        assert!(msg.starts_with("profile validation failed:"), "unexpected Display prefix: {msg}");
        assert!(
            msg.contains("error one; error two; error three"),
            "errors must be joined with \"; \"; got: {msg}"
        );
    }

    #[test]
    fn parses_teamserver_tls_certificate_paths() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = "/tmp/server.crt"
                Key = "/tmp/server.key"
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
        )
        .expect("profile with teamserver cert block should parse");

        let cert =
            profile.teamserver.cert.as_ref().expect("teamserver cert block should be present");

        assert_eq!(cert.cert, "/tmp/server.crt");
        assert_eq!(cert.key, "/tmp/server.key");

        profile.validate().expect("profile with valid cert paths should pass validation");
    }

    #[test]
    fn rejects_teamserver_with_blank_certificate_path() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = "   "
                Key = "/tmp/server.key"
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|message| message.contains("Teamserver.Cert.Cert")),
            "expected error about blank Teamserver.Cert.Cert path, got: {error:?}"
        );
    }

    #[test]
    fn rejects_teamserver_with_blank_certificate_key_path() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = "/tmp/server.crt"
                Key = "   "
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|message| message.contains("Teamserver.Cert.Key")),
            "expected error about blank Teamserver.Cert.Key path, got: {error:?}"
        );
    }

    #[test]
    fn rejects_teamserver_with_both_blank_certificate_paths() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "0.0.0.0"
              Port = 40056

              Cert {
                Cert = ""
                Key = ""
              }
            }

            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }

            Listeners {}

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|message| message.contains("Teamserver.Cert.Cert")),
            "expected Cert path error, got: {error:?}"
        );
        assert!(
            error.errors.iter().any(|message| message.contains("Teamserver.Cert.Key")),
            "expected Key path error, got: {error:?}"
        );
    }

    #[test]
    fn rejects_smb_listener_with_empty_name_and_pipe_name() {
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

            Listeners {
              Smb {
                Name = ""
                PipeName = ""
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let error = profile.validate().expect_err("profile should be invalid");
        assert!(
            error.errors.iter().any(|message| message.contains("Smb.Name")),
            "expected Smb.Name error, got: {error:?}"
        );
        assert!(
            error.errors.iter().any(|message| message.contains("PipeName")),
            "expected PipeName error, got: {error:?}"
        );
    }
}
