//! Root YAOTL [`Profile`] document and [`Profile::validate`].

use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use super::api::{ApiConfig, ServiceConfig, WebHookConfig};
use super::demon::DemonConfig;
use super::listeners::ListenersConfig;
use super::teamserver::{OperatorsConfig, TeamserverConfig};

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
            } else if !Path::new(cert.cert.trim()).exists() {
                errors.push(format!("Teamserver.Cert.Cert file not found: {}", cert.cert.trim()));
            }

            if cert.key.trim().is_empty() {
                errors.push("Teamserver.Cert.Key path must not be empty when specified".to_owned());
            } else if !Path::new(cert.key.trim()).exists() {
                errors.push(format!("Teamserver.Cert.Key file not found: {}", cert.key.trim()));
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
                } else {
                    if !Path::new(cert.cert.trim()).exists() {
                        errors.push(format!(
                            "Listeners.Http \"{}\" cert file not found: {}",
                            listener.name,
                            cert.cert.trim()
                        ));
                    }
                    if !Path::new(cert.key.trim()).exists() {
                        errors.push(format!(
                            "Listeners.Http \"{}\" key file not found: {}",
                            listener.name,
                            cert.key.trim()
                        ));
                    }
                }
            }

            if let Some(doh) = &listener.doh_domain {
                if !doh.trim().is_empty() && !is_valid_fqdn(doh.trim()) {
                    errors.push(format!(
                        "Listeners.Http \"{}\" DoHDomain `{}` is not a valid FQDN",
                        listener.name,
                        doh.trim()
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

        if let Some(secret) = &self.demon.init_secret {
            if secret.is_empty() {
                errors.push(
                    "Demon.InitSecret must not be empty when specified — omit the field to disable HKDF derivation".to_owned(),
                );
            } else if secret.len() < 16 {
                errors.push(format!(
                    "Demon.InitSecret is {} byte(s); minimum is 16 bytes (128 bits) to provide useful HKDF salt entropy",
                    secret.len()
                ));
            }
        }

        if self.demon.init_secret.is_some() && !self.demon.init_secrets.is_empty() {
            errors.push(
                "Demon.InitSecret and Demon.InitSecrets are mutually exclusive — \
                 remove InitSecret and use InitSecrets for rotation support"
                    .to_owned(),
            );
        }

        {
            let mut seen_versions = std::collections::BTreeSet::new();
            for entry in &self.demon.init_secrets {
                if entry.secret.is_empty() {
                    errors.push(format!(
                        "Demon.InitSecrets[version={}].Secret must not be empty",
                        entry.version
                    ));
                } else if entry.secret.len() < 16 {
                    errors.push(format!(
                        "Demon.InitSecrets[version={}].Secret is {} byte(s); minimum is 16 bytes (128 bits)",
                        entry.version,
                        entry.secret.len()
                    ));
                }
                if !seen_versions.insert(entry.version) {
                    errors.push(format!(
                        "Demon.InitSecrets contains duplicate version {}",
                        entry.version
                    ));
                }
            }
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

        // Check for listener port conflicts across all listener types.
        {
            let mut seen_ports: Vec<(&str, &str, u16)> = Vec::new();

            for listener in &self.listeners.http {
                if listener.port_bind != 0 {
                    if let Some((kind, name, _)) =
                        seen_ports.iter().find(|(_, _, p)| *p == listener.port_bind)
                    {
                        errors.push(format!(
                            "Listeners.Http \"{}\" port {} conflicts with {kind} \"{name}\"",
                            listener.name, listener.port_bind
                        ));
                    } else {
                        seen_ports.push(("Http", &listener.name, listener.port_bind));
                    }
                }
            }

            for listener in &self.listeners.dns {
                if listener.port_bind != 0 {
                    if let Some((kind, name, _)) =
                        seen_ports.iter().find(|(_, _, p)| *p == listener.port_bind)
                    {
                        errors.push(format!(
                            "Listeners.Dns \"{}\" port {} conflicts with {kind} \"{name}\"",
                            listener.name, listener.port_bind
                        ));
                    } else {
                        seen_ports.push(("Dns", &listener.name, listener.port_bind));
                    }
                }
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(ProfileValidationError { errors }) }
    }
}
/// Validate that `s` is a well-formed fully qualified domain name.
///
/// A valid FQDN consists of dot-separated labels where each label:
/// - Is 1–63 characters long
/// - Contains only ASCII alphanumeric characters and hyphens
/// - Does not start or end with a hyphen
///
/// A trailing dot is tolerated (root label).
pub(crate) fn is_valid_fqdn(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
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
