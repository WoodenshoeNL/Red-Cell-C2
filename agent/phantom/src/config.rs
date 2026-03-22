//! Runtime configuration for the Phantom Linux agent.

use crate::error::PhantomError;

/// Configuration inputs that control Phantom's callback transport and timing.
#[derive(Debug, Clone)]
pub struct PhantomConfig {
    /// Teamserver HTTP(S) callback endpoint.
    pub callback_url: String,
    /// Optional listener init secret used for HKDF session key derivation.
    pub init_secret: Option<String>,
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
}

impl PhantomConfig {
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
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self {
            callback_url: String::from("https://127.0.0.1:40056/"),
            init_secret: None,
            user_agent: String::from(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            ),
            sleep_delay_ms: 5_000,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
        }
    }
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
}
