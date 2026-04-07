//! Public client crate API used by integration tests and shared binary modules.

pub mod known_servers;
pub mod local_config;
pub mod logging;
pub mod login;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_root_exposes_local_config_module() {
        let _cfg = crate::local_config::LocalConfig::default();
    }

    #[test]
    fn crate_root_exposes_logging_module() {
        let cfg = crate::local_config::LocalConfig::default();
        let _dir = crate::logging::resolve_log_dir(&cfg);
    }

    #[test]
    fn crate_root_exposes_login_module() {
        let cfg = crate::local_config::LocalConfig::default();
        let _state = crate::login::LoginState::new("wss://localhost:40056", &cfg);
    }

    #[test]
    fn crate_root_exposes_known_servers_module() {
        let store = crate::known_servers::KnownServersStore::default();
        assert!(store.is_empty());
    }
}
