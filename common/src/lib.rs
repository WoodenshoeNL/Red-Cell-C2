//! Shared types and protocol primitives for Red Cell C2.

pub mod config;
pub mod crypto;
pub mod demon;
pub mod domain;
pub mod error;
pub mod operator;
pub mod tls;

pub use domain::{
    AgentEncryptionInfo, AgentRecord, DnsListenerConfig, ExternalListenerConfig,
    HttpListenerConfig, HttpListenerProxyConfig, HttpListenerResponseConfig, ListenerConfig,
    ListenerProtocol, ListenerTlsConfig, OperatorInfo, SmbListenerConfig, parse_kill_date_to_epoch,
    validate_kill_date,
};
pub use error::CommonError;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Happy-path: key re-exports compile and behave as expected ───

    #[test]
    fn listener_protocol_round_trips_from_crate_root() {
        let proto = ListenerProtocol::try_from_str("http").unwrap();
        assert_eq!(proto, ListenerProtocol::Http);
    }

    #[test]
    fn parse_kill_date_epoch_from_crate_root() {
        let epoch = parse_kill_date_to_epoch("2030-01-01 00:00:00").unwrap();
        assert!(epoch > 0, "kill-date epoch should be positive");
    }

    #[test]
    fn validate_kill_date_none_from_crate_root() {
        let result = validate_kill_date(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn common_error_reexported_from_crate_root() {
        let err = CommonError::InvalidAgentId { value: "bad".into() };
        assert!(format!("{err}").contains("bad"));
    }

    // ── Regression: assert listener config types remain crate-root reachable ───

    #[test]
    fn http_listener_config_accessible() {
        fn _assert_type(_: &HttpListenerConfig) {}
    }

    #[test]
    fn dns_listener_config_accessible() {
        fn _assert_type(_: &DnsListenerConfig) {}
    }

    #[test]
    fn smb_listener_config_accessible() {
        fn _assert_type(_: &SmbListenerConfig) {}
    }

    #[test]
    fn external_listener_config_accessible() {
        fn _assert_type(_: &ExternalListenerConfig) {}
    }

    #[test]
    fn listener_config_enum_accessible() {
        fn _assert_type(_: &ListenerConfig) {}
    }

    #[test]
    fn listener_tls_config_accessible() {
        fn _assert_type(_: &ListenerTlsConfig) {}
    }

    #[test]
    fn http_listener_proxy_config_accessible() {
        fn _assert_type(_: &HttpListenerProxyConfig) {}
    }

    #[test]
    fn http_listener_response_config_accessible() {
        fn _assert_type(_: &HttpListenerResponseConfig) {}
    }

    // ── Regression: agent and operator types reachable ───

    #[test]
    fn agent_record_accessible() {
        fn _assert_type(_: &AgentRecord) {}
    }

    #[test]
    fn agent_encryption_info_accessible() {
        fn _assert_type(_: &AgentEncryptionInfo) {}
    }

    #[test]
    fn operator_info_accessible() {
        fn _assert_type(_: &OperatorInfo) {}
    }

    // ── Edge case: compile-fail guard via static assertions ───

    /// This test ensures all re-exported items are usable as type parameters.
    /// If a future refactor removes or renames a re-export, this will fail to
    /// compile, catching the regression at the source.
    #[test]
    fn all_reexports_usable_as_type_params() {
        fn assert_sized<T: Sized>() {}
        assert_sized::<ListenerProtocol>();
        assert_sized::<ListenerConfig>();
        assert_sized::<ListenerTlsConfig>();
        assert_sized::<HttpListenerConfig>();
        assert_sized::<HttpListenerProxyConfig>();
        assert_sized::<HttpListenerResponseConfig>();
        assert_sized::<SmbListenerConfig>();
        assert_sized::<DnsListenerConfig>();
        assert_sized::<ExternalListenerConfig>();
        assert_sized::<AgentRecord>();
        assert_sized::<AgentEncryptionInfo>();
        assert_sized::<OperatorInfo>();
        assert_sized::<CommonError>();
    }
}
