//! Callback URL construction for Rust-based agents.

use red_cell_common::ListenerConfig;

use super::super::PayloadBuildError;

/// Build the callback URL that a Rust agent should use from the listener config.
pub(super) fn rust_agent_callback_url(
    listener: &ListenerConfig,
) -> Result<String, PayloadBuildError> {
    match listener {
        ListenerConfig::Http(http) => {
            let scheme = if http.secure { "https" } else { "http" };
            let port = http.port_conn.unwrap_or(http.port_bind);
            let host = http.hosts.first().map(|h| h.as_str()).unwrap_or("127.0.0.1");
            // Strip an existing port suffix if the host entry already includes one.
            let host_name = host
                .rsplit_once(':')
                .and_then(|(name, p)| p.parse::<u16>().ok().map(|_| name))
                .unwrap_or(host);
            Ok(format!("{scheme}://{host_name}:{port}/"))
        }
        other => Err(PayloadBuildError::InvalidRequest {
            message: format!(
                "{} listeners are not supported for Rust agent payload builds",
                other.protocol()
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::{HttpListenerConfig, ListenerConfig};

    #[test]
    fn rust_agent_callback_url_builds_https_url() -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "https-listener".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.example.com:8443".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 443,
            port_conn: Some(8443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(),
            host_header: None,
            secure: true,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }));
        let url = rust_agent_callback_url(&listener)?;
        assert_eq!(url, "https://c2.example.com:8443/");
        Ok(())
    }

    #[test]
    fn rust_agent_callback_url_builds_http_url_with_default_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http-listener".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["10.0.0.1".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
            port_conn: None,
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(),
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }));
        let url = rust_agent_callback_url(&listener)?;
        assert_eq!(url, "http://10.0.0.1:80/");
        Ok(())
    }

    #[test]
    fn rust_agent_callback_url_falls_back_to_localhost_when_no_hosts()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "empty-hosts".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: Vec::new(),
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 443,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(),
            host_header: None,
            secure: true,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }));
        let url = rust_agent_callback_url(&listener)?;
        assert_eq!(url, "https://127.0.0.1:443/");
        Ok(())
    }

    #[test]
    fn rust_agent_callback_url_rejects_smb_listener() {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pipe".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let err = rust_agent_callback_url(&listener).expect_err("SMB listener should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
    }
}
