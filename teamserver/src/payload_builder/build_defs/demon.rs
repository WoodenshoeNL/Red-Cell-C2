use super::super::PayloadBuildError;
use super::define_utils::{format_config_bytes, validate_define};
use red_cell_common::{ListenerConfig, ListenerProtocol};

/// Build the `-D` defines injected into the Demon agent compiler invocation.
///
/// The returned defines include the serialised config bytes, the transport
/// identifier, and — optionally — a `SHELLCODE` flag.
pub(in super::super) fn build_defines(
    listener: &ListenerConfig,
    config_bytes: &[u8],
    shellcode_define: bool,
) -> Result<Vec<String>, PayloadBuildError> {
    let config_bytes_define = format!("CONFIG_BYTES={{{}}}", format_config_bytes(config_bytes));
    validate_define(&config_bytes_define)?;
    let mut defines = vec![config_bytes_define];
    let transport = match listener.protocol() {
        ListenerProtocol::Http => "TRANSPORT_HTTP",
        ListenerProtocol::Smb => "TRANSPORT_SMB",
        ListenerProtocol::Dns | ListenerProtocol::External => {
            return Err(PayloadBuildError::InvalidRequest {
                message: format!(
                    "{} listeners are not supported for Demon payload builds",
                    listener.protocol()
                ),
            });
        }
    };
    validate_define(transport)?;
    defines.push(transport.to_owned());
    // ARC-08: add TRANSPORT_DOH when an HTTP listener has a DoH fallback domain.
    if let ListenerConfig::Http(http) = listener {
        if http.doh_domain.as_deref().is_some_and(|d| !d.is_empty()) {
            validate_define("TRANSPORT_DOH")?;
            defines.push("TRANSPORT_DOH".to_owned());
        }
    }
    if shellcode_define {
        validate_define("SHELLCODE")?;
        defines.push("SHELLCODE".to_owned());
    }
    Ok(defines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::{HttpListenerConfig, ListenerConfig};

    fn http_listener_minimal() -> ListenerConfig {
        ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:80".to_owned()],
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
        }))
    }

    #[test]
    fn build_defines_includes_transport_and_config_for_http()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_minimal();
        let config_bytes = &[0x01, 0x02, 0x03];
        let defines = build_defines(&listener, config_bytes, false)?;
        assert!(defines.iter().any(|d| d == "TRANSPORT_HTTP"), "TRANSPORT_HTTP missing");
        assert!(defines.iter().any(|d| d.starts_with("CONFIG_BYTES=")), "CONFIG_BYTES missing");
        assert_eq!(defines.len(), 2, "should have exactly config + transport defines");
        Ok(())
    }

    #[test]
    fn build_defines_includes_shellcode_define_when_requested()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_minimal();
        let defines = build_defines(&listener, &[0x01], true)?;
        assert!(defines.iter().any(|d| d == "SHELLCODE"), "SHELLCODE define missing");
        assert_eq!(defines.len(), 3);
        Ok(())
    }

    #[test]
    fn build_defines_uses_transport_smb_for_smb_listener() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let defines = build_defines(&listener, &[0x01], false)?;
        assert!(defines.iter().any(|d| d == "TRANSPORT_SMB"), "TRANSPORT_SMB missing");
        Ok(())
    }

    #[test]
    fn build_defines_rejects_dns_listener() {
        let listener = ListenerConfig::Dns(red_cell_common::DnsListenerConfig {
            name: "dns".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.local".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
            suppress_opsec_warnings: true,
        });
        let err =
            build_defines(&listener, &[0x01], false).expect_err("DNS listener should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
    }

    #[test]
    fn build_defines_adds_transport_doh_when_doh_domain_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["localhost:80".to_owned()],
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
            doh_domain: Some("c2.example.com".to_owned()),
            doh_provider: Some("cloudflare".to_owned()),
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }));
        let defines = build_defines(&listener, &[0x01], false)?;
        assert!(defines.iter().any(|d| d == "TRANSPORT_HTTP"), "TRANSPORT_HTTP missing");
        assert!(defines.iter().any(|d| d == "TRANSPORT_DOH"), "TRANSPORT_DOH missing");
        assert_eq!(defines.len(), 3, "config + TRANSPORT_HTTP + TRANSPORT_DOH");
        Ok(())
    }

    #[test]
    fn build_defines_does_not_add_transport_doh_when_doh_domain_absent()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = http_listener_minimal();
        let defines = build_defines(&listener, &[0x01], false)?;
        assert!(!defines.iter().any(|d| d == "TRANSPORT_DOH"), "TRANSPORT_DOH should be absent");
        Ok(())
    }
}
