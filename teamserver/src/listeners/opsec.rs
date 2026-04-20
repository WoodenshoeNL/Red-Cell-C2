//! Opsec-risk detection for listener startup.
//!
//! Emits structured warnings when a listener is configured with values that
//! create detectable fingerprints in live engagements (default port, stale
//! User-Agent, self-signed TLS certificate).

use red_cell_common::{DnsListenerConfig, HttpListenerConfig, ListenerConfig};

/// The Red Cell C2 default listener port, which is becoming a known signature.
pub(super) const FINGERPRINT_PORT: u16 = 40056;

/// Known-bad User-Agent substrings that indicate a stale or default UA filter.
///
/// `"Mozilla/5.0"` is checked via exact/trimmed equality (not substring) because every modern
/// browser UA begins with that prefix — only the bare string is a red flag.
const BAD_UA_SUBSTRINGS: &[&str] = &["Chrome/96"];
const BAD_UA_EXACT: &[&str] = &["Mozilla/5.0"];

/// Return a list of opsec-risk warning messages for the given listener config.
///
/// Returns an empty `Vec` when no warnings apply, or when the listener has
/// `suppress_opsec_warnings` set to `true`.
pub(super) fn opsec_warnings(config: &ListenerConfig) -> Vec<&'static str> {
    match config {
        ListenerConfig::Http(c) => http_warnings(c),
        ListenerConfig::Dns(c) => dns_warnings(c),
        ListenerConfig::Smb(_) | ListenerConfig::External(_) => vec![],
    }
}

fn http_warnings(config: &HttpListenerConfig) -> Vec<&'static str> {
    if config.suppress_opsec_warnings {
        return vec![];
    }

    let mut warnings = Vec::new();

    if config.port_bind == FINGERPRINT_PORT {
        warnings.push(
            "opsec: listener bound to port 40056 — this port is a known Red Cell C2 \
             fingerprint; change PortBind for live engagements",
        );
    }

    if let Some(ua) = &config.user_agent {
        let is_bad = BAD_UA_SUBSTRINGS.iter().any(|p| ua.contains(p))
            || BAD_UA_EXACT.iter().any(|p| ua.trim() == *p);
        if is_bad {
            warnings.push(
                "opsec: User-Agent filter matches a known-bad default value (Chrome/96 or \
                 bare Mozilla/5.0); update UserAgent to a current browser string",
            );
        }
    }

    if config.secure && config.cert.is_none() {
        warnings.push(
            "opsec: HTTPS listener is using a runtime-generated self-signed certificate; \
             supply a real certificate via Cert/Key for live engagements",
        );
    }

    warnings
}

fn dns_warnings(config: &DnsListenerConfig) -> Vec<&'static str> {
    if config.suppress_opsec_warnings {
        return vec![];
    }

    let mut warnings = Vec::new();

    if config.port_bind == FINGERPRINT_PORT {
        warnings.push(
            "opsec: DNS listener bound to port 40056 — this port is a known Red Cell C2 \
             fingerprint; change PortBind for live engagements",
        );
    }

    warnings
}

#[cfg(test)]
mod tests {
    use red_cell_common::{
        DnsListenerConfig, HttpListenerConfig, ListenerConfig, ListenerTlsConfig, SmbListenerConfig,
    };

    use super::{FINGERPRINT_PORT, opsec_warnings};

    fn base_http() -> HttpListenerConfig {
        HttpListenerConfig {
            name: "test".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec![],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8080,
            port_conn: None,
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: vec![],
            user_agent: None,
            headers: vec![],
            uris: vec![],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
            suppress_opsec_warnings: false,
        }
    }

    fn base_dns() -> DnsListenerConfig {
        DnsListenerConfig {
            name: "dns-test".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.example.com".to_owned(),
            record_types: vec!["TXT".to_owned()],
            kill_date: None,
            working_hours: None,
            suppress_opsec_warnings: false,
        }
    }

    #[test]
    fn no_warnings_for_safe_http_config() {
        let config = ListenerConfig::from(base_http());
        assert!(opsec_warnings(&config).is_empty());
    }

    #[test]
    fn warns_on_fingerprint_port_http() {
        let mut c = base_http();
        c.port_bind = FINGERPRINT_PORT;
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("port 40056"));
    }

    #[test]
    fn warns_on_fingerprint_port_dns() {
        let mut c = base_dns();
        c.port_bind = FINGERPRINT_PORT;
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("port 40056"));
    }

    #[test]
    fn warns_on_chrome_96_ua() {
        let mut c = base_http();
        c.user_agent =
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.110".to_owned());
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("User-Agent"));
    }

    #[test]
    fn warns_on_bare_mozilla_ua() {
        let mut c = base_http();
        c.user_agent = Some("Mozilla/5.0".to_owned());
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("User-Agent"));
    }

    #[test]
    fn no_ua_warning_for_modern_browser_ua() {
        // A real browser UA starts with "Mozilla/5.0" but must not trigger the bare-string check.
        let mut c = base_http();
        c.user_agent = Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/120.0.0.0 Safari/537.36"
                .to_owned(),
        );
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert!(warnings.is_empty(), "modern browser UA must not trigger a warning");
    }

    #[test]
    fn no_ua_warning_when_ua_is_none() {
        let c = base_http();
        assert!(opsec_warnings(&ListenerConfig::from(c)).is_empty());
    }

    #[test]
    fn warns_on_self_signed_https() {
        let mut c = base_http();
        c.secure = true;
        c.cert = None;
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("self-signed"));
    }

    #[test]
    fn no_self_signed_warning_when_cert_provided() {
        let mut c = base_http();
        c.secure = true;
        c.cert = Some(ListenerTlsConfig {
            cert: "/etc/certs/server.crt".to_owned(),
            key: "/etc/certs/server.key".to_owned(),
        });
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert!(warnings.is_empty());
    }

    #[test]
    fn multiple_warnings_accumulate() {
        let mut c = base_http();
        c.port_bind = FINGERPRINT_PORT;
        c.user_agent = Some("Mozilla/5.0".to_owned());
        c.secure = true;
        c.cert = None;
        let warnings = opsec_warnings(&ListenerConfig::from(c));
        assert_eq!(warnings.len(), 3);
    }

    #[test]
    fn suppress_flag_silences_all_http_warnings() {
        let mut c = base_http();
        c.port_bind = FINGERPRINT_PORT;
        c.user_agent = Some("Mozilla/5.0".to_owned());
        c.secure = true;
        c.cert = None;
        c.suppress_opsec_warnings = true;
        assert!(opsec_warnings(&ListenerConfig::from(c)).is_empty());
    }

    #[test]
    fn suppress_flag_silences_dns_warnings() {
        let mut c = base_dns();
        c.port_bind = FINGERPRINT_PORT;
        c.suppress_opsec_warnings = true;
        assert!(opsec_warnings(&ListenerConfig::from(c)).is_empty());
    }

    #[test]
    fn smb_and_external_never_warn() {
        let smb = ListenerConfig::from(SmbListenerConfig {
            name: "smb".to_owned(),
            pipe_name: "\\\\.\\pipe\\test".to_owned(),
            kill_date: None,
            working_hours: None,
        });
        assert!(opsec_warnings(&smb).is_empty());
    }
}
