use super::PayloadBuildError;
use super::formats::{Architecture, OutputFormat};
use red_cell_common::{ListenerConfig, ListenerProtocol};

/// Build the `-D` defines injected into the Demon agent compiler invocation.
///
/// The returned defines include the serialised config bytes, the transport
/// identifier, and — optionally — a `SHELLCODE` flag.
pub(super) fn build_defines(
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

/// Validates a compiler `-D` define string before it is passed to the compiler.
///
/// A valid define has the form `NAME` or `NAME=value` where:
/// - `NAME` contains only ASCII alphanumeric characters and underscores and begins
///   with a letter or underscore.
/// - The entire string contains no whitespace (a space-containing define would be
///   embedded as one argument but is almost certainly a bug or injection attempt).
/// - The entire string does not begin with `-` to prevent injecting extra compiler
///   flags.
pub(super) fn validate_define(define: &str) -> Result<(), PayloadBuildError> {
    if define.is_empty() {
        return Err(PayloadBuildError::InvalidRequest {
            message: "compiler define must not be empty".to_owned(),
        });
    }
    if define.starts_with('-') {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!("compiler define `{define}` must not begin with `-`"),
        });
    }
    if define.chars().any(|c| c.is_whitespace()) {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!("compiler define `{define}` must not contain whitespace"),
        });
    }
    let name = define.split_once('=').map_or(define, |(n, _)| n);
    if name.is_empty()
        || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!(
                "compiler define name `{name}` must contain only ASCII alphanumeric characters \
                 and underscores and begin with a letter or underscore"
            ),
        });
    }
    Ok(())
}

/// Format a byte slice as a comma-separated list of hex literals suitable for
/// embedding in a C array initialiser via a `-D` define.
pub(super) fn format_config_bytes(bytes: &[u8]) -> String {
    // No shell escaping needed: the compiler is invoked via Command::args() which
    // passes arguments directly to execvp, so commas do not need backslash-escaping.
    bytes.iter().map(|byte| format!("0x{byte:02x}")).collect::<Vec<_>>().join(",")
}

/// Generate a random 4-byte Archon magic value and return the corresponding
/// `-D` define string together with the raw `u32` value.
///
/// The define is injected as `-DARCHON_MAGIC_VALUE=0x<hex>` so the C compiler
/// overrides the fallback constant in `Defines.h`.  The returned `u32` is
/// stored in the agent record on first check-in and used to validate every
/// subsequent Archon packet before AES decryption.
///
/// The function guarantees that the generated value is never `0xDEADBEEF` so
/// that Archon traffic cannot be confused with legacy Demon traffic.
pub(super) fn generate_archon_magic() -> Result<(String, u32), PayloadBuildError> {
    let mut bytes = [0u8; 4];
    loop {
        getrandom::fill(&mut bytes).map_err(|e| PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to generate random Archon magic: {e}"),
        })?;
        let magic = u32::from_be_bytes(bytes);
        if magic != 0xDEAD_BEEF {
            let define = format!("ARCHON_MAGIC_VALUE=0x{magic:08X}");
            validate_define(&define)?;
            return Ok((define, magic));
        }
    }
}

/// Build the `-D` defines injected into the staged shellcode stager template.
///
/// Only HTTP listeners are supported: the stager makes an outbound HTTP(S) GET
/// request, which has no equivalent for SMB or DNS listeners.
pub(super) fn build_stager_defines(
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
pub(super) fn stager_cache_bytes(listener: &ListenerConfig) -> Result<Vec<u8>, PayloadBuildError> {
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

/// Return the default compiler flags for the given output format.
pub(super) fn default_compiler_flags(format: OutputFormat) -> Vec<&'static str> {
    let mut flags = vec![
        "-Os",
        "-fno-asynchronous-unwind-tables",
        "-masm=intel",
        "-fno-ident",
        "-fpack-struct=8",
        "-falign-functions=1",
        "-s",
        "-ffunction-sections",
        "-fdata-sections",
        "-falign-jumps=1",
        "-w",
        "-falign-labels=1",
        "-fPIC",
    ];

    if format == OutputFormat::ServiceExe {
        flags.push("-mwindows");
        flags.push("-ladvapi32");
    } else {
        flags.push("-nostdlib");
        flags.push("-mwindows");
    }

    flags.push("-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections");
    flags
}

/// Return the architecture- and format-specific main source and entry-point
/// arguments for the compiler invocation.
pub(super) fn main_args(architecture: Architecture, format: OutputFormat) -> Vec<&'static str> {
    match format {
        OutputFormat::Exe => vec![
            "-D",
            "MAIN_THREADED",
            "-e",
            if architecture == Architecture::X64 { "WinMain" } else { "_WinMain" },
            "src/main/MainExe.c",
        ],
        OutputFormat::ServiceExe => vec![
            "-D",
            "MAIN_THREADED",
            "-D",
            "SVC_EXE",
            "-lntdll",
            "-e",
            if architecture == Architecture::X64 { "WinMain" } else { "_WinMain" },
            "src/main/MainSvc.c",
        ],
        OutputFormat::Dll | OutputFormat::ReflectiveDll => vec![
            "-shared",
            "-e",
            if architecture == Architecture::X64 { "DllMain" } else { "_DllMain" },
            "src/main/MainDll.c",
        ],
        // These formats never reach compile_portable_executable:
        // Shellcode and RawShellcode compile a DLL then prepend a loader binary,
        // StagedShellcode is compiled by compile_stager via its own code path.
        OutputFormat::Shellcode | OutputFormat::RawShellcode | OutputFormat::StagedShellcode => {
            Vec::new()
        }
    }
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
        }))
    }

    // ── validate_define tests ─────────────────────────────────────────────

    #[test]
    fn validate_define_accepts_bare_name() {
        assert!(validate_define("SHELLCODE").is_ok());
        assert!(validate_define("TRANSPORT_HTTP").is_ok());
        assert!(validate_define("_PRIVATE").is_ok());
    }

    #[test]
    fn validate_define_accepts_name_equals_value() {
        assert!(validate_define("FOO=bar").is_ok());
        assert!(validate_define("CONFIG_BYTES={0x00,0x01}").is_ok());
        assert!(validate_define("LEVEL=1").is_ok());
    }

    #[test]
    fn validate_define_rejects_empty() {
        let err = validate_define("");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not be empty")
        ));
    }

    #[test]
    fn validate_define_rejects_leading_dash() {
        let err = validate_define("-o /tmp/evil");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not begin with `-`")
        ));
    }

    #[test]
    fn validate_define_rejects_whitespace_in_value() {
        let err = validate_define("FOO=bar baz");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn validate_define_rejects_whitespace_in_name() {
        let err = validate_define("FOO BAR=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn validate_define_rejects_name_starting_with_digit() {
        let err = validate_define("1FOO=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("alphanumeric characters and underscores")
        ));
    }

    #[test]
    fn validate_define_rejects_name_with_hyphen() {
        let err = validate_define("FOO-BAR=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("alphanumeric characters and underscores")
        ));
    }

    #[test]
    fn validate_define_rejects_embedded_flag_injection() {
        // Value contains a space followed by a flag — rejected due to whitespace rule
        let err = validate_define("FOO=1 -o /tmp/evil");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    // ── format_config_bytes tests ─────────────────────────────────────────

    #[test]
    fn format_config_bytes_formats_correctly() {
        assert_eq!(format_config_bytes(&[0x00, 0xFF, 0x42]), "0x00,0xff,0x42");
    }

    #[test]
    fn format_config_bytes_empty_input() {
        assert_eq!(format_config_bytes(&[]), "");
    }

    #[test]
    fn format_config_bytes_single_byte() {
        assert_eq!(format_config_bytes(&[0xAB]), "0xab");
    }

    // ── build_defines tests ───────────────────────────────────────────────

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

    // ── build_stager_defines tests ────────────────────────────────────────

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

    // ── stager_cache_bytes tests ──────────────────────────────────────────

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

    // ── main_args tests ───────────────────────────────────────────────────

    #[test]
    fn main_args_exe_includes_main_threaded_and_entry_point() {
        let args = main_args(Architecture::X64, OutputFormat::Exe);
        assert!(args.contains(&"MAIN_THREADED"));
        assert!(args.contains(&"WinMain"));
        assert!(args.contains(&"src/main/MainExe.c"));
    }

    #[test]
    fn main_args_exe_x86_uses_underscore_prefix() {
        let args = main_args(Architecture::X86, OutputFormat::Exe);
        assert!(args.contains(&"_WinMain"));
    }

    #[test]
    fn main_args_service_exe_includes_svc_flag() {
        let args = main_args(Architecture::X64, OutputFormat::ServiceExe);
        assert!(args.contains(&"SVC_EXE"));
        assert!(args.contains(&"src/main/MainSvc.c"));
    }

    #[test]
    fn main_args_dll_uses_shared_and_dllmain() {
        let args = main_args(Architecture::X64, OutputFormat::Dll);
        assert!(args.contains(&"-shared"));
        assert!(args.contains(&"DllMain"));
        assert!(args.contains(&"src/main/MainDll.c"));
    }

    #[test]
    fn main_args_shellcode_returns_empty() {
        assert!(main_args(Architecture::X64, OutputFormat::Shellcode).is_empty());
        assert!(main_args(Architecture::X64, OutputFormat::RawShellcode).is_empty());
        assert!(main_args(Architecture::X64, OutputFormat::StagedShellcode).is_empty());
    }

    // ── default_compiler_flags tests ──────────────────────────────────────

    #[test]
    fn default_compiler_flags_always_includes_pic_and_optimization() {
        for format in [OutputFormat::Exe, OutputFormat::Dll, OutputFormat::ServiceExe] {
            let flags = default_compiler_flags(format);
            assert!(flags.contains(&"-Os"), "missing -Os for {format:?}");
            assert!(flags.contains(&"-fPIC"), "missing -fPIC for {format:?}");
            assert!(flags.contains(&"-mwindows"), "missing -mwindows for {format:?}");
        }
    }

    #[test]
    fn default_compiler_flags_service_exe_links_advapi32() {
        let flags = default_compiler_flags(OutputFormat::ServiceExe);
        assert!(flags.contains(&"-ladvapi32"));
        assert!(!flags.contains(&"-nostdlib"), "service exe should not use -nostdlib");
    }

    #[test]
    fn default_compiler_flags_non_service_uses_nostdlib() {
        for format in [OutputFormat::Exe, OutputFormat::Dll, OutputFormat::ReflectiveDll] {
            let flags = default_compiler_flags(format);
            assert!(flags.contains(&"-nostdlib"), "missing -nostdlib for {format:?}");
        }
    }
}
