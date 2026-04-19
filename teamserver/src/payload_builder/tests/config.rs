use super::super::pe_patch::parse_header_u32_field;
use super::*;
use red_cell_common::HttpListenerProxyConfig as DomainHttpListenerProxyConfig;
use red_cell_common::config::{DemonConfig, JobExecutionMode};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

// ── Cursor / binary reader helpers ──────────────────────────────────

fn read_u32(cursor: &mut &[u8]) -> Result<u32, PayloadBuildError> {
    let bytes = take(cursor, 4)?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| PayloadBuildError::InvalidRequest {
        message: "test parser failed to decode u32".to_owned(),
    })?;
    Ok(u32::from_le_bytes(array))
}

fn read_u64(cursor: &mut &[u8]) -> Result<u64, PayloadBuildError> {
    let bytes = take(cursor, 8)?;
    let array: [u8; 8] = bytes.try_into().map_err(|_| PayloadBuildError::InvalidRequest {
        message: "test parser failed to decode u64".to_owned(),
    })?;
    Ok(u64::from_le_bytes(array))
}

fn read_wstring(cursor: &mut &[u8]) -> Result<String, PayloadBuildError> {
    let byte_len =
        usize::try_from(read_u32(cursor)?).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "test parser string length overflow".to_owned(),
        })?;
    let bytes = take(cursor, byte_len)?;
    if bytes.len() < 2 || bytes[bytes.len() - 2..] != [0, 0] {
        return Err(PayloadBuildError::InvalidRequest {
            message: "test parser missing UTF-16 terminator".to_owned(),
        });
    }

    let units = bytes[..bytes.len() - 2]
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|error| PayloadBuildError::InvalidRequest {
        message: format!("test parser invalid UTF-16: {error}"),
    })
}

/// Read a length-prefixed raw byte slice (as written by `add_bytes`).
fn read_bytes<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], PayloadBuildError> {
    let byte_len =
        usize::try_from(read_u32(cursor)?).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "test parser byte-slice length overflow".to_owned(),
        })?;
    take(cursor, byte_len)
}

fn take<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8], PayloadBuildError> {
    if cursor.len() < len {
        return Err(PayloadBuildError::InvalidRequest {
            message: "test parser reached end of buffer".to_owned(),
        });
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

// ── Listener constructor helpers ────────────────────────────────────

fn minimal_config_json() -> Map<String, Value> {
    serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))
    .expect("valid test json")
}

fn http_listener_with_method(method: Option<&str>) -> ListenerConfig {
    ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost:80".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 80,
        port_conn: None,
        method: method.map(str::to_owned),
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
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }))
}

/// Helper: build a minimal HTTPS listener with an optional `ja3_randomize` override.
fn https_listener_with_ja3(ja3_randomize: Option<bool>) -> ListenerConfig {
    ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "https".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost:443".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 443,
        port_conn: None,
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
        ja3_randomize,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }))
}

// ── merged_request_config tests ─────────────────────────────────────

#[test]
fn merged_request_config_applies_profile_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Injection":{"Alloc":"Win32","Execute":"Win32"}}"#,
        "demon",
        &DemonConfig {
            sleep: Some(10),
            jitter: Some(25),
            indirect_syscall: true,
            stack_duplication: true,
            sleep_technique: Some("Ekko".to_owned()),
            proxy_loading: Some("RtlCreateTimer".to_owned()),
            amsi_etw_patching: Some("Hardware breakpoints".to_owned()),
            injection: Some(red_cell_common::config::ProcessInjectionConfig {
                spawn64: Some("C:\\Windows\\System32\\notepad.exe".to_owned()),
                spawn32: Some("C:\\Windows\\SysWOW64\\notepad.exe".to_owned()),
            }),
            dotnet_name_pipe: Some(r"\\.\pipe\red-cell-dotnet".to_owned()),
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;

    assert_eq!(config.get("Sleep"), Some(&Value::String("10".to_owned())));
    assert_eq!(config.get("Jitter"), Some(&Value::String("25".to_owned())));
    assert_eq!(config.get("Indirect Syscall"), Some(&Value::Bool(true)));
    assert_eq!(config.get("Stack Duplication"), Some(&Value::Bool(true)));
    assert_eq!(config.get("Sleep Technique"), Some(&Value::String("Ekko".to_owned())));
    assert_eq!(config.get("DotNetNamePipe"), None);
    assert_eq!(
        config["Injection"]["Spawn64"],
        Value::String("C:\\Windows\\System32\\notepad.exe".to_owned())
    );
    assert_eq!(
        config["Injection"]["Spawn32"],
        Value::String("C:\\Windows\\SysWOW64\\notepad.exe".to_owned())
    );
    Ok(())
}

// ── pack_config binary layout tests ─────────────────────────────────

#[test]
fn pack_config_matches_expected_http_layout() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "15",
        "Indirect Syscall": true,
        "Stack Duplication": true,
        "Sleep Technique": "Ekko",
        "Sleep Jmp Gadget": "jmp rbx",
        "Proxy Loading": "RtlCreateTimer",
        "Amsi/Etw Patch": "Hardware breakpoints",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Native/Syscall",
            "Spawn64": "C:\\Windows\\System32\\notepad.exe",
            "Spawn32": "C:\\Windows\\SysWOW64\\notepad.exe"
        }
    }))?;
    let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: Some("1234".to_owned()),
        working_hours: Some("08:00-17:00".to_owned()),
        hosts: vec!["listener.local".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("Mozilla".to_owned()),
        headers: vec!["Header: One".to_owned()],
        uris: vec!["/beacon".to_owned()],
        host_header: Some("front.local".to_owned()),
        secure: true,
        cert: None,
        response: None,
        proxy: Some(DomainHttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("http".to_owned()),
            host: "proxy.local".to_owned(),
            port: 8080,
            username: Some("neo".to_owned()),
            password: Some(Zeroizing::new("trinity".to_owned())),
        }),
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));

    let bytes = pack_config(&listener, &config, "demon")?;
    let mut cursor = bytes.as_slice();
    assert_eq!(read_u32(&mut cursor)?, 5);
    assert_eq!(read_u32(&mut cursor)?, 15);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 2);
    assert_eq!(read_wstring(&mut cursor)?, "C:\\Windows\\System32\\notepad.exe");
    assert_eq!(read_wstring(&mut cursor)?, "C:\\Windows\\SysWOW64\\notepad.exe");
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 2);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 2);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 1); // HeapEnc (default true)
    // JobExecution and StompDll are Archon-only — absent for demon builds
    assert_eq!(read_u64(&mut cursor)?, 1234);
    assert_eq!(read_u32(&mut cursor)?, 5_243_968);
    assert_eq!(read_wstring(&mut cursor)?, "POST");
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "listener.local");
    assert_eq!(read_u32(&mut cursor)?, 443);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "Mozilla");
    assert_eq!(read_u32(&mut cursor)?, 2);
    assert_eq!(read_wstring(&mut cursor)?, "Header: One");
    assert_eq!(read_wstring(&mut cursor)?, "Host: front.local");
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "/beacon");
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "http://proxy.local:8080");
    assert_eq!(read_wstring(&mut cursor)?, "neo");
    assert_eq!(read_wstring(&mut cursor)?, "trinity");
    assert_eq!(read_u32(&mut cursor)?, 1); // ja3_randomize: true (secure=true, ja3_randomize=None → defaults to true)
    assert_eq!(read_bytes(&mut cursor)?, b""); // DoH domain: disabled (doh_domain=None)
    assert_eq!(read_u32(&mut cursor)?, 0); // DoH provider: Cloudflare (default)
    assert!(cursor.is_empty());
    Ok(())
}

#[test]
fn pack_config_ends_after_listener_specific_fields() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });

    let bytes = pack_config(&listener, &config, "demon")?;
    let mut cursor = bytes.as_slice();
    assert_eq!(read_u32(&mut cursor)?, 5);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "a");
    assert_eq!(read_wstring(&mut cursor)?, "b");
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1); // HeapEnc (default true)
    // JobExecution and StompDll are Archon-only — absent for demon builds
    assert_eq!(read_wstring(&mut cursor)?, r"\\.\pipe\pivot");
    assert_eq!(read_u64(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert!(cursor.is_empty());
    Ok(())
}

#[test]
fn pack_config_http_without_proxy_ends_after_disabled_proxy_flag()
-> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["listener.local".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
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
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));

    let bytes = pack_config(&listener, &config, "demon")?;
    let mut cursor = bytes.as_slice();
    assert_eq!(read_u32(&mut cursor)?, 5);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "a");
    assert_eq!(read_wstring(&mut cursor)?, "b");
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1); // HeapEnc (default true)
    // JobExecution and StompDll are Archon-only — absent for demon builds
    assert_eq!(read_u64(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_wstring(&mut cursor)?, "POST");
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "listener.local");
    assert_eq!(read_u32(&mut cursor)?, 443);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "");
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "Content-type: */*");
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "/");
    assert_eq!(read_u32(&mut cursor)?, 0); // proxy disabled
    assert_eq!(read_u32(&mut cursor)?, 1); // ja3_randomize: true (secure=true, ja3_randomize=None → defaults to true)
    assert_eq!(read_bytes(&mut cursor)?, b""); // DoH domain: disabled (doh_domain=None)
    assert_eq!(read_u32(&mut cursor)?, 0); // DoH provider: Cloudflare (default)
    assert!(cursor.is_empty());
    Ok(())
}

#[test]
fn pack_config_rejects_dns_listener() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
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

    let error =
        pack_config(&listener, &config, "demon").expect_err("dns listener should be rejected");
    assert!(matches!(
        error,
        PayloadBuildError::InvalidRequest { message }
            if message.contains("not supported for Demon payload builds")
    ));
    Ok(())
}

// ── pack_config method tests ────────────────────────────────────────

#[test]
fn pack_config_accepts_post_method() -> Result<(), Box<dyn std::error::Error>> {
    let listener = http_listener_with_method(Some("POST"));
    pack_config(&listener, &minimal_config_json(), "demon").expect("POST should be accepted");
    Ok(())
}

#[test]
fn pack_config_accepts_post_method_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
    let canonical = {
        let listener = http_listener_with_method(Some("POST"));
        pack_config(&listener, &minimal_config_json(), "demon").expect("POST should be accepted")
    };
    let normalised = {
        let listener = http_listener_with_method(Some("post"));
        pack_config(&listener, &minimal_config_json(), "demon")
            .expect("lowercase post should be accepted")
    };
    assert_eq!(
        canonical, normalised,
        "method=post must produce identical bytes to method=POST after case normalisation"
    );
    Ok(())
}

#[test]
fn pack_config_rejects_head_method() {
    let listener = http_listener_with_method(Some("HEAD"));
    let error = pack_config(&listener, &minimal_config_json(), "demon")
        .expect_err("HEAD should be rejected");
    assert!(
        matches!(&error, PayloadBuildError::InvalidRequest { message } if message.contains("HEAD")),
        "unexpected error: {error}"
    );
}

#[test]
fn pack_config_rejects_get_method() {
    let listener = http_listener_with_method(Some("GET"));
    let error = pack_config(&listener, &minimal_config_json(), "demon")
        .expect_err("GET should be rejected");
    assert!(
        matches!(&error, PayloadBuildError::InvalidRequest { message } if message.contains("GET")),
        "unexpected error: {error}"
    );
}

#[test]
fn pack_config_rejects_delete_method() {
    let listener = http_listener_with_method(Some("DELETE"));
    let error = pack_config(&listener, &minimal_config_json(), "demon")
        .expect_err("DELETE should be rejected");
    assert!(
        matches!(&error, PayloadBuildError::InvalidRequest { message } if message.contains("DELETE")),
        "unexpected error: {error}"
    );
}

#[test]
fn pack_config_method_none_defaults_to_post() -> Result<(), Box<dyn std::error::Error>> {
    // Producing a config with method=None should yield the same bytes as method=Some("POST").
    let bytes_default =
        pack_config(&http_listener_with_method(None), &minimal_config_json(), "demon")?;
    let bytes_explicit =
        pack_config(&http_listener_with_method(Some("POST")), &minimal_config_json(), "demon")?;
    assert_eq!(bytes_default, bytes_explicit);
    Ok(())
}

// ── JA3 randomize tests ─────────────────────────────────────────────

#[test]
fn pack_config_ja3_randomize_defaults_to_true_for_https() -> Result<(), Box<dyn std::error::Error>>
{
    // When ja3_randomize is None and the listener is HTTPS, the emitted flag must be 1.
    let bytes_none = pack_config(&https_listener_with_ja3(None), &minimal_config_json(), "demon")?;
    let bytes_true =
        pack_config(&https_listener_with_ja3(Some(true)), &minimal_config_json(), "demon")?;
    assert_eq!(
        bytes_none, bytes_true,
        "None should produce the same bytes as Some(true) for HTTPS"
    );
    Ok(())
}

#[test]
fn pack_config_ja3_randomize_explicit_false_disables_for_https()
-> Result<(), Box<dyn std::error::Error>> {
    // An explicit Some(false) must override the HTTPS default and emit 0.
    let bytes_false =
        pack_config(&https_listener_with_ja3(Some(false)), &minimal_config_json(), "demon")?;
    let bytes_true =
        pack_config(&https_listener_with_ja3(Some(true)), &minimal_config_json(), "demon")?;
    assert_ne!(
        bytes_false, bytes_true,
        "Some(false) and Some(true) should produce different bytes"
    );
    Ok(())
}

#[test]
fn pack_config_ja3_randomize_defaults_to_false_for_plain_http()
-> Result<(), Box<dyn std::error::Error>> {
    // For a plain HTTP (non-TLS) listener, ja3_randomize=None should emit 0.
    let http_none = ListenerConfig::Http(Box::new(HttpListenerConfig {
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
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));
    let http_false = ListenerConfig::Http(Box::new(HttpListenerConfig {
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
        ja3_randomize: Some(false),
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));
    let bytes_none = pack_config(&http_none, &minimal_config_json(), "demon")?;
    let bytes_false = pack_config(&http_false, &minimal_config_json(), "demon")?;
    assert_eq!(bytes_none, bytes_false, "None on plain HTTP should equal Some(false)");
    Ok(())
}

// ── Working hours / kill date / time parsing tests ──────────────────

#[test]
fn parse_working_hours_encodes_expected_bitmask() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(parse_working_hours(Some("08:00-17:00"))?, 5_243_968);
    Ok(())
}

#[test]
fn parse_working_hours_rejects_end_before_start() {
    let err = parse_working_hours(Some("17:00-08:00"));
    assert!(matches!(
        err,
        Err(PayloadBuildError::InvalidRequest { message })
            if message == "WorkingHours end must be after the start"
    ));
}

#[test]
fn parse_working_hours_rejects_equal_start_and_end() {
    let err = parse_working_hours(Some("10:30-10:30"));
    assert!(matches!(
        err,
        Err(PayloadBuildError::InvalidRequest { message })
            if message == "WorkingHours end must be after the start"
    ));
}

#[test]
fn parse_working_hours_rejects_missing_separator() {
    let err = parse_working_hours(Some("0800"));
    assert!(matches!(
        err,
        Err(PayloadBuildError::InvalidRequest { message })
            if message == "WorkingHours must use `HH:MM-HH:MM`"
    ));
}

#[test]
fn parse_working_hours_rejects_junk_input() {
    let err = parse_working_hours(Some("junk"));
    assert!(matches!(
        err,
        Err(PayloadBuildError::InvalidRequest { message })
            if message == "WorkingHours must use `HH:MM-HH:MM`"
    ));
}

#[test]
fn parse_working_hours_rejects_wrong_separator_format() {
    // Colon-separated only, no dash separator
    let err = parse_working_hours(Some("08:00:17:00"));
    assert!(matches!(
        err,
        Err(PayloadBuildError::InvalidRequest { message })
            if message == "WorkingHours must use `HH:MM-HH:MM`"
    ));
}

#[test]
fn parse_kill_date_accepts_positive_timestamp() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(parse_kill_date(Some("1234"))?, 1234);
    Ok(())
}

#[test]
fn parse_kill_date_rejects_negative_timestamp() {
    let err = parse_kill_date(Some("-1"));
    assert!(matches!(
        err,
        Err(PayloadBuildError::InvalidRequest { message })
            if message == "KillDate `-1` must be a non-negative unix timestamp"
    ));
}

#[test]
fn parse_hour_minute_accepts_max_valid_time() -> Result<(), Box<dyn std::error::Error>> {
    let (h, m) = parse_hour_minute("23:59")?;
    assert_eq!(h, 23);
    assert_eq!(m, 59);
    Ok(())
}

#[test]
fn parse_hour_minute_rejects_hour_24() {
    let err = parse_hour_minute("24:00");
    assert!(matches!(err, Err(PayloadBuildError::InvalidRequest { .. })));
}

#[test]
fn parse_hour_minute_rejects_minute_60() {
    let err = parse_hour_minute("00:60");
    assert!(matches!(err, Err(PayloadBuildError::InvalidRequest { .. })));
}

#[test]
fn parse_hour_minute_rejects_24_60() {
    let err = parse_hour_minute("24:60");
    assert!(matches!(err, Err(PayloadBuildError::InvalidRequest { .. })));
}

#[test]
fn add_bytes_writes_length_prefixed_data() -> Result<(), PayloadBuildError> {
    let mut buf = Vec::new();
    add_bytes(&mut buf, b"hello")?;
    assert_eq!(&buf[..4], &5_u32.to_le_bytes());
    assert_eq!(&buf[4..], b"hello");
    Ok(())
}

#[test]
fn add_bytes_returns_error_for_empty_after_wstring() -> Result<(), PayloadBuildError> {
    let mut buf = Vec::new();
    add_wstring(&mut buf, "")?;
    assert_eq!(&buf[..4], &2_u32.to_le_bytes(), "empty string still has null terminator");
    Ok(())
}

#[test]
fn parse_hour_minute_accepts_zero() -> Result<(), Box<dyn std::error::Error>> {
    let (h, m) = parse_hour_minute("00:00")?;
    assert_eq!(h, 0);
    assert_eq!(m, 0);
    Ok(())
}

// ── Config value mapping tests ──────────────────────────────────────

#[test]
fn sleep_obfuscation_value_maps_known_techniques() {
    assert_eq!(sleep_obfuscation_value("Foliage"), 3);
    assert_eq!(sleep_obfuscation_value("Ekko"), 1);
    assert_eq!(sleep_obfuscation_value("Zilean"), 2);
}

#[test]
fn sleep_obfuscation_value_returns_zero_for_unknown() {
    assert_eq!(sleep_obfuscation_value("WaitForSingleObjectEx"), 0);
    assert_eq!(sleep_obfuscation_value("Unknown"), 0);
    assert_eq!(sleep_obfuscation_value(""), 0);
}

#[test]
fn sleep_jump_bypass_returns_zero_when_obfuscation_disabled() {
    assert_eq!(sleep_jump_bypass(0, Some("jmp rax")).expect("unwrap"), 0);
    assert_eq!(sleep_jump_bypass(0, Some("jmp rbx")).expect("unwrap"), 0);
    assert_eq!(sleep_jump_bypass(0, None).expect("unwrap"), 0);
}

#[test]
fn sleep_jump_bypass_maps_gadgets_when_obfuscation_enabled() {
    assert_eq!(sleep_jump_bypass(1, Some("jmp rax")).expect("unwrap"), 1);
    assert_eq!(sleep_jump_bypass(1, Some("jmp rbx")).expect("unwrap"), 2);
    assert_eq!(sleep_jump_bypass(1, None).expect("unwrap"), 0);
    assert_eq!(sleep_jump_bypass(1, Some("unknown")).expect("unwrap"), 0);
}

#[test]
fn proxy_loading_value_maps_known_methods() {
    assert_eq!(proxy_loading_value(Some("RtlRegisterWait")), 1);
    assert_eq!(proxy_loading_value(Some("RtlCreateTimer")), 2);
    assert_eq!(proxy_loading_value(Some("RtlQueueWorkItem")), 3);
}

#[test]
fn proxy_loading_value_defaults_to_zero() {
    assert_eq!(proxy_loading_value(None), 0);
    assert_eq!(proxy_loading_value(Some("None (LdrLoadDll)")), 0);
    assert_eq!(proxy_loading_value(Some("unknown")), 0);
}

#[test]
fn amsi_patch_value_maps_known_methods() {
    // Legacy value strings (backward compat)
    assert_eq!(amsi_patch_value(Some("Hardware breakpoints")), 1);
    assert_eq!(amsi_patch_value(Some("Memory")), 2);
    // ARC-01 canonical profile values
    assert_eq!(amsi_patch_value(Some("hwbp")), 1);
    assert_eq!(amsi_patch_value(Some("patch")), 2);
    assert_eq!(amsi_patch_value(Some("none")), 0);
}

#[test]
fn amsi_patch_value_defaults_to_zero() {
    assert_eq!(amsi_patch_value(None), 0);
    assert_eq!(amsi_patch_value(Some("")), 0);
    assert_eq!(amsi_patch_value(Some("unknown")), 0);
}

#[test]
fn merged_request_config_archon_defaults_amsi_to_patch() -> Result<(), Box<dyn std::error::Error>> {
    // When AmsiEtw is absent from both request and profile, Archon
    // should default to "patch" (AMSIETW_PATCH_MEMORY = 2).
    let config = merged_request_config(
        r#"{}"#,
        "archon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    assert_eq!(
        config.get("Amsi/Etw Patch"),
        Some(&Value::String("patch".to_owned())),
        "Archon without an explicit AmsiEtw key should default to 'patch'"
    );
    Ok(())
}

#[test]
fn merged_request_config_archon_profile_amsi_overrides_default()
-> Result<(), Box<dyn std::error::Error>> {
    // An explicit profile value must take precedence over the Archon default.
    let config = merged_request_config(
        r#"{}"#,
        "archon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: Some("hwbp".to_owned()),
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    assert_eq!(
        config.get("Amsi/Etw Patch"),
        Some(&Value::String("hwbp".to_owned())),
        "explicit profile AmsiEtw must win over the Archon default"
    );
    Ok(())
}

#[test]
fn merged_request_config_demon_amsi_stays_none_by_default() -> Result<(), Box<dyn std::error::Error>>
{
    // For Demon, absence of AmsiEtw in the profile should leave it unset
    // (serialises to 0 = AMSIETW_PATCH_NONE in the agent config bytes).
    let config = merged_request_config(
        r#"{}"#,
        "demon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    assert_eq!(
        config.get("Amsi/Etw Patch"),
        None,
        "Demon without an explicit AmsiEtw key should leave the field absent"
    );
    Ok(())
}

// ── injection_mode tests ────────────────────────────────────────────

#[test]
fn injection_mode_maps_known_values() -> Result<(), PayloadBuildError> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Alloc": "Win32",
        "Execute": "Native/Syscall"
    }))
    .expect("unwrap");
    assert_eq!(injection_mode(&config, "Alloc")?, 1);
    assert_eq!(injection_mode(&config, "Execute")?, 2);
    Ok(())
}

#[test]
fn injection_mode_returns_zero_for_unknown() -> Result<(), PayloadBuildError> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Alloc": "Unknown"
    }))
    .expect("unwrap");
    assert_eq!(injection_mode(&config, "Alloc")?, 0);
    Ok(())
}

// ── pack_config validation edge cases ───────────────────────────────

#[test]
fn pack_config_rejects_jitter_above_100() {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "101",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))
    .expect("unwrap");
    let listener = http_listener_with_method(None);
    let err =
        pack_config(&listener, &config, "demon").expect_err("jitter > 100 should be rejected");
    assert!(matches!(
        err,
        PayloadBuildError::InvalidRequest { message }
            if message.contains("Jitter") && message.contains("100")
    ));
}

#[test]
fn pack_config_accepts_jitter_at_boundary_100() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "100",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = http_listener_with_method(None);
    pack_config(&listener, &config, "demon")?;
    Ok(())
}

#[test]
fn pack_config_accepts_jitter_at_boundary_0() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = http_listener_with_method(None);
    pack_config(&listener, &config, "demon")?;
    Ok(())
}

#[test]
fn pack_config_heap_enc_false_is_packed_as_zero() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "HeapEnc": false,
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });

    let bytes = pack_config(&listener, &config, "demon")?;
    let mut cursor = bytes.as_slice();
    assert_eq!(read_u32(&mut cursor)?, 5);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "a");
    assert_eq!(read_wstring(&mut cursor)?, "b");
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0); // HeapEnc (explicit false)
    // JobExecution and StompDll are Archon-only — absent for demon builds
    assert_eq!(read_wstring(&mut cursor)?, r"\\.\pipe\pivot");
    assert_eq!(read_u64(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert!(cursor.is_empty());
    Ok(())
}

#[test]
fn merged_request_config_propagates_heap_enc_false_from_profile_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "demon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: false,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    assert_eq!(config.get("HeapEnc"), Some(&Value::Bool(false)));
    Ok(())
}

#[test]
fn pack_config_job_execution_threadpool_is_packed_as_one() -> Result<(), Box<dyn std::error::Error>>
{
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "JobExecution": "threadpool",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });
    let bytes = pack_config(&listener, &config, "archon")?;
    let mut cursor = bytes.as_slice();
    // skip sleep, jitter, alloc, execute, spawn64, spawn32, technique, bypass, stackspoof,
    // proxyloading, syscall, amsi, heapenc
    read_u32(&mut cursor)?; // sleep
    read_u32(&mut cursor)?; // jitter
    read_u32(&mut cursor)?; // alloc
    read_u32(&mut cursor)?; // execute
    read_wstring(&mut cursor)?; // spawn64
    read_wstring(&mut cursor)?; // spawn32
    read_u32(&mut cursor)?; // SleepTechnique
    read_u32(&mut cursor)?; // SleepJmpBypass
    read_u32(&mut cursor)?; // StackSpoof
    read_u32(&mut cursor)?; // ProxyLoading
    read_u32(&mut cursor)?; // SysIndirect
    read_u32(&mut cursor)?; // AmsiEtwPatch
    read_u32(&mut cursor)?; // HeapEnc
    assert_eq!(read_u32(&mut cursor)?, 1); // JobExecution: threadpool (Archon-only)
    assert_eq!(read_wstring(&mut cursor)?, ""); // StompDll: auto-select (Archon-only)
    Ok(())
}

#[test]
fn pack_config_stomp_dll_is_packed_as_wstring() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "StompDll": "WINMM.DLL",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });
    let bytes = pack_config(&listener, &config, "archon")?;
    let mut cursor = bytes.as_slice();
    read_u32(&mut cursor)?; // sleep
    read_u32(&mut cursor)?; // jitter
    read_u32(&mut cursor)?; // alloc
    read_u32(&mut cursor)?; // execute
    read_wstring(&mut cursor)?; // spawn64
    read_wstring(&mut cursor)?; // spawn32
    read_u32(&mut cursor)?; // SleepTechnique
    read_u32(&mut cursor)?; // SleepJmpBypass
    read_u32(&mut cursor)?; // StackSpoof
    read_u32(&mut cursor)?; // ProxyLoading
    read_u32(&mut cursor)?; // SysIndirect
    read_u32(&mut cursor)?; // AmsiEtwPatch
    read_u32(&mut cursor)?; // HeapEnc
    assert_eq!(read_u32(&mut cursor)?, 0); // JobExecution: thread (default, Archon-only)
    assert_eq!(read_wstring(&mut cursor)?, "WINMM.DLL"); // StompDll (Archon-only)
    Ok(())
}

#[test]
fn pack_config_demon_excludes_archon_only_fields() -> Result<(), Box<dyn std::error::Error>> {
    // Demon blobs must NOT include JobExecution or StompDll, even when those
    // keys are present in the config map.  After HeapEnc, the next bytes must
    // be the SMB pipe wstring, not a u32 JobExecution value.
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "JobExecution": "threadpool",
        "StompDll": "WINMM.DLL",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });
    let bytes = pack_config(&listener, &config, "demon")?;
    let mut cursor = bytes.as_slice();
    read_u32(&mut cursor)?; // sleep
    read_u32(&mut cursor)?; // jitter
    read_u32(&mut cursor)?; // alloc
    read_u32(&mut cursor)?; // execute
    read_wstring(&mut cursor)?; // spawn64
    read_wstring(&mut cursor)?; // spawn32
    read_u32(&mut cursor)?; // SleepTechnique
    read_u32(&mut cursor)?; // SleepJmpBypass
    read_u32(&mut cursor)?; // StackSpoof
    read_u32(&mut cursor)?; // ProxyLoading
    read_u32(&mut cursor)?; // SysIndirect
    read_u32(&mut cursor)?; // AmsiEtwPatch
    read_u32(&mut cursor)?; // HeapEnc
    // Next field must be the pipe path — JobExecution/StompDll must not be present
    assert_eq!(read_wstring(&mut cursor)?, r"\\.\pipe\pivot");
    read_u64(&mut cursor)?; // KillDate
    read_u32(&mut cursor)?; // WorkingHours
    assert!(cursor.is_empty(), "demon blob has unexpected trailing bytes (Archon fields leaked)");
    Ok(())
}

#[test]
fn merged_request_config_propagates_job_execution_from_archon_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "archon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Threadpool,
            stomp_dll: None,
        },
    )?;
    assert_eq!(config.get("JobExecution"), Some(&Value::String("threadpool".to_owned())));
    Ok(())
}

#[test]
fn merged_request_config_propagates_stomp_dll_from_archon_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "archon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: Some("WINMM.DLL".to_owned()),
        },
    )?;
    assert_eq!(config.get("StompDll"), Some(&Value::String("WINMM.DLL".to_owned())));
    Ok(())
}

#[test]
fn merged_request_config_does_not_propagate_archon_keys_for_demon()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"5","Jitter":"0","Sleep Technique":"WaitForSingleObjectEx","Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"a","Spawn32":"b"}}"#,
        "demon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Threadpool,
            stomp_dll: Some("WINMM.DLL".to_owned()),
        },
    )?;
    assert_eq!(config.get("JobExecution"), None);
    assert_eq!(config.get("StompDll"), None);
    Ok(())
}

// ── merged_request_config override tests ────────────────────────────

#[test]
fn merged_request_config_request_overrides_profile_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Sleep":"20","Jitter":"50","Injection":{"Alloc":"Win32","Execute":"Win32"}}"#,
        "demon",
        &DemonConfig {
            sleep: Some(5),
            jitter: Some(10),
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    // Request values should override profile defaults.
    assert_eq!(config.get("Sleep"), Some(&Value::String("20".to_owned())));
    assert_eq!(config.get("Jitter"), Some(&Value::String("50".to_owned())));
    Ok(())
}

#[test]
fn merged_request_config_injection_spawn_overrides_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let config = merged_request_config(
        r#"{"Injection":{"Alloc":"Win32","Execute":"Win32","Spawn64":"custom64.exe","Spawn32":"custom32.exe"}}"#,
        "demon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: Some(red_cell_common::config::ProcessInjectionConfig {
                spawn64: Some("default64.exe".to_owned()),
                spawn32: Some("default32.exe".to_owned()),
            }),
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )?;
    assert_eq!(config["Injection"]["Spawn64"], Value::String("custom64.exe".to_owned()));
    assert_eq!(config["Injection"]["Spawn32"], Value::String("custom32.exe".to_owned()));
    Ok(())
}

#[test]
fn merged_request_config_rejects_non_object_input() {
    let err = merged_request_config(
        r#""just a string""#,
        "demon",
        &DemonConfig {
            sleep: None,
            jitter: None,
            indirect_syscall: false,
            stack_duplication: false,
            sleep_technique: None,
            proxy_loading: None,
            amsi_etw_patching: None,
            injection: None,
            dotnet_name_pipe: None,
            binary: None,
            init_secret: None,
            init_secrets: Vec::new(),
            trust_x_forwarded_for: false,
            trusted_proxy_peers: Vec::new(),
            heap_enc: true,
            allow_legacy_ctr: false,
            job_execution: JobExecutionMode::Thread,
            stomp_dll: None,
        },
    )
    .expect_err("non-object JSON should be rejected");
    assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
        if message.contains("JSON object")));
}

// ── proxy_url tests ─────────────────────────────────────────────────

#[test]
fn proxy_url_formats_with_default_scheme() {
    let proxy = DomainHttpListenerProxyConfig {
        enabled: true,
        proxy_type: None,
        host: "proxy.local".to_owned(),
        port: 8080,
        username: None,
        password: None,
    };
    assert_eq!(proxy_url(&proxy), "http://proxy.local:8080");
}

#[test]
fn proxy_url_uses_configured_scheme() {
    let proxy = DomainHttpListenerProxyConfig {
        enabled: true,
        proxy_type: Some("socks5".to_owned()),
        host: "socks.local".to_owned(),
        port: 1080,
        username: None,
        password: None,
    };
    assert_eq!(proxy_url(&proxy), "socks5://socks.local:1080");
}

// ── parse_header_u32_field tests ────────────────────────────────────

#[test]
fn parse_header_u32_field_decimal() -> Result<(), PayloadBuildError> {
    assert_eq!(parse_header_u32_field("CompileTime", "42")?, 42);
    Ok(())
}

#[test]
fn parse_header_u32_field_hex_lowercase() -> Result<(), PayloadBuildError> {
    assert_eq!(parse_header_u32_field("CompileTime", "0x1a2b")?, 0x1a2b);
    Ok(())
}

#[test]
fn parse_header_u32_field_hex_uppercase_prefix() -> Result<(), PayloadBuildError> {
    assert_eq!(parse_header_u32_field("CompileTime", "0X1A2B")?, 0x1a2b);
    Ok(())
}

#[test]
fn parse_header_u32_field_trims_whitespace() -> Result<(), PayloadBuildError> {
    assert_eq!(parse_header_u32_field("CompileTime", "  100  ")?, 100);
    Ok(())
}

#[test]
fn parse_header_u32_field_rejects_non_numeric() {
    let err = parse_header_u32_field("CompileTime", "not-a-number")
        .expect_err("non-numeric should be rejected");
    assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
}

// ── required_u32 parsing tests ──────────────────────────────────────

#[test]
fn required_u32_parses_string_value() -> Result<(), PayloadBuildError> {
    let config =
        serde_json::from_value::<Map<String, Value>>(json!({"val": "42"})).expect("unwrap");
    assert_eq!(required_u32(&config, "val")?, 42);
    Ok(())
}

#[test]
fn required_u32_parses_number_value() -> Result<(), PayloadBuildError> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({"val": 42})).expect("unwrap");
    assert_eq!(required_u32(&config, "val")?, 42);
    Ok(())
}

#[test]
fn required_u32_rejects_missing_key() {
    let config = serde_json::from_value::<Map<String, Value>>(json!({})).expect("unwrap");
    let err = required_u32(&config, "missing").expect_err("missing key should fail");
    assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
        if message.contains("missing")));
}

#[test]
fn required_u32_rejects_non_numeric_string() {
    let config =
        serde_json::from_value::<Map<String, Value>>(json!({"val": "abc"})).expect("unwrap");
    let err = required_u32(&config, "val").expect_err("non-numeric should fail");
    assert!(matches!(err, PayloadBuildError::InvalidRequest { .. }));
}

// ── DoH packing tests ───────────────────────────────────────────────

#[test]
fn pack_http_listener_packs_doh_domain_and_provider_cloudflare()
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
        ja3_randomize: Some(false),
        doh_domain: Some("c2.example.com".to_owned()),
        doh_provider: Some("cloudflare".to_owned()),
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));
    let bytes = pack_config(&listener, &minimal_config_json(), "demon")?;
    let mut cursor = bytes.as_slice();
    // Skip to the DoH fields: consume all preceding fields.
    // Sleep, Jitter, Alloc, Execute, Spawn64, Spawn32, SleepTech, SleepJmp,
    // StackSpoof, ProxyLoading, SysIndirect, AmsiEtwPatch, HeapEnc
    read_u32(&mut cursor)?; // Sleep
    read_u32(&mut cursor)?; // Jitter
    read_u32(&mut cursor)?; // Alloc
    read_u32(&mut cursor)?; // Execute
    read_wstring(&mut cursor)?; // Spawn64
    read_wstring(&mut cursor)?; // Spawn32
    read_u32(&mut cursor)?; // SleepTechnique
    read_u32(&mut cursor)?; // SleepJmpBypass
    read_u32(&mut cursor)?; // StackSpoof
    read_u32(&mut cursor)?; // ProxyLoading
    read_u32(&mut cursor)?; // SysIndirect
    read_u32(&mut cursor)?; // AmsiEtwPatch
    read_u32(&mut cursor)?; // HeapEnc
    // JobExecution and StompDll are Archon-only — absent for demon builds
    // HTTP-transport fields
    read_u64(&mut cursor)?; // KillDate
    read_u32(&mut cursor)?; // WorkingHours
    read_wstring(&mut cursor)?; // Method
    read_u32(&mut cursor)?; // HostRotation
    read_u32(&mut cursor)?; // host count
    read_wstring(&mut cursor)?; // host
    read_u32(&mut cursor)?; // port
    read_u32(&mut cursor)?; // Secure
    read_wstring(&mut cursor)?; // UserAgent
    read_u32(&mut cursor)?; // header count (1: Content-type)
    read_wstring(&mut cursor)?; // header
    read_u32(&mut cursor)?; // uri count (1: /)
    read_wstring(&mut cursor)?; // uri
    read_u32(&mut cursor)?; // Proxy enabled (0)
    read_u32(&mut cursor)?; // Ja3Randomize
    // DoH fields
    assert_eq!(read_bytes(&mut cursor)?, b"c2.example.com");
    assert_eq!(read_u32(&mut cursor)?, 0); // Cloudflare
    assert!(cursor.is_empty());
    Ok(())
}

#[test]
fn pack_http_listener_packs_doh_provider_google() -> Result<(), Box<dyn std::error::Error>> {
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
        ja3_randomize: Some(false),
        doh_domain: Some("c2.example.com".to_owned()),
        doh_provider: Some("google".to_owned()),
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }));
    let with_google = pack_config(&listener, &minimal_config_json(), "demon")?;
    // Verify the last 4 bytes (provider) are 1 = Google.
    let provider =
        u32::from_le_bytes(with_google[with_google.len() - 4..].try_into().expect("last 4 bytes"));
    assert_eq!(provider, 1, "Google provider should be encoded as 1");
    Ok(())
}
