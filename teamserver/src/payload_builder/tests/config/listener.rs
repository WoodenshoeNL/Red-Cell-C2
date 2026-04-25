use super::*;

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
    // HeapEnc, JobExecution, StompDll are Archon-only — absent for demon builds
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
    // HeapEnc, JobExecution, StompDll are Archon-only — absent for demon builds
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
    // HeapEnc, JobExecution, StompDll are Archon-only — absent for demon builds
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
    // StackSpoof, ProxyLoading, SysIndirect, AmsiEtwPatch
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
    // HeapEnc, JobExecution, StompDll are Archon-only — absent for demon builds
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
