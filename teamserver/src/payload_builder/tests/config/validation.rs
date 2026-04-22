use super::*;

// ── pack_config listener-type rejection tests ────────────────────────

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

// ── pack_config HTTP method rejection tests ──────────────────────────

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
fn parse_hour_minute_accepts_zero() -> Result<(), Box<dyn std::error::Error>> {
    let (h, m) = parse_hour_minute("00:00")?;
    assert_eq!(h, 0);
    assert_eq!(m, 0);
    Ok(())
}

// ── add_bytes / add_wstring primitive tests ─────────────────────────

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

// ── pack_config jitter validation tests ─────────────────────────────

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
