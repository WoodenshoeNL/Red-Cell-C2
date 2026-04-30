use super::super::inspect::InspectResult;
use super::super::inspect_local;
use crate::error::EXIT_SUCCESS;
use crate::output::{OutputFormat, TextRender};

// ── inspect_local ─────────────────────────────────────────────────────────────

#[test]
fn inspect_local_returns_success_for_valid_manifest() {
    use red_cell_common::payload_manifest::{PayloadManifest, encode_manifest};

    let manifest = PayloadManifest {
        agent_type: "Demon".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        hosts: vec!["192.168.1.100".to_owned()],
        port: Some(443),
        secure: true,
        callback_url: Some("https://192.168.1.100:443/".to_owned()),
        sleep_ms: Some(5000),
        jitter: Some(20),
        init_secret_hash: Some("abc123def4567890".to_owned()),
        kill_date: None,
        working_hours_mask: None,
        listener_name: "http1".to_owned(),
        export_name: None,
        built_at: "2026-04-25T12:00:00Z".to_owned(),
    };

    let mut payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    payload.extend_from_slice(&[0u8; 100]);
    payload.extend_from_slice(&encode_manifest(&manifest).expect("encode"));

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.exe");
    std::fs::write(&path, &payload).expect("write");

    let code = inspect_local(path.to_str().expect("path"), &OutputFormat::Json);
    assert_eq!(code, EXIT_SUCCESS);
}

#[test]
fn inspect_local_returns_error_for_missing_file() {
    let code = inspect_local("/nonexistent/file.exe", &OutputFormat::Json);
    assert_ne!(code, EXIT_SUCCESS);
}

#[test]
fn inspect_local_returns_error_for_no_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bare.bin");
    std::fs::write(&path, b"no manifest here").expect("write");

    let code = inspect_local(path.to_str().expect("path"), &OutputFormat::Json);
    assert_ne!(code, EXIT_SUCCESS);
}

// ── InspectResult rendering/serialization ─────────────────────────────────────

#[test]
fn inspect_result_text_render_includes_key_fields() {
    let result = InspectResult {
        agent_type: "Phantom".to_owned(),
        arch: "x64".to_owned(),
        format: "elf".to_owned(),
        callback_url: Some("https://10.0.0.1:8443/".to_owned()),
        hosts: vec!["10.0.0.1".to_owned()],
        port: Some(8443),
        secure: true,
        sleep_ms: Some(10000),
        jitter: Some(50),
        init_secret_hash: Some("0123456789abcdef".to_owned()),
        kill_date: Some("2027-01-01T00:00:00Z".to_owned()),
        working_hours_mask: Some(0x00FF_FF00),
        listener_name: "https-main".to_owned(),
        export_name: None,
        built_at: "2026-04-25T12:00:00Z".to_owned(),
    };

    let text = result.render_text();
    assert!(text.contains("Phantom"), "agent_type");
    assert!(text.contains("https://10.0.0.1:8443/"), "callback_url");
    assert!(text.contains("10000 ms"), "sleep");
    assert!(text.contains("50%"), "jitter");
    assert!(text.contains("0123456789abcdef"), "init_secret_hash");
    assert!(text.contains("2027-01-01"), "kill_date");
    assert!(text.contains("0x00FFFF00"), "working_hours_mask");
}

#[test]
fn inspect_result_serialises_to_json() {
    let result = InspectResult {
        agent_type: "Demon".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        callback_url: None,
        hosts: vec!["c2.example.com".to_owned()],
        port: Some(443),
        secure: true,
        sleep_ms: None,
        jitter: None,
        init_secret_hash: None,
        kill_date: None,
        working_hours_mask: None,
        listener_name: "http1".to_owned(),
        export_name: None,
        built_at: "2026-04-25T00:00:00Z".to_owned(),
    };
    let json = serde_json::to_value(&result).expect("serialize");
    assert_eq!(json["agent_type"], "Demon");
    assert_eq!(json["hosts"][0], "c2.example.com");
    assert!(json["callback_url"].is_null());
}
