use super::*;

#[test]
fn sanitize_file_name_replaces_invalid_characters() {
    assert_eq!(sanitize_file_name("C:\\Temp\\report?.txt"), "C__Temp_report_.txt");
}

#[test]
fn sanitize_file_name_returns_fallback_for_empty_input() {
    assert_eq!(sanitize_file_name(""), "loot.bin");
}

#[test]
fn sanitize_file_name_returns_fallback_for_whitespace_only() {
    assert_eq!(sanitize_file_name("   "), "loot.bin");
}

#[test]
fn sanitize_file_name_preserves_safe_names() {
    assert_eq!(sanitize_file_name("screenshot.png"), "screenshot.png");
}

#[test]
fn derive_download_file_name_uses_file_path_basename() {
    let item = LootItem {
        id: None,
        kind: LootKind::File,
        name: "fallback-name.bin".to_owned(),
        agent_id: "AGENT01".to_owned(),
        source: "download".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: Some("/home/user/Documents/secrets.docx".to_owned()),
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    assert_eq!(derive_download_file_name(&item), "secrets.docx");
}

#[test]
fn derive_download_file_name_falls_back_to_name_when_no_file_path() {
    let item = LootItem {
        id: None,
        kind: LootKind::Screenshot,
        name: "desktop.png".to_owned(),
        agent_id: "AGENT01".to_owned(),
        source: "screenshot".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    assert_eq!(derive_download_file_name(&item), "desktop.png");
}

#[test]
fn derive_download_file_name_sanitizes_dangerous_characters() {
    let item = LootItem {
        id: None,
        kind: LootKind::File,
        name: "fallback.bin".to_owned(),
        agent_id: "AGENT01".to_owned(),
        source: "download".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: Some("/tmp/report<v2>.txt".to_owned()),
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    assert_eq!(derive_download_file_name(&item), "report_v2_.txt");
}

#[test]
fn derive_download_file_name_falls_back_to_name_when_file_path_has_no_basename() {
    let item = LootItem {
        id: None,
        kind: LootKind::File,
        name: "my-report.txt".to_owned(),
        agent_id: "AGENT01".to_owned(),
        source: "download".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: Some("/".to_owned()),
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    assert_eq!(derive_download_file_name(&item), "my-report.txt");
}

#[test]
fn next_available_path_returns_original_when_no_collision() {
    let dir = std::env::temp_dir().join("rc2-test-navail-nocoll");
    let _ = std::fs::create_dir_all(&dir);
    let candidate = dir.join("unique-file.txt");
    // Ensure it does not exist
    let _ = std::fs::remove_file(&candidate);
    assert_eq!(next_available_path(&candidate), candidate);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn next_available_path_appends_suffix_on_collision() {
    let dir = std::env::temp_dir().join("rc2-test-navail-coll1");
    let _ = std::fs::create_dir_all(&dir);
    let base = dir.join("report.txt");
    std::fs::write(&base, b"existing").unwrap_or_else(|e| panic!("write failed: {e}"));

    let result = next_available_path(&base);
    assert_eq!(result, dir.join("report-1.txt"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn next_available_path_skips_multiple_collisions() {
    let dir = std::env::temp_dir().join("rc2-test-navail-multi");
    let _ = std::fs::create_dir_all(&dir);
    let base = dir.join("data.csv");
    std::fs::write(&base, b"v0").unwrap_or_else(|e| panic!("write failed: {e}"));
    std::fs::write(dir.join("data-1.csv"), b"v1").unwrap_or_else(|e| panic!("write failed: {e}"));
    std::fs::write(dir.join("data-2.csv"), b"v2").unwrap_or_else(|e| panic!("write failed: {e}"));

    let result = next_available_path(&base);
    assert_eq!(result, dir.join("data-3.csv"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn next_available_path_handles_no_extension() {
    let dir = std::env::temp_dir().join("rc2-test-navail-noext");
    let _ = std::fs::create_dir_all(&dir);
    let base = dir.join("README");
    std::fs::write(&base, b"exists").unwrap_or_else(|e| panic!("write failed: {e}"));

    let result = next_available_path(&base);
    assert_eq!(result, dir.join("README-1"));

    let _ = std::fs::remove_dir_all(&dir);
}
