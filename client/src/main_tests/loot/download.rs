use super::*;

#[test]
fn download_loot_item_rejects_missing_content() {
    let item = LootItem {
        id: None,
        kind: LootKind::File,
        name: "report.txt".to_owned(),
        agent_id: "ABCD1234".to_owned(),
        source: "download".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: Some("C:\\Temp\\report.txt".to_owned()),
        size_bytes: Some(12),
        content_base64: None,
        preview: None,
    };

    let error =
        download_loot_item(&item).expect_err("download_loot_item should reject missing content");
    assert_eq!(error, "This loot item does not include downloadable content.");
}

#[test]
fn download_loot_item_reports_decode_failures() {
    let item = LootItem {
        id: None,
        kind: LootKind::Screenshot,
        name: "desktop.png".to_owned(),
        agent_id: "ABCD1234".to_owned(),
        source: "download".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: None,
        size_bytes: Some(12),
        content_base64: Some("%%% definitely-not-base64 %%%".to_owned()),
        preview: None,
    };

    let error =
        download_loot_item(&item).expect_err("download_loot_item should reject invalid base64");
    assert!(error.starts_with("Failed to decode loot payload: "));
}

#[test]
fn download_loot_item_saves_bytes_with_sanitized_file_name() {
    let _guard = lock_export_test();
    let unique_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system clock should be after unix epoch: {error}"))
        .as_nanos();
    let file_stub = format!("report-{unique_id}");
    let expected_bytes = b"loot-bytes-\x00\xFF";
    let output_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    let item = LootItem {
        id: Some(9),
        kind: LootKind::File,
        name: "fallback-name.bin".to_owned(),
        agent_id: "ABCD1234".to_owned(),
        source: "download".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: Some(format!("C:\\Temp\\{file_stub}:Q1?.zip")),
        size_bytes: Some(expected_bytes.len() as u64),
        content_base64: Some(base64::engine::general_purpose::STANDARD.encode(expected_bytes)),
        preview: None,
    };

    let message = download_loot_item(&item)
        .unwrap_or_else(|error| panic!("download_loot_item should succeed: {error}"));
    let saved_path = PathBuf::from(
        message
            .strip_prefix("Saved ")
            .unwrap_or_else(|| panic!("save message missing path: {message}")),
    );
    assert_eq!(saved_path.parent(), Some(output_dir.as_path()));
    let saved_file_name = saved_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_else(|| panic!("saved path missing file name: {}", saved_path.display()));
    assert!(saved_file_name.starts_with("C__Temp_report-"));
    assert!(saved_file_name.contains(&file_stub));
    assert!(saved_file_name.ends_with("_Q1_.zip"));
    let saved_bytes = std::fs::read(&saved_path).unwrap_or_else(|error| {
        panic!("failed to read saved file {}: {error}", saved_path.display())
    });
    assert_eq!(saved_bytes, expected_bytes);
    std::fs::remove_file(&saved_path).unwrap_or_else(|error| {
        panic!("failed to remove saved file {}: {error}", saved_path.display())
    });
}

#[test]
fn loot_is_downloadable_file_with_content() {
    let mut item = make_loot(LootKind::File);
    item.content_base64 = Some("dGVzdA==".to_owned());
    assert!(loot_is_downloadable(&item));
}

#[test]
fn loot_is_downloadable_screenshot_with_content() {
    let mut item = make_loot(LootKind::Screenshot);
    item.content_base64 = Some("dGVzdA==".to_owned());
    assert!(loot_is_downloadable(&item));
}

#[test]
fn loot_not_downloadable_file_without_content() {
    let item = make_loot(LootKind::File);
    assert!(!loot_is_downloadable(&item));
}

#[test]
fn loot_not_downloadable_credential() {
    let mut item = make_loot(LootKind::Credential);
    item.content_base64 = Some("dGVzdA==".to_owned());
    assert!(!loot_is_downloadable(&item));
}

#[test]
fn loot_not_downloadable_other() {
    let item = make_loot(LootKind::Other);
    assert!(!loot_is_downloadable(&item));
}
