use super::*;

#[test]
fn loot_filter_matches_type_agent_and_text() {
    let item = LootItem {
        id: None,
        kind: LootKind::Screenshot,
        name: "desktop.png".to_owned(),
        agent_id: "ABCD1234".to_owned(),
        source: "download".to_owned(),
        collected_at: "2026-03-10T12:00:00Z".to_owned(),
        file_path: Some("C:/Temp/desktop.png".to_owned()),
        size_bytes: Some(1024),
        content_base64: None,
        preview: Some("primary desktop".to_owned()),
    };

    assert!(loot_matches_filters(
        &item,
        LootTypeFilter::Screenshots,
        CredentialSubFilter::All,
        FileSubFilter::All,
        "abcd",
        "",
        "",
        "desktop"
    ));
    assert!(!loot_matches_filters(
        &item,
        LootTypeFilter::Credentials,
        CredentialSubFilter::All,
        FileSubFilter::All,
        "",
        "",
        "",
        ""
    ));
}

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
fn loot_time_range_filter_since_excludes_older_items() {
    let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-05T10:00:00Z");
    // since=2026-03-10 should exclude an item collected on 2026-03-05
    assert!(!loot_matches_filters(
        &item,
        LootTypeFilter::All,
        CredentialSubFilter::All,
        FileSubFilter::All,
        "",
        "2026-03-10",
        "",
        ""
    ));
}

#[test]
fn loot_time_range_filter_until_excludes_newer_items() {
    let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-20T10:00:00Z");
    // until=2026-03-15 should exclude an item collected on 2026-03-20
    assert!(!loot_matches_filters(
        &item,
        LootTypeFilter::All,
        CredentialSubFilter::All,
        FileSubFilter::All,
        "",
        "",
        "2026-03-15",
        ""
    ));
}

#[test]
fn loot_time_range_filter_passes_item_in_range() {
    let item = make_loot_item(LootKind::File, "secret.exe", "AA", "2026-03-12T10:00:00Z");
    assert!(loot_matches_filters(
        &item,
        LootTypeFilter::All,
        CredentialSubFilter::All,
        FileSubFilter::All,
        "",
        "2026-03-10",
        "2026-03-15",
        ""
    ));
}

#[test]
fn detect_credential_category_ntlm() {
    // Name contains "ntlm" keyword
    let item = make_loot_item(LootKind::Credential, "NTLM hash", "AA", "");
    assert_eq!(detect_credential_category(&item), CredentialSubFilter::NtlmHash);

    // Source labelled "ntlm" — e.g. from a mimikatz sekurlsa::msv dump
    let mut item2 = make_loot_item(LootKind::Credential, "Administrator", "AA", "");
    item2.source = "ntlm".to_owned();
    assert_eq!(detect_credential_category(&item2), CredentialSubFilter::NtlmHash);
}

#[test]
fn detect_credential_category_kerberos() {
    let item = make_loot_item(LootKind::Credential, "TGT ticket.kirbi", "AA", "");
    assert_eq!(detect_credential_category(&item), CredentialSubFilter::KerberosTicket);
}

#[test]
fn detect_credential_category_certificate() {
    let item = make_loot_item(LootKind::Credential, "user.pfx", "AA", "");
    assert_eq!(detect_credential_category(&item), CredentialSubFilter::Certificate);
}

#[test]
fn detect_credential_category_plaintext() {
    let item = make_loot_item(LootKind::Credential, "plaintext password", "AA", "");
    assert_eq!(detect_credential_category(&item), CredentialSubFilter::Plaintext);
}

#[test]
fn detect_file_category_document() {
    let mut item = make_loot_item(LootKind::File, "report.pdf", "AA", "");
    item.file_path = Some("C:\\Users\\alice\\report.pdf".to_owned());
    assert_eq!(detect_file_category(&item), FileSubFilter::Document);
}

#[test]
fn detect_file_category_archive() {
    let mut item = make_loot_item(LootKind::File, "backup.zip", "AA", "");
    item.file_path = Some("C:\\Temp\\backup.zip".to_owned());
    assert_eq!(detect_file_category(&item), FileSubFilter::Archive);
}

#[test]
fn loot_cred_sub_filter_ntlm_excludes_plaintext() {
    let mut item = make_loot_item(LootKind::Credential, "plaintext password", "AA", "");
    item.preview = Some("P@ssw0rd".to_owned());
    assert!(!loot_matches_filters(
        &item,
        LootTypeFilter::Credentials,
        CredentialSubFilter::NtlmHash,
        FileSubFilter::All,
        "",
        "",
        "",
        ""
    ));
}

#[test]
fn loot_file_sub_filter_document_excludes_archives() {
    let mut item = make_loot_item(LootKind::File, "data.zip", "AA", "");
    item.file_path = Some("C:\\Temp\\data.zip".to_owned());
    assert!(!loot_matches_filters(
        &item,
        LootTypeFilter::Files,
        CredentialSubFilter::All,
        FileSubFilter::Document,
        "",
        "",
        "",
        ""
    ));
}

#[test]
fn export_loot_csv_writes_file_and_returns_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let items: Vec<&LootItem> = vec![];
    // exporting zero items should still succeed and report 0 items
    let result = export_loot_csv_to(&items, dir.path());
    assert!(result.is_ok(), "export_loot_csv failed: {:?}", result.err());
    assert!(result.unwrap().contains("0 item(s)"));
}

#[test]
fn export_loot_json_writes_file_and_returns_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let items: Vec<&LootItem> = vec![];
    let result = export_loot_json_to(&items, dir.path());
    assert!(result.is_ok(), "export_loot_json failed: {:?}", result.err());
    assert!(result.unwrap().contains("0 item(s)"));
}

#[test]
fn export_loot_csv_serializes_non_empty_rows_and_escapes_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let credential = LootItem {
        id: Some(7),
        kind: LootKind::Credential,
        name: "admin".to_owned(),
        agent_id: "operator,local".to_owned(),
        source: "ntlm sekurlsa \"logonpasswords\"".to_owned(),
        collected_at: "2026-03-18T09:10:11Z".to_owned(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: Some("hash,user\nline2".to_owned()),
    };
    let file = LootItem {
        id: Some(42),
        kind: LootKind::File,
        name: "report, \"Q1\".zip".to_owned(),
        agent_id: "BEEFCAFE".to_owned(),
        source: "browser download".to_owned(),
        collected_at: "2026-03-18T10:11:12Z".to_owned(),
        file_path: Some("C:\\Loot\\report, \"Q1\".zip".to_owned()),
        size_bytes: Some(2048),
        content_base64: None,
        preview: None,
    };
    let items = vec![&credential, &file];

    let result = export_loot_csv_to(&items, dir.path())
        .unwrap_or_else(|error| panic!("CSV export failed: {error}"));
    assert!(result.contains("2 item(s)"));

    let contents = read_exported_file(&result);
    assert!(contents.starts_with(
        "id,kind,sub_category,name,agent_id,source,collected_at,file_path,size_bytes,preview\n"
    ));
    assert!(contents.contains(
        "7,Credential,NTLM Hash,admin,\"operator,local\",\"ntlm sekurlsa \"\"logonpasswords\"\"\",2026-03-18T09:10:11Z,,,\"hash,user\nline2\"\n"
    ));
    assert!(contents.contains(
        "42,File,Archive,\"report, \"\"Q1\"\".zip\",BEEFCAFE,browser download,2026-03-18T10:11:12Z,\"C:\\Loot\\report, \"\"Q1\"\".zip\",2048,\n"
    ));
}

#[test]
fn export_loot_json_serializes_non_empty_rows_and_preserves_nulls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let credential = LootItem {
        id: Some(7),
        kind: LootKind::Credential,
        name: "admin".to_owned(),
        agent_id: "operator,local".to_owned(),
        source: "ntlm sekurlsa \"logonpasswords\"".to_owned(),
        collected_at: "2026-03-18T09:10:11Z".to_owned(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: Some("hash,user\nline2".to_owned()),
    };
    let file = LootItem {
        id: Some(42),
        kind: LootKind::File,
        name: "report, \"Q1\".zip".to_owned(),
        agent_id: "BEEFCAFE".to_owned(),
        source: "browser download".to_owned(),
        collected_at: "2026-03-18T10:11:12Z".to_owned(),
        file_path: Some("C:\\Loot\\report, \"Q1\".zip".to_owned()),
        size_bytes: Some(2048),
        content_base64: None,
        preview: None,
    };
    let items = vec![&credential, &file];

    let result = export_loot_json_to(&items, dir.path())
        .unwrap_or_else(|error| panic!("JSON export failed: {error}"));
    assert!(result.contains("2 item(s)"));

    let contents = read_exported_file(&result);
    assert!(contents.contains("ntlm sekurlsa \\\"logonpasswords\\\""));
    assert!(contents.contains("hash,user\\nline2"));

    let exported: serde_json::Value = serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("failed to parse exported JSON: {error}"));
    let entries = exported.as_array().expect("loot export should be a JSON array");
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0]["id"], serde_json::Value::from(7));
    assert_eq!(entries[0]["kind"], serde_json::Value::from("Credential"));
    assert_eq!(entries[0]["sub_category"], serde_json::Value::from("NTLM Hash"));
    assert_eq!(entries[0]["agent_id"], serde_json::Value::from("operator,local"));
    assert_eq!(entries[0]["source"], serde_json::Value::from("ntlm sekurlsa \"logonpasswords\""));
    assert_eq!(entries[0]["collected_at"], serde_json::Value::from("2026-03-18T09:10:11Z"));
    assert_eq!(entries[0]["file_path"], serde_json::Value::Null);
    assert_eq!(entries[0]["size_bytes"], serde_json::Value::Null);
    assert_eq!(entries[0]["preview"], serde_json::Value::from("hash,user\nline2"));

    assert_eq!(entries[1]["id"], serde_json::Value::from(42));
    assert_eq!(entries[1]["kind"], serde_json::Value::from("File"));
    assert_eq!(entries[1]["sub_category"], serde_json::Value::from("Archive"));
    assert_eq!(entries[1]["name"], serde_json::Value::from("report, \"Q1\".zip"));
    assert_eq!(entries[1]["file_path"], serde_json::Value::from("C:\\Loot\\report, \"Q1\".zip"));
    assert_eq!(entries[1]["size_bytes"], serde_json::Value::from(2048_u64));
    assert_eq!(entries[1]["preview"], serde_json::Value::Null);
}

#[test]
fn csv_field_escapes_commas_and_quotes() {
    assert_eq!(csv_field("hello, world"), "\"hello, world\"");
    assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field("bare\rreturn"), "\"bare\rreturn\"");
    assert_eq!(csv_field("line\nfeed"), "\"line\nfeed\"");
}

#[test]
fn csv_field_sanitizes_formula_injection() {
    // Plain formula triggers get a leading single-quote (no quoting needed).
    assert_eq!(csv_field("=SUM(A1)"), "'=SUM(A1)");
    assert_eq!(csv_field("+SUM(A1)"), "'+SUM(A1)");
    assert_eq!(csv_field("-1+2"), "'-1+2");
    assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
    // Leading whitespace: the first *non-whitespace* character determines injection risk.
    assert_eq!(csv_field("  =foo"), "'  =foo");
    // Formula trigger + embedded double-quote → prefix applied, then CSV-quoted.
    assert_eq!(csv_field("=EXEC(\"x\")"), "\"'=EXEC(\"\"x\"\")\"");
    // Values that do not start with a trigger must not be modified.
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field("hello, world"), "\"hello, world\"");
    // A bare minus sign (e.g. used as an empty sentinel) must also be neutralised.
    assert_eq!(csv_field("-"), "'-");
}

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

// ---- derive_download_file_name tests ----

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

// ---- next_available_path tests ----

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

// ── loot_is_downloadable ─────────────────────────────────────────────

fn make_loot(kind: LootKind) -> LootItem {
    LootItem {
        id: Some(1),
        kind,
        name: "test".to_owned(),
        agent_id: "agent-1".to_owned(),
        source: "source".to_owned(),
        collected_at: "2026-03-18T12:00:00Z".to_owned(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    }
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

// ── matches_loot_type_filter ─────────────────────────────────────────

#[test]
fn type_filter_all_matches_everything() {
    for kind in [LootKind::Credential, LootKind::File, LootKind::Screenshot, LootKind::Other] {
        let item = make_loot(kind);
        assert!(matches_loot_type_filter(
            &item,
            LootTypeFilter::All,
            CredentialSubFilter::All,
            FileSubFilter::All,
        ));
    }
}

#[test]
fn type_filter_credentials_matches_credential() {
    let item = make_loot(LootKind::Credential);
    assert!(matches_loot_type_filter(
        &item,
        LootTypeFilter::Credentials,
        CredentialSubFilter::All,
        FileSubFilter::All,
    ));
}

#[test]
fn type_filter_credentials_rejects_file() {
    let item = make_loot(LootKind::File);
    assert!(!matches_loot_type_filter(
        &item,
        LootTypeFilter::Credentials,
        CredentialSubFilter::All,
        FileSubFilter::All,
    ));
}

#[test]
fn type_filter_files_matches_file() {
    let item = make_loot(LootKind::File);
    assert!(matches_loot_type_filter(
        &item,
        LootTypeFilter::Files,
        CredentialSubFilter::All,
        FileSubFilter::All,
    ));
}

#[test]
fn type_filter_files_rejects_credential() {
    let item = make_loot(LootKind::Credential);
    assert!(!matches_loot_type_filter(
        &item,
        LootTypeFilter::Files,
        CredentialSubFilter::All,
        FileSubFilter::All,
    ));
}

#[test]
fn type_filter_screenshots_matches_screenshot() {
    let item = make_loot(LootKind::Screenshot);
    assert!(matches_loot_type_filter(
        &item,
        LootTypeFilter::Screenshots,
        CredentialSubFilter::All,
        FileSubFilter::All,
    ));
}

#[test]
fn type_filter_screenshots_rejects_other() {
    let item = make_loot(LootKind::Other);
    assert!(!matches_loot_type_filter(
        &item,
        LootTypeFilter::Screenshots,
        CredentialSubFilter::All,
        FileSubFilter::All,
    ));
}

// ── matches_credential_sub_filter ────────────────────────────────────

#[test]
fn credential_sub_filter_all_passes_everything() {
    let item = make_loot(LootKind::Credential);
    assert!(matches_credential_sub_filter(&item, CredentialSubFilter::All));
}

#[test]
fn credential_sub_filter_ntlm_matches() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "NTLM hash dump".to_owned();
    assert!(matches_credential_sub_filter(&item, CredentialSubFilter::NtlmHash));
}

#[test]
fn credential_sub_filter_ntlm_rejects_plaintext() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "plaintext password".to_owned();
    assert!(!matches_credential_sub_filter(&item, CredentialSubFilter::NtlmHash));
}

#[test]
fn credential_sub_filter_kerberos_matches() {
    let mut item = make_loot(LootKind::Credential);
    item.source = "kerberos ticket".to_owned();
    assert!(matches_credential_sub_filter(&item, CredentialSubFilter::KerberosTicket));
}

#[test]
fn credential_sub_filter_certificate_matches() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "client.pfx".to_owned();
    assert!(matches_credential_sub_filter(&item, CredentialSubFilter::Certificate));
}

#[test]
fn credential_sub_filter_plaintext_matches() {
    let mut item = make_loot(LootKind::Credential);
    item.preview = Some("plaintext creds".to_owned());
    assert!(matches_credential_sub_filter(&item, CredentialSubFilter::Plaintext));
}

// ── matches_file_sub_filter ──────────────────────────────────────────

#[test]
fn file_sub_filter_all_passes_everything() {
    let item = make_loot(LootKind::File);
    assert!(matches_file_sub_filter(&item, FileSubFilter::All));
}

#[test]
fn file_sub_filter_document_matches_pdf() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("/docs/report.pdf".to_owned());
    assert!(matches_file_sub_filter(&item, FileSubFilter::Document));
}

#[test]
fn file_sub_filter_archive_matches_zip() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("/tmp/backup.zip".to_owned());
    assert!(matches_file_sub_filter(&item, FileSubFilter::Archive));
}

#[test]
fn file_sub_filter_binary_matches_exe() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("C:\\tools\\beacon.exe".to_owned());
    assert!(matches_file_sub_filter(&item, FileSubFilter::Binary));
}

#[test]
fn file_sub_filter_document_rejects_exe() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("/usr/bin/agent.exe".to_owned());
    assert!(!matches_file_sub_filter(&item, FileSubFilter::Document));
}

#[test]
fn file_sub_filter_uses_name_when_no_file_path() {
    let mut item = make_loot(LootKind::File);
    item.file_path = None;
    item.name = "secrets.tar.gz".to_owned();
    assert!(matches_file_sub_filter(&item, FileSubFilter::Archive));
}

// ── loot_sub_category_label ──────────────────────────────────────────

#[test]
fn sub_category_label_credential_ntlm() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "NTLM dump".to_owned();
    assert_eq!(loot_sub_category_label(&item), "NTLM Hash");
}

#[test]
fn sub_category_label_credential_plaintext() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "password file".to_owned();
    assert_eq!(loot_sub_category_label(&item), "Plaintext");
}

#[test]
fn sub_category_label_credential_kerberos() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "kirbi ticket".to_owned();
    assert_eq!(loot_sub_category_label(&item), "Kerberos");
}

#[test]
fn sub_category_label_credential_certificate() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "client.crt".to_owned();
    assert_eq!(loot_sub_category_label(&item), "Certificate");
}

#[test]
fn sub_category_label_credential_unknown() {
    let item = make_loot(LootKind::Credential);
    assert_eq!(loot_sub_category_label(&item), "");
}

#[test]
fn sub_category_label_file_document() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("report.docx".to_owned());
    assert_eq!(loot_sub_category_label(&item), "Document");
}

#[test]
fn sub_category_label_file_archive() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("data.7z".to_owned());
    assert_eq!(loot_sub_category_label(&item), "Archive");
}

#[test]
fn sub_category_label_file_binary() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("agent.dll".to_owned());
    assert_eq!(loot_sub_category_label(&item), "Binary");
}

#[test]
fn sub_category_label_screenshot_empty() {
    let item = make_loot(LootKind::Screenshot);
    assert_eq!(loot_sub_category_label(&item), "");
}

#[test]
fn sub_category_label_other_empty() {
    let item = make_loot(LootKind::Other);
    assert_eq!(loot_sub_category_label(&item), "");
}

// ── type filter with credential sub-filter integration ───────────────

#[test]
fn type_filter_credentials_with_ntlm_sub_filter() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "NTLM hash dump".to_owned();
    assert!(matches_loot_type_filter(
        &item,
        LootTypeFilter::Credentials,
        CredentialSubFilter::NtlmHash,
        FileSubFilter::All,
    ));
}

#[test]
fn type_filter_credentials_with_wrong_sub_filter() {
    let mut item = make_loot(LootKind::Credential);
    item.name = "NTLM hash dump".to_owned();
    assert!(!matches_loot_type_filter(
        &item,
        LootTypeFilter::Credentials,
        CredentialSubFilter::Plaintext,
        FileSubFilter::All,
    ));
}

// ── type filter with file sub-filter integration ─────────────────────

#[test]
fn type_filter_files_with_document_sub_filter() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("report.pdf".to_owned());
    assert!(matches_loot_type_filter(
        &item,
        LootTypeFilter::Files,
        CredentialSubFilter::All,
        FileSubFilter::Document,
    ));
}

#[test]
fn type_filter_files_with_wrong_sub_filter() {
    let mut item = make_loot(LootKind::File);
    item.file_path = Some("report.pdf".to_owned());
    assert!(!matches_loot_type_filter(
        &item,
        LootTypeFilter::Files,
        CredentialSubFilter::All,
        FileSubFilter::Archive,
    ));
}
