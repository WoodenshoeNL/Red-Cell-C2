use super::*;

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
