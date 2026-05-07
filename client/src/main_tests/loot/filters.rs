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
