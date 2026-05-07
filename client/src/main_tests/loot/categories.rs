use super::*;

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
