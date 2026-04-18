use super::*;

// ── Loot panel types ─────────────────────────────────────────────────

#[test]
fn loot_tab_default_is_credentials() {
    assert_eq!(LootTab::default(), LootTab::Credentials);
}

#[test]
fn credential_sort_column_default_is_name() {
    assert_eq!(CredentialSortColumn::default(), CredentialSortColumn::Name);
}

#[test]
fn loot_panel_state_default_values() {
    let state = LootPanelState::default();
    assert_eq!(state.active_tab, LootTab::Credentials);
    assert!(state.selected_screenshot.is_none());
    assert!(!state.cred_sort_desc);
    assert!(state.filter_dirty);
    assert!(state.filtered_loot.is_empty());
}

#[test]
fn build_filtered_loot_indices_returns_matching_positions() {
    let loot = vec![
        make_loot_item(LootKind::Credential, "alice hash", "AA", "2026-03-10T12:00:00Z"),
        make_loot_item(LootKind::File, "report.pdf", "BB", "2026-03-11T12:00:00Z"),
        make_loot_item(LootKind::Credential, "bob hash", "BB", "2026-03-12T12:00:00Z"),
    ];

    let indices = build_filtered_loot_indices(
        &loot,
        LootTypeFilter::Credentials,
        CredentialSubFilter::All,
        FileSubFilter::All,
        "bb",
        "",
        "",
        "hash",
    );

    assert_eq!(indices, vec![2]);
}

#[test]
fn loot_panel_refresh_filtered_loot_rebuilds_when_revision_changes() {
    let mut panel = LootPanelState { active_tab: LootTab::Files, ..LootPanelState::default() };
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    Arc::make_mut(&mut state.loot).push(make_loot_item(
        LootKind::File,
        "report.pdf",
        "AA",
        "2026-03-10T12:00:00Z",
    ));
    state.loot_revision = 1;

    panel.refresh_filtered_loot(
        &state,
        CredentialSubFilter::All,
        FileSubFilter::Document,
        "",
        "",
        "",
        "",
    );
    assert_eq!(panel.filtered_loot, vec![0]);
    assert!(!panel.filter_dirty);

    {
        let loot = Arc::make_mut(&mut state.loot);
        loot.push(make_loot_item(LootKind::File, "backup.zip", "AA", "2026-03-11T12:00:00Z"));
        loot[1].file_path = Some("C:\\Temp\\backup.zip".to_owned());
    }
    state.loot_revision += 1;

    panel.refresh_filtered_loot(
        &state,
        CredentialSubFilter::All,
        FileSubFilter::Archive,
        "",
        "",
        "",
        "",
    );

    assert_eq!(panel.filtered_loot, vec![1]);
    assert_eq!(panel.cached_loot_revision, state.loot_revision);
}

#[test]
fn credential_category_color_returns_distinct_colors() {
    let ntlm_item = LootItem {
        id: Some(1),
        kind: LootKind::Credential,
        name: "NTLM hash".to_owned(),
        agent_id: String::new(),
        source: String::new(),
        collected_at: String::new(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    let plain_item = LootItem {
        id: Some(2),
        kind: LootKind::Credential,
        name: "plaintext password".to_owned(),
        agent_id: String::new(),
        source: String::new(),
        collected_at: String::new(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    let ntlm_color = credential_category_color(&ntlm_item);
    let plain_color = credential_category_color(&plain_item);
    assert_ne!(ntlm_color, plain_color);
}

#[test]
fn credential_category_color_kerberos_and_certificate() {
    let kerb = LootItem {
        id: Some(3),
        kind: LootKind::Credential,
        name: "kerberos ticket".to_owned(),
        agent_id: String::new(),
        source: String::new(),
        collected_at: String::new(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    let cert = LootItem {
        id: Some(4),
        kind: LootKind::Credential,
        name: "certificate".to_owned(),
        agent_id: String::new(),
        source: String::new(),
        collected_at: String::new(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    let kerb_color = credential_category_color(&kerb);
    let cert_color = credential_category_color(&cert);
    assert_ne!(kerb_color, cert_color);
    // Kerberos = purple, Certificate = cyan
    assert_eq!(kerb_color, Color32::from_rgb(140, 120, 220));
    assert_eq!(cert_color, Color32::from_rgb(80, 180, 220));
}

#[test]
fn credential_category_color_unknown_returns_gray() {
    let unknown = LootItem {
        id: Some(5),
        kind: LootKind::Credential,
        name: "some random cred".to_owned(),
        agent_id: String::new(),
        source: String::new(),
        collected_at: String::new(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    };
    assert_eq!(credential_category_color(&unknown), Color32::GRAY);
}

#[test]
fn screenshot_texture_cache_debug_shows_count() {
    let cache = ScreenshotTextureCache::default();
    let debug = format!("{cache:?}");
    assert!(debug.contains("count"));
    assert!(debug.contains('0'));
}
