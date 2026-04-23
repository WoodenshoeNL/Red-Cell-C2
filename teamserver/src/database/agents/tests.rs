use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use zeroize::Zeroizing;

use crate::database::{Database, TeamserverError};

fn stub_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"k".to_vec()),
            aes_iv: Zeroizing::new(b"i".to_vec()),
        },
        hostname: String::new(),
        username: String::new(),
        domain_name: String::new(),
        external_ip: String::new(),
        internal_ip: String::new(),
        process_name: String::new(),
        process_path: String::new(),
        base_address: 0,
        process_pid: 0,
        process_tid: 0,
        process_ppid: 0,
        process_arch: String::new(),
        elevated: false,
        os_version: String::new(),
        os_build: 0,
        os_arch: String::new(),
        sleep_delay: 0,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: String::new(),
        last_call_in: String::new(),
        archon_magic: None,
    }
}

#[tokio::test]
async fn create_full_persists_listener_ctr_offset_and_legacy_ctr() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.agents();
    repo.create_full(&stub_agent(0xAA), "https-listener", 42, true, false)
        .await
        .expect("create_full");
    let persisted = repo.get_persisted(0xAA).await.expect("get").expect("should exist");
    assert_eq!(persisted.listener_name, "https-listener");
    assert_eq!(persisted.ctr_block_offset, 42);
    assert!(persisted.legacy_ctr);
    assert_eq!(persisted.info.agent_id, 0xAA);
}

#[tokio::test]
async fn set_legacy_ctr_on_missing_agent_returns_agent_not_found() {
    let db = Database::connect_in_memory().await.expect("db");
    let err = db.agents().set_legacy_ctr(0xDEAD, true).await.expect_err("expected Err");
    assert!(
        matches!(err, TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD),
        "expected AgentNotFound, got: {err:?}",
    );
    assert!(db.agents().get_persisted(0xDEAD).await.expect("get").is_none());
}

#[tokio::test]
async fn toggle_legacy_ctr_preserves_other_fields() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.agents();
    repo.create_full(&stub_agent(0xBB), "smb-pipe", 99, true, false).await.expect("create_full");
    repo.set_legacy_ctr(0xBB, false).await.expect("set_legacy_ctr");
    let persisted = repo.get_persisted(0xBB).await.expect("get").expect("should exist");
    assert!(!persisted.legacy_ctr, "legacy_ctr should now be false");
    assert_eq!(persisted.listener_name, "smb-pipe");
    assert_eq!(persisted.ctr_block_offset, 99);
}

#[tokio::test]
async fn set_status_persists_active_and_reason() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.agents();
    repo.create_full(&stub_agent(0xCC), "https-listener", 0, false, false)
        .await
        .expect("create_full");
    repo.set_status(0xCC, false, "timed out").await.expect("set_status");
    let persisted = repo.get_persisted(0xCC).await.expect("get").expect("should exist");
    assert!(!persisted.info.active, "active should be false after set_status");
    assert_eq!(persisted.info.reason, "timed out");
    assert_eq!(persisted.listener_name, "https-listener");
}

#[tokio::test]
async fn set_status_on_missing_agent_returns_agent_not_found() {
    let db = Database::connect_in_memory().await.expect("db");
    let err = db.agents().set_status(0xDEAD, false, "gone").await.expect_err("expected Err");
    assert!(
        matches!(err, TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD),
        "expected AgentNotFound, got: {err:?}",
    );
    assert!(db.agents().get_persisted(0xDEAD).await.expect("get").is_none());
}

#[tokio::test]
async fn session_keys_survive_create_then_read_roundtrip() {
    let db = Database::connect_in_memory().await.expect("db");
    let agent = AgentRecord {
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0xAA; 32]),
            aes_iv: Zeroizing::new(vec![0xBB; 16]),
        },
        ..stub_agent(0x1234)
    };
    db.agents().create(&agent).await.expect("create");
    let loaded = db.agents().get(0x1234).await.expect("get").expect("should exist");
    assert_eq!(*loaded.encryption.aes_key, vec![0xAA; 32], "aes_key must survive round-trip");
    assert_eq!(*loaded.encryption.aes_iv, vec![0xBB; 16], "aes_iv must survive round-trip");
}

#[tokio::test]
async fn session_keys_survive_update_then_read_roundtrip() {
    let db = Database::connect_in_memory().await.expect("db");
    let original = stub_agent(0x5678);
    db.agents().create(&original).await.expect("create");

    let updated = AgentRecord {
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0xCC; 32]),
            aes_iv: Zeroizing::new(vec![0xDD; 16]),
        },
        ..original
    };
    db.agents().update(&updated).await.expect("update");
    let loaded = db.agents().get(0x5678).await.expect("get").expect("should exist");
    assert_eq!(*loaded.encryption.aes_key, vec![0xCC; 32], "aes_key must be updated");
    assert_eq!(*loaded.encryption.aes_iv, vec![0xDD; 16], "aes_iv must be updated");
}

#[tokio::test]
async fn session_keys_survive_reregister_roundtrip() {
    let db = Database::connect_in_memory().await.expect("db");
    db.agents().create(&stub_agent(0x9ABC)).await.expect("create");
    let rereg = AgentRecord {
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0xEE; 32]),
            aes_iv: Zeroizing::new(vec![0xFF; 16]),
        },
        ..stub_agent(0x9ABC)
    };
    db.agents().reregister_full(&rereg, "smb-pipe", false, false).await.expect("reregister");
    let loaded = db.agents().get(0x9ABC).await.expect("get").expect("should exist");
    assert_eq!(*loaded.encryption.aes_key, vec![0xEE; 32]);
    assert_eq!(*loaded.encryption.aes_iv, vec![0xFF; 16]);
}

#[tokio::test]
async fn legacy_plaintext_key_fallback_survives_read() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    let db = Database::connect_in_memory().await.expect("db");
    db.agents().create(&stub_agent(0x1111)).await.expect("create");

    // Simulate a pre-migration row: plaintext base64 in aes_key/aes_iv,
    // empty aes_key_enc/aes_iv_enc.
    let raw_key = vec![0x42u8; 32];
    let raw_iv = vec![0x13u8; 16];
    let key_b64 = BASE64_STANDARD.encode(&raw_key);
    let iv_b64 = BASE64_STANDARD.encode(&raw_iv);
    sqlx::query("UPDATE ts_agents SET aes_key = ?, aes_iv = ?, aes_key_enc = '', aes_iv_enc = '' WHERE agent_id = ?")
        .bind(&key_b64)
        .bind(&iv_b64)
        .bind(0x1111i64)
        .execute(db.pool())
        .await
        .expect("backdate row to legacy format");

    let loaded = db.agents().get(0x1111).await.expect("get").expect("exists");
    assert_eq!(*loaded.encryption.aes_key, raw_key, "legacy plaintext key must be read");
    assert_eq!(*loaded.encryption.aes_iv, raw_iv, "legacy plaintext iv must be read");
}
