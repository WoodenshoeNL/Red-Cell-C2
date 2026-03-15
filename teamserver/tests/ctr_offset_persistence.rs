//! Integration test: AES-CTR block offset persists across a simulated teamserver restart.
//!
//! Verifies that `AgentRegistry::load()` correctly reloads the per-agent CTR block
//! offset from SQLite, so that encryption after a restart continues from the correct
//! keystream position rather than silently resetting to block 0 (two-time-pad collision).

use red_cell::{AgentRegistry, database::Database};
use red_cell_common::{
    AgentEncryptionInfo, AgentRecord,
    crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
        encrypt_agent_data_at_offset,
    },
};
use zeroize::Zeroizing;

fn sample_agent_with_crypto(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
        },
        hostname: "wkstn-test".to_owned(),
        username: "testuser".to_owned(),
        domain_name: "TESTDOMAIN".to_owned(),
        external_ip: "203.0.113.1".to_owned(),
        internal_ip: "10.0.0.1".to_owned(),
        process_name: "test.exe".to_owned(),
        process_path: "C:\\test.exe".to_owned(),
        base_address: 0x400000,
        process_pid: 100,
        process_tid: 101,
        process_ppid: 4,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 10".to_owned(),
        os_build: 19041,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-01-01T00:00:00Z".to_owned(),
        last_call_in: "2026-01-01T00:00:01Z".to_owned(),
    }
}

/// Encrypting N messages with a fresh registry advances the CTR offset and persists it.
/// After dropping the registry and reloading it, the next encryption produces ciphertext
/// identical to encrypting from the persisted offset directly — confirming no keystream reuse.
#[tokio::test]
async fn ctr_offset_survives_registry_reload() -> Result<(), Box<dyn std::error::Error>> {
    let key = [0x42_u8; AGENT_KEY_LENGTH];
    let iv = [0x7F_u8; AGENT_IV_LENGTH];
    let agent_id: u32 = 0xAB12_CD34;

    // Shared in-memory pool — both registry instances use the same SQLite data.
    let database = Database::connect_in_memory().await?;

    // --- Phase 1: register agent and advance the CTR offset via N encryptions ---
    let messages: &[&[u8]] = &[
        b"first encrypted message",
        b"second encrypted message, somewhat longer than the first one",
        b"third message to push the block counter past a single 16-byte block boundary",
    ];

    let expected_offset = {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;

        let mut running_offset: u64 = 0;
        for msg in messages {
            registry.encrypt_for_agent(agent_id, msg).await?;
            running_offset += ctr_blocks_for_len(msg.len());
        }

        // Confirm the in-memory offset matches our manual calculation before reload.
        let stored = registry.ctr_offset(agent_id).await?;
        assert_eq!(
            stored, running_offset,
            "in-memory CTR offset should equal the sum of blocks consumed"
        );

        running_offset
        // registry is dropped here — simulated restart
    };

    // --- Phase 2: reload the registry from the shared database pool ---
    let reloaded_registry = AgentRegistry::load(database).await?;

    let reloaded_offset = reloaded_registry.ctr_offset(agent_id).await?;
    assert_eq!(
        reloaded_offset, expected_offset,
        "reloaded registry must restore CTR offset from SQLite (got {reloaded_offset}, \
         expected {expected_offset}); a reset to 0 would cause two-time-pad keystream collision"
    );

    // --- Phase 3: verify keystream continuity by comparing ciphertexts ---
    // Encrypt one more message with the reloaded registry and confirm it matches
    // a reference encryption starting from `expected_offset` — not from 0.
    let post_restart_plaintext = b"message sent after the simulated teamserver restart";

    let ciphertext_from_reloaded =
        reloaded_registry.encrypt_for_agent(agent_id, post_restart_plaintext).await?;

    let reference_ciphertext =
        encrypt_agent_data_at_offset(&key, &iv, expected_offset, post_restart_plaintext)?;

    assert_eq!(
        ciphertext_from_reloaded, reference_ciphertext,
        "post-restart ciphertext must match reference encryption from offset {expected_offset}; \
         a mismatch means the registry reset the counter to 0 (two-time-pad)"
    );

    // Sanity check: also confirm the reference ciphertext is NOT what offset-0 would produce.
    let offset_zero_ciphertext =
        encrypt_agent_data_at_offset(&key, &iv, 0, post_restart_plaintext)?;
    assert_ne!(
        ciphertext_from_reloaded, offset_zero_ciphertext,
        "test invariant violated: chosen test data produces identical ciphertext at offset 0 \
         and offset {expected_offset}; increase the number of pre-restart messages"
    );

    // Verify the post-restart ciphertext round-trips correctly when decrypted at the right offset.
    let decrypted =
        decrypt_agent_data_at_offset(&key, &iv, expected_offset, &ciphertext_from_reloaded)?;
    assert_eq!(
        decrypted, post_restart_plaintext,
        "post-restart ciphertext should decrypt back to the original plaintext"
    );

    Ok(())
}

/// A CTR offset of zero on reload means the DB either never stored the offset or stored 0.
/// This test registers an agent and immediately reloads it — confirming the initial offset
/// of 0 is also faithfully round-tripped (no off-by-one on first registration).
#[tokio::test]
async fn ctr_offset_zero_is_preserved_on_reload() -> Result<(), Box<dyn std::error::Error>> {
    let key = [0x11_u8; AGENT_KEY_LENGTH];
    let iv = [0x22_u8; AGENT_IV_LENGTH];
    let agent_id: u32 = 0x0000_0001;

    let database = Database::connect_in_memory().await?;

    {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;
        // No encryptions — offset stays at 0.
        let offset = registry.ctr_offset(agent_id).await?;
        assert_eq!(offset, 0, "freshly registered agent should start at CTR offset 0");
    }

    let reloaded = AgentRegistry::load(database).await?;
    let reloaded_offset = reloaded.ctr_offset(agent_id).await?;
    assert_eq!(reloaded_offset, 0, "reloaded offset should still be 0 when no messages were sent");

    Ok(())
}

/// Advancing the offset by exactly one block-boundary value (16 bytes) is preserved.
#[tokio::test]
async fn ctr_offset_exact_block_boundary_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    let key = [0x33_u8; AGENT_KEY_LENGTH];
    let iv = [0x44_u8; AGENT_IV_LENGTH];
    let agent_id: u32 = 0x0000_0002;

    let database = Database::connect_in_memory().await?;

    // A 16-byte plaintext consumes exactly one AES block.
    let one_block = b"exactly-16-bytes";
    assert_eq!(one_block.len(), 16, "test data must be exactly one AES block");

    let expected_offset = {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;
        registry.encrypt_for_agent(agent_id, one_block).await?;
        registry.ctr_offset(agent_id).await?
    };

    assert_eq!(expected_offset, 1, "one 16-byte message should advance offset by exactly 1 block");

    let reloaded = AgentRegistry::load(database).await?;
    assert_eq!(
        reloaded.ctr_offset(agent_id).await?,
        1,
        "reloaded offset must be 1 after one 16-byte message"
    );

    Ok(())
}
