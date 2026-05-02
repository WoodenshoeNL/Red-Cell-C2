mod apply_replay_lockout_config_tests;
mod crypto_tests;
mod degraded_tests;
mod jobs_tests;
mod lifecycle_tests;
mod pivot_tests;
mod query_tests;
mod seq_tests;
mod state_tests;

use red_cell_common::AgentEncryptionInfo;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::Job;
use crate::database::{Database, TeamserverError};

/// Generate a non-degenerate test key from a seed byte.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

fn temp_db_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("red-cell-agent-registry-{}.sqlite", Uuid::new_v4()))
}

fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"aes-key".to_vec()),
            aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
            // Default insert uses legacy_ctr=false; row_to_agent_record derives monotonic_ctr=true.
            monotonic_ctr: true,
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "REDCELL".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x401000,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 15,
        sleep_jitter: 20,
        kill_date: Some(1_893_456_000),
        working_hours: Some(0b101010),
        first_call_in: "2026-03-09T18:45:00Z".to_owned(),
        last_call_in: "2026-03-09T18:46:00Z".to_owned(),
        archon_magic: None,
    }
}

fn sample_agent_with_crypto(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> red_cell_common::AgentRecord {
    let mut agent = sample_agent(agent_id);
    agent.encryption = AgentEncryptionInfo {
        aes_key: Zeroizing::new(key.to_vec()),
        aes_iv: Zeroizing::new(iv.to_vec()),
        monotonic_ctr: false,
    };
    agent
}

async fn test_database() -> Result<Database, TeamserverError> {
    Database::connect(temp_db_path()).await
}

fn sample_job(index: u32) -> Job {
    Job {
        command: 0x1000 + index,
        request_id: index,
        payload: vec![u8::try_from(index & 0xff).expect("test data fits in u8")],
        command_line: format!("job-{index}"),
        task_id: format!("task-{index}"),
        created_at: format!("2026-03-09T19:{index:02}:00Z"),
        operator: "operator".to_owned(),
    }
}
