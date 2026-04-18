mod callbacks;
mod command_output;
mod config;
mod demon_info;
mod job;
mod loot;

use super::common::*;

use super::super::output::{
    handle_command_error_callback, handle_command_output_callback, handle_config_callback,
    handle_demon_info_callback, handle_exit_callback, handle_job_callback,
    handle_kill_date_callback, handle_sleep_callback,
};
use super::super::{
    CommandDispatchError, CommandDispatcher, LootContext, extract_credentials,
    looks_like_credential_line, looks_like_inline_secret, looks_like_pwdump_hash, loot_context,
};
use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager, TeamserverError};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{
    DemonCallback, DemonCallbackError, DemonCommand, DemonConfigKey, DemonInfoClass,
};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use zeroize::Zeroizing;

pub(super) const AGENT_ID: u32 = 0xBEEF_0001;
pub(super) const REQUEST_ID: u32 = 99;

pub(super) fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn push_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn sample_agent() -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id: AGENT_ID,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0u8; 32]),
            aes_iv: Zeroizing::new(vec![0u8; 16]),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "lab".to_owned(),
        external_ip: "127.0.0.1".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x1000,
        process_pid: 1337,
        process_tid: 7331,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 10,
        sleep_jitter: 25,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-09T20:00:00Z".to_owned(),
        last_call_in: "2026-03-09T20:00:00Z".to_owned(),
    }
}

/// Build registry + event bus with a pre-registered sample agent.
pub(super) async fn setup() -> (AgentRegistry, EventBus) {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(16);
    registry.insert(sample_agent()).await.expect("insert sample agent");
    (registry, events)
}

/// Build registry + event bus + socket relay manager with a pre-registered sample agent.
pub(super) async fn setup_with_sockets() -> (AgentRegistry, EventBus, SocketRelayManager) {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(16);
    registry.insert(sample_agent()).await.expect("insert sample agent");
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    (registry, events, sockets)
}
