use std::time::{SystemTime, UNIX_EPOCH};

use red_cell_common::{AgentEncryptionInfo, HttpListenerConfig, ListenerConfig};
use zeroize::Zeroizing;

use super::registry::{NamedCallback, RegisteredCommand};
pub(super) use super::*;
pub(super) use pyo3::types::PyList;
pub(super) use red_cell_common::operator::{AgentTaskInfo, OperatorMessage};

// Tests that install a `PluginRuntime` as the active global must hold
// `super::PLUGIN_RUNTIME_TEST_MUTEX` so that wiring tests in other modules that
// call `PluginRuntime::swap_active` are serialised with us.
//
// We use `unwrap_or_else(|e| e.into_inner())` to tolerate a poisoned mutex — if a
// prior test panicked while holding the lock, the data inside is still valid (it is
// just `()`), so we recover and continue rather than cascading failures.
pub(super) fn lock_test_guard() -> std::sync::MutexGuard<'static, ()> {
    super::PLUGIN_RUNTIME_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
pub(super) const POISON_CURRENT_ENV: &str = "RED_CELL_POISON_PLUGIN_RUNTIME_CURRENT";

pub(super) fn unique_test_dir(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("red-cell-{label}-{suffix}"))
}

pub(super) fn sample_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: "note".to_owned(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"aes-key".to_vec()),
            aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
            monotonic_ctr: false,
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

pub(super) fn sample_listener() -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: "http-main".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("Mozilla/5.0".to_owned()),
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    })
}

pub(super) async fn runtime_fixture(
    label: &str,
) -> Result<(Database, AgentRegistry, EventBus, SocketRelayManager, PluginRuntime), PluginError> {
    let database = Database::connect(unique_test_dir(label)).await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = PluginRuntime::initialize(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    )
    .await?;
    Ok((database, registry, events, sockets, runtime))
}

pub(super) fn replace_active_runtime(
    runtime: Option<PluginRuntime>,
) -> Result<Option<PluginRuntime>, PluginError> {
    let mut guard = runtime_slot().lock().map_err(|_| PluginError::MutexPoisoned)?;
    Ok(std::mem::replace(&mut *guard, runtime))
}

pub(super) struct ActiveRuntimeReset {
    previous: Option<PluginRuntime>,
}

impl ActiveRuntimeReset {
    pub(super) fn clear() -> Result<Self, PluginError> {
        Ok(Self { previous: replace_active_runtime(None)? })
    }
}

impl Drop for ActiveRuntimeReset {
    fn drop(&mut self) {
        let _ = replace_active_runtime(self.previous.take());
    }
}

mod commands;
mod events;
mod lifecycle;
mod python_api;
