use super::*;
use panels::session_graph::{
    agent_is_active_status, build_session_graph, session_graph_status_color,
};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, EventCode, MessageHead, OperatorMessage};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::known_servers::KnownServersStore;
use crate::local_config::LocalConfig;
use crate::login::LoginState;
use transport::{
    AgentFileBrowserState, AgentSummary, AppState, ClientTransport, ConnectionStatus,
    FileBrowserEntry, LootItem, SharedAppState, TlsVerification,
};

static EXPORT_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub(super) fn lock_export_test() -> MutexGuard<'static, ()> {
    EXPORT_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn sample_agent(
    name_id: &str,
    hostname: &str,
    username: &str,
    elevated: bool,
    last_call_in: &str,
) -> AgentSummary {
    AgentSummary {
        name_id: name_id.to_owned(),
        status: "Alive".to_owned(),
        domain_name: "LAB".to_owned(),
        username: username.to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        hostname: hostname.to_owned(),
        process_arch: "x64".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_pid: "1234".to_owned(),
        elevated,
        os_version: "Windows 11".to_owned(),
        os_build: "22631".to_owned(),
        os_arch: "x64".to_owned(),
        sleep_delay: "5".to_owned(),
        sleep_jitter: "10".to_owned(),
        last_call_in: last_call_in.to_owned(),
        note: "primary workstation".to_owned(),
        pivot_parent: None,
        pivot_links: Vec::new(),
    }
}

pub(super) fn make_loot_item(
    kind: LootKind,
    name: &str,
    agent_id: &str,
    collected_at: &str,
) -> LootItem {
    LootItem {
        id: None,
        kind,
        name: name.to_owned(),
        agent_id: agent_id.to_owned(),
        source: "test".to_owned(),
        collected_at: collected_at.to_owned(),
        file_path: None,
        size_bytes: None,
        content_base64: None,
        preview: None,
    }
}

pub(super) fn exported_path(message: &str) -> PathBuf {
    let Some((_, path)) = message.split_once(" to ") else {
        panic!("export message missing output path: {message}");
    };
    PathBuf::from(path)
}

pub(super) fn read_exported_file(message: &str) -> String {
    let path = exported_path(message);
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read exported file {}: {error}", path.display()));
    std::fs::remove_file(&path).unwrap_or_else(|error| {
        panic!("failed to remove exported file {}: {error}", path.display())
    });
    contents
}

mod agent_metadata;
mod agent_panel;
mod app_state;
mod auth;
mod cli;
mod console;
mod file_browser;
mod filesystem_tasks;
mod listener_dialog;
mod loot;
mod loot_panel;
mod payload_dialog;
mod process;
mod session_graph;
mod ui_helpers;
