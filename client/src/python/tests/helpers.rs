//! Shared fixtures and helpers for `crate::python` integration tests.

use std::path::Path;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use super::super::PythonRuntime;
use crate::transport::{AgentSummary, ListenerSummary, LootItem};

pub(super) static TEST_GUARD: Mutex<()> = Mutex::new(());

pub(super) fn sample_agent(agent_id: &str) -> AgentSummary {
    AgentSummary {
        name_id: agent_id.to_owned(),
        status: "Alive".to_owned(),
        domain_name: "REDCELL".to_owned(),
        username: "operator".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        hostname: "wkstn-01".to_owned(),
        process_arch: "x64".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_pid: "1337".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: "22631".to_owned(),
        os_arch: "x64".to_owned(),
        sleep_delay: "15".to_owned(),
        sleep_jitter: "20".to_owned(),
        last_call_in: "2026-03-10T10:00:00Z".to_owned(),
        note: "test".to_owned(),
        pivot_parent: None,
        pivot_links: Vec::new(),
    }
}

pub(super) fn sample_listener(name: &str) -> ListenerSummary {
    ListenerSummary {
        name: name.to_owned(),
        protocol: "https".to_owned(),
        host: "0.0.0.0".to_owned(),
        port_bind: "443".to_owned(),
        port_conn: "443".to_owned(),
        status: "Online".to_owned(),
    }
}

pub(super) fn sample_loot_item(
    agent_id: &str,
    kind: crate::transport::LootKind,
    name: &str,
    content: Option<&str>,
) -> LootItem {
    LootItem {
        id: Some(42),
        kind,
        name: name.to_owned(),
        agent_id: agent_id.to_owned(),
        source: "operator".to_owned(),
        collected_at: "2026-03-15T12:00:00Z".to_owned(),
        file_path: None,
        size_bytes: None,
        content_base64: content.map(ToOwned::to_owned),
        preview: None,
    }
}

pub(super) fn write_script(path: &Path, body: &str) {
    if let Err(error) = std::fs::write(path, body) {
        panic!("script write should succeed: {error}");
    }
}

pub(super) fn wait_for_file_contents(path: &Path) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if !contents.is_empty() {
                return Some(contents);
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    None
}

pub(super) fn wait_for_output(runtime: &PythonRuntime, needle: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if runtime.script_output().iter().any(|entry| entry.text.contains(needle)) {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

pub(super) fn output_occurrences(runtime: &PythonRuntime, needle: &str) -> usize {
    runtime.script_output().iter().map(|entry| entry.text.matches(needle).count()).sum()
}

pub(super) fn wait_for_output_occurrences(
    runtime: &PythonRuntime,
    needle: &str,
    expected: usize,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if output_occurrences(runtime, needle) >= expected {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}
