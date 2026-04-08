//! Shared helpers for database integration tests.
//!
//! Include this module in each `database_*.rs` test file with:
//! ```ignore
//! #[path = "database_common.rs"]
//! mod database_common;
//! use database_common::*;
//! ```
#![allow(dead_code)]

use red_cell::database::{Database, TeamserverError};
use red_cell_common::{
    AgentEncryptionInfo, AgentRecord, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerTlsConfig,
};
use sqlx::sqlite::SqliteConnectOptions;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Create a temporary database file path with a unique name.
pub fn temp_db_path() -> PathBuf {
    std::env::temp_dir().join(format!("red-cell-teamserver-db-{}.sqlite", Uuid::new_v4()))
}

/// Build `SqliteConnectOptions` for a given path with foreign keys enabled.
pub fn sqlite_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new().filename(path).create_if_missing(true).foreign_keys(true)
}

/// Build a sample [`AgentRecord`] for database tests.
pub fn sample_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"aes-key".to_vec()),
            aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
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
        os_build: 22000,
        os_arch: "x64".to_owned(),
        sleep_delay: 15,
        sleep_jitter: 20,
        kill_date: Some(1_893_456_000),
        working_hours: Some(0b101010),
        first_call_in: "2026-03-09T18:45:00Z".to_owned(),
        last_call_in: "2026-03-09T18:46:00Z".to_owned(),
    }
}

/// Build a sample [`ListenerConfig`] for database tests.
pub fn sample_listener() -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: "http-main".to_owned(),
        kill_date: Some("2026-12-31".to_owned()),
        working_hours: Some("08:00-18:00".to_owned()),
        hosts: vec!["c2.red-cell.test".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: Some("POST".to_owned()),
        behind_redirector: true,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("Mozilla/5.0".to_owned()),
        headers: vec!["X-Test: true".to_owned()],
        uris: vec!["/index".to_owned()],
        host_header: Some("cdn.red-cell.test".to_owned()),
        secure: true,
        cert: Some(ListenerTlsConfig {
            cert: "server.pem".to_owned(),
            key: "server.key".to_owned(),
        }),
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: nginx".to_owned()],
            body: Some("{\"status\":\"ok\"}".to_owned()),
        }),
        proxy: Some(HttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("http".to_owned()),
            host: "127.0.0.1".to_owned(),
            port: 8080,
            username: Some("proxy".to_owned()),
            password: Some(Zeroizing::new("secret".to_owned())),
        }),
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    })
}

/// Create and return a fresh test [`Database`] backed by a temporary file.
pub async fn test_database() -> Result<Database, TeamserverError> {
    Database::connect(temp_db_path()).await
}
