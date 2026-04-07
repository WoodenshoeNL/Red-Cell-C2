use std::collections::{HashMap, HashSet};
use std::io;
use std::net::TcpListener as StdTcpListener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::dns::{
    DNS_DOH_RESPONSE_CHUNK_BYTES, DNS_HEADER_LEN, DNS_MAX_DOWNLOAD_CHUNKS,
    DNS_MAX_PENDING_RESPONSE_BYTES, DNS_MAX_PENDING_RESPONSES, DNS_MAX_PENDING_UPLOADS,
    DNS_MAX_UPLOAD_CHUNKS, DNS_MAX_UPLOADS_PER_IP, DNS_QTYPE_ANY, DNS_QTYPE_AXFR,
    DNS_RESPONSE_CHUNK_BYTES, DNS_TYPE_A, DNS_TYPE_CNAME, DNS_TYPE_TXT, DNS_UPLOAD_TIMEOUT_SECS,
    DnsC2Query, DnsListenerState, DnsPendingResponse, DnsPendingUpload, DnsUploadAssembly,
    base32_rfc4648_decode, base32_rfc4648_encode, base32hex_decode, base32hex_encode,
    build_dns_c2_response, build_dns_nxdomain_response, chunk_response_to_b32hex,
    chunk_response_to_doh_b32, dns_allowed_query_types, dns_wire_domain_from_ascii_payload,
    parse_dns_c2_query, parse_dns_query, spawn_dns_listener_runtime,
};
use super::{
    DEMON_INIT_WINDOW_DURATION, DNS_RECON_WINDOW_DURATION, DemonInitRateLimiter,
    DnsReconBlockLimiter, DownloadTracker, ListenerEventAction, ListenerManager,
    ListenerManagerError, ListenerStatus, ListenerSummary, MAX_AGENT_MESSAGE_LEN,
    MAX_DEMON_INIT_ATTEMPT_WINDOWS, MAX_DEMON_INIT_ATTEMPTS_PER_IP, MAX_DNS_RECON_QUERIES_PER_IP,
    MAX_RECONNECT_PROBE_WINDOWS, MAX_RECONNECT_PROBES_PER_AGENT, MAX_SMB_FRAME_PAYLOAD_LEN,
    MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE, RECONNECT_PROBE_WINDOW_DURATION,
    ReconnectProbeRateLimiter, TrustedProxyPeer, UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION,
    UnknownCallbackProbeAuditLimiter, action_from_mark, collect_body_with_magic_precheck,
    extract_external_ip, handle_external_request, is_past_kill_date, listener_config_from_operator,
    listener_error_event, listener_event_for_action, listener_removed_event,
    operator_protocol_name, operator_requests_start, parse_trusted_proxy_peer,
    profile_listener_configs, read_smb_frame, smb_local_socket_name, spawn_managed_listener_task,
    spawn_smb_listener_runtime,
};
use crate::{
    AgentRegistry, AuditQuery, AuditResultStatus, Database, DemonInitSecretConfig, EventBus, Job,
    PersistedListenerState, ShutdownController, SocketRelayManager, query_audit_log,
};
use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use interprocess::local_socket::ListenerOptions;
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::Listener as _;
use interprocess::local_socket::traits::tokio::Stream as _;
use red_cell_common::AgentEncryptionInfo;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data,
    decrypt_agent_data_at_offset, encrypt_agent_data,
};
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonMessage};
use red_cell_common::operator::{ListenerInfo, OperatorMessage};
use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, ListenerTlsConfig,
    SmbListenerConfig,
};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

/// Generate a non-degenerate test key from a seed byte.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

fn http_listener(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
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
    })
}

fn http_listener_with_redirector(
    name: &str,
    port: u16,
    trusted_proxy_peers: Vec<String>,
) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: true,
        trusted_proxy_peers,
        user_agent: None,
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
    })
}

fn smb_listener(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

async fn manager() -> Result<ListenerManager, ListenerManagerError> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    Ok(ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true))
}

#[tokio::test]
async fn demon_init_rate_limiter_blocks_after_threshold() {
    let limiter = DemonInitRateLimiter::new();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

    for _ in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        assert!(limiter.allow(ip).await);
    }

    assert!(!limiter.allow(ip).await);
}

#[tokio::test]
async fn demon_init_rate_limiter_prunes_expired_windows() {
    let limiter = DemonInitRateLimiter::new();
    let stale_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    let fresh_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21));

    {
        let mut windows = limiter.windows.lock().await;
        windows.insert(
            stale_ip,
            crate::rate_limiter::AttemptWindow {
                attempts: 1,
                window_start: Instant::now() - DEMON_INIT_WINDOW_DURATION - Duration::from_secs(1),
            },
        );
    }

    assert!(limiter.allow(fresh_ip).await);
    let windows = limiter.windows.lock().await;
    assert!(!windows.contains_key(&stale_ip));
    assert!(windows.contains_key(&fresh_ip));
    drop(windows);
    assert_eq!(limiter.tracked_ip_count().await, 1);
}

#[tokio::test]
async fn demon_init_rate_limiter_evicts_oldest_when_at_capacity() {
    let limiter = DemonInitRateLimiter::new();

    // Pre-populate the limiter with MAX_DEMON_INIT_ATTEMPT_WINDOWS unique IPs,
    // each with a distinct window_start so we can identify the oldest.
    let base_instant = Instant::now() - Duration::from_secs(MAX_DEMON_INIT_ATTEMPT_WINDOWS as u64);
    {
        let mut windows = limiter.windows.lock().await;
        for i in 0..MAX_DEMON_INIT_ATTEMPT_WINDOWS {
            // Use 10.x.y.z addressing space — cycle through octets.
            let a = (i / (256 * 256)) as u8;
            let b = ((i / 256) % 256) as u8;
            let c = (i % 256) as u8;
            let ip = IpAddr::V4(Ipv4Addr::new(10, a, b, c));
            windows.insert(
                ip,
                crate::rate_limiter::AttemptWindow {
                    attempts: 1,
                    window_start: base_instant + Duration::from_secs(i as u64),
                },
            );
        }
    }

    // The oldest entry has window_start == base_instant (i == 0), i.e. 10.0.0.0.
    let oldest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    assert!(limiter.windows.lock().await.contains_key(&oldest_ip));

    // Calling allow() for a brand-new IP must trigger eviction.
    let new_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
    assert!(limiter.allow(new_ip).await, "allow should return true for the new IP");

    // After eviction the map should be at most MAX/2 + 1 (half evicted, new IP inserted).
    let count = limiter.tracked_ip_count().await;
    assert!(
        count <= MAX_DEMON_INIT_ATTEMPT_WINDOWS / 2 + 1,
        "expected at most {} entries after eviction, got {}",
        MAX_DEMON_INIT_ATTEMPT_WINDOWS / 2 + 1,
        count
    );

    // The new IP must be present.
    assert!(
        limiter.windows.lock().await.contains_key(&new_ip),
        "new IP should be tracked after allow()"
    );

    // The oldest IP (earliest window_start) must have been evicted.
    assert!(
        !limiter.windows.lock().await.contains_key(&oldest_ip),
        "oldest IP should have been evicted"
    );
}

#[tokio::test]
async fn unknown_callback_probe_audit_limiter_blocks_after_threshold() {
    let limiter = UnknownCallbackProbeAuditLimiter::new();

    for _ in 0..MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE {
        assert!(limiter.allow("edge-http", "127.0.0.1").await);
    }

    assert!(!limiter.allow("edge-http", "127.0.0.1").await);
    assert!(limiter.allow("edge-http", "127.0.0.2").await);
}

#[tokio::test]
async fn unknown_callback_probe_audit_limiter_prunes_expired_windows() {
    let limiter = UnknownCallbackProbeAuditLimiter::new();
    let stale_source = format!("{}\0{}", "edge-http", "127.0.0.1");

    {
        let mut windows = limiter.windows.lock().await;
        windows.insert(
            stale_source.clone(),
            crate::rate_limiter::AttemptWindow {
                attempts: 1,
                window_start: Instant::now()
                    - UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION
                    - Duration::from_secs(1),
            },
        );
    }

    assert!(limiter.allow("edge-http", "127.0.0.2").await);
    let windows = limiter.windows.lock().await;
    assert!(!windows.contains_key(&stale_source));
    drop(windows);
    assert_eq!(limiter.tracked_source_count().await, 1);
}

#[tokio::test]
async fn reconnect_probe_rate_limiter_blocks_after_threshold() {
    let limiter = ReconnectProbeRateLimiter::new();
    let agent_id = 0xDEAD_BEEF_u32;

    for _ in 0..MAX_RECONNECT_PROBES_PER_AGENT {
        assert!(limiter.allow(agent_id).await);
    }

    // 11th probe in the same window must be blocked.
    assert!(!limiter.allow(agent_id).await);
    // A different agent_id must still be allowed.
    assert!(limiter.allow(agent_id.wrapping_add(1)).await);
}

#[tokio::test]
async fn reconnect_probe_rate_limiter_resets_after_window_expires() {
    let limiter = ReconnectProbeRateLimiter::new();
    let agent_id = 0xAAAA_BBBB_u32;

    // Exhaust the window by injecting a stale entry directly.
    {
        let mut windows = limiter.windows.lock().await;
        windows.insert(
            agent_id,
            crate::rate_limiter::AttemptWindow {
                attempts: MAX_RECONNECT_PROBES_PER_AGENT,
                window_start: Instant::now()
                    - RECONNECT_PROBE_WINDOW_DURATION
                    - Duration::from_secs(1),
            },
        );
    }

    // The window has expired: allow() must reset the counter and permit the probe.
    assert!(limiter.allow(agent_id).await, "probe must be allowed after window expiry");
}

#[tokio::test]
async fn reconnect_probe_rate_limiter_evicts_oldest_when_at_capacity() {
    let limiter = ReconnectProbeRateLimiter::new();
    let base_instant = Instant::now() - Duration::from_secs(MAX_RECONNECT_PROBE_WINDOWS as u64 + 1);

    {
        let mut windows = limiter.windows.lock().await;
        for i in 0u32..MAX_RECONNECT_PROBE_WINDOWS as u32 {
            windows.insert(
                i,
                crate::rate_limiter::AttemptWindow {
                    attempts: 1,
                    window_start: base_instant + Duration::from_secs(u64::from(i)),
                },
            );
        }
    }

    let oldest_agent_id: u32 = 0; // window_start == base_instant
    assert!(limiter.windows.lock().await.contains_key(&oldest_agent_id));

    let new_agent_id: u32 = MAX_RECONNECT_PROBE_WINDOWS as u32 + 1;
    assert!(limiter.allow(new_agent_id).await, "allow must succeed for new agent_id");

    let count = limiter.tracked_agent_count().await;
    assert!(
        count <= MAX_RECONNECT_PROBE_WINDOWS / 2 + 1,
        "expected at most {} entries after eviction, got {}",
        MAX_RECONNECT_PROBE_WINDOWS / 2 + 1,
        count
    );
    assert!(
        !limiter.windows.lock().await.contains_key(&oldest_agent_id),
        "oldest agent_id must have been evicted"
    );
}

#[test]
fn extract_external_ip_ignores_forwarded_headers_from_untrusted_peers() {
    let peer = SocketAddr::from(([198, 51, 100, 25], 443));
    let trusted_proxy_peers =
        vec![TrustedProxyPeer::Address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))];
    let request = Request::builder()
        .header("X-Forwarded-For", "10.0.0.77")
        .header("X-Real-IP", "10.0.0.88")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, peer.ip());
}

#[test]
fn extract_external_ip_uses_rightmost_untrusted_forwarded_hop() {
    let peer = SocketAddr::from(([203, 0, 113, 10], 443));
    let trusted_proxy_peers = vec![TrustedProxyPeer::Address(peer.ip())];
    let request = Request::builder()
        .header("X-Forwarded-For", "10.0.0.66, 10.0.0.77")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 77)));
}

#[test]
fn extract_external_ip_skips_trusted_proxy_chain_when_parsing_forwarded_hops() {
    let peer = SocketAddr::from(([203, 0, 113, 10], 443));
    let trusted_proxy_peers = vec![
        TrustedProxyPeer::Address(peer.ip()),
        TrustedProxyPeer::Address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))),
    ];
    let request = Request::builder()
        .header("X-Forwarded-For", "198.51.100.24, 203.0.113.20")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)));
}

#[test]
fn extract_external_ip_ignores_invalid_forwarded_for_and_falls_back_to_x_real_ip() {
    let peer = SocketAddr::from(([203, 0, 113, 10], 443));
    let trusted_proxy_peers = vec![TrustedProxyPeer::Address(peer.ip())];
    let request = Request::builder()
        .header("X-Forwarded-For", "not-an-ip, 10.0.0.77")
        .header("X-Real-IP", "192.0.2.44")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
}

#[test]
fn extract_external_ip_trusts_forwarded_headers_from_allowed_proxy_cidr() {
    let peer = SocketAddr::from(([10, 1, 2, 3], 443));
    let trusted_proxy_peers =
        vec![parse_trusted_proxy_peer("10.0.0.0/8", "edge").expect("cidr should parse")];
    let request = Request::builder()
        .header("X-Real-IP", "192.0.2.44")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
}

#[test]
fn parse_trusted_proxy_peer_rejects_invalid_entries() {
    let error = parse_trusted_proxy_peer("10.0.0.0/33", "edge")
        .expect_err("invalid prefix length should fail");
    assert!(matches!(error, ListenerManagerError::InvalidConfig { .. }));
}

#[tokio::test]
async fn create_and_list_persist_listener_state() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let summary = manager.create(http_listener("alpha", 32001)).await?;

    assert_eq!(summary.name, "alpha");
    assert_eq!(summary.state.status, ListenerStatus::Created);
    assert_eq!(manager.list().await?.len(), 1);

    Ok(())
}

#[tokio::test]
async fn start_stop_and_delete_manage_runtime_handles() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    manager.create(http_listener("alpha", 32002)).await?;

    let running = manager.start("alpha").await?;
    assert_eq!(running.state.status, ListenerStatus::Running);

    let stopped = manager.stop("alpha").await?;
    assert_eq!(stopped.state.status, ListenerStatus::Stopped);

    manager.delete("alpha").await?;
    assert!(matches!(
        manager.summary("alpha").await,
        Err(ListenerManagerError::ListenerNotFound { .. })
    ));

    Ok(())
}

#[tokio::test]
async fn sync_profile_deletes_persisted_listener_missing_from_profile()
-> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let removed_port = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    let kept_port = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    manager.create(http_listener("removed", removed_port)).await?;
    manager.start("removed").await?;

    let profile = Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
        }}

        Operators {{
          user "operator" {{
            Password = "password1234"
          }}
        }}

        Listeners {{
          Http = [{{
            Name = "kept"
            Hosts = ["127.0.0.1"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = {kept_port}
            Secure = false
          }}]
        }}

        Demon {{}}
        "#
    ))
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    assert!(matches!(
        manager.summary("removed").await,
        Err(ListenerManagerError::ListenerNotFound { .. })
    ));
    assert!(!manager.active_handles.read().await.contains_key("removed"));
    assert_eq!(manager.summary("kept").await?.state.status, ListenerStatus::Created);

    Ok(())
}

#[tokio::test]
async fn sync_profile_creates_new_listener_absent_from_repository()
-> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let port = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    let profile = Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
        }}

        Operators {{
          user "operator" {{
            Password = "password1234"
          }}
        }}

        Listeners {{
          Http = [{{
            Name = "fresh"
            Hosts = ["127.0.0.1"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = {port}
            Secure = false
          }}]
        }}

        Demon {{}}
        "#
    ))
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    let summary = manager.summary("fresh").await?;
    assert_eq!(summary.name, "fresh");
    assert_eq!(summary.state.status, ListenerStatus::Created);
    assert_eq!(summary.protocol, ListenerProtocol::Http);

    Ok(())
}

#[tokio::test]
async fn sync_profile_updates_existing_listener_via_duplicate_path()
-> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let port_a = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    let port_b = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    // Pre-create a listener with port_a.
    manager.create(http_listener("updatable", port_a)).await?;
    assert_eq!(manager.summary("updatable").await?.state.status, ListenerStatus::Created);

    // Build a profile that references the same name but with port_b.
    let profile = Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
        }}

        Operators {{
          user "operator" {{
            Password = "password1234"
          }}
        }}

        Listeners {{
          Http = [{{
            Name = "updatable"
            Hosts = ["127.0.0.1"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = {port_b}
            Secure = false
          }}]
        }}

        Demon {{}}
        "#
    ))
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    // After sync the listener should exist in Stopped state (update_locked sets Stopped).
    let summary = manager.summary("updatable").await?;
    assert_eq!(summary.state.status, ListenerStatus::Stopped);

    Ok(())
}

#[tokio::test]
async fn sync_profile_mixed_remove_update_and_add() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;

    let port_removed = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    let port_existing = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    let port_existing_new = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    let port_added = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    // Pre-create two listeners: one to be removed, one to be updated.
    manager.create(http_listener("to-remove", port_removed)).await?;
    manager.create(http_listener("to-update", port_existing)).await?;

    // Profile keeps "to-update" (with a new port), adds "to-add", and omits "to-remove".
    let profile = Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
        }}

        Operators {{
          user "operator" {{
            Password = "password1234"
          }}
        }}

        Listeners {{
          Http = [
            {{
              Name = "to-update"
              Hosts = ["127.0.0.1"]
              HostBind = "127.0.0.1"
              HostRotation = "round-robin"
              PortBind = {port_existing_new}
              Secure = false
            }},
            {{
              Name = "to-add"
              Hosts = ["127.0.0.1"]
              HostBind = "127.0.0.1"
              HostRotation = "round-robin"
              PortBind = {port_added}
              Secure = false
            }}
          ]
        }}

        Demon {{}}
        "#
    ))
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    // "to-remove" should be gone.
    assert!(matches!(
        manager.summary("to-remove").await,
        Err(ListenerManagerError::ListenerNotFound { .. })
    ));

    // "to-update" should exist in Stopped state (went through duplicate-update path).
    let updated = manager.summary("to-update").await?;
    assert_eq!(updated.state.status, ListenerStatus::Stopped);

    // "to-add" should exist in Created state (new listener path).
    let added = manager.summary("to-add").await?;
    assert_eq!(added.state.status, ListenerStatus::Created);
    assert_eq!(added.protocol, ListenerProtocol::Http);

    // Exactly two listeners should remain.
    let all = manager.list().await?;
    assert_eq!(all.len(), 2);

    Ok(())
}

// ── sync_profile tests for External listeners ───────────────────────────

#[tokio::test]
async fn sync_profile_creates_new_external_listener() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" { Password = "password1234" }
        }

        Listeners {
          External {
            Name = "bridge-new"
            Endpoint = "/ext"
          }
        }

        Demon {}
        "#,
    )
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    let summary = manager.summary("bridge-new").await?;
    assert_eq!(summary.name, "bridge-new");
    assert_eq!(summary.protocol, ListenerProtocol::External);
    assert_eq!(summary.state.status, ListenerStatus::Created);

    Ok(())
}

#[tokio::test]
async fn sync_profile_removes_external_listener_missing_from_profile()
-> Result<(), ListenerManagerError> {
    let manager = manager().await?;

    manager.create(external_listener_config("ext-gone", "/old")).await?;
    assert!(manager.summary("ext-gone").await.is_ok());

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" { Password = "password1234" }
        }

        Listeners {}

        Demon {}
        "#,
    )
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    assert!(matches!(
        manager.summary("ext-gone").await,
        Err(ListenerManagerError::ListenerNotFound { .. })
    ));

    Ok(())
}

#[tokio::test]
async fn sync_profile_removes_running_external_listener_and_deregisters_endpoint()
-> Result<(), ListenerManagerError> {
    let manager = manager().await?;

    manager.create(external_listener_config("ext-live", "/live")).await?;
    manager.start("ext-live").await?;
    assert!(manager.external_state_for_path("/live").await.is_some());

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" { Password = "password1234" }
        }

        Listeners {}

        Demon {}
        "#,
    )
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    sleep(Duration::from_millis(50)).await;

    assert!(matches!(
        manager.summary("ext-live").await,
        Err(ListenerManagerError::ListenerNotFound { .. })
    ));

    assert!(!manager.active_handles.read().await.contains_key("ext-live"));

    Ok(())
}

#[tokio::test]
async fn sync_profile_updates_external_listener_endpoint() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;

    manager.create(external_listener_config("ext-upd", "/old-path")).await?;

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" { Password = "password1234" }
        }

        Listeners {
          External {
            Name = "ext-upd"
            Endpoint = "/new-path"
          }
        }

        Demon {}
        "#,
    )
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    let summary = manager.summary("ext-upd").await?;
    assert_eq!(summary.state.status, ListenerStatus::Stopped);
    assert_eq!(summary.protocol, ListenerProtocol::External);

    Ok(())
}

#[tokio::test]
async fn sync_profile_external_mixed_remove_update_add() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;

    manager.create(external_listener_config("ext-remove", "/remove")).await?;
    manager.create(external_listener_config("ext-update", "/old-ep")).await?;
    manager.create(external_listener_config("ext-keep", "/keep")).await?;

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" { Password = "password1234" }
        }

        Listeners {
          External {
            Name = "ext-update"
            Endpoint = "/updated-ep"
          }
          External {
            Name = "ext-keep"
            Endpoint = "/keep"
          }
          External {
            Name = "ext-new"
            Endpoint = "/fresh"
          }
        }

        Demon {}
        "#,
    )
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    assert!(matches!(
        manager.summary("ext-remove").await,
        Err(ListenerManagerError::ListenerNotFound { .. })
    ));

    let updated = manager.summary("ext-update").await?;
    assert_eq!(updated.state.status, ListenerStatus::Stopped);

    let kept = manager.summary("ext-keep").await?;
    assert_eq!(kept.protocol, ListenerProtocol::External);

    let added = manager.summary("ext-new").await?;
    assert_eq!(added.state.status, ListenerStatus::Created);
    assert_eq!(added.protocol, ListenerProtocol::External);

    let all = manager.list().await?;
    assert_eq!(all.len(), 3);

    Ok(())
}

#[tokio::test]
async fn sync_profile_external_duplicate_endpoint_across_listeners_rejected()
-> Result<(), ListenerManagerError> {
    let manager = manager().await?;

    manager.create(external_listener_config("ext-owner", "/shared")).await?;

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" { Password = "password1234" }
        }

        Listeners {
          External {
            Name = "ext-owner"
            Endpoint = "/shared"
          }
          External {
            Name = "ext-clash"
            Endpoint = "/shared"
          }
        }

        Demon {}
        "#,
    )
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    let result = manager.sync_profile(&profile).await;
    assert!(
        matches!(result, Err(ListenerManagerError::DuplicateEndpoint { .. })),
        "expected DuplicateEndpoint, got {result:?}"
    );

    Ok(())
}

#[tokio::test]
async fn sync_profile_external_and_http_mixed() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let port = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    let profile = Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
        }}

        Operators {{
          user "operator" {{
            Password = "password1234"
          }}
        }}

        Listeners {{
          Http = [{{
            Name = "http-one"
            Hosts = ["127.0.0.1"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = {port}
            Secure = false
          }}]
          External {{
            Name = "ext-one"
            Endpoint = "/bridge"
          }}
        }}

        Demon {{}}
        "#
    ))
    .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;

    manager.sync_profile(&profile).await?;

    let http = manager.summary("http-one").await?;
    assert_eq!(http.protocol, ListenerProtocol::Http);
    assert_eq!(http.state.status, ListenerStatus::Created);

    let ext = manager.summary("ext-one").await?;
    assert_eq!(ext.protocol, ListenerProtocol::External);
    assert_eq!(ext.state.status, ListenerStatus::Created);

    assert_eq!(manager.list().await?.len(), 2);

    Ok(())
}

#[tokio::test]
async fn start_records_bind_errors() -> Result<(), ListenerManagerError> {
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:32003")
        .await
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    let manager = manager().await?;
    manager.create(http_listener("alpha", 32003)).await?;

    let error = manager.start("alpha").await.expect_err("bind should fail");
    let summary = manager.summary("alpha").await?;

    drop(blocker);

    assert!(matches!(error, ListenerManagerError::StartFailed { .. }));
    assert_eq!(summary.state.status, ListenerStatus::Error);
    assert!(summary.state.last_error.is_some());

    Ok(())
}

#[tokio::test]
async fn create_accepts_dns_listener_config() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let summary =
        manager.create(dns_listener_config("dns-managed", 5300, "c2.example.com")).await?;

    assert_eq!(summary.name, "dns-managed");
    assert_eq!(summary.protocol, ListenerProtocol::Dns);
    assert_eq!(summary.state.status, ListenerStatus::Created);
    assert_eq!(summary.config, dns_listener_config("dns-managed", 5300, "c2.example.com"));

    Ok(())
}

#[tokio::test]
async fn update_accepts_dns_listener_config() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let port = free_udp_port();
    manager.create(dns_listener_config("dns-update", port, "c2.example.com")).await?;
    let updated_port = free_udp_port();

    let summary =
        manager.update(dns_listener_config("dns-update", updated_port, "ops.example.com")).await?;

    assert_eq!(summary.state.status, ListenerStatus::Stopped);
    assert_eq!(summary.config, dns_listener_config("dns-update", updated_port, "ops.example.com"));

    Ok(())
}

#[tokio::test]
async fn start_persisted_dns_listener_uses_dns_runtime() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let repository = manager.repository();
    let port = free_udp_port();
    repository.create(&dns_listener_config("dns-runtime", port, "c2.example.com")).await?;

    let summary = manager.start("dns-runtime").await?;

    assert_eq!(summary.state.status, ListenerStatus::Running);
    assert!(manager.active_handles.read().await.contains_key("dns-runtime"));

    manager.stop("dns-runtime").await?;
    let summary = manager.summary("dns-runtime").await?;

    assert_eq!(summary.state.status, ListenerStatus::Stopped);
    assert!(!manager.active_handles.read().await.contains_key("dns-runtime"));

    Ok(())
}

#[tokio::test]
async fn restore_running_restarts_dns_listener() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let repository = manager.repository();
    let port = free_udp_port();
    repository.create(&dns_listener_config("dns-restore", port, "c2.example.com")).await?;
    repository.set_state("dns-restore", ListenerStatus::Running, None).await?;

    manager.restore_running().await?;
    let summary = manager.summary("dns-restore").await?;

    assert_eq!(summary.state.status, ListenerStatus::Running);
    assert!(manager.active_handles.read().await.contains_key("dns-restore"));

    manager.stop("dns-restore").await?;

    Ok(())
}

#[tokio::test]
async fn runtime_exit_clears_handle_and_marks_listener_stopped() -> Result<(), ListenerManagerError>
{
    let manager = manager().await?;
    let repository = manager.repository();
    repository.create(&http_listener("alpha", 32004)).await?;
    repository.set_state("alpha", ListenerStatus::Running, None).await?;

    let handle = spawn_managed_listener_task(
        "alpha".to_owned(),
        Box::pin(async { Ok(()) }),
        repository.clone(),
        manager.active_handles.clone(),
    );
    manager.active_handles.write().await.insert("alpha".to_owned(), handle);

    wait_for_listener_status(&manager, "alpha", ListenerStatus::Stopped).await?;
    assert!(!manager.active_handles.read().await.contains_key("alpha"));

    Ok(())
}

#[tokio::test]
async fn runtime_error_clears_handle_and_marks_listener_error() -> Result<(), ListenerManagerError>
{
    let manager = manager().await?;
    let repository = manager.repository();
    repository.create(&http_listener("alpha", 32005)).await?;
    repository.set_state("alpha", ListenerStatus::Running, None).await?;

    let handle = spawn_managed_listener_task(
        "alpha".to_owned(),
        Box::pin(async { Err("boom".to_owned()) }),
        repository.clone(),
        manager.active_handles.clone(),
    );
    manager.active_handles.write().await.insert("alpha".to_owned(), handle);

    wait_for_listener_status(&manager, "alpha", ListenerStatus::Error).await?;
    let summary = manager.summary("alpha").await?;
    assert_eq!(summary.state.last_error.as_deref(), Some("boom"));
    assert!(!manager.active_handles.read().await.contains_key("alpha"));

    Ok(())
}

#[tokio::test]
async fn start_prunes_finished_stale_handle_before_restart() -> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let port = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    manager.create(http_listener("alpha", port)).await?;

    let finished_handle = tokio::spawn(async {});
    for _ in 0..20 {
        if finished_handle.is_finished() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    manager.active_handles.write().await.insert("alpha".to_owned(), finished_handle);
    let running = manager.start("alpha").await?;

    assert_eq!(running.state.status, ListenerStatus::Running);
    assert!(manager.active_handles.read().await.contains_key("alpha"));

    manager.stop("alpha").await?;

    Ok(())
}

#[tokio::test]
async fn http_listener_returns_fake_404_for_non_matching_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let agent_id = 0x1234_5678;
    let config = ListenerConfig::from(HttpListenerConfig {
        name: "edge-http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("Agent-UA".to_owned()),
        headers: vec!["Accept-Encoding: gzip".to_owned(), "X-Auth: 123".to_owned()],
        uris: vec!["/submit".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: ExampleFront".to_owned(), "Content-Type: text/plain".to_owned()],
            body: Some("decoy".to_owned()),
        }),
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    });

    manager.create(config).await?;
    manager.start("edge-http").await?;
    wait_for_listener(port, false).await?;

    let client = Client::new();

    let invalid = client.get(format!("http://127.0.0.1:{port}/nope")).send().await?;
    assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
    assert!(
        invalid.headers().get("x-havoc").is_none(),
        "fake 404 must not expose x-havoc fingerprinting header"
    );
    assert_eq!(invalid.text().await?, "decoy");

    let valid = client
        .post(format!("http://127.0.0.1:{port}/submit"))
        .header("User-Agent", "Agent-UA")
        .header("X-Auth", "123")
        .body(valid_demon_request_body(agent_id))
        .send()
        .await?;
    assert_eq!(valid.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        valid.headers().get("server").and_then(|value| value.to_str().ok()),
        Some("ExampleFront")
    );
    assert_eq!(valid.text().await?, "decoy");

    manager.stop("edge-http").await?;
    Ok(())
}

#[tokio::test]
async fn https_listener_generates_tls_and_accepts_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let agent_id = 1;
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let config = ListenerConfig::from(HttpListenerConfig {
        name: "edge-https".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: true,
        cert: None,
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: TLSFront".to_owned()],
            body: Some("tls".to_owned()),
        }),
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    });

    manager.create(config).await?;
    manager.start("edge-https").await?;
    wait_for_listener(port, true).await?;

    let client = Client::builder().danger_accept_invalid_certs(true).build()?;
    let response = client
        .post(format!("https://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("server").and_then(|value| value.to_str().ok()),
        Some("TLSFront")
    );
    let decrypted = decrypt_agent_data(&key, &iv, &response.bytes().await?)?;
    assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());

    manager.stop("edge-https").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_returns_fake_404_for_invalid_demon_callback_body()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = manager().await?;
    let port = available_port()?;
    manager.create(http_listener("edge-http-invalid", port)).await?;
    manager.start("edge-http-invalid").await?;
    wait_for_listener(port, false).await?;

    let client = Client::new();

    let too_short =
        client.post(format!("http://127.0.0.1:{port}/")).body(vec![0_u8; 8]).send().await?;
    assert_eq!(too_short.status(), StatusCode::NOT_FOUND);

    let mut invalid_magic = valid_demon_request_body(0x0102_0304);
    invalid_magic[4..8].copy_from_slice(&0xFEED_FACE_u32.to_be_bytes());
    let invalid_magic =
        client.post(format!("http://127.0.0.1:{port}/")).body(invalid_magic).send().await?;
    assert_eq!(invalid_magic.status(), StatusCode::NOT_FOUND);

    manager.stop("edge-http-invalid").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_rejects_oversized_request_body() -> Result<(), Box<dyn std::error::Error>> {
    let manager = manager().await?;
    let port = available_port()?;
    manager.create(http_listener("edge-http-oversize", port)).await?;
    manager.start("edge-http-oversize").await?;
    wait_for_listener(port, false).await?;

    let oversized = vec![0xAA_u8; MAX_AGENT_MESSAGE_LEN + 1];
    let response =
        Client::new().post(format!("http://127.0.0.1:{port}/")).body(oversized).send().await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    manager.stop("edge-http-oversize").await?;
    Ok(())
}

#[tokio::test]
async fn collect_body_with_magic_precheck_accepts_valid_demon_body() {
    let body = valid_demon_request_body(0x1234_5678);
    let result =
        collect_body_with_magic_precheck(Body::from(body.clone()), MAX_AGENT_MESSAGE_LEN).await;
    assert_eq!(result.as_deref(), Some(body.as_slice()));
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_wrong_magic() {
    let mut body = valid_demon_request_body(0x1234_5678);
    body[4..8].copy_from_slice(&0xFEED_FACE_u32.to_be_bytes());
    let result = collect_body_with_magic_precheck(Body::from(body), MAX_AGENT_MESSAGE_LEN).await;
    assert!(result.is_none(), "wrong magic must be rejected before full body is buffered");
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_body_shorter_than_8_bytes() {
    let short = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE];
    let result = collect_body_with_magic_precheck(Body::from(short), MAX_AGENT_MESSAGE_LEN).await;
    assert!(result.is_none(), "body shorter than 8 bytes must be rejected");
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_body_exceeding_max_len() {
    // Construct a body that starts with a valid magic value but exceeds max_len.
    let mut body = vec![0u8; 9];
    body[4..8].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());
    body.extend(vec![0u8; 10]);
    let result = collect_body_with_magic_precheck(Body::from(body), 8).await;
    assert!(result.is_none(), "body exceeding max_len must be rejected");
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_empty_body() {
    let result = collect_body_with_magic_precheck(Body::empty(), MAX_AGENT_MESSAGE_LEN).await;
    assert!(result.is_none(), "empty body must be rejected");
}

#[tokio::test]
async fn http_listener_registers_demon_init_and_broadcasts_agent_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let port = available_port()?;

    manager.create(http_listener("edge-http-init", port)).await?;
    manager.start("edge-http-init").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(0x1234_5678, key, iv))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let decrypted = decrypt_agent_data(&key, &iv, &response.bytes().await?)?;
    assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

    let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
    assert_eq!(stored.hostname, "wkstn-01");
    assert_eq!(stored.external_ip, "127.0.0.1");
    assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

    let event = event_receiver.recv().await.expect("agent registration should broadcast");
    let OperatorMessage::AgentNew(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http-init");
    assert_eq!(message.info.process_name, "explorer.exe");
    assert_eq!(message.info.process_path, "C:\\Windows\\explorer.exe");
    assert_eq!(message.info.sleep_delay, serde_json::json!(15));
    manager.stop("edge-http-init").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_demon_init_records_agent_registered_audit_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-http-audit-init", port)).await?;
    manager.start("edge-http-audit-init").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let agent_id = 0xDEAD_CAFE_u32;
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.registered".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one agent.registered audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.actor, "teamserver");
    assert_eq!(entry.action, "agent.registered");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("DEADCAFE"));
    assert_eq!(entry.result_status, AuditResultStatus::Success);
    let params = entry.parameters.as_ref().expect("parameters must be present");
    assert_eq!(params["listener"], "edge-http-audit-init");

    manager.stop("edge-http-audit-init").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_uses_peer_ip_when_not_behind_redirector()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-http-peer-ip", port)).await?;
    manager.start("edge-http-peer-ip").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("X-Forwarded-For", "198.51.100.24")
        .header("X-Real-IP", "198.51.100.25")
        .body(valid_demon_init_body(0x1111_2222, test_key(0x41), test_iv(0x24)))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = registry.get(0x1111_2222).await.expect("agent should be registered");
    assert_eq!(stored.external_ip, "127.0.0.1");

    manager.stop("edge-http-peer-ip").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_trusts_forwarded_ip_from_trusted_redirector()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager
        .create(http_listener_with_redirector(
            "edge-http-redirector",
            port,
            vec!["127.0.0.1/32".to_owned()],
        ))
        .await?;
    manager.start("edge-http-redirector").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("X-Forwarded-For", "203.0.113.200, 198.51.100.24")
        .body(valid_demon_init_body(0x3333_4444, test_key(0x41), test_iv(0x24)))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = registry.get(0x3333_4444).await.expect("agent should be registered");
    assert_eq!(stored.external_ip, "198.51.100.24");

    manager.stop("edge-http-redirector").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_rate_limits_demon_init_per_source_ip()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-http-init-limit", port)).await?;
    manager.start("edge-http-init-limit").await?;
    wait_for_listener(port, false).await?;

    let client = Client::new();
    for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0x1000_0000 + attempt;
        let response = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_init_body(agent_id, test_key(0x41), test_iv(0x24)))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(registry.get(agent_id).await.is_some());
    }

    let blocked_agent_id = 0x1000_00FF;
    let blocked = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(blocked_agent_id, test_key(0x41), test_iv(0x24)))
        .send()
        .await?;
    assert_eq!(blocked.status(), StatusCode::NOT_FOUND);
    assert!(registry.get(blocked_agent_id).await.is_none());

    manager.stop("edge-http-init-limit").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_returns_empty_body_when_agent_has_no_jobs()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x51);
    let iv = test_iv(0x19);
    let agent_id = 0x1020_3040;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    manager.create(http_listener("edge-http-empty-jobs", port)).await?;
    manager.start("edge-http-empty-jobs").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.bytes().await?.is_empty());

    manager.stop("edge-http-empty-jobs").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_preserves_headers_but_not_decoy_body_for_empty_successful_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x31);
    let iv = test_iv(0x17);
    let agent_id = 0x0BAD_F00D;
    let config = ListenerConfig::from(HttpListenerConfig {
        name: "edge-http-decoy-success".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: ExampleFront".to_owned()],
            body: Some("decoy".to_owned()),
        }),
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    });

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    manager.create(config).await?;
    manager.start("edge-http-decoy-success").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("server").and_then(|value| value.to_str().ok()),
        Some("ExampleFront")
    );
    assert!(response.bytes().await?.is_empty());

    manager.stop("edge-http-decoy-success").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_reconnect_ack_does_not_advance_ctr_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x52);
    let iv = test_iv(0x1A);
    let agent_id = 0x1020_3040;
    let client = Client::new();

    manager.create(http_listener("edge-http-reconnect", port)).await?;
    manager.start("edge-http-reconnect").await?;
    wait_for_listener(port, false).await?;

    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(init_response.status(), StatusCode::OK);
    let _ = init_response.bytes().await?;

    let reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id))
        .send()
        .await?;

    assert_eq!(reconnect_response.status(), StatusCode::OK);
    let reconnect_bytes = reconnect_response.bytes().await?;
    // Legacy mode: reconnect ACK also uses offset 0.
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &reconnect_bytes)?;

    assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());
    assert_eq!(registry.ctr_offset(agent_id).await?, 0);

    manager.stop("edge-http-reconnect").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_unknown_callback_probe_is_rate_limited_before_auditing()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let client = Client::new();
    // Use an agent_id that is never registered so decrypt_from_agent returns AgentNotFound.
    let agent_id = 0xCAFE_BABE;
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);

    manager.create(http_listener("edge-http-unknown-callback", port)).await?;
    manager.start("edge-http-unknown-callback").await?;
    wait_for_listener(port, false).await?;

    let first_callback_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(agent_id, key, iv, 1, 1, b"data"))
        .send()
        .await?;

    assert_eq!(first_callback_response.status(), StatusCode::NOT_FOUND);

    let second_callback_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(agent_id.wrapping_add(1), key, iv, 1, 1, b"data"))
        .send()
        .await?;

    assert_eq!(second_callback_response.status(), StatusCode::NOT_FOUND);

    let audit_page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.callback_probe".to_owned()), ..AuditQuery::default() },
    )
    .await?;

    assert_eq!(audit_page.total, 1);
    let entry = &audit_page.items[0];
    assert_eq!(entry.actor, "teamserver");
    assert_eq!(entry.action, "agent.callback_probe");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("CAFEBABE"));
    assert_eq!(entry.agent_id.as_deref(), Some("CAFEBABE"));
    assert_eq!(entry.command.as_deref(), Some("callback_probe"));
    assert_eq!(entry.result_status, AuditResultStatus::Failure);
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("listener"))
            .and_then(serde_json::Value::as_str),
        Some("edge-http-unknown-callback")
    );
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("external_ip"))
            .and_then(serde_json::Value::as_str),
        Some("127.0.0.1")
    );

    manager.stop("edge-http-unknown-callback").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_unknown_reconnect_probe_is_rate_limited_before_auditing()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let client = Client::new();
    let agent_id = 0xDEAD_BEEF;

    manager.create(http_listener("edge-http-unknown-reconnect", port)).await?;
    manager.start("edge-http-unknown-reconnect").await?;
    wait_for_listener(port, false).await?;

    let reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id))
        .send()
        .await?;

    assert_eq!(reconnect_response.status(), StatusCode::NOT_FOUND);

    let second_reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id.wrapping_add(1)))
        .send()
        .await?;

    assert_eq!(second_reconnect_response.status(), StatusCode::NOT_FOUND);

    let audit_page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.reconnect_probe".to_owned()), ..AuditQuery::default() },
    )
    .await?;

    assert_eq!(audit_page.total, 1);
    let entry = &audit_page.items[0];
    assert_eq!(entry.actor, "teamserver");
    assert_eq!(entry.action, "agent.reconnect_probe");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.agent_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.command.as_deref(), Some("reconnect_probe"));
    assert_eq!(entry.result_status, AuditResultStatus::Failure);
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("listener"))
            .and_then(serde_json::Value::as_str),
        Some("edge-http-unknown-reconnect")
    );
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("external_ip"))
            .and_then(serde_json::Value::as_str),
        Some("127.0.0.1")
    );

    manager.stop("edge-http-unknown-reconnect").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_reconnect_probe_returns_429_after_per_agent_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let client = Client::new();
    let agent_id = 0xCAFE_BABE_u32;

    manager.create(http_listener("edge-http-probe-limit", port)).await?;
    manager.start("edge-http-probe-limit").await?;
    wait_for_listener(port, false).await?;

    // Send MAX_RECONNECT_PROBES_PER_AGENT probes — all must succeed (404, unknown agent).
    for i in 0..MAX_RECONNECT_PROBES_PER_AGENT {
        let resp = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_request_body(agent_id))
            .send()
            .await?;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "probe {i} should return 404 (unknown agent)"
        );
    }

    // The (MAX+1)-th probe must be rate-limited with 429.
    let limited = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id))
        .send()
        .await?;
    assert_eq!(
        limited.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "probe exceeding per-agent limit must return 429"
    );

    // A different agent_id must still be allowed (limit is per agent_id).
    let other = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id.wrapping_add(1)))
        .send()
        .await?;
    assert_eq!(
        other.status(),
        StatusCode::NOT_FOUND,
        "probe for a different agent_id must still be allowed"
    );

    manager.stop("edge-http-probe-limit").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_serializes_all_queued_jobs_for_get_job()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x61);
    let iv = test_iv(0x27);
    let agent_id = 0x5566_7788;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 41,
                payload: vec![1, 2, 3, 4],
                command_line: "sleep 10".to_owned(),
                task_id: "task-41".to_owned(),
                created_at: "2026-03-09T20:10:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 42,
                payload: vec![5, 6, 7],
                command_line: "checkin".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-09T20:11:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    manager.create(http_listener("edge-http-jobs", port)).await?;
    manager.start("edge-http-jobs").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            9,
            &[],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.bytes().await?;
    let message = DemonMessage::from_bytes(bytes.as_ref())?;
    let response_ctr_offset = ctr_blocks_for_len(4);
    assert_eq!(message.packages.len(), 2);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(message.packages[0].request_id, 41);
    let pt0 =
        decrypt_agent_data_at_offset(&key, &iv, response_ctr_offset, &message.packages[0].payload)?;
    assert_eq!(pt0, vec![1, 2, 3, 4]);
    assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(message.packages[1].request_id, 42);
    let pt1 = decrypt_agent_data_at_offset(
        &key,
        &iv,
        response_ctr_offset + ctr_blocks_for_len(message.packages[0].payload.len()),
        &message.packages[1].payload,
    )?;
    assert_eq!(pt1, vec![5, 6, 7]);
    assert!(registry.queued_jobs(agent_id).await?.is_empty());

    manager.stop("edge-http-jobs").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_checkin_refreshes_metadata_and_rejects_key_rotation()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let key = test_key(0x71);
    let iv = test_iv(0x37);
    // A different key/IV that the agent embeds in its CHECKIN — must be rejected.
    let attempted_key = test_key(0x12);
    let attempted_iv = test_iv(0x34);
    let agent_id = 0xCAFE_BABE;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    let port = create_and_start_http(&manager, "edge-http-checkin").await?;
    wait_for_listener(port, false).await?;

    let checkin_payload = sample_checkin_metadata_payload(agent_id, attempted_key, attempted_iv);
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_multi_callback_body(
            agent_id,
            key,
            iv,
            (u32::from(DemonCommand::CommandGetJob), 5, Vec::new()),
            &[(u32::from(DemonCommand::CommandCheckin), 6, checkin_payload.clone())],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.bytes().await?.is_empty());

    let updated =
        registry.get(agent_id).await.ok_or_else(|| "agent should still exist".to_owned())?;
    assert_eq!(updated.hostname, "wkstn-02");
    assert_eq!(updated.process_name, "cmd.exe");
    assert_eq!(updated.sleep_delay, 45);
    assert_eq!(updated.sleep_jitter, 5);
    // Key rotation must be refused — original key material preserved.
    assert_eq!(updated.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(updated.encryption.aes_iv.as_slice(), iv.as_slice());
    // CTR must NOT be reset since the rotation was rejected.
    //
    // The multi-callback body encrypts:
    //   4 bytes (first payload len=0) + 4 (CheckIn cmd) + 4 (req_id) + 4 (payload len) +
    //   checkin_payload
    let first_request_encrypted_len = 4 + 4 + 4 + 4 + checkin_payload.len();
    let expected_ctr_after_first = ctr_blocks_for_len(first_request_encrypted_len);
    assert_eq!(registry.ctr_offset(agent_id).await?, expected_ctr_after_first);
    assert_eq!(
        database
            .agents()
            .get(agent_id)
            .await?
            .ok_or_else(|| "agent should be persisted".to_owned())?
            .encryption
            .aes_key
            .as_slice(),
        key.as_slice()
    );

    let event = event_receiver
        .recv()
        .await
        .ok_or_else(|| "agent update event should broadcast".to_owned())?;
    let OperatorMessage::AgentUpdate(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(message.info.marked, "Alive");

    manager.stop("edge-http-checkin").await?;
    Ok(())
}

#[tokio::test]
async fn smb_listener_registers_demon_init_and_returns_framed_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_smb_pipe_name("init");

    manager.create(smb_listener("edge-smb-init", &pipe_name)).await?;
    manager.start("edge-smb-init").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let mut stream = connect_smb_stream(&pipe_name).await?;
    write_test_smb_frame(&mut stream, 0x1234_5678, &valid_demon_init_body(0x1234_5678, key, iv))
        .await?;

    let (agent_id, response) = read_test_smb_frame(&mut stream).await?;
    assert_eq!(agent_id, 0x1234_5678);
    let decrypted = decrypt_agent_data(&key, &iv, &response)?;
    assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

    let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
    assert_eq!(stored.hostname, "wkstn-01");
    // Synthetic IPv4 derived from agent_id 0x1234_5678 → bytes [0x12,0x34,0x56,0x78]
    assert_eq!(stored.external_ip, "18.52.86.120");
    assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

    let event = event_receiver.recv().await.expect("agent registration should broadcast");
    let OperatorMessage::AgentNew(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.listener, "edge-smb-init");

    manager.stop("edge-smb-init").await?;
    Ok(())
}

#[tokio::test]
async fn smb_listener_rate_limits_demon_init_per_named_pipe_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let pipe_name = unique_smb_pipe_name("init-limit");

    manager.create(smb_listener("edge-smb-init-limit", &pipe_name)).await?;
    manager.start("edge-smb-init-limit").await?;
    wait_for_smb_listener(&pipe_name).await?;

    // On one named-pipe connection, each full DEMON_INIT counts against the same sliding
    // window — rotating `agent_id` must not grant a fresh bucket (regression for
    // synthetic-IPv4 keying).
    let mut stream = connect_smb_stream(&pipe_name).await?;
    for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0x5000_0000 + attempt;
        write_test_smb_frame(
            &mut stream,
            agent_id,
            &valid_demon_init_body(agent_id, test_key(0x41), test_iv(0x24)),
        )
        .await?;

        let (response_agent_id, response) = read_test_smb_frame(&mut stream).await?;
        assert_eq!(response_agent_id, agent_id);
        assert!(!response.is_empty());
        assert!(registry.get(agent_id).await.is_some());
    }

    let rotated_id = 0x5000_00FF_u32;
    write_test_smb_frame(
        &mut stream,
        rotated_id,
        &valid_demon_init_body(rotated_id, test_key(0x42), test_iv(0x26)),
    )
    .await?;
    let blocked =
        tokio::time::timeout(Duration::from_millis(250), read_test_smb_frame(&mut stream)).await;
    assert!(
        blocked.is_err(),
        "sixth DEMON_INIT on the same SMB connection must be rate-limited even with a new agent_id"
    );
    assert!(
        registry.get(rotated_id).await.is_none(),
        "rate-limited init must not register a new agent"
    );

    // A new connection gets its own window — one more full DEMON_INIT must succeed.
    let mut stream2 = connect_smb_stream(&pipe_name).await?;
    let fresh_id = 0x6000_0001_u32;
    write_test_smb_frame(
        &mut stream2,
        fresh_id,
        &valid_demon_init_body(fresh_id, test_key(0x43), test_iv(0x27)),
    )
    .await?;
    let (ack_id, ack) = read_test_smb_frame(&mut stream2).await?;
    assert_eq!(ack_id, fresh_id);
    assert!(!ack.is_empty());
    assert!(registry.get(fresh_id).await.is_some());

    manager.stop("edge-smb-init-limit").await?;
    Ok(())
}

#[tokio::test]
async fn smb_listener_reinit_updates_pivot_agent_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_smb_pipe_name("pivot-reinit");
    let parent_id = 0x1111_2222;
    let parent_key = test_key(0x31);
    let parent_iv = test_iv(0x41);
    let child_id = 0x3333_4444;
    let child_key = test_key(0x51);
    let child_iv = test_iv(0x61);

    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
    registry.add_link(parent_id, child_id).await?;

    manager.create(smb_listener("edge-smb-pivot-reinit", &pipe_name)).await?;
    manager.start("edge-smb-pivot-reinit").await?;
    wait_for_smb_listener(&pipe_name).await?;

    // Re-register with the same key material (legitimate restart).
    let mut stream = connect_smb_stream(&pipe_name).await?;
    write_test_smb_frame(
        &mut stream,
        child_id,
        &valid_demon_init_body(child_id, child_key, child_iv),
    )
    .await?;

    // Re-registration must return an ACK.
    let (ack_id, ack_payload) =
        tokio::time::timeout(Duration::from_millis(500), read_test_smb_frame(&mut stream))
            .await
            .expect("re-registration ack must arrive within timeout")
            .expect("re-registration ack read must succeed");
    assert_eq!(ack_id, child_id, "ack agent_id must match the child");
    assert!(!ack_payload.is_empty(), "ack payload must not be empty");

    // Re-registration must emit an AgentReregistered event.
    let reinit_event = tokio::time::timeout(Duration::from_millis(500), event_receiver.recv())
        .await
        .expect("AgentReregistered must arrive within timeout");
    assert!(
        matches!(reinit_event, Some(OperatorMessage::AgentReregistered(_))),
        "re-registration must broadcast AgentReregistered"
    );

    // The child's listener_name must now reflect the SMB listener.
    let listener_after = registry.listener_name(child_id).await;
    assert_eq!(
        listener_after.as_deref(),
        Some("edge-smb-pivot-reinit"),
        "listener_name must be updated to the SMB listener after re-registration"
    );

    // Key material must remain unchanged (same keys were used).
    let stored_after = registry.get(child_id).await.expect("child agent must still be registered");
    assert_eq!(
        stored_after.encryption.aes_key.as_slice(),
        &child_key,
        "re-registration must preserve the session key"
    );

    manager.stop("edge-smb-pivot-reinit").await?;
    Ok(())
}

#[tokio::test]
async fn smb_listener_serializes_all_queued_jobs_for_get_job()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let pipe_name = unique_smb_pipe_name("jobs");
    let key = test_key(0x61);
    let iv = test_iv(0x27);
    let agent_id = 0x5566_7788;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 41,
                payload: vec![1, 2, 3, 4],
                command_line: "sleep 10".to_owned(),
                task_id: "task-41".to_owned(),
                created_at: "2026-03-09T20:10:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 42,
                payload: vec![5, 6, 7],
                command_line: "checkin".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-09T20:11:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    manager.create(smb_listener("edge-smb-jobs", &pipe_name)).await?;
    manager.start("edge-smb-jobs").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let mut stream = connect_smb_stream(&pipe_name).await?;
    write_test_smb_frame(
        &mut stream,
        agent_id,
        &valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            9,
            &[],
        ),
    )
    .await?;

    let (response_agent_id, response_bytes) = read_test_smb_frame(&mut stream).await?;
    assert_eq!(response_agent_id, agent_id);
    let message = DemonMessage::from_bytes(response_bytes.as_ref())?;
    let response_ctr_offset = ctr_blocks_for_len(4);
    assert_eq!(message.packages.len(), 2);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(message.packages[0].request_id, 41);
    let pt0 =
        decrypt_agent_data_at_offset(&key, &iv, response_ctr_offset, &message.packages[0].payload)?;
    assert_eq!(pt0, vec![1, 2, 3, 4]);
    assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(message.packages[1].request_id, 42);
    let pt1 = decrypt_agent_data_at_offset(
        &key,
        &iv,
        response_ctr_offset + ctr_blocks_for_len(message.packages[0].payload.len()),
        &message.packages[1].payload,
    )?;
    assert_eq!(pt1, vec![5, 6, 7]);
    assert!(registry.queued_jobs(agent_id).await?.is_empty());

    manager.stop("edge-smb-jobs").await?;
    Ok(())
}

#[test]
fn operator_payload_maps_to_http_listener_config() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("alpha".to_owned()),
        protocol: Some("Https".to_owned()),
        status: Some("Online".to_owned()),
        hosts: Some("a.example, b.example".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("8443".to_owned()),
        port_conn: Some("443".to_owned()),
        headers: Some("X-Test: true".to_owned()),
        uris: Some("/one, /two".to_owned()),
        user_agent: Some("Mozilla/5.0".to_owned()),
        secure: Some("true".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;

    assert!(operator_requests_start(&info));
    match config {
        ListenerConfig::Http(config) => {
            assert_eq!(config.name, "alpha");
            assert!(config.secure);
            assert_eq!(config.hosts, vec!["a.example".to_owned(), "b.example".to_owned()]);
        }
        other => panic!("unexpected config: {other:?}"),
    }

    Ok(())
}

#[test]
fn http_listener_operator_round_trip_preserves_advanced_settings()
-> Result<(), ListenerManagerError> {
    let original = ListenerConfig::from(HttpListenerConfig {
        name: "edge".to_owned(),
        kill_date: Some("1773086400".to_owned()),
        working_hours: Some("08:00-17:00".to_owned()),
        hosts: vec!["a.example".to_owned(), "b.example".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: Some("POST".to_owned()),
        behind_redirector: true,
        trusted_proxy_peers: vec!["127.0.0.1/32".to_owned(), "10.0.0.0/8".to_owned()],
        user_agent: Some("Mozilla/5.0".to_owned()),
        headers: vec!["X-Test: true".to_owned()],
        uris: vec!["/one".to_owned(), "/two".to_owned()],
        host_header: Some("team.example".to_owned()),
        secure: true,
        cert: Some(ListenerTlsConfig {
            cert: "/tmp/server.crt".to_owned(),
            key: "/tmp/server.key".to_owned(),
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
            username: Some("user".to_owned()),
            password: Some(Zeroizing::new("pass".to_owned())),
        }),
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    });
    let summary = ListenerSummary {
        name: "edge".to_owned(),
        protocol: original.protocol(),
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: original.clone(),
    };

    let info = summary.to_operator_info_with_secrets();
    let round_tripped = listener_config_from_operator(&info)?;

    assert_eq!(round_tripped, original);
    Ok(())
}

#[test]
fn operator_payload_redacts_http_proxy_password() {
    let summary = ListenerSummary {
        name: "edge".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: ListenerConfig::from(HttpListenerConfig {
            name: "edge".to_owned(),
            hosts: vec!["edge.example".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8443,
            port_conn: Some(443),
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: true,
            cert: None,
            kill_date: None,
            working_hours: None,
            response: None,
            proxy: Some(HttpListenerProxyConfig {
                enabled: true,
                proxy_type: Some("http".to_owned()),
                host: "127.0.0.1".to_owned(),
                port: 8080,
                username: Some("user".to_owned()),
                password: Some(Zeroizing::new("pass".to_owned())),
            }),
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        }),
    };

    let info = summary.to_operator_info();

    assert_eq!(info.proxy_enabled.as_deref(), Some("true"));
    assert_eq!(info.proxy_username.as_deref(), Some("user"));
    assert_eq!(info.proxy_password, None);
}

#[test]
fn profile_listener_configs_preserve_http_host_header() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "neo" {
            Password = "password1234"
          }
        }

        Listeners {
          Http {
            Name = "edge"
            Hosts = ["listener.local"]
            HostBind = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind = 8080
            HostHeader = "front.example"
          }
        }

        Demon {
          TrustXForwardedFor = true
          TrustedProxyPeers = ["127.0.0.1/32"]
        }
        "#,
    )
    .expect("profile should parse");

    let listeners = profile_listener_configs(&profile).expect("configs should be valid");

    assert_eq!(listeners.len(), 1);
    let ListenerConfig::Http(config) = &listeners[0] else {
        panic!("expected http listener");
    };
    assert_eq!(config.host_header.as_deref(), Some("front.example"));
    assert!(config.behind_redirector);
    assert_eq!(config.trusted_proxy_peers, vec!["127.0.0.1/32".to_owned()]);
}

#[test]
fn smb_and_dns_listener_operator_round_trip_preserves_profile_timing()
-> Result<(), ListenerManagerError> {
    let smb = ListenerConfig::from(SmbListenerConfig {
        name: "pivot".to_owned(),
        pipe_name: r"pivot-01".to_owned(),
        kill_date: Some("1773086400".to_owned()),
        working_hours: Some("08:00-17:00".to_owned()),
    });
    let dns = ListenerConfig::from(DnsListenerConfig {
        name: "dns-edge".to_owned(),
        host_bind: "0.0.0.0".to_owned(),
        port_bind: 53,
        domain: "c2.example".to_owned(),
        record_types: vec!["A".to_owned(), "TXT".to_owned()],
        kill_date: Some("1773086400".to_owned()),
        working_hours: Some("08:00-17:00".to_owned()),
    });

    for config in [smb, dns] {
        let summary = ListenerSummary {
            name: config.name().to_owned(),
            protocol: config.protocol(),
            state: PersistedListenerState { status: ListenerStatus::Stopped, last_error: None },
            config: config.clone(),
        };

        let info = summary.to_operator_info();
        let round_tripped = listener_config_from_operator(&info)?;
        assert_eq!(round_tripped, config);
    }

    Ok(())
}

#[test]
fn operator_payload_maps_to_smb_listener_config() -> Result<(), ListenerManagerError> {
    let mut info = ListenerInfo {
        name: Some("pivot".to_owned()),
        protocol: Some("SMB".to_owned()),
        ..ListenerInfo::default()
    };
    info.extra.insert("PipeName".to_owned(), serde_json::json!(r"pivot-01"));

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Smb(config) => {
            assert_eq!(config.name, "pivot");
            assert_eq!(config.pipe_name, "pivot-01");
        }
        other => panic!("unexpected config: {other:?}"),
    }

    Ok(())
}

#[test]
fn mark_actions_accept_start_and_stop_aliases() -> Result<(), ListenerManagerError> {
    assert_eq!(action_from_mark("online")?, ListenerEventAction::Started);
    assert_eq!(action_from_mark("stop")?, ListenerEventAction::Stopped);
    assert!(matches!(
        action_from_mark("restart"),
        Err(ListenerManagerError::UnsupportedMark { .. })
    ));

    Ok(())
}

#[test]
fn action_from_mark_accepts_all_start_aliases_case_insensitive() -> Result<(), ListenerManagerError>
{
    for alias in
        ["Online", "ONLINE", "online", "start", "Start", "START", "running", "Running", "RUNNING"]
    {
        assert_eq!(
            action_from_mark(alias)?,
            ListenerEventAction::Started,
            "expected Started for mark {alias:?}",
        );
    }
    Ok(())
}

#[test]
fn action_from_mark_accepts_all_stop_aliases_case_insensitive() -> Result<(), ListenerManagerError>
{
    for alias in
        ["Offline", "OFFLINE", "offline", "stop", "Stop", "STOP", "stopped", "Stopped", "STOPPED"]
    {
        assert_eq!(
            action_from_mark(alias)?,
            ListenerEventAction::Stopped,
            "expected Stopped for mark {alias:?}",
        );
    }
    Ok(())
}

#[test]
fn action_from_mark_rejects_unsupported_values() {
    for bad in ["restart", "pause", "unknown", "", " ", "onl ine", "star t"] {
        assert!(
            matches!(action_from_mark(bad), Err(ListenerManagerError::UnsupportedMark { .. })),
            "expected UnsupportedMark for {bad:?}",
        );
    }
}

#[test]
fn operator_requests_start_accepts_online_and_start_case_insensitive() {
    for status in ["Online", "ONLINE", "online", "start", "Start", "START"] {
        let info = ListenerInfo { status: Some(status.to_owned()), ..ListenerInfo::default() };
        assert!(operator_requests_start(&info), "expected true for status {status:?}",);
    }
}

#[test]
fn operator_requests_start_rejects_stop_and_unknown_statuses() {
    for status in ["Offline", "stop", "stopped", "running", "unknown", ""] {
        let info = ListenerInfo { status: Some(status.to_owned()), ..ListenerInfo::default() };
        assert!(!operator_requests_start(&info), "expected false for status {status:?}",);
    }
}

#[test]
fn operator_requests_start_returns_false_when_status_absent() {
    let info = ListenerInfo { status: None, ..ListenerInfo::default() };
    assert!(!operator_requests_start(&info));
}

/// Return a port that is free on 127.0.0.1 and is unique across all concurrent callers
/// within this test binary.
///
/// Binds to port 0 so the OS kernel assigns an ephemeral port. This is safe
/// across nextest process boundaries because the kernel's ephemeral allocator
/// avoids handing out the same port to concurrent callers. The socket is
/// dropped after reading the assigned port — callers that start real
/// listeners should use [`create_and_start_http`] which retries on
/// `EADDRINUSE` to cover the brief TOCTOU window.
fn available_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Create and start an HTTP listener, retrying with a fresh port when the
/// initial candidate was stolen between `available_port()` and the actual
/// `TcpListener::bind` inside the listener runtime (TOCTOU race).
async fn create_and_start_http(
    manager: &ListenerManager,
    name: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    const MAX_ATTEMPTS: usize = 5;
    for attempt in 0..MAX_ATTEMPTS {
        let port = available_port()?;
        manager.create(http_listener(name, port)).await?;
        match manager.start(name).await {
            Ok(_) => return Ok(port),
            Err(ListenerManagerError::StartFailed { ref message, .. })
                if message.contains("Address already in use")
                    || message.contains("os error 98") =>
            {
                // Port was stolen — delete the listener and retry.
                tracing::debug!(
                    %name,
                    %port,
                    %attempt,
                    "port conflict during start, retrying with a new port"
                );
                manager.delete(name).await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(format!("failed to start listener `{name}` after {MAX_ATTEMPTS} port attempts").into())
}

async fn wait_for_listener_status(
    manager: &ListenerManager,
    name: &str,
    expected: ListenerStatus,
) -> Result<(), ListenerManagerError> {
    for _ in 0..40 {
        if manager.summary(name).await?.state.status == expected {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }

    Err(ListenerManagerError::InvalidConfig {
        message: format!("listener `{name}` did not reach expected status {expected:?}"),
    })
}

async fn wait_for_listener(port: u16, secure: bool) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder().danger_accept_invalid_certs(true).build()?;
    let scheme = if secure { "https" } else { "http" };
    let url = format!("{scheme}://127.0.0.1:{port}/");

    for _ in 0..40 {
        match client.get(&url).send().await {
            Ok(_) => return Ok(()),
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }

    Err(format!("listener on port {port} did not become ready").into())
}

async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..40 {
        match connect_smb_stream(pipe_name).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }

    Err(format!("smb listener `{pipe_name}` did not become ready").into())
}

async fn connect_smb_stream(
    pipe_name: &str,
) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
    let socket_name = smb_local_socket_name(pipe_name)?;
    Ok(LocalSocketStream::connect(socket_name).await?)
}

async fn connected_smb_stream_pair(
    pipe_name: &str,
) -> Result<(LocalSocketStream, LocalSocketStream), Box<dyn std::error::Error>> {
    let socket_name = smb_local_socket_name(pipe_name)?;
    let listener = ListenerOptions::new().name(socket_name).create_tokio()?;
    let server = tokio::spawn(async move { listener.accept().await });
    let client = connect_smb_stream(pipe_name).await?;
    let server = server.await??;
    Ok((client, server))
}

async fn write_test_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(u32::try_from(payload.len())?).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_test_smb_frame(
    stream: &mut LocalSocketStream,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
    let agent_id = stream.read_u32_le().await?;
    let payload_len = usize::try_from(stream.read_u32_le().await?)?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((agent_id, payload))
}

#[tokio::test]
async fn read_smb_frame_rejects_payloads_over_limit() -> Result<(), Box<dyn std::error::Error>> {
    let pipe_name = unique_smb_pipe_name("oversize");
    let (mut client, mut server) = connected_smb_stream_pair(&pipe_name).await?;
    let oversized_len = u32::try_from(MAX_SMB_FRAME_PAYLOAD_LEN + 1)?;

    client.write_u32_le(0x1234_5678).await?;
    client.write_u32_le(oversized_len).await?;
    client.flush().await?;

    let error = read_smb_frame(&mut server).await.expect_err("oversized frame should be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("exceeds maximum"), "unexpected error message: {error}");

    Ok(())
}

fn unique_smb_pipe_name(suffix: &str) -> String {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("red-cell-test-{suffix}-{unique}")
}

fn valid_demon_request_body(agent_id: u32) -> Vec<u8> {
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| {
            panic!("failed to build valid demon request body: {error}");
        })
        .to_bytes()
}

fn sample_agent_info(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
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
        first_call_in: "2026-03-09T19:00:00Z".to_owned(),
        last_call_in: "2026-03-09T19:01:00Z".to_owned(),
    }
}

fn valid_demon_init_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes(&mut metadata, b"operator");
    add_length_prefixed_bytes(&mut metadata, b"REDCELL");
    add_length_prefixed_bytes(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

    let encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata)
        .expect("metadata encryption should succeed");
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
        .to_bytes()
}

fn valid_demon_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    command_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    valid_demon_multi_callback_body(
        agent_id,
        key,
        iv,
        (command_id, request_id, payload.to_vec()),
        &[],
    )
}

fn valid_demon_multi_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    first: (u32, u32, Vec<u8>),
    additional: &[(u32, u32, Vec<u8>)],
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(
        &u32::try_from(first.2.len()).expect("test data fits in u32").to_be_bytes(),
    );
    decrypted.extend_from_slice(&first.2);

    for (command_id, request_id, payload) in additional {
        decrypted.extend_from_slice(&command_id.to_be_bytes());
        decrypted.extend_from_slice(&request_id.to_be_bytes());
        decrypted.extend_from_slice(
            &u32::try_from(payload.len()).expect("test data fits in u32").to_be_bytes(),
        );
        decrypted.extend_from_slice(payload);
    }

    let encrypted =
        encrypt_agent_data(&key, &iv, &decrypted).expect("callback encryption should succeed");
    let payload =
        [first.0.to_be_bytes().as_slice(), first.1.to_be_bytes().as_slice(), encrypted.as_slice()]
            .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon callback request body: {error}"))
        .to_bytes()
}

fn add_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(
        &u32::try_from(bytes.len()).expect("test data fits in u32").to_be_bytes(),
    );
    buf.extend_from_slice(bytes);
}

fn add_length_prefixed_utf16(buf: &mut Vec<u8>, value: &str) {
    let encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    add_length_prefixed_bytes(buf, &encoded);
}

fn add_checkin_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn add_checkin_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn add_checkin_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    add_checkin_u32(buf, u32::try_from(bytes.len()).expect("test data fits in u32"));
    buf.extend_from_slice(bytes);
}

fn add_checkin_utf16(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_checkin_bytes(buf, &encoded);
}

fn sample_checkin_metadata_payload(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    add_checkin_u32(&mut payload, agent_id);
    add_checkin_bytes(&mut payload, b"wkstn-02");
    add_checkin_bytes(&mut payload, b"svc-op");
    add_checkin_bytes(&mut payload, b"research");
    add_checkin_bytes(&mut payload, b"10.10.10.50");
    add_checkin_utf16(&mut payload, "C:\\Windows\\System32\\cmd.exe");
    add_checkin_u32(&mut payload, 4040);
    add_checkin_u32(&mut payload, 5050);
    add_checkin_u32(&mut payload, 3030);
    add_checkin_u32(&mut payload, 1);
    add_checkin_u32(&mut payload, 0);
    add_checkin_u64(&mut payload, 0x401000);
    add_checkin_u32(&mut payload, 10);
    add_checkin_u32(&mut payload, 0);
    add_checkin_u32(&mut payload, 1);
    add_checkin_u32(&mut payload, 0);
    add_checkin_u32(&mut payload, 22_621);
    add_checkin_u32(&mut payload, 9);
    add_checkin_u32(&mut payload, 45);
    add_checkin_u32(&mut payload, 5);
    add_checkin_u64(&mut payload, 1_725_000_000);
    add_checkin_u32(&mut payload, 0x00FF_00FF);
    payload
}

fn dns_upload_qname(agent_id: u32, seq: u16, total: u16, chunk: &[u8], domain: &str) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Return the TYPE field of the first answer RR (after a single question).
///
/// `qname_raw_len` is the length of the wire-format QNAME in the echoed question
/// (including the root label's zero octet).
fn dns_answer_rr_type(packet: &[u8], qname_raw_len: usize) -> Option<u16> {
    let ans_start = DNS_HEADER_LEN.checked_add(qname_raw_len)?.checked_add(4)?;
    let type_off = ans_start.checked_add(2)?;
    let t = packet.get(type_off..type_off + 2)?;
    Some(u16::from_be_bytes([t[0], t[1]]))
}

/// RDATA octets of the first answer RR (single question, compressed NAME pointer).
fn dns_answer_rdata(packet: &[u8], qname_raw_len: usize) -> Option<Vec<u8>> {
    let ans_start = DNS_HEADER_LEN.checked_add(qname_raw_len)?.checked_add(4)?;
    let rdlen_off = ans_start.checked_add(2 + 2 + 2 + 4)?;
    let rdlen = u16::from_be_bytes([*packet.get(rdlen_off)?, *packet.get(rdlen_off + 1)?]) as usize;
    let rdata_start = rdlen_off.checked_add(2)?;
    let end = rdata_start.checked_add(rdlen)?;
    Some(packet.get(rdata_start..end)?.to_vec())
}

fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    while pos < packet.len() {
        let len = usize::from(packet[pos]);
        pos += 1;
        if len == 0 {
            break;
        }
        pos = pos.checked_add(len)?;
    }

    pos = pos.checked_add(4)?;
    pos = pos.checked_add(2 + 2 + 2 + 4 + 2)?;
    let txt_len = usize::from(*packet.get(pos)?);
    let start = pos.checked_add(1)?;
    let end = start.checked_add(txt_len)?;
    std::str::from_utf8(packet.get(start..end)?).ok().map(str::to_owned)
}

// ── DNS C2 unit tests ─────────────────────────────────────────────────────
use tokio::net::UdpSocket as TokioUdpSocket;

fn free_udp_port() -> u16 {
    // Bind on :0 to let the OS pick an ephemeral port, then return it.
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

fn dns_listener_config(name: &str, port: u16, domain: &str) -> ListenerConfig {
    ListenerConfig::from(red_cell_common::DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    })
}

async fn dns_state(name: &str) -> DnsListenerState {
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let config = red_cell_common::DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: 0,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };

    DnsListenerState::new(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        DnsReconBlockLimiter::new(),
        ShutdownController::new(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
}

async fn spawn_test_dns_listener(
    config: red_cell_common::DnsListenerConfig,
) -> (JoinHandle<()>, AgentRegistry) {
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = spawn_dns_listener_runtime(
        &config,
        registry.clone(),
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        ShutdownController::new(),
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
    .await
    .expect("dns runtime should start");
    let handle = tokio::spawn(async move {
        let _ = runtime.await;
    });

    (handle, registry)
}

async fn spawn_test_smb_runtime(
    config: red_cell_common::SmbListenerConfig,
    shutdown: ShutdownController,
) -> Result<super::ListenerRuntimeFuture, ListenerManagerError> {
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    spawn_smb_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        shutdown,
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
    .await
}

/// Build a minimal DNS query packet for `qname`.
fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: QR=0, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // QNAME
    for label in qname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // zero terminator
    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    buf
}

fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, DNS_TYPE_TXT)
}

fn build_dns_cname_query(id: u16, qname: &str) -> Vec<u8> {
    build_dns_query(id, qname, DNS_TYPE_CNAME)
}

#[test]
fn base32hex_encode_and_decode_round_trip() {
    let cases: &[&[u8]] =
        &[b"hello", b"", b"\x00\xff\xaa", b"The quick brown fox jumps over the lazy dog"];
    for &data in cases {
        let encoded = base32hex_encode(data);
        let decoded = base32hex_decode(&encoded).expect("decode failed");
        assert_eq!(decoded, data, "round trip failed for {data:?}");
    }
}

#[test]
fn base32hex_decode_is_case_insensitive() {
    let lower = base32hex_decode("c9gq6u").expect("lower decode failed");
    let upper = base32hex_decode("C9GQ6U").expect("upper decode failed");
    assert_eq!(lower, upper);
}

#[test]
fn base32hex_decode_rejects_invalid_characters() {
    assert!(base32hex_decode("XY!").is_none());
    assert!(base32hex_decode("ZZZZ").is_none()); // Z is not in base32hex
}

#[test]
fn parse_dns_query_extracts_labels_and_type() {
    let qname = "data.0-1-deadbeef.up.c2.example.com";
    let packet = build_dns_txt_query(0x1234, qname);
    let parsed = parse_dns_query(&packet).expect("parse failed");
    assert_eq!(parsed.id, 0x1234);
    assert_eq!(parsed.qtype, DNS_TYPE_TXT);
    assert_eq!(parsed.labels, &["data", "0-1-deadbeef", "up", "c2", "example", "com"]);
    // qname_raw includes zero terminator
    assert_eq!(*parsed.qname_raw.last().expect("DNS qname should end with a zero-length label"), 0);
}

#[test]
fn parse_dns_query_rejects_short_packets() {
    assert!(parse_dns_query(&[0u8; 3]).is_none());
}

#[test]
fn parse_dns_query_rejects_multiple_questions() {
    let mut packet = build_dns_txt_query(1, "foo.bar");
    // Set qdcount = 2
    packet[4] = 0;
    packet[5] = 2;
    assert!(parse_dns_query(&packet).is_none());
}

#[test]
fn parse_dns_query_rejects_response_packets() {
    let mut packet = build_dns_txt_query(0x1234, "foo.bar");
    packet[2] |= 0x80;
    assert!(parse_dns_query(&packet).is_none());
}

#[test]
fn parse_dns_c2_query_recognises_upload_query() {
    let data = b"hello";
    let b32 = base32hex_encode(data);
    let labels: Vec<String> = [b32.as_str(), "0-1-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::Upload { agent_id, seq, total, data: decoded }) = result else {
        panic!("expected Upload variant");
    };
    assert_eq!(agent_id, 0xDEAD_BEEF);
    assert_eq!(seq, 0);
    assert_eq!(total, 1);
    assert_eq!(decoded, b"hello");
}

#[test]
fn parse_dns_c2_query_recognises_download_query() {
    let labels: Vec<String> =
        ["3-cafebabe", "dn", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::Download { agent_id, seq }) = result else {
        panic!("expected Download variant");
    };
    assert_eq!(agent_id, 0xCAFE_BABE);
    assert_eq!(seq, 3);
}

#[test]
fn parse_dns_c2_query_rejects_wrong_domain() {
    let labels: Vec<String> = ["data", "0-1-deadbeef", "up", "other", "domain", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_ctrl_too_few_parts() {
    // Only 2 dash-separated parts instead of 3 → None
    let labels: Vec<String> = ["CPNMU", "0-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_ctrl_too_many_parts() {
    // 4 dash-separated parts instead of 3 → None
    let labels: Vec<String> =
        ["CPNMU", "0-1-2-3", "up", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_non_hex_seq() {
    // "zzz" is not valid hex → from_str_radix fails → None
    let labels: Vec<String> = ["CPNMU", "zzz-1-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_non_hex_agent_id() {
    let labels: Vec<String> = ["CPNMU", "0-1-GGGGGGGG", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_upload_invalid_base32hex() {
    // 'Z' is outside the base32hex alphabet (0-9, A-V) → None
    let labels: Vec<String> = ["ZZZZ", "0-1-deadbeef", "up", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_download_ctrl_no_dash() {
    // Single part with no dash → parts.len() == 1 → None
    let labels: Vec<String> =
        ["deadbeef", "dn", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_rejects_unknown_direction() {
    // "fwd" is neither "up" nor "dn" → falls through to _ => None
    let labels: Vec<String> = ["CPNMU", "0-1-deadbeef", "fwd", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_dns_c2_query(&labels, "c2.example.com").is_none());
}

#[test]
fn parse_dns_c2_query_recognises_doh_upload() {
    let payload = b"hello";
    let b32 = base32_rfc4648_encode(payload);
    let seqtotal = format!("{:04x}{:04x}", 0u16, 1u16);
    let session = "0123456789abcdef";
    let labels: Vec<String> = [b32.as_str(), &seqtotal, session, "u", "c2", "example", "com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::DohUpload { session: s, seq, total, data }) = result else {
        panic!("expected DohUpload variant, got {result:?}");
    };
    assert_eq!(s, session);
    assert_eq!(seq, 0);
    assert_eq!(total, 1);
    assert_eq!(data, payload);
}

#[test]
fn parse_dns_c2_query_recognises_doh_ready() {
    let session = "0123456789abcdef";
    let labels: Vec<String> =
        ["rdy", session, "d", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::DohReady { session: s }) = result else {
        panic!("expected DohReady variant");
    };
    assert_eq!(s, session);
}

#[test]
fn parse_dns_c2_query_recognises_doh_chunk_download() {
    let session = "fedcba9876543210";
    let labels: Vec<String> =
        ["0003", session, "d", "c2", "example", "com"].iter().map(|s| s.to_string()).collect();
    let result = parse_dns_c2_query(&labels, "c2.example.com");
    let Some(DnsC2Query::DohDownload { session: s, seq }) = result else {
        panic!("expected DohDownload variant");
    };
    assert_eq!(s, session);
    assert_eq!(seq, 3);
}

/// End-to-end interop: query names built with the same `format!` patterns as
/// `agent/specter/src/doh_transport.rs` and `agent/archon/src/core/TransportDoH.c`
/// must parse through `parse_dns_query` → `parse_dns_c2_query` (the DNS listener path).
#[test]
fn doh_interop_specter_archon_wire_names_parse_from_udp_packet() {
    const C2_DOMAIN: &str = "c2.example.com";
    let payload = b"demon-packet-bytes";
    let chunk = base32_rfc4648_encode(payload);
    let seq = 7u16;
    let total = 99u16;
    let session_mixed = "0123456789ABCDEF";
    let session_lower = "0123456789abcdef";

    // Uplink — one label for `<seq:04x><total:04x>` (not two labels).
    let uplink_name = format!("{chunk}.{seq:04x}{total:04x}.{session_mixed}.u.{C2_DOMAIN}");
    let pkt = build_dns_txt_query(0xACE, &uplink_name);
    let parsed = parse_dns_query(&pkt).expect("wire parse");
    let q = parse_dns_c2_query(&parsed.labels, C2_DOMAIN).expect("c2 parse uplink");
    let DnsC2Query::DohUpload { session, seq: got_seq, total: got_total, data } = q else {
        panic!("expected DohUpload, got {q:?}");
    };
    assert_eq!(session, session_lower);
    assert_eq!(got_seq, seq);
    assert_eq!(got_total, total);
    assert_eq!(data.as_slice(), payload);

    // Ready poll — `rdy.<session>.d.<domain>`
    let ready_name = format!("rdy.{session_mixed}.d.{C2_DOMAIN}");
    let pkt = build_dns_txt_query(0xBEE, &ready_name);
    let parsed = parse_dns_query(&pkt).expect("wire parse");
    let q = parse_dns_c2_query(&parsed.labels, C2_DOMAIN).expect("c2 parse ready");
    let DnsC2Query::DohReady { session } = q else {
        panic!("expected DohReady, got {q:?}");
    };
    assert_eq!(session, session_lower);

    // Chunk fetch — `<seq:04x>.<session>.d.<domain>`
    let fetch_seq = 12u16;
    let fetch_name = format!("{fetch_seq:04x}.{session_mixed}.d.{C2_DOMAIN}");
    let pkt = build_dns_txt_query(0xC0D, &fetch_name);
    let parsed = parse_dns_query(&pkt).expect("wire parse");
    let q = parse_dns_c2_query(&parsed.labels, C2_DOMAIN).expect("c2 parse fetch");
    let DnsC2Query::DohDownload { session, seq } = q else {
        panic!("expected DohDownload, got {q:?}");
    };
    assert_eq!(session, session_lower);
    assert_eq!(seq, fetch_seq);
}

#[test]
fn build_dns_nxdomain_response_sets_rcode_3() {
    let packet = build_dns_txt_query(0x4242, "rdy.testsession.d.c2.example.com");
    let parsed = parse_dns_query(&packet).expect("parse failed");
    let resp = build_dns_nxdomain_response(parsed.id, &parsed.qname_raw, parsed.qtype);
    assert_eq!(resp[3] & 0x0F, 3u8);
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
}

#[test]
fn chunk_response_to_doh_b32_round_trip() {
    let payload = vec![0xABu8; 80];
    let chunks = chunk_response_to_doh_b32(&payload);
    assert_eq!(chunks.len(), 3); // ceil(80/37) = 3
    let mut out = Vec::new();
    for c in &chunks {
        out.extend_from_slice(&base32_rfc4648_decode(c).expect("decode"));
    }
    assert_eq!(out, payload);
}

#[test]
fn dns_doh_chunk_size_matches_specter() {
    assert_eq!(DNS_DOH_RESPONSE_CHUNK_BYTES, 37);
}

#[test]
fn build_dns_c2_response_answer_rr_matches_txt_a_cname_queries() {
    let payload = b"ok";
    for (qtype, expected_type) in
        [(DNS_TYPE_TXT, DNS_TYPE_TXT), (DNS_TYPE_A, DNS_TYPE_A), (DNS_TYPE_CNAME, DNS_TYPE_CNAME)]
    {
        let packet = build_dns_query(0xABCD, "test.c2.example.com", qtype);
        let parsed = parse_dns_query(&packet).expect("parse failed");
        let response = build_dns_c2_response(parsed.id, &parsed.qname_raw, parsed.qtype, payload)
            .expect("response should encode");

        assert!(response.len() >= DNS_HEADER_LEN);
        assert!(response[2] & 0x80 != 0, "QR bit not set");
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);

        let question_qtype_offset = DNS_HEADER_LEN + parsed.qname_raw.len();
        let echoed_qtype = u16::from_be_bytes([
            response[question_qtype_offset],
            response[question_qtype_offset + 1],
        ]);
        assert_eq!(echoed_qtype, qtype);

        assert_eq!(
            dns_answer_rr_type(&response, parsed.qname_raw.len()),
            Some(expected_type),
            "answer RR TYPE must match query type {qtype}"
        );
    }

    let packet_a = build_dns_query(0xABCD, "test.c2.example.com", DNS_TYPE_A);
    let parsed_a = parse_dns_query(&packet_a).expect("parse failed");
    let response_a = build_dns_c2_response(parsed_a.id, &parsed_a.qname_raw, parsed_a.qtype, b"ok")
        .expect("a response");
    assert_eq!(
        dns_answer_rdata(&response_a, parsed_a.qname_raw.len()),
        Some(vec![b'o', b'k', 0, 0])
    );
}

#[test]
fn build_dns_c2_response_returns_none_when_a_payload_exceeds_four_octets() {
    let packet = build_dns_query(0xABCD, "test.c2.example.com", DNS_TYPE_A);
    let parsed = parse_dns_query(&packet).expect("parse failed");
    assert!(build_dns_c2_response(parsed.id, &parsed.qname_raw, parsed.qtype, b"hello").is_none());
}

#[test]
fn dns_wire_domain_splits_long_payload_into_labels() {
    let s = "a".repeat(130);
    let wire = dns_wire_domain_from_ascii_payload(&s).expect("wire");
    assert!(wire.len() <= 255);
    assert_eq!(wire[0], 63);
    assert_eq!(wire[64], 63);
    assert_eq!(wire[128], 4);
    assert_eq!(wire[133], 0);
}

#[test]
fn dns_allowed_query_types_defaults_to_txt_and_supports_cname() {
    assert_eq!(dns_allowed_query_types(&[]), Some(vec![DNS_TYPE_TXT]));
    assert_eq!(
        dns_allowed_query_types(&["txt".to_owned(), "CNAME".to_owned(), "A".to_owned()]),
        Some(vec![DNS_TYPE_TXT, DNS_TYPE_CNAME, DNS_TYPE_A])
    );
    assert!(dns_allowed_query_types(&["MX".to_owned()]).is_none());
}

#[test]
fn chunk_response_splits_payload_into_base32hex_chunks() {
    let payload = vec![0xABu8; 300]; // 300 bytes > 1 chunk (125 bytes each)
    let chunks = chunk_response_to_b32hex(&payload);
    assert_eq!(chunks.len(), 3); // ceil(300/125) = 3
    // Each chunk decodes back to the expected slice
    let mut reassembled = Vec::new();
    for chunk in &chunks {
        let decoded = base32hex_decode(chunk).expect("chunk decode failed");
        reassembled.extend_from_slice(&decoded);
    }
    assert_eq!(reassembled, payload);
}

#[test]
fn dns_max_download_chunks_matches_u16_max() {
    // Verify the constant is exactly u16::MAX so the seq field can address
    // every chunk without overflow.
    assert_eq!(DNS_MAX_DOWNLOAD_CHUNKS, u16::MAX as usize);
    assert_eq!(DNS_MAX_DOWNLOAD_CHUNKS, 65_535);
}

#[test]
fn chunk_response_at_u16_boundary_is_within_limit() {
    // Exactly u16::MAX chunks — should be accepted.
    let payload_size = DNS_MAX_DOWNLOAD_CHUNKS * DNS_RESPONSE_CHUNK_BYTES;
    let chunks = chunk_response_to_b32hex(&vec![0xBB; payload_size]);
    assert_eq!(chunks.len(), DNS_MAX_DOWNLOAD_CHUNKS);
}

#[test]
fn chunk_response_exceeding_u16_limit_produces_too_many_chunks() {
    // One byte over the limit produces chunk count > u16::MAX.
    let payload_size = DNS_MAX_DOWNLOAD_CHUNKS * DNS_RESPONSE_CHUNK_BYTES + 1;
    let chunks = chunk_response_to_b32hex(&vec![0xCC; payload_size]);
    assert!(
        chunks.len() > DNS_MAX_DOWNLOAD_CHUNKS,
        "expected more than {} chunks, got {}",
        DNS_MAX_DOWNLOAD_CHUNKS,
        chunks.len()
    );
}

#[tokio::test]
async fn dns_listener_starts_and_responds_to_unknown_queries_with_refused() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-test".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    // Brief delay for the listener to bind
    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    // Send a query for an unrecognised C2 domain — expect REFUSED
    let packet = build_dns_txt_query(0x1111, "something.other.domain.com");
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    // RCODE should be 5 (REFUSED)
    let rcode = buf[3] & 0x0F;
    assert_eq!(rcode, 5, "expected REFUSED RCODE");
    handle.abort();
}

#[tokio::test]
async fn dns_listener_runtime_exits_when_shutdown_started_before_first_poll() {
    let shutdown = ShutdownController::new();
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-shutdown-prepoll".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let runtime = spawn_dns_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        shutdown.clone(),
        None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
    .await
    .expect("dns runtime should start");

    shutdown.initiate();

    let result = timeout(Duration::from_millis(200), runtime)
        .await
        .expect("dns runtime should observe pre-existing shutdown");
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn dns_listener_download_poll_returns_wait_when_no_response_queued() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-wait".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    // Download poll for agent 0xDEADBEEF, seq 0
    let qname = "0-deadbeef.dn.c2.example.com";
    let packet = build_dns_txt_query(0x2222, qname);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    // NOERROR (RCODE=0)
    let rcode = buf[3] & 0x0F;
    assert_eq!(rcode, 0, "expected NOERROR");

    // ANCOUNT = 1
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    assert_eq!(ancount, 1);
    let parsed = parse_dns_query(&packet).expect("query should parse");
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_TXT),
        "answer RR must be TXT when the query is TXT"
    );
    handle.abort();
}

#[tokio::test]
async fn dns_listener_a_query_returns_ipv4_rdata_when_payload_fits() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-a-rdata".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["A".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_query(0x7777, "0-deadbeef.dn.c2.example.com", DNS_TYPE_A);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR");
    let parsed = parse_dns_query(&packet).expect("query should parse");
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_A),
        "answer RR must be A when the query is A"
    );
    assert_eq!(dns_answer_rdata(&buf, parsed.qname_raw.len()), Some(vec![b'w', b'a', b'i', b't']));
    handle.abort();
}

#[tokio::test]
async fn dns_listener_rate_limits_demon_init_per_source_ip() {
    let port = free_udp_port();
    let domain = "c2.example.com".to_owned();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-init-limit".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.clone(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, registry) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    for attempt in 0..=MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0x3000_0000 + attempt;
        let payload = valid_demon_init_body(agent_id, test_key(0x41), test_iv(0x24));
        let chunks: Vec<&[u8]> = payload.chunks(39).collect();
        let total = u16::try_from(chunks.len()).expect("chunk count should fit in u16");
        let expected_txt = if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP { "ack" } else { "err" };

        for (seq, chunk) in chunks.iter().enumerate() {
            let qname = dns_upload_qname(
                agent_id,
                u16::try_from(seq).expect("chunk index should fit in u16"),
                total,
                chunk,
                &domain,
            );
            let packet = build_dns_txt_query(0x4000 + seq as u16, &qname);
            client.send(&packet).await.expect("send failed");

            let mut buf = vec![0u8; 1024];
            tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
                .await
                .expect("no response received")
                .expect("recv failed");

            let txt = parse_dns_txt_answer(&buf).expect("TXT answer should parse");
            let is_last = seq + 1 == chunks.len();
            if is_last {
                assert_eq!(txt, expected_txt);
            } else {
                assert_eq!(txt, "ok");
            }
        }

        if attempt < MAX_DEMON_INIT_ATTEMPTS_PER_IP {
            assert!(registry.get(agent_id).await.is_some());
        } else {
            assert!(registry.get(agent_id).await.is_none());
        }
    }
    handle.abort();
}

#[tokio::test]
async fn dns_listener_refuses_query_types_not_enabled_by_config() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-txt-only".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_query(0x3333, "0-deadbeef.dn.c2.example.com", DNS_TYPE_A);
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
    handle.abort();
}

#[tokio::test]
async fn dns_listener_responds_to_a_burst_of_udp_queries() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-burst".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    for id in 0x5000..0x5010 {
        let packet = build_dns_txt_query(id, "burst.other.domain.com");
        client.send(&packet).await.expect("send failed");
    }

    let mut buf = vec![0u8; 512];
    let mut seen_ids = HashSet::new();
    for _ in 0x5000..0x5010 {
        let received = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");
        assert!(received >= DNS_HEADER_LEN, "response too short");
        seen_ids.insert(u16::from_be_bytes([buf[0], buf[1]]));
        assert_eq!(buf[3] & 0x0F, 5, "expected REFUSED RCODE");
    }
    assert_eq!(seen_ids.len(), 16, "every burst query should receive a response");

    handle.abort();
}

#[tokio::test]
async fn dns_listener_accepts_cname_queries_when_enabled() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-cname".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["CNAME".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let packet = build_dns_cname_query(0x4444, "0-deadbeef.dn.c2.example.com");
    client.send(&packet).await.expect("send failed");

    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");

    assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR");
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    assert_eq!(ancount, 1);
    let parsed = parse_dns_query(&packet).expect("query should parse");
    let question_qtype_offset = DNS_HEADER_LEN + parsed.qname_raw.len();
    let echoed_qtype =
        u16::from_be_bytes([buf[question_qtype_offset], buf[question_qtype_offset + 1]]);
    assert_eq!(echoed_qtype, DNS_TYPE_CNAME);
    assert_eq!(
        dns_answer_rr_type(&buf, parsed.qname_raw.len()),
        Some(DNS_TYPE_CNAME),
        "answer RR must be CNAME when the query is CNAME"
    );
    let expected_rdata =
        dns_wire_domain_from_ascii_payload("wait").expect("wait encodes as CNAME RDATA");
    assert_eq!(dns_answer_rdata(&buf, parsed.qname_raw.len()), Some(expected_rdata));
    handle.abort();
}

/// When multiple record types are enabled, each successful C2 poll must answer with an RR
/// whose TYPE matches the question QTYPE (not always TXT).
#[tokio::test]
async fn dns_listener_multi_record_types_each_answer_rr_matches_query_qtype() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-multi-qtype".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned(), "A".to_owned(), "CNAME".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;

    sleep(Duration::from_millis(50)).await;

    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");

    let qname = "0-deadbeef.dn.c2.example.com";
    for (id, qtype) in [(0x6001u16, DNS_TYPE_TXT), (0x6002, DNS_TYPE_A), (0x6003, DNS_TYPE_CNAME)] {
        let packet = build_dns_query(id, qname, qtype);
        client.send(&packet).await.expect("send failed");

        let mut buf = vec![0u8; 512];
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no response received")
            .expect("recv failed");

        assert_eq!(buf[3] & 0x0F, 0, "expected NOERROR for qtype {qtype}");
        let parsed = parse_dns_query(&packet).expect("query should parse");
        assert_eq!(
            dns_answer_rr_type(&buf, parsed.qname_raw.len()),
            Some(qtype),
            "answer RR TYPE must match QTYPE {qtype}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn smb_listener_runtime_exits_when_shutdown_started_before_first_poll() {
    let shutdown = ShutdownController::new();
    let pipe_name = unique_smb_pipe_name("shutdown-prepoll");
    let config = red_cell_common::SmbListenerConfig {
        name: "smb-shutdown-prepoll".to_owned(),
        pipe_name,
        kill_date: None,
        working_hours: None,
    };
    let runtime =
        spawn_test_smb_runtime(config, shutdown.clone()).await.expect("smb runtime should start");

    shutdown.initiate();

    let result = timeout(Duration::from_millis(200), runtime)
        .await
        .expect("smb runtime should observe pre-existing shutdown");
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn dns_listener_start_rejects_unsupported_record_types() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-invalid-type".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["MX".to_owned()],
        kill_date: None,
        working_hours: None,
    };

    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let error = match spawn_dns_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        DemonInitRateLimiter::new(),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        ShutdownController::new(),
        None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        false,
    )
    .await
    {
        Ok(_) => panic!("start should fail"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("unsupported DNS record type configuration"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn dns_listener_download_done_removes_pending_response() {
    let state = dns_state("dns-cleanup").await;
    let agent_id = 0xDEAD_BEEF;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(agent_id, key, iv)).await.expect("insert agent");

    state.responses.lock().await.insert(
        agent_id,
        DnsPendingResponse {
            chunks: vec!["AAA".to_owned(), "BBB".to_owned()],
            received_at: Instant::now(),
        },
    );

    assert_eq!(state.handle_download(agent_id, 0).await, "2 AAA");
    assert!(state.responses.lock().await.contains_key(&agent_id));

    assert_eq!(state.handle_download(agent_id, 2).await, "done");
    assert!(!state.responses.lock().await.contains_key(&agent_id));
    assert_eq!(state.handle_download(agent_id, 0).await, "wait");
}

#[tokio::test]
async fn dns_listener_download_rejects_unknown_agent_id() {
    let state = dns_state("dns-auth-reject").await;
    let agent_id = 0xDEAD_BEEF;
    let unknown_id = 0xCAFE_BABE;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(agent_id, key, iv)).await.expect("insert agent");

    // Insert a queued response for the known agent using the unknown_id as the key
    // to simulate an attacker injecting under an unregistered agent ID.
    state.responses.lock().await.insert(
        unknown_id,
        DnsPendingResponse { chunks: vec!["SECRET".to_owned()], received_at: Instant::now() },
    );

    // Unknown agent should be rejected with "wait" and the queue entry must survive.
    assert_eq!(state.handle_download(unknown_id, 0).await, "wait");
    assert!(
        state.responses.lock().await.contains_key(&unknown_id),
        "queued response must not be consumed for unregistered agent"
    );
}

/// Regression test for red-cell-c2-59m7: DNS download must succeed even
/// when the resolver IP changes between upload and download.  Recursive
/// resolver pools legitimately rotate source IPs, so binding to the
/// upload peer_ip strands real agents.
#[tokio::test]
async fn dns_download_succeeds_from_different_resolver_ip() {
    let state = dns_state("dns-resolver-rotate").await;
    let agent_id = 0xDEAD_BEEF;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(agent_id, key, iv)).await.expect("insert agent");

    // Simulate response queued from upload via resolver A.
    state.responses.lock().await.insert(
        agent_id,
        DnsPendingResponse {
            chunks: vec!["AAA".to_owned(), "BBB".to_owned()],
            received_at: Instant::now(),
        },
    );

    // Download arrives via resolver B (different IP) — must still work.
    assert_eq!(state.handle_download(agent_id, 0).await, "2 AAA");
    assert!(state.responses.lock().await.contains_key(&agent_id));
    assert_eq!(state.handle_download(agent_id, 1).await, "2 BBB");
    assert!(state.responses.lock().await.contains_key(&agent_id));
    assert_eq!(state.handle_download(agent_id, 2).await, "done");
    assert!(!state.responses.lock().await.contains_key(&agent_id));
}

/// An unregistered agent must not be able to download responses, even
/// though the IP check was removed.  The registry check is the gate.
#[tokio::test]
async fn dns_download_rejects_unregistered_agent_regardless_of_ip() {
    let state = dns_state("dns-unregistered-dl").await;
    let registered_id = 0xDEAD_BEEF;
    let unregistered_id = 0xCAFE_BABE;
    let key = [0x11u8; AGENT_KEY_LENGTH];
    let iv = [0x22u8; AGENT_IV_LENGTH];

    state.registry.insert(sample_agent_info(registered_id, key, iv)).await.expect("insert");

    // Plant a response under the unregistered agent ID.
    state.responses.lock().await.insert(
        unregistered_id,
        DnsPendingResponse { chunks: vec!["SECRET".to_owned()], received_at: Instant::now() },
    );

    // Must be rejected because the agent is not in the registry.
    assert_eq!(state.handle_download(unregistered_id, 0).await, "wait");
    assert!(
        state.responses.lock().await.contains_key(&unregistered_id),
        "queued response must not be consumed for unregistered agent"
    );
}

#[tokio::test]
async fn dns_upload_rejects_total_over_limit() {
    let state = dns_state("dns-total-cap").await;

    let result = state
        .try_assemble_upload(
            0xDEAD_BEEF,
            0,
            DNS_MAX_UPLOAD_CHUNKS + 1,
            vec![0x41],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .await;

    assert_eq!(result, DnsUploadAssembly::Rejected);
    assert!(state.uploads.lock().await.is_empty());
}

#[tokio::test]
async fn dns_upload_rejects_inconsistent_total_and_clears_session() {
    let state = dns_state("dns-total-mismatch").await;
    let agent_id = 0xDEAD_BEEF;

    let first = state
        .try_assemble_upload(agent_id, 0, 2, vec![0x41], IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await;
    assert_eq!(first, DnsUploadAssembly::Pending);

    let second = state
        .try_assemble_upload(agent_id, 1, 3, vec![0x42], IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await;
    assert_eq!(second, DnsUploadAssembly::Rejected);
    assert!(!state.uploads.lock().await.contains_key(&agent_id));
}

/// A third-party host that knows a valid agent_id must not be able to clear the legitimate
/// agent's in-progress upload session by sending a chunk with a mismatched total.
#[tokio::test]
async fn dns_upload_spoof_does_not_clear_legitimate_session() {
    let state = dns_state("dns-spoof-dos").await;
    let agent_id = 0xDEAD_BEEF;
    let legit_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let attacker_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    // Legitimate agent opens a 3-chunk upload session.
    let first = state.try_assemble_upload(agent_id, 0, 3, vec![0x41], legit_ip).await;
    assert_eq!(first, DnsUploadAssembly::Pending);

    // Attacker sends a chunk for the same agent_id with a different total to trigger
    // the inconsistent-total branch — this must be rejected without clearing the session.
    let spoof = state.try_assemble_upload(agent_id, 0, 99, vec![0xFF], attacker_ip).await;
    assert_eq!(spoof, DnsUploadAssembly::Rejected);

    // The legitimate session must still be intact.
    {
        let uploads = state.uploads.lock().await;
        let session = uploads.get(&agent_id).expect("session must still exist after spoof");
        assert_eq!(session.total, 3, "session total must not have been overwritten");
        assert_eq!(session.peer_ip, legit_ip, "session peer_ip must not have changed");
    }

    // Attacker sends matching total but is still rejected due to IP mismatch.
    let spoof_matching_total =
        state.try_assemble_upload(agent_id, 1, 3, vec![0xAA], attacker_ip).await;
    assert_eq!(spoof_matching_total, DnsUploadAssembly::Rejected);

    // Session must remain unchanged — only legit_ip's chunk (seq 0) is present.
    {
        let uploads = state.uploads.lock().await;
        let session = uploads.get(&agent_id).expect("session must still exist");
        assert_eq!(session.chunks.len(), 1);
        assert!(session.chunks.contains_key(&0));
    }

    // Legitimate agent completes the upload normally.
    let second = state.try_assemble_upload(agent_id, 1, 3, vec![0x42], legit_ip).await;
    assert_eq!(second, DnsUploadAssembly::Pending);
    let third = state.try_assemble_upload(agent_id, 2, 3, vec![0x43], legit_ip).await;
    assert_eq!(third, DnsUploadAssembly::Complete(vec![0x41, 0x42, 0x43]));
}

#[tokio::test]
async fn dns_upload_rejects_new_session_when_capacity_reached() {
    let state = dns_state("dns-capacity").await;

    {
        let mut uploads = state.uploads.lock().await;
        for agent_id in 0..DNS_MAX_PENDING_UPLOADS {
            uploads.insert(
                agent_id as u32,
                DnsPendingUpload {
                    chunks: HashMap::new(),
                    total: 1,
                    received_at: Instant::now(),
                    // Use a distinct IP per slot so per-IP limits don't interfere.
                    peer_ip: IpAddr::V4(Ipv4Addr::new(
                        10,
                        ((agent_id >> 16) & 0xFF) as u8,
                        ((agent_id >> 8) & 0xFF) as u8,
                        (agent_id & 0xFF) as u8,
                    )),
                },
            );
        }
    }

    let result = state
        .try_assemble_upload(
            0xDEAD_BEEF,
            0,
            1,
            vec![0x41],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        )
        .await;

    assert_eq!(result, DnsUploadAssembly::Rejected);
    assert_eq!(state.uploads.lock().await.len(), DNS_MAX_PENDING_UPLOADS);
}

#[tokio::test]
async fn dns_upload_rejects_new_session_when_per_ip_limit_reached() {
    let state = dns_state("dns-per-ip-cap").await;
    let attacker_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let other_ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

    // Fill up DNS_MAX_UPLOADS_PER_IP sessions from the attacker IP.
    for i in 0..DNS_MAX_UPLOADS_PER_IP {
        let result = state.try_assemble_upload(i as u32, 0, 2, vec![0x41], attacker_ip).await;
        assert_eq!(result, DnsUploadAssembly::Pending, "session {i} should be accepted");
    }

    // Next session from the same IP must be rejected.
    let result = state
        .try_assemble_upload(DNS_MAX_UPLOADS_PER_IP as u32, 0, 1, vec![0x41], attacker_ip)
        .await;
    assert_eq!(result, DnsUploadAssembly::Rejected);

    // A different IP must still be accepted.
    let result = state.try_assemble_upload(0xFFFF_0001, 0, 1, vec![0x41], other_ip).await;
    assert_eq!(result, DnsUploadAssembly::Complete(vec![0x41]));
}

#[tokio::test]
async fn dns_upload_cleanup_removes_expired_sessions() {
    let state = dns_state("dns-expiry").await;
    let stale_age = Duration::from_secs(DNS_UPLOAD_TIMEOUT_SECS + 1);

    {
        let mut uploads = state.uploads.lock().await;
        uploads.insert(
            1,
            DnsPendingUpload {
                chunks: HashMap::new(),
                total: 1,
                received_at: Instant::now() - stale_age,
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
        );
        uploads.insert(
            2,
            DnsPendingUpload {
                chunks: HashMap::new(),
                total: 1,
                received_at: Instant::now(),
                peer_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            },
        );
    }
    {
        let mut responses = state.responses.lock().await;
        responses.insert(
            3,
            DnsPendingResponse {
                chunks: vec!["AAA".to_owned()],
                received_at: Instant::now() - stale_age,
            },
        );
        responses.insert(
            4,
            DnsPendingResponse { chunks: vec!["BBB".to_owned()], received_at: Instant::now() },
        );
    }

    state.cleanup_expired_uploads().await;

    let uploads = state.uploads.lock().await;
    assert!(!uploads.contains_key(&1));
    assert!(uploads.contains_key(&2));
    drop(uploads);

    let responses = state.responses.lock().await;
    assert!(!responses.contains_key(&3));
    assert!(responses.contains_key(&4));
}

#[tokio::test]
async fn dns_response_cap_evicts_oldest_when_count_exceeded() {
    let state = dns_state("dns-resp-count-cap").await;

    {
        let mut responses = state.responses.lock().await;
        for i in 0..DNS_MAX_PENDING_RESPONSES {
            responses.insert(
                i as u32,
                DnsPendingResponse {
                    chunks: vec!["A".to_owned()],
                    // Stagger timestamps so eviction order is deterministic.
                    received_at: Instant::now()
                        - Duration::from_secs((DNS_MAX_PENDING_RESPONSES - i) as u64),
                },
            );
        }
        assert_eq!(responses.len(), DNS_MAX_PENDING_RESPONSES);
    }

    // Insert one more via enforce_response_caps — should evict agent 0 (oldest).
    let new_chunks = vec!["NEW".to_owned()];
    {
        let mut responses = state.responses.lock().await;
        let accepted = DnsListenerState::enforce_response_caps(
            &mut responses,
            0xFFFF_FFFF,
            &new_chunks,
            "test",
        );
        assert!(accepted, "small response should be accepted");
        responses.insert(
            0xFFFF_FFFF,
            DnsPendingResponse { chunks: new_chunks, received_at: Instant::now() },
        );

        assert_eq!(responses.len(), DNS_MAX_PENDING_RESPONSES);
        assert!(!responses.contains_key(&0), "oldest entry (agent 0) should have been evicted");
        assert!(responses.contains_key(&0xFFFF_FFFF), "new entry should be present");
    }
}

#[tokio::test]
async fn dns_response_cap_evicts_oldest_when_byte_limit_exceeded() {
    let state = dns_state("dns-resp-byte-cap").await;

    // Each chunk is 1 MB of data — insert 7 entries (7 MB total, under 8 MB cap).
    let big_chunk = "X".repeat(1024 * 1024);
    {
        let mut responses = state.responses.lock().await;
        for i in 0..7u32 {
            responses.insert(
                i,
                DnsPendingResponse {
                    chunks: vec![big_chunk.clone()],
                    received_at: Instant::now() - Duration::from_secs((7 - i) as u64),
                },
            );
        }
        assert_eq!(responses.len(), 7);
    }

    // Inserting a 2 MB response should push total to 9 MB, evicting the oldest.
    let new_chunks = vec![big_chunk.clone(), big_chunk.clone()];
    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 100, &new_chunks, "test");
        assert!(accepted, "response fitting within cap should be accepted");
        responses
            .insert(100, DnsPendingResponse { chunks: new_chunks, received_at: Instant::now() });

        // Agent 0 (oldest, 1 MB) evicted → 6 old + 1 new = 7 entries, 8 MB total.
        assert!(!responses.contains_key(&0), "oldest entry should have been evicted");
        assert!(responses.contains_key(&100), "new entry should be present");
        let total = DnsListenerState::pending_response_bytes(&responses);
        assert!(
            total <= DNS_MAX_PENDING_RESPONSE_BYTES,
            "total bytes {total} exceeds cap {DNS_MAX_PENDING_RESPONSE_BYTES}"
        );
    }
}

#[tokio::test]
async fn dns_response_cap_replacement_does_not_evict() {
    let state = dns_state("dns-resp-replace").await;

    {
        let mut responses = state.responses.lock().await;
        for i in 0..DNS_MAX_PENDING_RESPONSES {
            responses.insert(
                i as u32,
                DnsPendingResponse { chunks: vec!["OLD".to_owned()], received_at: Instant::now() },
            );
        }
    }

    // Replacing agent 0's response (same agent_id) should not evict any other entry.
    let new_chunks = vec!["REPLACED".to_owned()];
    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 0, &new_chunks, "test");
        assert!(accepted, "replacement response should be accepted");
        responses.insert(0, DnsPendingResponse { chunks: new_chunks, received_at: Instant::now() });

        assert_eq!(responses.len(), DNS_MAX_PENDING_RESPONSES);
        assert_eq!(responses.get(&0).expect("agent 0").chunks[0], "REPLACED");
        // All other entries still present.
        for i in 1..DNS_MAX_PENDING_RESPONSES {
            assert!(responses.contains_key(&(i as u32)), "agent {i} must still exist");
        }
    }
}

#[tokio::test]
async fn dns_response_cap_rejects_oversized_single_response() {
    let state = dns_state("dns-resp-oversize").await;

    // Build a single response that exceeds DNS_MAX_PENDING_RESPONSE_BYTES (8 MiB).
    // Use (8 MiB + 1) bytes spread across two chunks.
    let half = DNS_MAX_PENDING_RESPONSE_BYTES / 2;
    let oversized_chunks = vec!["X".repeat(half), "X".repeat(half + 1)];
    let total: usize = oversized_chunks.iter().map(|c| c.len()).sum();
    assert!(total > DNS_MAX_PENDING_RESPONSE_BYTES);

    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 42, &oversized_chunks, "test");
        assert!(!accepted, "oversized single response must be rejected");
        assert!(responses.is_empty(), "map should remain empty after rejection");
    }
}

#[tokio::test]
async fn dns_response_cap_rejects_oversized_and_restores_replaced() {
    let state = dns_state("dns-resp-oversize-replace").await;

    // Pre-populate an entry for agent 42.
    let original_chunks = vec!["ORIGINAL".to_owned()];
    {
        let mut responses = state.responses.lock().await;
        responses.insert(
            42,
            DnsPendingResponse { chunks: original_chunks, received_at: Instant::now() },
        );
    }

    // Try to replace agent 42's entry with an oversized response.
    let half = DNS_MAX_PENDING_RESPONSE_BYTES / 2;
    let oversized_chunks = vec!["X".repeat(half), "X".repeat(half + 1)];

    {
        let mut responses = state.responses.lock().await;
        let accepted =
            DnsListenerState::enforce_response_caps(&mut responses, 42, &oversized_chunks, "test");
        assert!(!accepted, "oversized replacement must be rejected");
        // The original entry should be restored.
        assert!(responses.contains_key(&42), "original entry must be restored");
        assert_eq!(
            responses.get(&42).expect("agent 42").chunks[0],
            "ORIGINAL",
            "restored entry must have original data"
        );
    }
}

#[test]
fn dns_pending_response_bytes_computes_correctly() {
    let mut map = HashMap::new();
    map.insert(
        1,
        DnsPendingResponse {
            chunks: vec!["ABC".to_owned(), "DE".to_owned()],
            received_at: Instant::now(),
        },
    );
    map.insert(
        2,
        DnsPendingResponse { chunks: vec!["FGHIJ".to_owned()], received_at: Instant::now() },
    );
    // "ABC" (3) + "DE" (2) + "FGHIJ" (5) = 10
    assert_eq!(DnsListenerState::pending_response_bytes(&map), 10);
}

// --- listener lifecycle event payload helpers ---

fn minimal_http_summary(name: &str) -> ListenerSummary {
    ListenerSummary {
        name: name.to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: http_listener(name, 8080),
    }
}

#[test]
fn listener_event_for_action_created_returns_listener_new() {
    let summary = minimal_http_summary("alpha");
    let msg = listener_event_for_action("operator1", &summary, ListenerEventAction::Created);
    match msg {
        OperatorMessage::ListenerNew(m) => {
            assert_eq!(m.head.user, "operator1");
            assert_eq!(m.info.name.as_deref(), Some("alpha"));
        }
        other => panic!("expected ListenerNew, got {other:?}"),
    }
}

#[test]
fn listener_event_for_action_updated_returns_listener_edit() {
    let summary = minimal_http_summary("beta");
    let msg = listener_event_for_action("op", &summary, ListenerEventAction::Updated);
    match msg {
        OperatorMessage::ListenerEdit(m) => {
            assert_eq!(m.head.user, "op");
            assert_eq!(m.info.name.as_deref(), Some("beta"));
        }
        other => panic!("expected ListenerEdit, got {other:?}"),
    }
}

#[test]
fn listener_event_for_action_started_returns_online_mark() {
    let summary = minimal_http_summary("gamma");
    let msg = listener_event_for_action("op", &summary, ListenerEventAction::Started);
    match msg {
        OperatorMessage::ListenerMark(m) => {
            assert_eq!(m.info.name, "gamma");
            assert_eq!(m.info.mark, "Online");
        }
        other => panic!("expected ListenerMark(Online), got {other:?}"),
    }
}

#[test]
fn listener_event_for_action_stopped_returns_offline_mark() {
    let summary = minimal_http_summary("delta");
    let msg = listener_event_for_action("op", &summary, ListenerEventAction::Stopped);
    match msg {
        OperatorMessage::ListenerMark(m) => {
            assert_eq!(m.info.name, "delta");
            assert_eq!(m.info.mark, "Offline");
        }
        other => panic!("expected ListenerMark(Offline), got {other:?}"),
    }
}

#[test]
fn listener_error_event_preserves_name_and_error_text() {
    let error = ListenerManagerError::StartFailed {
        name: "epsilon".to_owned(),
        message: "bind failed".to_owned(),
    };
    let msg = listener_error_event("admin", "epsilon", &error);
    match msg {
        OperatorMessage::ListenerError(m) => {
            assert_eq!(m.head.user, "admin");
            assert_eq!(m.info.name, "epsilon");
            assert!(
                m.info.error.contains("bind failed"),
                "error text should contain the original message"
            );
        }
        other => panic!("expected ListenerError, got {other:?}"),
    }
}

#[test]
fn listener_error_event_invalid_config_variant() {
    let error = ListenerManagerError::InvalidConfig { message: "missing port".to_owned() };
    let msg = listener_error_event("sysop", "zeta", &error);
    match msg {
        OperatorMessage::ListenerError(m) => {
            assert_eq!(m.info.name, "zeta");
            assert!(m.info.error.contains("missing port"));
        }
        other => panic!("expected ListenerError, got {other:?}"),
    }
}

#[test]
fn listener_removed_event_preserves_name() {
    let msg = listener_removed_event("op", "eta");
    match msg {
        OperatorMessage::ListenerRemove(m) => {
            assert_eq!(m.head.user, "op");
            assert_eq!(m.info.name, "eta");
        }
        other => panic!("expected ListenerRemove, got {other:?}"),
    }
}

#[test]
fn listener_event_for_action_head_user_is_propagated() {
    // Verify all four actions carry the correct user in MessageHead.
    let summary = minimal_http_summary("theta");
    for action in [
        ListenerEventAction::Created,
        ListenerEventAction::Updated,
        ListenerEventAction::Started,
        ListenerEventAction::Stopped,
    ] {
        let msg = listener_event_for_action("carol", &summary, action);
        let user = match &msg {
            OperatorMessage::ListenerNew(m) => &m.head.user,
            OperatorMessage::ListenerEdit(m) => &m.head.user,
            OperatorMessage::ListenerMark(m) => &m.head.user,
            _ => panic!("unexpected variant"),
        };
        assert_eq!(user, "carol", "action {action:?} did not preserve user");
    }
}

#[test]
fn operator_protocol_name_emits_havoc_compatible_title_case_labels() {
    // HTTP (non-secure) → "Http"
    let http = http_listener("http-test", 8080);
    assert_eq!(operator_protocol_name(&http), "Http");

    // HTTPS (secure) → "Https"
    let https = ListenerConfig::from(HttpListenerConfig {
        name: "https-test".to_owned(),
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 443,
        port_conn: None,
        secure: true,
        kill_date: None,
        working_hours: None,
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
    });
    assert_eq!(operator_protocol_name(&https), "Https");

    // SMB → "Smb"
    let smb = ListenerConfig::from(SmbListenerConfig {
        name: "smb-test".to_owned(),
        pipe_name: "pipe-test".to_owned(),
        kill_date: None,
        working_hours: None,
    });
    assert_eq!(operator_protocol_name(&smb), "Smb");

    // DNS → "Dns"
    let dns = dns_listener_config("dns-test", 53, "c2.example");
    assert_eq!(operator_protocol_name(&dns), "Dns");

    // External → "External"
    let external = ListenerConfig::from(ExternalListenerConfig {
        name: "ext-test".to_owned(),
        endpoint: "/bridge".to_owned(),
    });
    assert_eq!(operator_protocol_name(&external), "External");
}

// ── ListenerManager constructor helpers and shutdown lifecycle ────────────

/// Happy path: `with_max_download_bytes` returns a manager that shares registry/shutdown
/// handles with the caller, and `shutdown` returns `true` after draining a started listener.
#[tokio::test]
async fn with_max_download_bytes_exposes_registry_and_shutdown_handles_and_drains_cleanly()
-> Result<(), ListenerManagerError> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let manager = ListenerManager::with_max_download_bytes(
        database,
        registry.clone(),
        events,
        sockets,
        None,
        1024 * 1024,
    )
    .with_demon_allow_legacy_ctr(true);

    // agent_registry() must return the same underlying handle: an insert via the returned
    // registry is visible through the original handle.
    let returned_registry = manager.agent_registry();
    let agent = sample_agent_info(0xCAFE_BABE, test_key(0x41), test_iv(0x24));
    returned_registry.insert(agent).await.expect("agent insert should succeed");
    assert!(registry.get(0xCAFE_BABE).await.is_some(), "registry handle must be shared");

    // shutdown_controller() must start in the running state.
    let ctrl = manager.shutdown_controller();
    assert!(!ctrl.is_shutting_down(), "controller must not be shutting down before shutdown()");

    // Start a real listener so shutdown() has an active handle to stop.
    let port = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    manager.create(http_listener("alpha", port)).await?;
    let running = manager.start("alpha").await?;
    assert_eq!(running.state.status, ListenerStatus::Running);
    assert!(!manager.active_handles.read().await.is_empty());

    // No in-flight callbacks → drain completes immediately → shutdown returns true.
    let drained = manager.shutdown(Duration::from_secs(1)).await;
    assert!(drained, "drain should complete when no callbacks are tracked");
    assert!(
        manager.active_handles.read().await.is_empty(),
        "all active handles must be cleared after shutdown",
    );
    assert!(ctrl.is_shutting_down(), "shutdown controller must reflect initiated state");

    Ok(())
}

/// Error path: `shutdown` still stops all active listeners and returns `false` when the
/// callback-drain timeout is exceeded because a tracked guard is held.
#[tokio::test]
async fn shutdown_stops_active_listeners_and_returns_false_when_drain_times_out()
-> Result<(), ListenerManagerError> {
    let manager = manager().await?;
    let port = available_port()
        .map_err(|error| ListenerManagerError::InvalidConfig { message: error.to_string() })?;
    manager.create(http_listener("beta", port)).await?;
    manager.start("beta").await?;
    assert!(!manager.active_handles.read().await.is_empty());

    // Acquire a callback guard before calling shutdown; this prevents the drain from
    // completing during the short timeout window.
    let ctrl = manager.shutdown_controller();
    let _guard = ctrl.try_track_callback().expect("callback must be accepted before shutdown");

    // A very short timeout ensures drain times out while the guard is still live.
    let drained = manager.shutdown(Duration::from_millis(5)).await;
    assert!(!drained, "drain should time out when an active callback guard is held");

    // Even with a failed drain, the shutdown loop must have stopped every listener.
    assert!(
        manager.active_handles.read().await.is_empty(),
        "active handles must be cleared even when callback drain times out",
    );

    // Release the guard so the runtime can fully wind down.
    drop(_guard);
    Ok(())
}

/// Edge case: the cleanup hook registered by `with_max_download_bytes` fires when the
/// registry removes an agent, draining any per-agent download state.
#[tokio::test]
async fn cleanup_hook_installed_by_with_max_download_bytes_fires_on_agent_removal()
-> Result<(), ListenerManagerError> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::with_max_download_bytes(
        database,
        registry.clone(),
        events,
        sockets,
        None,
        1024,
    )
    .with_demon_allow_legacy_ctr(true);

    // Register a spy hook after construction to confirm the full cleanup chain fires.
    // Hooks run in registration order: the download-drain hook runs first, then the spy.
    let observed_id = Arc::new(AtomicU32::new(0));
    let spy_id = observed_id.clone();
    manager.agent_registry().register_cleanup_hook(move |agent_id| {
        let spy_id = spy_id.clone();
        async move {
            spy_id.store(agent_id, Ordering::SeqCst);
        }
    });

    // Insert an agent and then remove it to trigger the cleanup chain.
    let agent_id: u32 = 0x1234_5678;
    let agent = sample_agent_info(agent_id, test_key(0x41), test_iv(0x24));
    registry.insert(agent).await.expect("agent insert should succeed");
    registry.remove(agent_id).await.expect("agent removal should succeed");

    // The spy hook must have been called with the correct agent_id.
    assert_eq!(
        observed_id.load(Ordering::SeqCst),
        agent_id,
        "spy hook must be called with the removed agent_id",
    );

    // The download drain hook ran before the spy (FIFO registration order). Calling
    // drain_agent again must return 0 — nothing left to drain.
    let remaining = manager.downloads.drain_agent(agent_id).await;
    assert_eq!(
        remaining, 0,
        "download hook must have already drained all per-agent state before spy ran",
    );

    Ok(())
}

// ── Plugin event wiring test ──────────────────────────────────────────────

/// Verify that a successful DemonInit (processed inside `process_demon_transport`)
/// causes `emit_agent_registered` to be called, which in turn fires any registered
/// `AgentRegistered` Python callbacks.
///
/// This test goes end-to-end through the real HTTP listener stack so that a future
/// refactor cannot silently disconnect the `emit_agent_registered` call without a
/// test failure.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn process_demon_transport_fires_plugin_agent_registered_event()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{PluginEvent, PluginRuntime};
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList};

    let _guard = crate::plugins::PLUGIN_RUNTIME_TEST_MUTEX
        .lock()
        .map_err(|_| "plugin test mutex poisoned")?;

    // Build a PluginRuntime that has access to the registry (needed by emit_agent_registered).
    let database = Database::connect_in_memory().await?;
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

    // Install this runtime as the process-wide active runtime and arrange for
    // cleanup when the test exits (success or panic).
    struct RuntimeGuard(Option<PluginRuntime>);
    impl Drop for RuntimeGuard {
        fn drop(&mut self) {
            let _ = PluginRuntime::swap_active(self.0.take());
        }
    }
    let previous = PluginRuntime::swap_active(Some(runtime.clone()))?;
    let _reset = RuntimeGuard(previous);

    // Register an AgentRegistered callback that appends the event_type to a Python list.
    let (tracker, callback) = tokio::task::spawn_blocking({
        let runtime = runtime.clone();
        move || {
            Python::with_gil(|py| {
                runtime.install_api_module_for_test(py)?;
                let tracker = PyList::empty(py);
                let locals = PyDict::new(py);
                locals.set_item("_tracker", tracker.clone())?;
                let cb = py.eval(
                    pyo3::ffi::c_str!(
                        "(lambda t: lambda event: t.append(event.event_type))(_tracker)"
                    ),
                    None,
                    Some(&locals),
                )?;
                Ok::<_, PyErr>((tracker.unbind(), cb.unbind()))
            })
        }
    })
    .await??;

    runtime.register_callback_for_test(PluginEvent::AgentRegistered, callback).await?;

    // Start a real HTTP listener, submit a valid DemonInit, and assert it succeeds.
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    manager.create(http_listener("plugin-init-wiring", port)).await?;
    manager.start("plugin-init-wiring").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(0xABCD_1234, key, iv))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.bytes().await?;

    // Allow the spawn_blocking inside invoke_callbacks to complete.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let (count, event_type) = tokio::task::spawn_blocking(move || {
        Python::with_gil(|py| -> PyResult<(usize, String)> {
            let list = tracker.bind(py);
            let count = list.len();
            let first = list.get_item(0)?.extract::<String>()?;
            Ok((count, first))
        })
    })
    .await??;

    assert_eq!(count, 1, "exactly one agent_registered callback should have fired");
    assert_eq!(event_type, "agent_registered");

    manager.stop("plugin-init-wiring").await?;
    Ok(())
}

// ── External C2 bridge listener tests ───────────────────────────────────

fn external_listener_config(name: &str, endpoint: &str) -> ListenerConfig {
    ListenerConfig::from(ExternalListenerConfig {
        name: name.to_owned(),
        endpoint: endpoint.to_owned(),
    })
}

#[test]
fn listener_config_from_operator_parses_external() {
    let info = ListenerInfo {
        name: Some("bridge".to_owned()),
        protocol: Some("External".to_owned()),
        extra: [("Endpoint".to_owned(), serde_json::Value::String("/ext".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info).expect("should parse external config");
    assert_eq!(config.name(), "bridge");
    assert_eq!(config.protocol(), ListenerProtocol::External);
    match &config {
        ListenerConfig::External(c) => {
            assert_eq!(c.endpoint, "/ext");
        }
        other => panic!("expected External config, got {other:?}"),
    }
}

#[test]
fn listener_config_from_operator_rejects_external_without_endpoint() {
    let info = ListenerInfo {
        name: Some("bridge".to_owned()),
        protocol: Some("External".to_owned()),
        extra: std::collections::BTreeMap::new(),
        ..ListenerInfo::default()
    };

    let error = listener_config_from_operator(&info).expect_err("missing endpoint should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[tokio::test]
async fn external_listener_create_start_stop_lifecycle() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let config = external_listener_config("ext1", "/bridge");

    // Create persists the listener.
    manager.create(config).await.expect("create should succeed");
    let summary = manager.summary("ext1").await.expect("listener should exist");
    assert_eq!(summary.protocol, ListenerProtocol::External);
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start should register the endpoint.
    manager.start("ext1").await.expect("start should succeed");
    let summary = manager.summary("ext1").await.expect("listener should exist");
    assert_eq!(summary.state.status, ListenerStatus::Running);

    // The external endpoint should be registered.
    let state =
        manager.external_state_for_path("/bridge").await.expect("endpoint should be registered");
    assert_eq!(state.listener_name(), "ext1");
    assert_eq!(state.endpoint(), "/bridge");

    // Stop should deregister the endpoint.
    manager.stop("ext1").await.expect("stop should succeed");

    // Give the managed task a moment to clean up.
    sleep(Duration::from_millis(50)).await;

    let removed = manager.external_state_for_path("/bridge").await;
    assert!(removed.is_none(), "endpoint should be deregistered after stop");
}

#[tokio::test]
async fn external_listener_to_operator_info_includes_endpoint() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let config = external_listener_config("ext-info", "/c2");
    manager.create(config).await.expect("create should succeed");

    let summary = manager.summary("ext-info").await.expect("listener should exist");
    let info = summary.to_operator_info();
    assert_eq!(info.protocol.as_deref(), Some("External"));
    assert_eq!(info.extra.get("Endpoint").and_then(|v| v.as_str()), Some("/c2"),);
    assert_eq!(info.extra.get("Info").and_then(|v| v.as_str()), Some("/c2"),);
}

#[test]
fn profile_listener_configs_includes_external() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "op" { Password = "password1234" }
        }

        Listeners {
          External {
            Name = "bridge"
            Endpoint = "/ext"
          }
        }

        Demon {}
        "#,
    )
    .expect("profile should parse");

    let configs = profile_listener_configs(&profile).expect("configs should be valid");
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].name(), "bridge");
    assert_eq!(configs[0].protocol(), ListenerProtocol::External);
}

#[tokio::test]
async fn external_state_for_path_returns_none_for_unknown() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    assert!(
        manager.external_state_for_path("/nonexistent").await.is_none(),
        "unknown path should return None"
    );
}

#[tokio::test]
async fn external_listener_serializes_and_restores() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let config = external_listener_config("ext-persist", "/persist");
    manager.create(config).await.expect("create");

    // Verify the config round-trips through the database.
    let summary = manager.summary("ext-persist").await.expect("should exist");
    assert_eq!(summary.config.protocol(), ListenerProtocol::External);
    match &summary.config {
        ListenerConfig::External(c) => {
            assert_eq!(c.name, "ext-persist");
            assert_eq!(c.endpoint, "/persist");
        }
        other => panic!("expected External, got {other:?}"),
    }
}

#[tokio::test]
async fn update_external_listener_rejects_duplicate_endpoint() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    // Create two external listeners with distinct endpoints.
    manager.create(external_listener_config("ext-a", "/alpha")).await.expect("create ext-a");
    manager.create(external_listener_config("ext-b", "/beta")).await.expect("create ext-b");

    // Updating ext-b to use ext-a's endpoint must fail.
    let conflict = manager.update(external_listener_config("ext-b", "/alpha")).await;
    assert!(
        matches!(conflict, Err(ListenerManagerError::DuplicateEndpoint { .. })),
        "expected DuplicateEndpoint, got {conflict:?}"
    );

    // Updating ext-a to its own endpoint must succeed (no self-conflict).
    manager
        .update(external_listener_config("ext-a", "/alpha"))
        .await
        .expect("self-update should succeed");

    // Updating ext-b to a new unique endpoint must succeed.
    manager
        .update(external_listener_config("ext-b", "/gamma"))
        .await
        .expect("update to unique endpoint should succeed");
}

// ── External listener preflight guard tests ──────────────────────────────

/// Verify that `handle_external_request` enforces the per-IP DEMON_INIT
/// rate limit in the same way as the HTTP listener.
#[tokio::test]
async fn handle_external_request_rate_limits_demon_init_per_source_ip() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    manager.create(external_listener_config("ext-rate", "/rate")).await.expect("create");
    manager.start("ext-rate").await.expect("start");

    let state = manager.external_state_for_path("/rate").await.expect("state must be registered");

    let peer: SocketAddr = "10.0.0.1:5000".parse().expect("unwrap");

    // Exhaust the allowed DEMON_INIT budget for this IP.
    for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0xEE00_0000 + attempt;
        let body = valid_demon_init_body(agent_id, test_key(0x11), test_iv(0x22));
        let result: Result<Vec<u8>, StatusCode> =
            handle_external_request(&state, peer, &body).await;
        assert!(result.is_ok(), "attempt {attempt} should be allowed, got {result:?}");
    }

    // The next DEMON_INIT from the same IP must be blocked (404).
    let blocked_id = 0xEE00_00FF;
    let blocked_body = valid_demon_init_body(blocked_id, test_key(0x11), test_iv(0x22));
    let blocked = handle_external_request(&state, peer, &blocked_body).await;
    assert_eq!(blocked, Err(StatusCode::NOT_FOUND), "over-limit init must return 404");
    assert!(registry.get(blocked_id).await.is_none(), "blocked agent must not be registered");

    manager.stop("ext-rate").await.expect("stop");
}

/// Verify that `handle_external_request` returns 503 when shutdown is in
/// progress (matching the behaviour of the HTTP and DNS listener paths).
#[tokio::test]
async fn handle_external_request_rejects_new_callbacks_during_shutdown() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    manager.create(external_listener_config("ext-shutdown", "/shutdown")).await.expect("create");
    manager.start("ext-shutdown").await.expect("start");

    let state =
        manager.external_state_for_path("/shutdown").await.expect("state must be registered");

    // Initiate shutdown before issuing a request.
    manager.shutdown_controller().initiate();

    let peer: SocketAddr = "10.0.0.2:6000".parse().expect("unwrap");
    let body = valid_demon_init_body(0xDEAD_0001, test_key(0x33), test_iv(0x44));
    let result = handle_external_request(&state, peer, &body).await;
    assert_eq!(
        result,
        Err(StatusCode::SERVICE_UNAVAILABLE),
        "request during shutdown must return 503"
    );
}

// ── HTTP required-field rejection tests ──────────────────────────────────

/// Helper: returns a fully-valid HTTP `ListenerInfo` that
/// `listener_config_from_operator` accepts.  Individual tests blank out one
/// field at a time to verify rejection.
fn valid_http_listener_info() -> ListenerInfo {
    ListenerInfo {
        name: Some("http-test".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("false".to_owned()),
        ..ListenerInfo::default()
    }
}

#[test]
fn listener_config_from_operator_rejects_http_without_name() {
    let info = ListenerInfo { name: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing Name should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_protocol() {
    let info = ListenerInfo { protocol: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing Protocol should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_unrecognised_protocol() {
    let info = ListenerInfo { protocol: Some("Telnet".to_owned()), ..valid_http_listener_info() };
    let error =
        listener_config_from_operator(&info).expect_err("unrecognised protocol should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_host_bind() {
    let info = ListenerInfo { host_bind: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing HostBind should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_host_rotation() {
    let info = ListenerInfo { host_rotation: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing HostRotation should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_without_port_bind() {
    let info = ListenerInfo { port_bind: None, ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("missing PortBind should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_rejects_http_with_non_numeric_port_bind() {
    let info =
        ListenerInfo { port_bind: Some("not-a-number".to_owned()), ..valid_http_listener_info() };
    let error = listener_config_from_operator(&info).expect_err("non-numeric PortBind should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

// ── kill_date helper unit tests ──────────────────────────────────────────

#[test]
fn is_past_kill_date_returns_false_when_none() {
    assert!(!is_past_kill_date(None));
}

#[test]
fn is_past_kill_date_returns_false_for_empty_string() {
    assert!(!is_past_kill_date(Some("")));
    assert!(!is_past_kill_date(Some("   ")));
}

#[test]
fn is_past_kill_date_returns_true_for_epoch_zero() {
    assert!(is_past_kill_date(Some("0")));
}

#[test]
fn is_past_kill_date_returns_true_for_past_timestamp() {
    // 2020-01-01 00:00:00 UTC
    assert!(is_past_kill_date(Some("1577836800")));
}

#[test]
fn is_past_kill_date_returns_false_for_far_future_timestamp() {
    // Year 2099
    assert!(!is_past_kill_date(Some("4102444800")));
}

#[test]
fn is_past_kill_date_returns_true_for_negative_timestamp() {
    assert!(is_past_kill_date(Some("-1")));
}

#[test]
fn is_past_kill_date_returns_true_for_malformed_string() {
    // Malformed values are treated as expired (fail-closed).
    assert!(is_past_kill_date(Some("not-a-number")));
}

#[test]
fn is_past_kill_date_accepts_human_readable_datetime() {
    // "2020-01-01 00:00:00" is in the past.
    assert!(is_past_kill_date(Some("2020-01-01 00:00:00")));
    // Far-future datetime should not be past.
    assert!(!is_past_kill_date(Some("2099-12-31 23:59:59")));
}

// ── to_operator_info isolated field assertions for SMB/DNS ──────────────

#[test]
fn smb_to_operator_info_includes_pipe_name_and_protocol() {
    let summary = ListenerSummary {
        name: "pivot".to_owned(),
        protocol: ListenerProtocol::Smb,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: smb_listener("pivot", "pivot-pipe"),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.name.as_deref(), Some("pivot"));
    assert_eq!(info.protocol.as_deref(), Some("Smb"));
    assert_eq!(info.status.as_deref(), Some("Offline"));
    assert_eq!(info.extra.get("PipeName").and_then(|v| v.as_str()), Some("pivot-pipe"),);
    assert_eq!(info.extra.get("Info").and_then(|v| v.as_str()), Some("pivot-pipe"),);
    // SMB has no real host/port — should be empty strings.
    assert_eq!(info.extra.get("Host").and_then(|v| v.as_str()), Some(""));
    assert_eq!(info.extra.get("Port").and_then(|v| v.as_str()), Some(""));
}

#[test]
fn smb_to_operator_info_with_last_error() {
    let summary = ListenerSummary {
        name: "smb-err".to_owned(),
        protocol: ListenerProtocol::Smb,
        state: PersistedListenerState {
            status: ListenerStatus::Error,
            last_error: Some("pipe busy".to_owned()),
        },
        config: smb_listener("smb-err", "pipe1"),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.status.as_deref(), Some("Offline"));
    assert_eq!(info.extra.get("Error").and_then(|v| v.as_str()), Some("pipe busy"),);
}

#[test]
fn dns_to_operator_info_includes_domain_and_record_types() {
    let summary = ListenerSummary {
        name: "dns-edge".to_owned(),
        protocol: ListenerProtocol::Dns,
        state: PersistedListenerState { status: ListenerStatus::Running, last_error: None },
        config: ListenerConfig::from(DnsListenerConfig {
            name: "dns-edge".to_owned(),
            host_bind: "0.0.0.0".to_owned(),
            port_bind: 53,
            domain: "c2.example".to_owned(),
            record_types: vec!["A".to_owned(), "TXT".to_owned()],
            kill_date: None,
            working_hours: None,
        }),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.name.as_deref(), Some("dns-edge"));
    assert_eq!(info.protocol.as_deref(), Some("Dns"));
    assert_eq!(info.status.as_deref(), Some("Online"));
    assert_eq!(info.extra.get("Domain").and_then(|v| v.as_str()), Some("c2.example"),);
    assert_eq!(info.extra.get("RecordTypes").and_then(|v| v.as_str()), Some("A,TXT"),);
    assert_eq!(info.extra.get("Host").and_then(|v| v.as_str()), Some("0.0.0.0"),);
    assert_eq!(info.extra.get("Port").and_then(|v| v.as_str()), Some("53"),);
    assert_eq!(info.extra.get("Info").and_then(|v| v.as_str()), Some("c2.example"),);
    assert_eq!(info.host_bind.as_deref(), Some("0.0.0.0"));
    assert_eq!(info.port_bind.as_deref(), Some("53"));
}

#[test]
fn http_to_operator_info_running_status_maps_to_online() {
    let summary = ListenerSummary {
        name: "http-run".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Running, last_error: None },
        config: http_listener("http-run", 8080),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.status.as_deref(), Some("Online"));
}

#[test]
fn http_to_operator_info_stopped_status_maps_to_offline() {
    let summary = ListenerSummary {
        name: "http-stop".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Stopped, last_error: None },
        config: http_listener("http-stop", 8080),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.status.as_deref(), Some("Offline"));
}

#[test]
fn http_to_operator_info_without_proxy_has_disabled_proxy() {
    let summary = ListenerSummary {
        name: "no-proxy".to_owned(),
        protocol: ListenerProtocol::Http,
        state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        config: http_listener("no-proxy", 8080),
    };

    let info = summary.to_operator_info();
    assert_eq!(info.proxy_enabled.as_deref(), Some("false"));
    assert!(info.proxy_host.is_none());
    assert!(info.proxy_port.is_none());
    assert!(info.proxy_username.is_none());
    assert!(info.proxy_password.is_none());
}

// ── listener_config_from_operator DNS isolated test ─────────────────────

#[test]
fn listener_config_from_operator_parses_dns() -> Result<(), ListenerManagerError> {
    let mut info = ListenerInfo {
        name: Some("dns-test".to_owned()),
        protocol: Some("Dns".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        port_bind: Some("5353".to_owned()),
        ..ListenerInfo::default()
    };
    info.extra.insert("Domain".to_owned(), serde_json::Value::String("c2.example".to_owned()));
    info.extra.insert("RecordTypes".to_owned(), serde_json::Value::String("A,TXT".to_owned()));

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Dns(dns) => {
            assert_eq!(dns.name, "dns-test");
            assert_eq!(dns.host_bind, "0.0.0.0");
            assert_eq!(dns.port_bind, 5353);
            assert_eq!(dns.domain, "c2.example");
            assert_eq!(dns.record_types, vec!["A", "TXT"]);
        }
        other => panic!("expected Dns config, got {other:?}"),
    }

    Ok(())
}

#[test]
fn listener_config_from_operator_dns_defaults_host_bind() -> Result<(), ListenerManagerError> {
    let mut info = ListenerInfo {
        name: Some("dns-default".to_owned()),
        protocol: Some("Dns".to_owned()),
        host_bind: None,
        port_bind: Some("53".to_owned()),
        ..ListenerInfo::default()
    };
    info.extra.insert("Domain".to_owned(), serde_json::Value::String("c2.test".to_owned()));

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Dns(dns) => {
            assert_eq!(dns.host_bind, "0.0.0.0", "DNS should default host_bind to 0.0.0.0");
        }
        other => panic!("expected Dns config, got {other:?}"),
    }

    Ok(())
}

#[test]
fn listener_config_from_operator_rejects_dns_without_domain() {
    let info = ListenerInfo {
        name: Some("dns-no-domain".to_owned()),
        protocol: Some("Dns".to_owned()),
        port_bind: Some("53".to_owned()),
        ..ListenerInfo::default()
    };

    let error = listener_config_from_operator(&info).expect_err("missing Domain should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[test]
fn listener_config_from_operator_parses_optional_port_conn() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("port-conn-test".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("8443".to_owned()),
        port_conn: Some("443".to_owned()),
        secure: Some("false".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_conn, Some(443));
        }
        other => panic!("expected Http config, got {other:?}"),
    }

    Ok(())
}

#[test]
fn listener_config_from_operator_accepts_absent_port_conn() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("no-port-conn".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("8080".to_owned()),
        port_conn: None,
        secure: Some("false".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert!(http.port_conn.is_none());
        }
        other => panic!("expected Http config, got {other:?}"),
    }

    Ok(())
}

// ── repository() returns a usable handle ────────────────────────────────

#[tokio::test]
async fn repository_returns_usable_listener_persistence_handle() -> Result<(), ListenerManagerError>
{
    let mgr = manager().await?;
    let repo = mgr.repository();

    // Initially empty.
    let all = repo.list().await?;
    assert!(all.is_empty());

    // Create via manager, verify via repository handle.
    mgr.create(http_listener("repo-test", 9090)).await?;
    let all = repo.list().await?;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].name, "repo-test");

    Ok(())
}

// ── with_demon_init_secret integration tests ────────────────────────────

/// Helper: build a `ListenerManager` configured with a DEMON_INIT secret.
async fn manager_with_secret(
    secret: Vec<u8>,
) -> Result<(ListenerManager, AgentRegistry, Database, EventBus), ListenerManagerError> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true)
            .with_demon_init_secret(Some(secret));
    Ok((manager, registry, database, events))
}

/// HTTP listener configured with `with_demon_init_secret` accepts a
/// DEMON_INIT packet and the returned ACK is encrypted with the derived
/// (HKDF) session keys — not the raw agent keys.
#[tokio::test]
async fn http_listener_with_init_secret_registers_agent_and_ack_uses_derived_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"http-test-server-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret.clone()).await?;
    let port = available_port()?;

    manager.create(http_listener("edge-secret", port)).await?;
    manager.start("edge-secret").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x61);
    let iv = test_iv(0x34);
    let agent_id = 0xABCD_0001_u32;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let ack_bytes = response.bytes().await?;

    // Agent must be registered.
    let stored = registry.get(agent_id).await.expect("agent should be registered");
    assert_eq!(stored.hostname, "wkstn-01");

    // The stored keys should be the HKDF-derived keys, not the raw ones.
    let derived = red_cell_common::crypto::derive_session_keys(&key, &iv, &secret)?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &derived.key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &derived.iv);

    // The ACK must be decryptable with derived keys.
    let ack_plain = decrypt_agent_data(&derived.key, &derived.iv, &ack_bytes)?;
    assert_eq!(ack_plain.as_slice(), &agent_id.to_le_bytes());

    // Decrypting the ACK with the *raw* agent keys must NOT produce the
    // expected agent_id (proves the secret actually changed the keys).
    let raw_plain = decrypt_agent_data(&key, &iv, &ack_bytes)?;
    assert_ne!(
        raw_plain.as_slice(),
        &agent_id.to_le_bytes(),
        "raw keys must not decrypt the ACK correctly when a secret is configured"
    );

    manager.stop("edge-secret").await?;
    Ok(())
}

/// HTTP listener with init secret rejects callbacks that use the raw
/// (non-derived) agent keys — the callback parse fails and the listener
/// returns 404.
#[tokio::test]
async fn http_listener_with_init_secret_rejects_callback_with_raw_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"http-callback-reject-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret).await?;
    let port = available_port()?;

    manager.create(http_listener("edge-secret-cb", port)).await?;
    manager.start("edge-secret-cb").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x71);
    let iv = test_iv(0x44);
    let agent_id = 0xABCD_0002_u32;

    // Register the agent via DEMON_INIT.
    let init_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(init_resp.status(), StatusCode::OK);
    assert!(registry.get(agent_id).await.is_some());

    // Send a callback using the *raw* keys — should fail because the
    // server stored derived keys.
    let callback_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;
    assert_eq!(
        callback_resp.status(),
        StatusCode::NOT_FOUND,
        "callback with raw keys must be rejected when init_secret is configured"
    );

    manager.stop("edge-secret-cb").await?;
    Ok(())
}

/// External listener configured with `with_demon_init_secret` accepts a
/// DEMON_INIT and returns an ACK encrypted with HKDF-derived keys.
#[tokio::test]
async fn external_listener_with_init_secret_registers_agent_and_ack_uses_derived_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"ext-test-server-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret.clone()).await?;

    manager.create(external_listener_config("ext-secret", "/secret")).await?;
    manager.start("ext-secret").await?;

    let state = manager.external_state_for_path("/secret").await.expect("state must be registered");

    let key = test_key(0x81);
    let iv = test_iv(0x54);
    let agent_id = 0xEEFF_0001_u32;
    let peer: SocketAddr = "10.0.0.50:7000".parse().expect("unwrap");

    let body = valid_demon_init_body(agent_id, key, iv);
    let result: Result<Vec<u8>, StatusCode> = handle_external_request(&state, peer, &body).await;
    let ack_bytes = result.expect("DEMON_INIT with matching secret should succeed");

    // Agent must be registered.
    let stored = registry.get(agent_id).await.expect("agent should be registered");

    // The stored keys should be HKDF-derived.
    let derived = red_cell_common::crypto::derive_session_keys(&key, &iv, &secret)?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &derived.key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &derived.iv);

    // ACK decryptable with derived keys.
    let ack_plain = decrypt_agent_data(&derived.key, &derived.iv, &ack_bytes)?;
    assert_eq!(ack_plain.as_slice(), &agent_id.to_le_bytes());

    manager.stop("ext-secret").await?;
    Ok(())
}

/// External listener with init secret rejects callbacks that use the raw
/// (non-derived) agent keys — `handle_external_request` returns 404.
#[tokio::test]
async fn external_listener_with_init_secret_rejects_callback_with_raw_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"ext-callback-reject-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret).await?;

    manager.create(external_listener_config("ext-secret-cb", "/secret-cb")).await?;
    manager.start("ext-secret-cb").await?;

    let state =
        manager.external_state_for_path("/secret-cb").await.expect("state must be registered");

    let key = test_key(0x91);
    let iv = test_iv(0x64);
    let agent_id = 0xEEFF_0002_u32;
    let peer: SocketAddr = "10.0.0.51:8000".parse().expect("unwrap");

    // Register agent via DEMON_INIT.
    let init_body = valid_demon_init_body(agent_id, key, iv);
    let init_result: Result<Vec<u8>, StatusCode> =
        handle_external_request(&state, peer, &init_body).await;
    assert!(init_result.is_ok());
    assert!(registry.get(agent_id).await.is_some());

    // Callback with raw keys — server stored derived keys, so parse fails.
    let callback_body = valid_demon_callback_body(
        agent_id,
        key,
        iv,
        u32::from(DemonCommand::CommandGetJob),
        7,
        &[],
    );
    let callback_result: Result<Vec<u8>, StatusCode> =
        handle_external_request(&state, peer, &callback_body).await;
    assert_eq!(
        callback_result,
        Err(StatusCode::NOT_FOUND),
        "callback with raw keys must be rejected when init_secret is configured"
    );

    manager.stop("ext-secret-cb").await?;
    Ok(())
}

/// A manager without `with_demon_init_secret` (default no-secret path)
/// stores raw agent keys and accepts callbacks with those same raw keys —
/// confirming that the secret path is not a no-op.
#[tokio::test]
async fn http_listener_without_init_secret_stores_raw_keys_and_accepts_raw_callback()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-no-secret", port)).await?;
    manager.start("edge-no-secret").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0xA1);
    let iv = test_iv(0x74);
    let agent_id = 0xBEEF_0001_u32;

    // Register agent.
    let init_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(init_resp.status(), StatusCode::OK);

    // ACK decryptable with raw keys.
    let ack_bytes = init_resp.bytes().await?;
    let ack_plain = decrypt_agent_data(&key, &iv, &ack_bytes)?;
    assert_eq!(ack_plain.as_slice(), &agent_id.to_le_bytes());

    // Stored keys are the raw keys.
    let stored = registry.get(agent_id).await.expect("agent should be registered");
    assert_eq!(stored.encryption.aes_key.as_slice(), &key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &iv);

    // Callback with raw keys succeeds.
    let callback_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;
    assert_eq!(
        callback_resp.status(),
        StatusCode::OK,
        "callback with raw keys must succeed when no init_secret is configured"
    );

    manager.stop("edge-no-secret").await?;
    Ok(())
}

// ── ja3_randomize wiring tests ───────────────────────────────────────────

/// `listener_config_from_operator` honours an explicit `Ja3Randomize = false` in the
/// operator extra map.
#[test]
fn listener_config_from_operator_wires_ja3_randomize_false() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("true".to_owned()),
        extra: [("Ja3Randomize".to_owned(), serde_json::Value::String("false".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.ja3_randomize, Some(false), "ja3_randomize should be Some(false)");
        }
        other => panic!("expected Http config, got {other:?}"),
    }
    Ok(())
}

/// `listener_config_from_operator` honours an explicit `Ja3Randomize = true`.
#[test]
fn listener_config_from_operator_wires_ja3_randomize_true() -> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("80".to_owned()),
        secure: Some("false".to_owned()),
        extra: [("Ja3Randomize".to_owned(), serde_json::Value::String("true".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.ja3_randomize, Some(true), "ja3_randomize should be Some(true)");
        }
        other => panic!("expected Http config, got {other:?}"),
    }
    Ok(())
}

/// When `Ja3Randomize` is absent from the operator message the field is `None`, which
/// lets the payload builder apply its default (enabled for HTTPS, disabled for HTTP).
#[test]
fn listener_config_from_operator_ja3_randomize_absent_yields_none()
-> Result<(), ListenerManagerError> {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("true".to_owned()),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info)?;
    match config {
        ListenerConfig::Http(http) => {
            assert!(http.ja3_randomize.is_none(), "absent Ja3Randomize should yield None");
        }
        other => panic!("expected Http config, got {other:?}"),
    }
    Ok(())
}

/// An invalid value for `Ja3Randomize` in the operator message must be rejected.
#[test]
fn listener_config_from_operator_rejects_invalid_ja3_randomize() {
    let info = ListenerInfo {
        name: Some("edge".to_owned()),
        protocol: Some("Http".to_owned()),
        host_bind: Some("0.0.0.0".to_owned()),
        host_rotation: Some("round-robin".to_owned()),
        port_bind: Some("443".to_owned()),
        secure: Some("true".to_owned()),
        extra: [("Ja3Randomize".to_owned(), serde_json::Value::String("yes".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let err = listener_config_from_operator(&info).expect_err("invalid Ja3Randomize should fail");
    assert!(err.to_string().contains("Ja3Randomize"), "error should mention the field name: {err}");
}

/// `profile_listener_configs` wires `Ja3Randomize = false` from the HCL profile.
#[test]
fn profile_listener_configs_wires_ja3_randomize_false() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }
        Operators {
          user "neo" {
            Password = "password1234"
          }
        }
        Listeners {
          Http {
            Name         = "edge"
            Hosts        = ["listener.local"]
            HostBind     = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind     = 443
            Secure       = true
            Ja3Randomize = false
          }
        }
        Demon {
          TrustXForwardedFor = false
        }
        "#,
    )
    .expect("profile should parse");

    let listeners = profile_listener_configs(&profile).expect("configs should be valid");
    assert_eq!(listeners.len(), 1);
    let ListenerConfig::Http(config) = &listeners[0] else {
        panic!("expected http listener");
    };
    assert_eq!(config.ja3_randomize, Some(false));
}

/// When `Ja3Randomize` is omitted from the HCL profile the field is `None`.
#[test]
fn profile_listener_configs_ja3_randomize_absent_yields_none() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }
        Operators {
          user "neo" {
            Password = "password1234"
          }
        }
        Listeners {
          Http {
            Name         = "edge"
            Hosts        = ["listener.local"]
            HostBind     = "127.0.0.1"
            HostRotation = "round-robin"
            PortBind     = 443
            Secure       = true
          }
        }
        Demon {
          TrustXForwardedFor = false
        }
        "#,
    )
    .expect("profile should parse");

    let listeners = profile_listener_configs(&profile).expect("configs should be valid");
    assert_eq!(listeners.len(), 1);
    let ListenerConfig::Http(config) = &listeners[0] else {
        panic!("expected http listener");
    };
    assert!(config.ja3_randomize.is_none());
}

// ── DNS AXFR/ANY recon blocking ───────────────────────────────────────────────

/// An AXFR query (qtype=252) must receive REFUSED without attempting C2 parsing.
#[tokio::test]
async fn dns_listener_refuses_axfr_query() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-axfr-refused".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;
    sleep(Duration::from_millis(50)).await;
    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");
    let packet = build_dns_query(0xAF01, "c2.example.com", DNS_QTYPE_AXFR);
    client.send(&packet).await.expect("send failed");
    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");
    assert_eq!(buf[3] & 0x0F, 5, "AXFR must receive REFUSED RCODE");
    handle.abort();
}

/// An ANY query (qtype=255) must receive REFUSED without attempting C2 parsing.
#[tokio::test]
async fn dns_listener_refuses_any_query() {
    let port = free_udp_port();
    let config = red_cell_common::DnsListenerConfig {
        name: "dns-any-refused".to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: "c2.example.com".to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    };
    let (handle, _) = spawn_test_dns_listener(config).await;
    sleep(Duration::from_millis(50)).await;
    let client = TokioUdpSocket::bind("127.0.0.1:0").await.expect("client bind failed");
    client.connect(format!("127.0.0.1:{port}")).await.expect("connect failed");
    let packet = build_dns_query(0xAF02, "c2.example.com", DNS_QTYPE_ANY);
    client.send(&packet).await.expect("send failed");
    let mut buf = vec![0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("no response received")
        .expect("recv failed");
    assert_eq!(buf[3] & 0x0F, 5, "ANY must receive REFUSED RCODE");
    handle.abort();
}

/// After MAX_DNS_RECON_QUERIES_PER_IP AXFR/ANY queries the limiter must
/// stop allowing further queries from that IP (returns false).
#[tokio::test]
async fn dns_recon_block_limiter_stops_responding_after_threshold() {
    let peer_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let limiter = DnsReconBlockLimiter::new();
    for i in 0..MAX_DNS_RECON_QUERIES_PER_IP {
        assert!(limiter.allow(peer_ip).await, "query {i} should be allowed (below threshold)");
    }
    assert!(!limiter.allow(peer_ip).await, "query beyond threshold should be blocked");
    let other_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    assert!(limiter.allow(other_ip).await, "different IP should still be allowed");
}

/// After the window expires the IP counter resets and the IP is allowed again.
#[tokio::test]
async fn dns_recon_block_limiter_resets_after_window_expires() {
    let peer_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let limiter = DnsReconBlockLimiter::new();
    for _ in 0..=MAX_DNS_RECON_QUERIES_PER_IP {
        limiter.allow(peer_ip).await;
    }
    assert!(!limiter.allow(peer_ip).await, "should be blocked before window resets");
    {
        let mut windows = limiter.windows.lock().await;
        if let Some(w) = windows.get_mut(&peer_ip) {
            w.window_start = Instant::now()
                .checked_sub(DNS_RECON_WINDOW_DURATION + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }
    assert!(limiter.allow(peer_ip).await, "IP should be allowed again after recon window expires");
}

/// The limiter tracks distinct IPs correctly.
#[tokio::test]
async fn dns_recon_block_limiter_tracks_ip_count() {
    let limiter = DnsReconBlockLimiter::new();
    assert_eq!(limiter.tracked_ip_count().await, 0);
    let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    limiter.allow(ip1).await;
    assert_eq!(limiter.tracked_ip_count().await, 1);
    limiter.allow(ip2).await;
    assert_eq!(limiter.tracked_ip_count().await, 2);
    limiter.allow(ip1).await;
    assert_eq!(limiter.tracked_ip_count().await, 2);
}

/// Once the threshold is exceeded handle_dns_packet must return None
/// (drop without response) rather than returning a REFUSED packet.
#[tokio::test]
async fn dns_state_drops_axfr_from_repeat_offender_without_response() {
    let state = dns_state("dns-recon-drop").await;
    let peer_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    for _ in 0..MAX_DNS_RECON_QUERIES_PER_IP {
        let packet = build_dns_query(0x1000, "c2.example.com", DNS_QTYPE_AXFR);
        let resp = state.handle_dns_packet(&packet, peer_ip).await;
        assert!(resp.is_some(), "within-threshold AXFR should receive REFUSED");
        assert_eq!(resp.unwrap()[3] & 0x0F, 5, "within-threshold AXFR RCODE must be REFUSED");
    }
    let packet = build_dns_query(0x1001, "c2.example.com", DNS_QTYPE_AXFR);
    let resp = state.handle_dns_packet(&packet, peer_ip).await;
    assert!(resp.is_none(), "repeat offender AXFR must be dropped without response");
}
