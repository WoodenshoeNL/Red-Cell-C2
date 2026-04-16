use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use super::super::{
    DEMON_INIT_WINDOW_DURATION, ListenerEventAction, MAX_DEMON_INIT_ATTEMPT_WINDOWS,
    MAX_DEMON_INIT_ATTEMPTS_PER_IP, MAX_RECONNECT_PROBE_WINDOWS, MAX_RECONNECT_PROBES_PER_AGENT,
    MAX_UNKNOWN_CALLBACK_PROBE_AUDITS_PER_SOURCE, RECONNECT_PROBE_WINDOW_DURATION,
    TrustedProxyPeer, UNKNOWN_CALLBACK_PROBE_AUDIT_WINDOW_DURATION, action_from_mark,
    extract_external_ip, is_past_kill_date, listener_config_from_operator, listener_error_event,
    listener_event_for_action, listener_removed_event, operator_protocol_name,
    operator_requests_start, parse_trusted_proxy_peer, profile_listener_configs,
    spawn_managed_listener_task,
};
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell_common::config::Profile;
use red_cell_common::operator::OperatorMessage;
use red_cell_common::{
    DnsListenerConfig, HttpListenerProxyConfig, HttpListenerResponseConfig, ListenerTlsConfig,
};

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

// ── ja3_randomize wiring tests ───────────────────────────────────────────

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
async fn listener_manager_with_max_concurrent_downloads_per_agent_stores_limit() {
    let mgr = manager().await.expect("manager must build");
    // Default is whatever the hardcoded constant is; just verify the builder changes it.
    let default_limit = mgr.downloads.max_concurrent_downloads_per_agent();

    let custom_limit: usize = default_limit / 2 + 1;
    let mgr = mgr.with_max_concurrent_downloads_per_agent(custom_limit);
    assert_eq!(
        mgr.downloads.max_concurrent_downloads_per_agent(),
        custom_limit,
        "builder must override the concurrent download limit"
    );
}

/// `with_max_aggregate_download_bytes` stores the supplied cap (clamped to at
/// least the per-download cap) on the embedded `DownloadTracker`.
#[tokio::test]
async fn listener_manager_with_max_aggregate_download_bytes_stores_limit() {
    use crate::DEFAULT_MAX_DOWNLOAD_BYTES;
    let mgr = manager().await.expect("manager must build");

    // A cap well above the per-download limit must be stored as-is.
    let large_cap: u64 = DEFAULT_MAX_DOWNLOAD_BYTES * 8;
    let mgr = mgr.with_max_aggregate_download_bytes(large_cap);
    assert_eq!(
        mgr.downloads.max_total_download_bytes(),
        large_cap as usize,
        "builder must store the supplied aggregate cap"
    );
}

/// `with_max_pivot_chain_depth` stores the supplied depth so it is passed to
/// each dispatcher created when a listener is spawned.
#[tokio::test]
async fn listener_manager_with_max_pivot_chain_depth_stores_depth() {
    use crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH;
    let mgr = manager().await.expect("manager must build");
    assert_eq!(
        mgr.max_pivot_chain_depth, DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        "default depth must equal the hardcoded constant"
    );

    let custom_depth: usize = 3;
    let mgr = mgr.with_max_pivot_chain_depth(custom_depth);
    assert_eq!(
        mgr.max_pivot_chain_depth, custom_depth,
        "builder must override the pivot chain depth"
    );
}

// ---------------------------------------------------------------------------
// reload_tls_cert tests
// ---------------------------------------------------------------------------
