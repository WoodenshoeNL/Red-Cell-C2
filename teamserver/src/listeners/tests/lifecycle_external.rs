use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::super::{TrustedProxyPeer, extract_external_ip, parse_trusted_proxy_peer};
use super::*;
use axum::body::Body;
use axum::http::Request;
use red_cell_common::config::Profile;

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

// ── sync_profile tests for External listeners ────────────────────────────

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
