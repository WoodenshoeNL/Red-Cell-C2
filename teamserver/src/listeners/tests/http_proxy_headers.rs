use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::super::{TrustedProxyPeer, extract_external_ip, parse_trusted_proxy_peer};
use super::*;
use axum::body::Body;
use axum::http::Request;

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
