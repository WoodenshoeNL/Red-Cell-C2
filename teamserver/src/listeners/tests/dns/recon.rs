use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use super::super::*;
use super::helpers::{build_dns_query, dns_state, spawn_test_dns_listener};
use tokio::net::UdpSocket as TokioUdpSocket;

use super::super::super::dns::{DNS_QTYPE_ANY, DNS_QTYPE_AXFR};
use super::super::super::{
    DNS_RECON_WINDOW_DURATION, DnsReconBlockLimiter, MAX_DNS_RECON_QUERIES_PER_IP,
};

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
        suppress_opsec_warnings: true,
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
        suppress_opsec_warnings: true,
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
