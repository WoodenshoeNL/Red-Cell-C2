use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use super::super::*;
use super::helpers::dns_state;

use super::super::super::dns::{
    DNS_MAX_PENDING_UPLOADS, DNS_MAX_UPLOAD_CHUNKS, DNS_MAX_UPLOADS_PER_IP,
    DNS_UPLOAD_TIMEOUT_SECS, DnsPendingResponse, DnsPendingUpload, DnsUploadAssembly,
};

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
