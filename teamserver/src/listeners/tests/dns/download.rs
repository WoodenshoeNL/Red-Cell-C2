use std::collections::HashMap;
use std::time::Instant;

use super::super::*;
use super::helpers::{build_dns_txt_query, dns_answer_rr_type, dns_state, spawn_test_dns_listener};
use tokio::net::UdpSocket as TokioUdpSocket;

use super::super::super::dns::{
    DNS_MAX_PENDING_RESPONSE_BYTES, DNS_MAX_PENDING_RESPONSES, DNS_TYPE_TXT, DnsListenerState,
    DnsPendingResponse, parse_dns_query,
};

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
        suppress_opsec_warnings: true,
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
