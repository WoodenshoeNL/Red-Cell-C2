use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use red_cell_common::demon::{DemonCommand, DemonMessage};

use super::super::*;
use super::helpers::dns_state;

use super::super::super::dns::{
    DNS_DOH_RESPONSE_CHUNK_BYTES, DNS_MAX_PENDING_UPLOADS, DNS_MAX_UPLOAD_CHUNKS,
    DNS_MAX_UPLOADS_PER_IP, DNS_UPLOAD_TIMEOUT_SECS, DnsPendingResponse, DnsPendingUpload,
    DnsUploadAssembly, base32_rfc4648_decode,
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

/// Split a packet into DoH uplink chunks (same encoding the Specter/Archon agents use).
fn doh_chunk_packet(packet: &[u8]) -> Vec<Vec<u8>> {
    packet.chunks(DNS_DOH_RESPONSE_CHUNK_BYTES).map(<[u8]>::to_vec).collect()
}

/// Upload all chunks of `packet` via `handle_doh_upload` and assert every chunk returns `true`.
async fn doh_upload_all(
    state: &super::super::super::dns::DnsListenerState,
    session: &str,
    packet: &[u8],
    peer_ip: IpAddr,
) {
    let raw_chunks = doh_chunk_packet(packet);
    let total = u16::try_from(raw_chunks.len()).expect("chunk count fits in u16");
    for (seq, chunk) in raw_chunks.into_iter().enumerate() {
        let ok = state
            .handle_doh_upload(
                session.to_owned(),
                u16::try_from(seq).expect("seq fits"),
                total,
                chunk,
                peer_ip,
            )
            .await;
        assert!(ok, "handle_doh_upload must return true for seq={seq}");
    }
}

/// Download all chunks via `handle_doh_download` and reassemble the payload.
async fn doh_download_all(
    state: &super::super::super::dns::DnsListenerState,
    session: &str,
    total: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    for seq in 0..total {
        let b32 = state.handle_doh_download(session, u16::try_from(seq).expect("seq fits")).await;
        let chunk = base32_rfc4648_decode(&b32).expect("server chunk must be valid base32");
        out.extend_from_slice(&chunk);
    }
    out
}

/// The DoH ready-poll must resolve (return Some) even when `CommandGetJob` has no queued
/// work: the dispatcher still returns a framed `CommandNoJob` sentinel (matching
/// `handle_get_job` in `dispatcher_runtime.rs`).
///
/// Prior to the DNS fix, **truly empty** payloads were discarded and `handle_doh_ready` could
/// return `None`; this test asserts the sentinel path clears the rendezvous reliably.
#[tokio::test]
async fn doh_no_job_response_signals_ready_with_one_download_chunk() {
    let state = dns_state("doh-empty-payload").await;
    let agent_id = 0xBEEF_0001_u32;
    let key = test_key(0xAB);
    let iv = test_iv(0xCD);
    let peer_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // 1. Register the agent via DEMON_INIT so GET_JOB is dispatched correctly.
    let init_packet = valid_demon_init_body(agent_id, key, iv);
    let init_session = "doh00000init0001";
    doh_upload_all(&state, init_session, &init_packet, peer_ip).await;
    let init_total = state.handle_doh_ready(init_session).await.expect("init ready must resolve");
    // Consume the init-ACK chunks so the response slot is cleared.
    for seq in 0..init_total {
        state.handle_doh_download(init_session, u16::try_from(seq).unwrap()).await;
    }
    // Exhaust the "done" sentinel read so the slot is actually removed.
    state.handle_doh_download(init_session, u16::try_from(init_total).unwrap()).await;

    // 2. Send a GET_JOB callback (no commands queued → NO_JOB sentinel).
    let get_job_packet = valid_demon_callback_body(
        agent_id,
        key,
        iv,
        u32::from(DemonCommand::CommandGetJob),
        1,
        &[],
    );
    let get_job_session = "doh00000getjob01";
    doh_upload_all(&state, get_job_session, &get_job_packet, peer_ip).await;

    // 3. The ready poll must resolve with at least one chunk (NO_JOB ciphertext).
    let total_chunks = state
        .handle_doh_ready(get_job_session)
        .await
        .expect("DoH ready must resolve after GET_JOB completes");
    assert_eq!(
        total_chunks, 1,
        "NO_JOB response must fit within a single DoH DNS download chunk encoding"
    );

    let ciphertext = doh_download_all(&state, get_job_session, total_chunks).await;
    let msg = DemonMessage::from_bytes(ciphertext.as_ref())
        .expect("GET_JOB response payload must decode as DemonMessage");
    assert_eq!(msg.packages.len(), 1, "idle GET_JOB must use a single package");
    assert_eq!(
        msg.packages[0].command_id,
        u32::from(DemonCommand::CommandNoJob),
        "idle queue must reply with CommandNoJob"
    );
}

/// Full DoH round-trip for a DEMON_INIT packet: upload all chunks, poll ready, download the
/// init ACK, and verify it decrypts to the agent_id (little-endian u32).
#[tokio::test]
async fn doh_full_round_trip_demon_init_upload_ready_download() {
    let state = dns_state("doh-full-init").await;
    let agent_id = 0xCAFE_BABE_u32;
    let key = test_key(0x11);
    let iv = test_iv(0x22);
    let peer_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let session = "doh0cafebabetest";

    let init_packet = valid_demon_init_body(agent_id, key, iv);

    // Packet must span at least 2 chunks to exercise multi-chunk reassembly.
    let chunk_count = init_packet.len().div_ceil(DNS_DOH_RESPONSE_CHUNK_BYTES);
    assert!(chunk_count >= 2, "DEMON_INIT must span >= 2 chunks; got {chunk_count}");

    // Upload all chunks — each must return true (NXDOMAIN).
    doh_upload_all(&state, session, &init_packet, peer_ip).await;

    // Ready poll must resolve with a non-zero chunk count.
    let total = state
        .handle_doh_ready(session)
        .await
        .expect("DoH ready must resolve after all init chunks are uploaded");
    assert!(total > 0, "init ACK must have at least one chunk");

    // Download and reassemble the init ACK.
    let ack_ciphertext = doh_download_all(&state, session, total).await;

    // Verify the ACK decrypts to agent_id as little-endian u32 at offset 0.
    let plaintext = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &ack_ciphertext)
        .expect("init ACK must decrypt");
    assert_eq!(
        plaintext,
        agent_id.to_le_bytes(),
        "init ACK plaintext must be agent_id as little-endian u32"
    );
}

/// The ready poll for a session that has not been uploaded yet returns None (NXDOMAIN),
/// and resolves only after the upload completes.
#[tokio::test]
async fn doh_ready_returns_none_before_upload_completes() {
    let state = dns_state("doh-ready-none").await;
    let peer_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let session = "doh0readynotyet1";
    let agent_id = 0xDEAD_D00D_u32;
    let key = test_key(0x33);
    let iv = test_iv(0x44);

    let init_packet = valid_demon_init_body(agent_id, key, iv);
    let raw_chunks = doh_chunk_packet(&init_packet);
    let total = u16::try_from(raw_chunks.len()).unwrap();

    // Before any chunks are uploaded, ready must return None.
    assert!(state.handle_doh_ready(session).await.is_none(), "ready before upload must be None");

    // Send all-but-last chunks; ready must still be None.
    for seq in 0..raw_chunks.len() - 1 {
        let ok = state
            .handle_doh_upload(
                session.to_owned(),
                u16::try_from(seq).unwrap(),
                total,
                raw_chunks[seq].clone(),
                peer_ip,
            )
            .await;
        assert!(ok, "chunk {seq} must be accepted");
        assert!(
            state.handle_doh_ready(session).await.is_none(),
            "ready must be None after chunk {seq}"
        );
    }

    // Send the final chunk — ready must now resolve.
    let last = raw_chunks.len() - 1;
    let ok = state
        .handle_doh_upload(
            session.to_owned(),
            u16::try_from(last).unwrap(),
            total,
            raw_chunks[last].clone(),
            peer_ip,
        )
        .await;
    assert!(ok, "last chunk must be accepted");
    assert!(
        state.handle_doh_ready(session).await.is_some(),
        "ready must be Some after all chunks are uploaded"
    );
}
