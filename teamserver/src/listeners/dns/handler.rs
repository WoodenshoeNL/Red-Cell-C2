//! Upload/download reassembly and callback dispatch for the DNS C2 listener.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use tracing::warn;

use super::packet::{chunk_response_to_b32hex, chunk_response_to_doh_b32};
use super::{
    DNS_DOH_MAX_UPLOAD_CHUNKS, DNS_MAX_DOWNLOAD_CHUNKS, DNS_MAX_PENDING_RESPONSE_BYTES,
    DNS_MAX_PENDING_RESPONSES, DNS_MAX_PENDING_UPLOADS, DNS_MAX_UPLOAD_CHUNKS,
    DNS_MAX_UPLOADS_PER_IP, DNS_UPLOAD_TIMEOUT_SECS, DnsListenerState, DnsPendingResponse,
    DnsPendingUpload, DnsUploadAssembly,
};
use crate::listeners::{
    allow_demon_init_for_ip, is_valid_demon_callback_request, process_demon_transport,
};

impl DnsListenerState {
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
